package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/superbiche/safe/internal/privtrust"
)

const privateTrustUsage = "safe-core: usage: safe-core private-trust <match|match-names|registries|registry-add|registry-remove|list|export|follow-apply|forget-origin|go-route|under-origin|canonical-url|canonical-origin> [flags]"

// privateTrust is the decision core behind safe's private-registry lane.
// Exit codes: 0 ok; 2 usage; 3 malformed store or input (never a decision);
// 4 refused operation (a validation or conflict the operator must resolve);
// for follow-apply, 5 older generation and 6 collision.
func privateTrust(args []string, stdinReader io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, privateTrustUsage)
		return 2
	}
	sub := args[0]
	flags, multi, ok := parsePrivateFlags(args[1:])
	if !ok {
		fmt.Fprintln(stderr, privateTrustUsage)
		return 2
	}
	stores := privtrust.Stores{Policy: flags["policy"],
		FollowState: flags["follow-state"], Config: flags["config"]}
	emit := func(v any) int {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			fmt.Fprintf(stderr, "safe-core: private-trust: write JSON: %v\n", err)
			return 3
		}
		return 0
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "safe-core: private-trust %s: %v\n", sub, err)
		if errors.Is(err, privtrust.ErrMalformed) {
			return 3
		}
		return 4
	}
	need := func(names ...string) bool {
		for _, n := range names {
			if flags[n] == "" {
				fmt.Fprintf(stderr, "safe-core: private-trust %s: --%s is required\n", sub, n)
				return false
			}
		}
		return true
	}

	switch sub {
	case "match":
		if !need("ecosystem", "name") {
			return 2
		}
		v, err := privtrust.Load(stores)
		if err != nil {
			return fail(err)
		}
		return emit(v.Match(flags["ecosystem"], flags["name"]))
	case "match-names":
		// Names on stdin, one per line; prints the matches that are on a
		// private or conflict lane (none-lane names are omitted).
		if !need("ecosystem") {
			return 2
		}
		v, err := privtrust.Load(stores)
		if err != nil {
			return fail(err)
		}
		raw, err := io.ReadAll(stdinReader)
		if err != nil {
			fmt.Fprintf(stderr, "safe-core: private-trust match-names: %v\n", err)
			return 3
		}
		out := []privtrust.Match{}
		seen := map[string]bool{}
		for _, name := range strings.Split(string(raw), "\n") {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			if m := v.Match(flags["ecosystem"], name); m.Lane != "none" {
				out = append(out, m)
			}
		}
		return emit(out)
	case "registries":
		// The effective registries of one ecosystem (local, then followed).
		if !need("ecosystem") {
			return 2
		}
		v, err := privtrust.Load(stores)
		if err != nil {
			return fail(err)
		}
		regs := v.Registries(flags["ecosystem"])
		if regs == nil {
			regs = []privtrust.ListEntry{}
		}
		return emit(regs)
	case "registry-add":
		if !need("policy", "id", "ecosystem", "origin") {
			return 2
		}
		r, err := privtrust.AddRegistry(stores, flags["id"], privtrust.Registry{
			Ecosystem: flags["ecosystem"], Origin: flags["origin"], Owner: flags["owner"],
			Namespace: multi["namespace"], Added: flags["added"], Reason: flags["reason"]})
		if err != nil {
			return fail(err)
		}
		return emit(r)
	case "registry-remove":
		if !need("policy", "id") {
			return 2
		}
		if err := privtrust.RemoveRegistry(stores, flags["id"]); err != nil {
			return fail(err)
		}
		return 0
	case "list":
		v, err := privtrust.Load(stores)
		if err != nil {
			return fail(err)
		}
		return emit(v.List())
	case "export":
		if !need("host", "exported-at") {
			return 2
		}
		st, err := privtrust.Export(stores, flags["host"], flags["exported-at"])
		if err != nil {
			return fail(err)
		}
		return emit(st)
	case "follow-apply":
		if !need("follow-state", "host", "signer", "statement") {
			return 2
		}
		raw, err := os.ReadFile(flags["statement"])
		if err != nil {
			fmt.Fprintf(stderr, "safe-core: private-trust follow-apply: %v\n", err)
			return 3
		}
		res, err := privtrust.ApplyStatement(flags["follow-state"], flags["host"],
			strings.ToUpper(flags["signer"]), raw, flags["dry-run"] == "1")
		for _, w := range res.Warnings {
			fmt.Fprintf(stderr, "safe-core: private-trust follow-apply: %s: %s\n", flags["host"], w)
		}
		if err != nil {
			fmt.Fprintf(stderr, "safe-core: private-trust follow-apply: %s: %v\n", flags["host"], err)
			return 3
		}
		if rc := emit(res); rc != 0 {
			return rc
		}
		switch res.Result {
		case "older":
			return 5
		case "collision":
			return 6
		}
		return 0
	case "forget-origin":
		if !need("follow-state", "host") {
			return 2
		}
		found, err := privtrust.ForgetOrigin(flags["follow-state"], flags["host"])
		if err != nil {
			return fail(err)
		}
		if !found {
			fmt.Fprintf(stderr, "safe-core: private-trust forget-origin: no followed origin %s\n", flags["host"])
			return 4
		}
		return 0
	case "go-route":
		// --module is a module path or namespace prefix.
		if !need("module", "origin") {
			return 2
		}
		return emit(privtrust.GoRoute(flags["module"], flags["origin"], flags["goproxy"], flags["gonoproxy"], flags["goprivate"]))
	case "under-origin":
		// Exit 0 when --url lies at or below --origin; 1 otherwise.
		if !need("url", "origin") {
			return 2
		}
		if privtrust.UnderOrigin(flags["url"], flags["origin"]) {
			return 0
		}
		return 1
	case "canonical-url":
		if !need("url") {
			return 2
		}
		c := privtrust.CanonicalURL(flags["url"])
		if c == "" {
			fmt.Fprintln(stderr, "safe-core: private-trust canonical-url: not an http(s) URL")
			return 4
		}
		fmt.Fprintln(stdout, c)
		return 0
	case "canonical-origin":
		if !need("origin") {
			return 2
		}
		o, err := privtrust.CanonicalOrigin(flags["origin"])
		if err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, o)
		return 0
	}
	fmt.Fprintln(stderr, privateTrustUsage)
	return 2
}

// parsePrivateFlags reads --name value pairs (and --name=value). --namespace
// may repeat; --dry-run is boolean. Positionals are refused.
func parsePrivateFlags(args []string) (map[string]string, map[string][]string, bool) {
	flags := map[string]string{}
	multi := map[string][]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			return nil, nil, false
		}
		name, value, hasValue := strings.Cut(a[2:], "=")
		if name == "dry-run" && !hasValue {
			flags[name] = "1"
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				return nil, nil, false
			}
			value = args[i+1]
			i++
		}
		if name == "namespace" {
			multi[name] = append(multi[name], value)
			continue
		}
		if _, dup := flags[name]; dup {
			return nil, nil, false
		}
		flags[name] = value
	}
	return flags, multi, true
}
