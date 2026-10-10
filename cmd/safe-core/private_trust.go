package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/superbiche/safe/internal/privtrust"
)

const privateTrustUsage = "safe-core: usage: safe-core private-trust <match|decide|record|registry-add|registry-remove|list|export|follow-apply|forget-origin|go-route|gosum|canonical-origin> [flags]"

// privateTrust is the decision core behind safe's private-registry lane.
// Exit codes: 0 ok; 2 usage; 3 malformed store or input (never a decision);
// 4 refused operation (a validation or conflict the operator must resolve);
// for follow-apply, 5 older generation and 6 collision.
func privateTrust(args []string, stdout, stderr io.Writer) int {
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
	stores := privtrust.Stores{Policy: flags["policy"], Pins: flags["pins"],
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
	case "decide":
		if !need("ecosystem", "name", "version", "observed") {
			return 2
		}
		v, err := privtrust.Load(stores)
		if err != nil {
			return fail(err)
		}
		var observed, fetched *privtrust.Integrity
		if observed, err = parseIntegrity(flags["observed"]); err != nil {
			fmt.Fprintf(stderr, "safe-core: private-trust decide: --observed: %v\n", err)
			return 3
		}
		if flags["fetched"] != "" {
			if fetched, err = parseIntegrity(flags["fetched"]); err != nil {
				fmt.Fprintf(stderr, "safe-core: private-trust decide: --fetched: %v\n", err)
				return 3
			}
		}
		m := v.Match(flags["ecosystem"], flags["name"])
		return emit(struct {
			Match    privtrust.Match    `json:"match"`
			Decision privtrust.Decision `json:"decision"`
		}{m, v.Decide(m, flags["version"], observed, fetched)})
	case "record":
		if !need("pins", "ecosystem", "origin", "name", "version", "mode") {
			return 2
		}
		in := &privtrust.Integrity{}
		if flags["integrity"] != "" {
			var err error
			if in, err = parseIntegrity(flags["integrity"]); err != nil {
				fmt.Fprintf(stderr, "safe-core: private-trust record: --integrity: %v\n", err)
				return 3
			}
		}
		p, written, err := privtrust.WritePin(flags["pins"], privtrust.Pin{
			Ecosystem: flags["ecosystem"], Origin: flags["origin"], Name: flags["name"],
			Version: flags["version"], Integrity: *in, Artifact: flags["artifact"]}, flags["mode"])
		if err != nil {
			return fail(err)
		}
		return emit(struct {
			Pin     privtrust.Pin `json:"pin"`
			Written bool          `json:"written"`
		}{p, written})
	case "registry-add":
		if !need("policy", "id", "ecosystem", "origin") {
			return 2
		}
		cooldown := 0
		if c := flags["cooldown-days"]; c != "" {
			n, err := strconv.Atoi(c)
			if err != nil {
				fmt.Fprintln(stderr, "safe-core: private-trust registry-add: --cooldown-days must be an integer")
				return 2
			}
			cooldown = n
		}
		r, err := privtrust.AddRegistry(stores, flags["id"], privtrust.Registry{
			Ecosystem: flags["ecosystem"], Origin: flags["origin"], Owner: flags["owner"],
			Namespace: multi["namespace"], PinMode: flags["pin-mode"], CooldownDays: cooldown,
			Added: flags["added"], Reason: flags["reason"]})
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
		if !need("module", "origin") {
			return 2
		}
		reason := privtrust.GoRoute(flags["module"], flags["origin"], flags["goproxy"], flags["gonoproxy"], flags["goprivate"])
		return emit(struct {
			OK     bool   `json:"ok"`
			Reason string `json:"reason,omitempty"`
		}{reason == "", reason})
	case "gosum":
		if !need("file") {
			return 2
		}
		raw, err := os.ReadFile(flags["file"])
		if err != nil {
			fmt.Fprintf(stderr, "safe-core: private-trust gosum: %v\n", err)
			return 3
		}
		entries, err := privtrust.ParseGoSum(raw)
		if err != nil {
			fmt.Fprintf(stderr, "safe-core: private-trust gosum: %v\n", err)
			return 3
		}
		return emit(entries)
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

func parseIntegrity(raw string) (*privtrust.Integrity, error) {
	var in privtrust.Integrity
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, err
	}
	return &in, nil
}
