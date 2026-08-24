// Command fixture-server serves canned GitHub API responses over real HTTP.
//
// It exists so the parity corpus can drive BOTH sides of the migration from one
// set of fixtures: the bash sub-lanes reach it through curl, the Go composite
// through net/http, and neither knows it is not talking to GitHub. Mocking curl
// on one side and httptest on the other would compare two different fixtures
// and call the result parity.
//
// Fixtures live under -dir as one directory per scenario, and the scenario is
// the first path segment of the request, so one server serves every case:
//
//	-dir corpus/            request /clean/repos/example/tool/releases
//	  clean/                serves  corpus/clean/repos_example_tool_releases.json
//	    repos_example_tool_releases.json
//	    repos_example_tool_releases.status      → answer with this status code
//	    repos_example_tool_releases_page2.json  → offer a Link rel="next" page
//
// A path with no fixture answers 404 with GitHub's own body, which is what a
// missing release, tag or repository looks like.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	dir := flag.String("dir", "", "directory holding the scenario fixture directories")
	flag.Parse()
	if *dir == "" {
		log.Fatal("fixture-server: -dir is required")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("fixture-server: listen: %v", err)
	}
	// The harness reads this line to learn where to point both lanes.
	fmt.Printf("http://%s\n", listener.Addr().String())
	if err := os.Stdout.Sync(); err != nil {
		log.Fatalf("fixture-server: flush the address: %v", err)
	}
	if err := http.Serve(listener, handler(*dir)); err != nil {
		log.Fatalf("fixture-server: serve: %v", err)
	}
}

func handler(dir string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		trimmed := strings.TrimPrefix(request.URL.Path, "/")
		// Traversal is a whole segment of "..", not the substring: GitHub's own
		// compare endpoint spells its range `v1.2.2...v1.2.3`, and refusing
		// every path containing two dots refuses that.
		for _, segment := range strings.Split(trimmed, "/") {
			if segment == ".." || segment == "." {
				http.Error(writer, "no", http.StatusBadRequest)
				return
			}
		}
		scenario, rest, ok := strings.Cut(trimmed, "/")
		if !ok || scenario == "" || rest == "" {
			notFound(writer)
			return
		}

		base := filepath.Join(dir, scenario, strings.ReplaceAll(rest, "/", "_"))
		writer.Header().Set("Content-Type", "application/json")

		if status, err := os.ReadFile(base + ".status"); err == nil {
			code, convErr := strconv.Atoi(strings.TrimSpace(string(status)))
			if convErr != nil {
				http.Error(writer, "unusable status fixture", http.StatusInternalServerError)
				return
			}
			writer.WriteHeader(code)
			fmt.Fprint(writer, `{"message":"fixture status override"}`)
			return
		}

		body := base + ".json"
		if page := request.URL.Query().Get("page"); page != "" && page != "1" {
			body = fmt.Sprintf("%s_page%s.json", base, page)
		} else if _, err := os.Stat(base + "_page2.json"); err == nil {
			writer.Header().Set("Link", fmt.Sprintf(`<http://%s%s?page=2>; rel="next"`,
				request.Host, request.URL.Path))
		}

		content, err := os.ReadFile(body)
		if err != nil {
			notFound(writer)
			return
		}
		writer.Write(content)
	})
}

func notFound(writer http.ResponseWriter) {
	writer.WriteHeader(http.StatusNotFound)
	fmt.Fprint(writer, `{"message":"Not Found","documentation_url":"https://docs.github.com/rest"}`)
}
