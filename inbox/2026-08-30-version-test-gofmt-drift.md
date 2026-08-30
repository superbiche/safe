# internal/releasereview/version_test.go is not gofmt-clean on main

Captured 2026-08-30 (#206 slice, noticed via `gofmt -l internal/`).

Comment-alignment drift only, committed with b14beb4 (1.47.0, PR #122). No gate
enforces gofmt today, which is why it landed and stays green.

Ask: `gofmt -w` the file in some no-impact-eligible change, and consider adding
a `gofmt -l` check to the Go suite so the next drift is caught at commit time.
