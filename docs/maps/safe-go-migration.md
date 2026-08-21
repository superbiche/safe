# Safe Go Migration — wayfinder map (belt export)

Canonical map: [Safe Go Migration](https://superbiche.fibery.io/Superbiche/Tasks/119)
(Fibery is coordination only; this export means losing the tracker loses
frontier/blocking state, zero decisions. Re-export after each session that
closes a ticket.)

## Destination

`safe` ships as a single static Go binary: `bin/safe`, `bin/safe-run`,
`bin/safe-audit`, and `lib/gate-lib.sh` are retired; bash remains only as
trivial PATH shims and completions.

## Notes

- Strangler start exists: `cmd/safe-core` (lockdiff, package-verdict),
  version-locked to `safe` by the gate.
- Standing constraint (`docs/architecture.md` § Direction: Go): binary-audit
  is built composite-first in Go — one `release-review` command, one report,
  one capability key.
- Test law (charting ruling 2026-08-21): each migrated lane ports its tests
  to Go in the same slice, AND the surface's existing bash suite must stay
  green run against the Go binary until that surface's bash implementation
  is deleted (the parity belt).
- Dependency policy is ruled per lane in that lane's ticket; until a lane
  rules otherwise, the posture is subprocess (status quo).
- First bite (charting ruling 2026-08-21): the binary-audit lane.
- Repo review law applies (`AGENTS.md` § Reviews).

## Tickets (index at export time, 2026-08-21)

- [Binary-audit lane: native Go vs subprocess survey](https://superbiche.fibery.io/Superbiche/Tasks/120) — research, CLOSED at charting.
- [Composite release-review: spec, report schema, deps posture](https://superbiche.fibery.io/Superbiche/Tasks/121) — grilling, open; blocked by the survey.
- [Parity belt: wire the bash-suite-against-Go rule into the repo](https://superbiche.fibery.io/Superbiche/Tasks/122) — task, open.
- [Mixed-era binary shape: safe-core sidecar vs Go dispatcher](https://superbiche.fibery.io/Superbiche/Tasks/123) — grilling, open.
- [End-state gate: what replaces gate-lib and the PATH wrappers](https://superbiche.fibery.io/Superbiche/Tasks/124) — grilling, open.

## Decisions so far

- [Binary-audit lane: native Go vs subprocess survey](https://superbiche.fibery.io/Superbiche/Tasks/120) — subprocess-everywhere for the composite's v1, except GitHub REST which goes native stdlib (a straight port of the existing pinned-version curl contract); sigstore-go flagged as the future native candidate behind a fixture-corpus parity gate.

## Not yet specified

- Ordering of lanes after binary-audit — reshuffles as slices land.
- Interactive/TTY surfaces in Go (safe-run prompts, exit-102 semantics,
  interactive host-allow adds) — ports with the first lane that hits prompts.
- Go package layout conventions as lanes multiply — expected to settle in
  early slices.
- End-state install/distribution story: `install.sh`'s future, completions,
  fleet rollout via machine-setup, and whether safe's own releases flow
  through the binary-audit review lane (self-hosting).
- Contract/docs regeneration (`docs/contract/agent-contract.json` render
  pipeline) in the Go world.

## Out of scope

(none yet)
