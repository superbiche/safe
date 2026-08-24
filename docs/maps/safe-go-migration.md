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
  is deleted (the parity belt). Binary-audit variant (ruled at the composite
  ticket, 2026-08-23): the composite is a new surface the bash suites cannot
  exercise — parity evidence there is a fixture corpus (same releases through
  the bash sub-lanes and `release-review`, verdicts diffed) until the bash
  sub-lanes are deleted. Wired into the repo 2026-08-23 at the parity-belt
  ticket: `AGENTS.md` § Tests law text, `tests/run-all.sh` enumeration guard
  (every suite registered or explicitly excluded), `SAFE_TEST_STRICT=1`
  (missing Go toolchain is red under the aggregate runner).
- Dependency policy is ruled per lane in that lane's ticket; until a lane
  rules otherwise, the posture is subprocess (status quo).
- First bite (charting ruling 2026-08-21): the binary-audit lane.
- Repo review law applies (`AGENTS.md` § Reviews).

## Tickets (index at export time, 2026-08-24)

- [Binary-audit lane: native Go vs subprocess survey](https://superbiche.fibery.io/Superbiche/Tasks/120) — research, CLOSED at charting.
- [Composite release-review: spec, report schema, deps posture](https://superbiche.fibery.io/Superbiche/Tasks/121) — grilling, CLOSED 2026-08-23.
- [Parity belt: wire the bash-suite-against-Go rule into the repo](https://superbiche.fibery.io/Superbiche/Tasks/122) — task, CLOSED 2026-08-23.
- [Mixed-era binary shape: safe-core sidecar vs Go dispatcher](https://superbiche.fibery.io/Superbiche/Tasks/123) — grilling, CLOSED 2026-08-24.
- [End-state gate: what replaces gate-lib and the PATH wrappers](https://superbiche.fibery.io/Superbiche/Tasks/124) — grilling, open.

## Decisions so far

- [Binary-audit lane: native Go vs subprocess survey](https://superbiche.fibery.io/Superbiche/Tasks/120) — subprocess-everywhere for the composite's v1, except GitHub REST which goes native stdlib (a straight port of the existing pinned-version curl contract); sigstore-go flagged as the future native candidate behind a fixture-corpus parity gate.
- [Composite release-review: spec, report schema, deps posture](https://superbiche.fibery.io/Superbiche/Tasks/121) — JSON spec file in (`--spec PATH|-`); one report `{schema_version, subject, verdict, checks[]}` with a redesigned reason taxonomy (old bash codes die with the bash sub-lanes); worst-of aggregation with spec-declared advisory checks and first-class ERROR for could-not-run; single capability key `binary-audit.release-review` + advertised schema_version, strict spec decoding as backstop; composite-only (no Go shims for the six sub-lanes, deleted after consumer swap; fixture-corpus parity variant); survey deps posture ratified as-is.
- [Parity belt: wire the bash-suite-against-Go rule into the repo](https://superbiche.fibery.io/Superbiche/Tasks/122) — landed (PR #97, `be4b240`): law text in `AGENTS.md` § Tests (SUITES-departure rule + fixture-corpus variant), `tests/run-all.sh` enumeration guard refusing unregistered suites, `SAFE_TEST_STRICT=1` making belt-not-run red; suite-to-surface mapping deliberately law-not-tooling until the mixed-era binary shape is ruled.
- [Mixed-era binary shape: safe-core sidecar vs Go dispatcher](https://superbiche.fibery.io/Superbiche/Tasks/123) — sidecar continues: one `safe-core` binary, lanes accrete as subcommands, bash dispatcher forwards via exec-passthrough (zero bash logic); exact `SAFE_VERSION` lockstep stays and extends to every migrated surface; capabilities stay statically advertised (lockstep makes them truthful); composite CLI path `safe audit binary-audit release-review`; a lane's migration slice replaces its bash implementation with the forward, so the parity belt holds through the unchanged CLI; Go dispatcher takeover deliberately left as fog.

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
