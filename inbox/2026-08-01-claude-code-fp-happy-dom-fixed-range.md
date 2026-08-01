# happy-dom BLOCKed although the resolved version is outside every advisory's affected range

**Date:** 2026-08-01
**Source:** Claude Code (reveille v1 slice H session)
**Affects:** safe audit OSV verdict logic

## What was observed

Command: `npm install -D @vue/test-utils happy-dom @vitejs/plugin-vue` (from `~/dev/personal/reveille`)

Refusal (verbatim):

```
[safe audit] checking happy-dom@latest (npm)
Socket:      PASS (no behavioral anomalies)
OSV:         WARN (3 known CVEs)
Blocklist:   PASS (not blocked)
VERDICT: BLOCK
safe: BLOCKED npm install of happy-dom@latest — safe audit verdict BLOCK; to allow: ask the operator to run: safe run host-allow add happy-dom@latest --reason "..." — then retry
```

## Evidence

Receipt: `~/.local/share/safe/audit/checks/2026-08-01-happy-dom-latest.json`

Resolved target (per the Socket section of the same receipt): `npm/happy-dom@20.11.1`.

All three OSV advisories carry fixed ranges BELOW the resolved version:

- GHSA-37j7-fg3j-429f (VM context escape → RCE): introduced 0, **fixed 20.0.0**
- GHSA-96g7-g7g9-jxw8 (script-tag server-side execution): introduced 0, **fixed 15.10.2**
- GHSA-w4gp-fjgq-3q4g (fetch credentials page-origin cookies): introduced 0, **fixed 20.8.9**

Expected: 20.11.1 ≥ every fixed bound → no advisory affects the resolved target → the OSV WARN should not escalate to BLOCK (or the WARN itself should not count these as hits on the target version).
Actual: VERDICT: BLOCK.

Possible confounder worth ruling on: the Socket section also reports an `obfuscatedFile` (high) supply-chain alert on 20.11.1 with `vulnerability: 100` and Socket line "PASS (no behavioral anomalies)" — if the BLOCK actually came from that alert rather than OSV, the printed check lines misattribute the cause.

Session impact: not blocked — the reveille UI test suite proceeded on `jsdom` instead; no allow was requested.

---

## Resolution — 2026-08-01, verified on `main` @ 6709468

Confirmed fixed by the version-aware verdict core (PR #29). Re-ran the same
check on current `main`:

```
$ safe audit check happy-dom --ecosystem npm --gate install
[safe audit] checking happy-dom (npm)

Resolved:    20.11.1 (dist-tag via https://registry.npmjs.org; range latest)
Socket:      PASS (no behavioral anomalies)
OSV:         PASS (no known advisories for 20.11.1)
Blocklist:   PASS (not blocked)

VERDICT: GO
[safe audit] recorded clean check: npm:happy-dom@20.11.1 (install-known)
```

Both parts of the report are answered:

- The spec is no longer fabricated as `happy-dom@latest`; the packument is
  resolved to `20.11.1` first, and OSV is queried for that version. All three
  advisories have fixed bounds at or below 20.11.1, so none affect the target
  and the verdict is GO — no operator round-trip, and the check is now recorded
  in `install-known`.
- The reported confounder does not fire: the Socket `obfuscatedFile` alert was
  never the BLOCK source. Socket is PASS here, and the printed lines were not
  misattributing.

The refusal in the original report came from a session running a stale gated
zsh snapshot (wrapper functions predating PR #29), not from current code —
the same shadowing that produced a false "shipped hard bug" report during the
#32 slice. Nothing further to fix.
