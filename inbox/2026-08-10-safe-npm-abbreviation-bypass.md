# npm command-prefix abbreviations bypass the gate's literal subcommand matching

**Date:** 2026-08-10
**Source:** PR #70 orthogonal review, finding F1 (sol/xhigh) — the finding was
scoped to the new dedupe/prune lane and fixed there in-slice; this note captures
the PRE-EXISTING sibling surface it exposed.
**Affects:** safe — gate-lib npm-lane subcommand classification (and any other
package manager whose CLI dispatches on unique prefixes)

## Observed

npm 12 resolves unique command prefixes via `abbrev` (npm
`lib/utils/cmd-list.js`). Verified live on npm 12.0.2:

- `npm inst --help` / `npm insta --help` → install
- `npm upd --help` / `npm updat --help` → update
- `npm unin --help` → uninstall

The gate's npm classification matches literal tokens only
(`install|i|it|install-test|add|ci|update|u|up|upgrade|udpate`,
`lib/gate-lib.sh` npm-lane set). Therefore `npm inst lodash` reaches the real
npm delegate with NO per-target audit — the same mechanism the PR #70 review
proved for `npm ded`/`npm pru` before the in-slice fix.

## Why it matters

The gate's install lane is the core promise on this fleet; a two-letter
truncation defeats it silently. Agents are unlikely to type `npm inst`, but the
hole is trivially discoverable and defeats the seatbelt for cooperative-but-
sloppy automation too.

## Suggested action

Same remedy shape as the lockdiff-lane fix: route tokens that are a prefix
(length ≥3, or the documented alias set) of a gated npm subcommand into that
subcommand's lane — the delegated argv keeps the user's original token, so
genuinely ambiguous prefixes still fail inside npm itself (fail closed).
Sweep the other gated tools for prefix/abbreviation dispatch semantics
(pnpm, yarn, bun, pip, uv, cargo, composer, mise) before assuming npm is the
only one.

## Resolution (2026-08-12)

Closed by PR #74 (safe 1.15.0). Live probes showed the hole was wider than
the note: npm dispatches via its hardcoded alias map (in/inst/isntall typo
aliases, clean-install/ic, the install-ci-test/cit family) PLUS generic
prefixes over commands AND alias keys (updat, exe, ad, dd) AND camelCase
normalization (installTest, cleanInstall); composer's symfony console
abbreviates the same way including the g..globa proxy prefixes.

npm: one classifier per tool consulted by every former literal site (gated
membership, exec dispatch, update-op selection, lockdiff) — exact alias
lookup first over the full npm map (alias priority: `c`→config, `un`→
uninstall stay passthrough), then len>=2 prefixes over canonical names and
gated alias keys, camelCase normalized to kebab before lookup; the delegate
always keeps the original token. Drift-guarded hermetically and by a live
oracle against the installed npm cmd-list.js (a 519-spelling mechanical
sweep found zero misses).

composer: operator-ruled FULL CANONICAL-OR-REFUSE (2026-08-11) after the
symfony abbreviation-surface mirror produced repeated review findings —
only exact install/update/require and exact global route; aliases (i/u/
upgrade/r) and every gated/global prefix refuse (case-insensitively, per
symfony's fallback) with a single line naming the canonical spelling and
the `composer run-script` escape hatch; exact non-gated commands and
rei*/rem* stay passthrough (a live oracle derives all installed command
names to prevent false refusals). Package-less require (top+global)
refuses — composer's interactive discovery selects the package after the
audit boundary; RequireCommand value-taking options are never audited as
packages; relative global --working-dir refuses; the global-home resolver
is Unix-only and env-spoof-proof.

Review: 4 rounds (initial + 3 deltas) + a targeted confirmation, all
sol/xhigh; the D339 two-fix-regression tripwire fired on the composer
surface and triggered the simplification that became the operator's
canonical-or-refuse ruling; the final round exceeded the nominal 4-round
cap under explicit operator authorization (the round-4 findings were
pre-existing perimeter gaps, not fix-caused churn). Chain archived at
~/.liaison/reviews/2026-08-11-safe-slice5-abbreviation/.

Sibling captured, out of scope: composer reinstall/create-project are
fetch-class and ungated (inbox/2026-08-11-safe-composer-ungated-fetch-commands.md).
Host tests/run-all.sh: all 21 suites green.
