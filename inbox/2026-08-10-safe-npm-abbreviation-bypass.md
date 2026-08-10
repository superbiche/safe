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
