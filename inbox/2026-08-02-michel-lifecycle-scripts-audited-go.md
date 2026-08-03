# Audited GO cannot authorize a required lifecycle script (manager-neutral)

**Date:** 2026-08-02
**Source:** michel (re-scoped by claude from the 2026-07-13 Volta capture, per operator ruling)
**Affects:** safe — npm-family install gate; any manager driving npm (mise npm backend, `npm i -g`, bun)

## Problem

`~/.npmrc` has `ignore-scripts=true`. A package whose functioning REQUIRES a
postinstall (e.g. opencode-ai fetching its platform binary) installs
"successfully" but broken: the entrypoint stays a placeholder, the operator
gets an exec error later, and nothing connects it to the skipped script. An
audited GO verdict currently has no way to say "this exact identity's
lifecycle scripts were reviewed — run them".

Originally observed through Volta (retired since); the gap is manager-neutral
and unfixed by v1.2.0 — the verdict/gate work never touches lifecycle
scripts.

## Proposal sketch (carried over from the original capture, Volta stripped)

Fail-closed, exact-identity only:

1. Require exact `package@version`; never names, ranges, or tags.
2. Tie authorization to the GO receipt for that identity (registry integrity
   + reviewed scripts), e.g. a `scripts_reviewed` marker on the
   install-known / receipt record.
3. After auditing and adopting npm 12, use per-command overrides so global
   `ignore-scripts=true` never changes:
   `NPM_CONFIG_IGNORE_SCRIPTS=false NPM_CONFIG_ALLOW_SCRIPTS='<pkg>@<ver>'
   NPM_CONFIG_STRICT_ALLOW_SCRIPTS=true npm i -g <pkg>@<ver>`
4. Fail if any transitive dependency carries an unapproved lifecycle script.
5. Verify the installed artifact (file type, reported version) before
   recording success.
6. npm 11 fallback stays explicit and package-specific: install with scripts
   disabled, then run only the audited script — no generic run-all hook.
7. Optional depth: bubblewrap-backed `script-shell` (clean env, hidden home,
   private /tmp, package-dir-only writes).

## References

- Original Volta-scoped capture: `2026-07-13-michel-volta-exact-postinstall-allowlist.md` (superseded)
- npm 12 `allow-scripts`: https://docs.npmjs.com/cli/v12/using-npm/config/#allow-scripts

## Resolution (2026-08-03)

Shipped in 1.5.0 (PR #52, merge d8cbe07; DEEP review chain
`~/.liaison/reviews/2026-08-03-safe-pr52-scripts-allow`, sol-xhigh, 4
rounds to the D339 cap + operator-ruled post-cap closure). Operator ruling
(a): grants are operator-TTY, machines never self-grant.

- `safe run scripts-allow add <pkg>@<x.y.z>` (TTY, exact identity only)
  displays the package's lifecycle scripts before confirmation — no
  sight-unseen grants — and snapshots scripts + registry integrity.
- Gated `npm install -g` of a granted identity injects npm 12's
  per-command policy (ignore-scripts=false, allow-scripts=<source-verified
  granted identities>, strict-allow-scripts=true): exactly the reviewed
  scripts run, unreviewed script-bearing deps hard-fail (sketch item 4),
  global ignore-scripts never changes (item 3). npm < 12: legible manual
  fallback (item 6).
- Script-policy argv/env overrides are refused/scrubbed on every gated
  route incl. mise; audit GO hints when a resolved version declares
  install scripts without a grant.

Deferred from the sketch: item 5 (post-install artifact verification) and
item 7 (bubblewrap script-shell). Related parked consideration:
`2026-08-03-claude-trust-store-hardening-consideration.md`.
npm 12 itself still pending on this host (Socket rate limit; the feature
degrades legibly on npm 11).
