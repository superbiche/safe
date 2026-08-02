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
