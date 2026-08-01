# Make audited Volta installs selectively run exact-version lifecycle scripts

**Date:** 2026-07-13
**Source:** michel (Volta/OpenCode failure investigation)
**Affects:** safe — npm package audit and approved-install workflow

## Observed

`~/.npmrc` has `ignore-scripts=true`. After a `safe audit` GO verdict, `volta install opencode-ai@1.17.18` installed OpenCode but skipped its required `postinstall.mjs`. The package entrypoint remained a 479-byte placeholder without a shebang, so Volta failed with `Exec format error (os error 8)`. Explicitly running the reviewed `postinstall.mjs` repaired it.

Volta 2.0.2 has no package post-install event hook; its documented hooks only customize Node/npm/Yarn distribution downloads. npm 11.14.1 also has no selective lifecycle-script allowlist. npm 12 introduces `allow-scripts` and `strict-allow-scripts` for exact package identities in global/one-off install contexts.

## Why it matters

Keeping lifecycle scripts globally disabled is valuable, but an audited GO verdict currently cannot authorize a required script. This can produce an apparently successful yet broken Volta install. Temporarily enabling every lifecycle script would weaken the audit boundary and could execute unaudited transitive scripts.

A sandbox is defense-in-depth, not the trust decision: a postinstall can generate the executable that will later run outside the sandbox with normal user access.

## Suggested action

Implement a fail-closed audited Volta install path in `safe`:

1. Require an exact `package@version`; reject `@latest`, ranges, and name-only approvals.
2. Emit or consume a machine-readable GO receipt tied to the exact package version, registry integrity, and reviewed lifecycle scripts.
3. After separately auditing and adopting npm 12, invoke Volta only for the approved identity with per-command overrides, leaving global `ignore-scripts=true` unchanged:

   ```bash
   NPM_CONFIG_IGNORE_SCRIPTS=false \
   NPM_CONFIG_ALLOW_SCRIPTS='opencode-ai@1.17.18' \
   NPM_CONFIG_STRICT_ALLOW_SCRIPTS=true \
   volta install opencode-ai@1.17.18
   ```

4. Fail if any transitive dependency has an unapproved lifecycle script.
5. Verify the resolved Volta package metadata, executable file type, and reported version before recording success.
6. Optionally pass lifecycle scripts through a `bubblewrap`-backed `script-shell`: clear the environment, hide the real home, use a private `/tmp`, mount the system read-only, and permit writes only to the installed package directory. Treat network access as exceptional; OpenCode currently may need it to fetch its version-pinned platform package.
7. Keep the npm 11 fallback explicit and package-specific: install with scripts disabled, then execute only the audited lifecycle script. Do not build a generic hook that automatically runs every skipped script.

## References

- npm 12 `allow-scripts`: https://docs.npmjs.com/cli/v12/using-npm/config/#allow-scripts
- npm 12 `npm approve-scripts`: https://docs.npmjs.com/cli/v12/commands/npm-approve-scripts/
- Volta hooks scope: https://docs.volta.sh/advanced/hooks
