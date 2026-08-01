# `safe install` inside the sandbox fails with a raw `EAI_AGAIN` and no hint

**Date:** 2026-07-17
**Source:** operator terminal
**Affects:** `safe install` / `safe run install` sandbox UX

## What was observed

```
➜ safe install @opentelemetry/sdk-node@0.219.0
safe run: secret-like files in project dir: .env
safe run:   the sandboxed package will be able to read them through the project mount
safe run:   pass -s/--allow-secrets to allow this without a prompt
  Continue and expose these files? [y/N] y
npm error code EAI_AGAIN
npm error syscall getaddrinfo
npm error errno EAI_AGAIN
npm error request to https://registry.npmjs.org/@opentelemetry%2fsdk-node failed, reason: getaddrinfo EAI_AGAIN registry.npmjs.org
npm error A complete log of this run can be found in: /root/.npm/_logs/2026-07-16T22_35_34_026Z-debug-0.log
```

## Diagnosis — 2026-08-01

Not a bug in the sandbox, a legibility gap. The sandbox is strict by default:
`bin/safe-run:1911` adds `--network=none` unless `ALLOW_NETWORK=1`, which only
`-n, --network` sets (`bin/safe-run:1861`). So npm resolves nothing, and the
operator sees the registry's DNS failure with no indication that safe is the
one that cut the network.

Worse for the specific case: the run had already prompted about `.env`
exposure and been approved, so the failure lands after an interactive yes —
it reads as "safe broke my install", not "safe needs a flag".

## Proposed fix (not implemented — PR-worthy, not housekeeping)

Two cheap moves, either or both:

1. Say it up front. When a sandboxed install starts with the network disabled,
   print one line before handing off to npm: strict sandbox, no network,
   `-n` to allow it.
2. Say it after. A network-class failure (`EAI_AGAIN`, `ENOTFOUND`,
   `ECONNREFUSED` against a registry host) inside a `--network=none` sandbox
   is diagnosable — trailer the child's exit with the cause and the `-n`
   recovery, same shape as the refusal contract elsewhere.

Belongs with the agent-legibility family (cf. the `npm` shim silent-127 note).
