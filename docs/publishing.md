# Publishing

## Release Artifacts

`safe` releases are manual until the release process is proven. A release must
be consumer-verifiable before it is published.

Release baseline:

- signed annotated tag `vX.Y.Z`;
- immutable GitHub Release;
- `safe-vX.Y.Z.tar.gz`;
- `SHA256SUMS`;
- `SHA256SUMS.sigstore.json`.

Prepare release metadata and commit it:

```bash
scripts/release check
git add VERSION CHANGELOG.md
git commit -m "Release vX.Y.Z"
```

Create the signed tag:

```bash
git tag -s vX.Y.Z -m "vX.Y.Z"
```

Create release assets from the signed tag:

```bash
scripts/release package
```

Sign the checksum file:

```bash
scripts/release sign-checksums
```

Verify local outputs:

```bash
scripts/release verify-checksums
COSIGN_VERIFY_ARGS="--certificate-identity-regexp REGEXP --certificate-oidc-issuer ISSUER" \
  scripts/release verify-signature
```

Upload these release assets:

```text
dist/safe-vX.Y.Z.tar.gz
dist/SHA256SUMS
dist/SHA256SUMS.sigstore.json
```

Release notes must include checksum and signature verification commands:

```bash
sha256sum -c SHA256SUMS
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp REGEXP \
  --certificate-oidc-issuer ISSUER \
  SHA256SUMS
```

CI provenance is not claimed for manual releases.

## Documentation

The docs are built with MkDocs and published to GitHub Pages with Mike. Mike
keeps multiple versions on the `gh-pages` branch and writes the `versions.json`
metadata that the `superbiche` theme uses for its version selector.

## Setup

Install the local docs toolchain from the repository root:

```bash
scripts/docs deps
```

This installs MkDocs, Mike, and the local `superbiche` theme package.

## Local Builds

Build the current docs:

```bash
scripts/docs build
```

Serve the current docs:

```bash
scripts/docs serve
```

Serve the versioned `gh-pages` output locally:

```bash
scripts/docs mike-serve
```

## Publish

Publish a new release version and move the `latest` alias:

```bash
scripts/docs deploy-latest 0.1
```

Publish an additional named version without changing `latest`:

```bash
scripts/docs deploy dev
```

Set the root redirect:

```bash
scripts/docs set-default latest
```

List deployed versions:

```bash
scripts/docs list
```

## GitHub Pages

Configure GitHub Pages to serve from the `gh-pages` branch. The published site
URL is:

```text
https://superbiche.github.io/safe/
```

The root URL redirects to the version selected with `scripts/docs set-default`.
