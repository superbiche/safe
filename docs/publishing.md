# Publishing

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
