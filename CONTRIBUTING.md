# Contributing

This project is early-stage. Open an issue before opening a pull request, so the
scope and trust implications can be discussed first.

For code or documentation changes:

1. Fork the repository.
2. Create a branch from `main`.
3. Make the smallest focused change that solves the issue.
4. Run `safe audit repo-audit .` on your own changes.
5. Run any targeted tests or smoke checks relevant to the files changed.
6. Open a pull request.

This project is not exempt from its own zero-trust model. Clone it, inspect it,
scan it, and only then install or run it.

There is no CLA.

## Docs drift

Free-prose docs are bound to the code they describe with
[Fiberplane Drift](https://github.com/fiberplane/drift). Bindings live in
`drift.lock`; a fail-open pre-commit hook in `.githooks/` runs `drift check` and
blocks a commit whose bound code changed without the doc being reviewed. (This
is separate from `tests/contract/drift.sh`, which guards the structured
agent-contract pipeline.)

Enable the hook once per clone:

```bash
git config core.hooksPath .githooks
```

The hook is fail-open: with `drift` not installed it does nothing. When a bound
target changes, update the doc prose, then refresh provenance with
`drift link <doc> <target>` (or `drift link <doc> --doc-is-still-accurate` if the
prose already covers the change). Bypass once, if you must, with
`git commit --no-verify`.
