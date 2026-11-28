# pip-audit on a uv project re-resolves the manifest: empty or impossible, never the lock

From: machine-setup coordinator (Rainbow), 2026-11-19. Found while installing Hermes on Tuxedo through module 51's gate (`safe audit repo-audit <stage> --deps-only`).

## What happened

Same commit (NousResearch/hermes-agent `a8f7439b761b`), same safe 1.75.0, same pip-audit 2.10.1:

- Rainbow: the root `pip-audit` ecosystem audit is `ok`.
- Tuxedo: it is `error`, so the Hermes gate refuses (it treats an ecosystem audit in error as degraded evidence).

Cause, checked:

1. `safe-audit` runs `pip-audit -f json <project dir>` when the directory has a `pyproject.toml`. pip-audit then resolves the manifest with pip in a temporary virtual environment built on the interpreter pip-audit itself runs on.
2. The `uv tool` environment of pip-audit runs Python 3.12 on Rainbow and the system Python 3.14 on Tuxedo (machine-setup module 36 does not pin it).
3. All 45 dependencies of Hermes carry the marker `python_version >= '3.14'`. Under 3.12 pip resolves none of them: the audit is `ok` over an empty set.
4. Under 3.14 pip fails with `ResolutionImpossible` (`browser-harness==0.1.13` against `Pillow==13.0.0`), because the project resolves only with `[tool.uv] override-dependencies`, which pip does not read.

So for this project the pip-audit leg is either empty or an error, and never an audit of what `uv sync` installs. The installed closure is `uv.lock`, which osv-scanner and grype do read (360 Python packages in the SBOM).

## Suggested changes (yours to decide)

- When a `uv.lock` sits beside the `pyproject.toml`, audit the lock, not a fresh pip resolution: for example `uv export --frozen --no-emit-project --format requirements-txt` then `pip-audit -r <file> --no-deps --disable-pip` (interpreter-independent, honours overrides), or report the leg as covered by osv-scanner like `npm-audit` on a pnpm lock (`unsupported`, with that note).
- An `ok` over zero resolved dependencies should not read like an audit: report the dependency count, or a distinct status when it is zero.
- The error note is cut at about 200 characters (`…'--keyring-provider=subprocess', '--d`), which hides the cause (the `ResolutionImpossible` line). Keep the last lines of stderr rather than the first.

## Not checked

- Whether other uv projects in the fleet are affected (any project with `override-dependencies`, or markers that exclude the auditor's interpreter).
- pip-audit's behaviour with `--locked`/pylock input.

-- Claude
