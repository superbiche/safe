# Private registries

Operator-managed trust for **owner-controlled private package registries**
(npm, Go and PyPI). After the operator registers a registry once, installs of
its packages run unattended through the normal entry points (the PATH
wrappers, `safe install`, `safe gate`). There is no per-install terminal
confirmation, and enforcement for every other package is unchanged.

## Model: trusted origins

The operator ruled (a37, 2026-10-10) that Safe trusts the operator's own
registry: a package fetched from it is treated **like a local artifact**. It
needs no OSV, CVE or Socket evidence, and there is no per-version pin ledger,
trust-on-first-use record, revocation list or integrity check.

A **registry** declares that a namespace resolves **only** from one canonical
origin, for example:

- npm scope `@superbiche-private/*` resolves only from
  `https://git.superbiche.me:8443/api/packages/superbiche-packages/npm`;
- Go module prefix `superbiche.me` resolves only from that host's `/go`
  proxy;
- PyPI name `caviar-redact` resolves only from its `/pypi` index.

A name that matches a registry namespace is on the **private lane**. It never
reaches public evidence: OSV, Socket and public publish dates describe a public
namesake, and querying them would leak the private name. Names outside the
namespace are unaffected, even when the private origin serves them.

### Guardrails

The trust label holds only because three guardrails stay in force:

1. **Origin binding.** The bypass applies only when the package manager would
   fetch the name from its registered origin. Otherwise the decision is a
   BLOCK (20, class `private`): cross-registry substitution, or a public
   namesake. Safe asks the manager or controls it, rather than modelling its
   configuration:
   - **npm.** npm's own answer to `npm config get @scope:registry`, in the
     command's directory and with its `--userconfig`/`--globalconfig` and argv
     scope selectors, must lie under the origin. Every lockfile entry whose
     install path, declared `name` or alias target (`npm:@scope/x@v`) is in a
     namespace must have its `resolved` URL under the origin, because npm
     fetches lockfile entries from `resolved`. This holds for v1, v2 and v3
     lockfiles.
   - **Go.** One `go env` in the command's context (`go -C` followed, the go
     env file included) must route each registered namespace to its origin.
     Local `file://` GOPROXY entries may come first: they are local
     artifacts, so the check walks past them. The first other entry must be
     the origin; any other proxy, `direct`, or `GONOPROXY`/`GOPRIVATE`
     covering the namespace ahead of it BLOCKs. Go fetches every module of
     that path prefix through this routing, whatever the module graph,
     workspace, replace or build tag. Entries after the origin are a
     documented residual (see [Known limitations](#known-limitations)).
   - **Python.** For `pip install` and `uv pip install` of explicit specs,
     Safe controls the configuration. When the lane allows a private name,
     the gate runs the installer with its configuration switched off
     (`PIP_CONFIG_FILE=/dev/null`, `UV_NO_CONFIG=1`) and without the source
     environment (`PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`,
     `PIP_NO_INDEX`, and the `UV_*` index, find-links, no-index and config
     variables). The command line is then the whole source set:
     - one argv index must lie under the origin;
     - every other argv index, and PyPI (pip's default when `--index-url`
       does not replace it), is probed and must not serve the name;
     - argv `--find-links` or `--no-index` BLOCKs.
2. **Everything else is unchanged.** Public packages in the same command keep
   today's audit. A command mixing public and private specs gives the private
   specs the bypass and the public specs their normal audit, and the
   strictest outcome wins.
3. **Audit trail.** Every bypass writes one gate line naming the registry,
   origin, name and version (see below).

The local blocklist still applies to private names: explicit specs, private
npm lockfile entries and names an npm project operation names, and every
private Go module a command names (download targets, and the requirements and
remote `replace` destinations of the selected module context and `go.work`).

An observed source (a lockfile `resolved` URL, a scope registry, an argv
index, a GOPROXY entry) counts as under an origin only on its literal path:
one with a `.` or `..` segment, literal or percent-encoded, or a backslash,
never does, because the client would fetch a normalized path elsewhere.

### Trust perimeter

Trust covers the bytes the registered origin serves **and every URL the
origin server itself directs the client to**: npm tarball links in its
metadata, simple-index file links, and HTTP redirects. Safe does not check
those destinations separately. The operator's Forgejo keeps its package
storage local (`FORGEJO__packages__STORAGE_TYPE=local` in the infra
manifests), so its artifacts and redirects stay on the origin.

### Roots-only audit (pre-existing limitation)

Safe audits the packages an operation names, and a project's lockfile or
module graph through the project scan. It does not audit, before delegation,
the dependencies a package manager resolves on its own while installing a
named package. That holds for public and private roots alike and predates this
feature. A private root is treated like any public root that passes its audit:
its dependencies are fetched by the manager without a Safe decision. Closure
planning (auditing every planned dependency before delegating) is a tracked
follow-up: [Superbiche/Tasks/752](https://superbiche.fibery.io/Superbiche/Tasks/752).

### Credentials

Safe **never reads, stores or forwards a registry credential**. The package
manager fetches with its own credentials: npm's `.npmrc` token, Go's `GOAUTH`
(default `~/.netrc`), pip's and uv's `~/.netrc` or the inline credentials of
the argv index URL. Under the Python isolation a credential kept in a pip or
uv configuration file is not read, so use `~/.netrc` or the index URL. The lane
itself makes no registry request, apart from the Python namesake probe of the
other argv indexes and PyPI. A missing credential surfaces as the manager's
own error. Every identity the lane prints goes through the
credential-stripping canonical form.

## Install-gate outcomes

| Gate exit | Meaning | Unattended | Operator lane |
| --- | --- | --- | --- |
| 18 `ALLOWED_VIA_PRIVATE_REGISTRY` | the manager fetches the name from its registered origin | proceeds | n/a |
| 19 | operator decision needed: the namespace is claimed by two origins, the spec is not one exact version, the manager or its configuration route is not modelled (bun, `uv run --with`, `uv tool`, mise `pipx:`, a requirements file, `uv --config-file`, pnpm/yarn/bun projects, npm workspace roots, lockfile-redirecting flags), a lockfile entry carries no `resolved` URL or is bundled, or the client could not answer | refuses 102 with the reason and its remedy | `[y/N]` install once at a terminal |
| 20, class `private` | the manager would fetch the name from somewhere other than its origin: scope mapped elsewhere or not at all, a lockfile entry resolved elsewhere, a Go route ahead of the origin, no argv index at the origin, another index or PyPI serving the name, argv find-links or `--no-index` | refuses 104 | typed `<name>@<version>` installs once; never recorded |

A plain `safe audit package-audit` of a private name reports `VERDICT: PRIVATE`
and exits 0, or 10/20 for the refusals. It never reports `GO`.

Every allowed install writes one gate line to
`~/.local/share/safe/run/audit.log`:

```text
2026-10-10T18:00:00+02:00 | install:npm | @superbiche-private/x@1.2.3 | GATE | non-tty | ALLOWED_VIA_PRIVATE_REGISTRY | registry=superbiche-npm origin=https://git.superbiche.me:8443/api/packages/superbiche-packages/npm name=@superbiche-private/x version=1.2.3
```

The format of that line depends on the operation:

- **Explicit specs** name their exact version.
- **npm project operations** log one line per private lockfile entry.
- **npm project operations** also log a line for a private name the operation
  names that has no lockfile entry yet (a first install, a new dependency):
  `version=unknown command=npm-<operation>`.
- **Go commands** add `route=` with the GOPROXY entries up to the origin.
  When a `file://` entry comes first, Safe cannot know beforehand which entry
  serves a version, so the line names the route rather than claiming the
  origin served the bytes. A Go project command logs one line per namespace
  requirement of the context Go selects (every module of an active
  `go.work`, else the `-modfile` from argv or `GOFLAGS`, else the module root
  above the working directory) and per explicit
  `go mod download <module>@<version>` target. Every registered namespace
  with no such identity (a first `go mod tidy`, a new import, an absent or
  unreadable module file, a public-only project) gets the fallback line
  `name=<namespace> version=unknown ... command=go-<subcommand>`. An allow
  that reaches the gate without a complete line is refused as
  audit-infrastructure breakage.

Each allow or refusal also writes a `private_registry` event to the verdict log
(`~/.local/share/safe/audit/audit-log.jsonl`). The `safe install` lane logs
`INSTALL_UNATTENDED_PRIVATE_REGISTRY`.

## Where the lane runs

The lane runs before the package manager is delegated to:

- **npm, explicit specs and `-g`.** The scope mapping check. With the lock-diff
  lane (`dedupe`, `prune`), the projected lockfile entries of the name are
  checked too.
- **npm projects (`install`, `ci`, `update`, `dedupe`, `prune`).** On a host
  with an npm private registry, two checks run:
  - **Scope mapping (ruling a43).** Every registered scope must map to its
    origin. A scope mapped elsewhere or not mapped at all BLOCKs every npm
    project operation (`install`, `ci`, ...), whether or not it names a
    private package: an unmapped scope would let a private package a public
    dependency newly pulls in resolve from the default registry.
    Provisioning (machine setup, the user `.npmrc`) writes the mapping.
    Claiming the `@superbiche-private` organisation on npmjs is an
    operator-side complement that keeps the public namespace from being
    squatted; Safe does not depend on it.
  - **Lockfile.** Every private entry of the current lockfile must resolve
    under its origin. New resolutions take the checked scope mapping.

  A private name in a pnpm, yarn or bun project, in an npm workspace root, or
  behind a lockfile-redirecting flag (`--prefix`, `--global`,
  `--package-lock=false`, a bare `--`) asks (19).
- **Python.** `pip install` and `uv pip install` of explicit specs, with the
  isolation above. A private name reached any other way asks (19). That
  includes requirement and constraint files: Safe walks their `-r`/`-c`
  includes (`-r`, `-c`, `--requirement`, `--constraint`, with any whitespace
  or `=`; relative to the including file; at most 64 files and 16 levels;
  cycle-safe). A private name there asks. So does a file set it cannot fully
  inventory: an unreadable, remote or out-of-bounds include, a line using
  `${VAR}` expansion, a direct URL requirement, a remote editable, an option
  it does not model, or an unrecognized line. Local paths and local
  editables are local artifacts. Use the explicit form:

  ```bash
  pip install --index-url <origin>/simple <name>==<version>
  ```

- **Go.** `go install|run <module>@<version>` checks the routing for the named
  module. Every module-downloading command checks the routing of every
  registered namespace in its own context: `go build`, `test`, `vet`, `list`,
  a local `go run`/`go install`, and
  `go mod download|tidy|vendor|graph|why|verify`.

## Known limitations

- **Roots-only audit.** Dependencies a package manager resolves beside a named
  root, private or public, are not audited before delegation:
  [Superbiche/Tasks/752](https://superbiche.fibery.io/Superbiche/Tasks/752).
- **pnpm, yarn and bun resolution.** A private name visible in the manifest,
  the npm lockfile or the argv asks the operator (19). A private package one
  of these managers would newly resolve behind a public one is fetched
  through that manager's own scope configuration, which Safe checks only for
  npm. This is accepted while no pnpm/yarn/bun project consumes a private npm
  namespace. The trigger is a pnpm/yarn/bun project that adds or resolves
  such a package; it then needs fail-closed handling or a resolution check:
  [Superbiche/Tasks/755](https://superbiche.fibery.io/Superbiche/Tasks/755).
- **Go routing on every module command (ruling a41).** While a Go private
  registry is registered, locally or through follow, every
  module-downloading Go command on the host checks the routing, public-only,
  cached and vendored projects included. The costs:
  - A host whose GOPROXY does not route the namespace to the origin BLOCKs
    Go commands until it is provisioned (or uses a `file://`/`off`
    local-only route).
  - A project that overrides GOPROXY for itself (in its environment or
    tooling) BLOCKs on such a host.
  - Two Go namespaces registered on different origins cannot both come
    first, so every module command BLOCKs.
- **Go proxies after the origin (ruling a42, residual).** Go moves on to the
  next GOPROXY entry when the origin lacks a version: on 404/410 after a
  comma, on any error after a pipe. A later public proxy or `direct` can then
  serve a private module version the origin does not have, under the
  origin's allow line. This is reachable only while a Go private namespace is
  registered. Caviar, the only module under `superbiche.me/`, is going public
  on `github.com/superbiche/caviar`; once Memoire migrates, the Go private
  registry leaves the machine configuration and the routing rule goes
  dormant.
- **`go get` and public explicit `go mod download`** are not gated:
  [Superbiche/Tasks/753](https://superbiche.fibery.io/Superbiche/Tasks/753).

## Commands

All changes require an operator terminal, are refused on a redirected trust
root, and are logged as `TRUST` lines.

```bash
safe run private-registry add <id> --ecosystem npm|go|python --origin <https-url> \
  --namespace <ns> [--namespace <ns>]... [--owner <owner>] --reason "..."
safe run private-registry remove <id>
safe run private-registry list [--json]          # read-only; exits 1 on conflicts
safe run private-registry export [--sign [--out <dir>]]
safe run private-registry follow [--dry-run] [--from <dir>]
safe run private-registry forget-origin <host>
```

Rules for the policy fields:

- **Origin.** Origins are canonical `https` URLs. The port is part of the
  identity, and an origin carries no userinfo, query or fragment. Plain
  `http` is accepted only for a loopback host.
- **Namespace.** The accepted forms depend on the ecosystem:
  - npm: `@scope/*` or `@scope/name`;
  - Go: a literal module path prefix starting with a domain (no globs);
  - Python: one exact distribution name per entry, because PyPI has no
    namespaces and a pattern would amplify dependency confusion.
- **Overlaps.** Two registries whose namespaces overlap with different origins
  are refused at `add`. If they meet through fleet propagation, they fail
  closed (19).
- **Removing a registry** withdraws its lane.
- **`host-allow add`/`update` of a private name** (the `npx`/`safe run` host
  execution tier) is refused. The origin is trusted already, and the public
  registry's integrity would describe another artifact.

Stores live beside `host-allow.json` and are honored only from the canonical
trust root (see [configuration](configuration.md#trust-is-anchored-to-the-canonical-root)):

```text
~/.config/safe/run/private-registries.json   # local policy (operator), schema safe-private-registries/2
~/.config/safe/run/private-follow-state.json # followed statements (follow)
```

`install.trusted_registries` keeps its meaning: it treats a source like the
public registry, so public evidence still applies. Do not use it for a private
registry. A namespace on a private lane is decided by that lane whatever
`trusted_registries` says.

## Fleet propagation

Private-registry trust uses the same signed channel as the host-allow grants:
the `~/Sync/state/safe/` directory, the same `follow.signing_key`, the same
`follow.signers` pins, and the same isolated-keyring verifier.

- **Publishing.** An origin, meaning a host that already publishes a signed
  export, republishes `private-registries.<host>.json` (schema
  `safe-private-registries-export/2`) and its `.asc` signature with every
  terminal change (`follow.auto_export`). The statement carries the host's
  **own** registries and nothing followed from elsewhere. It never carries a
  credential.
- **Following.** `safe run host-allow follow` also follows private statements,
  so the existing follow timer and path units need no change.
  - Each verified statement **replaces** that origin's previous one in the
    local follow ledger. Unlike the host-allow union, an origin's removals
    therefore propagate.
  - Older generations are refused. An equal generation with different bytes is
    a collision and changes nothing. Unsigned, foreign-signed or tampered
    files are skipped (exit 1).
  - A missing file never revokes anything: sync gaps are not a signal.
- **Effective trust** combines local state with every followed origin whose
  signer is **still** pinned. `follow-signer remove` withdraws everything that
  key published at the next gate decision. The same namespace and origin from
  several sources merge; the same namespace on different origins is refused
  (19).
- **New machine.** Install safe, pin the operator key
  (`safe run host-allow follow-signer add <fpr>`), and let the follow units
  run.

Each machine still needs provisioning outside Safe:

- the package manager's own credentials: the `.npmrc` scope and token, and a
  `~/.netrc` entry for the registry host and port;
- the npm scope mapping and the Go environment (below).

Until these exist, the npm and Go checks BLOCK and name the fix, and the
managers report their own authentication errors.

## Setting up the Forgejo registries

On the origin host, at an operator terminal:

```bash
safe run private-registry add superbiche-npm --ecosystem npm \
  --origin https://git.superbiche.me:8443/api/packages/superbiche-packages/npm \
  --namespace '@superbiche-private/*' --owner superbiche-packages --reason "own Forgejo npm registry"
safe run private-registry add superbiche-go --ecosystem go \
  --origin https://git.superbiche.me:8443/api/packages/superbiche-packages/go \
  --namespace superbiche.me --owner superbiche-packages --reason "own Forgejo Go proxy"
safe run private-registry add superbiche-pypi --ecosystem python \
  --origin https://git.superbiche.me:8443/api/packages/superbiche-packages/pypi \
  --namespace caviar-redact --owner superbiche-packages --reason "own Forgejo PyPI registry"
```

Then configure each client:

- **npm:** map the scope in `.npmrc` (required: without it every npm project
  operation on the host BLOCKs):
  `@superbiche-private:registry=https://git.superbiche.me:8443/api/packages/superbiche-packages/npm/`.
- **Go:** use `GONOSUMDB=superbiche.me` with the Forgejo proxy first in
  `GOPROXY`. Local `file://` module trees may come before it:

  ```bash
  GOPROXY=https://git.superbiche.me:8443/api/packages/superbiche-packages/go,https://proxy.golang.org,direct
  ```

  Do not use `GOPRIVATE`: it also sets `GONOPROXY`, which sends the vanity
  path to its VCS instead of the proxy, and the lane refuses that route.
- **Python:** pass the index on the command line, plus PyPI as an extra index
  for public dependencies:

  ```bash
  pip install --index-url https://git.superbiche.me:8443/api/packages/superbiche-packages/pypi/simple \
    --extra-index-url https://pypi.org/simple caviar-redact==<version>
  ```

  The lane refuses if PyPI ever serves a package of the same name.
