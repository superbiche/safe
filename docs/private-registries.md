# Private registries

Operator-managed trust for **owner-controlled private package registries**
(npm, Go and PyPI). After the operator authorizes a registry once, exact-pinned
installs of its packages run unattended through the normal entry points (the
PATH wrappers, `safe install`, `safe gate`). There is no per-install terminal
confirmation, and enforcement for every other package is unchanged.

## Model

The model has two parts:

- **Registry policy: the operator's authorization.** A registry declares
  that a namespace resolves **only** from one canonical origin, for example:
  - npm scope `@superbiche-private/*` resolves only from
    `https://git.superbiche.me:8443/api/packages/superbiche-packages/npm`;
  - Go module prefix `superbiche.me` resolves only from that host's `/go`
    proxy;
  - PyPI name `caviar-redact` resolves only from its `/pypi` index.
- **Pins: artifact integrity per exact version.** The lane records one pin for
  each version it installs. The pin holds the npm sha512 SRI, the Go module zip
  and `go.mod` `h1:` hashes, or the sha256 of **every** Python distribution
  file of that version (pip chooses a file per platform, so the whole set is
  bound). A registry's `pin_mode` decides who creates pins:
  - `tofu` (default): the first install records the pin, the way `go.sum`
    and lockfiles work;
  - `operator`: each version needs `safe run private-registry pin add` at a
    terminal first.

A name that matches a registry namespace is on the **private lane**. It never
reaches public evidence: OSV, Socket and public publish dates describe a public
namesake, and querying them would leak the private name. Instead the lane does
the following:

1. It binds the install to the origin. For npm, the effective
   `@scope:registry`, every lockfile `resolved` occurrence and the tarball URL
   must lie under the origin. For Python, an effective index must be under the
   origin, and no other index pip may consult (other effective sources, and
   PyPI) may serve the name. For Go, `go env` must route the module through
   the origin first, and `GONOPROXY`/`GOPRIVATE` must not send it straight to
   its VCS.
2. It checks the local blocklist, which remains a malice signal.
3. It compares the artifact the manager will install with the pin. When there
   is no pin yet, it fetches the artifact from the origin and confirms the
   bytes match before recording the TOFU pin.
4. It applies the registry's own `cooldown_days`. The default is `0` and is
   disclosed on the audit line.

Names outside the namespace are unaffected, even when the private origin
serves them: a public package keeps its ordinary audit when an operation names
it.

### Roots-only audit (pre-existing limitation) and the dependency-free rule

Safe audits the packages an operation names (and the project's lockfile or
module graph through the project scan); it does not audit, before delegation,
the dependencies a package manager resolves on its own while installing a
named package. That holds for public and private roots alike and predates
this feature. Because an unattended private allow would otherwise carry that
gap into an unattended install, exit 18 on an explicit spec requires an
install that fetches nothing beyond the checked root:

- pip, uv, pipx: `--no-deps` (pipx: inside `--pip-args`), `PIP_NO_DEPS`, or
  pip config `no-deps = true`;
- npm spec and `-g`: the exact version declares no `dependencies`, no
  `optionalDependencies` and no peer dependency npm would install (peers
  marked optional in `peerDependenciesMeta` do not count);
- `go install`/`go run mod@version`: the module's own `go.mod` requires
  nothing.

Otherwise the decision is 19 (`private_dependencies_unaudited`) with the
recovery: install the dependencies first as exact pins (each is audited), then
the private package without its dependencies — or, for npm and Go, use the
private package inside a project, whose lane checks the lockfile or module
graph. The project lanes decide every private entry they sweep; public entries
of a project's lockfile or module graph keep the project scan. Closure
planning (auditing every planned dependency before delegating, for public
roots too) is a tracked follow-up, not part of this lane.

Safe **never reads, stores or forwards a registry credential**. The lane runs
each ecosystem's own client, which uses its own credentials:

| Ecosystem | Client | Credential source |
| --- | --- | --- |
| npm | `npm view` | `.npmrc` token |
| Go | `go mod download` with a scratch module cache | `GOAUTH` (default `~/.netrc`) |
| Python | `curl --netrc-optional` | `~/.netrc`, or the inline credentials of the operator's own index URL |

Client errors are classified, never echoed, and every identity the lane prints
or stores goes through the credential-stripping canonical form.

## Install-gate outcomes

| Gate exit | Meaning | Unattended | Operator lane |
| --- | --- | --- | --- |
| 18 `ALLOWED_VIA_PRIVATE_REGISTRY` | origin binding holds and the integrity matches the pin (or was pinned on first use) | proceeds | n/a |
| 19 | operator decision needed: namespace claimed by two origins, operator pin missing, non-exact spec, version not on the registry, credentials missing or rejected, registry unreachable, inside the cooldown, the install would fetch dependencies safe does not audit, a project shape the lane does not model | refuses 102 with the reason and its remedy | `[y/N]` install once at a terminal |
| 20, class `private` | the pinned version's bytes changed, the version is revoked, signed pins disagree, or the artifact comes from another source (cross-registry substitution) | refuses 104 | typed `<name>@<version>` installs once; never recorded. A reviewed re-pin is `pin replace` |

Missing credentials and outages are labelled audit-infrastructure breakage,
never package findings. A plain `safe audit package-audit` of a private name
reports `VERDICT: PRIVATE` and exits 0, or 10/20 for the refusals. It never
reports `GO`.

Every allowed install writes one gate line to `~/.local/share/safe/run/audit.log`
naming the registry, origin, artifact and integrity:

```text
2026-10-10T18:00:00+02:00 | install:npm | @superbiche-private/x@1.2.3 | GATE | non-tty | ALLOWED_VIA_PRIVATE_REGISTRY | registry=superbiche-npm origin=https://git.superbiche.me:8443/api/packages/superbiche-packages/npm artifact=https://git.superbiche.me:8443/api/packages/superbiche-packages/npm/@superbiche-private%2Fx/-/1.2.3/x-1.2.3.tgz integrity=sha512-… pin=tofu-new cooldown=0
```

Each allow or refusal also writes a `private_registry` event to the verdict log
(`~/.local/share/safe/audit/audit-log.jsonl`). The `safe install` lane logs
`INSTALL_UNATTENDED_PRIVATE_REGISTRY`.

Where the lane runs — at every boundary that can materialize a private
identity, before the package manager is delegated to:

- **npm, explicit specs and `-g`.** The exact version's metadata comes from
  the real npm client (`npm view`; npm 12's one-element array answer and the
  older object answer are both read, several versions are refused), with the
  operator's selected `--userconfig`/`--globalconfig` kept in force.
- **npm projects (`install`, `ci`, `update`, `dedupe`, `prune`, with or without
  package arguments).** When the manifest, the lockfile or the argv names a
  private namespace, `npm ci` sweeps the lockfile as it stands and every other
  operation sweeps a `--package-lock-only` projection made in a scratch copy;
  every private entry of that lockfile (aliases included) must lie under the
  origin with exactly one sha512 integrity matching its pin (or be confirmed
  against the origin and pinned on first use). pnpm, yarn and bun lockfiles,
  npm workspace roots, and flags that redirect or disable the projected
  lockfile (`--prefix`, `--global`, `--package-lock=false`, a bare `--`) are
  not modelled: a private name there asks the operator (19). A project that
  names nothing private is untouched.
- **Python.** Explicit `pip`/`uv`/`pipx` specs. A find-links source (argv
  `--find-links`/`-f`, `PIP_FIND_LINKS`/`UV_FIND_LINKS`, pip config
  `find-links`) or `--no-index` is a BLOCK on the private lane: a flat file
  page cannot be probed for a namesake, and pip could take the private
  name's files from it. The fetch uses the operator's own index URL (with any
  inline credentials) and never prints it.
- **Go.** `go install mod@version` and `go run mod@version`. In addition,
  `go build|test|mod download|mod tidy` checks every module the operation can
  download that is on a private lane: the `go.mod` requirements (replace
  directives applied; a local-directory replace downloads nothing) and the
  `go.sum` entries. A missing `go.sum` line is never authorization — that
  module is confirmed against the origin and pinned on first use, and a
  revoked or changed one BLOCKs before Go downloads it. `go -C <dir>` is
  followed; `-modfile`, workspace mode (`go.work`) and `go.mod` files older
  than go 1.17 (which do not list the full module graph) ask the operator
  (19). Explicit `go mod download <module>@<version>` targets on a private
  lane are decided too, inside a module or not (a query such as `@latest`
  asks). Pre-existing gaps, public and private alike: `go get` is not gated,
  and neither is an explicit `go mod download <module>@<version>` of a public
  module; a private module fetched by `go get` is checked by the next build,
  download or tidy. A private module that `go mod tidy` adds from
  a new import is checked by the next such command, not by the tidy that adds
  it.

An npm integrity carrying two different sha512 digests is refused: npm would
accept bytes matching either.

## Commands

All changes require an operator terminal, are refused on a redirected trust
root, and are logged as `TRUST` lines.

```bash
safe run private-registry add <id> --ecosystem npm|go|python --origin <https-url> \
  --namespace <ns> [--namespace <ns>]... [--pin-mode tofu|operator] \
  [--cooldown-days N] [--owner <owner>] --reason "..."
safe run private-registry remove <id>
safe run private-registry list [--json]          # read-only; exits 1 on conflicts
safe run private-registry pins [--json]          # read-only
safe run private-registry pin add|replace|revoke <name>@<version> --ecosystem <eco>
safe run private-registry export [--sign [--out <dir>]]
safe run private-registry follow [--dry-run] [--from <dir>]
safe run private-registry forget-origin <host>
safe audit private-fetch <name>@<version> --ecosystem <eco>   # integrity the registry serves
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
- **`pin replace` and `pin revoke`** require the operator to type
  `<name>@<version>`.
- **Revocation.** A revoked version is refused even in `tofu` mode. Removing a
  registry withdraws its lane; its pins stay on disk as inert history.
- **`host-allow add`/`update` of a private name** (the `npx`/`safe run` host
  execution tier) take the integrity from the private registry and never fall
  back to the public registry.

Stores live beside `host-allow.json` and are honored only from the canonical
trust root (see [configuration](configuration.md#trust-is-anchored-to-the-canonical-root)):

```text
~/.config/safe/run/private-registries.json   # local policy (operator)
~/.config/safe/run/private-pins.json         # local pins (gate TOFU + operator)
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
  export, republishes `private-registries.<host>.json` and its `.asc`
  signature with every terminal change (`follow.auto_export`). The statement
  carries the host's **own** registries and pins (TOFU, operator and revoked)
  and nothing followed from elsewhere. It never carries a credential.
  - TOFU pins recorded by unattended installs cannot be signed when they are
    written. They are published by the next terminal change or by
    `safe run private-registry export --sign`.
- **Following.** `safe run host-allow follow` also follows private statements,
  so the existing follow timer and path units need no change.
  - Each verified statement **replaces** that origin's previous one in the
    local follow ledger. Unlike the host-allow union, an origin's removals and
    revocations therefore propagate.
  - Older generations are refused. An equal generation with different bytes is
    a collision and changes nothing. Unsigned, foreign-signed or tampered
    files are skipped (exit 1).
  - A missing file never revokes anything: sync gaps are not a signal.
- **Effective trust** combines local state with every followed origin whose
  signer is **still** pinned. `follow-signer remove` withdraws everything that
  key published at the next gate decision. Conflicts resolve as follows:
  - same namespace and origin from several sources: merged, with the strictest
    `pin_mode` and the longest cooldown;
  - same namespace on different origins: refused (19);
  - signed pins that disagree with each other, or with a local operator pin:
    BLOCK;
  - a signed pin always decides over a local TOFU pin.
- **New machine.** Install safe, pin the operator key
  (`safe run host-allow follow-signer add <fpr>`), and let the follow units
  run.

Provisioning outside safe is still needed on each machine: the package
manager's own credentials (`.npmrc` scope and token, `~/.netrc` entry for the
registry host and port) and the Go environment. Until credentials exist, the
lane refuses with `private_registry_auth_missing` (19) and names the fix.

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

- **Go:** use `GONOSUMDB=superbiche.me` with the Forgejo proxy first in
  `GOPROXY`:

  ```bash
  GOPROXY=https://git.superbiche.me:8443/api/packages/superbiche-packages/go,https://proxy.golang.org,direct
  ```

  Do not use `GOPRIVATE`: it also sets `GONOPROXY`, which sends the vanity
  path to its VCS instead of the proxy, and the lane refuses that route.
- **Python:** pip needs `--index-url
  https://git.superbiche.me:8443/api/packages/superbiche-packages/pypi/simple`
  (or the matching pip config), plus PyPI as an extra index for public
  dependencies. The lane refuses if PyPI ever serves a package of the same
  name.
