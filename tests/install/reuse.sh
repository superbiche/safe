#!/usr/bin/env bash
# safe install --reuse: reuse of already-installed Composer dependencies in a
# worktree (operator ruling 2026-09-30). Real git checkouts and a real copy;
# php and the lockfile audit are fixtures on PATH / SAFE_AUDIT_PATH. Nothing
# here reaches a registry: the operation itself never does.

set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck disable=SC1091
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
safe_test_setup_isolation || exit 1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE="$ROOT/bin/safe"

PASS_COUNT=0
pass() { printf 'ok - %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

for tool in git jq sha256sum realpath python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required command: $tool"
done
bash -n "$SAFE" || fail "bin/safe syntax"

tmp="$(mktemp -d)"
safe_test_compose_exit_trap "rm -rf \"\$tmp\""
tmp="$(realpath -e -- "$tmp")"

# The canonical run store of the scratch HOME carries the per-host rule.
export SAFE_RUN_CONFIG_DIR="$HOME/.config/safe/run" SAFE_RUN_TRUST_OVERRIDE=0
export SAFE_DATA_DIR="$tmp/data" SAFE_RUN_DATA_DIR="$tmp/data/run"
mkdir -p "$SAFE_RUN_CONFIG_DIR" "$SAFE_DATA_DIR"
rule() { printf '{"install":{"reuse":{"enabled":%s}}}\n' "$1" > "$SAFE_RUN_CONFIG_DIR/config.json"; }
rule true

# --- fixtures ------------------------------------------------------------------
mkdir -p "$tmp/bin"
# php: identity comes from a .php-identity file in the directory it runs in
# (what a per-directory version manager does); a platform check fails when the
# checked file carries the marker.
cat > "$tmp/bin/php" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == "-r" ]]; then
  if [[ -f .php-identity ]]; then cat .php-identity; else printf '8.5.10 Core,json,mbstring'; fi
  exit 0
fi
grep -q 'PLATFORM_ISSUE' "$1" 2>/dev/null && exit 255
exit 0
STUB
# The lockfile audit: verdict and counts from the environment, and a log of
# every call so "no package manager, no install" stays observable.
cat > "$tmp/bin/safe-audit-stub" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$AUDIT_CALLS"
[[ "${1:-}" == "repo-audit" ]] || exit 0
[[ "${STUB_SCAN_FAIL:-0}" == "1" ]] && exit 3
out="" prev=""
for arg in "$@"; do [[ "$prev" == "--result-out" ]] && out="$arg"; prev="$arg"; done
printf '{"verdict":"%s","summary":{"packages_total":3},"cve_scan":{"critical":%s,"high":%s,"medium":0,"low":0},"audit_totals":{"critical":%s,"high":%s,"medium":0,"low":0}}\n' \
  "${STUB_VERDICT:-GO}" "${STUB_CRITICAL:-0}" "${STUB_HIGH:-0}" "${STUB_CRITICAL:-0}" "${STUB_HIGH:-0}" > "$out"
STUB
# Any package manager reaching PATH is a test failure by itself.
for manager in composer npm; do
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$0 $*" >> "%s/manager-calls"\nexit 97\n' "$tmp" > "$tmp/bin/$manager"
done
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH" SAFE_AUDIT_PATH="$tmp/bin/safe-audit-stub" AUDIT_CALLS="$tmp/audit-calls"
: > "$AUDIT_CALLS"

LOCK='{"content-hash":"abc","packages":[{"name":"acme/runtime","version":"1.2.0"},{"name":"acme/spreadsheet","version":"3.10.0"}],"packages-dev":[{"name":"acme/pest","version":"4.0.1"}]}'
INSTALLED='{"packages":[{"name":"acme/runtime","version":"1.2.0","install-path":"../acme/runtime"},{"name":"acme/spreadsheet","version":"3.10.0","install-path":"../acme/spreadsheet"},{"name":"acme/pest","version":"4.0.1","install-path":"../acme/pest"}],"dev":true,"dev-package-names":["acme/pest"]}'

git_q() { git -c init.defaultBranch=main -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@" >/dev/null 2>&1; }

# make_repo <name>: a main checkout with an installed vendor/, plus a linked
# worktree of the same commit with none.
make_repo() {
  local name="$1" main="$tmp/$1/main" wt="$tmp/$1/wt" pkg
  mkdir -p "$main"
  git_q -C "$main" init || fail "git init"
  printf '{"name":"acme/app","require":{"acme/runtime":"^1.2"}}\n' > "$main/composer.json"
  printf '%s\n' "$LOCK" > "$main/composer.lock"
  printf 'vendor/\n.php-identity\n' > "$main/.gitignore"
  git_q -C "$main" add -A && git_q -C "$main" commit -m init || fail "git commit"
  for pkg in runtime spreadsheet pest; do
    mkdir -p "$main/vendor/acme/$pkg/src"
    printf '<?php // %s\n' "$pkg" > "$main/vendor/acme/$pkg/src/Main.php"
  done
  mkdir -p "$main/vendor/composer" "$main/vendor/bin"
  printf '%s\n' "$INSTALLED" > "$main/vendor/composer/installed.json"
  printf '<?php // generated platform check\n' > "$main/vendor/composer/platform_check.php"
  printf '<?php return require __DIR__ . "/composer/autoload_real.php";\n' > "$main/vendor/autoload.php"
  ln -s ../acme/pest/src/Main.php "$main/vendor/bin/pest"
  git_q -C "$main" worktree add "$wt" -b "wt-$name" || fail "git worktree add"
  MAIN="$main" WT="$wt"
}

# reuse <dir> [args...]: runs the command in <dir>, non-interactive.
reuse() {
  local dir="$1"
  shift
  RC=0
  ( cd "$dir" && "$SAFE" install --reuse "$@" ) > "$tmp/out.txt" 2> "$tmp/err.txt" </dev/null || RC=$?
}
expect_refusal() {
  local code="$1" fragment="$2" label="$3"
  [[ "$RC" == "$code" ]] || { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "$label: expected exit $code, got $RC"; }
  grep -Fq -- "$fragment" "$tmp/err.txt" || { cat "$tmp/err.txt" >&2; fail "$label: refusal lacks '$fragment'"; }
  [[ "$(wc -l < "$tmp/err.txt")" == "1" ]] || { cat "$tmp/err.txt" >&2; fail "$label: a refusal is one stderr line"; }
  grep -Fq 'safe explain' "$tmp/err.txt" || fail "$label: refusal lacks the safe explain pointer"
  [[ ! -e "$WT/vendor" ]] || fail "$label: a refusal left a vendor/ behind"
  compgen -G "$WT/vendor.safe-reuse.*" >/dev/null && fail "$label: a refusal left a staging directory behind"
  pass "$label"
}
gate_log() { cat "$SAFE_RUN_DATA_DIR/audit.log" 2>/dev/null; }

# --- the Vacation case: adverse lockfile, identical tree in the main checkout --
make_repo adverse
STUB_VERDICT=BLOCK STUB_CRITICAL=2 STUB_HIGH=20 reuse "$WT"
[[ "$RC" == "0" ]] || { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "adverse reuse failed (rc=$RC)"; }
diff -r "$MAIN/vendor" "$WT/vendor" >/dev/null || fail "the copied tree differs from the source"
[[ -L "$WT/vendor/bin/pest" && "$(readlink "$WT/vendor/bin/pest")" == "../acme/pest/src/Main.php" ]] ||
  fail "a relative link did not survive the copy"
grep -Fq 'status:    reused-existing-vendor-with-known-risks' "$tmp/out.txt" || fail "adverse reuse does not carry its status"
grep -Fq 'verdict BLOCK — critical 2, high 20' "$tmp/out.txt" || fail "the inherited verdict is not printed"
grep -Fq "source:    $MAIN" "$tmp/out.txt" || fail "the source checkout is not named"
grep -Fq 'not evidence of a clean audit' "$tmp/err.txt" || fail "adverse reuse lacks its stderr notice"
pass "an adverse lockfile reuses the resident tree unattended, as reused-existing-vendor-with-known-risks"

receipt="$(sed -n 's/^  receipt:   //p' "$tmp/out.txt")"
[[ -s "$receipt" ]] || fail "no receipt was written"
jq -e --arg s "$MAIN" --arg t "$WT" --arg sha "$(sha256sum "$WT/composer.lock" | cut -d' ' -f1)" '
  .operation == "reuse" and .ecosystem == "composer"
  and .status == "reused-existing-vendor-with-known-risks"
  and .authorized_by == "install.reuse.enabled"
  and .source == $s and .target == $t and .lockfile.sha256 == $sha
  and .inventory == {packages: 3, dev: true}
  and .inherited_audit.verdict == "BLOCK" and .inherited_audit.critical == 2 and .inherited_audit.high == 20
  and .network == false and .lifecycle_scripts == false
  and (.integrity | startswith("unverified"))' "$receipt" >/dev/null || { cat "$receipt" >&2; fail "receipt content differs"; }
gate_log | grep -Fq "reuse:composer | $WT | GATE | non-tty | REUSED_EXISTING_WITH_KNOWN_RISKS | source=$MAIN" ||
  fail "the gate log lacks the reuse decision"
pass "the receipt and the gate log record source, lockfile, inventory and the inherited verdict"

[[ ! -e "$tmp/manager-calls" ]] || fail "a package manager was invoked: $(cat "$tmp/manager-calls")"
[[ "$(grep -c . "$AUDIT_CALLS")" == "1" ]] && grep -q '^repo-audit \. --deps-only' "$AUDIT_CALLS" ||
  fail "reuse ran something other than one lockfile audit: $(cat "$AUDIT_CALLS")"
pass "reuse runs no package manager and no install audit, only the lockfile audit"

# No hardlinks: rewriting a copied file never reaches the source checkout.
printf 'changed by a test run\n' > "$WT/vendor/acme/runtime/src/Main.php"
grep -q 'runtime' "$MAIN/vendor/acme/runtime/src/Main.php" || fail "a write in the copy reached the source checkout"
[[ "$(stat -c %i "$WT/vendor/autoload.php")" != "$(stat -c %i "$MAIN/vendor/autoload.php")" ]] ||
  fail "the copy shares an inode with the source"
pass "the copy shares no file with the source checkout"

# A second reuse never overwrites what is there.
reuse "$WT"
[[ "$RC" == "100" ]] && grep -Fq 'already exists and reuse never overwrites' "$tmp/err.txt" ||
  fail "reuse overwrote an existing vendor/ (rc=$RC)"
grep -q 'changed by a test run' "$WT/vendor/acme/runtime/src/Main.php" || fail "the existing vendor/ was replaced"
pass "an existing vendor/ is never overwritten"

# --- clean and unaudited outcomes ----------------------------------------------
make_repo clean
STUB_VERDICT=GO reuse "$WT"
[[ "$RC" == "0" ]] && grep -Fq 'status:    reused-existing-vendor' "$tmp/out.txt" &&
  ! grep -Fq 'known-risks' "$tmp/out.txt" && [[ ! -s "$tmp/err.txt" ]] ||
  { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "clean reuse (rc=$RC)"; }
pass "a clean lockfile ends as reused-existing-vendor"

make_repo unaudited
STUB_SCAN_FAIL=1 reuse "$WT"
[[ "$RC" == "0" ]] && grep -Fq 'status:    reused-existing-vendor-unaudited' "$tmp/out.txt" &&
  grep -Fq 'audit:     NOT AVAILABLE' "$tmp/out.txt" ||
  { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "unaudited reuse (rc=$RC)"; }
jq -e '.inherited_audit.verdict == "UNKNOWN" and .inherited_audit.critical == null' \
  "$(sed -n 's/^  receipt:   //p' "$tmp/out.txt")" >/dev/null || fail "an unavailable audit was recorded as a verdict"
pass "an audit that cannot run is recorded as unaudited, never as clean"

make_repo go-with-criticals
STUB_VERDICT=GO STUB_CRITICAL=1 reuse "$WT"
[[ "$RC" == "0" ]] && grep -Fq 'status:    reused-existing-vendor-with-known-risks' "$tmp/out.txt" ||
  fail "a GO verdict carrying critical findings read as clean"
pass "critical findings are never reported as a clean reuse"

# --- dry run and explicit source -----------------------------------------------
make_repo dry
STUB_VERDICT=WARN STUB_HIGH=4 reuse "$WT" --dry-run
[[ "$RC" == "0" && ! -e "$WT/vendor" ]] || fail "dry run copied something (rc=$RC)"
grep -Fq 'dry run — nothing copied (would end as reused-existing-vendor-with-known-risks)' "$tmp/out.txt" ||
  fail "dry run does not state its outcome"
pass "--dry-run verifies everything and copies nothing"
rule false
reuse "$WT" --dry-run
[[ "$RC" == "0" && ! -e "$WT/vendor" ]] || fail "dry run needs the host rule (rc=$RC)"
pass "--dry-run works on a host without the rule"
rule true
reuse "$WT" --reuse-from "$MAIN"
[[ "$RC" == "0" ]] && diff -r "$MAIN/vendor" "$WT/vendor" >/dev/null || fail "explicit --reuse-from failed (rc=$RC)"
pass "--reuse-from names the source checkout explicitly"

# --- the per-host rule ----------------------------------------------------------
make_repo policy
rule false
reuse "$WT"
expect_refusal 102 'not enabled on this host (install.reuse.enabled)' "a host without the rule refuses 102 unattended"
rm -f "$SAFE_RUN_CONFIG_DIR/config.json"
reuse "$WT"
expect_refusal 102 'not enabled on this host' "the rule is off by default"
# A redirected config root cannot enable the rule without the trust token.
mkdir -p "$tmp/redirected"
printf '{"install":{"reuse":{"enabled":true}}}\n' > "$tmp/redirected/config.json"
SAFE_RUN_CONFIG_DIR="$tmp/redirected" reuse "$WT"
expect_refusal 102 'not enabled on this host' "a redirected config root cannot enable the rule"
printf '{"install":{"reuse":{"enabled":"true"}}}\n' > "$SAFE_RUN_CONFIG_DIR/config.json"
reuse "$WT"
expect_refusal 102 'not enabled on this host' "only the boolean true enables the rule"

# With the rule off the operator decides each reuse at a real terminal; an
# agent session holding a terminal is still not the operator.
terminal_reuse() {
  local answer="$1" marker="${2:-}"
  ANSWER="$answer" MARKER="$marker" TARGET="$WT" SAFE="$SAFE" python3 <<'PY'
import os, pty, select, signal, sys, time
env = {k: v for k, v in os.environ.items() if k not in ('CODEX_THREAD_ID', 'CODEX_CI', 'CLAUDECODE', 'OPENCODE')}
if os.environ['MARKER']:
    env[os.environ['MARKER']] = 'fixture-agent'
pid, fd = pty.fork()
if pid == 0:
    os.chdir(os.environ['TARGET'])
    os.execve(os.environ['SAFE'], ['safe', 'install', '--reuse'], env)
buf = b''; asked = False; deadline = time.monotonic() + 30
try:
    while time.monotonic() < deadline:
        if not select.select([fd], [], [], 0.1)[0]:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if not asked and b'copy this installed tree into' in buf:
            os.write(fd, os.environ['ANSWER'].encode() + b'\n'); asked = True
    else:
        os.kill(pid, signal.SIGKILL); raise AssertionError('timed out: ' + repr(buf))
    _, rc = os.waitpid(pid, 0)
    sys.stdout.write('%d %d\n' % (os.waitstatus_to_exitcode(rc), 1 if asked else 0))
    sys.stdout.write(buf.decode(errors='replace'))
finally:
    os.close(fd)
PY
}
rule false
terminal_reuse n > "$tmp/terminal.txt" || fail "terminal fixture failed"
[[ "$(head -n 1 "$tmp/terminal.txt")" == "100 1" && ! -e "$WT/vendor" ]] ||
  { cat "$tmp/terminal.txt" >&2; fail "a declined reuse copied something or did not refuse 100"; }
grep -Fq 'declined at the terminal; nothing was copied' "$tmp/terminal.txt" || fail "a declined reuse lacks its refusal"
pass "with the rule off, the operator declines at the terminal and nothing is copied"
terminal_reuse y CLAUDECODE > "$tmp/terminal.txt" || fail "terminal fixture failed"
[[ "$(head -n 1 "$tmp/terminal.txt")" == "102 0" && ! -e "$WT/vendor" ]] ||
  { cat "$tmp/terminal.txt" >&2; fail "an agent session holding a terminal was treated as the operator"; }
pass "with the rule off, an agent session holding a terminal is refused 102 without a prompt"
terminal_reuse y > "$tmp/terminal.txt" || fail "terminal fixture failed"
[[ "$(head -n 1 "$tmp/terminal.txt")" == "0 1" ]] && diff -r "$MAIN/vendor" "$WT/vendor" >/dev/null ||
  { cat "$tmp/terminal.txt" >&2; fail "a confirmed reuse did not copy"; }
jq -e '.authorized_by == "operator-terminal"' "$(sed -n 's/^  receipt:   //p' "$tmp/terminal.txt" | tr -d '\r')" >/dev/null ||
  fail "a terminal-confirmed reuse is not attributed to the operator"
pass "with the rule off, the operator confirms at the terminal and the receipt says so"
rule true

# --- negative cases: nothing is copied -----------------------------------------
make_repo changed-lock
jq '.packages[1].version = "3.10.1"' "$WT/composer.lock" > "$tmp/lock.json" && mv "$tmp/lock.json" "$WT/composer.lock"
reuse "$WT" --reuse-from "$MAIN"
expect_refusal 100 'composer.lock differs' "a changed lockfile is a new install, not a reuse"
reuse "$WT"
expect_refusal 100 'holds an installed vendor/ for this composer.lock' "auto-detection finds no source for a changed lockfile"

make_repo stale-version
jq '.packages[1].version = "3.9.0"' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
reuse "$WT"
expect_refusal 100 'does not match its lockfile (missing acme/spreadsheet@3.10.0' "a stale installed tree is refused"

make_repo extra-package
jq '.packages += [{"name":"evil/extra","version":"9.9.9","install-path":"../evil/extra"}]' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
mkdir -p "$MAIN/vendor/evil/extra"
reuse "$WT"
expect_refusal 100 'not in the lockfile: evil/extra@9.9.9' "a package the lockfile does not list is refused"

make_repo missing-dir
rm -rf "$MAIN/vendor/acme/spreadsheet"
reuse "$WT"
expect_refusal 100 'missing or outside the project (../acme/spreadsheet)' "a tree missing a package directory is refused"

make_repo escaping-path
jq '.packages[0]["install-path"] = "../../../../outside"' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
mkdir -p "$tmp/escaping-path/outside"
reuse "$WT"
expect_refusal 100 'missing or outside the project' "an install path outside the project is refused"

make_repo no-dev-source
jq '.dev = false | .packages |= map(select(.name != "acme/pest"))' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
reuse "$WT"
[[ "$RC" == "0" ]] && grep -Fq 'dev packages: NOT installed in the source' "$tmp/out.txt" ||
  { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "a no-dev source tree (rc=$RC)"; }
pass "a no-dev source tree is reused and says dev packages are absent"

make_repo composer1-format
printf '[{"name":"acme/runtime","version":"1.2.0"}]\n' > "$MAIN/vendor/composer/installed.json"
reuse "$WT"
expect_refusal 100 'not in the Composer 2 format' "an inventory safe cannot read is refused"

make_repo absolute-link
ln -s "$MAIN/vendor/acme/runtime" "$MAIN/vendor/acme/linked"
reuse "$WT"
expect_refusal 100 'would leave the project once copied (vendor/acme/linked' "an absolute symlink is refused"

make_repo escaping-link
ln -s ../../../outside "$MAIN/vendor/acme/linked"
reuse "$WT"
expect_refusal 100 'would leave the project once copied' "a relative symlink leaving the project is refused"

make_repo platform-version
printf '8.3.2 Core,json,mbstring' > "$WT/.php-identity"
reuse "$WT"
expect_refusal 100 'php differs between the two checkouts (source: 8.5.10, here: 8.3.2' "another php version is an incompatible platform"

make_repo platform-extensions
printf '8.5.10 Core,json' > "$WT/.php-identity"
reuse "$WT"
expect_refusal 100 'php differs between the two checkouts' "another extension set is an incompatible platform"

make_repo platform-check
printf '<?php // PLATFORM_ISSUE ext-gd missing\n' > "$MAIN/vendor/composer/platform_check.php"
reuse "$WT"
expect_refusal 100 "Composer's platform check fails" "a failing Composer platform check is refused"

# Provenance: another repository cannot vouch, identical lockfile or not.
make_repo provenance
provenance_wt="$WT"
make_repo other-repository
WT="$provenance_wt"
reuse "$WT" --reuse-from "$tmp/other-repository/main"
expect_refusal 100 'is not the same project in a checkout of this repository' "another repository cannot be the source"
reuse "$WT" --reuse-from "$tmp/does-not-exist"
expect_refusal 100 'is not a directory' "a missing source directory is refused"
reuse "$WT" --reuse-from "$WT"
expect_refusal 100 'the same directory' "the target cannot be its own source"

make_repo no-source
rm -rf "$MAIN/vendor"
reuse "$WT"
expect_refusal 100 'holds an installed vendor/ for this composer.lock' "no installed tree anywhere refuses with the recovery path"

make_repo symlinked-vendor
mv "$MAIN/vendor" "$tmp/symlinked-vendor/real-vendor"
ln -s "$tmp/symlinked-vendor/real-vendor" "$MAIN/vendor"
reuse "$WT"
expect_refusal 100 'vendor is a symlink or belongs to another user' "a symlinked source vendor/ is refused"

mkdir -p "$tmp/not-a-project"
WT="$tmp/not-a-project"
reuse "$WT"
expect_refusal 100 'has no composer.json with a composer.lock' "a directory without a Composer project is refused"

mkdir -p "$tmp/no-git" && printf '{}\n' > "$tmp/no-git/composer.json" && printf '%s\n' "$LOCK" > "$tmp/no-git/composer.lock"
WT="$tmp/no-git"
GIT_CEILING_DIRECTORIES="$tmp" reuse "$WT"
expect_refusal 100 'is not inside a git checkout' "a project outside git is refused"

# --- a project in a subdirectory of the repository ------------------------------
mono="$tmp/mono/main"
mkdir -p "$mono/apps/api"
git_q -C "$mono" init
printf '{}\n' > "$mono/apps/api/composer.json"
printf '%s\n' "$LOCK" > "$mono/apps/api/composer.lock"
printf 'vendor/\n' > "$mono/.gitignore"
git_q -C "$mono" add -A && git_q -C "$mono" commit -m init
mkdir -p "$mono/apps/api/vendor/composer" "$mono/apps/api/vendor/acme/"{runtime,spreadsheet,pest}
printf '%s\n' "$INSTALLED" > "$mono/apps/api/vendor/composer/installed.json"
git_q -C "$mono" worktree add "$tmp/mono/wt" -b wt-mono
MAIN="$mono/apps/api" WT="$tmp/mono/wt/apps/api"
reuse "$WT"
[[ "$RC" == "0" ]] && diff -r "$MAIN/vendor" "$WT/vendor" >/dev/null ||
  { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "subdirectory project (rc=$RC)"; }
grep -Fq "source:    $MAIN" "$tmp/out.txt" || fail "subdirectory project used the wrong source"
pass "a project in a repository subdirectory reuses the same subdirectory of the main checkout"

# --- argument contract -----------------------------------------------------------
make_repo arguments
for bad in "acme/thing" "-g" "--project" "--host" "--sandbox"; do
  RC=0
  ( cd "$WT" && "$SAFE" install --reuse "$bad" ) > "$tmp/out.txt" 2> "$tmp/err.txt" </dev/null || RC=$?
  [[ "$RC" == "1" && ! -e "$WT/vendor" ]] || fail "--reuse accepted '$bad' (rc=$RC)"
done
pass "--reuse takes no package and no install-mode flag"
[[ ! -e "$tmp/manager-calls" ]] || fail "a package manager was invoked during the suite: $(cat "$tmp/manager-calls")"
grep -vq '^repo-audit ' "$AUDIT_CALLS" && fail "the suite ran an audit other than the lockfile audit"
pass "no package manager ran in any case"

printf '\n%d passed, 0 failed\n' "$PASS_COUNT"
