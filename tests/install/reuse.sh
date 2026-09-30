#!/usr/bin/env bash
# safe install --reuse: reuse of already-installed Composer dependencies in a
# worktree (operator rulings 2026-09-30). Real git checkouts and a real copy.
# The operation runs no audit, no php and no package manager: each is a
# logging fixture here whose log must stay empty.

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
for tool in composer npm php; do
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$0 $*" >> "%s/forbidden-calls"\nexit 97\n' "$tmp" > "$tmp/bin/$tool"
done
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "safe-audit $*" >> "%s/forbidden-calls"\nexit 97\n' "$tmp" > "$tmp/bin/safe-audit-stub"
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH" SAFE_AUDIT_PATH="$tmp/bin/safe-audit-stub"

LOCK='{"content-hash":"abc","packages":[{"name":"acme/runtime","version":"1.2.0"},{"name":"acme/spreadsheet","version":"3.10.0"}],"packages-dev":[{"name":"acme/pest","version":"4.0.1"}]}'
INSTALLED='{"packages":[{"name":"acme/runtime","version":"1.2.0","install-path":"../acme/runtime"},{"name":"acme/spreadsheet","version":"3.10.0","install-path":"../acme/spreadsheet"},{"name":"acme/pest","version":"4.0.1","install-path":"../acme/pest"}],"dev":true,"dev-package-names":["acme/pest"]}'

git_q() { git -c init.defaultBranch=main -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@" >/dev/null 2>&1; }

# install_tree <project>: a complete installed vendor/ for $LOCK.
install_tree() {
  local dir="$1" pkg
  for pkg in runtime spreadsheet pest; do
    mkdir -p "$dir/vendor/acme/$pkg/src"
    printf '<?php // %s\n' "$pkg" > "$dir/vendor/acme/$pkg/src/Main.php"
  done
  mkdir -p "$dir/vendor/composer" "$dir/vendor/bin"
  printf '%s\n' "$INSTALLED" > "$dir/vendor/composer/installed.json"
  printf '<?php // generated autoloader\n' > "$dir/vendor/composer/autoload_real.php"
  printf '<?php return require __DIR__ . "/composer/autoload_real.php";\n' > "$dir/vendor/autoload.php"
  ln -s ../acme/pest/src/Main.php "$dir/vendor/bin/pest"
}

# make_repo <name>: a main checkout with an installed vendor/, plus linked
# worktrees wt and wt2 of the same commit with none.
make_repo() {
  local name="$1" main="$tmp/$1/main"
  mkdir -p "$main"
  git_q -C "$main" init || fail "git init"
  printf '{"name":"acme/app","require":{"acme/runtime":"^1.2"},"autoload":{"psr-4":{"App\\\\":"src/"}}}\n' > "$main/composer.json"
  printf '%s\n' "$LOCK" > "$main/composer.lock"
  printf 'vendor/\n' > "$main/.gitignore"
  git_q -C "$main" add -A && git_q -C "$main" commit -m init || fail "git commit"
  install_tree "$main"
  git_q -C "$main" worktree add "$tmp/$1/wt" -b "wt-$name" || fail "git worktree add"
  git_q -C "$main" worktree add "$tmp/$1/wt2" -b "wt2-$name" || fail "git worktree add"
  MAIN="$main" WT="$tmp/$1/wt" WT2="$tmp/$1/wt2"
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
  compgen -G "$WT/.safe-reuse.*" >/dev/null && fail "$label: a refusal left a staging directory behind"
  pass "$label"
}
receipt_of() { sed -n 's/^  receipt:   //p' "$1" | tr -d '\r'; }
gate_log() { cat "$SAFE_RUN_DATA_DIR/audit.log" 2>/dev/null; }

# --- the Vacation case: an installed tree in the main checkout ------------------
make_repo basic
reuse "$WT"
[[ "$RC" == "0" ]] || { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "reuse failed (rc=$RC)"; }
diff -r "$MAIN/vendor" "$WT/vendor" >/dev/null || fail "the copied tree differs from the source"
[[ -L "$WT/vendor/bin/pest" && "$(readlink "$WT/vendor/bin/pest")" == "../acme/pest/src/Main.php" ]] ||
  fail "a relative link did not survive the copy"
grep -Fq 'status:    reused-existing-vendor' "$tmp/out.txt" || fail "reuse does not carry its status"
grep -Fq 'audit:     not run' "$tmp/out.txt" || fail "reuse does not say it ran no audit"
grep -Fq 'integrity: baseline-recorded' "$tmp/out.txt" || fail "the first reuse does not record a baseline"
grep -Fq "source:    $MAIN" "$tmp/out.txt" || fail "the source checkout is not named"
[[ ! -s "$tmp/err.txt" ]] || fail "a clean reuse wrote to stderr: $(cat "$tmp/err.txt")"
pass "reuse copies the resident tree unattended under the host rule"

receipt="$(receipt_of "$tmp/out.txt")"
[[ -s "$receipt" ]] || fail "no receipt was written"
jq -e --arg s "$MAIN" --arg t "$WT" --arg sha "$(sha256sum "$WT/composer.lock" | cut -d' ' -f1)" '
  .operation == "reuse" and .ecosystem == "composer" and .status == "reused-existing-vendor"
  and .authorized_by == "install.reuse.enabled" and .operator_override == []
  and .source == $s and .target == $t and .lockfile.sha256 == $sha
  and .inventory == {packages: 3, dev: true} and .skipped == []
  and .integrity.state == "baseline-recorded" and .integrity.files == 7
  and (.audit | startswith("not run"))
  and .network == false and .package_manager == false and .scripts_executed == false' "$receipt" >/dev/null ||
  { cat "$receipt" >&2; fail "receipt content differs"; }
gate_log | grep -Fq "reuse:composer | $WT | GATE | non-tty | REUSED_EXISTING | source=$MAIN" ||
  fail "the gate log lacks the reuse decision"
[[ ! -e "$tmp/forbidden-calls" ]] || fail "reuse ran an audit, php or a package manager: $(cat "$tmp/forbidden-calls")"
pass "the receipt records source, lockfile, inventory and baseline; no audit, php or package manager ran"

printf 'changed by a test run\n' > "$WT/vendor/acme/runtime/src/Main.php"
grep -q 'runtime' "$MAIN/vendor/acme/runtime/src/Main.php" || fail "a write in the copy reached the source checkout"
[[ "$(stat -c %i "$WT/vendor/autoload.php")" != "$(stat -c %i "$MAIN/vendor/autoload.php")" ]] ||
  fail "the copy shares an inode with the source"
pass "the copy shares no file with the source checkout"

reuse "$WT"
[[ "$RC" == "100" ]] && grep -Fq 'already exists and reuse never overwrites' "$tmp/err.txt" ||
  fail "reuse overwrote an existing vendor/ (rc=$RC)"
grep -q 'changed by a test run' "$WT/vendor/acme/runtime/src/Main.php" || fail "the existing vendor/ was replaced"
pass "an existing vendor/ is never overwritten"

# --- trust on first use ---------------------------------------------------------
reuse "$WT2"
[[ "$RC" == "0" ]] && grep -Fq 'integrity: baseline-matched' "$tmp/out.txt" ||
  { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "a second reuse from an unchanged source (rc=$RC)"; }
pass "a later reuse from an unchanged source matches its baseline"

make_repo tampered
reuse "$WT"
[[ "$RC" == "0" ]] || fail "baseline reuse failed (rc=$RC)"
printf '<?php // injected\n' > "$MAIN/vendor/acme/spreadsheet/src/Main.php"
WT="$WT2" reuse "$WT2"
WT="$WT2" reuse "$WT2" --dry-run
WT="$WT2" expect_refusal 102 'changed since its baseline' "--dry-run predicts the changed baseline"
WT="$WT2" reuse "$WT2"
WT="$WT2" expect_refusal 102 'changed since its baseline' "a source changed since its baseline is refused unattended"
grep -Fq 'acme/spreadsheet/src/Main.php' "$tmp/err.txt" || fail "the refusal does not name the changed file"

# --- evidence gaps: refused unattended, never partially copied -------------------
make_repo stale-version
jq '.packages[1].version = "3.9.0"' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
reuse "$WT"
expect_refusal 102 'does not match the lockfile (missing acme/spreadsheet@3.10.0' "a stale installed tree is refused"

make_repo extra-package
jq '.packages += [{"name":"evil/extra","version":"9.9.9","install-path":"../evil/extra"}]' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
mkdir -p "$MAIN/vendor/evil/extra"
reuse "$WT"
expect_refusal 102 'not in the lockfile: evil/extra@9.9.9' "a package the lockfile does not list is refused"

make_repo missing-dir
rm -rf "$MAIN/vendor/acme/spreadsheet"
reuse "$WT"
expect_refusal 102 'package directory ../acme/spreadsheet is missing or outside vendor/' "a tree missing a package directory is refused"

make_repo missing-install-path
jq '.packages[1] |= del(.["install-path"])' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
rm -rf "$MAIN/vendor/acme/spreadsheet"
reuse "$WT"
expect_refusal 102 'package acme/spreadsheet has no install path' "a package without an install path is refused"

make_repo escaping-path
jq '.packages[0]["install-path"] = "../../../../outside"' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
mkdir -p "$tmp/escaping-path/outside"
reuse "$WT"
expect_refusal 102 'is missing or outside vendor/' "an install path outside vendor/ is refused"

make_repo untracked-dir
jq '.dev = false | .packages |= map(select(.name != "acme/pest"))' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
rm -f "$MAIN/vendor/bin/pest"
reuse "$WT"
[[ "$RC" == "0" && ! -e "$WT/vendor/acme/pest" && -d "$WT/vendor/acme/runtime" ]] ||
  { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "an entry outside the inventory was copied (rc=$RC)"; }
grep -Fq 'skipped:   acme/pest (in vendor/ but not in the inventory; not copied)' "$tmp/out.txt" || fail "the skipped entry is not reported"
jq -e '.skipped == ["acme/pest"]' "$(receipt_of "$tmp/out.txt")" >/dev/null || fail "the receipt does not list the skipped entry"
pass "only what the inventory describes is copied; the rest is listed as skipped"

make_repo no-autoload
rm -f "$MAIN/vendor/autoload.php"
reuse "$WT"
expect_refusal 102 'vendor/autoload.php is missing' "a tree without its autoloader is refused"

make_repo absolute-link
ln -s "$MAIN/vendor/acme/runtime" "$MAIN/vendor/acme/runtime/linked"
reuse "$WT"
expect_refusal 102 'points outside the project' "an absolute symlink is refused"

make_repo path-repository
mkdir -p "$MAIN/packages/local"
ln -s ../../packages/local "$MAIN/vendor/acme/local"
jq '.packages += [{"name":"acme/local","version":"dev-main","install-path":"../acme/local"}]' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
for lockfile in "$MAIN/composer.lock" "$WT/composer.lock"; do
  jq '.packages += [{"name":"acme/local","version":"dev-main"}]' "$lockfile" > "$tmp/l.json" && mv "$tmp/l.json" "$lockfile"
done
reuse "$WT"
expect_refusal 102 'would dangle here (packages/local is absent)' "a path-repository link that would dangle in the target is refused"
printf '{"name":"acme/local","autoload":{"psr-4":{"Local\\\\":"src/"}}}\n' > "$MAIN/packages/local/composer.json"
mkdir -p "$WT/packages/local" && printf '{"name":"acme/local","autoload":{"psr-4":{"Local\\\\":"lib/"}}}\n' > "$WT/packages/local/composer.json"
reuse "$WT"
expect_refusal 102 'reaches packages/local, whose name or autoload rules differ here' "a path repository with other autoload rules in the target is refused"
cp "$MAIN/packages/local/composer.json" "$WT/packages/local/composer.json"
printf 'this branch\n' > "$WT/packages/local/a.php"
reuse "$WT"
[[ "$RC" == "0" && -L "$WT/vendor/acme/local" && "$(cat "$WT/vendor/acme/local/a.php")" == "this branch" ]] ||
  { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "a path repository was not reused onto the target's own copy (rc=$RC)"; }
pass "a path-repository link reaches the target's own copy of the package, as Composer would install it"
rm -rf "$WT/vendor"
ln -s ../../../../elsewhere "$MAIN/vendor/acme/runtime/escape"
reuse "$WT"
expect_refusal 102 'points outside the project' "a relative symlink leaving the project is refused"

make_repo composer1-format
printf '[{"name":"acme/runtime","version":"1.2.0"}]\n' > "$MAIN/vendor/composer/installed.json"
reuse "$WT"
expect_refusal 102 'not in the Composer 2 format' "an inventory safe cannot read is refused"

make_repo no-dev-source
jq '.dev = false | .packages |= map(select(.name != "acme/pest"))' "$MAIN/vendor/composer/installed.json" > "$tmp/i.json" && mv "$tmp/i.json" "$MAIN/vendor/composer/installed.json"
rm -rf "$MAIN/vendor/acme/pest" "$MAIN/vendor/bin/pest"
reuse "$WT"
[[ "$RC" == "0" ]] && grep -Fq 'dev packages: NOT installed in the source' "$tmp/out.txt" ||
  { cat "$tmp/out.txt" "$tmp/err.txt" >&2; fail "a no-dev source tree (rc=$RC)"; }
pass "a no-dev source tree is reused and says dev packages are absent"

# --- identity refusals (no override: another operation is the answer) -------------
make_repo changed-lock
jq '.packages[1].version = "3.10.1"' "$WT/composer.lock" > "$tmp/lock.json" && mv "$tmp/lock.json" "$WT/composer.lock"
reuse "$WT" --reuse-from "$MAIN"
expect_refusal 100 'composer.lock differs' "a changed lockfile is a new install, not a reuse"
reuse "$WT"
expect_refusal 100 'holds an installed vendor/ for this composer.lock' "auto-detection finds no source for a changed lockfile"

make_repo autoload-rules
jq '.autoload["psr-4"]["Other\\"] = "lib/"' "$WT/composer.json" > "$tmp/c.json" && mv "$tmp/c.json" "$WT/composer.json"
reuse "$WT"
expect_refusal 102 'autoload rules differ' "different root autoload rules are an evidence gap for the operator"

make_repo unwritable-store
printf 'not a directory\n' > "$tmp/store-file"
SAFE_DATA_DIR="$tmp/store-file" reuse "$WT"
expect_refusal 100 'is not writable; nothing was copied' "an unwritable receipt store refuses before copying"

# Concurrency and interruption: a vendor/ that appears during the copy is
# never overwritten, and an interrupted copy leaves no staging behind.
make_repo race
mkdir -p "$tmp/racebin"
REAL_CP="$(command -v cp)"
cat > "$tmp/racebin/cp" <<STUB
#!/usr/bin/env bash
case "\$RACE_MODE" in
  writer) mkdir -p "$WT/vendor/other" ;;
  term) kill -TERM "\$PPID"; sleep 1 ;;
esac
exec "$REAL_CP" "\$@"
STUB
chmod +x "$tmp/racebin/cp"
RACE_MODE=writer PATH="$tmp/racebin:$PATH" reuse "$WT"
[[ "$RC" == "100" ]] && grep -Fq 'appeared while copying' "$tmp/err.txt" && [[ -d "$WT/vendor/other" && ! -e "$WT/vendor/autoload.php" ]] ||
  { cat "$tmp/err.txt" >&2; fail "a concurrent vendor/ was overwritten or not refused (rc=$RC)"; }
compgen -G "$WT/.safe-reuse.*" >/dev/null && fail "a refused publish left its staging behind"
rm -rf "$WT/vendor"
RACE_MODE=term PATH="$tmp/racebin:$PATH" reuse "$WT"
[[ "$RC" == "143" && ! -e "$WT/vendor" ]] || fail "an interrupted copy did not stop cleanly (rc=$RC)"
compgen -G "$WT/.safe-reuse.*" >/dev/null && fail "an interrupted copy left its staging behind"
compgen -G "$SAFE_DATA_DIR/install/reuse/.receipt.*" >/dev/null && fail "an interrupted copy left a partial receipt"
compgen -G "$SAFE_DATA_DIR/install/reuse/baselines/.baseline.*" >/dev/null && fail "a refused or interrupted copy left a temporary baseline"
pass "a concurrent vendor/ is never overwritten and an interrupted copy leaves nothing behind"

# --- review r2: damaged evidence never becomes an accepted baseline ---------------
make_repo hash-failure
REAL_SHA="$(command -v sha256sum)"
mkdir -p "$tmp/hashbin"
cat > "$tmp/hashbin/sha256sum" <<STUB
#!/usr/bin/env bash
for arg in "\$@"; do
  if [[ "\$arg" == *acme/runtime/src/Main.php ]]; then
    echo "sha256sum: \$arg: Input/output error" >&2
    args=(); for a in "\$@"; do [[ "\$a" == "\$arg" ]] || args+=("\$a"); done
    "$REAL_SHA" "\${args[@]}"; exit 1
  fi
done
exec "$REAL_SHA" "\$@"
STUB
chmod +x "$tmp/hashbin/sha256sum"
PATH="$tmp/hashbin:$PATH" reuse "$WT"
expect_refusal 102 'could be read and hashed' "a file that cannot be hashed is an evidence gap, never a baseline"
[[ -z "$(find "$SAFE_DATA_DIR/install/reuse/baselines" -name '*.json' -newer "$tmp/hashbin/sha256sum" 2>/dev/null)" ]] ||
  fail "a partial manifest was recorded as a baseline"

make_repo corrupt-baseline
reuse "$WT"
[[ "$RC" == "0" ]] || fail "baseline reuse failed (rc=$RC)"
baseline_json="$(find "$SAFE_DATA_DIR/install/reuse/baselines" -name '*.json' -newer "$MAIN/composer.lock" | head -n 1)"
printf '{"lock_sha' > "$baseline_json"
printf '<?php // changed\n' > "$MAIN/vendor/acme/runtime/src/Main.php"
WT="$WT2" reuse "$WT2"
WT="$WT2" expect_refusal 102 'integrity baseline recorded for' "an unreadable baseline is an evidence gap, never a new lockfile"

make_repo chained-link
mkdir -p "$tmp/chained-link/outside"
printf 'outside\n' > "$tmp/chained-link/outside/x"
ln -s "$tmp/chained-link/outside" "$MAIN/packages-redirect" 2>/dev/null || { mkdir -p "$MAIN"; ln -s "$tmp/chained-link/outside" "$MAIN/packages-redirect"; }
ln -s "$tmp/chained-link/outside" "$WT/packages-redirect"
ln -s ../../../packages-redirect "$MAIN/vendor/acme/runtime/link"
reuse "$WT"
expect_refusal 102 'leads outside the project through another link' "a link reaching outside the project through another link is refused"

# --- dry run and explicit source -----------------------------------------------
make_repo dry
reuse "$WT" --dry-run
[[ "$RC" == "0" && ! -e "$WT/vendor" ]] || fail "dry run copied something (rc=$RC)"
grep -Fq 'dry run — nothing copied (would end as reused-existing-vendor)' "$tmp/out.txt" ||
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
mkdir -p "$tmp/redirected"
printf '{"install":{"reuse":{"enabled":true}}}\n' > "$tmp/redirected/config.json"
SAFE_RUN_CONFIG_DIR="$tmp/redirected" reuse "$WT"
expect_refusal 102 'not enabled on this host' "a redirected config root cannot enable the rule"
printf '{"install":{"reuse":{"enabled":"true"}}}\n' > "$SAFE_RUN_CONFIG_DIR/config.json"
reuse "$WT"
expect_refusal 102 'not enabled on this host' "only the boolean true enables the rule"

# terminal_reuse <target> <answer...> [-- marker]: answers each prompt in turn.
terminal_reuse() {
  local target="$1"; shift
  TARGET="$target" SAFE="$SAFE" ANSWERS="$*" MARKER="${MARKER:-}" python3 <<'PY'
import os, pty, select, signal, sys, time
env = {k: v for k, v in os.environ.items() if k not in ('CODEX_THREAD_ID', 'CODEX_CI', 'CLAUDECODE', 'OPENCODE')}
if os.environ['MARKER']:
    env[os.environ['MARKER']] = 'fixture-agent'
answers = os.environ['ANSWERS'].split()
pid, fd = pty.fork()
if pid == 0:
    os.chdir(os.environ['TARGET'])
    os.execve(os.environ['SAFE'], ['safe', 'install', '--reuse'], env)
buf = b''; seen = 0; asked = 0; deadline = time.monotonic() + 30
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
        while buf.count(b'[y/N]') > seen and asked < len(answers):
            os.write(fd, answers[asked].encode() + b'\n'); asked += 1; seen += 1
    else:
        os.kill(pid, signal.SIGKILL); raise AssertionError('timed out: ' + repr(buf))
    _, rc = os.waitpid(pid, 0)
    sys.stdout.write('%d %d\n' % (os.waitstatus_to_exitcode(rc), asked))
    sys.stdout.write(buf.decode(errors='replace'))
finally:
    os.close(fd)
PY
}
rule false
terminal_reuse "$WT" n > "$tmp/terminal.txt" || fail "terminal fixture failed"
[[ "$(head -n 1 "$tmp/terminal.txt")" == "100 1" && ! -e "$WT/vendor" ]] ||
  { cat "$tmp/terminal.txt" >&2; fail "a declined reuse copied something or did not refuse 100"; }
grep -Fq 'declined at the terminal; nothing was copied' "$tmp/terminal.txt" || fail "a declined reuse lacks its refusal"
pass "with the rule off, the operator declines at the terminal and nothing is copied"
MARKER=CLAUDECODE terminal_reuse "$WT" y > "$tmp/terminal.txt" || fail "terminal fixture failed"
[[ "$(head -n 1 "$tmp/terminal.txt")" == "102 0" && ! -e "$WT/vendor" ]] ||
  { cat "$tmp/terminal.txt" >&2; fail "an agent session holding a terminal was treated as the operator"; }
pass "with the rule off, an agent session holding a terminal is refused 102 without a prompt"
terminal_reuse "$WT" y > "$tmp/terminal.txt" || fail "terminal fixture failed"
[[ "$(head -n 1 "$tmp/terminal.txt")" == "0 1" ]] && diff -r "$MAIN/vendor" "$WT/vendor" >/dev/null ||
  { cat "$tmp/terminal.txt" >&2; fail "a confirmed reuse did not copy"; }
jq -e '.authorized_by == "operator-terminal"' "$(receipt_of "$tmp/terminal.txt")" >/dev/null ||
  fail "a terminal-confirmed reuse is not attributed to the operator"
pass "with the rule off, the operator confirms at the terminal and the receipt says so"
rule true

# The operator accepts an evidence gap at the terminal; it is recorded.
make_repo override
reuse "$WT"
[[ "$RC" == "0" ]] || fail "baseline reuse failed (rc=$RC)"
printf '<?php // patched locally\n' > "$MAIN/vendor/acme/runtime/src/Main.php"
terminal_reuse "$WT2" n > "$tmp/terminal.txt" || fail "terminal fixture failed"
[[ "$(head -n 1 "$tmp/terminal.txt")" == "100 1" && ! -e "$WT2/vendor" ]] ||
  { cat "$tmp/terminal.txt" >&2; fail "a declined evidence gap copied something"; }
terminal_reuse "$WT2" y > "$tmp/terminal.txt" || fail "terminal fixture failed"
[[ "$(head -n 1 "$tmp/terminal.txt")" == "0 1" ]] && grep -q 'patched locally' "$WT2/vendor/acme/runtime/src/Main.php" ||
  { cat "$tmp/terminal.txt" >&2; fail "an accepted evidence gap did not copy"; }
jq -e '.integrity.state == "baseline-re-recorded-by-operator" and (.operator_override | length) == 1
  and (.operator_override[0] | contains("acme/runtime/src/Main.php"))' "$(receipt_of "$tmp/terminal.txt")" >/dev/null ||
  fail "the operator override is not recorded in the receipt"
gate_log | grep -Fq "REUSED_EXISTING_OPERATOR_OVERRIDE" || fail "the gate log lacks the override decision"
WT3="$tmp/override/wt3"; git_q -C "$MAIN" worktree add "$WT3" -b wt3-override
reuse "$WT3"
[[ "$RC" == "0" ]] && grep -Fq 'integrity: baseline-matched' "$tmp/out.txt" || fail "the accepted tree is not the new baseline (rc=$RC)"
pass "an evidence gap is the operator's decision at the terminal, recorded, and re-baselines the source"

# --- provenance -------------------------------------------------------------------
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
install_tree "$mono/apps/api"
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
[[ ! -e "$tmp/forbidden-calls" ]] || fail "an audit, php or a package manager ran during the suite: $(cat "$tmp/forbidden-calls")"
pass "no audit, php or package manager ran in any case"

printf '\n%d passed, 0 failed\n' "$PASS_COUNT"
