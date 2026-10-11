#!/usr/bin/env bash
# LIVE suite — the private-registry npm lane (trusted origins) against the
# REAL npm client and a loopback registry. The hermetic suite stubs npm; this
# one checks that the shipped code paths read the real client's answers: the
# scope mapping (`npm config get @scope:registry`, with --userconfig) and the
# lockfiles real npm writes (plain and aliased entries), through
# `safe audit package-audit` and `safe audit private-npm-project`. Offline:
# the registry is 127.0.0.1.
set -uo pipefail

# SAFE_TEST_ISOLATION_MARKER: every suite owns a scratch HOME and safe state.
# shellcheck source=tests/lib/test-isolation.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/test-isolation.sh"
export SAFE_TEST_ISOLATION_KEEP_TOOLS=1
safe_test_setup_isolation || exit 1

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

real_npm=""
while IFS= read -r candidate; do
  [[ -x "${candidate}" ]] || continue
  LC_ALL=C head -n 2 -- "${candidate}" 2>/dev/null | grep -q '^# safe-gate-wrapper' && continue
  real_npm="${candidate}"
  break
done < <(type -a -p npm 2>/dev/null)
if [[ -z "${real_npm}" ]]; then
  printf 'SKIP: no real (non-wrapper) npm available; live private-registry npm oracle skipped\n'
  exit 0
fi
command -v python3 >/dev/null || fail "python3 required"
printf '# npm oracle target: %s (%s)\n' "${real_npm}" "$("${real_npm}" --version 2>/dev/null || printf 'version unknown')"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/safe-live-private-npm.XXXXXX")" || exit 1
server_pid=""
cleanup() { [[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null; rm -rf -- "$tmp"; }
safe_test_compose_exit_trap cleanup

# shellcheck source=tests/lib/safe-core.sh
source "$ROOT/tests/lib/safe-core.sh"
if ! safe_core_test_prepare "$ROOT" "$tmp/safe-core"; then
  [[ "${SAFE_TEST_STRICT:-}" == "1" ]] && fail "safe-core could not be built under SAFE_TEST_STRICT=1"
  printf 'SKIP: safe-core unavailable\n'
  exit 0
fi

# Loopback registry: one package @p/x@1.0.0 with a real tarball.
cat > "$tmp/registry.py" <<'PY'
import hashlib, base64, io, json, os, sys, tarfile, http.server, socketserver
root = sys.argv[1]
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    for name, body in (("package/package.json", b'{"name":"@p/x","version":"1.0.0","main":"index.js"}'),
                       ("package/index.js", b'module.exports="PRIVATE_OK";')):
        info = tarfile.TarInfo(name); info.size = len(body); info.mtime = 0
        tar.addfile(info, io.BytesIO(body))
tgz = buf.getvalue()
sri = "sha512-" + base64.b64encode(hashlib.sha512(tgz).digest()).decode()
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        port = self.server.server_address[1]
        base = f"http://127.0.0.1:{port}/npm"
        if self.path.rstrip("/") in ("/npm/@p%2fx", "/npm/@p%2Fx", "/npm/@p/x"):
            doc = {"name": "@p/x", "dist-tags": {"latest": "1.0.0"},
                   "versions": {"1.0.0": {"name": "@p/x", "version": "1.0.0",
                       "dist": {"tarball": f"{base}/@p/x/-/x-1.0.0.tgz", "integrity": sri}}},
                   "time": {"1.0.0": "2020-01-01T00:00:00.000Z"}}
            body = json.dumps(doc).encode(); ctype = "application/json"
        elif self.path == "/npm/@p/x/-/x-1.0.0.tgz":
            body = tgz; ctype = "application/octet-stream"
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
srv = socketserver.TCPServer(("127.0.0.1", 0), H)
open(os.path.join(root, "port"), "w").write(str(srv.server_address[1]))
open(os.path.join(root, "sri"), "w").write(sri)
srv.serve_forever()
PY
python3 "$tmp/registry.py" "$tmp" > "$tmp/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do [[ -s "$tmp/port" && -s "$tmp/sri" ]] && break; sleep 0.1; done
[[ -s "$tmp/port" ]] || fail "loopback registry did not start: $(cat "$tmp/server.log")"
port=$(cat "$tmp/port"); sri=$(cat "$tmp/sri")
origin="http://127.0.0.1:${port}/npm"

export HOME="$tmp/home" SAFE_CORE_BIN="$tmp/safe-core"
export SAFE_RUN_CONFIG_DIR="$HOME/.config/safe/run" SAFE_DATA_DIR="$tmp/data" SAFE_AUDIT_DATA_DIR="$tmp/data/audit"
export npm_config_cache="$tmp/npm-cache" npm_config_update_notifier=false npm_config_registry="http://127.0.0.1:${port}/unused/"
mkdir -p "$SAFE_RUN_CONFIG_DIR" "$tmp/bin"
ln -s "$real_npm" "$tmp/bin/npm"
export PATH="$tmp/bin:$PATH"
printf '@p:registry=%s/\n' "$origin" > "$HOME/.npmrc"
"$SAFE_CORE_BIN" private-trust registry-add --policy "$SAFE_RUN_CONFIG_DIR/private-registries.json" --id p --ecosystem npm \
  --origin "$origin" --namespace '@p/*' --reason live >/dev/null || fail "registry-add"

rc=0
SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$ROOT/bin/safe-audit" package-audit @p/x@1.0.0 --ecosystem npm --gate install > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 18 ]] && jq -e --arg o "$origin" '.private_registry.audit_extra == ("registry=p origin=" + $o + " name=@p/x version=1.0.0")' "$tmp/result.json" >/dev/null \
  || fail "spec audit with real npm: rc=$rc $(cat "$tmp/out")"
printf '@p:registry=https://registry.npmjs.org/\n' > "$tmp/elsewhere.npmrc"
rc=0
SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$ROOT/bin/safe-audit" package-audit @p/x@1.0.0 --ecosystem npm --gate install \
  --npm-userconfig "$tmp/elsewhere.npmrc" > "$tmp/out" 2>&1 || rc=$?
[[ "$rc" == 20 ]] || fail "real npm with a userconfig mapping the scope to npmjs: rc=$rc $(cat "$tmp/out")"
pass "the spec lane reads the real npm client's scope mapping (18 at the origin, 20 with a --userconfig mapping it elsewhere)"

proj() {
  rm -f "$tmp/result.json"; rc=0
  SAFE_AUDIT_RESULT_OUT="$tmp/result.json" "$ROOT/bin/safe-audit" private-npm-project --tool npm --class ci \
    --project-dir "$tmp/proj" --gate install -- ci > "$tmp/out" 2>&1 || rc=$?
}
mkdir -p "$tmp/proj"
printf '{"name":"app","version":"1.0.0","dependencies":{"@p/x":"1.0.0","private-alias":"npm:@p/x@1.0.0"}}\n' > "$tmp/proj/package.json"
(cd "$tmp/proj" && "$real_npm" install --package-lock-only --ignore-scripts --no-audit --no-fund > "$tmp/npm.log" 2>&1) \
  || fail "real npm could not write the lockfile: $(cat "$tmp/npm.log")"
jq -e '.packages["node_modules/private-alias"].name == "@p/x"' "$tmp/proj/package-lock.json" >/dev/null \
  || fail "real npm alias lockfile shape changed: $(cat "$tmp/proj/package-lock.json")"
proj
[[ "$rc" == 18 ]] && jq -e '[.private_registry_lines[].package] | unique == ["@p/x@1.0.0"]' "$tmp/result.json" >/dev/null \
  || fail "lockfile written by real npm, at the origin: rc=$rc $(cat "$tmp/out")"
jq '.packages["node_modules/private-alias"].resolved = "https://registry.npmjs.org/@p/x/-/x-1.0.0.tgz"' "$tmp/proj/package-lock.json" > "$tmp/l.json" \
  && cp "$tmp/l.json" "$tmp/proj/package-lock.json"
proj
[[ "$rc" == 20 ]] || fail "real npm alias entry resolved elsewhere: rc=$rc $(cat "$tmp/out")"
pass "the project lane sweeps the lockfile real npm writes, aliased entries included (18 at the origin, 20 elsewhere)"
printf 'all live private-registry npm oracle checks passed\n'
