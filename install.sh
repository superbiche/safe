#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${SAFE_BIN_DIR:-$HOME/.local/bin}"
CONFIG_BASE="${SAFE_CONFIG_DIR:-$HOME/.config/safe}"
DATA_BASE="${SAFE_DATA_DIR:-$HOME/.local/share/safe}"
RUN_CONFIG_DIR="$CONFIG_BASE/run"
RUN_DATA_DIR="$DATA_BASE/run"
AUDIT_CONFIG_DIR="$CONFIG_BASE/audit"
AUDIT_DATA_DIR="$DATA_BASE/audit"
WRAPPER_TARGET="$CONFIG_BASE/install-wrappers.zsh"
GATE_LIB_TARGET="$CONFIG_BASE/gate-lib.sh"
# The agent contract travels with the dispatcher: `safe explain` runs from
# ~/.local/bin, which has no ../docs, so the single source is installed here.
AGENT_CONTRACT_TARGET="$CONFIG_BASE/agent-contract.json"
# Tools that get a PATH wrapper. Every wrapper is a dumb 3-line shim into
# `safe gate`; all routing lives in gate-lib.sh, so upgrading safe upgrades the
# gate without rewriting a single wrapper.
GATE_TOOLS=(npm pnpm pnpx yarn bun pip pip3 uv cargo go composer mise)
# Tools installed at exactly the path their wrapper must occupy, so the only
# way to gate them is to move the real binary to <tool>.original.
GATE_DISPLACE_TOOLS=(uv)
# Tools whose wrapper could not be written. Non-empty means the install did not
# achieve what it was asked to, and the exit status must say so.
GATE_WRAPPER_FAILURES=()
COMPLETION_DIR="${SAFE_ZSH_COMPLETION_DIR:-$HOME/.local/share/zsh/site-functions}"
COMPLETION_TARGET="$COMPLETION_DIR/_safe"
ZSHRC="${SAFE_ZSHRC:-$HOME/.zshrc}"
SOURCE_LINE='source "$HOME/.config/safe/install-wrappers.zsh"'
FPATH_LINE='fpath=("$HOME/.local/share/zsh/site-functions" $fpath)'
LEGACY_SAFE_RUN_CONFIG_DIR="${SAFE_RUN_CONFIG_DIR:-$HOME/.config/safe-run}"
LEGACY_SAFE_AUDIT_CONFIG_DIR="${SAFE_AUDIT_CONFIG_DIR:-$HOME/.config/safe-audit}"
LEGACY_SAFE_RUN_DATA_DIR="${SAFE_RUN_DATA_DIR:-$HOME/.local/share/safe-run}"
LEGACY_SAFE_AUDIT_DATA_DIR="${SAFE_AUDIT_DATA_DIR:-$HOME/.local/share/safe-audit}"
LEGACY_WRAPPER_TARGET="$LEGACY_SAFE_RUN_CONFIG_DIR/install-wrappers.zsh"
LEGACY_COMPLETION_TARGET="$LEGACY_SAFE_RUN_CONFIG_DIR/completions/_safe-install"
LEGACY_SOURCE_LINE='source "$HOME/.config/safe-run/install-wrappers.zsh"'
LEGACY_SOURCE_LINE_TILDE='source ~/.config/safe-run/install-wrappers.zsh'
LEGACY_FPATH_LINE='fpath=("$HOME/.config/safe-run/completions" $fpath)'

DO_RUN=0
DO_AUDIT=0
DO_WRAPPERS=0
DO_REVIEW_TIMER=0

err()  { printf '\033[31minstall:\033[0m %s\n' "$*" >&2; }
info() { printf '\033[36minstall:\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33minstall:\033[0m %s\n' "$*" >&2; }
die()  { err "$@"; exit 1; }

# A previous safe install may still own `go` on PATH while this invocation is
# rebuilding its target HOME. Calling that wrapper before this installer has
# copied gate-lib.sh into the target config fails bootstrap. Select the first
# executable `go` that is not a safe wrapper; the normal PATH order still
# chooses a version-manager or system toolchain behind the wrapper.
resolve_real_go() {
  local dir candidate
  local -a dirs=()

  IFS=':' read -r -a dirs <<< "${PATH}"
  for dir in "${dirs[@]}"; do
    [[ -n "$dir" ]] || dir="."
    candidate="${dir}/go"
    [[ -f "$candidate" && -x "$candidate" ]] || continue
    if LC_ALL=C sed -n '2p' -- "$candidate" 2>/dev/null \
      | LC_ALL=C grep -qxF -- '# safe-gate-wrapper v1 tool=go'; then
      continue
    fi
    printf '%s\n' "$candidate"
    return 0
  done
  return 1
}

usage() {
  cat <<'EOF'
usage: bash install.sh [--all] [--run] [--audit] [--wrappers] [--no-wrappers] [--review-timer] [--uninstall]

Default is --all. --review-timer additionally installs and enables the weekly
host-allow staleness review as a systemd user timer (opt-in; machine state).
EOF
}

if [[ $# -eq 0 ]]; then
  DO_RUN=1
  DO_AUDIT=1
  DO_WRAPPERS=1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      DO_RUN=1
      DO_AUDIT=1
      DO_WRAPPERS=1
      ;;
    --run)
      DO_RUN=1
      ;;
    --audit)
      DO_AUDIT=1
      ;;
    --wrappers)
      DO_WRAPPERS=1
      ;;
    --review-timer)
      DO_REVIEW_TIMER=1
      ;;
    --no-wrappers)
      DO_RUN=1
      DO_AUDIT=1
      DO_WRAPPERS=0
      ;;
    --with-completions)
      ;;
    --uninstall)
      exec "$REPO_DIR/uninstall.sh"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

command -v bash >/dev/null 2>&1 || die "missing dependency: bash"
command -v jq >/dev/null 2>&1 || die "missing dependency: jq"
GO_BIN="$(resolve_real_go)" || die "missing dependency: go"
command -v podman >/dev/null 2>&1 || warn "podman not installed; sandbox execution will fail until it is installed"

for script in "$REPO_DIR/bin/safe" "$REPO_DIR/bin/safe-run" "$REPO_DIR/bin/safe-audit"; do
  [[ -f "$script" ]] || die "missing source file: $script"
done
[[ -f "$REPO_DIR/lib/install-wrappers.zsh" ]] || die "missing wrapper source"
[[ -f "$REPO_DIR/lib/gate-lib.sh" ]] || die "missing gate library source"
[[ -f "$REPO_DIR/docs/contract/agent-contract.json" ]] || die "missing agent contract source"
[[ -f "$REPO_DIR/lib/completions/_safe" ]] || die "missing zsh completion"

# Ownership check: a regular (never symlinked) file whose second line is
# EXACTLY our per-tool marker. A loose substring match let a foreign file
# carrying the phrase be overwritten/deleted, and a marked symlink let a
# reinstall truncate its target outside BIN_DIR (PR#30 review finding 5).
gate_wrapper_marked() {
  local path="$1" tool="$2"
  [[ -f "$path" && ! -L "$path" ]] || return 1
  # Byte-stream comparison, never a command substitution: these paths hold
  # arbitrary foreign executables, and capturing an ELF second line into a
  # shell variable made bash emit "ignored null byte in input" warnings from
  # status/doctor/install (PR#30 round regression R1). Same exact whole-line
  # test, no capture.
  LC_ALL=C sed -n '2p' -- "$path" 2>/dev/null \
    | LC_ALL=C grep -qxF -- "# safe-gate-wrapper v1 tool=${tool}"
}

# Any owned wrapper anywhere in the set means gating is live on this machine
# and the library it loads must be refreshed. Probing npm alone missed an
# installation that kept, say, an owned pnpm wrapper and no npm one, leaving
# the library unrestored (PR#30 delta finding 2).
gate_wrappers_exist() {
  local tool
  for tool in "${GATE_TOOLS[@]}"; do
    gate_wrapper_marked "$BIN_DIR/$tool" "$tool" && return 0
  done
  return 1
}

# PATH wrappers are what makes gating work in every shell (bash -c, Makefiles,
# CI, agent harnesses), not just an interactive zsh. A pre-existing file
# without our marker is somebody else's binary: report it and leave it alone.
gate_tool_displaceable() {
  local tool="$1" candidate
  for candidate in "${GATE_DISPLACE_TOOLS[@]}"; do
    [[ "$candidate" == "$tool" ]] && return 0
  done
  return 1
}

write_gate_wrapper() {
  local target="$1" tool="$2"
  if [[ "$tool" == "mise" ]]; then
    # mise multiplexes on argv[0]: its shims are symlinks to whatever `mise`
    # resolves to on PATH, and a reshim run while this wrapper shadows the
    # real binary binds every shim here (2026-08-02: all 36 shims broke and
    # every node-family tool executed mise bare). A shim dispatch must reach
    # the real mise with argv[0] intact and must never enter the gate. The
    # branch is self-contained (no `safe gate` involvement) so a gate bug
    # can never take the whole shim fleet down with it.
    cat > "$target" <<'EOF' || return 1
#!/usr/bin/env bash
# safe-gate-wrapper v1 tool=mise
if [[ "${0##*/}" != "mise" ]]; then
  IFS=: read -ra __dirs <<< "$PATH"
  for __d in "${__dirs[@]}"; do
    [[ -n "$__d" ]] || continue
    __c="${__d%/}/mise"
    [[ -f "$__c" && -x "$__c" ]] || continue
    [[ "$__c" -ef "${BASH_SOURCE[0]}" ]] && continue
    LC_ALL=C head -n 2 -- "$__c" 2>/dev/null | grep -q '^# safe-gate-wrapper' && continue
    exec -a "$0" "$__c" "$@"
  done
  printf 'safe gate: real mise not found on PATH (argv0 dispatch for %s)\n' "${0##*/}" >&2
  exit 127
fi
exec safe gate mise -- "$@"
EOF
    chmod 0755 "$target" || return 1
    return 0
  fi
  cat > "$target" <<EOF || return 1
#!/usr/bin/env bash
# safe-gate-wrapper v1 tool=${tool}
exec safe gate ${tool} -- "\$@"
EOF
  chmod 0755 "$target" || return 1
}

install_gate_wrappers() {
  local tool target moved
  local -a written=() skipped=() displaced=() conflicted=() failed=()

  mkdir -p "$BIN_DIR"
  for tool in "${GATE_TOOLS[@]}"; do
    target="$BIN_DIR/$tool"
    moved=""
    if [[ -e "$target" || -L "$target" ]] && ! gate_wrapper_marked "$target" "$tool"; then
      # For most tools an unmarked file is somebody else's binary and the tool
      # goes ungated. For a tool whose ONLY installation sits at exactly the
      # path the wrapper needs, that rule means it can never be gated at all —
      # uv installs itself to $BIN_DIR/uv, so skipping left `uv add`/`uv sync`
      # permanently outside the gate. Those tools are moved aside instead, and
      # safe_gate_resolve_real falls back to <tool>.original: the convention
      # already in use for uvx.
      if gate_tool_displaceable "$tool" && [[ -f "$target" && ! -L "$target" ]]; then
        if [[ -e "$target.original" || -L "$target.original" ]]; then
          # Never clobber: an existing .original means either a prior
          # displacement whose wrapper was overwritten (a self-update), or a
          # foreign file. Leave both alone and say the tool is ungated.
          conflicted+=("$tool")
          skipped+=("$tool")
          continue
        fi
        if ! mv -- "$target" "$target.original"; then
          skipped+=("$tool")
          continue
        fi
        moved="$target.original"
      else
        skipped+=("$tool")
        continue
      fi
    fi
    rm -f "$target"
    if write_gate_wrapper "$target" "$tool"; then
      [[ -n "$moved" ]] && displaced+=("$tool")
      written+=("$tool")
    else
      # The displacement is only complete once the wrapper is on disk and
      # executable. If the write or the chmod fails — a full filesystem, an I/O
      # error — the user is left with a truncated `uv` and their real binary
      # stranded at uv.original, and every later `uv` call breaks until they
      # find it. Undo both halves: a failed install must never cost the
      # operator their tool.
      rm -f "$target"
      if [[ -n "$moved" ]] && ! mv -- "$moved" "$target"; then
        warn "could not restore $moved to $target — the real $tool binary is at $moved"
      fi
      failed+=("$tool")
    fi
  done

  if [[ "${#written[@]}" -gt 0 ]]; then
    info "installed gate wrappers in $BIN_DIR: ${written[*]}"
  fi
  if [[ "${#displaced[@]}" -gt 0 ]]; then
    info "moved real binaries aside to <tool>.original and gated them: ${displaced[*]}"
  fi
  if [[ "${#failed[@]}" -gt 0 ]]; then
    warn "could not write gate wrappers for: ${failed[*]} — nothing was left half-installed, and these tools stay ungated"
    # Remembered, not raised here: the remaining install steps still run so the
    # machine is left in the most complete state we can reach. The exit status
    # is settled at the end. Before the rollback existed, `set -e` turned a
    # failed wrapper write into a non-zero exit; swallowing it would tell
    # automation, and an operator reading $?, that gating is active when it is
    # not.
    GATE_WRAPPER_FAILURES=("${failed[@]}")
  fi
  if [[ "${#conflicted[@]}" -gt 0 ]]; then
    warn "found an existing <tool>.original for: ${conflicted[*]} — left it and the current binary untouched, so these stay ungated"
  fi
  if [[ "${#skipped[@]}" -gt 0 ]]; then
    warn "kept existing non-safe files, gating NOT active for: ${skipped[*]} (remove them and re-run to gate these tools)"
  fi
}

migrate_dir() {
  local old="$1" new="$2"
  if [[ -e "$old" && ! -e "$new" ]]; then
    mkdir -p "$(dirname "$new")"
    mv "$old" "$new"
    info "migrated $old -> $new"
  elif [[ -e "$old" && -e "$new" ]]; then
    info "both $old and $new exist; merging legacy state into new path"
  fi
}

strip_zshrc_line() {
  local target="$1" line="$2"
  [[ -f "$target" ]] || return 0
  local tmp status
  tmp=$(mktemp)
  if grep -Fvx "$line" "$target" > "$tmp"; then
    :
  else
    status=$?
    if [[ "$status" -gt 1 ]]; then
      rm -f "$tmp"
      return "$status"
    fi
  fi
  if cat "$tmp" > "$target"; then
    rm -f "$tmp"
  else
    status=$?
    rm -f "$tmp"
    return "$status"
  fi
}

cleanup_legacy_install_artifacts() {
  local had_legacy=0
  if [[ -e "$BIN_DIR/safe-install" ]]; then
    rm -f "$BIN_DIR/safe-install"
    had_legacy=1
  fi
  if [[ -e "$LEGACY_WRAPPER_TARGET" ]]; then
    rm -f "$LEGACY_WRAPPER_TARGET"
    had_legacy=1
  fi
  if [[ -e "$LEGACY_COMPLETION_TARGET" ]]; then
    rm -f "$LEGACY_COMPLETION_TARGET"
    had_legacy=1
  fi
  if [[ -d "${LEGACY_SAFE_RUN_CONFIG_DIR}/completions" ]] && [[ -z "$(find "${LEGACY_SAFE_RUN_CONFIG_DIR}/completions" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
    rmdir "${LEGACY_SAFE_RUN_CONFIG_DIR}/completions" 2>/dev/null || true
  fi
  if [[ -f "$ZSHRC" ]]; then
    strip_zshrc_line "$ZSHRC" "$LEGACY_SOURCE_LINE"
    strip_zshrc_line "$ZSHRC" "$LEGACY_SOURCE_LINE_TILDE"
    strip_zshrc_line "$ZSHRC" "$LEGACY_FPATH_LINE"
  fi
  if (( had_legacy )); then
    info "removed legacy safe-install artifacts"
  fi
}

merge_unique_lines() {
  local src="$1" dst="$2"
  [[ -f "$src" ]] || return 0
  mkdir -p "$(dirname "$dst")"
  touch "$dst"
  local tmp
  tmp=$(mktemp)
  awk '!seen[$0]++' "$dst" "$src" > "$tmp"
  mv "$tmp" "$dst"
}

merge_tree_files() {
  local src_root="$1" dst_root="$2"
  [[ -d "$src_root" ]] || return 0
  local src_file rel dst_file alt n
  while IFS= read -r -d '' src_file; do
    rel="${src_file#$src_root/}"
    dst_file="$dst_root/$rel"
    mkdir -p "$(dirname "$dst_file")"
    if [[ ! -e "$dst_file" ]]; then
      cp "$src_file" "$dst_file"
    elif ! cmp -s "$src_file" "$dst_file"; then
      alt="${dst_file}.legacy"
      n=1
      while [[ -e "$alt" ]]; do
        alt="${dst_file}.legacy.$n"
        n=$((n + 1))
      done
      cp "$src_file" "$alt"
    fi
  done < <(find "$src_root" -type f -print0)
}

machine_key_for_legacy_name() {
  local machines_file="$1" legacy_name="$2" resolved
  resolved=$(jq -r --arg name "$legacy_name" '
    .machines
    | to_entries[]
    | select(.key == $name or (.value.host // "") == $name)
    | .key
  ' "$machines_file" 2>/dev/null | head -n 1)
  if [[ -n "$resolved" ]]; then
    printf '%s' "$resolved"
  else
    printf '%s' "$legacy_name"
  fi
}

merge_json_prefer_legacy() {
  local legacy="$1" current="$2" query="$3"
  [[ -f "$legacy" ]] || return 0
  mkdir -p "$(dirname "$current")"
  if [[ ! -f "$current" ]]; then
    cp "$legacy" "$current"
    return 0
  fi
  local tmp
  tmp=$(mktemp)
  jq -s "$query" "$current" "$legacy" > "$tmp"
  mv "$tmp" "$current"
}

merge_run_config_state() {
  merge_json_prefer_legacy \
    "$LEGACY_SAFE_RUN_CONFIG_DIR/blocked.json" \
    "$RUN_CONFIG_DIR/blocked.json" \
    '{
      _note: (.[1]._note // .[0]._note // null),
      packages: ((.[0].packages // {}) + (.[1].packages // {}))
    }'
  merge_json_prefer_legacy \
    "$LEGACY_SAFE_RUN_CONFIG_DIR/host-allow.json" \
    "$RUN_CONFIG_DIR/host-allow.json" \
    '{
      _note: (.[1]._note // .[0]._note // null),
      packages: ((.[0].packages // {}) + (.[1].packages // {}))
    }'
  merge_json_prefer_legacy \
    "$LEGACY_SAFE_RUN_CONFIG_DIR/sandbox-known.json" \
    "$RUN_CONFIG_DIR/sandbox-known.json" \
    '{packages: ((.[0].packages // {}) + (.[1].packages // {}))}'
  merge_json_prefer_legacy \
    "$LEGACY_SAFE_RUN_CONFIG_DIR/config.json" \
    "$RUN_CONFIG_DIR/config.json" \
    '(.[0] // {}) as $current
     | (.[1] // {}) as $legacy
     | ($current + $legacy)
     | .defaults = (($current.defaults // {}) + ($legacy.defaults // {}))
     | .runners = (($current.runners // {}) + ($legacy.runners // {}))
     | .sandbox = (($current.sandbox // {}) + ($legacy.sandbox // {}))
     | .linked_targets = ((($current.linked_targets // []) + ($legacy.linked_targets // [])) | unique)
     | .warn_env_files = (if ($legacy | has("warn_env_files")) then $legacy.warn_env_files else $current.warn_env_files end)'
}

merge_audit_config_state() {
  merge_json_prefer_legacy \
    "$LEGACY_SAFE_AUDIT_CONFIG_DIR/machines.json" \
    "$AUDIT_CONFIG_DIR/machines.json" \
    '{machines: ((.[0].machines // {}) + (.[1].machines // {}))}'

  [[ -f "$LEGACY_SAFE_AUDIT_CONFIG_DIR/tools.json" ]] || return 0
  mkdir -p "$(dirname "$AUDIT_CONFIG_DIR/tools.json")"
  if [[ ! -f "$AUDIT_CONFIG_DIR/tools.json" ]]; then
    cp "$LEGACY_SAFE_AUDIT_CONFIG_DIR/tools.json" "$AUDIT_CONFIG_DIR/tools.json"
  else
    local normalized_tools tmp
    normalized_tools=$(mktemp)
    jq -n \
      --slurpfile machines "$AUDIT_CONFIG_DIR/machines.json" \
      --slurpfile tools "$LEGACY_SAFE_AUDIT_CONFIG_DIR/tools.json" '
      ($machines[0].machines // {}) as $machines
      | ($tools[0] // {}) as $tools
      | reduce ($machines | to_entries[]) as $entry ($tools;
          if .[$entry.key] == null and .[$entry.value.host // ""] != null
          then .[$entry.key] = .[$entry.value.host] | del(.[$entry.value.host])
          else .
          end
        )
    ' > "$normalized_tools"
    tmp=$(mktemp)
    if jq -s '((.[0] // {}) + (.[1] // {}))' "$AUDIT_CONFIG_DIR/tools.json" "$normalized_tools" > "$tmp" \
       && jq -e -s 'length == 1 and (.[0] | type == "object")' "$tmp" >/dev/null 2>&1; then
      mv "$tmp" "$AUDIT_CONFIG_DIR/tools.json"
    else
      rm -f "$tmp"
    fi
    rm -f "$normalized_tools"
  fi

  # A legacy tools.json that was empty, truncated, or a multi-document stream
  # imports verbatim through the `cp` above and would poison every audit's jq
  # cache ops (safe-audit self-heals on its next run, but leaving a broken file
  # installed is a needless footgun). The cache is re-derivable — detection
  # re-probes — so normalizing anything but a single JSON object to `{}` loses
  # nothing. Slurp-and-count so a `[]\n{}` stream is rejected, not accepted on
  # its last document.
  if ! jq -e -s 'length == 1 and (.[0] | type == "object")' "$AUDIT_CONFIG_DIR/tools.json" >/dev/null 2>&1; then
    printf '%s\n' '{}' > "$AUDIT_CONFIG_DIR/tools.json"
  fi
}

merge_audit_machine_data_tree() {
  local src_root="$1" dst_root="$2" machines_file="$3"
  [[ -d "$src_root" ]] || return 0
  local legacy_dir legacy_name canonical dst_dir
  while IFS= read -r -d '' legacy_dir; do
    legacy_name=$(basename "$legacy_dir")
    canonical=$(machine_key_for_legacy_name "$machines_file" "$legacy_name")
    dst_dir="$dst_root/$canonical"
    merge_tree_files "$legacy_dir" "$dst_dir"
  done < <(find "$src_root" -mindepth 1 -maxdepth 1 -type d -print0)
}

merge_legacy_state() {
  merge_run_config_state
  merge_audit_config_state

  merge_unique_lines "$LEGACY_SAFE_RUN_DATA_DIR/audit.log" "$RUN_DATA_DIR/audit.log"
  merge_unique_lines "$LEGACY_SAFE_AUDIT_DATA_DIR/host-allow-log.jsonl" "$AUDIT_DATA_DIR/host-allow-log.jsonl"
  merge_tree_files "$LEGACY_SAFE_AUDIT_DATA_DIR/checks" "$AUDIT_DATA_DIR/checks"
  merge_tree_files "$LEGACY_SAFE_AUDIT_DATA_DIR/ioc" "$AUDIT_DATA_DIR/ioc"
  merge_audit_machine_data_tree "$LEGACY_SAFE_AUDIT_DATA_DIR/results" "$AUDIT_DATA_DIR/results" "$AUDIT_CONFIG_DIR/machines.json"
  merge_audit_machine_data_tree "$LEGACY_SAFE_AUDIT_DATA_DIR/sbom" "$AUDIT_DATA_DIR/sbom" "$AUDIT_CONFIG_DIR/machines.json"
}

seed_file() {
  local src="$1" dst="$2"
  if [[ -e "$dst" ]]; then
    info "config exists, skipping: $dst"
  else
    mkdir -p "$(dirname "$dst")"
    install -m 0644 "$src" "$dst"
    info "seeded $dst"
  fi
}

detect_local_tools_json() {
  local machine="$1" tool path entries=()
  for tool in osv-scanner grype syft govulncheck cargo-audit pip-audit socket; do
    path=$(command -v "$tool" 2>/dev/null || true)
    entries+=("$(jq -n --arg tool "$tool" --arg path "$path" '{key:$tool,value:(if $path == "" then null else $path end)}')")
  done
  printf '%s\n' "${entries[@]}" | jq -s --arg machine "$machine" '{($machine): from_entries}'
}

migrate_dir "$LEGACY_SAFE_RUN_CONFIG_DIR" "$RUN_CONFIG_DIR"
migrate_dir "$LEGACY_SAFE_AUDIT_CONFIG_DIR" "$AUDIT_CONFIG_DIR"
migrate_dir "$LEGACY_SAFE_RUN_DATA_DIR" "$RUN_DATA_DIR"
migrate_dir "$LEGACY_SAFE_AUDIT_DATA_DIR" "$AUDIT_DATA_DIR"
merge_legacy_state

mkdir -p "$BIN_DIR"
# The dispatcher and its installed gate library are ONE upgrade unit: a
# selective mode (--run, --audit, --no-wrappers) that refreshes `safe` while
# active wrappers keep loading an older library would leave a fixed
# dispatcher routing through vulnerable tables (PR#30 review finding 2).
# Refresh the library FIRST (never a new dispatcher with an old library),
# whenever an installed copy or marked wrappers already exist.
if [[ -f "$GATE_LIB_TARGET" ]] || gate_wrappers_exist; then
  mkdir -p "$CONFIG_BASE"
  install -m 0644 "$REPO_DIR/lib/gate-lib.sh" "$GATE_LIB_TARGET"
  info "refreshed gate library at $GATE_LIB_TARGET"
fi
mkdir -p "$CONFIG_BASE"
install -m 0644 "$REPO_DIR/docs/contract/agent-contract.json" "$AGENT_CONTRACT_TARGET"
# Bun Security Scanner API adapter: consumed by hosts implementing Bun's
# scanner contract (mise aube via AUBE_SECURITY_SCANNER, bun >= 1.3 via
# bunfig). The gate injects the env var when this file is present.
install -m 0644 "$REPO_DIR/share/scanner.mjs" "$CONFIG_BASE/scanner.mjs"
safe_core_build="$(mktemp "${TMPDIR:-/tmp}/safe-core.XXXXXX" 2>/dev/null)" || die "cannot allocate safe-core build output"
if ! (
  cd "$REPO_DIR"
  "$GO_BIN" build -trimpath -ldflags "-X main.version=$(tr -d '[:space:]' < VERSION)" \
    -o "$safe_core_build" ./cmd/safe-core
); then
  rm -f -- "$safe_core_build"
  die "safe-core build failed"
fi
install -m 0755 "$REPO_DIR/bin/safe-run" "$BIN_DIR/safe-run"
install -m 0755 "$REPO_DIR/bin/safe-audit" "$BIN_DIR/safe-audit"
install -m 0755 "$safe_core_build" "$BIN_DIR/safe-core"
# Install the dispatcher last: a completed safe binary then has the matching
# safe-core/safe-run/safe-audit siblings already written by this install run.
install -m 0755 "$REPO_DIR/bin/safe" "$BIN_DIR/safe"
rm -f -- "$safe_core_build"
cleanup_legacy_install_artifacts
info "installed binaries to $BIN_DIR"

if (( DO_RUN )); then
  mkdir -p "$RUN_CONFIG_DIR" "$RUN_DATA_DIR"
  seed_file "$REPO_DIR/config/seed/run/host-allow.json" "$RUN_CONFIG_DIR/host-allow.json"
  seed_file "$REPO_DIR/config/seed/run/scripts-allow.json" "$RUN_CONFIG_DIR/scripts-allow.json"
  seed_file "$REPO_DIR/config/seed/run/sandbox-known.json" "$RUN_CONFIG_DIR/sandbox-known.json"
  seed_file "$REPO_DIR/config/seed/run/blocked.json" "$RUN_CONFIG_DIR/blocked.json"
  seed_file "$REPO_DIR/config/seed/run/config.json" "$RUN_CONFIG_DIR/config.json"
  touch "$RUN_DATA_DIR/audit.log"
fi

if (( DO_AUDIT )); then
  mkdir -p "$AUDIT_CONFIG_DIR" "$AUDIT_DATA_DIR"
  seed_file "$REPO_DIR/config/seed/audit/machines.json" "$AUDIT_CONFIG_DIR/machines.json"
  if [[ -e "$AUDIT_CONFIG_DIR/tools.json" ]]; then
    info "config exists, skipping: $AUDIT_CONFIG_DIR/tools.json"
  else
    local_machine=$(jq -r '.machines | to_entries[] | select(.value.type == "local") | .key' "$AUDIT_CONFIG_DIR/machines.json" | head -n 1)
    [[ -n "$local_machine" ]] || local_machine="local"
    detect_local_tools_json "$local_machine" > "$AUDIT_CONFIG_DIR/tools.json"
    info "seeded $AUDIT_CONFIG_DIR/tools.json"
  fi
  touch "$AUDIT_DATA_DIR/host-allow-log.jsonl"
fi

if (( DO_WRAPPERS )); then
  mkdir -p "$CONFIG_BASE"
  install -m 0644 "$REPO_DIR/lib/install-wrappers.zsh" "$WRAPPER_TARGET"
  install -m 0644 "$REPO_DIR/lib/gate-lib.sh" "$GATE_LIB_TARGET"
  install_gate_wrappers
  touch "$ZSHRC"
  if grep -Fqx "$SOURCE_LINE" "$ZSHRC" || grep -Fqx 'source ~/.config/safe/install-wrappers.zsh' "$ZSHRC"; then
    info "wrapper source line already present in $ZSHRC"
  else
    {
      printf '\n'
      printf '# safe persistent install wrappers\n'
      printf '%s\n' "$SOURCE_LINE"
    } >> "$ZSHRC"
    info "added wrapper source line to $ZSHRC"
  fi
fi

mkdir -p "$COMPLETION_DIR"
install -m 0644 "$REPO_DIR/lib/completions/_safe" "$COMPLETION_TARGET"
touch "$ZSHRC"
if grep -Fqx "$FPATH_LINE" "$ZSHRC"; then
  info "completion fpath already present in $ZSHRC"
else
  {
    printf '\n'
    printf '# safe zsh completions\n'
    printf '%s\n' "$FPATH_LINE"
  } >> "$ZSHRC"
  info "added completion fpath line to $ZSHRC"
fi

if (( DO_REVIEW_TIMER )); then
  SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  mkdir -p "$SYSTEMD_USER_DIR"
  install -m 0644 "$REPO_DIR/systemd/safe-host-allow-review.service" "$SYSTEMD_USER_DIR/"
  install -m 0644 "$REPO_DIR/systemd/safe-host-allow-review.timer" "$SYSTEMD_USER_DIR/"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload
    systemctl --user enable --now safe-host-allow-review.timer
    info "enabled weekly host-allow review timer (safe-host-allow-review.timer)"
  else
    warn "systemctl not found; timer units installed to $SYSTEMD_USER_DIR but not enabled"
  fi
fi

info ""
info "installed safe $("$BIN_DIR/safe" version | head -n 1 | awk '{print $2}')"
info "next steps:"
info "  1. Ensure $BIN_DIR is in PATH"
info "  2. Run: safe run link"
info "  3. Review: $AUDIT_CONFIG_DIR/machines.json"
info "  4. Run: safe audit setup"
info "  5. Verify: safe status"

if [[ "${#GATE_WRAPPER_FAILURES[@]}" -gt 0 ]]; then
  err "gate wrappers could not be installed for: ${GATE_WRAPPER_FAILURES[*]} — these tools are NOT gated"
  exit 1
fi
