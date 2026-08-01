#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${SAFE_BIN_DIR:-$HOME/.local/bin}"
CONFIG_BASE="${SAFE_CONFIG_DIR:-$HOME/.config/safe}"
DATA_BASE="${SAFE_DATA_DIR:-$HOME/.local/share/safe}"
COMPLETION_DIR="${SAFE_ZSH_COMPLETION_DIR:-$HOME/.local/share/zsh/site-functions}"
ZSHRC="${SAFE_ZSHRC:-$HOME/.zshrc}"
LEGACY_SAFE_RUN_CONFIG_DIR="${SAFE_RUN_CONFIG_DIR:-$HOME/.config/safe-run}"
LEGACY_SAFE_AUDIT_CONFIG_DIR="${SAFE_AUDIT_CONFIG_DIR:-$HOME/.config/safe-audit}"
LEGACY_SAFE_RUN_DATA_DIR="${SAFE_RUN_DATA_DIR:-$HOME/.local/share/safe-run}"
LEGACY_SAFE_AUDIT_DATA_DIR="${SAFE_AUDIT_DATA_DIR:-$HOME/.local/share/safe-audit}"
REMOVE_CONFIG=0
REMOVE_SOURCE=0

info() { printf '\033[36muninstall:\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33muninstall:\033[0m %s\n' "$*" >&2; }

usage() {
  cat <<'EOF'
usage: bash uninstall.sh [--all|--purge]

Default removes binaries and completions, preserving config and data.
EOF
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      REMOVE_CONFIG=1
      ;;
    --purge)
      REMOVE_CONFIG=1
      REMOVE_SOURCE=1
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

if [[ -x "$BIN_DIR/safe-run" ]]; then
  if ! "$BIN_DIR/safe-run" unlink >/dev/null 2>&1; then
    warn "safe run unlink failed; PATH may still contain linked runner shims"
  fi
fi

rm -f \
  "$BIN_DIR/safe" \
  "$BIN_DIR/safe-run" \
  "$BIN_DIR/safe-audit" \
  "$BIN_DIR/safe-install" \
  "$BIN_DIR/safe-npx" \
  "$BIN_DIR/safe-bunx" \
  "$BIN_DIR/safe-uvx" \
  "$BIN_DIR/safe-pipx-run"
rm -f "$COMPLETION_DIR/_safe"
rm -f "$LEGACY_SAFE_RUN_CONFIG_DIR/completions/_safe-install"
info "removed binaries and zsh completions"

# Only files we generated: a regular (never symlinked) file whose second line
# is EXACTLY our per-tool marker. Anything else belongs to somebody else and
# stays (PR#30 review finding 5).
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

removed_wrappers=()
for tool in npm pnpm pnpx yarn bun pip pip3 uv cargo go composer mise; do
  if gate_wrapper_marked "$BIN_DIR/$tool" "$tool"; then
    rm -f "$BIN_DIR/$tool"
    removed_wrappers+=("$tool")
  fi
done
rm -f "$CONFIG_BASE/gate-lib.sh"
if [[ "${#removed_wrappers[@]}" -gt 0 ]]; then
  info "removed gate wrappers: ${removed_wrappers[*]}"
fi

if [[ -f "$ZSHRC" ]]; then
  strip_zshrc_line "$ZSHRC" 'source "$HOME/.config/safe/install-wrappers.zsh"'
  strip_zshrc_line "$ZSHRC" 'source ~/.config/safe/install-wrappers.zsh'
  strip_zshrc_line "$ZSHRC" 'fpath=("$HOME/.local/share/zsh/site-functions" $fpath)'
  strip_zshrc_line "$ZSHRC" 'source "$HOME/.config/safe-run/install-wrappers.zsh"'
  strip_zshrc_line "$ZSHRC" 'source ~/.config/safe-run/install-wrappers.zsh'
  strip_zshrc_line "$ZSHRC" 'fpath=("$HOME/.config/safe-run/completions" $fpath)'
  info "removed safe shell activation lines from $ZSHRC"
fi

if (( REMOVE_CONFIG )); then
  rm -rf \
    "$CONFIG_BASE" \
    "$DATA_BASE" \
    "$LEGACY_SAFE_RUN_CONFIG_DIR" \
    "$LEGACY_SAFE_AUDIT_CONFIG_DIR" \
    "$LEGACY_SAFE_RUN_DATA_DIR" \
    "$LEGACY_SAFE_AUDIT_DATA_DIR"
  info "removed config and data"
fi

if (( REMOVE_SOURCE )) && [[ -f "$ZSHRC" ]]; then
  info "removed source/fpath lines from $ZSHRC"
fi
