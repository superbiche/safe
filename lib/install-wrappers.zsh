# safe install wrappers — retired, kept as a sourcing stub
#
# Install gating used to live here as zsh functions (npm/pnpm/yarn/bun/pip/
# uv/cargo/go/composer/volta), which meant it only existed inside an
# interactive zsh: `bash -c 'npm i evil'`, a Makefile recipe, a CI step, or an
# agent harness went straight to the version-manager shim and was never
# audited. Gating now ships as executable wrappers on PATH
# (~/.local/bin/npm and friends) that exec `safe gate <tool> -- "$@"`, with all
# routing in lib/gate-lib.sh — so it applies in every shell and every
# non-interactive context.
#
# This file defines NO wrapper functions. It stays because existing .zshrc
# files source it, and because an interactive shell is the right place to tell
# the operator when gating is silently absent.
#
# Note: a zsh session started before the upgrade still has the old wrapper
# functions defined; they shadow the PATH wrappers until the shell restarts.

typeset -g _SAFE_GATE_WARNED="${_SAFE_GATE_WARNED:-0}"

_safe_gate_shell_check() {
  (( ${_SAFE_GATE_WARNED:-0} )) && return 0
  [[ -o interactive ]] || return 0
  (( $+commands[safe] )) || return 0

  # Check the FULL wrapper set with the exact per-tool marker — an npm-only
  # probe concealed missing or foreign sibling wrappers.
  local bin_dir="${SAFE_BIN_DIR:-$HOME/.local/bin}"
  local tool wrapper
  local -a broken=()
  for tool in npm pnpm pnpx yarn bun pip pip3 uv cargo go composer; do
    wrapper="${bin_dir}/${tool}"
    if [[ ! -f "${wrapper}" || -L "${wrapper}" ]] \
      || ! LC_ALL=C sed -n '2p' "${wrapper}" 2>/dev/null \
           | LC_ALL=C grep -qxF -- "# safe-gate-wrapper v1 tool=${tool}"; then
      broken+=("${tool}")
    fi
  done
  if (( ${#broken[@]} > 0 )); then
    print -u2 -- "safe: install gating is NOT active for: ${broken[*]} — run safe's install.sh; details: safe status"
    _SAFE_GATE_WARNED=1
  fi

  return 0
}

_safe_gate_shell_check
unfunction _safe_gate_shell_check 2>/dev/null
