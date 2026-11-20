#!/usr/bin/env bash
# The judge of the npm option oracle: what the gate observably did with a command line, against what npm's own
# parser says about it. Sourced; pure (it calls nothing of the gate), so that tests/lib/npm-option-gate-oracle.sh
# --selftest can feed it a wrong observation of each kind and require a reported disagreement.
#
# Inputs (globals set by the caller):
#   J_ARGS[]        the command line, as given
#   J_RC            the gate's exit status; J_ERR_LINES the number of stderr lines; J_ERR_FIRST the first one
#   J_DELEGATIONS[] one entry per delegation to npm: its arguments joined by US (0x1f); J_SUBCMDS[] the command word
#                   the gate held at that moment; J_CANON the canonical command the gate makes of it
#   J_AUDITS[]      the exact identities the gate audited; J_SCANNED 1 when the project scan ran
#   J_GLOBALS[]     each answer the gate gave, in that invocation, to "is this command global"
#   NPM_REMAIN[] NPM_GLOBAL NPM_COMMAND NPM_CLASS   npm's reading (the command is `-` when npm resolves none; the class is
#                   what the gate's table makes of the command)
#   NPM_LOCGLOBAL   1 when npm's location setting is global (a gated command with it is refused: npm 8.1.0 parses it and
#                   does not act on it, later versions do); NPM_GLOBAL is the mode THIS npm acts on
#   EXPECTED[]      the identities npm fetches, as the gate spells an audited identity; the gate's audits must be exactly
#                   this set (nothing missing, nothing extra), for every command, gated or not
# Prints one `kind<TAB>detail` line per disagreement; returns their number.
npm_oracle_judge() {
  local n=0 us=$'\x1f' joined want i e o found oname ename scan_expected=0 class="${NPM_CLASS:-}"
  _dis() { printf '%s\t%s\n' "$1" "$2"; n=$((n + 1)); }
  case "${J_RC}" in
    0|100) ;;
    *) _dis harness-error "exit status ${J_RC}"; return "${n}" ;;
  esac
  if [[ "${J_RC}" == 100 ]]; then
    # a refusal is exit 100 with ONE line that is the gate's: anything else is a harness or gate error, not a refusal
    if [[ "${J_ERR_LINES}" != 1 || "${J_ERR_FIRST}" != "safe: BLOCKED "* ]]; then _dis harness-error "exit 100 with ${J_ERR_LINES} stderr lines (${J_ERR_FIRST:0:80})"; fi
    # a refusal delegates nothing
    if (( ${#J_DELEGATIONS[@]} )); then _dis delegation-on-refusal "${#J_DELEGATIONS[@]} delegation(s) beside a refusal"; fi
    return "${n}"
  fi
  # the gate let the command through: one delegation, of exactly the arguments given
  if (( ${#J_DELEGATIONS[@]} != 1 )); then _dis delegation-count "${#J_DELEGATIONS[@]} delegations"; return "${n}"; fi
  printf -v joined '%s\x1f' "${J_ARGS[@]}"
  [[ "${J_DELEGATIONS[0]}" == "${joined}" ]] || _dis delegation-args "the delegated arguments differ from the command line"
  if [[ "${NPM_COMMAND}" != "-" ]]; then
    [[ "${J_SUBCMDS[0]-}" == "${NPM_REMAIN[0]-}" ]] || _dis command-word "gate '${J_SUBCMDS[0]-}', npm '${NPM_REMAIN[0]-}'"
    # a command the gate does not gate has no canonical command: the gate must make none of it, as it makes none of npm's
    want="${NPM_COMMAND}"; [[ -n "${class}" ]] || want=""
    [[ "${J_CANON}" == "${want}" ]] || _dis command "gate '${J_CANON}', npm '${NPM_COMMAND}' (class ${class:-none})"
  fi
  # the audited identities are EXACTLY the identities npm fetches, in both directions, whatever the command
  for e in ${EXPECTED[@]+"${EXPECTED[@]}"}; do
    found=0
    for o in ${J_AUDITS[@]+"${J_AUDITS[@]}"}; do [[ "${o}" == "${e}" ]] && found=1; done
    (( found )) || _dis package-unaudited "npm fetches '${e}'; audited: ${J_AUDITS[*]:-nothing}"
  done
  for o in ${J_AUDITS[@]+"${J_AUDITS[@]}"}; do
    found=0; oname="${o%@*}"; [[ "${o}" == @*/* && "${o#@*/}" != *@* ]] && oname="${o}"
    for e in ${EXPECTED[@]+"${EXPECTED[@]}"}; do
      ename="${e%@*}"; [[ "${e}" == @*/* && "${e#@*/}" != *@* ]] && ename="${e}"
      [[ "${o}" == "${e}" ]] && found=2
      [[ "${oname}" == "${ename}" && "${o}" != "${e}" && "${found}" != 2 ]] && found=1
    done
    if (( found == 1 )); then _dis package-wrong-version "audited '${o}', npm fetches a different version of that name"
    elif (( found == 0 )); then _dis package-extra "audited '${o}', which npm does not fetch (npm fetches: ${EXPECTED[*]:-nothing})"; fi
  done
  # a gated command whose location setting is global is refused (the one global form the gate reads is -g)
  if [[ -n "${class}" ]] && (( ${NPM_LOCGLOBAL:-0} )); then _dis location-global-accepted "a ${class} command with a global location went through"; fi
  if [[ "${NPM_COMMAND}" != "-" ]]; then
    case "${class}" in install|update|install-test|install-ci-test|ci) (( ! NPM_GLOBAL )) && scan_expected=1 ;; esac
    if (( J_SCANNED != scan_expected )); then _dis scan-decision "project scan ran=${J_SCANNED}, expected ${scan_expected} (npm global=${NPM_GLOBAL}, class ${class:-none})"; fi
    case "${class}" in
      install|update|install-test|install-ci-test)
        if (( ${#J_GLOBALS[@]} == 0 )); then _dis global-not-read "the gate never decided global mode"; fi ;;
    esac
    case "${class}" in install|update|install-test|install-ci-test|ci|lockdiff)
      for o in ${J_GLOBALS[@]+"${J_GLOBALS[@]}"}; do
        [[ "${o}" == "${NPM_GLOBAL}" ]] || { _dis global-mode "the gate decided ${o}, npm ${NPM_GLOBAL}"; break; }
      done ;;
    esac
  fi
  return "${n}"
}
