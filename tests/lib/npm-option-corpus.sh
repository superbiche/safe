#!/usr/bin/env bash
# Decoding of the npm option corpus (tests/lib/npm-option-corpus.cjs): a list is percent-encoded members, comma
# separated; the empty string is %00; the empty list is a lone %. Sourced.

# $1 the encoded list, $2 the name of the array to fill
npm_corpus_list() {
  local -n _out="$2"
  local raw="$1" item
  local -a parts=()
  _out=()
  [[ -n "${raw}" && "${raw}" != % ]] || return 0
  IFS=',' read -r -a parts <<<"${raw}"
  for item in "${parts[@]}"; do
    if [[ "${item}" == "%00" ]]; then _out+=(""); else printf -v item '%b' "${item//%/\\x}"; _out+=("${item}"); fi
  done
}
