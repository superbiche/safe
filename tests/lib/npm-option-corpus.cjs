#!/usr/bin/env node
// The differential corpus of the npm option oracle, read by npm's OWN parser (nopt with npm's own types
// and shorthands, offline: nothing is installed or run). One case per line, tab separated:
//   <arguments joined by US (0x1f)> RS <npm's positional arguments, US-joined> RS <global 0|1> RS <command or -> RS <the values of --package, US-joined>
// (RS is 0x1e: a field separator that `read` does not collapse when a field is empty)
// where the command is what npm's own `deref` makes of the first positional argument.
//
//   node tests/lib/npm-option-corpus.cjs <npm dir> [--quick | --sample=N]
//
// Every option npm defines, in the forms --x, --x=v, --x v, --no-x, its shorthands (alone, with =v, with a
// value) and abbreviations (unique prefixes, with and without =v); before the command, after it, between
// package arguments, and in front of a command hidden by the value; with the values true, false, a command
// name, a package name and a word that looks like an option. --quick keeps one option in four, --sample=N one in N.
'use strict'
const path = require('path')
const npmDir = process.argv[2]
const sampleArg = process.argv.find((a) => a.startsWith('--sample='))
const sample = sampleArg ? Number(sampleArg.slice(9)) : (process.argv.includes('--quick') ? 4 : 1)
const quick = sample > 1
const nopt = require(path.join(npmDir, 'node_modules', 'nopt'))
const abbrev = require(path.join(npmDir, 'node_modules', 'abbrev'))
const { definitions, shorthands } = require(path.join(npmDir, 'node_modules', '@npmcli', 'config', 'lib', 'definitions'))
const { deref } = require(path.join(npmDir, 'lib', 'utils', 'cmd-list.js'))
const types = {}
for (const [k, d] of Object.entries(definitions)) types[k] = d.type
nopt.invalidHandler = () => {}
nopt.unknownHandler = () => {}
nopt.abbrevHandler = () => {}

const US = '\x1f'
let count = 0
const seen = new Set()
function emit(args) {
  const key = args.join(US)
  if (seen.has(key)) return
  seen.add(key)
  const parsed = nopt(types, shorthands, ['node', 'npm', ...args], 2)
  const remain = parsed.argv.remain
  const global = parsed.global === true || parsed.location === 'global'
  let command = null
  try { command = deref(remain[0]) } catch (e) { command = null }
  const pkgOpt = parsed.package === undefined ? [] : [].concat(parsed.package).filter((x) => typeof x === 'string')
  process.stdout.write(`${key}\x1e${remain.join(US)}\x1e${global ? 1 : 0}\x1e${command || '-'}\x1e${pkgOpt.join(US)}\n`)
  count++
}

const names = Object.keys(types).sort()
const keys = quick ? names.filter((_, i) => i % sample === 0) : names
const abbrevs = abbrev(Object.keys(types))
// the shortest and one longer unique abbreviation of an option, when they differ from the name
function abbreviations(name) {
  const out = []
  for (let n = 1; n < name.length; n++) {
    const p = name.slice(0, n)
    if (abbrevs[p] === name) { out.push(p); if (name.length - n > 1) out.push(name.slice(0, n + 1)); break }
  }
  return [...new Set(out)].filter((a) => abbrevs[a] === name && a !== name)
}
const values = ['true', 'false', 'install', 'evilpkg', '-g', '--']
const shortNames = Object.keys(shorthands).sort()

// the places a spelling can sit
function placements(spelling) {
  // spelling: array of tokens (one option, possibly with its value as a separate token)
  return [
    [...spelling, 'install', 'evilpkg'],
    ['install', ...spelling, 'evilpkg'],
    ['install', 'pkga', ...spelling, 'evilpkg'],
    ['exec', ...spelling, 'evilpkg'],
    ['view', ...spelling, 'evilpkg'],
    [...spelling, 'evilpkg'],
    ['install', 'evilpkg', ...spelling],
  ]
}

for (const name of keys) {
  const spellings = [[`--${name}`], [`--no-${name}`]]
  for (const v of values) {
    spellings.push([`--${name}=${v}`], [`--${name}`, v], [`--no-${name}=${v}`])
  }
  for (const a of abbreviations(name)) {
    spellings.push([`--${a}`], [`--${a}=evilpkg`], [`--${a}=true`], [`--${a}=install`])
  }
  for (const s of spellings) for (const full of placements(s)) emit(full)
}
for (const sh of shortNames) {
  const dashed = sh.length === 1 ? `-${sh}` : `--${sh}`
  const spellings = [[dashed]]
  for (const v of values) spellings.push([`${dashed}=${v}`], [dashed, v])
  for (const s of spellings) for (const full of placements(s)) emit(full)
}
// clusters of single-letter shorthands, alone and with a value
const singles = shortNames.filter((s) => s.length === 1)
for (const a of singles) for (const b of singles) {
  if (quick && (a.charCodeAt(0) + b.charCodeAt(0)) % (sample + 1)) continue
  for (const full of placements([`-${a}${b}`])) emit(full)
  for (const v of ['evilpkg', 'true', 'install']) for (const full of placements([`-${a}${b}=${v}`])) emit(full)
}
// unknown names, with and without a value
for (const u of ['--frobnicate', '--no-frobnicate', '--frobnicate=true', '--frobnicate=evilpkg', '--frobnicate=install', '--filter', '--cwd=evilpkg', '--mode=evilpkg', '--//registry.npmjs.org/:_authToken=evilpkg']) {
  for (const full of placements([u])) emit(full)
  for (const full of placements([u, 'evilpkg'])) emit(full)
}
// the terminator
for (const full of [['--', 'install', 'evilpkg'], ['install', '--', '--json=evilpkg'], ['install', '--json=evilpkg', '--', 'x'], ['exec', '--', '--json=evilpkg'], ['---', 'install', 'evilpkg']]) emit(full)
process.stderr.write(`corpus: ${count} cases from ${keys.length} of ${names.length} options and ${shortNames.length} shorthands\n`)
