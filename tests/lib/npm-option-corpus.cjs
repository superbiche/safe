#!/usr/bin/env node
// The differential corpus of the npm option oracle, read by npm's OWN parser (nopt with npm's own types
// and shorthands, offline: nothing is installed or run). One case per line, tab separated:
//   <arguments> TAB <npm's positional arguments> TAB <global 0|1> TAB <command or -> TAB <the values of --package>
//   TAB <1 when --call is set>
// where the command is what npm's own `deref` makes of the first positional argument. A list is its members
// percent-encoded (every byte outside A-Za-z0-9_.:/@=+-, so a tab, a newline, a comma or a control character
// survives), comma separated; the empty string is `%00` and the empty list is a lone `%` (see
// tests/lib/npm-option-corpus.sh, which decodes).
//
//   node tests/lib/npm-option-corpus.cjs <npm dir> [--union=<dir>,<dir>...] [--quick | --sample=N]
//
// --union: the names (options and shorthands) the cases are made of are the union of those of the given npm
// installations and the one under test; npm's parser under test reads them with ITS OWN definitions, so a name this npm
// does not define (one a newer npm adds) is tried against it as an unknown name, which is how an older npm reads it.
//
// Families (each counted on stderr): every option npm defines in the forms --x, --x=v, --x v, --no-x, with the
// values true, false, a command name, a package name, a word that looks like an option and the terminator, before
// the command, after it, between package arguments, before `exec`; the shorthands alone, with a value, and in clusters
// (also with a double dash: nopt strips every leading dash); the literal values of every option that lists some;
// abbreviations (every unique prefix); pairs of the options the gate interprets; empty arguments and control
// characters; the terminator. --quick keeps one option in four, --sample=N one in N.
'use strict'
const path = require('path')
const npmDir = process.argv[2]
const sampleArg = process.argv.find((a) => a.startsWith('--sample='))
const sample = sampleArg ? Number(sampleArg.slice(9)) : (process.argv.includes('--quick') ? 4 : 1)
const quick = sample > 1
const nopt = require(path.join(npmDir, 'node_modules', 'nopt'))
const abbrev = require(path.join(npmDir, 'node_modules', 'abbrev'))
function loadDefinitions(dir) {
  for (const rel of [['node_modules', '@npmcli', 'config', 'lib', 'definitions'], ['lib', 'utils', 'config']]) {
    try { return require(path.join(dir, ...rel)) } catch (e) { /* the other layout */ }
  }
  throw new Error(`no option definitions under ${dir}`)
}
const { definitions, shorthands } = loadDefinitions(npmDir)
const unionArg = process.argv.find((a) => a.startsWith('--union='))
// the generation tables: this npm's own, extended with the names the other installations define
const genTypes = {}
const genShorthands = { ...shorthands }
for (const [k, d] of Object.entries(definitions)) genTypes[k] = d.type
for (const dir of unionArg ? unionArg.slice(8).split(',').filter(Boolean) : []) {
  const other = loadDefinitions(dir)
  for (const [k, d] of Object.entries(other.definitions)) if (genTypes[k] === undefined) genTypes[k] = d.type
  for (const [k, v] of Object.entries(other.shorthands)) if (genShorthands[k] === undefined) genShorthands[k] = v
}
// npm 8 keeps the command resolution in lib/utils/deref-command.js, later versions in cmd-list.js
let deref
try { ({ deref } = require(path.join(npmDir, 'lib', 'utils', 'cmd-list.js'))) } catch (e) { deref = undefined }
if (typeof deref !== 'function') deref = require(path.join(npmDir, 'lib', 'utils', 'deref-command.js'))
const types = {}
for (const [k, d] of Object.entries(definitions)) types[k] = d.type
nopt.invalidHandler = () => {}
nopt.unknownHandler = () => {}
nopt.abbrevHandler = () => {}

const enc = (s) => (s === '' ? '%00' : [...Buffer.from(s, 'utf8')].map((b) => (/[A-Za-z0-9_.:/@=+-]/.test(String.fromCharCode(b)) ? String.fromCharCode(b) : '%' + b.toString(16).padStart(2, '0'))).join(''))
const list = (xs) => (xs.length === 0 ? '%' : xs.map(enc).join(','))
let count = 0
const families = {}
const seen = new Set()
function emit(family, args) {
  const key = list(args)
  if (seen.has(key)) return
  seen.add(key)
  const parsed = nopt(types, shorthands, ['node', 'npm', ...args], 2)
  const remain = parsed.argv.remain
  const global = parsed.global === true || parsed.location === 'global'
  let command = null
  try { command = deref(remain[0]) } catch (e) { command = null }
  const pkgOpt = parsed.package === undefined ? [] : [].concat(parsed.package).filter((x) => typeof x === 'string')
  process.stdout.write([key, list(remain), global ? 1 : 0, command || '-', list(pkgOpt), parsed.call === undefined ? 0 : 1].join('\t') + '\n')
  count++
  families[family] = (families[family] || 0) + 1
}

const names = Object.keys(genTypes).sort()
const keys = quick ? names.filter((_, i) => i % sample === 0) : names
const abbrevs = abbrev(Object.keys(genTypes))
function allAbbreviations(name) {
  const out = []
  for (let n = 1; n < name.length; n++) if (abbrevs[name.slice(0, n)] === name) out.push(name.slice(0, n))
  return out
}
function literals(name) {
  const t = genTypes[name]
  if (!Array.isArray(t) || name === 'local-address') return []
  return t.filter((m) => typeof m === 'string')
}
const values = ['true', 'false', 'install', 'evilpkg', '-g', '--']
const shortNames = Object.keys(genShorthands).sort()

// the places a spelling can sit
function placements(spelling) {
  return [
    [...spelling, 'install', 'evilpkg'],
    ['install', ...spelling, 'evilpkg'],
    ['install', 'pkga', ...spelling, 'evilpkg'],
    ['exec', ...spelling, 'evilpkg'],
    [...spelling, 'exec', 'evilpkg'],
    [...spelling, 'x', '-c', 'cmd'],
    ['view', ...spelling, 'evilpkg'],
    [...spelling, 'evilpkg'],
    ['install', 'evilpkg', ...spelling],
  ]
}
// the fewer places a family that multiplies spellings needs: before the verb, after it, before exec
function placementsLite(spelling) {
  return [[...spelling, 'install', 'evilpkg'], ['install', ...spelling, 'evilpkg'], [...spelling, 'exec', 'evilpkg'], ['view', ...spelling, 'evilpkg']]
}
const fam = (family, spellings, lite = false) => { for (const s of spellings) for (const full of (lite ? placementsLite(s) : placements(s))) emit(family, full) }

for (const name of keys) {
  const spellings = [[`--${name}`], [`--no-${name}`]]
  for (const v of values) spellings.push([`--${name}=${v}`], [`--${name}`, v], [`--no-${name}=${v}`])
  spellings.push([`--${name}=`], [`--${name}`, ''], [`--${name}= global `], [`--${name}= evilpkg`])
  fam('options', spellings)
  const lit = literals(name).flatMap((l) => [[`--${name}=${l}`], [`--${name}`, l], [`--no-${name}=${l}`], [`--no-${name}`, l]])
  fam('literals', lit, true)
  const ab = allAbbreviations(name).flatMap((a) => [[`--${a}`], [`--${a}=true`], [`--${a}=evilpkg`], [`--${a}`, 'evilpkg']])
  fam('abbreviations', ab, true)
}
for (const sh of shortNames) {
  const dashed = sh.length === 1 ? `-${sh}` : `--${sh}`
  const spellings = [[dashed], [`-${sh}`], [`--${sh}`]]
  for (const v of values) spellings.push([`${dashed}=${v}`], [dashed, v])
  fam('shorthands', spellings, true)
}
// clusters of single-letter shorthands, with one, two and three dashes, alone and with a value
const singles = shortNames.filter((s) => s.length === 1)
for (const a of singles) for (const b of singles) {
  if (quick && (a.charCodeAt(0) + b.charCodeAt(0)) % (sample + 1)) continue
  const sp = []
  for (const dash of ['-', '--']) {
    sp.push([`${dash}${a}${b}`])
    for (const v of ['evilpkg', 'true', 'install']) sp.push([`${dash}${a}${b}=${v}`])
  }
  fam('clusters', sp, true)
}
for (const c of ['-gfD', '--gfD', '---gf', '-gCq', '--cwd', '--Cq', '-dg', '-Dg', '-gD=x']) fam('clusters', [[c], [c, 'evilpkg']], true)
// unknown names, with and without a value
for (const u of ['--frobnicate', '--no-frobnicate', '--frobnicate=true', '--frobnicate=evilpkg', '--frobnicate=install', '--filter', '--cwd=evilpkg', '--mode=evilpkg', '--//registry.npmjs.org/:_authToken=evilpkg', '--@scope:registry=evilpkg', '--@scope:registry']) {
  fam('unknown', [[u], [u, 'evilpkg']])
}
// pairs of options, the ones the gate interprets and the common ones: every order, both sides of the verb
const pairNames = ['global', 'location', 'package', 'call', 'json', 'yes', 'prefix', 'registry', 'color', 'save-dev'].filter((n) => genTypes[n] !== undefined)
const pairSpell = (n) => [[`--${n}`], [`--${n}=true`], [`--${n}=evilpkg`], [`--${n}=global`], [`--${n}`, 'evilpkg']]
const pairUnits = pairNames.flatMap(pairSpell).filter((_, i) => !quick || i % sample === 0)
for (const a of pairUnits) for (const b of pairUnits) {
  if (quick && ((a.join(' ').length + b.join(' ').length) % sample)) continue
  const two = [...a, ...b]
  for (const full of [[...two, 'install', 'evilpkg'], ['install', ...two, 'evilpkg'], [...two, 'exec', 'evilpkg'], ['exec', ...two, 'cowsay']]) emit('pairs', full)
}
// empty arguments and control characters, as arguments and inside options
const odd = ['', ' ', '\t', '\n', 'a\nb', '\u001b[31m', 'evil pkg', '\u0000'.slice(0, 0) + 'ev\u0001il', 'évil', '-']
for (const o of odd) {
  for (const full of [['install', o, 'evilpkg'], [o, 'install', 'evilpkg'], ['install', 'evilpkg', o], ['exec', o], ['install', `--json=${o}`, 'evilpkg'], [`--${o}=1`, 'install', 'evilpkg'], [`--location=${o}`, 'install', 'evilpkg'], ['install', '--registry', o, 'evilpkg']]) emit('odd', full)
}
// the terminator
for (const full of [['--', 'install', 'evilpkg'], ['install', '--', '--json=evilpkg'], ['install', '--json=evilpkg', '--', 'x'], ['exec', '--', '--json=evilpkg'], ['---', 'install', 'evilpkg'], ['install', '---', 'evilpkg']]) emit('terminator', full)
process.stderr.write(`corpus: ${count} cases from ${keys.length} of ${names.length} options (${Object.keys(types).length} defined by this npm) and ${shortNames.length} shorthands (${Object.entries(families).map(([k, v]) => `${k} ${v}`).join(', ')})\n`)
