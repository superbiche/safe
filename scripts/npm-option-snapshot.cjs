#!/usr/bin/env node
// Prints, for one or more npm installations, the option types the gate's front door reads: per option
// (key) the letters B (the type is or includes Boolean), S (exactly String), A (null is allowed), N (an
// array type that includes Number), T (an array type that includes String), Y (an array type of more than
// one member), then after a colon the literal string members of an array type (`color=ABY:always`: nopt
// takes `always` as the option's value though the type includes Boolean), and per shorthand its expansion. These are the facts nopt (npm's argument parser) decides
// value consumption by. With several installations the options are merged: letters are united, so a
// name npm renamed or retyped keeps the more cautious reading.
//
//   node scripts/npm-option-snapshot.cjs <npm dir>...            # the merged snapshot, as bash array lines
//   node scripts/npm-option-snapshot.cjs --one <npm dir>          # one installation, as `kind<TAB>name<TAB>value`
//
// An npm dir is the directory holding npm's package.json (…/lib/node_modules/npm).
'use strict'
const path = require('path')

function read(npmDir) {
  // npm 9 and later keep the definitions in @npmcli/config; npm 8 has them under lib/utils/config
  let loaded = null
  for (const rel of [['node_modules', '@npmcli', 'config', 'lib', 'definitions'], ['lib', 'utils', 'config']]) {
    try { loaded = require(path.join(npmDir, ...rel)); break } catch (e) { /* try the next layout */ }
  }
  if (!loaded) throw new Error(`no option definitions under ${npmDir}`)
  const { definitions, shorthands } = loaded
  const options = {}
  for (const [key, def] of Object.entries(definitions)) {
    let type = def.type
    let isArray = Array.isArray(type)
    if (isArray && type.length === 1) { type = type[0]; isArray = false }
    const members = isArray ? type : [type]
    let letters = ''
    if (type === Boolean || (isArray && members.includes(Boolean))) letters += 'B'
    if (type === String) letters += 'S'
    if (type === null || (isArray && members.includes(null))) letters += 'A'
    if (isArray && members.includes(Number)) letters += 'N'
    if (isArray && members.includes(String)) letters += 'T'
    if (isArray) letters += 'Y'
    const literals = isArray && key !== 'local-address' ? members.filter((m) => typeof m === 'string') : []
    options[key] = { letters, literals }
  }
  const shorts = {}
  for (const [name, expansion] of Object.entries(shorthands)) {
    shorts[name] = (Array.isArray(expansion) ? expansion : String(expansion).split(/\s+/)).join(' ')
  }
  return { options, shorts }
}

const args = process.argv.slice(2)
const one = args[0] === '--one'
const dirs = one ? args.slice(1) : args
if (dirs.length === 0) { console.error('usage: npm-option-snapshot.cjs [--one] <npm dir>...'); process.exit(2) }
const reading = (v) => `${[...v.letters].sort().join('') || '-'}${v.literals.length ? ':' + [...v.literals].sort().join(',') : ''}`
const versions = dirs.map((dir) => ({ dir, ...read(dir) }))
const options = {}
const shorts = {}
// the readings of one name over the reference versions: `@` when a version does not define it
const optReadings = {}
const shortReadings = {}
for (const ver of versions) {
  for (const [k, v] of Object.entries(ver.options)) {
    const had = options[k] || { letters: '', literals: [] }
    options[k] = {
      letters: [...new Set(had.letters + v.letters)].sort().join(''),
      literals: [...new Set([...had.literals, ...v.literals])].sort(),
    }
  }
  for (const [k, v] of Object.entries(ver.shorts)) {
    if (shorts[k] !== undefined && shorts[k] !== v) shorts[k] = `${shorts[k]}` // (a changed expansion is a variant below)
    else shorts[k] = v
  }
}
for (const k of Object.keys(options)) optReadings[k] = new Set(versions.map((ver) => (ver.options[k] ? reading(ver.options[k]) : '@')))
for (const k of Object.keys(shorts)) shortReadings[k] = new Set(versions.map((ver) => (ver.shorts[k] !== undefined ? ver.shorts[k] : '@')))
const sortKeys = (o) => Object.keys(o).sort()
if (one) {
  for (const k of sortKeys(options)) console.log(`opt\t${k}\t${options[k].letters}\t${options[k].literals.join(',')}`)
  for (const k of sortKeys(shorts)) console.log(`sh\t${k}\t${shorts[k]}`)
} else {
  console.log('SAFE_GATE_NPM_OPTIONS=(')
  const keys = sortKeys(options)
  for (let i = 0; i < keys.length; i += 4) console.log('  ' + keys.slice(i, i + 4).map((k) => `${k}=${options[k].letters || '-'}${options[k].literals.length ? ':' + options[k].literals.join(',') : ''}`).join(' '))
  console.log(')')
  console.log('SAFE_GATE_NPM_SHORTHANDS=(')
  for (const k of sortKeys(shorts)) console.log(`  '${k}=${shorts[k]}'`)
  console.log(')')
  // The options (and shorthands) the reference versions read differently: absent in one, another type in another.
  // `name=reading;reading;...` (readings sorted, `@` for a version that does not define it); a version-dependent name is read every way.
  console.log('SAFE_GATE_NPM_VARIANT_OPTIONS=(')
  const vo = sortKeys(optReadings).filter((k) => optReadings[k].size > 1)
  for (let i = 0; i < vo.length; i += 3) console.log('  ' + vo.slice(i, i + 3).map((k) => `'${k}=${[...optReadings[k]].sort().join(';')}'`).join(' '))
  console.log(')')
  console.log('SAFE_GATE_NPM_VARIANT_SHORTHANDS=(')
  for (const k of sortKeys(shortReadings).filter((k) => shortReadings[k].size > 1)) console.log(`  '${k}=${[...shortReadings[k]].sort().join(';')}'`)
  console.log(')')
  console.log(`SAFE_GATE_NPM_REFERENCE_VERSIONS='${versions.map((ver) => require(path.join(ver.dir, 'package.json')).version).sort().join(' ')}'`)
}
