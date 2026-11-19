#!/usr/bin/env node
// Prints, for one or more npm installations, the option types the gate's front door reads: per option
// (key) the letters B (the type is or includes Boolean), S (exactly String), A (null is allowed), N (an
// array type that includes Number), T (an array type that includes String), Y (an array type of more than
// one member), and per shorthand its expansion. These are the facts nopt (npm's argument parser) decides
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
  const base = path.join(npmDir, 'node_modules', '@npmcli', 'config', 'lib', 'definitions')
  const { definitions, shorthands } = require(base)
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
    options[key] = letters
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
const options = {}
const shorts = {}
for (const dir of dirs) {
  const got = read(dir)
  for (const [k, v] of Object.entries(got.options)) options[k] = [...new Set((options[k] || '') + v)].sort().join('')
  for (const [k, v] of Object.entries(got.shorts)) {
    if (shorts[k] !== undefined && shorts[k] !== v) { console.error(`shorthand ${k} differs: "${shorts[k]}" vs "${v}"`); process.exit(3) }
    shorts[k] = v
  }
}
const sortKeys = (o) => Object.keys(o).sort()
if (one) {
  for (const k of sortKeys(options)) console.log(`opt\t${k}\t${options[k]}`)
  for (const k of sortKeys(shorts)) console.log(`sh\t${k}\t${shorts[k]}`)
} else {
  console.log('SAFE_GATE_NPM_OPTIONS=(')
  const keys = sortKeys(options)
  for (let i = 0; i < keys.length; i += 4) console.log('  ' + keys.slice(i, i + 4).map((k) => `${k}=${options[k] || '-'}`).join(' '))
  console.log(')')
  console.log('SAFE_GATE_NPM_SHORTHANDS=(')
  for (const k of sortKeys(shorts)) console.log(`  '${k}=${shorts[k]}'`)
  console.log(')')
}
