#!/usr/bin/env node
// Fixture oracle: FIRSTdotorg/cvss-v4-calculator at c5b0d409ae9f57c44264c6ce5f27d89298e1d32a.
// The reference lives outside the tree; tests/audit/fetch_cvss4_ref.sh
// bootstraps it (hash-pinned) into tmp/cvss4-ref from a fresh clone.

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "../..");
const REF = process.env.CVSS4_REF_DIR || path.join(ROOT, "tmp/cvss4-ref");
const SHA = "c5b0d409ae9f57c44264c6ce5f27d89298e1d32a";

if (fs.readFileSync(path.join(REF, "PROVENANCE-SHA.txt"), "utf8").trim() !== SHA) {
  throw new Error(`CVSS v4 reference is not pinned to ${SHA}`);
}
for (const file of ["cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js"]) {
  vm.runInThisContext(fs.readFileSync(path.join(REF, file), "utf8"), {filename: file});
}

const BASE = {
  AV: ["N", "A", "L", "P"], AC: ["L", "H"], AT: ["N", "P"],
  PR: ["N", "L", "H"], UI: ["N", "P", "A"],
  VC: ["H", "L", "N"], VI: ["H", "L", "N"], VA: ["H", "L", "N"],
  SC: ["H", "L", "N"], SI: ["H", "L", "N"], SA: ["H", "L", "N"],
};
const OPTIONAL = {
  E: ["X", "A", "P", "U"], CR: ["X", "H", "M", "L"], IR: ["X", "H", "M", "L"], AR: ["X", "H", "M", "L"],
  MAV: ["X", "N", "A", "L", "P"], MAC: ["X", "L", "H"], MAT: ["X", "N", "P"],
  MPR: ["X", "N", "L", "H"], MUI: ["X", "N", "P", "A"],
  MVC: ["X", "H", "L", "N"], MVI: ["X", "H", "L", "N"], MVA: ["X", "H", "L", "N"],
  MSC: ["X", "H", "L", "N"], MSI: ["X", "S", "H", "L", "N"], MSA: ["X", "S", "H", "L", "N"],
};
const SUPPLEMENTAL = {
  S: ["X", "N", "P"], AU: ["X", "N", "Y"], R: ["X", "A", "U", "I"],
  V: ["X", "D", "C"], RE: ["X", "L", "M", "H"], U: ["X", "Clear", "Green", "Amber", "Red"],
};
const ORDER = [...Object.keys(BASE), ...Object.keys(OPTIONAL), ...Object.keys(SUPPLEMENTAL)];
const DEFAULTS = Object.fromEntries([...Object.keys(OPTIONAL), ...Object.keys(SUPPLEMENTAL)].map(key => [key, "X"]));

function parse(vector) {
  const parts = vector.split("/");
  if (parts.shift() !== "CVSS:4.0") throw new Error(`invalid vector: ${vector}`);
  const metrics = {...DEFAULTS};
  for (const part of parts) {
    const [key, value] = part.split(":");
    metrics[key] = value;
  }
  return metrics;
}

function score(vector) {
  const metrics = parse(vector);
  return cvss_score(metrics, cvssLookup_global, maxSeverity, macroVector(metrics));
}

function band(value) {
  if (value >= 9) return "critical";
  if (value >= 7) return "high";
  if (value >= 4) return "moderate";
  if (value > 0) return "low";
  return "none";
}

function vector(metrics, explicitX = false) {
  const parts = [];
  for (const key of ORDER) {
    if (metrics[key] !== undefined && (explicitX || metrics[key] !== "X")) parts.push(`${key}:${metrics[key]}`);
  }
  return `CVSS:4.0/${parts.join("/")}`;
}

function* baseVectors() {
  const keys = Object.keys(BASE);
  function* visit(index, metrics) {
    if (index === keys.length) {
      yield vector(metrics);
      return;
    }
    const key = keys[index];
    for (const value of BASE[key]) yield* visit(index + 1, {...metrics, [key]: value});
  }
  yield* visit(0, {});
}

function rng(seed) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function randomMetrics(next, domains) {
  return Object.fromEntries(Object.entries(domains).map(([key, values]) => [key, values[next() % values.length]]));
}

function* randomBtBte(count) {
  const next = rng(0xc5b0d409);
  const environmental = Object.fromEntries(Object.entries(OPTIONAL).filter(([key]) => key !== "E"));
  for (let i = 0; i < count; i++) {
    const metrics = randomMetrics(next, BASE);
    metrics.E = ["A", "P", "U"][next() % 3];
    if (i >= count / 2) Object.assign(metrics, randomMetrics(next, environmental));
    yield vector(metrics);
  }
}

function emitExhaustive() {
  let count = 0;
  for (const item of baseVectors()) {
    const value = score(item);
    process.stdout.write(`${item}\t${Math.round(value * 10)}\t${band(value)}\n`);
    count++;
  }
  for (const item of randomBtBte(5120)) {
    const value = score(item);
    process.stdout.write(`${item}\t${Math.round(value * 10)}\t${band(value)}\n`);
    count++;
  }
  if (count !== 110096) throw new Error(`unexpected exhaustive count: ${count}`);
}

function emitFixture() {
  const cases = new Map();
  const add = (item, category) => {
    const value = score(item);
    cases.set(item, {vector: item, score: value, band: band(value), category});
  };

  const firstExamples = [
    "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L",
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
    "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U/MVA:H/MSA:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:L/IR:H/AR:L/MAV:L/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:H/MVA:L/MSC:N/MSI:S/MSA:L",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/V:C/RE:L",
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/MSI:S/S:P",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H/E:U/MAV:A/R:U/V:C",
  ];
  firstExamples.forEach(item => add(item, "first-example"));

  add("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "all-highest");
  add("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "all-lowest");

  const ndBase = parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:N/SA:N");
  add(vector(ndBase, true), "nd-heavy");
  add(vector({...ndBase, E: "P", CR: "X", IR: "M", AR: "X", MAV: "X", MAC: "H", MUI: "X", MSI: "N"}, true), "nd-heavy");
  add(vector({...ndBase, E: "X", CR: "L", IR: "X", AR: "H", MVC: "X", MVI: "H", MVA: "X", MSA: "S"}, true), "nd-heavy");

  add("CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:H/VI:N/VA:N/SC:N/SI:H/SA:H/E:U", "boundary-3.9");
  const boundaries = new Set(["4.0", "6.9", "7.0", "8.9", "9.0"]);
  for (const item of baseVectors()) {
    const key = score(item).toFixed(1);
    if (boundaries.has(key)) {
      add(item, `boundary-${key}`);
      boundaries.delete(key);
      if (boundaries.size === 0) break;
    }
  }
  if (boundaries.size !== 0) throw new Error(`missing boundaries: ${[...boundaries].join(", ")}`);

  const next = rng(0x40c5b0d4);
  for (let i = 0; i < 250; i++) add(vector(randomMetrics(next, BASE)), "base-random");
  for (let i = 0; i < 160; i++) {
    const metrics = randomMetrics(next, BASE);
    metrics.E = ["A", "P", "U"][next() % 3];
    add(vector(metrics), "bt-random");
  }
  const environmental = Object.fromEntries(Object.entries(OPTIONAL).filter(([key]) => key !== "E"));
  for (let i = 0; i < 210; i++) {
    const metrics = {...randomMetrics(next, BASE), ...randomMetrics(next, environmental)};
    metrics.E = ["A", "P", "U"][next() % 3];
    add(vector(metrics), "bte-random");
  }

  process.stdout.write(`${JSON.stringify([...cases.values()], null, 2)}\n`);
}

if (process.argv[2] === "--exhaustive") emitExhaustive();
else emitFixture();
