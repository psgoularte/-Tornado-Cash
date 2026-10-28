// Generate the reference vectors for the nullifier hash H_N(n): Poseidon of
// width 3 with initial state [1, n, 0] (decision D1 in
// docs/withdrawal-circuit-spec.md). The values are recorded in
// tests/poseidon_native.rs.
//
// What it does
//   Runs circomlibjs' own Poseidon implementations, poseidon(inputs, initState)
//   with inputs [n, 0] and initState 1, whose state is [initState, ...inputs].
//   Nothing is computed here: the script only calls circomlibjs.
//   Before printing, it checks that circomlibjs reproduces two published
//   vectors (one of them with an initial state), and it requires the
//   reference, optimized and wasm implementations to agree on every output.
//
// Source
//   circomlibjs 0.1.8, commit 48b3ab37013c5ed21e9ff8a80a5b010795c97094 (the
//   same commit as the constants in src/hash/params.rs):
//   https://github.com/iden3/circomlibjs/blob/48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/poseidon_reference.js
//
// Usage (Node 18+), with circomlibjs installed outside the repository:
//   mkdir circomlibjs-env && cd circomlibjs-env && npm init -y
//   npm install --ignore-scripts https://codeload.github.com/iden3/circomlibjs/tar.gz/48b3ab37013c5ed21e9ff8a80a5b010795c97094
//   cd <repository root>
//   node scripts/nullifier_hash_vectors.mjs <path>/circomlibjs-env/node_modules/circomlibjs

import assert from "node:assert/strict";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = process.argv[2];
if (!root) {
  console.error("usage: node scripts/nullifier_hash_vectors.mjs <path to circomlibjs>");
  process.exit(1);
}
const load = (file) => import(pathToFileURL(join(root, "src", file)).href);

const reference = await (await load("poseidon_reference.js")).default();
const opt = await (await load("poseidon_opt.js")).default();
const wasm = await (await load("poseidon_wasm.js")).buildPoseidon();
const F = reference.F;
const decimal = (x) => F.toString(x, 10);

// Published vectors, reproduced before anything is generated:
// circomlib test/poseidoncircuit.js, hash([1, 2]) with t = 3.
assert.equal(
  decimal(reference([1, 2])),
  "7853200120776062878684798364095072458815029376092732009249414926327459813530",
);
// circomlibjs test/poseidon.js, "Should check poseidon with init state",
// inputs [1, 2, 3, 4] with initState 7.
assert.equal(
  decimal(reference([1, 2, 3, 4], 7)),
  "1569211601569591254857354699102545060324851338714426496554851741114291465006",
);

const DOMAIN_TAG = 1;
const nullifiers = [
  "0",
  "1",
  "2",
  "123456789",
  // r - 1, the largest field element.
  "21888242871839275222246405745257275088548364400416034343698204186575808495616",
];

for (const n of nullifiers) {
  const out = decimal(reference([n, 0], DOMAIN_TAG));
  assert.equal(decimal(opt([n, 0], DOMAIN_TAG)), out, `opt differs for n = ${n}`);
  assert.equal(wasm.F.toString(wasm([n, 0], DOMAIN_TAG), 10), out, `wasm differs for n = ${n}`);
  console.log(`H_N(${n}) = ${out}`);
}

// ffjavascript may keep worker threads alive.
process.exit(0);
