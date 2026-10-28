//! Native Poseidon (width 3) against external reference vectors. None of the
//! expected values below were computed here; each one is copied from the
//! source cited next to it.

use ark_bn254::Fr;
use ark_ff::MontFp;
use tornado_mixer::hash::{hash2, nullifier_hash, permute};

// circomlib, test/poseidoncircuit.js, "Should check constrain of hash([1, 2]) t=3":
// https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/test/poseidoncircuit.js
#[test]
fn us01_poseidon_hash_of_1_2_matches_circomlib() {
    let expected: Fr =
        MontFp!("7853200120776062878684798364095072458815029376092732009249414926327459813530");
    assert_eq!(hash2(Fr::from(1u64), Fr::from(2u64)), expected);
}

// circomlib, test/poseidoncircuit.js, "Should check constrain of hash([3, 4]) t=3":
// https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/test/poseidoncircuit.js
#[test]
fn us01_poseidon_hash_of_3_4_matches_circomlib() {
    let expected: Fr =
        MontFp!("14763215145315200506921711489642608356394854266165572616578112107564877678998");
    assert_eq!(hash2(Fr::from(3u64), Fr::from(4u64)), expected);
}

// Reference implementation by the Poseidon authors (hadeshash),
// code/test_vectors.txt, "poseidonperm_x5_254_3": full permutation of [0, 1, 2]:
// https://extgit.isec.tugraz.at/krypto/hadeshash/-/blob/208b5a164c6a252b137997694d90931b2bb851c5/code/test_vectors.txt
#[test]
fn us01_poseidon_permutation_matches_hadeshash_reference() {
    let input = [Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)];
    let expected: [Fr; 3] = [
        MontFp!("0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"),
        MontFp!("0x0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29"),
        MontFp!("0x0e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c"),
    ];
    assert_eq!(permute(input), expected);
}

// circomlibjs, test/poseidon.js, "Should check poseidon with n outputs",
// inputs [1, 2] with nOut = 2 (first two elements of the permuted state):
// https://github.com/iden3/circomlibjs/blob/48b3ab37013c5ed21e9ff8a80a5b010795c97094/test/poseidon.js
#[test]
fn us01_poseidon_permutation_state_matches_circomlibjs() {
    let state = permute([Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)]);
    let expected: [Fr; 2] = [
        MontFp!("7853200120776062878684798364095072458815029376092732009249414926327459813530"),
        MontFp!("7142104613055408817911962100316808866448378443474503659992478482890339429929"),
    ];
    assert_eq!(state[..2], expected);
}

// Nullifier hash H_N(n) = Poseidon of the state [1, n, 0] (decision D1).
// circomlibjs publishes no width-3 vector with a non-zero initial state, so
// these values were produced by running circomlibjs' own implementation,
// poseidon([n, 0], 1), at commit 48b3ab37013c5ed21e9ff8a80a5b010795c97094
// (the same commit as the constants in src/hash/params.rs):
// https://github.com/iden3/circomlibjs/blob/48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/poseidon_reference.js
// Command: `node scripts/nullifier_hash_vectors.mjs <path to circomlibjs>`
// (installation steps in the script header). The script first checks that
// circomlibjs reproduces two published vectors, one of them with an initial
// state, and requires its reference, optimized and wasm implementations to
// agree on every value below.
#[test]
fn us04_nullifier_hash_matches_circomlibjs_with_initial_state() {
    let vectors: [(Fr, Fr); 5] = [
        (
            MontFp!("0"),
            MontFp!("6728884524783278352701962419612726171407918527066264154829676679182488395286"),
        ),
        (
            MontFp!("1"),
            MontFp!("415600613235378359744539731387103727073144920510400543186315443896602800829"),
        ),
        (
            MontFp!("2"),
            MontFp!(
                "19928211794257771485102269587486881376606572650317269981454285080979503847156"
            ),
        ),
        (
            MontFp!("123456789"),
            MontFp!(
                "16833478348948103367746408098071931045374119346370171770387198897189550487551"
            ),
        ),
        (
            MontFp!(
                "21888242871839275222246405745257275088548364400416034343698204186575808495616"
            ),
            MontFp!("375476029929284139926554489095330350743170095663101439724742927625530494406"),
        ),
    ];

    for (nullifier, expected) in vectors {
        assert_eq!(nullifier_hash(nullifier), expected, "n = {nullifier}");
    }
}
