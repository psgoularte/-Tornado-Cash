//! Native Poseidon (width 3) against external reference vectors. None of the
//! expected values below were computed here; each one is copied from the
//! source cited next to it.

use ark_bn254::Fr;
use ark_ff::MontFp;
use tornado_mixer::hash::{hash2, permute};

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
