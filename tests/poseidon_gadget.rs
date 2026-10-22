//! In-circuit Poseidon (width 3) against the native implementation and the
//! external reference vectors used in `poseidon_native.rs`.

use ark_bn254::Fr;
use ark_ff::MontFp;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, GR1CSVar};
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tornado_mixer::hash::{self, gadget};

/// Constraints of one permutation whose whole state is variables: 81 S-boxes
/// (8 full rounds x 3 + 57 partial rounds x 1) x 3 constraints each = 243.
const PERMUTATION_CONSTRAINTS: usize = 243;

/// Constraints of one in-circuit `hash2`: the capacity element is the constant
/// 0, so its round-0 S-box costs nothing; 80 S-boxes x 3 = 240.
const HASH2_CONSTRAINTS: usize = 240;

/// Allocates `left` and `right` as witnesses and returns the gadget output.
fn gadget_hash2(cs: &ConstraintSystemRef<Fr>, left: Fr, right: Fr) -> FpVar<Fr> {
    let left = FpVar::new_witness(cs.clone(), || Ok(left)).expect("allocate left");
    let right = FpVar::new_witness(cs.clone(), || Ok(right)).expect("allocate right");
    gadget::hash2(&left, &right).expect("gadget hash2")
}

// Expected values from circomlib, test/poseidoncircuit.js (t = 3):
// https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/test/poseidoncircuit.js
#[test]
fn us01_poseidon_gadget_matches_circomlib_vectors() {
    let vectors: [(u64, u64, Fr); 2] = [
        (
            1,
            2,
            MontFp!("7853200120776062878684798364095072458815029376092732009249414926327459813530"),
        ),
        (
            3,
            4,
            MontFp!(
                "14763215145315200506921711489642608356394854266165572616578112107564877678998"
            ),
        ),
    ];

    for (left, right, expected) in vectors {
        let (left, right) = (Fr::from(left), Fr::from(right));
        let cs = ConstraintSystem::<Fr>::new_ref();
        let out = gadget_hash2(&cs, left, right);

        assert_eq!(out.value().expect("output value"), expected);
        assert_eq!(out.value().expect("output value"), hash::hash2(left, right));
        assert!(cs.is_satisfied().expect("satisfiability check"));
    }
}

#[test]
fn us01_poseidon_gadget_matches_native() {
    let mut rng = ChaCha20Rng::seed_from_u64(2026);

    for _ in 0..100 {
        let (left, right) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let cs = ConstraintSystem::<Fr>::new_ref();
        let out = gadget_hash2(&cs, left, right);

        assert_eq!(out.value().expect("output value"), hash::hash2(left, right));
        assert!(cs.is_satisfied().expect("satisfiability check"));
    }
}

#[test]
fn us02_poseidon_gadget_rejects_wrong_output() {
    let (left, right) = (Fr::from(1u64), Fr::from(2u64));
    let correct = hash::hash2(left, right);

    for (claimed, satisfied) in [(correct, true), (correct + Fr::from(1u64), false)] {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let out = gadget_hash2(&cs, left, right);
        let claimed = FpVar::new_input(cs.clone(), || Ok(claimed)).expect("allocate claim");
        out.enforce_equal(&claimed).expect("enforce equal");

        assert_eq!(cs.is_satisfied().expect("satisfiability check"), satisfied);
    }
}

#[test]
fn us02_poseidon_gadget_constraint_count() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let _out = gadget_hash2(&cs, Fr::from(1u64), Fr::from(2u64));

    assert_eq!(cs.num_constraints(), HASH2_CONSTRAINTS);
}

#[test]
fn us02_poseidon_permutation_constraint_count() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let state = [0u64, 1, 2]
        .map(|v| FpVar::new_witness(cs.clone(), || Ok(Fr::from(v))).expect("allocate state"));
    let _out = gadget::permute(state).expect("gadget permute");

    assert_eq!(cs.num_constraints(), PERMUTATION_CONSTRAINTS);
}
