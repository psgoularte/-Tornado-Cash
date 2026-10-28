//! In-circuit Poseidon permutation and two-input hash (R1CS gadget).
//!
//! Mirrors `native.rs` round by round with the same `params`, so both compute
//! the same function. Additions and multiplications by constants only build
//! linear combinations; each S-box x^5 costs 3 constraints (x^2, x^4, x^4 * x)
//! when its input is a variable and none when it is a constant.

use ark_bn254::Fr;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::gr1cs::SynthesisError;

use super::params::{FULL_ROUNDS, MDS, PARTIAL_ROUNDS, ROUND_CONSTANTS, WIDTH};
use super::NULLIFIER_DOMAIN;

/// Applies the Poseidon permutation to a width-3 state of circuit variables.
///
/// Same round structure as `native::permute`: add round constants, S-box on
/// every element in full rounds and only on `state[0]` in partial rounds,
/// then the MDS linear layer.
pub fn permute(mut state: [FpVar<Fr>; WIDTH]) -> Result<[FpVar<Fr>; WIDTH], SynthesisError> {
    let first_partial = FULL_ROUNDS / 2;
    let last_partial = first_partial + PARTIAL_ROUNDS;

    for (round, constants) in ROUND_CONSTANTS.iter().enumerate() {
        for (element, constant) in state.iter_mut().zip(constants) {
            *element += *constant;
        }

        if (first_partial..last_partial).contains(&round) {
            state[0] = sbox(&state[0])?;
        } else {
            for element in state.iter_mut() {
                *element = sbox(element)?;
            }
        }

        state = mix(&state);
    }
    Ok(state)
}

/// In-circuit Poseidon hash of two field elements; matches `native::hash2`.
///
/// The state starts as `[0, left, right]` with the capacity element as the
/// constant 0, so its first S-box is evaluated on a constant and adds no
/// constraints. One call costs 240 constraints: 80 S-boxes on variables
/// (81 minus that one) times 3. A permutation of a fully variable state
/// costs 243.
pub fn hash2(left: &FpVar<Fr>, right: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let [out, _, _] = permute([FpVar::zero(), left.clone(), right.clone()])?;
    Ok(out)
}

/// In-circuit nullifier hash `H_N(n)`; matches `native::nullifier_hash`.
///
/// The state starts as `[NULLIFIER_DOMAIN, nullifier, 0]`. Two of its three
/// elements are constants, so two round-0 S-boxes are free: one call costs
/// 237 constraints (79 S-boxes on variables times 3).
pub fn nullifier_hash(nullifier: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let domain = FpVar::Constant(Fr::from(NULLIFIER_DOMAIN));
    let [out, _, _] = permute([domain, nullifier.clone(), FpVar::zero()])?;
    Ok(out)
}

/// S-box x -> x^5 (`params::ALPHA`): two squarings and one multiplication.
fn sbox(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x4 = x.square()?.square()?;
    Ok(x4 * x)
}

/// Linear layer: `out[i] = sum_j MDS[i][j] * state[j]`, no constraints.
fn mix(state: &[FpVar<Fr>; WIDTH]) -> [FpVar<Fr>; WIDTH] {
    core::array::from_fn(|i| MDS[i].iter().zip(state).map(|(m, s)| s * *m).sum())
}
