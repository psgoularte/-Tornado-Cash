//! Native (out-of-circuit) Poseidon permutation and two-input hash.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};

use super::params::{FULL_ROUNDS, MDS, PARTIAL_ROUNDS, ROUND_CONSTANTS, WIDTH};
use super::NULLIFIER_DOMAIN;

/// Applies the Poseidon permutation to a width-3 state.
///
/// Each round adds the round constants, applies the S-box (to every element
/// in full rounds, only to `state[0]` in partial rounds) and multiplies by the
/// MDS matrix. The first and last `FULL_ROUNDS / 2` rounds are full.
pub fn permute(mut state: [Fr; WIDTH]) -> [Fr; WIDTH] {
    let first_partial = FULL_ROUNDS / 2;
    let last_partial = first_partial + PARTIAL_ROUNDS;

    for (round, constants) in ROUND_CONSTANTS.iter().enumerate() {
        for (element, constant) in state.iter_mut().zip(constants) {
            *element += constant;
        }

        if (first_partial..last_partial).contains(&round) {
            state[0] = sbox(state[0]);
        } else {
            for element in state.iter_mut() {
                *element = sbox(*element);
            }
        }

        state = mix(&state);
    }
    state
}

/// Poseidon hash of two field elements, equal to circomlib's `Poseidon(2)`.
///
/// The state starts as `[0, left, right]` and the output is the first element
/// of the permuted state. Used for the note commitment, the nullifier hash
/// and the internal nodes of the deposit tree.
pub fn hash2(left: Fr, right: Fr) -> Fr {
    permute([Fr::ZERO, left, right])[0]
}

/// Nullifier hash `H_N(n)`: the Poseidon permutation of the state
/// `[NULLIFIER_DOMAIN, nullifier, 0]`, output is the first element.
///
/// The capacity element carries the domain tag, so no inputs can make this
/// state equal to the `[0, a, b]` state of `hash2`: the nullifier hash is
/// separated from commitments and tree nodes (decision D1 in
/// `docs/withdrawal-circuit-spec.md`). Equal to circomlibjs'
/// `poseidon([nullifier, 0], 1)`.
pub fn nullifier_hash(nullifier: Fr) -> Fr {
    permute([Fr::from(NULLIFIER_DOMAIN), nullifier, Fr::ZERO])[0]
}

/// S-box x -> x^5 (`params::ALPHA`), computed with two squarings and one
/// multiplication.
fn sbox(x: Fr) -> Fr {
    x.square().square() * x
}

/// Linear layer: `out[i] = sum_j MDS[i][j] * state[j]`.
fn mix(state: &[Fr; WIDTH]) -> [Fr; WIDTH] {
    core::array::from_fn(|i| MDS[i].iter().zip(state).map(|(m, s)| *m * s).sum())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::params::ALPHA;

    #[test]
    fn sbox_is_x_to_the_alpha() {
        for x in [0u64, 1, 2, 12345].map(Fr::from) {
            assert_eq!(sbox(x), x.pow([ALPHA]));
        }
    }
}
