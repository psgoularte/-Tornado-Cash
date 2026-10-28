//! In-circuit path verification: recomputes the root from a leaf and its
//! path (constraints C3 and C4 of `docs/withdrawal-circuit-spec.md`).
//!
//! Mirrors `MerklePath::compute_root` level by level, so both compute the
//! same root.

use ark_bn254::Fr;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::gr1cs::SynthesisError;

use crate::hash::gadget::hash2;

/// One level of a path as circuit variables.
///
/// `bit` is the direction bit as a field element: 0 if the node at this level
/// is a left child, 1 if it is a right child. `compute_root` enforces that it
/// is 0 or 1, so callers allocate it as a plain field variable.
#[derive(Debug, Clone)]
pub struct PathLevelVar {
    pub sibling: FpVar<Fr>,
    pub bit: FpVar<Fr>,
}

/// Hashes `leaf` up `path` (leaf level first) and returns the computed root.
///
/// Costs 242 constraints per level: 1 for the boolean bit (C3), 1 for the
/// selection and 240 for `hash2` (C4). The caller enforces that the result
/// equals the public root.
pub fn compute_root(leaf: &FpVar<Fr>, path: &[PathLevelVar]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut node = leaf.clone();
    for PathLevelVar { sibling, bit } in path {
        // C3: bit * (1 - bit) = 0.
        bit.mul_equals(&(FpVar::one() - bit), &FpVar::zero())?;

        // C4, one multiplication per level (D4): left = node + bit * (sibling - node)
        // is (node, sibling) for bit 0 and (sibling, node) for bit 1, and right
        // is the other one. This is sound only because of C3 above: with any
        // other bit value, left can be any field element and right follows it,
        // so the prover could hash an arbitrary pair.
        let left = &node + bit * (sibling - &node);
        let right = &node + sibling - &left;
        node = hash2(&left, &right)?;
    }
    Ok(node)
}
