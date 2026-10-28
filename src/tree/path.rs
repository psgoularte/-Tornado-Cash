//! Path from a leaf to the root, and its native verification.

use ark_bn254::Fr;

use super::TreeError;
use crate::hash::hash2;

/// Path of a leaf in the format consumed by the withdrawal circuit
/// (`docs/withdrawal-circuit-spec.md`, inputs `siblings` and `bits`).
///
/// Level `i` counts from the leaf upward. `bits[i]` is `false` if the node
/// at level `i` is a left child and `true` if it is a right child, so the
/// bits are the leaf index in binary, least significant bit first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePath {
    siblings: Vec<Fr>,
    bits: Vec<bool>,
}

impl MerklePath {
    /// Builds a path from its siblings and direction bits, which must have
    /// the same length.
    pub fn new(siblings: Vec<Fr>, bits: Vec<bool>) -> Result<Self, TreeError> {
        if siblings.len() != bits.len() {
            return Err(TreeError::PathLengthMismatch {
                siblings: siblings.len(),
                bits: bits.len(),
            });
        }
        Ok(Self { siblings, bits })
    }

    /// Sibling node at each level.
    pub fn siblings(&self) -> &[Fr] {
        &self.siblings
    }

    /// Direction bit at each level (`true`: the node is a right child).
    pub fn bits(&self) -> &[bool] {
        &self.bits
    }

    /// Root obtained by hashing `leaf` up the path: at each level the node
    /// and its sibling are ordered by the direction bit, as in constraint C4
    /// of the circuit specification. Reference for the in-circuit path.
    pub fn compute_root(&self, leaf: Fr) -> Fr {
        self.siblings
            .iter()
            .zip(&self.bits)
            .fold(leaf, |node, (sibling, is_right)| {
                if *is_right {
                    hash2(*sibling, node)
                } else {
                    hash2(node, *sibling)
                }
            })
    }

    /// Whether `leaf` with this path hashes up to `root`.
    pub fn verify(&self, leaf: Fr, root: Fr) -> bool {
        self.compute_root(leaf) == root
    }
}
