//! Deposit tree.
//!
//! Incremental Merkle tree (depth 20 by default, configurable) whose leaves
//! are the commitments, with Poseidon `hash2` nodes, leaf path generation,
//! native path verification and the in-circuit path gadget (`gadget`). The
//! history of recent roots belongs to the mixer, not to the tree.
//!
//! Covers: US01 (insertion into the next free leaf, full tree) and US02 (path
//! as private input of the withdrawal circuit).

pub mod gadget;
mod path;

pub use path::MerklePath;

use ark_bn254::Fr;
use ark_ff::MontFp;
use thiserror::Error;

use crate::hash::hash2;

/// Default tree depth, the same as Tornado Cash: 2^20 leaves.
pub const DEFAULT_DEPTH: usize = 20;

/// Largest supported depth, so that the capacity 2^depth fits in a `usize`.
pub const MAX_DEPTH: usize = usize::BITS as usize - 1;

/// Value of an empty leaf: `keccak256("tornado") mod r`, Tornado Cash's
/// `ZERO_VALUE` (decision D2 in `docs/withdrawal-circuit-spec.md`).
///
/// Source, tornado-core `contracts/MerkleTreeWithHistory.sol`, line 21:
/// https://github.com/tornadocash/tornado-core/blob/5cb9d6017878f4d4237fcc42c978fb34a2192b0c/contracts/MerkleTreeWithHistory.sol#L21
pub const EMPTY_LEAF: Fr =
    MontFp!("21663839004416932945382355908790599225266501822907911457504978515578255421292");

/// Errors of the deposit tree.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TreeError {
    /// The requested depth is 0 or above `MAX_DEPTH`.
    #[error("tree depth must be between 1 and {max}, got {depth}")]
    InvalidDepth { depth: usize, max: usize },
    /// Every leaf is already used.
    #[error("tree is full: all {capacity} leaves are used")]
    Full { capacity: usize },
    /// The leaf index is not below the number of inserted leaves.
    #[error("leaf {index} does not exist: the tree has {len} leaves")]
    LeafNotFound { index: usize, len: usize },
    /// A path was built with different numbers of siblings and bits.
    #[error("path has {siblings} siblings but {bits} direction bits")]
    PathLengthMismatch { siblings: usize, bits: usize },
}

/// Incremental Merkle tree of fixed depth.
///
/// Leaves are filled left to right. An insertion hashes only the `depth`
/// nodes on the new leaf's path: every node to the right of the path is
/// still empty, so its value is the precomputed root of an empty subtree.
/// This is the scheme of Tornado's `filledSubtrees`, but the tree keeps every
/// non-empty node, not only the last left node of each level, so that it can
/// also produce the path of any leaf.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    depth: usize,
    /// `empty[i]` is the root of an empty subtree of height `i`:
    /// `empty[0] = EMPTY_LEAF`, `empty[i + 1] = hash2(empty[i], empty[i])`.
    /// Length `depth + 1`.
    empty: Vec<Fr>,
    /// `nodes[i]` holds the non-empty nodes at height `i`, left to right;
    /// `nodes[0]` are the leaves. Length `depth`.
    nodes: Vec<Vec<Fr>>,
    root: Fr,
}

impl MerkleTree {
    /// Creates an empty tree with `2^depth` leaves.
    pub fn new(depth: usize) -> Result<Self, TreeError> {
        if depth == 0 || depth > MAX_DEPTH {
            return Err(TreeError::InvalidDepth {
                depth,
                max: MAX_DEPTH,
            });
        }

        let mut empty = Vec::with_capacity(depth + 1);
        let mut node = EMPTY_LEAF;
        empty.push(node);
        for _ in 0..depth {
            node = hash2(node, node);
            empty.push(node);
        }

        Ok(Self {
            depth,
            empty,
            nodes: vec![Vec::new(); depth],
            root: node,
        })
    }

    /// Tree depth: number of levels between a leaf and the root.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Number of leaves, `2^depth`.
    pub fn capacity(&self) -> usize {
        1 << self.depth
    }

    /// Number of inserted leaves.
    pub fn len(&self) -> usize {
        self.nodes[0].len()
    }

    /// Whether no leaf has been inserted yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Current root.
    pub fn root(&self) -> Fr {
        self.root
    }

    /// Inserts `leaf` into the next free position and returns its index.
    ///
    /// Costs `depth` hashes. Fails with `TreeError::Full` when every leaf is
    /// used, leaving the tree unchanged.
    pub fn insert(&mut self, leaf: Fr) -> Result<usize, TreeError> {
        let index = self.len();
        if index == self.capacity() {
            return Err(TreeError::Full {
                capacity: self.capacity(),
            });
        }

        let mut node = leaf;
        let mut position = index;
        for (layer, empty) in self.nodes.iter_mut().zip(&self.empty) {
            // The node is either new (rightmost so far) or replaces the
            // previous value of the rightmost node of this level.
            if position == layer.len() {
                layer.push(node);
            } else {
                layer[position] = node;
            }

            // A left child's sibling is still empty; a right child's sibling
            // is the node just before it.
            node = if position.is_multiple_of(2) {
                hash2(node, *empty)
            } else {
                hash2(layer[position - 1], node)
            };
            position /= 2;
        }

        self.root = node;
        Ok(index)
    }

    /// Path from leaf `index` to the current root.
    ///
    /// Fails with `TreeError::LeafNotFound` if no leaf was inserted at
    /// `index`.
    pub fn path(&self, index: usize) -> Result<MerklePath, TreeError> {
        if index >= self.len() {
            return Err(TreeError::LeafNotFound {
                index,
                len: self.len(),
            });
        }

        let mut siblings = Vec::with_capacity(self.depth);
        let mut bits = Vec::with_capacity(self.depth);
        let mut position = index;
        for (layer, empty) in self.nodes.iter().zip(&self.empty) {
            let sibling = layer.get(position ^ 1).copied().unwrap_or(*empty);
            siblings.push(sibling);
            bits.push(position % 2 == 1);
            position /= 2;
        }

        MerklePath::new(siblings, bits)
    }
}
