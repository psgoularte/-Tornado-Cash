//! Deposit tree: incremental insertion against a root recomputed from all
//! leaves, path generation and native path verification.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tornado_mixer::hash::hash2;
use tornado_mixer::tree::{
    MerklePath, MerkleTree, TreeError, DEFAULT_DEPTH, EMPTY_LEAF, MAX_DEPTH,
};

fn random_leaves(count: usize, seed: u64) -> Vec<Fr> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    (0..count).map(|_| Fr::rand(&mut rng)).collect()
}

/// Root computed from scratch: pads the leaves with `EMPTY_LEAF` up to
/// `2^depth` and hashes every pair, level by level. Only for small depths.
fn full_recomputed_root(leaves: &[Fr], depth: usize) -> Fr {
    let mut layer = leaves.to_vec();
    layer.resize(1 << depth, EMPTY_LEAF);
    for _ in 0..depth {
        layer = layer
            .chunks(2)
            .map(|pair| hash2(pair[0], pair[1]))
            .collect();
    }
    layer[0]
}

/// Root computed from scratch without materializing empty subtrees: at each
/// level, an odd-length layer is padded with the root of an empty subtree of
/// that height. Usable at the default depth.
fn sparse_recomputed_root(leaves: &[Fr], depth: usize) -> Fr {
    let mut layer = leaves.to_vec();
    let mut empty = EMPTY_LEAF;
    for _ in 0..depth {
        if layer.is_empty() || layer.len() % 2 == 1 {
            layer.push(empty);
        }
        layer = layer
            .chunks(2)
            .map(|pair| hash2(pair[0], pair[1]))
            .collect();
        empty = hash2(empty, empty);
    }
    layer[0]
}

/// Tree of the given depth with `leaves` inserted in order.
fn tree_with(depth: usize, leaves: &[Fr]) -> MerkleTree {
    let mut tree = MerkleTree::new(depth).expect("valid depth");
    for leaf in leaves {
        tree.insert(*leaf).expect("tree has room");
    }
    tree
}

#[test]
fn us01_empty_leaf_is_tornado_zero_value() {
    // Hex spelling of the same constant, recomputed as keccak256("tornado")
    // mod r in docs/withdrawal-circuit-spec.md (D2).
    let hex = "2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect();
    assert_eq!(EMPTY_LEAF, Fr::from_be_bytes_mod_order(&bytes));
    assert_eq!(EMPTY_LEAF.into_bigint().to_bytes_be(), bytes);
}

#[test]
fn us01_empty_tree_root_matches_empty_leaf_value() {
    for depth in [1, 3, DEFAULT_DEPTH] {
        let mut expected = EMPTY_LEAF;
        for _ in 0..depth {
            expected = hash2(expected, expected);
        }

        let tree = MerkleTree::new(depth).expect("valid depth");
        assert!(tree.is_empty());
        assert_eq!(tree.root(), expected, "depth {depth}");
    }
}

#[test]
fn us01_root_after_each_insertion_matches_recomputed_root() {
    let depth = 4;
    let leaves = random_leaves(1 << depth, 1);
    let mut tree = MerkleTree::new(depth).expect("valid depth");

    for (count, leaf) in leaves.iter().enumerate() {
        assert_eq!(tree.insert(*leaf), Ok(count));
        assert_eq!(tree.len(), count + 1);
        assert_eq!(
            tree.root(),
            full_recomputed_root(&leaves[..=count], depth),
            "after {} insertions",
            count + 1
        );
    }
}

#[test]
fn us01_root_after_each_insertion_matches_recomputed_root_at_default_depth() {
    let leaves = random_leaves(9, 2);
    let mut tree = MerkleTree::new(DEFAULT_DEPTH).expect("valid depth");

    for (count, leaf) in leaves.iter().enumerate() {
        tree.insert(*leaf).expect("tree has room");
        assert_eq!(
            tree.root(),
            sparse_recomputed_root(&leaves[..=count], DEFAULT_DEPTH),
            "after {} insertions",
            count + 1
        );
    }
}

#[test]
fn us01_rejects_insertion_into_full_tree() {
    let depth = 3;
    let leaves = random_leaves(9, 3);
    let mut tree = tree_with(depth, &leaves[..8]);
    let root = tree.root();

    assert_eq!(tree.insert(leaves[8]), Err(TreeError::Full { capacity: 8 }));
    assert_eq!(tree.len(), 8);
    assert_eq!(tree.root(), root);
}

#[test]
fn us01_rejects_invalid_depth() {
    for depth in [0, MAX_DEPTH + 1] {
        assert_eq!(
            MerkleTree::new(depth).err(),
            Some(TreeError::InvalidDepth {
                depth,
                max: MAX_DEPTH
            })
        );
    }
}

#[test]
fn us02_path_of_every_leaf_verifies_against_current_root() {
    let depth = 4;
    let leaves = random_leaves(1 << depth, 4);
    let mut tree = MerkleTree::new(depth).expect("valid depth");

    for (count, leaf) in leaves.iter().enumerate() {
        tree.insert(*leaf).expect("tree has room");
        for (index, inserted) in leaves[..=count].iter().enumerate() {
            let path = tree.path(index).expect("leaf exists");
            assert_eq!(path.siblings().len(), depth);
            assert!(
                path.verify(*inserted, tree.root()),
                "leaf {index} after {} insertions",
                count + 1
            );
        }
    }
}

#[test]
fn us02_path_bits_are_leaf_index_lsb_first() {
    let depth = 4;
    let tree = tree_with(depth, &random_leaves(13, 5));

    for index in 0..tree.len() {
        let path = tree.path(index).expect("leaf exists");
        let expected: Vec<bool> = (0..depth).map(|i| (index >> i) & 1 == 1).collect();
        assert_eq!(path.bits(), expected.as_slice(), "leaf {index}");
    }
}

#[test]
fn us02_rejects_path_with_altered_sibling() {
    let depth = 4;
    let leaves = random_leaves(11, 6);
    let tree = tree_with(depth, &leaves);

    for (index, leaf) in leaves.iter().enumerate() {
        let path = tree.path(index).expect("leaf exists");
        for level in 0..depth {
            let mut siblings = path.siblings().to_vec();
            siblings[level] += Fr::from(1u64);
            let tampered = MerklePath::new(siblings, path.bits().to_vec()).expect("same lengths");
            assert!(
                !tampered.verify(*leaf, tree.root()),
                "leaf {index}, level {level}"
            );
        }
    }
}

#[test]
fn us02_rejects_path_with_flipped_direction_bit() {
    let depth = 4;
    let leaves = random_leaves(11, 7);
    let tree = tree_with(depth, &leaves);

    for (index, leaf) in leaves.iter().enumerate() {
        let path = tree.path(index).expect("leaf exists");
        for level in 0..depth {
            let mut bits = path.bits().to_vec();
            bits[level] = !bits[level];
            let tampered = MerklePath::new(path.siblings().to_vec(), bits).expect("same lengths");
            assert!(
                !tampered.verify(*leaf, tree.root()),
                "leaf {index}, level {level}"
            );
        }
    }
}

#[test]
fn us02_rejects_path_with_wrong_leaf() {
    let leaves = random_leaves(5, 8);
    let tree = tree_with(4, &leaves);

    let path = tree.path(2).expect("leaf exists");
    assert!(!path.verify(leaves[3], tree.root()));
    assert!(!path.verify(leaves[2] + Fr::from(1u64), tree.root()));
}

#[test]
fn us02_rejects_path_of_nonexistent_leaf() {
    let tree = MerkleTree::new(3).expect("valid depth");
    assert_eq!(
        tree.path(0),
        Err(TreeError::LeafNotFound { index: 0, len: 0 })
    );

    let tree = tree_with(3, &random_leaves(5, 9));
    for index in [5, 7, 8] {
        assert_eq!(
            tree.path(index),
            Err(TreeError::LeafNotFound { index, len: 5 })
        );
    }
}

#[test]
fn us02_rejects_path_with_mismatched_lengths() {
    assert_eq!(
        MerklePath::new(vec![EMPTY_LEAF; 3], vec![false; 2]),
        Err(TreeError::PathLengthMismatch {
            siblings: 3,
            bits: 2
        })
    );
}
