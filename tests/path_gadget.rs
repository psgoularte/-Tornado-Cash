//! In-circuit path verification (C3 and C4 of the circuit specification)
//! against the native `MerklePath::compute_root`.

use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, GR1CSVar};
use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tornado_mixer::tree::gadget::{compute_root, PathLevelVar};
use tornado_mixer::tree::{MerklePath, MerkleTree};

/// Constraints per level: 240 for `hash2`, 1 for the selection and 1 for the
/// boolean direction bit.
const CONSTRAINTS_PER_LEVEL: usize = 242;

fn random_tree(depth: usize, count: usize, seed: u64) -> (MerkleTree, Vec<Fr>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let leaves: Vec<Fr> = (0..count).map(|_| Fr::rand(&mut rng)).collect();
    let mut tree = MerkleTree::new(depth).expect("valid depth");
    for leaf in &leaves {
        tree.insert(*leaf).expect("tree has room");
    }
    (tree, leaves)
}

fn path_values(path: &MerklePath) -> (Vec<Fr>, Vec<Fr>) {
    let bits = path.bits().iter().map(|bit| Fr::from(*bit)).collect();
    (path.siblings().to_vec(), bits)
}

/// Allocates the leaf, siblings and bits as witnesses and returns the root
/// computed by the gadget.
fn gadget_root(cs: &ConstraintSystemRef<Fr>, leaf: Fr, siblings: &[Fr], bits: &[Fr]) -> FpVar<Fr> {
    let leaf = FpVar::new_witness(cs.clone(), || Ok(leaf)).expect("allocate leaf");
    let path: Vec<PathLevelVar> = siblings
        .iter()
        .zip(bits)
        .map(|(sibling, bit)| PathLevelVar {
            sibling: FpVar::new_witness(cs.clone(), || Ok(*sibling)).expect("allocate sibling"),
            bit: FpVar::new_witness(cs.clone(), || Ok(*bit)).expect("allocate bit"),
        })
        .collect();
    compute_root(&leaf, &path).expect("gadget compute_root")
}

/// Whether the system is satisfied when the computed root is enforced to
/// equal `root`, given as a public input.
fn satisfied_against_root(leaf: Fr, siblings: &[Fr], bits: &[Fr], root: Fr) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let computed = gadget_root(&cs, leaf, siblings, bits);
    let root = FpVar::new_input(cs.clone(), || Ok(root)).expect("allocate root");
    computed.enforce_equal(&root).expect("enforce equal");
    cs.is_satisfied().expect("satisfiability check")
}

#[test]
fn us02_path_gadget_matches_native_root() {
    for (depth, count, seed) in [(3, 8, 1), (20, 5, 2)] {
        let (tree, leaves) = random_tree(depth, count, seed);

        for (index, leaf) in leaves.iter().enumerate() {
            let path = tree.path(index).expect("leaf exists");
            let (siblings, bits) = path_values(&path);

            let cs = ConstraintSystem::<Fr>::new_ref();
            let computed = gadget_root(&cs, *leaf, &siblings, &bits);
            assert_eq!(
                computed.value().expect("root value"),
                path.compute_root(*leaf),
                "depth {depth}, leaf {index}"
            );
            assert!(cs.is_satisfied().expect("satisfiability check"));

            assert!(
                satisfied_against_root(*leaf, &siblings, &bits, tree.root()),
                "depth {depth}, leaf {index}"
            );
        }
    }
}

#[test]
fn us02_path_gadget_rejects_altered_sibling() {
    for (depth, count, seed) in [(3, 8, 3), (20, 5, 4)] {
        let (tree, leaves) = random_tree(depth, count, seed);
        let index = count - 1;
        let (siblings, bits) = path_values(&tree.path(index).expect("leaf exists"));

        for level in 0..depth {
            let mut altered = siblings.clone();
            altered[level] += Fr::from(1u64);
            assert!(
                !satisfied_against_root(leaves[index], &altered, &bits, tree.root()),
                "depth {depth}, level {level}"
            );
        }
    }
}

#[test]
fn us02_path_gadget_rejects_flipped_direction_bit() {
    for (depth, count, seed) in [(3, 8, 5), (20, 5, 6)] {
        let (tree, leaves) = random_tree(depth, count, seed);
        let index = count - 1;
        let (siblings, bits) = path_values(&tree.path(index).expect("leaf exists"));

        for level in 0..depth {
            let mut flipped = bits.clone();
            flipped[level] = Fr::from(1u64) - flipped[level];
            assert!(
                !satisfied_against_root(leaves[index], &siblings, &flipped, tree.root()),
                "depth {depth}, level {level}"
            );
        }
    }
}

#[test]
fn us02_path_gadget_rejects_wrong_leaf() {
    let (tree, leaves) = random_tree(3, 8, 7);
    let (siblings, bits) = path_values(&tree.path(2).expect("leaf exists"));

    assert!(!satisfied_against_root(
        leaves[3],
        &siblings,
        &bits,
        tree.root()
    ));
    assert!(!satisfied_against_root(
        leaves[2] + Fr::from(1u64),
        &siblings,
        &bits,
        tree.root()
    ));
}

#[test]
fn us02_path_gadget_rejects_non_boolean_direction_bit() {
    let (tree, leaves) = random_tree(3, 8, 8);
    let (siblings, bits) = path_values(&tree.path(5).expect("leaf exists"));

    // The root is not enforced here, so only the booleanity constraints (C3)
    // can fail: a valid path satisfies the system, and any bit outside
    // {0, 1} at any level makes it unsatisfied.
    let satisfied = |bits: &[Fr]| {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let _root = gadget_root(&cs, leaves[5], &siblings, bits);
        cs.is_satisfied().expect("satisfiability check")
    };
    assert!(satisfied(&bits));

    for level in 0..bits.len() {
        for value in [Fr::from(2u64), -Fr::from(1u64)] {
            let mut tampered = bits.clone();
            tampered[level] = value;
            assert!(!satisfied(&tampered), "level {level}, bit {value}");
        }
    }
}

#[test]
fn us02_path_gadget_constraint_count() {
    for depth in [1, 3, 20] {
        let (tree, leaves) = random_tree(depth, 1, 9);
        let (siblings, bits) = path_values(&tree.path(0).expect("leaf exists"));

        let cs = ConstraintSystem::<Fr>::new_ref();
        let _root = gadget_root(&cs, leaves[0], &siblings, &bits);
        assert_eq!(
            cs.num_constraints(),
            CONSTRAINTS_PER_LEVEL * depth,
            "depth {depth}"
        );
    }
}
