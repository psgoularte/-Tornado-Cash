//! Withdrawal circuit (docs/withdrawal-circuit-spec.md): a valid witness
//! satisfies it, and each of the constraints C1 to C4 rejects invalid
//! witnesses. The C5 tests run at the verifier and belong with proof
//! generation (issue #21).

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Matrix, SynthesisMode,
    R1CS_PREDICATE_LABEL,
};
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tornado_mixer::circuit::{address_to_field, PathLevel, PublicInputs, WithdrawalCircuit};
use tornado_mixer::hash::{hash2, nullifier_hash};
use tornado_mixer::tree::{MerkleTree, DEFAULT_DEPTH};

/// Constraints at depth d: 242 per path level (240 hash2, 1 selection, 1
/// boolean bit), 240 for the commitment, 237 + 1 for the nullifier hash and
/// its equality, 1 for the root equality and 3 for the C5 squares.
fn expected_constraints(depth: usize) -> usize {
    242 * depth + 482
}

/// Witness indices fixed by the allocation order in `generate_constraints`:
/// nullifier, secret, then sibling and bit of each level.
const NULLIFIER_WITNESS: usize = 0;
const SECRET_WITNESS: usize = 1;

struct Fixture {
    circuit: WithdrawalCircuit,
    tree: MerkleTree,
    leaves: Vec<Fr>,
    index: usize,
}

/// Tree of `depth` with 8 random leaves; the note's commitment is leaf 5.
fn fixture(depth: usize, seed: u64) -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (nullifier, secret) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let index = 5;

    let mut leaves: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
    leaves[index] = hash2(nullifier, secret);
    let mut tree = MerkleTree::new(depth).expect("valid depth");
    for leaf in &leaves {
        tree.insert(*leaf).expect("tree has room");
    }

    let public = PublicInputs {
        root: tree.root(),
        nullifier_hash: nullifier_hash(nullifier),
        recipient: [0x11; 20],
        relayer: [0x22; 20],
        fee: 1_000,
    };
    let path = tree.path(index).expect("leaf exists");
    let circuit = WithdrawalCircuit::new(public, nullifier, secret, &path);
    Fixture {
        circuit,
        tree,
        leaves,
        index,
    }
}

fn synthesize(circuit: WithdrawalCircuit) -> ConstraintSystemRef<Fr> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("synthesis");
    cs
}

fn is_satisfied(circuit: WithdrawalCircuit) -> bool {
    synthesize(circuit)
        .is_satisfied()
        .expect("satisfiability check")
}

/// Whether the full assignment `z` (instance followed by witness)
/// satisfies the R1CS matrices `[A, B, C]`: (A z)_i * (B z)_i = (C z)_i for
/// every row i. This is the relation Groth16 proves.
fn r1cs_holds(matrices: &[Matrix<Fr>], z: &[Fr]) -> bool {
    let row = |row: &Vec<(Fr, usize)>| -> Fr { row.iter().map(|(coeff, i)| *coeff * z[*i]).sum() };
    let [a, b, c] = matrices else {
        panic!("R1CS has three matrices");
    };
    a.iter()
        .zip(b)
        .zip(c)
        .all(|((a, b), c)| row(a) * row(b) == row(c))
}

/// Synthesizes `circuit`, finalizes it and extracts the R1CS matrices and the
/// full assignment exactly as the Groth16 prover does, then overwrites
/// witness `index` with `value` and checks the R1CS. Models a prover whose
/// assignment for that one variable is inconsistent with the rest.
fn r1cs_holds_with_tampered_witness(
    circuit: WithdrawalCircuit,
    index: usize,
    original: Fr,
    value: Fr,
) -> bool {
    let cs = synthesize(circuit);
    cs.finalize();
    let matrices = cs.to_matrices().expect("matrices")[R1CS_PREDICATE_LABEL].clone();
    let mut z = [
        cs.instance_assignment().expect("instance"),
        cs.witness_assignment().expect("witness"),
    ]
    .concat();

    let position = cs.num_instance_variables() + index;
    assert_eq!(z[position], original, "allocation order changed");
    z[position] = value;
    r1cs_holds(&matrices, &z)
}

#[test]
fn us02_valid_witness_satisfies_circuit() {
    for depth in [3, DEFAULT_DEPTH] {
        let fixture = fixture(depth, 1);
        assert!(is_satisfied(fixture.circuit.clone()), "depth {depth}");

        // No relayer and no fee.
        let mut circuit = fixture.circuit;
        circuit.public.relayer = [0; 20];
        circuit.public.fee = 0;
        assert!(is_satisfied(circuit), "depth {depth}, no relayer");
    }
}

#[test]
fn us02_r1cs_check_agrees_with_constraint_system() {
    // Control for the tampered-witness tests: the R1CS evaluation accepts an
    // untouched valid witness, and rejects a witness the constraint system
    // also rejects.
    let circuit = fixture(3, 2).circuit;
    let secret = circuit.secret;
    assert!(r1cs_holds_with_tampered_witness(
        circuit.clone(),
        SECRET_WITNESS,
        secret,
        secret
    ));

    let mut wrong_root = circuit;
    wrong_root.public.root += Fr::ONE;
    assert!(!is_satisfied(wrong_root.clone()));
    assert!(!r1cs_holds_with_tampered_witness(
        wrong_root,
        SECRET_WITNESS,
        secret,
        secret
    ));
}

// C1: the leaf is hash2(nullifier, secret).

#[test]
fn us02_rejects_wrong_secret() {
    let mut circuit = fixture(3, 3).circuit;
    circuit.secret += Fr::ONE;
    assert!(!is_satisfied(circuit));
}

#[test]
fn us02_rejects_secret_not_matching_commitment() {
    // The leaf used by the path stays the real commitment; only the secret
    // assignment differs, so only C1 can fail.
    let circuit = fixture(3, 4).circuit;
    let secret = circuit.secret;
    assert!(!r1cs_holds_with_tampered_witness(
        circuit,
        SECRET_WITNESS,
        secret,
        secret + Fr::ONE
    ));
}

#[test]
fn us02_rejects_note_not_in_tree() {
    let fixture = fixture(3, 5);
    let mut rng = ChaCha20Rng::seed_from_u64(55);
    let (nullifier, secret) = (Fr::rand(&mut rng), Fr::rand(&mut rng));

    let mut circuit = fixture.circuit;
    circuit.public.nullifier_hash = nullifier_hash(nullifier);
    circuit.nullifier = nullifier;
    circuit.secret = secret;
    assert!(!is_satisfied(circuit));
}

// C2: the public nullifier hash is H_N(nullifier).

#[test]
fn us02_rejects_wrong_nullifier() {
    let mut circuit = fixture(3, 6).circuit;
    circuit.nullifier += Fr::ONE;
    assert!(!is_satisfied(circuit));
}

#[test]
fn us02_rejects_wrong_nullifier_hash() {
    let mut circuit = fixture(3, 7).circuit;
    circuit.public.nullifier_hash += Fr::ONE;
    assert!(!is_satisfied(circuit));
}

#[test]
fn us02_rejects_nullifier_not_matching_nullifier_hash() {
    // Tampering the nullifier assignment after synthesis breaks both hashes
    // that read it (C1 and C2).
    let circuit = fixture(3, 8).circuit;
    let nullifier = circuit.nullifier;
    assert!(!r1cs_holds_with_tampered_witness(
        circuit,
        NULLIFIER_WITNESS,
        nullifier,
        nullifier + Fr::ONE
    ));
}

// C3: every direction bit is 0 or 1.

#[test]
fn us02_rejects_non_boolean_direction_bit() {
    // Forgery that only C3 stops: a note that is not in the tree, with a
    // level-0 bit chosen outside {0, 1} so that the selected pair is exactly
    // the real pair (leaf 0, leaf 1). Every hash and the root then match, so
    // the system is unsatisfied only because of the bit.
    let fixture = fixture(3, 9);
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let (nullifier, secret) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let fake_leaf = hash2(nullifier, secret);
    let (left, right) = (fixture.leaves[0], fixture.leaves[1]);

    // left = h + b (s - h) and right = h + s - left, with h = fake_leaf.
    let sibling = left + right - fake_leaf;
    let bit = (left - fake_leaf)
        * (sibling - fake_leaf)
            .inverse()
            .expect("non-zero denominator");
    assert!(bit != Fr::from(0u64) && bit != Fr::from(1u64));
    assert_eq!(fake_leaf + bit * (sibling - fake_leaf), left);

    let real_path = fixture.tree.path(0).expect("leaf exists");
    let mut circuit = WithdrawalCircuit::new(
        PublicInputs {
            nullifier_hash: nullifier_hash(nullifier),
            ..fixture.circuit.public
        },
        nullifier,
        secret,
        &real_path,
    );
    circuit.path[0] = PathLevel { sibling, bit };

    // The forged witness reaches the true root.
    let forged_root = circuit.path.iter().fold(fake_leaf, |node, level| {
        let l = node + level.bit * (level.sibling - node);
        hash2(l, node + level.sibling - l)
    });
    assert_eq!(forged_root, fixture.tree.root());

    assert!(!is_satisfied(circuit));
}

// C4: the path reaches the public root.

#[test]
fn us02_rejects_wrong_sibling() {
    for depth in [3, DEFAULT_DEPTH] {
        let circuit = fixture(depth, 10).circuit;
        for level in 0..depth {
            let mut tampered = circuit.clone();
            tampered.path[level].sibling += Fr::ONE;
            assert!(!is_satisfied(tampered), "depth {depth}, level {level}");
        }
    }
}

#[test]
fn us02_rejects_flipped_direction_bit() {
    for depth in [3, DEFAULT_DEPTH] {
        let circuit = fixture(depth, 11).circuit;
        for level in 0..depth {
            let mut tampered = circuit.clone();
            tampered.path[level].bit = Fr::ONE - tampered.path[level].bit;
            assert!(!is_satisfied(tampered), "depth {depth}, level {level}");
        }
    }
}

#[test]
fn us02_rejects_wrong_root() {
    let fixture = fixture(3, 12);

    let mut circuit = fixture.circuit.clone();
    circuit.public.root += Fr::ONE;
    assert!(!is_satisfied(circuit));

    // A real root of the same tree from before the note was inserted.
    let mut earlier = MerkleTree::new(3).expect("valid depth");
    for leaf in &fixture.leaves[..fixture.index] {
        earlier.insert(*leaf).expect("tree has room");
    }
    let mut circuit = fixture.circuit;
    circuit.public.root = earlier.root();
    assert!(!is_satisfied(circuit));
}

// Shape of the constraint system.

#[test]
fn us02_withdrawal_circuit_constraint_count() {
    let cs = synthesize(fixture(DEFAULT_DEPTH, 13).circuit);
    assert_eq!(cs.num_constraints(), 5_322);
    assert_eq!(cs.num_constraints(), expected_constraints(DEFAULT_DEPTH));

    let cs = synthesize(fixture(3, 14).circuit);
    assert_eq!(cs.num_constraints(), expected_constraints(3));
}

#[test]
fn us02_blank_circuit_matches_shape_in_setup_mode() {
    let valid = synthesize(fixture(DEFAULT_DEPTH, 15).circuit);

    let blank = ConstraintSystem::<Fr>::new_ref();
    blank.set_mode(SynthesisMode::Setup);
    WithdrawalCircuit::blank(DEFAULT_DEPTH)
        .generate_constraints(blank.clone())
        .expect("synthesis in setup mode");

    assert_eq!(blank.num_constraints(), valid.num_constraints());
    assert_eq!(
        blank.num_instance_variables(),
        valid.num_instance_variables()
    );
    assert_eq!(blank.num_witness_variables(), valid.num_witness_variables());
    assert_eq!(
        WithdrawalCircuit::blank(DEFAULT_DEPTH).depth(),
        DEFAULT_DEPTH
    );
}

#[test]
fn us02_public_inputs_follow_spec_order() {
    let circuit = fixture(3, 16).circuit;
    let public = circuit.public.clone();
    let cs = synthesize(circuit);

    // The constant 1, then root, nullifier hash, recipient, relayer, fee.
    let mut expected = vec![Fr::ONE];
    expected.extend(public.to_field_elements());
    assert_eq!(cs.instance_assignment().expect("instance"), expected);
    assert_eq!(
        public.to_field_elements(),
        [
            public.root,
            public.nullifier_hash,
            address_to_field(&public.recipient),
            address_to_field(&public.relayer),
            Fr::from(public.fee),
        ]
    );
}

#[test]
fn us05_address_encoding_is_big_endian() {
    let mut address = [0u8; 20];
    address[19] = 1;
    assert_eq!(address_to_field(&address), Fr::ONE);

    let mut address = [0u8; 20];
    address[0] = 1;
    assert_eq!(address_to_field(&address), Fr::from(2u64).pow([152u64]));

    assert_eq!(
        address_to_field(&[0xff; 20]),
        Fr::from_be_bytes_mod_order(&[0xff; 20])
    );
    assert_ne!(address_to_field(&[0xff; 20]), -Fr::ONE);
}
