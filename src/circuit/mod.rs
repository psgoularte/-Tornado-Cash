//! Withdrawal circuit (`ConstraintSynthesizer`).
//!
//! Implements `docs/withdrawal-circuit-spec.md`: public inputs root,
//! nullifier hash, recipient, relayer and fee; private inputs nullifier,
//! secret and leaf path; constraints C1 to C5.
//!
//! Covers: US02 (proof of membership in the tree) and US05 (binding to
//! recipient, relayer and fee).

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::hash::gadget::{hash2, nullifier_hash};
use crate::tree::gadget::{compute_root, PathLevelVar};
use crate::tree::MerklePath;

/// Recipient or relayer identifier: 20 bytes, the size of an Ethereum
/// address (decision D3).
pub type Address = [u8; 20];

/// Maps an address into the field, big-endian (D3). Injective, because
/// 160 bits are fewer than the 254 bits of the field.
pub fn address_to_field(address: &Address) -> Fr {
    Fr::from_be_bytes_mod_order(address)
}

/// Public inputs of the withdrawal circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputs {
    pub root: Fr,
    pub nullifier_hash: Fr,
    pub recipient: Address,
    /// All zeros when there is no relayer.
    pub relayer: Address,
    pub fee: u64,
}

impl PublicInputs {
    /// The public inputs as field elements, in the order the circuit
    /// allocates them and the verifier expects them: root, nullifier hash,
    /// recipient, relayer, fee.
    pub fn to_field_elements(&self) -> [Fr; 5] {
        [
            self.root,
            self.nullifier_hash,
            address_to_field(&self.recipient),
            address_to_field(&self.relayer),
            Fr::from(self.fee),
        ]
    }
}

/// One level of the private path as field elements.
///
/// `bit` is 0 if the node at this level is a left child and 1 if it is a
/// right child. It is a field element, as in the constraint system, and the
/// circuit enforces that it is 0 or 1 (C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathLevel {
    pub sibling: Fr,
    pub bit: Fr,
}

/// Withdrawal circuit: proves knowledge of a note whose commitment is a leaf
/// of the tree with root `public.root`, and whose nullifier hashes to
/// `public.nullifier_hash`.
///
/// The depth is the length of `path` (20 by default, see
/// `tree::DEFAULT_DEPTH`). Proving and verifying keys are specific to a depth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalCircuit {
    pub public: PublicInputs,
    pub nullifier: Fr,
    pub secret: Fr,
    /// Leaf level first.
    pub path: Vec<PathLevel>,
}

impl WithdrawalCircuit {
    /// Circuit for a note `(nullifier, secret)` with the path of its leaf.
    pub fn new(public: PublicInputs, nullifier: Fr, secret: Fr, path: &MerklePath) -> Self {
        let path = path
            .siblings()
            .iter()
            .zip(path.bits())
            .map(|(sibling, bit)| PathLevel {
                sibling: *sibling,
                bit: Fr::from(*bit),
            })
            .collect();
        Self {
            public,
            nullifier,
            secret,
            path,
        }
    }

    /// Circuit of the given depth with placeholder values (zeros), for the
    /// Groth16 setup, which only needs the shape of the constraint system.
    pub fn blank(depth: usize) -> Self {
        let level = PathLevel {
            sibling: Fr::ZERO,
            bit: Fr::ZERO,
        };
        Self {
            public: PublicInputs {
                root: Fr::ZERO,
                nullifier_hash: Fr::ZERO,
                recipient: [0; 20],
                relayer: [0; 20],
                fee: 0,
            },
            nullifier: Fr::ZERO,
            secret: Fr::ZERO,
            path: vec![level; depth],
        }
    }

    /// Tree depth, the number of levels in the path.
    pub fn depth(&self) -> usize {
        self.path.len()
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawalCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs, in the order of the specification.
        let [root, public_nullifier_hash, recipient, relayer, fee] =
            self.public.to_field_elements();
        let root = FpVar::new_input(cs.clone(), || Ok(root))?;
        let public_nullifier_hash = FpVar::new_input(cs.clone(), || Ok(public_nullifier_hash))?;
        let recipient = FpVar::new_input(cs.clone(), || Ok(recipient))?;
        let relayer = FpVar::new_input(cs.clone(), || Ok(relayer))?;
        let fee = FpVar::new_input(cs.clone(), || Ok(fee))?;

        // Private inputs.
        let nullifier = FpVar::new_witness(cs.clone(), || Ok(self.nullifier))?;
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;
        let path = self
            .path
            .iter()
            .map(|level| {
                Ok(PathLevelVar {
                    sibling: FpVar::new_witness(cs.clone(), || Ok(level.sibling))?,
                    bit: FpVar::new_witness(cs.clone(), || Ok(level.bit))?,
                })
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // C1: the leaf is the commitment hash2(nullifier, secret).
        let leaf = hash2(&nullifier, &secret)?;

        // C2: the public nullifier hash is H_N(nullifier).
        nullifier_hash(&nullifier)?.enforce_equal(&public_nullifier_hash)?;

        // C3 and C4: compute_root enforces each direction bit to be boolean
        // (C3) and hashes the leaf up the path, ordering each pair by its bit
        // (C4).
        let computed_root = compute_root(&leaf, &path)?;

        // C4: the path reaches the public root.
        computed_root.enforce_equal(&root)?;

        // C5: bind recipient, relayer and fee to the proof by squaring each
        // into an otherwise unused witness (see "Why C5 is needed" in the
        // specification).
        for input in [&recipient, &relayer, &fee] {
            let _square = input.square()?;
        }

        Ok(())
    }
}
