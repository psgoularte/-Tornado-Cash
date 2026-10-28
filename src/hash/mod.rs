//! Poseidon hash over the BN254 scalar field, compatible with circomlib.
//!
//! `native` is the out-of-circuit implementation and `gadget` the in-circuit
//! one; both use the same `params` and are checked against each other. Used
//! for the tree, the commitment (`hash2`) and the nullifier hash
//! (`nullifier_hash`).
//!
//! Covers: US01 (commitment) and US02 (hashes checked in the circuit).

pub mod gadget;
pub mod native;
pub mod params;

pub use native::{hash2, nullifier_hash, permute};

/// Domain tag of the nullifier hash, placed in the capacity element of the
/// initial state (decision D1 in `docs/withdrawal-circuit-spec.md`).
/// `hash2` uses capacity 0.
pub const NULLIFIER_DOMAIN: u64 = 1;
