//! Poseidon hash over the BN254 scalar field, compatible with circomlib.
//!
//! `native` is the out-of-circuit implementation and `gadget` the in-circuit
//! one; both use the same `params` and are checked against each other. Used
//! for the tree, the commitment and the nullifier hash.
//!
//! Covers: US01 (commitment) and US02 (hashes checked in the circuit).

pub mod gadget;
pub mod native;
pub mod params;

pub use native::{hash2, permute};
