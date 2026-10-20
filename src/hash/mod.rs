//! Poseidon hash over the BN254 scalar field, compatible with circomlib.
//!
//! `native` is the out-of-circuit implementation; the in-circuit gadget will
//! use the same `params`, with an equivalence test between them. Used for the
//! tree, the commitment and the nullifier hash.
//!
//! Covers: US01 (commitment) and US02 (hashes checked in the circuit).

pub mod native;
pub mod params;

pub use native::{hash2, permute};
