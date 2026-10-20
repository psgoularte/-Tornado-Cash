//! Poseidon hash over the BN254 scalar field.
//!
//! Will contain the native implementation and the in-circuit gadget, with an
//! equivalence test between them and reference vectors from a cited source.
//! Used for the tree, the commitment and the nullifier hash.
//!
//! Covers: US01 (commitment) and US02 (hashes checked in the circuit).
