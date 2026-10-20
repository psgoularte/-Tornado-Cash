//! Tornado Cash-style mixer implemented from scratch, without a blockchain.
//!
//! Undergraduate research project (LARC/USP): the goal is to measure where
//! the cost of generating the withdrawal proof lies (Groth16 over BN254,
//! Poseidon hash) and to reduce it with a measured optimization. The user
//! stories are in `docs/user-stories.md`.

// Library code does not use unwrap/expect; tests may.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod circuit;
pub mod hash;
pub mod mixer;
pub mod note;
pub mod prover;
pub mod tree;
