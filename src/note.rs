//! The depositor's secret note.
//!
//! Will contain the note (nullifier and secret), generated with a generic
//! `RngCore + CryptoRng` RNG from `ark_std::rand`, the commitment
//! `Poseidon(nullifier, secret)` and the nullifier hash.
//!
//! Covers: US01 (note and commitment generation) and US04 (nullifier hash).
