//! Groth16 setup, proof generation and verification.
//!
//! Will contain key setup, withdrawal proof generation and verification. The
//! generation steps (constraint synthesis, witness, polynomial transforms and
//! each MSM) are kept separable so they can be measured.
//!
//! Covers: US02 (generation and verification), US07 (per-step measurement)
//! and US09 (optimized version accepted by the same verifier).
