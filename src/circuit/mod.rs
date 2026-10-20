//! Withdrawal circuit (`ConstraintSynthesizer`).
//!
//! Will contain the circuit with public inputs root, nullifier hash,
//! recipient, relayer and fee, and private inputs nullifier, secret and leaf
//! path. Each constraint will have a negative test.
//!
//! Covers: US02 (proof of membership in the tree) and US05 (binding to
//! recipient, relayer and fee).
