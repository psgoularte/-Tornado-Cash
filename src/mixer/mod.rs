//! Mixer state, playing the role of the smart contract.
//!
//! Will contain the deposit tree, the root history and the registry of spent
//! nullifier hashes, with the deposit and withdraw operations.
//!
//! Covers: US01 (deposit), US03 (withdraw), US04 (prevent double withdrawal)
//! and US06 (accept recent roots).
