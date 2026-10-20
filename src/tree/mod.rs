//! Deposit tree.
//!
//! Will contain the incremental Merkle tree (depth 20 by default,
//! configurable) whose leaves are the commitments, leaf path generation
//! (native and in-circuit) and the history of the last 30 roots.
//!
//! Covers: US01 (insertion into the next free leaf, full tree), US02 (path as
//! private input) and US06 (root history).
