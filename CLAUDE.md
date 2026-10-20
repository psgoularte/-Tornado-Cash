# CLAUDE.md

## Project

A Tornado Cash-style mixer implemented from scratch in Rust, **without a blockchain**, for an undergraduate research project (LARC/USP). The goal is not a product: it is to measure, through profiling, where the cost of generating the withdrawal proof lies and to reduce it with a measured optimization. The result will be a paper for an SBC workshop.

Research questions:

1. Where is the cost of generating the withdrawal proof, step by step, and how does it grow with the tree size?
2. Which part of that cost can be avoided or reused?
3. How much does the chosen optimization reduce proof generation time, and what is its memory cost?

What the mixer must do is in `docs/user-stories.md` (stories US01 to US09, with acceptance criteria). **Read that file before implementing any feature.**

## Fixed parameters

- Proof system: Groth16 (`ark-groth16`)
- Curve: BN254 (`ark-bn254`)
- Hash: Poseidon, for the tree, the commitment and the nullifier hash
- Tree depth: 20 by default, configurable
- Deposit amount: single and fixed (no amount in the circuit)
- Mixer root history: 30
- Public inputs of the withdrawal circuit: root, nullifier hash, recipient, relayer, fee
- Private inputs: nullifier, secret, leaf path

Do not change these parameters without asking.

## Stack

- Stable Rust, edition 2021
- arkworks: `ark-ff`, `ark-ec`, `ark-std`, `ark-bn254`, `ark-relations`, `ark-r1cs-std`, `ark-crypto-primitives` (features `constraints`, `crh`, `merkle_tree`, `sponge`), `ark-groth16`, `ark-snark`
  - In arkworks 0.6, the `r1cs` feature of `ark-crypto-primitives` was renamed to `constraints`, and the `ark_relations::r1cs` module was renamed to `ark_relations::gr1cs`.
- Use the latest stable versions from crates.io and keep **all `ark-*` crates on the same version**. Pin the versions in `Cargo.toml`.
- Randomness: `rand` 0.8 and `rand_chacha` 0.3, **deliberately pinned below the latest version**. arkworks uses the `rand_core` 0.6 interface, and newer `rand` versions are not compatible with it. Do not upgrade these two crates.
  - In library code, functions that need randomness take a generic RNG with the `ark_std::rand` traits (`RngCore + CryptoRng`), without depending on a specific generator.
  - In tests and benchmarks, use `ChaCha20Rng` with a fixed seed for reproducible results. Do not use `StdRng`, whose algorithm may change between versions.
  - Check with `cargo tree -i rand_core` that there is only one version of `rand_core` in the project.
- `criterion` for benchmarks
- `thiserror` for library errors

## Structure

```
src/
  lib.rs
  hash/       # Poseidon outside the circuit (native) and inside it (gadget)
  tree/       # deposit tree, paths, root history
  note.rs     # note, commitment, nullifier hash
  circuit/    # withdrawal circuit (ConstraintSynthesizer)
  prover/     # setup, proof generation and verification
  mixer/      # mixer state: tree, roots, spent nullifiers; deposit and withdraw
benches/      # criterion
docs/         # user-stories.md, circuit specification, measurement protocol
tests/        # integration tests per story
```

## Implementation rules

- **Own implementation.** Do not copy code from other mixers (for example, arkworks-gadgets from the Webb project). You may consult them to understand design decisions, but the code in this repository must be written here.
- **Do not invent test vectors.** For Poseidon, use parameters and reference vectors from a cited source (for example, the circomlib tests) and record the source in a comment. If you do not have the source, stop and ask.
- **Native and in-circuit must match.** Every function implemented in both places (hash, path, commitment) has an equivalence test.
- **A negative test for each constraint.** For each circuit constraint, a test shows that invalid inputs do not satisfy the circuit.
- **Test names carry the story ID:** `us04_rejects_repeated_nullifier`, `us06_rejects_root_outside_history`.
- **The prover must be instrumentable.** The research will separately measure constraint synthesis, witness generation, polynomial transforms and each MSM. Keep these steps separable and do not hide proof generation behind abstractions that prevent this.
- No `unwrap()` or `expect()` in library code; in tests it is fine.
- Measurements and benchmarks always in `--release`.
- Small, focused changes: one schedule task per branch and pull request.
- **Language.** Everything in the repository and on GitHub is written in English: code comments, documentation, test names, commit messages, pull requests.
- Code must be portable: development happens on Windows and measurements on native Linux, so nothing platform-specific.

## Commands

```
cargo build
cargo test
cargo test --release            # tests that generate proofs are slow in debug
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo bench
```

Before considering a task done: `fmt`, `clippy` and `test` passing.

## Out of scope

Blockchain, smart contracts, relayer network, graphical interface, wallet, variable amounts, anonymity analysis. If a task seems to require any of these, stop and ask.
