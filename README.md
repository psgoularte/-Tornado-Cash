# Tornado Cash-style mixer in Rust

An independent, blockchain-free implementation of a Tornado Cash-style mixer,
built for an undergraduate research project (LARC/USP). The goal is not a
product: it is to measure, through profiling, where the cost of generating the
withdrawal proof lies and to reduce it with a measured optimization.

- Proof system: Groth16 (`ark-groth16`), BN254 curve
- Hash: Poseidon (tree, commitment and nullifier hash)
- Tree depth 20 (configurable), history of 30 roots

The user stories are in [`docs/user-stories.md`](docs/user-stories.md).

## Requirements

- Stable Rust (via [rustup](https://rustup.rs))
- Builds and tests on Linux and Windows. Measurements are taken on native
  Linux, because they use `perf` and `cargo-flamegraph`.

## Build

```sh
cargo build --release
```

## Tests

Tests that generate proofs are slow in debug mode; prefer `--release`:

```sh
cargo test --release
```

Checks required before every PR (the same ones CI runs):

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --release
```

## Benchmarks

```sh
cargo bench
```
