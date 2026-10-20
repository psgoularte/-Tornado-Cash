//! Withdrawal proof generation benchmarks (US07, US09).
//!
//! Empty for now: it only ensures the criterion setup compiles.
//! Always run in `--release` (`cargo bench` already uses the bench profile).

use criterion::{criterion_group, criterion_main, Criterion};

fn withdrawal_proof(_c: &mut Criterion) {}

criterion_group!(benches, withdrawal_proof);
criterion_main!(benches);
