//! Phase 3 — algebraic identities & fusion catalog.

use criterion::{Criterion, criterion_group, criterion_main};

mod common;

fn phase3(c: &mut Criterion) {
    common::run_phase(
        c,
        common::PhaseConfig {
            group_name: "algebraic_fusion",
            phase: 3,
            fixture_subdir: "benches/algebraic_fusion",
            empty_hint: None,
        },
    );
}

criterion_group!(benches, phase3);
criterion_main!(benches);
