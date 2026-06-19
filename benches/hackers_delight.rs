//! Phase 1 — Hacker's Delight micro-suite.

use criterion::{Criterion, criterion_group, criterion_main};

mod common;

fn phase1(c: &mut Criterion) {
    common::run_phase(
        c,
        common::PhaseConfig {
            group_name: "hackers_delight",
            phase: 1,
            fixture_subdir: "benches/hackers_delight",
            empty_hint: None,
        },
    );
}

criterion_group!(benches, phase1);
criterion_main!(benches);
