//! Phase 2 — LLVM AArch64 codegen sample. Fixtures are harvested by
//! `scripts/harvest_llvm_codegen.sh`; the bench gracefully skips when
//! `benches/llvm_codegen/` is empty.

use criterion::{Criterion, criterion_group, criterion_main};

mod common;

fn phase2(c: &mut Criterion) {
    common::run_phase(
        c,
        common::PhaseConfig {
            group_name: "llvm_codegen",
            phase: 2,
            fixture_subdir: "benches/llvm_codegen",
            empty_hint: Some("run scripts/harvest_llvm_codegen.sh to populate"),
        },
    );
}

criterion_group!(benches, phase2);
criterion_main!(benches);
