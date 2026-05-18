//! Phase 2 — LLVM AArch64 codegen sample. Fixtures are harvested by
//! `scripts/harvest_llvm_codegen.sh`; the bench gracefully skips when
//! `benches/llvm_codegen/` is empty.

use criterion::{Criterion, criterion_group, criterion_main};
use s11::bench_support::{append_json, discover_specs_in, run_bench, run_provenance};
use std::cell::Cell;
use std::path::PathBuf;
use std::time::Duration;

fn phase2(c: &mut Criterion) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/llvm_codegen");
    let specs = discover_specs_in(&dir, 2);
    if specs.is_empty() {
        eprintln!(
            "no Phase 2 fixtures under {} — run scripts/harvest_llvm_codegen.sh to populate. \
             Skipping.",
            dir.display()
        );
        return;
    }
    let (git_sha, timestamp_utc) = run_provenance();
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/results/results.jsonl");

    let mut group = c.benchmark_group("llvm_codegen");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for spec in &specs {
        let spec_owned = spec.clone();
        let sha = git_sha.clone();
        let ts = timestamp_utc.clone();
        let out = out.clone();
        group.bench_function(spec_owned.id.clone(), |b| {
            // See benches/hackers_delight.rs for the rationale: JSON
            // emission inside iter_custom so filtered runs only emit
            // for selected fixtures; Cell<bool> dedups warm-up +
            // measurement repeats. PR #269 review.
            let emitted = Cell::new(false);
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut record = run_bench(&spec_owned);
                    total += record.search_elapsed;
                    if !emitted.get() {
                        record.git_sha = sha.clone();
                        record.timestamp_utc = ts.clone();
                        append_json(&record, &out);
                        emitted.set(true);
                    }
                }
                total
            });
        });
    }

    group.finish();
}

criterion_group!(benches, phase2);
criterion_main!(benches);
