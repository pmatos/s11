//! Phase 1 — Hacker's Delight micro-suite.

use criterion::{Criterion, criterion_group, criterion_main};
use s11::bench_support::{append_json, discover_specs_in, run_bench, run_provenance};
use std::cell::Cell;
use std::path::PathBuf;
use std::time::Duration;

fn phase1(c: &mut Criterion) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/hackers_delight");
    let specs = discover_specs_in(&dir, 1);
    if specs.is_empty() {
        eprintln!("no Phase 1 fixtures under {}; skipping", dir.display());
        return;
    }
    let (git_sha, timestamp_utc) = run_provenance();
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/results/results.jsonl");

    let mut group = c.benchmark_group("hackers_delight");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for spec in &specs {
        let spec_owned = spec.clone();
        let sha = git_sha.clone();
        let ts = timestamp_utc.clone();
        let out = out.clone();
        group.bench_function(spec_owned.id.clone(), |b| {
            // JSON emission lives inside the closure so a filtered run
            // (`cargo bench -- max`) only produces rows for fixtures
            // criterion actually selects. Cell<bool> dedups across
            // criterion's repeated iter_custom calls (warm-up +
            // measurement) — exactly one record per fixture per
            // `cargo bench` invocation. PR #269 review.
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

criterion_group!(benches, phase1);
criterion_main!(benches);
