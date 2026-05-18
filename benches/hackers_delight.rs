//! Phase 1 — Hacker's Delight micro-suite.

use criterion::{Criterion, criterion_group, criterion_main};
use s11::bench_support::{BenchRecord, append_json, discover_specs_in, run_bench, run_provenance};
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
            let mut next_sample = 0u32;
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut record: BenchRecord = run_bench(&spec_owned, next_sample);
                    record.git_sha = sha.clone();
                    record.timestamp_utc = ts.clone();
                    let elapsed = Duration::from_millis(record.search_elapsed_ms);
                    append_json(&record, &out);
                    total += elapsed;
                    next_sample = next_sample.wrapping_add(1);
                }
                total
            });
        });
    }

    group.finish();
}

criterion_group!(benches, phase1);
criterion_main!(benches);
