//! Phase 3 — algebraic identities & fusion catalog.

use criterion::{Criterion, criterion_group, criterion_main};
use s11::bench_support::{append_json, discover_specs_in, run_bench, run_provenance};
use std::path::PathBuf;
use std::time::Duration;

fn phase3(c: &mut Criterion) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/algebraic_fusion");
    let specs = discover_specs_in(&dir, 3);
    if specs.is_empty() {
        eprintln!("no Phase 3 fixtures under {}; skipping", dir.display());
        return;
    }
    let (git_sha, timestamp_utc) = run_provenance();
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/results/results.jsonl");

    let mut group = c.benchmark_group("algebraic_fusion");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for spec in &specs {
        let mut record = run_bench(spec);
        record.git_sha = git_sha.clone();
        record.timestamp_utc = timestamp_utc.clone();
        append_json(&record, &out);

        let spec_owned = spec.clone();
        group.bench_function(spec_owned.id.clone(), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += run_bench(&spec_owned).search_elapsed;
                }
                total
            });
        });
    }

    group.finish();
}

criterion_group!(benches, phase3);
criterion_main!(benches);
