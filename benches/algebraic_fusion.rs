//! Phase 3 — algebraic identities & fusion catalog.
//!
//! Mirror of `benches/hackers_delight.rs` (phase=3); fixtures under
//! `benches/algebraic_fusion/` exercise textbook identities the
//! optimizer is expected to rediscover. The optimizer measures the
//! search overhead of recognising each identity, recorded into the
//! shared JSON-Lines accumulator.

use criterion::{Criterion, criterion_group, criterion_main};
use s11::bench_support::{BenchRecord, BenchSpec, append_json, run_bench};
use s11::search::config::Algorithm;
use s11::semantics::cost::CostMetric;
use std::path::PathBuf;
use std::time::Duration;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/algebraic_fusion")
}

fn results_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/results/results.jsonl")
}

fn run_provenance() -> (Option<String>, Option<String>) {
    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        });
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| format!("{}s", d.as_secs()));
    (sha, ts)
}

fn discover_specs() -> Vec<BenchSpec> {
    let dir = fixture_dir();
    let mut specs: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "s"))
        .map(|fixture| {
            let id = fixture
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            BenchSpec {
                id,
                fixture,
                phase: 3,
                algorithm: Algorithm::Enumerative,
                cost_metric: CostMetric::InstructionCount,
                seed: 42,
                timeout: Duration::from_secs(30),
            }
        })
        .collect();
    specs.sort_by(|a, b| a.id.cmp(&b.id));
    specs
}

fn phase3(c: &mut Criterion) {
    let specs = discover_specs();
    if specs.is_empty() {
        eprintln!("no Phase 3 fixtures found; skipping");
        return;
    }

    let (git_sha, timestamp_utc) = run_provenance();
    let results = results_path();

    let mut group = c.benchmark_group("algebraic_fusion");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for spec in &specs {
        let spec_owned = spec.clone();
        let sha = git_sha.clone();
        let ts = timestamp_utc.clone();
        let out = results.clone();
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

criterion_group!(benches, phase3);
criterion_main!(benches);
