use criterion::Criterion;
use s11::bench_support::{append_json, discover_specs_in, run_bench, run_provenance};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct PhaseConfig<'a> {
    pub group_name: &'a str,
    pub phase: u8,
    pub fixture_subdir: &'a str,
    pub empty_hint: Option<&'a str>,
}

pub fn run_phase(c: &mut Criterion, config: PhaseConfig<'_>) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(config.fixture_subdir);
    let specs = discover_specs_in(&dir, config.phase);
    if specs.is_empty() {
        print_empty_message(config.phase, &dir, config.empty_hint);
        return;
    }
    let (git_sha, timestamp_utc) = run_provenance();
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/results/results.jsonl");

    let mut group = c.benchmark_group(config.group_name);
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for spec in &specs {
        let spec_owned = spec.clone();
        let sha = git_sha.clone();
        let ts = timestamp_utc.clone();
        let out = out.clone();
        group.bench_function(spec_owned.id.clone(), |b| {
            let emitted = Cell::new(false);
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut record = run_bench(&spec_owned);
                    total += record.criterion_elapsed();
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

fn print_empty_message(phase: u8, dir: &Path, hint: Option<&str>) {
    if let Some(hint) = hint {
        eprintln!(
            "no Phase {phase} fixtures under {} — {hint}. Skipping.",
            dir.display()
        );
    } else {
        eprintln!(
            "no Phase {phase} fixtures under {}; skipping",
            dir.display()
        );
    }
}
