//! Shared harness for the criterion benchmark suite (issue #70).
//!
//! Each bench file under `benches/` brings these helpers in via
//! `use s11::bench_support::*;`. The module lives in the library —
//! not under `benches/common/` — because `harness = false` benchmarks
//! cannot run `#[test]` blocks; we need a regular lib-test path to
//! exercise the helpers under TDD.

use crate::ir::Instruction;
use crate::parser::{LineResult, parse_line};
use crate::search::SearchAlgorithm;
use crate::search::config::{Algorithm, SearchConfig};
use crate::semantics::cost::{CostMetric, sequence_cost};
use crate::semantics::live_out::LiveOut;
use crate::validation::live_out::parse_live_out_contract;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Short git SHA + a unix-epoch-seconds timestamp, captured once per
/// process and stamped onto every `BenchRecord` emitted in this run.
pub fn run_provenance() -> (Option<String>, Option<String>) {
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

/// Discover every `.s` file under `dir` and turn each into a
/// `BenchSpec`. Specs are returned sorted by id for deterministic
/// criterion output ordering. Returns an empty vector if `dir` is
/// missing or has no `.s` files.
pub fn discover_specs_in(dir: &Path, phase: u8) -> Vec<BenchSpec> {
    let Ok(read) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut specs: Vec<_> = read
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
                phase,
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

/// Parse a benchmark `.s` fixture into its target sequence plus the
/// live-out contract declared in its `// Live-out:` header.
///
/// Header grammar matches `validation::live_out::parse_live_out_contract`
/// — e.g. `// Live-out: x0,x1;nzcv`. Comments starting with `//` are
/// stripped by `parse_line`; every non-comment line is parsed as
/// AArch64 assembly.
///
/// Panics if no `// Live-out:` header is found — bench fixtures are
/// author-controlled, so a missing header is a fixture defect.
pub fn load_sequence(path: &Path) -> (Vec<Instruction>, LiveOut, bool) {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));

    let live_spec = source
        .lines()
        .find_map(|line| {
            let trimmed = line.trim_start();
            let body = trimmed.strip_prefix("//")?.trim_start();
            body.strip_prefix("Live-out:").map(str::trim)
        })
        .unwrap_or_else(|| {
            panic!(
                "fixture {} missing required `// Live-out:` header — see benches/README.md",
                path.display()
            )
        });

    let (live_out, flags_live) = parse_live_out_contract(live_spec).unwrap_or_else(|e| {
        panic!(
            "fixture {}: malformed live-out contract {live_spec:?}: {e:?}",
            path.display()
        )
    });

    let mut sequence = Vec::new();
    for line in source.lines() {
        match parse_line(line) {
            Ok(LineResult::Instruction(instr)) => sequence.push(instr),
            Ok(LineResult::Skip) => {}
            Err(e) => panic!(
                "fixture {}: parse error on line {line:?}: {e:?}",
                path.display()
            ),
        }
    }

    (sequence, live_out, flags_live)
}

/// One canonical record per `(benchmark_id, cargo bench invocation)`.
///
/// JSON emission is gated to a single call site outside criterion's
/// `iter_custom`, so the JSONL accumulator contains exactly one row
/// per fixture per `cargo bench` run. Criterion's HTML report owns the
/// per-sample variance; this record is the snapshot downstream tooling
/// diffs across commits.
#[derive(Debug, Clone, Serialize)]
pub struct BenchRecord {
    pub benchmark_id: String,
    pub phase: u8,
    pub algorithm: String,
    pub seed: u64,
    pub cost_metric: String,
    pub original_length: usize,
    pub found_length: Option<usize>,
    pub original_cost: u64,
    pub best_cost: u64,
    /// Truncated to milliseconds for the JSON-Lines record so the file
    /// is easy to skim. Bench files MUST use [`BenchRecord::search_elapsed`]
    /// (precise `Duration`) when feeding criterion's `iter_custom`, or
    /// sub-millisecond samples round to zero — see PR #269 review.
    pub search_elapsed_ms: u64,
    /// Full-precision wall time of the search. Excluded from the JSON
    /// serialization because `search_elapsed_ms` is the documented
    /// schema field; this is the value criterion's timing model needs.
    #[serde(skip)]
    pub search_elapsed: Duration,
    pub smt_elapsed_ms: u64,
    pub smt_queries: u64,
    pub smt_equivalent: u64,
    pub candidates_evaluated: u64,
    pub success: bool,
    pub timeout: bool,
    pub git_sha: Option<String>,
    pub timestamp_utc: Option<String>,
}

/// Append one `BenchRecord` as a JSON line to `path`, creating the
/// file (and any missing parent directories) on first use. A process-
/// wide `Mutex` serialises concurrent appenders so multi-threaded
/// criterion runs cannot interleave half-records into the file.
pub fn append_json(record: &BenchRecord, path: &Path) {
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};

    static OUTPUT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = OUTPUT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("bench JSONL output lock poisoned");

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("create_dir_all {}: {e}", parent.display()));
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|e| panic!("open bench JSONL {}: {e}", path.display()));
    let line = serde_json::to_string(record).expect("BenchRecord must serialise");
    writeln!(file, "{line}").unwrap_or_else(|e| panic!("write bench JSONL: {e}"));
    drop(guard);
}

/// Spec for one benchmark — derived from the fixture path and the
/// surrounding bench file.
#[derive(Debug, Clone)]
pub struct BenchSpec {
    pub id: String,
    pub fixture: PathBuf,
    pub phase: u8,
    pub algorithm: Algorithm,
    pub cost_metric: CostMetric,
    pub seed: u64,
    pub timeout: Duration,
}

/// Run the optimizer against one fixture and synthesise a `BenchRecord`.
///
/// Deterministic given `spec.seed`. Bench drivers call this **once per
/// `cargo bench` invocation** outside criterion's `iter_custom` so the
/// JSON-Lines accumulator stays exactly one record per fixture —
/// criterion's warmup phase would otherwise emit unmeasured records
/// (PR #269 review). Inside `iter_custom`, drivers re-call `run_bench`
/// just to read `search_elapsed` for criterion's timing model.
pub fn run_bench(spec: &BenchSpec) -> BenchRecord {
    let (target, live_out, _flags_live) = load_sequence(&spec.fixture);
    let original_length = target.len();
    let original_cost = sequence_cost(&target, &spec.cost_metric);

    let mut config = SearchConfig::default()
        .with_algorithm(spec.algorithm)
        .with_cost_metric(spec.cost_metric)
        .with_timeout(spec.timeout);
    config.stochastic.seed = Some(spec.seed);

    let (statistics, optimized) = match spec.algorithm {
        Algorithm::Enumerative => {
            let mut search = crate::search::EnumerativeSearch::new();
            let result = search.search(&target, &live_out, &config);
            (result.statistics, result.optimized_sequence)
        }
        Algorithm::Stochastic => {
            let mut search = crate::search::StochasticSearch::<crate::isa::AArch64>::new();
            let result = search.search(&target, &live_out, &config);
            (result.statistics, result.optimized_sequence)
        }
        Algorithm::Symbolic => {
            let mut search = crate::search::SymbolicSearch::<crate::isa::AArch64>::new();
            let result = search.search(&target, &live_out, &config);
            (result.statistics, result.optimized_sequence)
        }
        // Hybrid/LLM not wired into the bench harness — issue #70 keeps
        // those out of scope. Caller should pre-filter.
        other => panic!("run_bench: unsupported algorithm {other:?}"),
    };

    let found_length = optimized.as_ref().map(|s| s.len());
    let best_cost = optimized
        .as_ref()
        .map(|s| sequence_cost(s, &spec.cost_metric))
        .unwrap_or(original_cost);
    let success = optimized.is_some();
    let timed_out = statistics.elapsed_time >= spec.timeout;

    BenchRecord {
        benchmark_id: spec.id.clone(),
        phase: spec.phase,
        algorithm: spec.algorithm.to_string(),
        seed: spec.seed,
        cost_metric: format!("{:?}", spec.cost_metric).to_ascii_lowercase(),
        original_length,
        found_length,
        original_cost,
        best_cost,
        search_elapsed_ms: statistics.elapsed_time.as_millis() as u64,
        search_elapsed: statistics.elapsed_time,
        smt_elapsed_ms: statistics.smt_elapsed.as_millis() as u64,
        smt_queries: statistics.smt_queries,
        smt_equivalent: statistics.smt_equivalent,
        candidates_evaluated: statistics.candidates_evaluated,
        success,
        timeout: timed_out,
        git_sha: None,
        timestamp_utc: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_fixture(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .prefix("bench-fixture")
            .suffix(".s")
            .tempfile()
            .expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    #[test]
    fn load_sequence_parses_header_and_body() {
        let f = write_fixture(
            "// Live-out: x0\n\
             // commentary\n\
             mov x0, x1\n\
             add x0, x0, #1\n",
        );
        let (seq, live_out, flags_live) = load_sequence(f.path());
        assert_eq!(seq.len(), 2, "expected MOV + ADD");
        assert!(
            live_out.contains_register(crate::ir::Register::X0),
            "live-out must include X0"
        );
        assert!(!flags_live, "header without ;nzcv should be flags-dead");
    }

    #[test]
    fn load_sequence_picks_up_flags_live() {
        let f = write_fixture("// Live-out: x0;nzcv\nmov x0, #1\n");
        let (_, _, flags_live) = load_sequence(f.path());
        assert!(flags_live, "header with ;nzcv must report flags_live=true");
    }

    #[test]
    #[should_panic(expected = "missing required `// Live-out:` header")]
    fn load_sequence_panics_without_header() {
        let f = write_fixture("mov x0, #0\n");
        let _ = load_sequence(f.path());
    }

    #[test]
    fn append_json_writes_one_jsonl_record_per_call() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("results.jsonl");
        let record = BenchRecord {
            benchmark_id: "demo".to_string(),
            phase: 1,
            algorithm: "enumerative".to_string(),
            seed: 7,
            cost_metric: "instructioncount".to_string(),
            original_length: 2,
            found_length: Some(1),
            original_cost: 2,
            best_cost: 1,
            search_elapsed_ms: 5,
            search_elapsed: Duration::from_millis(5),
            smt_elapsed_ms: 1,
            smt_queries: 3,
            smt_equivalent: 1,
            candidates_evaluated: 20,
            success: true,
            timeout: false,
            git_sha: None,
            timestamp_utc: None,
        };
        append_json(&record, &path);
        let mut second = record.clone();
        second.benchmark_id = "demo-2".to_string();
        append_json(&second, &path);

        let body = std::fs::read_to_string(&path).expect("read jsonl");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "two appends → two lines");
        let parsed: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).expect("each line must be valid JSON"))
            .collect();
        assert_eq!(parsed[0]["benchmark_id"], "demo");
        assert_eq!(parsed[1]["benchmark_id"], "demo-2");
    }

    /// Smoke-test every shipped fixture (Phase 1 + Phase 3): each
    /// must parse via `load_sequence` without panicking. Catches typos
    /// in the fixture set without depending on running the optimizer.
    /// Phase 2 (benches/llvm_codegen/) is intentionally skipped — that
    /// directory is empty in HEAD and only populated by the
    /// harvester.
    #[test]
    fn every_committed_fixture_parses() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        for sub in ["benches/hackers_delight", "benches/algebraic_fusion"] {
            let dir = std::path::Path::new(manifest_dir).join(sub);
            let entries: Vec<_> = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "s"))
                .collect();
            assert!(
                entries.len() >= 10,
                "expected at least 10 fixtures under {sub}, found {}",
                entries.len()
            );
            for entry in entries {
                let path = entry.path();
                let (seq, _live_out, _flags_live) = load_sequence(&path);
                assert!(
                    !seq.is_empty(),
                    "fixture {} parsed to an empty sequence",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn run_bench_enumerative_records_metrics_for_fusible_target() {
        // `mov x0, x1; add x0, x0, #1` collapses into `add x0, x1, #1`
        // under enumerative search — original_length=2 must shrink to
        // found_length=1, success=true, and metrics must be populated.
        let f = write_fixture(
            "// Live-out: x0\n\
             mov x0, x1\n\
             add x0, x0, #1\n",
        );
        let spec = BenchSpec {
            id: "mov_add_fuse".to_string(),
            fixture: f.path().to_path_buf(),
            phase: 1,
            algorithm: Algorithm::Enumerative,
            cost_metric: CostMetric::InstructionCount,
            seed: 42,
            timeout: Duration::from_secs(30),
        };

        let record = run_bench(&spec);

        assert_eq!(record.benchmark_id, "mov_add_fuse");
        assert_eq!(record.phase, 1);
        assert_eq!(record.algorithm, "enumerative");
        assert_eq!(record.seed, 42);
        assert_eq!(record.original_length, 2);
        assert_eq!(record.original_cost, 2);
        assert!(record.success, "fusion target should succeed");
        assert_eq!(record.found_length, Some(1));
        assert_eq!(record.best_cost, 1);
        assert!(record.smt_queries > 0, "enumerative search must hit SMT");
        assert!(record.candidates_evaluated > 0);
        assert!(!record.timeout);
    }
}
