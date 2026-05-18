//! Enumerative search for AArch64 superoptimization.
//!
//! Replaces the MVP placeholder that previously lived in `main.rs`. Enumerates
//! candidate sequences of length `1..target.len()` over the configured
//! register/immediate sets (shared with the symbolic path) and verifies each
//! against the target with the live-out/flag-aware equivalence checker.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rayon::prelude::*;

use crate::ir::Instruction;
use crate::search::SearchAlgorithm;
use crate::search::candidate::generate_all_encodable_instructions;
use crate::search::config::{Algorithm, SearchConfig};
use crate::search::result::{SearchResult, SearchStatistics};
use crate::semantics::cost::sequence_cost;
use crate::semantics::live_out::LiveOut;
use crate::semantics::{
    EquivalenceConfig, EquivalenceResult, check_equivalence_with_config_metrics,
};

/// Shared state for parallel workers. Counters are atomic to avoid locking; the
/// best-so-far sequence is behind a `Mutex` because it is only touched on an
/// improvement (rare relative to candidate evaluation count).
struct SharedState {
    best_cost: AtomicU64,
    stop: AtomicBool,
    candidates_evaluated: AtomicU64,
    smt_queries: AtomicU64,
    smt_equivalent: AtomicU64,
    smt_elapsed_nanos: AtomicU64,
    candidates_passed_fast: AtomicU64,
    improvements_found: AtomicU64,
    best: Mutex<Option<Vec<Instruction>>>,
}

impl SharedState {
    fn new(initial_best_cost: u64) -> Self {
        Self {
            best_cost: AtomicU64::new(initial_best_cost),
            stop: AtomicBool::new(false),
            candidates_evaluated: AtomicU64::new(0),
            smt_queries: AtomicU64::new(0),
            smt_equivalent: AtomicU64::new(0),
            smt_elapsed_nanos: AtomicU64::new(0),
            candidates_passed_fast: AtomicU64::new(0),
            improvements_found: AtomicU64::new(0),
            best: Mutex::new(None),
        }
    }

    fn record_improvement(&self, candidate: Vec<Instruction>, cost: u64) {
        // Take the mutex first, then re-check best_cost under the lock. The
        // outer atomic load is still useful for the lock-free cost-prune fast
        // path in the per-length runners, but every actual commit happens
        // under the mutex so we cannot interleave a worse candidate after a
        // better one. Without the re-check, two threads could both CAS-win
        // sequentially (worse first, better second) and then have the worse
        // thread acquire the mutex last and clobber the better candidate.
        //
        // Ordering: the cost-prune fast path in `run_length_one`/`_two` loads
        // `best_cost` with `Ordering::Acquire`. The store below is `Release`
        // (not `Relaxed`) so those loads observe the new value — the mutex
        // unlock would publish the mutex-protected `best`, but the atomic is
        // read independently of the mutex on the fast path, so it needs its
        // own release.
        let mut guard = self.best.lock().expect("best mutex poisoned");
        if cost < self.best_cost.load(Ordering::Acquire) {
            self.best_cost.store(cost, Ordering::Release);
            *guard = Some(candidate);
            self.improvements_found.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Verify a candidate against the target with the symbolic-path verification
/// posture (live-out + NZCV + 5-test pre-filter). Free function so it can run
/// inside rayon's parallel closures (no `&mut self` capture).
fn verify_candidate(
    target: &[Instruction],
    candidate: &[Instruction],
    live_out: &LiveOut,
    config: &SearchConfig,
    shared: &SharedState,
) -> bool {
    let smt_timeout = config
        .symbolic
        .solver_timeout
        .unwrap_or(Duration::from_secs(5));
    let equiv_config = EquivalenceConfig::with_live_out(live_out.clone())
        .random_tests(5)
        .timeout(smt_timeout)
        .with_flags(true);

    shared.smt_queries.fetch_add(1, Ordering::Relaxed);
    let (verdict, metrics) =
        check_equivalence_with_config_metrics(target, candidate, &equiv_config);
    let solver_nanos: u64 = metrics
        .smt_elapsed
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX);
    shared
        .smt_elapsed_nanos
        .fetch_add(solver_nanos, Ordering::Relaxed);
    match verdict {
        EquivalenceResult::Equivalent => {
            shared.smt_equivalent.fetch_add(1, Ordering::Relaxed);
            shared
                .candidates_passed_fast
                .fetch_add(1, Ordering::Relaxed);
            true
        }
        EquivalenceResult::NotEquivalentFast(_) => {
            // Rejected by random-test pre-filter; not a real SMT query.
            shared.smt_queries.fetch_sub(1, Ordering::Relaxed);
            false
        }
        _ => false,
    }
}

pub struct EnumerativeSearch {
    statistics: SearchStatistics,
}

impl EnumerativeSearch {
    pub fn new() -> Self {
        Self {
            statistics: SearchStatistics::new(Algorithm::Enumerative),
        }
    }

    fn timed_out(start: Instant, timeout: Option<Duration>) -> bool {
        timeout.is_some_and(|t| start.elapsed() >= t)
    }
}

fn run_length_one(
    target: &[Instruction],
    live_out: &LiveOut,
    config: &SearchConfig,
    all_instructions: &[Instruction],
    shared: &SharedState,
    start: Instant,
) {
    all_instructions.par_iter().for_each(|instr| {
        if shared.stop.load(Ordering::Relaxed) {
            return;
        }
        if EnumerativeSearch::timed_out(start, config.timeout) {
            shared.stop.store(true, Ordering::Relaxed);
            return;
        }
        let candidate = [*instr];
        let candidate_cost = sequence_cost(&candidate, &config.cost_metric);
        if candidate_cost >= shared.best_cost.load(Ordering::Acquire) {
            return;
        }
        shared.candidates_evaluated.fetch_add(1, Ordering::Relaxed);
        if verify_candidate(target, &candidate, live_out, config, shared) {
            shared.record_improvement(candidate.to_vec(), candidate_cost);
        }
    });
}

fn run_length_two(
    target: &[Instruction],
    live_out: &LiveOut,
    config: &SearchConfig,
    all_instructions: &[Instruction],
    shared: &SharedState,
    start: Instant,
) {
    // Parallelise only over the outer `instr1` loop; the inner loop runs
    // sequentially per worker so we don't oversubscribe rayon with O(pool²)
    // tasks and so cost-pruning observes monotonic best-cost updates locally.
    all_instructions.par_iter().for_each(|instr1| {
        if shared.stop.load(Ordering::Relaxed) {
            return;
        }
        // Mirror symbolic's timeout granularity (instr1 level).
        if EnumerativeSearch::timed_out(start, config.timeout) {
            shared.stop.store(true, Ordering::Relaxed);
            return;
        }
        for instr2 in all_instructions {
            if shared.stop.load(Ordering::Relaxed) {
                return;
            }
            let candidate = [*instr1, *instr2];
            let candidate_cost = sequence_cost(&candidate, &config.cost_metric);
            if candidate_cost >= shared.best_cost.load(Ordering::Acquire) {
                continue;
            }
            shared.candidates_evaluated.fetch_add(1, Ordering::Relaxed);
            if verify_candidate(target, &candidate, live_out, config, shared) {
                shared.record_improvement(candidate.to_vec(), candidate_cost);
            }
        }
    });
}

impl Default for EnumerativeSearch {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchAlgorithm<crate::isa::AArch64> for EnumerativeSearch {
    type LiveOut = LiveOut;
    type Result = SearchResult;

    fn search(
        &mut self,
        target: &[Instruction],
        live_out: &LiveOut,
        config: &SearchConfig,
    ) -> SearchResult {
        self.reset();
        let start = Instant::now();

        let original_cost = sequence_cost(target, &config.cost_metric);
        self.statistics.original_cost = original_cost;
        self.statistics.best_cost_found = original_cost;

        if target.len() < 2 {
            self.statistics.elapsed_time = start.elapsed();
            return SearchResult::no_optimization(target.to_vec(), self.statistics.clone());
        }

        let all_instructions = generate_all_encodable_instructions(
            &config.available_registers,
            &config.available_immediates,
        );
        let shared = SharedState::new(original_cost);

        let run_lengths = |s: &SharedState| {
            // Search increasing lengths up to target.len()-1 so we never
            // propose a candidate as long as the target. We keep going after a
            // hit because length-1 may exist alongside length-2; cost-pruning
            // enforces strict improvement.
            for length in 1..target.len() {
                if Self::timed_out(start, config.timeout) || s.stop.load(Ordering::Relaxed) {
                    break;
                }
                match length {
                    1 => run_length_one(target, live_out, config, &all_instructions, s, start),
                    2 => run_length_two(target, live_out, config, &all_instructions, s, start),
                    _ => {} // length >= 3 lands in a follow-up TDD cycle.
                }
            }
        };

        match config.cores {
            // Any explicit thread count — including 1 — gets a private pool
            // sized to that count. The `Some(1)` case in particular must
            // *not* fall through to the global rayon pool, or the user's
            // request for 1 thread would silently run on every logical core.
            Some(n) => match rayon::ThreadPoolBuilder::new()
                .num_threads(n.max(1))
                .build()
            {
                Ok(pool) => pool.install(|| run_lengths(&shared)),
                Err(e) => {
                    // Resource exhaustion (rare in practice): fall back to
                    // the global rayon pool rather than unwinding through
                    // `search()`'s non-`Result` return type. The user gets
                    // unbounded parallelism instead of zero — better than a
                    // panic for a CLI tool.
                    eprintln!(
                        "warning: failed to build private rayon pool with {} thread(s) ({}); falling back to global pool",
                        n, e
                    );
                    run_lengths(&shared);
                }
            },
            // `None` → use the global pool (rayon's default = logical cores).
            None => run_lengths(&shared),
        }

        // Drain shared atomics into self.statistics.
        self.statistics.candidates_evaluated = shared.candidates_evaluated.load(Ordering::Relaxed);
        self.statistics.smt_queries = shared.smt_queries.load(Ordering::Relaxed);
        self.statistics.smt_equivalent = shared.smt_equivalent.load(Ordering::Relaxed);
        self.statistics.smt_elapsed =
            Duration::from_nanos(shared.smt_elapsed_nanos.load(Ordering::Relaxed));
        self.statistics.candidates_passed_fast =
            shared.candidates_passed_fast.load(Ordering::Relaxed);
        self.statistics.improvements_found = shared.improvements_found.load(Ordering::Relaxed);

        let best_solution = shared.best.into_inner().expect("best mutex poisoned");
        self.statistics.elapsed_time = start.elapsed();

        match best_solution {
            Some(seq) => {
                self.statistics.best_cost_found = sequence_cost(&seq, &config.cost_metric);
                SearchResult::with_optimization(target.to_vec(), seq, self.statistics.clone())
            }
            None => SearchResult::no_optimization(target.to_vec(), self.statistics.clone()),
        }
    }

    fn statistics(&self) -> SearchStatistics {
        self.statistics.clone()
    }

    fn reset(&mut self) {
        self.statistics = SearchStatistics::new(Algorithm::Enumerative);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Instruction, Operand, Register};
    use crate::search::config::SymbolicConfig;

    #[test]
    fn empty_target_returns_no_optimization() {
        let mut search = EnumerativeSearch::new();
        let result = search.search(&[], &LiveOut::all_registers(), &SearchConfig::default());
        assert!(!result.found_optimization);
        assert!(result.optimized_sequence.is_none());
    }

    #[test]
    fn statistics_aggregate_smt_elapsed() {
        // Reuse the same length-3 target as `finds_length_two_rewrite` —
        // proven to drive at least one SMT equivalence check during the
        // length-2 sweep. After the search returns, the cumulative SMT
        // wall time must be non-zero, and it must be <= the overall search
        // elapsed (sanity check on aggregation correctness).
        let target = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Register(Register::X0),
            },
            Instruction::Eor {
                rd: Register::X2,
                rn: Register::X2,
                rm: Operand::Register(Register::X2),
            },
        ];
        let live_out = LiveOut::from_registers(vec![Register::X0, Register::X2]);
        let config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![0, 1])
            .with_timeout(std::time::Duration::from_secs(30));

        let mut search = EnumerativeSearch::new();
        let result = search.search(&target, &live_out, &config);

        assert!(
            result.statistics.smt_queries > 0,
            "precondition: search must hit SMT"
        );
        assert!(
            result.statistics.smt_elapsed > std::time::Duration::ZERO,
            "smt_elapsed must aggregate non-zero solver time; got {:?}",
            result.statistics.smt_elapsed
        );
        assert!(
            result.statistics.smt_elapsed <= result.statistics.elapsed_time,
            "smt_elapsed ({:?}) must be <= overall elapsed ({:?})",
            result.statistics.smt_elapsed,
            result.statistics.elapsed_time
        );
    }

    fn small_config() -> SearchConfig {
        // Tight register/immediate pool so unit tests run fast.
        SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1])
            .with_timeout(std::time::Duration::from_secs(10))
    }

    #[test]
    fn single_instruction_target_returns_no_optimization() {
        // Length-1 cannot be shortened (search range is 1..target.len() = 1..1 = empty).
        let target = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];
        let mut search = EnumerativeSearch::new();
        let result = search.search(&target, &LiveOut::all_registers(), &SearchConfig::default());
        assert!(!result.found_optimization);
    }

    #[test]
    fn finds_length_two_rewrite() {
        // Target (length 3):
        //   mov x0, x1                 ; x0 = x1
        //   eor x0, x0, x0             ; x0 = 0
        //   eor x2, x2, x2             ; x2 = 0
        // Live { X0, X2 }: post-state needs X0 = 0 AND X2 = 0. No single AArch64
        // instruction writes both registers, so length 1 is unreachable. The
        // length-2 optimum (e.g. `mov x0, #0; mov x2, #0`) is found on the very
        // first outer-loop iteration once length-2 search is implemented: both
        // halves are MovImm — the first candidate the generator emits for each
        // `rd` in `generate_all_encodable_instructions`. After the hit,
        // cost-pruning collapses the remainder of the search to O(pool).
        let target = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Register(Register::X0),
            },
            Instruction::Eor {
                rd: Register::X2,
                rn: Register::X2,
                rm: Operand::Register(Register::X2),
            },
        ];
        let live_out = LiveOut::from_registers(vec![Register::X0, Register::X2]);

        let config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![0, 1])
            .with_timeout(std::time::Duration::from_secs(30));

        let mut search = EnumerativeSearch::new();
        let result = search.search(&target, &live_out, &config);

        assert!(
            result.found_optimization,
            "expected a length-2 rewrite to be found"
        );
        let optimized = result.optimized_sequence.expect("optimized seq present");
        assert!(
            optimized.len() < target.len(),
            "optimized length {} should be shorter than target length {}",
            optimized.len(),
            target.len()
        );
        assert_eq!(optimized.len(), 2, "expected length-2 optimum");
    }

    #[test]
    fn respects_available_registers() {
        // Restrict to {X0, X1}; any candidate the search returns must only
        // reference those registers (no X2-X30, SP, or XZR).
        let target = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        // 60s budget absorbs cargo-llvm-cov's 3-5x instrumentation overhead.
        let config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1])
            .with_timeout(std::time::Duration::from_secs(60));

        let mut search = EnumerativeSearch::new();
        let result = search.search(&target, &live_out, &config);

        let optimized = result.optimized_sequence.expect("expected an optimization");
        let allowed = [Register::X0, Register::X1];
        for instr in &optimized {
            if let Some(rd) = instr.destination() {
                assert!(
                    allowed.contains(&rd),
                    "destination {:?} not in allowed registers {:?}",
                    rd,
                    allowed
                );
            }
            for src in instr.source_registers() {
                assert!(
                    allowed.contains(&src),
                    "source register {:?} not in allowed registers {:?}",
                    src,
                    allowed
                );
            }
        }
    }

    #[test]
    fn cores_one_uses_private_pool_not_global() {
        // Regression: a previous `Some(n) if n > 1` guard let `Some(1)` fall
        // through to the global rayon pool. After the fix every `Some(_)`
        // gets a private pool sized to that value, even 1. We assert
        // correctness by checking that `cores = Some(1)` still finds the
        // rewrite and that observable behaviour matches the parallel runs.
        let target = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        let live_out = LiveOut::from_registers(vec![Register::X0]);
        let config = small_config().with_cores(Some(1));

        let mut search = EnumerativeSearch::new();
        let result = search.search(&target, &live_out, &config);

        assert!(
            result.found_optimization,
            "cores=Some(1) should still find rewrite"
        );
        assert_eq!(result.optimized_sequence.as_ref().map(Vec::len), Some(1));
    }

    #[test]
    fn cores_parallel_finds_same_optimization() {
        // Same acceptance target as the length-1 test. With cores = Some(2) the
        // search must still find a length-1 rewrite, demonstrating that the
        // rayon parallelism path is correct (not just that it compiles).
        let target = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let config = small_config().with_cores(Some(2));

        let mut search = EnumerativeSearch::new();
        let result = search.search(&target, &live_out, &config);

        assert!(
            result.found_optimization,
            "parallel search should find rewrite"
        );
        assert_eq!(
            result.optimized_sequence.as_ref().map(Vec::len),
            Some(1),
            "should collapse to a single instruction under cores=Some(2)"
        );
    }

    #[test]
    fn length_four_target_iterates_past_length_three_dispatch() {
        // Pins the `_ => {}` arm of the per-length dispatch: a length-4
        // target makes the outer loop iterate over lengths 1, 2, and 3, so
        // length 3 must hit the not-yet-implemented arm without panicking.
        // The target intentionally has a length-1 equivalent (`add x0, x1,
        // #1`) so cost-pruning collapses the length-2 enumeration after the
        // first hit and the test completes in well under a second; the
        // assertion still proves we *reached and survived* length 3.
        let target = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let mut search = EnumerativeSearch::new();
        let result = search.search(&target, &live_out, &small_config());

        // The important assertion is that the search returned — i.e. the
        // length-3 `_ => {}` arm did not panic, the loop iterated past it,
        // and the result was assembled cleanly.
        assert!(result.statistics.elapsed_time > std::time::Duration::ZERO);
        assert!(result.found_optimization, "length-1 collapse should fire");
        assert_eq!(result.optimized_sequence.as_ref().map(Vec::len), Some(1));
    }

    #[test]
    fn search_honors_timeout() {
        // Construct a target with no length-1 equivalent in the small pool, so
        // length-1 enumeration runs all the way through. Then set an extremely
        // tight timeout and assert wall-clock is bounded.
        //
        // Target: two non-trivial instructions writing X0 and X2. There is no
        // single-instruction equivalent in {X0, X1, X2} × {0, 1}.
        let target = vec![
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Add {
                rd: Register::X2,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
        ];
        let live_out = LiveOut::from_registers(vec![Register::X0, Register::X2]);

        // cores=1 + 200ms SMT cap bound post-timeout drain deterministically.
        let config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![0, 1])
            .with_timeout(std::time::Duration::from_millis(50))
            .with_cores(Some(1))
            .with_symbolic(
                SymbolicConfig::default().with_timeout(std::time::Duration::from_millis(200)),
            );

        let start = std::time::Instant::now();
        let mut search = EnumerativeSearch::new();
        let result = search.search(&target, &live_out, &config);
        let elapsed = start.elapsed();

        // 10s ceiling: 1 worker × 200ms drain × cargo-llvm-cov 3-5x ≈ 1s typical.
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "search ran for {:?}, expected < 10s under a 50ms timeout",
            elapsed
        );
        // Statistics must reflect that the search actually ran.
        assert!(
            result.statistics.elapsed_time > std::time::Duration::ZERO,
            "statistics.elapsed_time should be populated"
        );
    }

    #[test]
    fn collapses_mov_add_into_single_add() {
        // Acceptance example from issue #67:
        //   mov x0, x1; add x0, x0, #1   ≡   add x0, x1, #1
        let target = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        // Only X0 needs to be live-out for the rewrite to be valid; if we kept
        // X1's pre-value live we couldn't prove equivalence (the MOV clobbers
        // it). Test the supported acceptance shape.
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let mut search = EnumerativeSearch::new();
        let result = search.search(&target, &live_out, &small_config());

        assert!(
            result.found_optimization,
            "expected length-1 rewrite to be found"
        );
        let optimized = result.optimized_sequence.expect("optimized seq present");
        assert_eq!(
            optimized.len(),
            1,
            "should collapse to a single instruction"
        );
    }
}
