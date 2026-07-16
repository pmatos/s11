//! Enumerative search for superoptimization.
//!
//! Replaces the MVP placeholder that previously lived in `main.rs`. Enumerates
//! candidate sequences of length `1..target.len()` over the configured
//! register/immediate sets (shared with the symbolic path) and verifies each
//! against the target with the live-out/flag-aware equivalence checker.

use std::marker::PhantomData;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rayon::prelude::*;

use crate::isa::{AArch64, CostModel, ISA, InstructionGenerator};
use crate::search::SearchAlgorithm;
use crate::search::candidate::generate_all_encodable_instructions;
use crate::search::config::{Algorithm, SearchConfig};
use crate::search::result::{SearchResultFor, SearchStatistics};
use crate::semantics::cost::CostMetric;
use crate::semantics::equivalence::{
    EquivalenceConfigFor, check_equivalence_for_metrics, check_equivalence_with_config_metrics,
};
use crate::semantics::live_out::{LiveOut, X86LiveOut};
use crate::semantics::{EquivalenceConfig, EquivalenceMetrics, EquivalenceResult};

/// Shared state for parallel workers. Counters are atomic to avoid locking; the
/// best-so-far sequence is behind a `Mutex` because it is only touched on an
/// improvement (rare relative to candidate evaluation count).
struct SharedState<I: ISA> {
    best_cost: AtomicU64,
    stop: AtomicBool,
    candidates_evaluated: AtomicU64,
    candidates_pruned_by_cost: AtomicU64,
    smt_queries: AtomicU64,
    smt_equivalent: AtomicU64,
    smt_elapsed_nanos: AtomicU64,
    candidates_passed_fast: AtomicU64,
    improvements_found: AtomicU64,
    best: Mutex<Option<Vec<I::Instruction>>>,
}

struct CandidatePool<I: ISA> {
    registers: Vec<I::Register>,
    immediates: Vec<i64>,
    instructions: Vec<I::Instruction>,
}

impl<I: ISA> SharedState<I> {
    fn new(initial_best_cost: u64) -> Self {
        Self {
            best_cost: AtomicU64::new(initial_best_cost),
            stop: AtomicBool::new(false),
            candidates_evaluated: AtomicU64::new(0),
            candidates_pruned_by_cost: AtomicU64::new(0),
            smt_queries: AtomicU64::new(0),
            smt_equivalent: AtomicU64::new(0),
            smt_elapsed_nanos: AtomicU64::new(0),
            candidates_passed_fast: AtomicU64::new(0),
            improvements_found: AtomicU64::new(0),
            best: Mutex::new(None),
        }
    }

    fn record_improvement(&self, candidate: Vec<I::Instruction>, cost: u64) {
        // Take the mutex first, then re-check best_cost under the lock. The
        // outer atomic load is still useful for the lock-free cost-prune fast
        // path in the per-length runners, but every actual commit happens
        // under the mutex so we cannot interleave a worse candidate after a
        // better one. Without the re-check, two threads could both CAS-win
        // sequentially (worse first, better second) and then have the worse
        // thread acquire the mutex last and clobber the better candidate.
        //
        // Ordering: the cost-prune fast path in the length runners loads
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

pub trait EnumerativeBackend<I: ISA>: Sized {
    type LiveOut: Clone + Sync;

    fn registers_from_config(config: &SearchConfig) -> Vec<I::Register>;
    fn immediates_from_config(config: &SearchConfig) -> Vec<i64>;
    fn enumerate_all(regs: &[I::Register], imms: &[i64]) -> Vec<I::Instruction>;
    fn sequence_cost(seq: &[I::Instruction], config: &SearchConfig) -> u64;
    fn target_terminator(_target: &[I::Instruction]) -> Option<I::Instruction> {
        None
    }
    fn check_equivalence(
        target: &[I::Instruction],
        candidate: &[I::Instruction],
        live_out: &Self::LiveOut,
        smt_timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics);
}

impl EnumerativeBackend<AArch64> for AArch64 {
    type LiveOut = LiveOut;

    fn registers_from_config(config: &SearchConfig) -> Vec<crate::ir::Register> {
        config.available_registers.clone()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn enumerate_all(regs: &[crate::ir::Register], imms: &[i64]) -> Vec<crate::ir::Instruction> {
        generate_all_encodable_instructions(regs, imms)
    }

    fn sequence_cost(seq: &[crate::ir::Instruction], config: &SearchConfig) -> u64 {
        <AArch64 as CostModel<crate::ir::Instruction>>::sequence_cost(
            &AArch64,
            seq,
            &config.cost_metric,
        )
    }

    fn check_equivalence(
        target: &[crate::ir::Instruction],
        candidate: &[crate::ir::Instruction],
        live_out: &Self::LiveOut,
        smt_timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        let equiv_config = EquivalenceConfig::with_live_out(live_out.clone())
            .random_tests(5)
            .timeout(smt_timeout)
            .with_flags(live_out.flags_live())
            .with_memory(true);

        check_equivalence_with_config_metrics(target, candidate, &equiv_config)
    }
}

impl EnumerativeBackend<crate::isa::X86_64> for crate::isa::X86_64 {
    type LiveOut = X86LiveOut;

    fn registers_from_config(config: &SearchConfig) -> Vec<crate::isa::x86::X86Register> {
        config.x86_available_registers.clone()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn enumerate_all(
        regs: &[crate::isa::x86::X86Register],
        imms: &[i64],
    ) -> Vec<crate::isa::x86::X86Instruction> {
        crate::isa::x86::X86InstructionGenerator
            .generate_all(regs, imms)
            .into_iter()
            .filter(|instruction| {
                crate::search::candidate::is_sequence_encodable_for(
                    std::slice::from_ref(instruction),
                    &crate::isa::X86_64,
                )
            })
            .collect()
    }

    fn sequence_cost(seq: &[crate::isa::x86::X86Instruction], config: &SearchConfig) -> u64 {
        <crate::isa::X86_64 as CostModel<crate::isa::x86::X86Instruction>>::sequence_cost(
            &crate::isa::X86_64,
            seq,
            &config.cost_metric,
        )
    }

    fn target_terminator(
        target: &[crate::isa::x86::X86Instruction],
    ) -> Option<crate::isa::x86::X86Instruction> {
        crate::ir::instructions::split_terminator_x86(target)
            .1
            .copied()
    }

    fn check_equivalence(
        target: &[crate::isa::x86::X86Instruction],
        candidate: &[crate::isa::x86::X86Instruction],
        live_out: &Self::LiveOut,
        smt_timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        let equiv_config =
            EquivalenceConfigFor::<crate::isa::X86_64>::with_live_out(live_out.clone())
                .random_tests(5)
                .timeout(smt_timeout);
        check_equivalence_for_metrics::<crate::isa::X86_64>(target, candidate, &equiv_config)
    }
}

impl EnumerativeBackend<crate::isa::X86_32> for crate::isa::X86_32 {
    type LiveOut = X86LiveOut;

    fn registers_from_config(config: &SearchConfig) -> Vec<crate::isa::x86::X86Register> {
        config
            .x86_available_registers
            .iter()
            .copied()
            .filter(|r| matches!(r.index(), Some(i) if i < 8))
            .collect()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn enumerate_all(
        regs: &[crate::isa::x86::X86Register],
        imms: &[i64],
    ) -> Vec<crate::isa::x86::X86Instruction> {
        crate::isa::x86::X86InstructionGenerator
            .generate_all(regs, imms)
            .into_iter()
            .filter(|instruction| {
                crate::search::candidate::is_sequence_encodable_for(
                    std::slice::from_ref(instruction),
                    &crate::isa::X86_32,
                )
            })
            .collect()
    }

    fn sequence_cost(seq: &[crate::isa::x86::X86Instruction], config: &SearchConfig) -> u64 {
        <crate::isa::X86_32 as CostModel<crate::isa::x86::X86Instruction>>::sequence_cost(
            &crate::isa::X86_32,
            seq,
            &config.cost_metric,
        )
    }

    fn target_terminator(
        target: &[crate::isa::x86::X86Instruction],
    ) -> Option<crate::isa::x86::X86Instruction> {
        crate::ir::instructions::split_terminator_x86(target)
            .1
            .copied()
    }

    fn check_equivalence(
        target: &[crate::isa::x86::X86Instruction],
        candidate: &[crate::isa::x86::X86Instruction],
        live_out: &Self::LiveOut,
        smt_timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        let equiv_config =
            EquivalenceConfigFor::<crate::isa::X86_32>::with_live_out(live_out.clone())
                .random_tests(5)
                .timeout(smt_timeout);
        check_equivalence_for_metrics::<crate::isa::X86_32>(target, candidate, &equiv_config)
    }
}

/// Verify a candidate against the target with the symbolic-path verification
/// posture (live-out + NZCV + 5-test pre-filter). Free function so it can run
/// inside rayon's parallel closures (no `&mut self` capture).
fn verify_candidate<I>(
    target: &[I::Instruction],
    candidate: &[I::Instruction],
    live_out: &<I as EnumerativeBackend<I>>::LiveOut,
    config: &SearchConfig,
    shared: &SharedState<I>,
    start: Instant,
) -> bool
where
    I: ISA + EnumerativeBackend<I>,
{
    let Some(smt_timeout) = config.solver_timeout_within_budget(start.elapsed()) else {
        // No millisecond-granularity SMT budget remains for this candidate, so
        // stop the whole parallel enumerative search rather than just this arm.
        shared.stop.store(true, Ordering::Relaxed);
        return false;
    };
    let (verdict, metrics) =
        <I as EnumerativeBackend<I>>::check_equivalence(target, candidate, live_out, smt_timeout);
    // The parallel path applies the same canonical policy as the symbolic path
    // (see `SearchStatistics::verification_tally` for what each counter means:
    // `reached_solver` marks both an SMT query and a fast pass, including
    // candidates later disproved by Z3) to its atomic counters.
    let tally = SearchStatistics::verification_tally(&metrics, &verdict);
    let solver_nanos: u64 = tally.smt_elapsed.as_nanos().try_into().unwrap_or(u64::MAX);
    shared
        .smt_elapsed_nanos
        .fetch_add(solver_nanos, Ordering::Relaxed);
    if tally.reached_solver {
        shared.smt_queries.fetch_add(1, Ordering::Relaxed);
        shared
            .candidates_passed_fast
            .fetch_add(1, Ordering::Relaxed);
    }
    if tally.proved_equivalent {
        shared.smt_equivalent.fetch_add(1, Ordering::Relaxed);
    }
    tally.proved_equivalent
}

struct CachedThreadPool {
    effective_cores: usize,
    pool: rayon::ThreadPool,
}

pub struct EnumerativeSearch<I: ISA = AArch64> {
    statistics: SearchStatistics,
    candidate_pool: Option<CandidatePool<I>>,
    private_pool: Option<CachedThreadPool>,
    #[cfg(test)]
    private_pool_builds: u64,
    _isa: PhantomData<I>,
}

impl<I: ISA> EnumerativeSearch<I> {
    pub fn new() -> Self {
        Self {
            statistics: SearchStatistics::new(Algorithm::Enumerative),
            candidate_pool: None,
            private_pool: None,
            #[cfg(test)]
            private_pool_builds: 0,
            _isa: PhantomData,
        }
    }

    fn timed_out(start: Instant, timeout: Option<Duration>) -> bool {
        timeout.is_some_and(|t| start.elapsed() >= t)
    }

    fn cached_private_pool(
        &mut self,
        effective_cores: usize,
    ) -> Result<&rayon::ThreadPool, rayon::ThreadPoolBuildError> {
        let needs_rebuild = !matches!(
            self.private_pool.as_ref(),
            Some(cached) if cached.effective_cores == effective_cores
        );

        if needs_rebuild {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(effective_cores)
                .build()?;
            #[cfg(test)]
            {
                self.private_pool_builds += 1;
            }
            self.private_pool = Some(CachedThreadPool {
                effective_cores,
                pool,
            });
        }

        Ok(&self
            .private_pool
            .as_ref()
            .expect("private pool should be present after successful build")
            .pool)
    }

    #[cfg(test)]
    fn private_pool_build_count(&self) -> u64 {
        self.private_pool_builds
    }

    #[cfg(test)]
    fn private_pool_effective_cores(&self) -> Option<usize> {
        self.private_pool
            .as_ref()
            .map(|cached| cached.effective_cores)
    }
}

impl<I> EnumerativeSearch<I>
where
    I: ISA + EnumerativeBackend<I>,
{
    /// Construct an enumerative searcher with the candidate pool for `config`
    /// generated up front.
    pub fn with_config(config: &SearchConfig) -> Self {
        let mut search = Self::new();
        let _ = search.candidate_pool_for_config(config);
        search
    }

    fn candidate_pool_for_config(&mut self, config: &SearchConfig) -> &[I::Instruction] {
        let registers = <I as EnumerativeBackend<I>>::registers_from_config(config);
        let immediates = <I as EnumerativeBackend<I>>::immediates_from_config(config);
        let regenerate = match &self.candidate_pool {
            Some(pool) => pool.registers != registers || pool.immediates != immediates,
            None => true,
        };

        if regenerate {
            let instructions = <I as EnumerativeBackend<I>>::enumerate_all(&registers, &immediates);
            self.candidate_pool = Some(CandidatePool {
                registers,
                immediates,
                instructions,
            });
        }

        &self
            .candidate_pool
            .as_ref()
            .expect("candidate pool must be populated")
            .instructions
    }
}

fn evaluate_candidate<I>(
    target: &[I::Instruction],
    live_out: &<I as EnumerativeBackend<I>>::LiveOut,
    config: &SearchConfig,
    mut candidate: Vec<I::Instruction>,
    terminator: Option<I::Instruction>,
    shared: &SharedState<I>,
    start: Instant,
) where
    I: ISA + EnumerativeBackend<I>,
{
    if let Some(t) = terminator {
        candidate.push(t);
    }
    let candidate_cost = <I as EnumerativeBackend<I>>::sequence_cost(&candidate, config);
    shared.candidates_evaluated.fetch_add(1, Ordering::Relaxed);
    if candidate_cost >= shared.best_cost.load(Ordering::Acquire) {
        shared
            .candidates_pruned_by_cost
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    if verify_candidate::<I>(target, &candidate, live_out, config, shared, start) {
        shared.record_improvement(candidate, candidate_cost);
    }
}

fn minimum_generated_instruction_cost<I>(
    config: &SearchConfig,
    all_instructions: &[I::Instruction],
) -> Option<u64>
where
    I: ISA + EnumerativeBackend<I>,
{
    all_instructions
        .iter()
        .map(|instr| <I as EnumerativeBackend<I>>::sequence_cost(&[*instr], config))
        .min()
}

/// Valid lower bound on the cost of any candidate of `length` instructions
/// (plus the pinned terminator), used to prune whole lengths in the search.
///
/// **This MUST never exceed the real cost of any sequence of that length**, or
/// the search would prune valid candidates and become unsound.
///
/// - `InstructionCount` / `CodeSize` are monotone per-instruction *sums*, so the
///   tight, valid bound is `min_per_instruction_cost * length + terminator_cost`.
/// - `Latency` is NOT a sum: it is the sequence's critical path
///   (`cost_x86::critical_path_latency`, issue #622). A length-`L` candidate can
///   have a critical path as small as the latency of a single independent
///   instruction (e.g. `L` independent 1-cycle ops cost ~1, not `L`), so the
///   multiply-by-length / add-terminator bound is INVALID here. The only
///   provably-valid bound is the minimum single-instruction latency in the
///   candidate pool: every non-empty sequence's critical path is
///   `>= max_i latency(i) >= min_i latency(i)`, and `min_instruction_cost` /
///   `terminator_cost` are exactly single-instruction critical paths
///   (= isolated latencies). The bound is constant in `length` (looser, but
///   correct — correctness over tightness).
fn length_cost_lower_bound(
    metric: &CostMetric,
    length: usize,
    min_instruction_cost: u64,
    terminator_cost: u64,
) -> u64 {
    match metric {
        CostMetric::Latency => {
            // Critical-path cost: the cheapest non-empty sequence's critical
            // path is the minimum single-instruction latency over the pool and
            // the pinned terminator. Never grows with `length` and never
            // exceeds the real critical path.
            if terminator_cost == 0 {
                min_instruction_cost
            } else {
                min_instruction_cost.min(terminator_cost)
            }
        }
        CostMetric::InstructionCount | CostMetric::CodeSize => min_instruction_cost
            .saturating_mul(length as u64)
            .saturating_add(terminator_cost),
    }
}

fn run_length_one<I>(
    target: &[I::Instruction],
    live_out: &<I as EnumerativeBackend<I>>::LiveOut,
    config: &SearchConfig,
    all_instructions: &[I::Instruction],
    terminator: Option<I::Instruction>,
    shared: &SharedState<I>,
    start: Instant,
) where
    I: ISA + EnumerativeBackend<I>,
{
    all_instructions.par_iter().for_each(|instr| {
        if shared.stop.load(Ordering::Relaxed) {
            return;
        }
        if EnumerativeSearch::<I>::timed_out(start, config.timeout) {
            shared.stop.store(true, Ordering::Relaxed);
            return;
        }
        evaluate_candidate::<I>(
            target,
            live_out,
            config,
            vec![*instr],
            terminator,
            shared,
            start,
        );
    });
}

fn run_length_two<I>(
    target: &[I::Instruction],
    live_out: &<I as EnumerativeBackend<I>>::LiveOut,
    config: &SearchConfig,
    all_instructions: &[I::Instruction],
    terminator: Option<I::Instruction>,
    shared: &SharedState<I>,
    start: Instant,
) where
    I: ISA + EnumerativeBackend<I>,
{
    // Parallelise only over the outer `instr1` loop; the inner loop runs
    // sequentially per worker so we don't oversubscribe rayon with O(pool²)
    // tasks and so cost-pruning observes monotonic best-cost updates locally.
    all_instructions.par_iter().for_each(|instr1| {
        if shared.stop.load(Ordering::Relaxed) {
            return;
        }
        // Let idle workers stop before claiming a new outer-loop item.
        if EnumerativeSearch::<I>::timed_out(start, config.timeout) {
            shared.stop.store(true, Ordering::Relaxed);
            return;
        }
        for instr2 in all_instructions {
            if shared.stop.load(Ordering::Relaxed) {
                return;
            }
            if EnumerativeSearch::<I>::timed_out(start, config.timeout) {
                shared.stop.store(true, Ordering::Relaxed);
                return;
            }
            evaluate_candidate::<I>(
                target,
                live_out,
                config,
                vec![*instr1, *instr2],
                terminator,
                shared,
                start,
            );
        }
    });
}

struct ProductContext<'a, I>
where
    I: ISA + EnumerativeBackend<I>,
{
    length: usize,
    target: &'a [I::Instruction],
    live_out: &'a <I as EnumerativeBackend<I>>::LiveOut,
    config: &'a SearchConfig,
    all_instructions: &'a [I::Instruction],
    terminator: Option<I::Instruction>,
    shared: &'a SharedState<I>,
    start: Instant,
}

impl<I> ProductContext<'_, I>
where
    I: ISA + EnumerativeBackend<I>,
{
    fn stop_if_timed_out(&self) -> bool {
        if self.shared.stop.load(Ordering::Relaxed) {
            return true;
        }
        if EnumerativeSearch::<I>::timed_out(self.start, self.config.timeout) {
            self.shared.stop.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }

    fn enumerate_suffix(&self, candidate: &mut Vec<I::Instruction>) {
        if self.stop_if_timed_out() {
            return;
        }

        if candidate.len() == self.length {
            evaluate_candidate::<I>(
                self.target,
                self.live_out,
                self.config,
                candidate.clone(),
                self.terminator,
                self.shared,
                self.start,
            );
            return;
        }

        for instr in self.all_instructions {
            if self.stop_if_timed_out() {
                return;
            }
            candidate.push(*instr);
            self.enumerate_suffix(candidate);
            candidate.pop();
        }
    }
}

fn run_length_product<I>(context: ProductContext<'_, I>)
where
    I: ISA + EnumerativeBackend<I>,
{
    if context.length == 0 {
        return;
    }

    context.all_instructions.par_iter().for_each(|instr| {
        if context.stop_if_timed_out() {
            return;
        }

        let mut candidate =
            Vec::with_capacity(context.length + usize::from(context.terminator.is_some()));
        candidate.push(*instr);
        context.enumerate_suffix(&mut candidate);
    });
}

impl<I: ISA> Default for EnumerativeSearch<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> SearchAlgorithm<I> for EnumerativeSearch<I>
where
    I: ISA + EnumerativeBackend<I>,
{
    type LiveOut = <I as EnumerativeBackend<I>>::LiveOut;
    type Result = SearchResultFor<I>;

    fn search(
        &mut self,
        target: &[I::Instruction],
        live_out: &Self::LiveOut,
        config: &SearchConfig,
    ) -> Self::Result {
        self.reset();
        let start = Instant::now();

        let original_cost = <I as EnumerativeBackend<I>>::sequence_cost(target, config);
        self.statistics.original_cost = original_cost;
        self.statistics.best_cost_found = original_cost;

        if target.len() < 2 {
            self.statistics.elapsed_time = start.elapsed();
            return SearchResultFor::no_optimization(target.to_vec(), self.statistics.clone());
        }

        // Own the cached candidate pool so the borrow on `self` is released
        // before `cached_private_pool` takes `&mut self` below. The cache still
        // avoids the expensive `enumerate_all`; only a cheap Vec copy remains.
        let all_instructions_owned = self.candidate_pool_for_config(config).to_vec();
        let all_instructions: &[I::Instruction] = &all_instructions_owned;
        let terminator = <I as EnumerativeBackend<I>>::target_terminator(target);
        let shared = SharedState::new(original_cost);
        let min_instruction_cost =
            minimum_generated_instruction_cost::<I>(config, all_instructions);
        let terminator_cost = terminator
            .map(|t| <I as EnumerativeBackend<I>>::sequence_cost(&[t], config))
            .unwrap_or(0);

        let run_lengths = |s: &SharedState<I>| {
            // Search increasing lengths up to target.len()-1 so we never
            // propose a candidate as long as the target. The per-length cost
            // lower bound is non-decreasing in length (for the additive metrics
            // it grows with length; for the critical-path `Latency` metric it is
            // constant — still non-decreasing) and `best_cost` only falls, so
            // once a length cannot beat the current best no longer length can
            // either — break out instead of scanning the rest.
            for length in 1..target.len() {
                if Self::timed_out(start, config.timeout) || s.stop.load(Ordering::Relaxed) {
                    break;
                }
                let Some(min_instruction_cost) = min_instruction_cost else {
                    break;
                };
                let lower_bound = length_cost_lower_bound(
                    &config.cost_metric,
                    length,
                    min_instruction_cost,
                    terminator_cost,
                );
                if lower_bound >= s.best_cost.load(Ordering::Acquire) {
                    break;
                }
                match length {
                    1 => run_length_one::<I>(
                        target,
                        live_out,
                        config,
                        all_instructions,
                        terminator,
                        s,
                        start,
                    ),
                    2 => run_length_two::<I>(
                        target,
                        live_out,
                        config,
                        all_instructions,
                        terminator,
                        s,
                        start,
                    ),
                    _ => run_length_product::<I>(ProductContext {
                        length,
                        target,
                        live_out,
                        config,
                        all_instructions,
                        terminator,
                        shared: s,
                        start,
                    }),
                }
            }
        };

        match config.cores {
            // Any explicit thread count — including 1 — gets a private pool
            // sized to that count. The `Some(1)` case in particular must
            // *not* fall through to the global rayon pool, or the user's
            // request for 1 thread would silently run on every logical core.
            Some(n) => match self.cached_private_pool(n.max(1)) {
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
        self.statistics.candidates_pruned_by_cost =
            shared.candidates_pruned_by_cost.load(Ordering::Relaxed);
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
                self.statistics.best_cost_found =
                    <I as EnumerativeBackend<I>>::sequence_cost(&seq, config);
                SearchResultFor::with_optimization(target.to_vec(), seq, self.statistics.clone())
            }
            None => SearchResultFor::no_optimization(target.to_vec(), self.statistics.clone()),
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
    use std::fmt;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Mutex as TestMutex, MutexGuard};

    use crate::ir::{Instruction, Operand, Register};
    use crate::isa::{ISA, ISAMutator, InstructionType, OperandType, RegisterType, U64};

    std::thread_local! {
        static LENGTH_TWO_COST_CALLS: std::cell::Cell<u64> =
            const { std::cell::Cell::new(0) };
    }

    fn reset_length_two_cost_calls() {
        LENGTH_TWO_COST_CALLS.with(|calls| calls.set(0));
    }

    fn increment_length_two_cost_calls() {
        LENGTH_TWO_COST_CALLS.with(|calls| calls.set(calls.get() + 1));
    }

    fn length_two_cost_calls() -> u64 {
        LENGTH_TWO_COST_CALLS.with(|calls| calls.get())
    }

    impl EnumerativeBackend<crate::isa::RiscV64> for crate::isa::RiscV64 {
        type LiveOut = ();

        fn registers_from_config(_config: &SearchConfig) -> Vec<crate::isa::riscv::RiscVRegister> {
            Vec::new()
        }

        fn immediates_from_config(_config: &SearchConfig) -> Vec<i64> {
            Vec::new()
        }

        fn enumerate_all(
            _regs: &[crate::isa::riscv::RiscVRegister],
            _imms: &[i64],
        ) -> Vec<crate::isa::riscv::RiscVInstruction> {
            Vec::new()
        }

        fn sequence_cost(
            _seq: &[crate::isa::riscv::RiscVInstruction],
            _config: &SearchConfig,
        ) -> u64 {
            increment_length_two_cost_calls();
            std::thread::sleep(std::time::Duration::from_millis(10));
            1
        }

        fn check_equivalence(
            _target: &[crate::isa::riscv::RiscVInstruction],
            _candidate: &[crate::isa::riscv::RiscVInstruction],
            _live_out: &Self::LiveOut,
            _smt_timeout: Duration,
        ) -> (EquivalenceResult, EquivalenceMetrics) {
            panic!("cost-pruned timeout regression must not verify candidates")
        }
    }

    #[test]
    fn length_two_cost_counter_is_thread_local() {
        use crate::isa::RiscV64;

        let config = SearchConfig::default();
        reset_length_two_cost_calls();

        std::thread::spawn(move || {
            <RiscV64 as EnumerativeBackend<RiscV64>>::sequence_cost(&[], &config);
        })
        .join()
        .expect("cost counter probe thread should finish");

        assert_eq!(
            length_two_cost_calls(),
            0,
            "cost calls from another test thread must not affect this test thread"
        );
    }

    static CACHE_PROBE_TEST_LOCK: TestMutex<()> = TestMutex::new(());
    static CACHE_PROBE_ENUMERATE_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn reset_cache_probe_counter() -> MutexGuard<'static, ()> {
        let guard = CACHE_PROBE_TEST_LOCK
            .lock()
            .expect("cache probe test lock poisoned");
        CACHE_PROBE_ENUMERATE_CALLS.store(0, AtomicOrdering::SeqCst);
        guard
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct CacheProbeRegister(u8);

    impl fmt::Display for CacheProbeRegister {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "r{}", self.0)
        }
    }

    impl RegisterType for CacheProbeRegister {
        fn index(&self) -> Option<u8> {
            Some(self.0)
        }

        fn from_index(idx: u8) -> Option<Self> {
            Some(Self(idx))
        }

        fn is_zero_register(&self) -> bool {
            false
        }

        fn is_special(&self) -> bool {
            false
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum CacheProbeOperand {
        Reg(CacheProbeRegister),
        Imm(i64),
    }

    impl fmt::Display for CacheProbeOperand {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Reg(reg) => write!(f, "{reg}"),
                Self::Imm(imm) => write!(f, "#{imm}"),
            }
        }
    }

    impl OperandType for CacheProbeOperand {
        type Register = CacheProbeRegister;

        fn as_register(&self) -> Option<Self::Register> {
            match self {
                Self::Reg(reg) => Some(*reg),
                Self::Imm(_) => None,
            }
        }

        fn as_immediate(&self) -> Option<i64> {
            match self {
                Self::Reg(_) => None,
                Self::Imm(imm) => Some(*imm),
            }
        }

        fn from_register(reg: Self::Register) -> Self {
            Self::Reg(reg)
        }

        fn from_immediate(imm: i64) -> Self {
            Self::Imm(imm)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct CacheProbeInstruction(u8);

    impl fmt::Display for CacheProbeInstruction {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "probe{}", self.0)
        }
    }

    impl InstructionType for CacheProbeInstruction {
        type Register = CacheProbeRegister;
        type Operand = CacheProbeOperand;

        fn destination(&self) -> Option<Self::Register> {
            None
        }

        fn source_registers(&self) -> Vec<Self::Register> {
            Vec::new()
        }

        fn opcode_id(&self) -> u8 {
            self.0
        }

        fn mnemonic(&self) -> &'static str {
            "probe"
        }
    }

    struct CacheProbeMutator;

    impl ISAMutator<CacheProbeInstruction> for CacheProbeMutator {
        fn mutate<R: rand::RngExt>(
            &self,
            _rng: &mut R,
            sequence: &[CacheProbeInstruction],
        ) -> Vec<CacheProbeInstruction> {
            sequence.to_vec()
        }
    }

    #[derive(Clone)]
    struct CacheProbeIsa;

    impl ISA for CacheProbeIsa {
        type Register = CacheProbeRegister;
        type Operand = CacheProbeOperand;
        type Instruction = CacheProbeInstruction;
        type Width = U64;
        type Flags = ();
        type Mutator = CacheProbeMutator;

        fn name(&self) -> &'static str {
            "CacheProbe"
        }

        fn register_count(&self) -> usize {
            1
        }

        fn instruction_size(&self) -> Option<usize> {
            Some(1)
        }

        fn general_registers(&self) -> Vec<Self::Register> {
            vec![CacheProbeRegister(0)]
        }

        fn zero_register(&self) -> Option<Self::Register> {
            None
        }
    }

    impl EnumerativeBackend<CacheProbeIsa> for CacheProbeIsa {
        type LiveOut = ();

        fn registers_from_config(_config: &SearchConfig) -> Vec<CacheProbeRegister> {
            vec![CacheProbeRegister(0)]
        }

        fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
            config.available_immediates.clone()
        }

        fn enumerate_all(
            _regs: &[CacheProbeRegister],
            _imms: &[i64],
        ) -> Vec<CacheProbeInstruction> {
            CACHE_PROBE_ENUMERATE_CALLS.fetch_add(1, AtomicOrdering::SeqCst);
            vec![CacheProbeInstruction(0)]
        }

        fn sequence_cost(seq: &[CacheProbeInstruction], _config: &SearchConfig) -> u64 {
            seq.len() as u64
        }

        fn check_equivalence(
            _target: &[CacheProbeInstruction],
            _candidate: &[CacheProbeInstruction],
            _live_out: &Self::LiveOut,
            _smt_timeout: Duration,
        ) -> (EquivalenceResult, EquivalenceMetrics) {
            (
                EquivalenceResult::NotEquivalent,
                EquivalenceMetrics::default(),
            )
        }
    }

    fn cache_probe_config(immediates: Vec<i64>) -> SearchConfig {
        SearchConfig::default()
            .with_immediates(immediates)
            .with_timeout_option(None)
    }

    fn cache_probe_target() -> Vec<CacheProbeInstruction> {
        vec![CacheProbeInstruction(1), CacheProbeInstruction(2)]
    }

    #[test]
    fn reuses_candidate_pool_across_same_config_search_calls() {
        let _guard = reset_cache_probe_counter();
        let config = cache_probe_config(vec![0]);
        let target = cache_probe_target();
        let mut search = EnumerativeSearch::<CacheProbeIsa>::new();

        let _ = search.search(&target, &(), &config);
        let _ = search.search(&target, &(), &config);

        assert_eq!(
            CACHE_PROBE_ENUMERATE_CALLS.load(AtomicOrdering::SeqCst),
            1,
            "candidate pool should be generated once for repeated same-config searches"
        );
    }

    #[test]
    fn with_config_pre_generates_candidate_pool() {
        let _guard = reset_cache_probe_counter();
        let config = cache_probe_config(vec![0]);
        let target = cache_probe_target();

        let mut search = EnumerativeSearch::<CacheProbeIsa>::with_config(&config);

        assert_eq!(
            CACHE_PROBE_ENUMERATE_CALLS.load(AtomicOrdering::SeqCst),
            1,
            "with_config should eagerly generate the candidate pool"
        );

        let _ = search.search(&target, &(), &config);

        assert_eq!(
            CACHE_PROBE_ENUMERATE_CALLS.load(AtomicOrdering::SeqCst),
            1,
            "same-config search should reuse the eagerly generated pool"
        );
    }

    #[test]
    fn regenerates_candidate_pool_when_effective_immediates_change() {
        let _guard = reset_cache_probe_counter();
        let target = cache_probe_target();
        let mut search = EnumerativeSearch::<CacheProbeIsa>::new();

        let _ = search.search(&target, &(), &cache_probe_config(vec![0, 1]));
        let _ = search.search(&target, &(), &cache_probe_config(vec![1, 0]));

        assert_eq!(
            CACHE_PROBE_ENUMERATE_CALLS.load(AtomicOrdering::SeqCst),
            2,
            "candidate pool should regenerate when the ordered effective immediate pool changes"
        );
    }

    #[test]
    fn regenerates_candidate_pool_when_registers_change() {
        // Covers the register branch of the invalidation condition. The mock
        // ISA's register set is constant, so this exercises it on AArch64,
        // where registers_from_config varies with the config. Re-querying the
        // same warmed search with a larger register pool must regenerate; a
        // stale pool (register change ignored) would compare equal.
        let one_reg = SearchConfig::default()
            .with_registers(vec![Register::X0])
            .with_immediates(vec![0, 1])
            .with_timeout_option(None);
        let two_regs = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1])
            .with_timeout_option(None);

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
        let pool_one = search.candidate_pool_for_config(&one_reg).to_vec();
        let pool_two = search.candidate_pool_for_config(&two_regs).to_vec();

        assert_ne!(
            pool_one, pool_two,
            "changing the register pool must regenerate the candidate pool"
        );
        assert!(
            pool_two.len() > pool_one.len(),
            "a larger register pool should enumerate strictly more candidates"
        );
    }

    #[test]
    fn reset_preserves_candidate_pool() {
        let _guard = reset_cache_probe_counter();
        let config = cache_probe_config(vec![0]);
        let target = cache_probe_target();
        let mut search = EnumerativeSearch::<CacheProbeIsa>::new();

        let _ = search.search(&target, &(), &config);
        search.reset();
        let _ = search.search(&target, &(), &config);

        assert_eq!(
            CACHE_PROBE_ENUMERATE_CALLS.load(AtomicOrdering::SeqCst),
            1,
            "reset should clear statistics without clearing the candidate pool"
        );
    }

    #[test]
    fn empty_target_returns_no_optimization() {
        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
        let result = search.search(&[], &LiveOut::all_registers(), &SearchConfig::default());
        assert!(!result.found_optimization);
        assert!(result.optimized_sequence.is_none());
    }

    #[test]
    fn statistics_aggregate_smt_elapsed() {
        // Reuse the same length-2 target as `collapses_mov_add_into_single_add`:
        // it reaches the equivalent `add x0, x1, #1` candidate promptly while
        // still driving at least one SMT equivalence check. After the search
        // returns, the cumulative SMT wall time must be non-zero, and it must
        // be <= the overall search elapsed (sanity check on aggregation
        // correctness).
        //
        // `cores = Some(1)` is required for the upper-bound assertion: the
        // global rayon pool would let multiple worker threads each spend
        // wall-clock time inside `solver.check()` in parallel, and the
        // shared atomic accumulator sums those per-thread durations —
        // making the cumulative `smt_elapsed` exceed total wall-clock
        // `elapsed_time` on a multicore runner. Pinning to one thread
        // restores the `smt_elapsed <= elapsed_time` invariant.
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

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
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

    #[derive(Clone)]
    struct VerifyStatsIsa;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct VerifyStatsInstruction(u8);

    impl fmt::Display for VerifyStatsInstruction {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "verify{}", self.0)
        }
    }

    impl InstructionType for VerifyStatsInstruction {
        type Register = Register;
        type Operand = Operand;

        fn destination(&self) -> Option<Self::Register> {
            Some(Register::X0)
        }

        fn source_registers(&self) -> Vec<Self::Register> {
            Vec::new()
        }

        fn opcode_id(&self) -> u8 {
            self.0
        }

        fn mnemonic(&self) -> &'static str {
            "verify"
        }
    }

    struct VerifyStatsMutator;

    impl ISAMutator<VerifyStatsInstruction> for VerifyStatsMutator {
        fn mutate<R: rand::RngExt>(
            &self,
            _rng: &mut R,
            sequence: &[VerifyStatsInstruction],
        ) -> Vec<VerifyStatsInstruction> {
            sequence.to_vec()
        }
    }

    impl ISA for VerifyStatsIsa {
        type Register = Register;
        type Operand = Operand;
        type Instruction = VerifyStatsInstruction;
        type Width = U64;
        type Flags = ();
        type Mutator = VerifyStatsMutator;

        fn name(&self) -> &'static str {
            "VerifyStats"
        }

        fn register_count(&self) -> usize {
            1
        }

        fn instruction_size(&self) -> Option<usize> {
            Some(1)
        }

        fn general_registers(&self) -> Vec<Self::Register> {
            vec![Register::X0]
        }

        fn zero_register(&self) -> Option<Self::Register> {
            Some(Register::XZR)
        }
    }

    const VERIFY_STATS_NOT_EQUIVALENT: usize = 0;
    const VERIFY_STATS_EQUIVALENT: usize = 1;

    static VERIFY_STATS_TEST_LOCK: TestMutex<()> = TestMutex::new(());
    static VERIFY_STATS_CHECKS: AtomicUsize = AtomicUsize::new(0);
    static VERIFY_STATS_VERDICT: AtomicUsize = AtomicUsize::new(VERIFY_STATS_NOT_EQUIVALENT);
    static VERIFY_STATS_SMT_CALLED: AtomicBool = AtomicBool::new(false);
    static VERIFY_STATS_DRAIN_FIXTURE: AtomicBool = AtomicBool::new(false);

    fn set_verify_stats_result(verdict: usize, smt_called: bool) -> MutexGuard<'static, ()> {
        let guard = VERIFY_STATS_TEST_LOCK
            .lock()
            .expect("verify stats test lock poisoned");
        VERIFY_STATS_CHECKS.store(0, AtomicOrdering::SeqCst);
        VERIFY_STATS_VERDICT.store(verdict, AtomicOrdering::SeqCst);
        VERIFY_STATS_SMT_CALLED.store(smt_called, AtomicOrdering::SeqCst);
        VERIFY_STATS_DRAIN_FIXTURE.store(false, AtomicOrdering::SeqCst);
        guard
    }

    impl EnumerativeBackend<VerifyStatsIsa> for VerifyStatsIsa {
        type LiveOut = ();

        fn registers_from_config(_config: &SearchConfig) -> Vec<Register> {
            vec![Register::X0]
        }

        fn immediates_from_config(_config: &SearchConfig) -> Vec<i64> {
            vec![0]
        }

        fn enumerate_all(_regs: &[Register], _imms: &[i64]) -> Vec<VerifyStatsInstruction> {
            if VERIFY_STATS_DRAIN_FIXTURE.load(AtomicOrdering::SeqCst) {
                vec![VerifyStatsInstruction(0), VerifyStatsInstruction(1)]
            } else {
                vec![VerifyStatsInstruction(0)]
            }
        }

        fn sequence_cost(seq: &[VerifyStatsInstruction], _config: &SearchConfig) -> u64 {
            if VERIFY_STATS_DRAIN_FIXTURE.load(AtomicOrdering::SeqCst) {
                match seq {
                    // One candidate is cheap enough to verify; the other ties
                    // the original cost and should be counted, then pruned.
                    [VerifyStatsInstruction(0)] => 0,
                    [VerifyStatsInstruction(1)] => 1,
                    [VerifyStatsInstruction(1), VerifyStatsInstruction(2)] => 1,
                    _ => seq.len() as u64,
                }
            } else {
                seq.len() as u64
            }
        }

        fn check_equivalence(
            _target: &[VerifyStatsInstruction],
            _candidate: &[VerifyStatsInstruction],
            _live_out: &Self::LiveOut,
            _smt_timeout: Duration,
        ) -> (EquivalenceResult, EquivalenceMetrics) {
            VERIFY_STATS_CHECKS.fetch_add(1, AtomicOrdering::SeqCst);
            let metrics = EquivalenceMetrics {
                smt_called: VERIFY_STATS_SMT_CALLED.load(AtomicOrdering::SeqCst),
                ..EquivalenceMetrics::default()
            };
            match VERIFY_STATS_VERDICT.load(AtomicOrdering::SeqCst) {
                VERIFY_STATS_EQUIVALENT => (EquivalenceResult::Equivalent, metrics),
                _ => (EquivalenceResult::NotEquivalent, metrics),
            }
        }
    }

    fn verify_stats_candidate(
        verdict: usize,
        smt_called: bool,
    ) -> (bool, SharedState<VerifyStatsIsa>) {
        let _guard = set_verify_stats_result(verdict, smt_called);
        let target = [VerifyStatsInstruction(1)];
        let candidate = [VerifyStatsInstruction(2)];
        let config = SearchConfig::default().with_timeout_option(None);
        let shared = SharedState::<VerifyStatsIsa>::new(u64::MAX);

        let is_equivalent = verify_candidate::<VerifyStatsIsa>(
            &target,
            &candidate,
            &(),
            &config,
            &shared,
            Instant::now(),
        );

        (is_equivalent, shared)
    }

    #[test]
    fn enumerative_verify_counts_smt_counterexample_as_fast_pass() {
        let (is_equivalent, shared) = verify_stats_candidate(VERIFY_STATS_NOT_EQUIVALENT, true);

        assert!(!is_equivalent);
        assert_eq!(shared.smt_queries.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidates_passed_fast.load(Ordering::Relaxed), 1);
        assert_eq!(shared.smt_equivalent.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn enumerative_verify_counts_smt_equivalence_as_fast_pass_and_equivalent() {
        let (is_equivalent, shared) = verify_stats_candidate(VERIFY_STATS_EQUIVALENT, true);

        assert!(is_equivalent);
        assert_eq!(shared.smt_queries.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidates_passed_fast.load(Ordering::Relaxed), 1);
        assert_eq!(shared.smt_equivalent.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn enumerative_verify_does_not_count_fast_refutation_as_fast_pass() {
        let (is_equivalent, shared) = verify_stats_candidate(VERIFY_STATS_NOT_EQUIVALENT, false);

        assert!(!is_equivalent);
        assert_eq!(shared.smt_queries.load(Ordering::Relaxed), 0);
        assert_eq!(shared.candidates_passed_fast.load(Ordering::Relaxed), 0);
        assert_eq!(shared.smt_equivalent.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn run_length_one_counts_cost_pruned_candidate() {
        let _guard = set_verify_stats_result(VERIFY_STATS_NOT_EQUIVALENT, true);
        let target = [VerifyStatsInstruction(1), VerifyStatsInstruction(2)];
        let all_instructions = [VerifyStatsInstruction(0)];
        let config = SearchConfig::default().with_timeout_option(None);
        let shared = SharedState::<VerifyStatsIsa>::new(0);

        run_length_one::<VerifyStatsIsa>(
            &target,
            &(),
            &config,
            &all_instructions,
            None,
            &shared,
            Instant::now(),
        );

        assert_eq!(shared.candidates_evaluated.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidates_pruned_by_cost.load(Ordering::Relaxed), 1);
        assert_eq!(VERIFY_STATS_CHECKS.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(shared.smt_queries.load(Ordering::Relaxed), 0);
        assert_eq!(shared.candidates_passed_fast.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn run_length_two_counts_cost_pruned_candidate() {
        let _guard = set_verify_stats_result(VERIFY_STATS_NOT_EQUIVALENT, true);
        let target = [
            VerifyStatsInstruction(1),
            VerifyStatsInstruction(2),
            VerifyStatsInstruction(3),
        ];
        let all_instructions = [VerifyStatsInstruction(0)];
        let config = SearchConfig::default().with_timeout_option(None);
        let shared = SharedState::<VerifyStatsIsa>::new(0);

        run_length_two::<VerifyStatsIsa>(
            &target,
            &(),
            &config,
            &all_instructions,
            None,
            &shared,
            Instant::now(),
        );

        assert_eq!(shared.candidates_evaluated.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidates_pruned_by_cost.load(Ordering::Relaxed), 1);
        assert_eq!(VERIFY_STATS_CHECKS.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(shared.smt_queries.load(Ordering::Relaxed), 0);
        assert_eq!(shared.candidates_passed_fast.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn search_drains_cost_pruned_candidate_count() {
        let _guard = set_verify_stats_result(VERIFY_STATS_NOT_EQUIVALENT, false);
        VERIFY_STATS_DRAIN_FIXTURE.store(true, AtomicOrdering::SeqCst);
        let target = vec![VerifyStatsInstruction(1), VerifyStatsInstruction(2)];
        let config = SearchConfig::default()
            .with_timeout_option(None)
            .with_cores(Some(1));

        let mut search = EnumerativeSearch::<VerifyStatsIsa>::new();
        let result = search.search(&target, &(), &config);

        assert_eq!(result.statistics.candidates_evaluated, 2);
        assert_eq!(result.statistics.candidates_pruned_by_cost, 1);
        assert_eq!(VERIFY_STATS_CHECKS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(result.statistics.smt_queries, 0);
        assert_eq!(result.statistics.candidates_passed_fast, 0);
    }

    fn small_config() -> SearchConfig {
        // Tight register/immediate pool so unit tests run fast.
        //
        // No wall-clock deadline: every search built on this config is a
        // bounded enumeration over a tiny pool that terminates on its own. A
        // finite timeout is nondeterministic under coverage instrumentation —
        // the slow instrumented suite can exceed it and spuriously report no
        // optimization (the x86 sibling tests use the same workaround).
        SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1])
            .with_timeout_option(None)
    }

    #[derive(Clone)]
    struct InnerTimeoutIsa;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct InnerTimeoutInstruction(u8);

    impl std::fmt::Display for InnerTimeoutInstruction {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "probe{}", self.0)
        }
    }

    impl InstructionType for InnerTimeoutInstruction {
        type Register = Register;
        type Operand = Operand;

        fn destination(&self) -> Option<Self::Register> {
            Some(Register::X0)
        }

        fn source_registers(&self) -> Vec<Self::Register> {
            Vec::new()
        }

        fn opcode_id(&self) -> u8 {
            self.0
        }

        fn mnemonic(&self) -> &'static str {
            "probe"
        }
    }

    struct InnerTimeoutMutator;

    impl ISAMutator<InnerTimeoutInstruction> for InnerTimeoutMutator {
        fn mutate<R: rand::RngExt>(
            &self,
            _rng: &mut R,
            sequence: &[InnerTimeoutInstruction],
        ) -> Vec<InnerTimeoutInstruction> {
            sequence.to_vec()
        }
    }

    impl ISA for InnerTimeoutIsa {
        type Register = Register;
        type Operand = Operand;
        type Instruction = InnerTimeoutInstruction;
        type Width = U64;
        type Flags = ();
        type Mutator = InnerTimeoutMutator;

        fn name(&self) -> &'static str {
            "InnerTimeout"
        }

        fn register_count(&self) -> usize {
            1
        }

        fn instruction_size(&self) -> Option<usize> {
            Some(1)
        }

        fn general_registers(&self) -> Vec<Self::Register> {
            vec![Register::X0]
        }

        fn zero_register(&self) -> Option<Self::Register> {
            Some(Register::XZR)
        }
    }

    static INNER_TIMEOUT_TEST_LOCK: TestMutex<()> = TestMutex::new(());
    static INNER_TIMEOUT_COST_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn reset_inner_timeout_counter() -> MutexGuard<'static, ()> {
        let guard = INNER_TIMEOUT_TEST_LOCK
            .lock()
            .expect("inner timeout test lock poisoned");
        INNER_TIMEOUT_COST_CALLS.store(0, Ordering::Relaxed);
        guard
    }

    impl EnumerativeBackend<InnerTimeoutIsa> for InnerTimeoutIsa {
        type LiveOut = ();

        fn registers_from_config(_config: &SearchConfig) -> Vec<Register> {
            vec![Register::X0]
        }

        fn immediates_from_config(_config: &SearchConfig) -> Vec<i64> {
            vec![0]
        }

        fn enumerate_all(_regs: &[Register], _imms: &[i64]) -> Vec<InnerTimeoutInstruction> {
            vec![InnerTimeoutInstruction(0), InnerTimeoutInstruction(1)]
        }

        fn sequence_cost(_seq: &[InnerTimeoutInstruction], _config: &SearchConfig) -> u64 {
            INNER_TIMEOUT_COST_CALLS.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(std::time::Duration::from_millis(50));
            1
        }

        fn check_equivalence(
            _target: &[InnerTimeoutInstruction],
            _candidate: &[InnerTimeoutInstruction],
            _live_out: &Self::LiveOut,
            _smt_timeout: Duration,
        ) -> (EquivalenceResult, EquivalenceMetrics) {
            panic!("cost pruning should prevent equivalence checks")
        }
    }

    #[test]
    fn run_length_two_sets_stop_when_inner_deadline_expires() {
        let _guard = reset_inner_timeout_counter();

        let config = SearchConfig::default().with_timeout(std::time::Duration::from_millis(25));
        let target = vec![InnerTimeoutInstruction(9), InnerTimeoutInstruction(8)];
        let all_instructions =
            <InnerTimeoutIsa as EnumerativeBackend<InnerTimeoutIsa>>::enumerate_all(&[], &[]);
        // Positive candidate costs prune before equivalence, isolating timeout behavior.
        let shared = SharedState::<InnerTimeoutIsa>::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("private rayon pool should build");

        pool.install(|| {
            let start = Instant::now();
            run_length_two::<InnerTimeoutIsa>(
                &target,
                &(),
                &config,
                &all_instructions,
                None,
                &shared,
                start,
            );
        });

        assert!(
            shared.stop.load(Ordering::Relaxed),
            "inner loop should set stop after the timeout expires"
        );
        assert_eq!(
            INNER_TIMEOUT_COST_CALLS.load(Ordering::Relaxed),
            1,
            "timeout should be checked before evaluating the second inner candidate"
        );
    }

    #[test]
    fn run_length_product_sets_stop_when_nested_deadline_expires() {
        let _guard = reset_inner_timeout_counter();

        let config = SearchConfig::default().with_timeout(std::time::Duration::from_millis(25));
        let target = vec![
            InnerTimeoutInstruction(9),
            InnerTimeoutInstruction(8),
            InnerTimeoutInstruction(7),
            InnerTimeoutInstruction(6),
        ];
        let all_instructions =
            <InnerTimeoutIsa as EnumerativeBackend<InnerTimeoutIsa>>::enumerate_all(&[], &[]);
        // Positive candidate costs prune before equivalence, isolating timeout behavior.
        let shared = SharedState::<InnerTimeoutIsa>::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("private rayon pool should build");

        pool.install(|| {
            let start = Instant::now();
            run_length_product::<InnerTimeoutIsa>(ProductContext {
                length: 3,
                target: &target,
                live_out: &(),
                config: &config,
                all_instructions: &all_instructions,
                terminator: None,
                shared: &shared,
                start,
            });
        });

        let cost_calls = INNER_TIMEOUT_COST_CALLS.load(Ordering::Relaxed);
        assert!(
            shared.stop.load(Ordering::Relaxed),
            "nested product loop should set stop after the timeout expires"
        );
        assert!(
            cost_calls < 8,
            "timeout should stop before the full length-three product sweep; saw {cost_calls} cost calls"
        );
    }

    fn mov_add_target() -> (Vec<Instruction>, LiveOut) {
        (
            vec![
                Instruction::MovReg {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X0,
                    rm: Operand::Immediate(1),
                },
            ],
            LiveOut::from_registers(vec![Register::X0]),
        )
    }

    #[test]
    fn verify_candidate_stops_without_smt_when_search_budget_is_exhausted() {
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let candidate = target.clone();
        let live_out = LiveOut::from_registers(vec![Register::X0]);
        let config = SearchConfig::default().with_timeout(std::time::Duration::from_millis(1));
        let shared = SharedState::<AArch64>::new(u64::MAX);
        // Exactly 1ms elapsed under a 1ms search timeout leaves ZERO
        // remaining; `as_millis() == 0` then disables the candidate SMT call.
        let expired_start = std::time::Instant::now() - std::time::Duration::from_millis(1);

        assert!(!verify_candidate::<AArch64>(
            &target,
            &candidate,
            &live_out,
            &config,
            &shared,
            expired_start,
        ));
        assert!(shared.stop.load(Ordering::Relaxed));
        assert_eq!(shared.smt_queries.load(Ordering::Relaxed), 0);
        assert_eq!(shared.smt_elapsed_nanos.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn verify_candidate_does_not_count_pre_smt_guard_as_smt() {
        let target = vec![Instruction::Cmp {
            rn: Register::X0,
            rm: Operand::Immediate(0),
        }];
        let candidate = vec![Instruction::MovImm {
            rd: Register::X1,
            imm: 7,
        }];
        let live_out = LiveOut::from_registers(vec![]).with_flags(true);
        let config = SearchConfig::default().with_timeout_option(None);
        let shared = SharedState::<AArch64>::new(u64::MAX);

        assert!(!verify_candidate::<AArch64>(
            &target,
            &candidate,
            &live_out,
            &config,
            &shared,
            std::time::Instant::now(),
        ));
        assert_eq!(shared.smt_queries.load(Ordering::Relaxed), 0);
        assert_eq!(shared.candidates_passed_fast.load(Ordering::Relaxed), 0);
        assert_eq!(shared.smt_elapsed_nanos.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn verify_candidate_counts_smt_refutation_as_fast_pass() {
        let target = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];
        let candidate = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];
        let live_out = LiveOut::from_registers(vec![Register::X0]);
        let config = SearchConfig::default().with_timeout_option(None);
        let shared = SharedState::<AArch64>::new(u64::MAX);

        assert!(!verify_candidate::<AArch64>(
            &target,
            &candidate,
            &live_out,
            &config,
            &shared,
            std::time::Instant::now(),
        ));
        assert_eq!(shared.smt_queries.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidates_passed_fast.load(Ordering::Relaxed), 1);
        assert_eq!(shared.smt_equivalent.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn verify_candidate_counts_smt_equivalence() {
        // Commutativity: `add x0, x1, x2` == `add x0, x2, x1`. The candidate
        // passes fast concrete validation and Z3 then proves equivalence, so
        // the success path must record one SMT query, one fast pass, and one
        // equivalence.
        let target = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        let candidate = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X2,
            rm: Operand::Register(Register::X1),
        }];
        let live_out = LiveOut::from_registers(vec![Register::X0]);
        let config = SearchConfig::default().with_timeout_option(None);
        let shared = SharedState::<AArch64>::new(u64::MAX);

        assert!(verify_candidate::<AArch64>(
            &target,
            &candidate,
            &live_out,
            &config,
            &shared,
            std::time::Instant::now(),
        ));
        assert_eq!(shared.smt_queries.load(Ordering::Relaxed), 1);
        assert_eq!(shared.candidates_passed_fast.load(Ordering::Relaxed), 1);
        assert_eq!(shared.smt_equivalent.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn length_two_search_honors_timeout_inside_inner_loop() {
        use crate::isa::{RiscV64, RiscVInstruction, RiscVRegister};

        let instr = RiscVInstruction::Addi {
            rd: RiscVRegister::X1,
            rs1: RiscVRegister::X1,
            imm: 1,
        };
        let all_instructions = vec![instr; 6];
        let target = vec![instr; 3];
        let live_out = ();
        let config = SearchConfig::default().with_timeout(std::time::Duration::from_millis(5));
        let shared = SharedState::<RiscV64>::new(0);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("private rayon pool");
        let cost_calls = pool.install(|| {
            reset_length_two_cost_calls();
            let start = std::time::Instant::now();
            run_length_two::<RiscV64>(
                &target,
                &live_out,
                &config,
                &all_instructions,
                None,
                &shared,
                start,
            );
            length_two_cost_calls()
        });

        assert!(
            shared.stop.load(Ordering::Relaxed),
            "timeout should set shared stop inside the inner length-two loop"
        );
        assert!(
            cost_calls > 0,
            "expected to observe cost calls from the worker running length-two search"
        );
        assert!(
            cost_calls < all_instructions.len() as u64,
            "expected timeout before a full inner sweep; saw {cost_calls} cost calls for {} instructions",
            all_instructions.len()
        );
    }

    #[test]
    fn aarch64_backend_honors_flags_dead_live_out_mask() {
        let target = vec![
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Immediate(0),
            },
            Instruction::MovImm {
                rd: Register::X1,
                imm: 7,
            },
        ];
        let candidate = vec![Instruction::MovImm {
            rd: Register::X1,
            imm: 7,
        }];
        let live_out = LiveOut::from_registers(vec![Register::X1]);

        let result = <AArch64 as EnumerativeBackend<AArch64>>::check_equivalence(
            &target,
            &candidate,
            &live_out,
            SearchConfig::default().solver_timeout(),
        );

        assert_eq!(result.0, EquivalenceResult::Equivalent);

        let flags_live_result = <AArch64 as EnumerativeBackend<AArch64>>::check_equivalence(
            &target,
            &candidate,
            &live_out.with_flags(true),
            SearchConfig::default().solver_timeout(),
        );

        assert_ne!(flags_live_result.0, EquivalenceResult::Equivalent);
    }

    #[test]
    fn single_instruction_target_returns_no_optimization() {
        // Length-1 cannot be shortened (search range is 1..target.len() = 1..1 = empty).
        let target = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];
        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
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
        // minimal configured pool still contains the length-2 witness
        // `mov x0, #0; mov x2, #0`, keeping this as an enabled regression for the
        // real AArch64 length-2 enumerative path without the broader pool's CI
        // runtime ceiling.
        let target = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Register(Register::X0),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Eor {
                rd: Register::X2,
                rn: Register::X2,
                rm: Operand::Register(Register::X2),
                width: crate::ir::RegisterWidth::X64,
            },
        ];
        let live_out = LiveOut::from_registers(vec![Register::X0, Register::X2]);

        let config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X2])
            .with_immediates(vec![0])
            .with_cores(Some(1))
            .with_solver_timeout(std::time::Duration::from_millis(250))
            .with_timeout(std::time::Duration::from_secs(10));

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
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

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
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

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
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

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
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
    fn explicit_cores_cache_private_pool_across_search_calls() {
        let (target, live_out) = mov_add_target();
        let config = small_config().with_cores(Some(2));

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
        let first = search.search(&target, &live_out, &config);

        assert!(
            first.found_optimization,
            "first search should find the rewrite"
        );
        assert_eq!(first.optimized_sequence.as_ref().map(Vec::len), Some(1));
        assert_eq!(search.private_pool_build_count(), 1);

        let second = search.search(&target, &live_out, &config);

        assert!(
            second.found_optimization,
            "second search should still find the rewrite"
        );
        assert_eq!(second.optimized_sequence.as_ref().map(Vec::len), Some(1));
        assert_eq!(
            search.private_pool_build_count(),
            1,
            "same explicit core count should reuse the cached pool"
        );
    }

    #[test]
    fn explicit_cores_rebuild_private_pool_when_effective_core_count_changes() {
        let (target, live_out) = mov_add_target();

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
        let one_thread = search.search(&target, &live_out, &small_config().with_cores(Some(1)));

        assert!(
            one_thread.found_optimization,
            "single-thread private pool should find the rewrite"
        );
        assert_eq!(search.private_pool_effective_cores(), Some(1));
        assert_eq!(search.private_pool_build_count(), 1);

        let zero_threads = search.search(&target, &live_out, &small_config().with_cores(Some(0)));

        assert!(
            zero_threads.found_optimization,
            "zero-thread request should be coerced to one worker and find the rewrite"
        );
        assert_eq!(search.private_pool_effective_cores(), Some(1));
        assert_eq!(
            search.private_pool_build_count(),
            1,
            "Some(0) and Some(1) have the same effective core count"
        );

        let two_threads = search.search(&target, &live_out, &small_config().with_cores(Some(2)));

        assert!(
            two_threads.found_optimization,
            "new private pool should still find the rewrite"
        );
        assert_eq!(search.private_pool_effective_cores(), Some(2));
        assert_eq!(
            search.private_pool_build_count(),
            2,
            "different effective core count should rebuild exactly once"
        );
    }

    #[test]
    fn cores_none_uses_global_pool_without_clearing_cached_private_pool() {
        let (target, live_out) = mov_add_target();

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
        let private_pool_result =
            search.search(&target, &live_out, &small_config().with_cores(Some(1)));

        assert!(
            private_pool_result.found_optimization,
            "private-pool precondition should find the rewrite"
        );
        assert_eq!(search.private_pool_effective_cores(), Some(1));
        assert_eq!(search.private_pool_build_count(), 1);

        let global_pool_result =
            search.search(&target, &live_out, &small_config().with_cores(None));

        assert!(
            global_pool_result.found_optimization,
            "global-pool search should still find the rewrite"
        );
        assert_eq!(
            search.private_pool_effective_cores(),
            Some(1),
            "global-pool search should not clear the cached private pool"
        );
        assert_eq!(
            search.private_pool_build_count(),
            1,
            "cores=None should not build another private pool"
        );
    }

    #[test]
    fn length_four_target_with_length_one_rewrite_returns_promptly() {
        // This target intentionally has a length-1 equivalent (`add x0, x1,
        // #1`). Once that best cost is found, longer lengths cannot strictly
        // improve under the configured cost model, so the length-level lower
        // bound should skip the expensive length-3 product sweep.
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

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
        let result = search.search(&target, &live_out, &small_config());

        assert!(result.statistics.elapsed_time > std::time::Duration::ZERO);
        assert!(result.found_optimization, "length-1 collapse should fire");
        assert_eq!(result.optimized_sequence.as_ref().map(Vec::len), Some(1));
    }

    #[derive(Clone)]
    struct LengthThreeProbeIsa;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct LengthThreeProbeInstruction(u8);

    impl std::fmt::Display for LengthThreeProbeInstruction {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "probe{}", self.0)
        }
    }

    impl InstructionType for LengthThreeProbeInstruction {
        type Register = Register;
        type Operand = Operand;

        fn destination(&self) -> Option<Self::Register> {
            None
        }

        fn source_registers(&self) -> Vec<Self::Register> {
            Vec::new()
        }

        fn opcode_id(&self) -> u8 {
            self.0
        }

        fn mnemonic(&self) -> &'static str {
            "probe"
        }
    }

    struct LengthThreeProbeMutator;

    impl ISAMutator<LengthThreeProbeInstruction> for LengthThreeProbeMutator {
        fn mutate<R: rand::RngExt>(
            &self,
            _rng: &mut R,
            sequence: &[LengthThreeProbeInstruction],
        ) -> Vec<LengthThreeProbeInstruction> {
            sequence.to_vec()
        }
    }

    impl ISA for LengthThreeProbeIsa {
        type Register = Register;
        type Operand = Operand;
        type Instruction = LengthThreeProbeInstruction;
        type Width = U64;
        type Flags = ();
        type Mutator = LengthThreeProbeMutator;

        fn name(&self) -> &'static str {
            "LengthThreeProbe"
        }

        fn register_count(&self) -> usize {
            1
        }

        fn instruction_size(&self) -> Option<usize> {
            Some(1)
        }

        fn general_registers(&self) -> Vec<Self::Register> {
            vec![Register::X0]
        }

        fn zero_register(&self) -> Option<Self::Register> {
            Some(Register::XZR)
        }
    }

    impl EnumerativeBackend<LengthThreeProbeIsa> for LengthThreeProbeIsa {
        type LiveOut = ();

        fn registers_from_config(_config: &SearchConfig) -> Vec<Register> {
            vec![Register::X0]
        }

        fn immediates_from_config(_config: &SearchConfig) -> Vec<i64> {
            vec![0]
        }

        fn enumerate_all(_regs: &[Register], _imms: &[i64]) -> Vec<LengthThreeProbeInstruction> {
            vec![
                LengthThreeProbeInstruction(1),
                LengthThreeProbeInstruction(2),
                LengthThreeProbeInstruction(3),
            ]
        }

        fn sequence_cost(seq: &[LengthThreeProbeInstruction], _config: &SearchConfig) -> u64 {
            seq.len() as u64
        }

        fn check_equivalence(
            _target: &[LengthThreeProbeInstruction],
            candidate: &[LengthThreeProbeInstruction],
            _live_out: &Self::LiveOut,
            _smt_timeout: Duration,
        ) -> (EquivalenceResult, EquivalenceMetrics) {
            let expected = [
                LengthThreeProbeInstruction(1),
                LengthThreeProbeInstruction(2),
                LengthThreeProbeInstruction(3),
            ];
            let verdict = if candidate == expected {
                EquivalenceResult::Equivalent
            } else {
                EquivalenceResult::NotEquivalent
            };

            (verdict, EquivalenceMetrics::default())
        }
    }

    #[test]
    fn length_four_target_finds_length_three_only_rewrite() {
        let target = vec![
            LengthThreeProbeInstruction(9),
            LengthThreeProbeInstruction(8),
            LengthThreeProbeInstruction(7),
            LengthThreeProbeInstruction(6),
        ];
        let config = SearchConfig::default()
            .with_timeout_option(None)
            .with_cores(Some(1));

        let mut search = EnumerativeSearch::<LengthThreeProbeIsa>::new();
        let result = search.search(&target, &(), &config);

        assert!(
            result.found_optimization,
            "length-three candidate should be searched for a length-four target"
        );
        assert_eq!(
            result.optimized_sequence,
            Some(vec![
                LengthThreeProbeInstruction(1),
                LengthThreeProbeInstruction(2),
                LengthThreeProbeInstruction(3),
            ])
        );
        assert_eq!(result.optimized_sequence.as_ref().map(Vec::len), Some(3));
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
            .with_solver_timeout(std::time::Duration::from_millis(200));

        let start = std::time::Instant::now();
        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
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

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
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

    #[test]
    fn with_config_preserves_aarch64_single_add_collapse() {
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
        let config = small_config();

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::with_config(&config);
        let result = search.search(&target, &live_out, &config);

        assert!(
            result.found_optimization,
            "expected length-1 rewrite to be found"
        );
        assert_eq!(result.optimized_sequence.as_ref().map(Vec::len), Some(1));
    }

    #[test]
    fn x86_64_enumerative_finds_single_instruction_rewrite() {
        use crate::isa::X86_64;
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::semantics::cost::CostMetric;

        let target = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        ];
        let live_out = X86LiveOut::from_registers(vec![X86Register::RAX]);
        let config = SearchConfig::default()
            .with_x86_registers(vec![X86Register::RAX, X86Register::RBX])
            .with_immediates(vec![0])
            .with_cost_metric(CostMetric::CodeSize)
            // No wall-clock deadline: the length-1 search over a tiny pool is
            // bounded and terminates on its own. A finite timeout here is
            // nondeterministic under coverage instrumentation (the slow
            // instrumented suite can exceed it and spuriously report no
            // optimization).
            .with_timeout_option(None);

        let mut search = EnumerativeSearch::<X86_64>::new();
        let result = search.search(&target, &live_out, &config);

        assert!(result.found_optimization);
        assert_eq!(
            result.optimized_sequence,
            Some(vec![X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            }])
        );
        assert!(result.statistics.smt_queries > 0);
        assert!(result.statistics.smt_equivalent > 0);
    }

    #[test]
    fn x86_32_enumerative_finds_single_instruction_rewrite() {
        use crate::isa::X86_32;
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::semantics::cost::CostMetric;

        let target = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        ];
        let live_out = X86LiveOut::from_registers(vec![X86Register::RAX]);
        let config = SearchConfig::default()
            .with_x86_registers(vec![X86Register::RAX, X86Register::RBX, X86Register::R8])
            .with_immediates(vec![0])
            .with_cost_metric(CostMetric::CodeSize)
            // See the x86-64 sibling test: a bounded length-1 search needs no
            // wall-clock deadline, and a finite one flakes under coverage.
            .with_timeout_option(None);

        let mut search = EnumerativeSearch::<X86_32>::new();
        let result = search.search(&target, &live_out, &config);

        assert!(result.found_optimization);
        assert_eq!(
            result.optimized_sequence,
            Some(vec![X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            }])
        );
        assert!(result.statistics.smt_queries > 0);
        assert!(result.statistics.smt_equivalent > 0);
    }

    #[test]
    fn x86_32_enumerative_only_generates_assemblable_setcc_candidates() {
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::isa::{Assembler, X86_32};

        let regs = [
            X86Register::RAX,
            X86Register::RSP,
            X86Register::RBP,
            X86Register::RSI,
            X86Register::RDI,
        ];
        let candidates = <X86_32 as EnumerativeBackend<X86_32>>::enumerate_all(&regs, &[0]);
        let setcc_count = candidates
            .iter()
            .filter(|instruction| matches!(instruction, X86Instruction::Setcc { .. }))
            .count();

        assert!(
            candidates
                .iter()
                .all(|instruction| X86_32.can_assemble(instruction)),
            "x86-32 enumerative search generated an unassemblable candidate"
        );
        assert_eq!(
            setcc_count,
            crate::isa::x86::X86Condition::ALL.len(),
            "enumerative search must retain every SETcc condition for EAX"
        );
        assert!(
            candidates.iter().any(|instruction| matches!(
                instruction,
                X86Instruction::MovImm {
                    rd: X86Register::RSI,
                    ..
                }
            )),
            "mode-specific SETcc filtering must not remove encodable ESI candidates"
        );
    }

    // --- Latency pruning-soundness (issue #622) ---
    //
    // The enumerative search prunes whole lengths via `length_cost_lower_bound`.
    // Under the critical-path `Latency` cost this bound MUST still be a valid
    // lower bound on the real cost of any sequence of that length, or the search
    // would prune valid candidates. These tests guard that invariant.

    #[test]
    fn latency_lower_bound_is_constant_in_length() {
        use crate::semantics::cost::CostMetric;
        // For Latency the bound ignores `length` (the critical path of a
        // length-L independent run is just the cheapest instruction's latency),
        // so it must NOT grow with length the way the additive metrics do.
        let m = CostMetric::Latency;
        let min_instr = 1;
        let term = 0;
        assert_eq!(length_cost_lower_bound(&m, 1, min_instr, term), 1);
        assert_eq!(length_cost_lower_bound(&m, 5, min_instr, term), 1);
        assert_eq!(length_cost_lower_bound(&m, 50, min_instr, term), 1);
        // With a terminator the bound is the min of the two single-instruction
        // latencies, never their sum.
        assert_eq!(length_cost_lower_bound(&m, 10, 3, 1), 1);
        assert_eq!(length_cost_lower_bound(&m, 10, 1, 4), 1);
        // The additive metrics still scale with length.
        assert_eq!(length_cost_lower_bound(&CostMetric::CodeSize, 5, 2, 1), 11);
        assert_eq!(
            length_cost_lower_bound(&CostMetric::InstructionCount, 5, 1, 1),
            6
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Pruning-soundness property: for many random supported x86 sequences,
        /// the Latency `length_cost_lower_bound` for EVERY length up to the
        /// sequence length must be `<=` the sequence's real critical-path cost.
        /// A bound that ever exceeded the real cost would make the enumerative
        /// search prune valid candidates.
        #[test]
        fn latency_length_lower_bound_never_exceeds_real_cost(
            // Indices into the candidate pool; up to 6 instructions.
            indices in proptest::collection::vec(proptest::prelude::any::<proptest::sample::Index>(), 1..=6),
            with_terminator in proptest::prelude::any::<bool>(),
        ) {
            use crate::isa::X86_64;
            use crate::isa::x86::{X86Instruction, X86Register, X86Condition};
            use crate::semantics::cost::CostMetric;

            let regs = vec![
                X86Register::RAX,
                X86Register::RBX,
                X86Register::RCX,
                X86Register::RDX,
            ];
            let imms = vec![0i64, 1, 7];
            let pool: Vec<X86Instruction> =
                <X86_64 as EnumerativeBackend<X86_64>>::enumerate_all(&regs, &imms);
            proptest::prop_assume!(!pool.is_empty());

            let seq: Vec<X86Instruction> =
                indices.iter().map(|idx| *idx.get(&pool)).collect();

            // The pinned terminator (x86 Jcc) the search would reattach.
            let terminator = if with_terminator {
                Some(X86Instruction::Jcc { cond: X86Condition::NE })
            } else {
                None
            };

            let m = CostMetric::Latency;
            let cfg = SearchConfig::default().with_cost_metric(m);
            // Reproduce exactly what `search()` computes for the bound inputs.
            let min_instruction_cost = pool
                .iter()
                .map(|i| {
                    <X86_64 as EnumerativeBackend<X86_64>>::sequence_cost(
                        std::slice::from_ref(i),
                        &cfg,
                    )
                })
                .min()
                .unwrap();
            let terminator_cost = terminator
                .map(|t| {
                    <X86_64 as EnumerativeBackend<X86_64>>::sequence_cost(
                        std::slice::from_ref(&t),
                        &cfg,
                    )
                })
                .unwrap_or(0);

            // The search evaluates candidates of EXACTLY `length` instructions at
            // each length (plus the pinned terminator). The bound for that length
            // must not exceed the real cost of any such candidate; we sample one
            // real candidate per length — the random prefix of that length.
            for length in 1..=seq.len() {
                let lb = length_cost_lower_bound(
                    &m,
                    length,
                    min_instruction_cost,
                    terminator_cost,
                );
                let mut candidate = seq[..length].to_vec();
                if let Some(t) = terminator {
                    candidate.push(t);
                }
                let real_cost =
                    <X86_64 as EnumerativeBackend<X86_64>>::sequence_cost(&candidate, &cfg);
                proptest::prop_assert!(
                    lb <= real_cost,
                    "Latency lower bound {lb} exceeded real critical-path cost \
                     {real_cost} at length {length} (candidate={candidate:?})"
                );
            }
        }
    }
}
