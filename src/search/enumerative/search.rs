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
        config: &SearchConfig,
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
        config: &SearchConfig,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        let smt_timeout = config
            .symbolic
            .solver_timeout
            .unwrap_or(Duration::from_secs(5));
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
        crate::isa::x86::X86InstructionGenerator.generate_all(regs, imms)
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
        config: &SearchConfig,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        let smt_timeout = config
            .symbolic
            .solver_timeout
            .unwrap_or(Duration::from_secs(5));
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
        crate::isa::x86::X86InstructionGenerator.generate_all(regs, imms)
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
        config: &SearchConfig,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        let smt_timeout = config
            .symbolic
            .solver_timeout
            .unwrap_or(Duration::from_secs(5));
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
) -> bool
where
    I: ISA + EnumerativeBackend<I>,
{
    let (verdict, metrics) =
        <I as EnumerativeBackend<I>>::check_equivalence(target, candidate, live_out, config);
    let solver_nanos: u64 = metrics
        .smt_elapsed
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX);
    shared
        .smt_elapsed_nanos
        .fetch_add(solver_nanos, Ordering::Relaxed);
    // Count only candidates that actually reached `solver.check()`. The
    // pre-SMT guard (`flag_writers_diverge && flags_live`) returns
    // `NotEquivalent` with `metrics.smt_called == false`, and the
    // fast-path returns `NotEquivalentFast` the same way — using the
    // metric is both correct and future-proof against new early-return
    // paths (PR #269 review).
    if metrics.smt_called {
        shared.smt_queries.fetch_add(1, Ordering::Relaxed);
    }
    match verdict {
        EquivalenceResult::Equivalent => {
            shared.smt_equivalent.fetch_add(1, Ordering::Relaxed);
            shared
                .candidates_passed_fast
                .fetch_add(1, Ordering::Relaxed);
            true
        }
        _ => false,
    }
}

pub struct EnumerativeSearch<I: ISA = AArch64> {
    statistics: SearchStatistics,
    candidate_pool: Option<CandidatePool<I>>,
    _isa: PhantomData<I>,
}

impl<I: ISA> EnumerativeSearch<I> {
    pub fn new() -> Self {
        Self {
            statistics: SearchStatistics::new(Algorithm::Enumerative),
            candidate_pool: None,
            _isa: PhantomData,
        }
    }

    fn timed_out(start: Instant, timeout: Option<Duration>) -> bool {
        timeout.is_some_and(|t| start.elapsed() >= t)
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
        let mut candidate = vec![*instr];
        if let Some(t) = terminator {
            candidate.push(t);
        }
        let candidate_cost = <I as EnumerativeBackend<I>>::sequence_cost(&candidate, config);
        if candidate_cost >= shared.best_cost.load(Ordering::Acquire) {
            return;
        }
        shared.candidates_evaluated.fetch_add(1, Ordering::Relaxed);
        if verify_candidate::<I>(target, &candidate, live_out, config, shared) {
            shared.record_improvement(candidate, candidate_cost);
        }
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
        // Mirror symbolic's timeout granularity (instr1 level).
        if EnumerativeSearch::<I>::timed_out(start, config.timeout) {
            shared.stop.store(true, Ordering::Relaxed);
            return;
        }
        for instr2 in all_instructions {
            if shared.stop.load(Ordering::Relaxed) {
                return;
            }
            let mut candidate = vec![*instr1, *instr2];
            if let Some(t) = terminator {
                candidate.push(t);
            }
            let candidate_cost = <I as EnumerativeBackend<I>>::sequence_cost(&candidate, config);
            if candidate_cost >= shared.best_cost.load(Ordering::Acquire) {
                continue;
            }
            shared.candidates_evaluated.fetch_add(1, Ordering::Relaxed);
            if verify_candidate::<I>(target, &candidate, live_out, config, shared) {
                shared.record_improvement(candidate, candidate_cost);
            }
        }
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

        let all_instructions = self.candidate_pool_for_config(config);
        let terminator = <I as EnumerativeBackend<I>>::target_terminator(target);
        let shared = SharedState::new(original_cost);

        let run_lengths = |s: &SharedState<I>| {
            // Search increasing lengths up to target.len()-1 so we never
            // propose a candidate as long as the target. We keep going after a
            // hit because length-1 may exist alongside length-2; cost-pruning
            // enforces strict improvement.
            for length in 1..target.len() {
                if Self::timed_out(start, config.timeout) || s.stop.load(Ordering::Relaxed) {
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
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Mutex as TestMutex, MutexGuard};

    use crate::ir::{Instruction, Operand, Register};
    use crate::isa::{ISA, ISAMutator, InstructionType, OperandType, RegisterType, U64};
    use crate::search::config::SymbolicConfig;

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
            _config: &SearchConfig,
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
            &SearchConfig::default(),
        );

        assert_eq!(result.0, EquivalenceResult::Equivalent);

        let flags_live_result = <AArch64 as EnumerativeBackend<AArch64>>::check_equivalence(
            &target,
            &candidate,
            &live_out.with_flags(true),
            &SearchConfig::default(),
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
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![0, 1])
            .with_timeout(std::time::Duration::from_secs(30));

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

        let mut search = EnumerativeSearch::<crate::isa::AArch64>::new();
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
            .with_x86_width(64)
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
            .with_x86_width(32)
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
    }
}
