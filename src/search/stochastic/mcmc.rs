//! Markov Chain Monte Carlo (MCMC) search implementation
//!
//! Implements stochastic superoptimization using MCMC-style mutation plus
//! Metropolis cost acceptance. Proposal probabilities are heuristic and no
//! Hastings ratio is computed.
//!
//! The algorithm:
//! 1. Generate test cases for fast validation
//! 2. Start with a random initial program (or copy of target)
//! 3. Loop for N iterations:
//!    a. Mutate current program
//!    b. Evaluate on tests (fast rejection if fails)
//!    c. If passes tests with zero cost → verify with SMT
//!    d. Accept/reject based on Metropolis cost acceptance
//! 4. Return best found optimization

use crate::ir::{Instruction, Register};
use crate::isa::{ISA, ISAMutator};
use crate::search::config::SearchConfig;
use crate::search::result::{SearchResultFor, SearchStatistics};
use crate::search::stochastic::acceptance::AcceptanceCriterion;
use crate::search::stochastic::backend::StochasticBackend;
use crate::search::{Algorithm, SearchAlgorithm};
use crate::semantics::EquivalenceResult;
use crate::semantics::concrete::{apply_sequence_concrete, states_equal_for_live_out};
use crate::semantics::live_out::RegisterSet;
use crate::semantics::state::ConcreteMachineState;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::marker::PhantomData;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Stochastic search using MCMC-style proposals and Metropolis cost
/// acceptance, generic over ISA.
///
/// The body routes through the `StochasticBackend<I>` dispatch trait
/// (`src/search/stochastic/backend.rs`) for every ISA-specific
/// operation: random-input generation, sequence cost summation,
/// encodability check against the assembler, equivalence dispatch,
/// mutator construction. Both AArch64 and x86 implement
/// `StochasticBackend`; the body is identical for both.
pub struct StochasticSearch<I = crate::isa::AArch64> {
    statistics: SearchStatistics,
    _marker: PhantomData<I>,
}

impl<I> StochasticSearch<I> {
    pub fn new() -> Self {
        Self {
            statistics: SearchStatistics::new(Algorithm::Stochastic),
            _marker: PhantomData,
        }
    }
}

impl<I> Default for StochasticSearch<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> SearchAlgorithm<I> for StochasticSearch<I>
where
    I: ISA + StochasticBackend<I>,
    <I as StochasticBackend<I>>::State: Clone,
    <I as StochasticBackend<I>>::LiveOut: Clone,
{
    type LiveOut = <I as StochasticBackend<I>>::LiveOut;
    type Result = SearchResultFor<I>;

    fn search(
        &mut self,
        target: &[I::Instruction],
        live_out: &Self::LiveOut,
        config: &SearchConfig,
    ) -> Self::Result {
        self.reset();
        let start_time = Instant::now();
        let width = <I as StochasticBackend<I>>::width();

        let original_cost =
            <I as StochasticBackend<I>>::sequence_cost(target, &config.cost_metric, width);
        self.statistics.original_cost = original_cost;
        self.statistics.best_cost_found = original_cost;

        if target.is_empty() {
            self.statistics.elapsed_time = start_time.elapsed();
            return SearchResultFor::no_optimization(target.to_vec(), self.statistics.clone());
        }

        // Set up RNG
        let mut rng: ChaCha8Rng = match config.stochastic.seed {
            Some(seed) => ChaCha8Rng::seed_from_u64(seed),
            None => {
                ChaCha8Rng::try_from_rng(&mut rand::rngs::SysRng).expect("OS entropy unavailable")
            }
        };

        // Pull register / immediate pools out of the config via the backend.
        let regs = <I as StochasticBackend<I>>::registers_from_config(config);
        let imms = <I as StochasticBackend<I>>::immediates_from_config(config);
        let validation_regs =
            <I as StochasticBackend<I>>::validation_registers(&regs, target, live_out);

        // Generate test cases: random + edge.
        let test_inputs = <I as StochasticBackend<I>>::make_test_inputs(
            &validation_regs,
            width,
            config.stochastic.test_count,
        );
        let edge_inputs = <I as StochasticBackend<I>>::make_edge_inputs(&validation_regs, width);

        // Precompute target outputs.
        let target_outputs: Vec<_> = test_inputs
            .iter()
            .chain(edge_inputs.iter())
            .map(|input| <I as StochasticBackend<I>>::apply_sequence(input.clone(), target))
            .collect();
        let all_inputs: Vec<_> = test_inputs.into_iter().chain(edge_inputs).collect();

        let mutator = <I as StochasticBackend<I>>::make_mutator(config);
        let acceptance = AcceptanceCriterion::new(config.stochastic.beta);

        // If the target ends in a terminator (x86 Jcc, AArch64 branch),
        // every random_sequence proposal must end in the same terminator
        // — the equivalence check's terminator-equality precheck rejects
        // any candidate that lacks it. Peel once and append below.
        let target_terminator = <I as StochasticBackend<I>>::target_terminator(target);
        let terminator_len = if target_terminator.is_some() { 1 } else { 0 };
        let with_term = |mut seq: Vec<I::Instruction>| -> Vec<I::Instruction> {
            if let Some(t) = target_terminator {
                seq.push(t);
            }
            seq
        };

        // Start with target sequence or random sequence of same length
        let mut current = if rng.random_bool(0.5) {
            target.to_vec()
        } else {
            loop {
                let prefix_len = target.len().saturating_sub(terminator_len);
                let seq = with_term(<I as StochasticBackend<I>>::random_sequence(
                    &mut rng, prefix_len, &regs, &imms, config,
                ));
                if <I as StochasticBackend<I>>::is_encodable(&seq) {
                    break seq;
                }
            }
        };
        let mut current_cost =
            <I as StochasticBackend<I>>::sequence_cost(&current, &config.cost_metric, width);

        let mut best_equivalent: Option<Vec<I::Instruction>> = None;
        let mut best_cost = original_cost;

        // Length bounds: the terminator (if any) is always pinned at the
        // tail, so length-change proposals only vary the prefix length.
        let min_length = 1 + terminator_len;
        let max_length = target.len();

        for iteration in 0..config.stochastic.iterations {
            self.statistics.iterations = iteration + 1;

            if config.timeout.is_some_and(|t| start_time.elapsed() >= t) {
                if config.verbose {
                    println!("Search timed out after {} iterations", iteration);
                }
                break;
            }

            // Cooperative cancel: the parallel coordinator (or any external
            // driver) can flip the shared flag to stop us promptly without
            // waiting for `config.timeout` to elapse. `Relaxed` is fine: the
            // flag is monotonic (false → true once) and late observation
            // costs at most one extra iteration.
            if config
                .stop_flag
                .as_ref()
                .is_some_and(|f| f.load(Ordering::Relaxed))
            {
                break;
            }

            // Occasionally try a different length
            if rng.random_bool(0.1) && max_length > min_length {
                let new_len = rng.random_range(min_length..=max_length);
                if new_len != current.len() {
                    loop {
                        let prefix_len = new_len.saturating_sub(terminator_len);
                        let seq = with_term(<I as StochasticBackend<I>>::random_sequence(
                            &mut rng, prefix_len, &regs, &imms, config,
                        ));
                        if <I as StochasticBackend<I>>::is_encodable(&seq) {
                            current = seq;
                            break;
                        }
                    }
                    current_cost = <I as StochasticBackend<I>>::sequence_cost(
                        &current,
                        &config.cost_metric,
                        width,
                    );
                }
            }

            let proposal = mutator.mutate(&mut rng, &current);

            if !<I as StochasticBackend<I>>::is_encodable(&proposal) {
                continue;
            }

            let proposal_cost =
                <I as StochasticBackend<I>>::sequence_cost(&proposal, &config.cost_metric, width);

            self.statistics.candidates_evaluated += 1;

            let mut passes_tests = true;
            for (input, target_output) in all_inputs.iter().zip(target_outputs.iter()) {
                let proposal_output =
                    <I as StochasticBackend<I>>::apply_sequence(input.clone(), &proposal);
                if !<I as StochasticBackend<I>>::states_equal(
                    &proposal_output,
                    target_output,
                    live_out,
                ) {
                    passes_tests = false;
                    break;
                }
            }

            if !passes_tests {
                continue;
            }

            self.statistics.candidates_passed_fast += 1;

            let mut smt_refuted = false;
            if proposal_cost < best_cost {
                let Some(smt_timeout) = config.solver_timeout_within_budget(start_time.elapsed())
                else {
                    // No millisecond-granularity SMT budget remains, so the
                    // overall search deadline is effectively reached; stop
                    // rather than hand Z3 a timeout it cannot honour. Mirrors
                    // the enumerative path.
                    break;
                };
                let (verdict, metrics) = <I as StochasticBackend<I>>::check_equivalence(
                    target,
                    &proposal,
                    live_out,
                    width,
                    smt_timeout,
                );
                // Fold the SMT counters through the canonical accounting seam so
                // this path cannot drift from the symbolic/enumerative ones.
                // `candidates_passed_fast` is counted separately above (at the
                // concrete-test stage), which is why we apply the tally directly
                // rather than calling `record_verification`.
                let tally = SearchStatistics::verification_tally(&metrics, &verdict);
                tally.fold_into(&mut self.statistics);
                if tally.proved_equivalent {
                    self.statistics.improvements_found += 1;

                    best_equivalent = Some(proposal.clone());
                    best_cost = proposal_cost;
                    self.statistics.best_cost_found = best_cost;

                    if config.verbose {
                        println!(
                            "Found improvement at iteration {}: cost {} -> {}",
                            iteration, original_cost, best_cost
                        );
                    }
                } else if matches!(
                    verdict,
                    EquivalenceResult::NotEquivalent | EquivalenceResult::NotEquivalentFast(_)
                ) {
                    smt_refuted = true;
                }
                // SMT timeout / inconclusive (`Unknown`): we cannot prove the
                // proposal incorrect, so leave the Metropolis decision below
                // intact rather than vetoing exploration.
            } else {
                self.statistics.candidates_pruned_by_cost += 1;
            }

            if smt_refuted {
                continue;
            }

            if acceptance.accept(&mut rng, current_cost, proposal_cost) {
                current = proposal;
                current_cost = proposal_cost;
                self.statistics.accepted_proposals += 1;
            }

            if config.verbose && iteration > 0 && iteration % 100_000 == 0 {
                println!(
                    "Iteration {}: current_cost={}, best_cost={}, acceptance_rate={:.2}%",
                    iteration,
                    current_cost,
                    best_cost,
                    self.statistics.acceptance_rate() * 100.0
                );
            }
        }

        self.statistics.elapsed_time = start_time.elapsed();

        if let Some(optimized) = best_equivalent {
            SearchResultFor::with_optimization(target.to_vec(), optimized, self.statistics.clone())
        } else {
            SearchResultFor::no_optimization(target.to_vec(), self.statistics.clone())
        }
    }

    fn statistics(&self) -> SearchStatistics {
        self.statistics.clone()
    }

    fn reset(&mut self) {
        self.statistics = SearchStatistics::new(Algorithm::Stochastic);
    }
}

/// Simplified cost function for MCMC that includes both cost and correctness
/// Returns high cost for programs that fail tests
pub fn evaluate_with_tests(
    proposal: &[Instruction],
    _target: &[Instruction],
    test_inputs: &[ConcreteMachineState],
    target_outputs: &[ConcreteMachineState],
    live_out: &RegisterSet<Register>,
) -> (u64, bool) {
    let mut passes_all = true;

    for (input, target_output) in test_inputs.iter().zip(target_outputs.iter()) {
        let proposal_output = apply_sequence_concrete(input.clone(), proposal);
        if !states_equal_for_live_out(&proposal_output, target_output, live_out, false) {
            passes_all = false;
            break;
        }
    }

    let base_cost = proposal.len() as u64;
    if passes_all {
        (base_cost, true)
    } else {
        // High penalty for incorrect programs
        (base_cost + 1000, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};
    use crate::isa::{AArch64, ISA, ISAMutator, U64};
    use crate::search::config::StochasticConfig;
    use crate::semantics::cost::CostMetric;
    use crate::semantics::live_out::LiveOut;
    use crate::semantics::state::{ConcreteValue, ConditionFlags};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Mutex as TestMutex, MutexGuard};
    use std::time::Duration;

    fn mov_add_sequence() -> Vec<Instruction> {
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
        ]
    }

    fn mov_zero_sequence() -> Vec<Instruction> {
        vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }]
    }

    #[test]
    fn test_stochastic_search_creation() {
        let search: StochasticSearch<AArch64> = StochasticSearch::new();
        let stats = search.statistics();
        assert_eq!(stats.algorithm, Algorithm::Stochastic);
        assert_eq!(stats.iterations, 0);
    }

    #[test]
    fn test_stochastic_search_empty_sequence() {
        let mut search: StochasticSearch<AArch64> = StochasticSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let result = search.search(&[], &live_out, &config);
        assert!(!result.found_optimization);
    }

    #[derive(Clone)]
    struct TimeoutProbeIsa;

    struct TimeoutProbeMutator;

    impl ISAMutator<Instruction> for TimeoutProbeMutator {
        fn mutate<R: rand::RngExt>(
            &self,
            _rng: &mut R,
            _sequence: &[Instruction],
        ) -> Vec<Instruction> {
            mov_zero_sequence()
        }
    }

    impl ISA for TimeoutProbeIsa {
        type Register = Register;
        type Operand = Operand;
        type Instruction = Instruction;
        type Width = U64;
        type Flags = ();
        type Mutator = TimeoutProbeMutator;

        fn name(&self) -> &'static str {
            "TimeoutProbe"
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
            None
        }
    }

    std::thread_local! {
        static RECORDED_SMT_TIMEOUT_MS: std::cell::Cell<Option<u128>> =
            const { std::cell::Cell::new(None) };
    }

    const TIMEOUT_PROBE_NOT_EQUIVALENT: usize = 0;
    const TIMEOUT_PROBE_EQUIVALENT: usize = 1;

    static TIMEOUT_PROBE_TEST_LOCK: TestMutex<()> = TestMutex::new(());
    static TIMEOUT_PROBE_VERDICT: AtomicUsize = AtomicUsize::new(TIMEOUT_PROBE_EQUIVALENT);
    static TIMEOUT_PROBE_SMT_CALLED: AtomicBool = AtomicBool::new(true);

    fn set_timeout_probe_result(verdict: usize, smt_called: bool) -> MutexGuard<'static, ()> {
        let guard = TIMEOUT_PROBE_TEST_LOCK
            .lock()
            .expect("timeout probe test lock poisoned");
        TIMEOUT_PROBE_VERDICT.store(verdict, AtomicOrdering::SeqCst);
        TIMEOUT_PROBE_SMT_CALLED.store(smt_called, AtomicOrdering::SeqCst);
        RECORDED_SMT_TIMEOUT_MS.with(|recorded| recorded.set(None));
        guard
    }

    impl StochasticBackend<TimeoutProbeIsa> for TimeoutProbeIsa {
        type State = ();
        type LiveOut = ();

        fn registers_from_config(_config: &SearchConfig) -> Vec<Register> {
            vec![Register::X0]
        }

        fn immediates_from_config(_config: &SearchConfig) -> Vec<i64> {
            vec![0]
        }

        fn make_mutator(_config: &SearchConfig) -> TimeoutProbeMutator {
            TimeoutProbeMutator
        }

        fn make_test_inputs(_regs: &[Register], _width: u32, count: usize) -> Vec<Self::State> {
            vec![(); count]
        }

        fn make_edge_inputs(_regs: &[Register], _width: u32) -> Vec<Self::State> {
            Vec::new()
        }

        fn apply_sequence(state: Self::State, _seq: &[Instruction]) -> Self::State {
            state
        }

        fn states_equal(_s1: &Self::State, _s2: &Self::State, _live_out: &Self::LiveOut) -> bool {
            true
        }

        fn sequence_cost(seq: &[Instruction], _metric: &CostMetric, _width: u32) -> u64 {
            seq.len() as u64
        }

        fn is_encodable(_seq: &[Instruction]) -> bool {
            true
        }

        fn check_equivalence(
            _target: &[Instruction],
            _proposal: &[Instruction],
            _live_out: &Self::LiveOut,
            _width: u32,
            timeout: Duration,
        ) -> (EquivalenceResult, crate::semantics::EquivalenceMetrics) {
            RECORDED_SMT_TIMEOUT_MS.with(|recorded| recorded.set(Some(timeout.as_millis())));
            let metrics = crate::semantics::EquivalenceMetrics {
                smt_called: TIMEOUT_PROBE_SMT_CALLED.load(AtomicOrdering::SeqCst),
                ..crate::semantics::EquivalenceMetrics::default()
            };
            (
                match TIMEOUT_PROBE_VERDICT.load(AtomicOrdering::SeqCst) {
                    TIMEOUT_PROBE_EQUIVALENT => EquivalenceResult::Equivalent,
                    _ => EquivalenceResult::NotEquivalent,
                },
                metrics,
            )
        }

        fn random_sequence<R: rand::RngExt>(
            _rng: &mut R,
            len: usize,
            _regs: &[Register],
            _imms: &[i64],
            _config: &SearchConfig,
        ) -> Vec<Instruction> {
            vec![
                Instruction::MovImm {
                    rd: Register::X0,
                    imm: 0,
                };
                len
            ]
        }

        fn width() -> u32 {
            64
        }
    }

    fn run_timeout_probe_search_with(
        config: SearchConfig,
        verdict: usize,
        smt_called: bool,
    ) -> (SearchStatistics, Option<u128>) {
        let _guard = set_timeout_probe_result(verdict, smt_called);
        let mut search: StochasticSearch<TimeoutProbeIsa> = StochasticSearch::new();
        let target = mov_add_sequence();
        let result = search.search(&target, &(), &config);
        let statistics = result.statistics;

        (
            statistics,
            RECORDED_SMT_TIMEOUT_MS.with(|recorded| recorded.get()),
        )
    }

    fn run_timeout_probe_search(config: SearchConfig) -> Option<u128> {
        let (statistics, recorded_timeout) =
            run_timeout_probe_search_with(config, TIMEOUT_PROBE_EQUIVALENT, true);
        assert_eq!(statistics.smt_queries, 1);
        recorded_timeout
    }

    #[test]
    fn stochastic_search_accounts_solver_proven_improvement_through_the_seam() {
        // The equivalent branch folds its SMT counters through the shared
        // `VerificationTally` seam: a solver-reaching, proven-equivalent cheaper
        // proposal counts as one SMT query, one proven equivalence, and one
        // recorded improvement — the counterpart to the refuted case below.
        let _guard = set_timeout_probe_result(TIMEOUT_PROBE_EQUIVALENT, true);

        let mut search: StochasticSearch<TimeoutProbeIsa> = StochasticSearch::new();
        let config = SearchConfig::default().with_stochastic(
            StochasticConfig::default()
                .with_iterations(1)
                .with_test_count(0)
                .with_seed(1),
        );
        let target = mov_add_sequence();

        let result = search.search(&target, &(), &config);

        assert_eq!(result.statistics.smt_queries, 1);
        assert_eq!(result.statistics.smt_equivalent, 1);
        assert_eq!(result.statistics.improvements_found, 1);
        assert!(result.found_optimization);
    }

    #[test]
    fn stochastic_search_does_not_accept_smt_refuted_cheaper_proposal() {
        let _guard = set_timeout_probe_result(TIMEOUT_PROBE_NOT_EQUIVALENT, true);

        let mut search: StochasticSearch<TimeoutProbeIsa> = StochasticSearch::new();
        let config = SearchConfig::default().with_stochastic(
            StochasticConfig::default()
                .with_iterations(1)
                .with_test_count(0)
                .with_seed(1),
        );
        let target = mov_add_sequence();

        let result = search.search(&target, &(), &config);

        assert_eq!(result.statistics.smt_queries, 1);
        assert_eq!(result.statistics.smt_equivalent, 0);
        assert_eq!(result.statistics.improvements_found, 0);
        assert!(!result.found_optimization);
        assert_eq!(result.statistics.accepted_proposals, 0);
    }

    #[test]
    fn stochastic_search_uses_top_level_solver_timeout_for_smt() {
        let recorded_timeout = run_timeout_probe_search(
            SearchConfig::default()
                .with_stochastic(
                    StochasticConfig::default()
                        .with_iterations(1)
                        .with_test_count(0)
                        .with_seed(1),
                )
                .with_solver_timeout(Duration::from_millis(17)),
        );

        assert_eq!(recorded_timeout, Some(17));
    }

    #[test]
    fn timeout_probe_preserves_full_millisecond_value() {
        let recorded_timeout = run_timeout_probe_search(
            SearchConfig::default()
                .with_stochastic(
                    StochasticConfig::default()
                        .with_iterations(1)
                        .with_test_count(0)
                        .with_seed(1),
                )
                .with_timeout_option(None)
                .with_solver_timeout(Duration::MAX),
        );

        assert_eq!(recorded_timeout, Some(Duration::MAX.as_millis()));
    }

    #[test]
    fn stochastic_smt_timeout_is_clamped_to_remaining_search_budget() {
        // Solver timeout (30s) vastly exceeds the remaining search budget
        // (50ms). The timeout handed to Z3 must be clamped to the budget rather
        // than the full solver timeout — the deadline-respecting behaviour this
        // seam restores to the MCMC path. Mirrors the symbolic backend's
        // `symbolic_smt_timeout_is_clamped_to_remaining_search_budget`, using
        // the deterministic `TimeoutProbeIsa` probe rather than wall-clock
        // timing.
        let (statistics, recorded_timeout) = run_timeout_probe_search_with(
            SearchConfig::default()
                .with_stochastic(
                    StochasticConfig::default()
                        .with_iterations(1)
                        .with_test_count(0)
                        .with_seed(1),
                )
                .with_timeout(Duration::from_millis(50))
                .with_solver_timeout(Duration::from_secs(30)),
            TIMEOUT_PROBE_EQUIVALENT,
            true,
        );

        // The cheaper proposal still reaches the solver (the budget is not yet
        // exhausted at ~0ms elapsed), so exactly one SMT query runs...
        assert_eq!(statistics.smt_queries, 1);
        // ...and the timeout it was handed is clamped to the ~50ms budget, not
        // the 30s solver timeout.
        let recorded = recorded_timeout.expect("an SMT query should have recorded a timeout");
        assert!(
            (1..=50).contains(&recorded),
            "solver timeout should be clamped to the ~50ms budget, got {recorded}ms",
        );
    }

    #[test]
    fn stochastic_search_falls_back_to_five_seconds_when_solver_timeout_unset() {
        let recorded_timeout = run_timeout_probe_search(
            SearchConfig::default()
                .with_stochastic(
                    StochasticConfig::default()
                        .with_iterations(1)
                        .with_test_count(0)
                        .with_seed(1),
                )
                .with_solver_timeout_option(None),
        );

        assert_eq!(recorded_timeout, Some(5000));
    }

    #[test]
    fn stochastic_counts_fast_passing_non_improving_proposal_as_cost_pruned() {
        let mut search: StochasticSearch<TimeoutProbeIsa> = StochasticSearch::new();
        let config = SearchConfig::default().with_stochastic(
            StochasticConfig::default()
                .with_iterations(1)
                .with_test_count(0)
                .with_seed(1),
        );
        let target = mov_zero_sequence();

        let result = search.search(&target, &(), &config);

        assert!(!result.found_optimization);
        assert_eq!(result.statistics.candidates_evaluated, 1);
        assert_eq!(result.statistics.candidates_passed_fast, 1);
        assert_eq!(result.statistics.candidates_pruned_by_cost, 1);
        assert_eq!(result.statistics.smt_queries, 0);
    }

    #[test]
    fn stochastic_search_does_not_count_pre_smt_refutation_as_smt_query() {
        let (statistics, recorded_timeout) = run_timeout_probe_search_with(
            SearchConfig::default()
                .with_stochastic(
                    StochasticConfig::default()
                        .with_iterations(1)
                        .with_test_count(0)
                        .with_seed(1),
                )
                .with_solver_timeout(Duration::from_millis(17)),
            TIMEOUT_PROBE_NOT_EQUIVALENT,
            false,
        );

        assert_eq!(recorded_timeout, Some(17));
        assert_eq!(statistics.candidates_passed_fast, 1);
        assert_eq!(statistics.smt_queries, 0);
        assert_eq!(statistics.smt_equivalent, 0);
    }

    #[test]
    fn test_stochastic_search_with_seed() {
        let mut search: StochasticSearch<AArch64> = StochasticSearch::new();
        let config = SearchConfig::default().with_stochastic(
            StochasticConfig::default()
                .with_seed(42)
                .with_iterations(1000),
        );
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let result = search.search(&mov_zero_sequence(), &live_out, &config);
        let stats = result.statistics;

        assert!(stats.iterations > 0);
        assert!(stats.candidates_evaluated > 0);
    }

    #[test]
    fn test_stochastic_finds_mov_zero_eor() {
        let mut search: StochasticSearch<AArch64> = StochasticSearch::new();

        // Use smaller iteration count for test speed, but enough to find the optimization
        let config = SearchConfig::default()
            .with_stochastic(StochasticConfig::default().with_iterations(100_000))
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![-1, 0, 1]);

        let live_out = LiveOut::from_registers(vec![Register::X0]);

        // Target: MOV X0, #0 - can be replaced with EOR X0, X0, X0
        // But since both are 1 instruction, no optimization expected
        let target = mov_zero_sequence();
        let result = search.search(&target, &live_out, &config);

        // The algorithm should complete without errors
        assert!(result.statistics.iterations > 0);
    }

    #[test]
    fn test_stochastic_finds_mov_add_fusion() {
        let mut search: StochasticSearch<AArch64> = StochasticSearch::new();

        let config = SearchConfig::default()
            .with_stochastic(StochasticConfig::default().with_iterations(500_000))
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![-1, 0, 1, 2]);

        let live_out = LiveOut::from_registers(vec![Register::X0]);

        // Target: MOV X0, X1; ADD X0, X0, #1 (2 instructions)
        // Can be optimized to: ADD X0, X1, #1 (1 instruction)
        let target = mov_add_sequence();
        let result = search.search(&target, &live_out, &config);

        // This is a probabilistic test - might not always find the optimization
        // But the search should complete
        assert!(result.statistics.iterations > 0);
        assert!(result.statistics.candidates_evaluated > 0);

        // If found, verify it's actually an optimization
        if result.found_optimization {
            assert!(result.cost_savings() > 0);
        }
    }

    #[test]
    fn test_evaluate_with_tests_correct() {
        let target = mov_zero_sequence();
        let proposal = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
            width: crate::ir::RegisterWidth::X64,
        }];

        let input = ConcreteMachineState::new_zeroed();
        let target_output = apply_sequence_concrete(input.clone(), &target);

        let live_out = RegisterSet::<Register>::from_registers(vec![Register::X0]);
        let (cost, passes) =
            evaluate_with_tests(&proposal, &target, &[input], &[target_output], &live_out);

        assert!(passes);
        assert_eq!(cost, 1); // 1 instruction
    }

    #[test]
    fn test_evaluate_with_tests_incorrect() {
        let target = mov_zero_sequence();
        let proposal = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }]; // Wrong value!

        let input = ConcreteMachineState::new_zeroed();
        let target_output = apply_sequence_concrete(input.clone(), &target);

        let live_out = RegisterSet::<Register>::from_registers(vec![Register::X0]);
        let (cost, passes) =
            evaluate_with_tests(&proposal, &target, &[input], &[target_output], &live_out);

        assert!(!passes);
        assert!(cost > 100); // High penalty
    }

    #[test]
    fn test_evaluate_with_tests_honors_flags_from_mask() {
        let target = Vec::new();
        let proposal = Vec::new();

        let mut input = ConcreteMachineState::new_zeroed();
        input.set_register(Register::X0, ConcreteValue(42));
        input.set_flags(ConditionFlags {
            n: true,
            z: false,
            c: false,
            v: false,
        });

        let mut target_output = input.clone();
        target_output.set_flags(ConditionFlags {
            n: false,
            z: true,
            c: false,
            v: false,
        });

        // Mask without flag liveness: the divergent NZCV bits are ignored, so
        // the proposal still passes.
        let live_out_flags_dead = RegisterSet::<Register>::from_registers(vec![Register::X0]);
        let (cost, passes) = evaluate_with_tests(
            &proposal,
            &target,
            &[input.clone()],
            &[target_output.clone()],
            &live_out_flags_dead,
        );
        assert!(passes);
        assert_eq!(cost, 0);

        // Mask with flag liveness: NZCV divergence now fails the proposal,
        // matching the flag-honoring stochastic prefilter.
        let live_out_flags_live = live_out_flags_dead.with_flags(true);
        let (_cost, passes) = evaluate_with_tests(
            &proposal,
            &target,
            &[input],
            &[target_output],
            &live_out_flags_live,
        );
        assert!(!passes);
    }

    #[test]
    fn test_statistics_tracking() {
        let mut search: StochasticSearch<AArch64> = StochasticSearch::new();

        let config = SearchConfig::default()
            .with_stochastic(StochasticConfig::default().with_iterations(1000))
            .with_registers(vec![Register::X0, Register::X1]);

        let live_out = LiveOut::from_registers(vec![Register::X0]);
        let target = mov_zero_sequence();

        let result = search.search(&target, &live_out, &config);
        let stats = result.statistics;

        assert_eq!(stats.algorithm, Algorithm::Stochastic);
        assert!(stats.elapsed_time.as_nanos() > 0);
        assert_eq!(stats.iterations, 1000);
        assert!(stats.candidates_evaluated >= stats.candidates_passed_fast);
    }

    /// Regression for issue #243: a stochastic search must abort promptly
    /// when an external coordinator flips its cooperative-cancel flag, even
    /// if `config.timeout` is `None` and `iterations` is unbounded.
    #[test]
    fn stochastic_search_respects_cooperative_stop_flag() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use std::thread;
        use std::time::{Duration, Instant};

        let flag = Arc::new(AtomicBool::new(false));
        let flag_for_search = Arc::clone(&flag);

        let configured_iterations: u64 = u64::MAX / 2;
        let join = thread::spawn(move || {
            let mut search: StochasticSearch<AArch64> = StochasticSearch::new();
            let config = SearchConfig::default()
                .with_timeout_option(None)
                .with_stop_flag(flag_for_search)
                .with_registers(vec![Register::X0, Register::X1])
                .with_immediates(vec![-1, 0, 1])
                .with_stochastic(
                    StochasticConfig::default()
                        .with_iterations(configured_iterations)
                        .with_seed(7),
                );
            let live_out = LiveOut::from_registers(vec![Register::X0]);
            let target = mov_add_sequence();
            search.search(&target, &live_out, &config)
        });

        // Give the worker a moment to enter its main loop, then signal stop.
        thread::sleep(Duration::from_millis(20));
        flag.store(true, std::sync::atomic::Ordering::SeqCst);

        let started_join = Instant::now();
        let result = join.join().expect("stochastic worker panicked");
        let join_elapsed = started_join.elapsed();

        assert!(
            join_elapsed < Duration::from_secs(2),
            "stop flag should abort the MCMC loop promptly; took {:?}",
            join_elapsed,
        );
        assert!(
            result.statistics.iterations < configured_iterations,
            "search should have aborted before exhausting iterations; got {}",
            result.statistics.iterations,
        );
    }

    #[test]
    fn test_acceptance_rate_tracking() {
        let mut search: StochasticSearch<AArch64> = StochasticSearch::new();

        let config = SearchConfig::default()
            .with_stochastic(
                StochasticConfig::default()
                    .with_iterations(10000)
                    .with_beta(1.0),
            )
            .with_registers(vec![Register::X0, Register::X1, Register::X2]);

        let live_out = LiveOut::from_registers(vec![Register::X0]);
        let target = mov_zero_sequence();

        let result = search.search(&target, &live_out, &config);
        let stats = result.statistics;

        // Acceptance rate should be between 0 and 1
        let rate = stats.acceptance_rate();
        assert!(rate >= 0.0);
        assert!(rate <= 1.0);
    }

    // ---- x86 stochastic search (issue #73 Phase C step 5) ----

    /// Tracer-bullet test that the generic `StochasticSearch<X86_64>`
    /// instantiates and discovers the dead-flags collapse for a
    /// 2-instruction x86 target.
    #[test]
    fn x86_stochastic_runs_end_to_end() {
        use crate::isa::X86_64;
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::semantics::live_out::X86LiveOut;

        let mut search: StochasticSearch<X86_64> = StochasticSearch::new();
        let config = SearchConfig::default()
            .with_stochastic(
                // Adding rewritable families shifts the seeded mutation
                // trajectory. With MOVZX/MOVSX and SETcc raising the opcode
                // count to 32, seed 2 reaches the equally valid `mov rax, rbx`
                // collapse within 500 iterations (flags are dead in this test).
                StochasticConfig::default()
                    .with_iterations(500)
                    .with_seed(2),
            )
            .with_x86_registers(vec![X86Register::RAX, X86Register::RBX, X86Register::RCX])
            .with_immediates(vec![0, 1]);

        let live_out = X86LiveOut::from_registers(vec![X86Register::RAX]).with_flags(false);

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

        let result = search.search(&target, &live_out, &config);
        let stats = &result.statistics;

        assert_eq!(stats.algorithm, Algorithm::Stochastic);
        assert_eq!(stats.iterations, 500);
        assert!(stats.candidates_evaluated > 0);
        assert!(result.found_optimization);
        assert_eq!(result.cost_savings(), 1);
        assert_eq!(
            result.optimized_sequence,
            Some(vec![X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            }])
        );
    }

    /// Mirror of `x86_stochastic_runs_end_to_end` for x86-32 (Mode32 /
    /// width 32). Covers the `StochasticBackend<X86_32>` impl methods
    /// — register pool extraction, edge inputs at width 32, the
    /// width-32 branch in `x86_check_equivalence`, and the mutator
    /// construction with `X86Mode::Mode32`.
    #[test]
    fn x86_stochastic_mode32_runs_end_to_end() {
        use crate::isa::X86_32;
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::semantics::live_out::X86LiveOut;

        let mut search: StochasticSearch<X86_32> = StochasticSearch::new();
        let config = SearchConfig::default()
            .with_stochastic(
                StochasticConfig::default()
                    .with_iterations(200)
                    .with_seed(11),
            )
            // Mode32 restricts to the low-8 GPRs.
            .with_x86_registers(vec![X86Register::RAX, X86Register::RBX, X86Register::RCX])
            .with_immediates(vec![0, 1]);

        let live_out = X86LiveOut::from_registers(vec![X86Register::RAX]).with_flags(false);
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

        let result = search.search(&target, &live_out, &config);
        assert_eq!(result.statistics.iterations, 200);
        assert!(result.statistics.candidates_evaluated > 0);
    }
}
