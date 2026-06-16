//! Markov Chain Monte Carlo (MCMC) search implementation
//!
//! Implements stochastic superoptimization using MCMC-style mutation plus
//! Metropolis cost acceptance. Proposal probabilities are heuristic and no
//! Hastings ratio is computed.
//! The algorithm:
//! 1. Generate test cases for fast validation
//! 2. Start with a random initial program (or copy of target)
//! 3. Loop for N iterations:
//!    a. Mutate current program
//!    b. Evaluate on tests (fast rejection if fails)
//!    c. If passes tests with zero cost → verify with SMT
//!    d. Accept/reject based on Metropolis cost acceptance
//! 4. Return best found optimization

#![allow(dead_code)]

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
use std::time::{Duration, Instant};

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
        let width = <I as StochasticBackend<I>>::width(config);

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

        // Generate test cases: random + edge.
        let test_inputs = <I as StochasticBackend<I>>::make_test_inputs(
            &regs,
            width,
            config.stochastic.test_count,
        );
        let edge_inputs = <I as StochasticBackend<I>>::make_edge_inputs(&regs, width);

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
        let smt_timeout = config
            .symbolic
            .solver_timeout
            .unwrap_or(Duration::from_secs(5));

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

            if proposal_cost < best_cost {
                self.statistics.smt_queries += 1;

                let (verdict, metrics) = <I as StochasticBackend<I>>::check_equivalence(
                    target,
                    &proposal,
                    live_out,
                    width,
                    smt_timeout,
                );
                self.statistics.smt_elapsed += metrics.smt_elapsed;
                if let EquivalenceResult::Equivalent = verdict {
                    self.statistics.smt_equivalent += 1;
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
                }
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
        if !states_equal_for_live_out(&proposal_output, target_output, live_out, false, false) {
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
    use crate::isa::{AArch64, ISA, ISAMutator, InstructionType, OperandType, RegisterType, U64};
    use crate::search::config::{StochasticConfig, SymbolicConfig};
    use crate::semantics::cost::CostMetric;
    use crate::semantics::live_out::LiveOut;

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

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct TimeoutProbeRegister;

    impl std::fmt::Display for TimeoutProbeRegister {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "tp0")
        }
    }

    impl RegisterType for TimeoutProbeRegister {
        fn index(&self) -> Option<u8> {
            Some(0)
        }

        fn from_index(idx: u8) -> Option<Self> {
            (idx == 0).then_some(Self)
        }

        fn is_zero_register(&self) -> bool {
            false
        }

        fn is_special(&self) -> bool {
            false
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum TimeoutProbeOperand {
        Reg(TimeoutProbeRegister),
        Imm(i64),
    }

    impl std::fmt::Display for TimeoutProbeOperand {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Reg(reg) => write!(f, "{reg}"),
                Self::Imm(imm) => write!(f, "#{imm}"),
            }
        }
    }

    impl OperandType for TimeoutProbeOperand {
        type Register = TimeoutProbeRegister;

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
    struct TimeoutProbeInstruction(u8);

    impl std::fmt::Display for TimeoutProbeInstruction {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "probe{}", self.0)
        }
    }

    impl InstructionType for TimeoutProbeInstruction {
        type Register = TimeoutProbeRegister;
        type Operand = TimeoutProbeOperand;

        fn destination(&self) -> Option<Self::Register> {
            Some(TimeoutProbeRegister)
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

    struct TimeoutProbeMutator;

    impl ISAMutator<TimeoutProbeInstruction> for TimeoutProbeMutator {
        fn mutate<R: rand::RngExt>(
            &self,
            _rng: &mut R,
            _sequence: &[TimeoutProbeInstruction],
        ) -> Vec<TimeoutProbeInstruction> {
            vec![TimeoutProbeInstruction(9)]
        }
    }

    impl ISA for TimeoutProbeIsa {
        type Register = TimeoutProbeRegister;
        type Operand = TimeoutProbeOperand;
        type Instruction = TimeoutProbeInstruction;
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
            vec![TimeoutProbeRegister]
        }

        fn zero_register(&self) -> Option<Self::Register> {
            None
        }
    }

    std::thread_local! {
        static RECORDED_SMT_TIMEOUT_MS: std::cell::Cell<Option<u64>> =
            const { std::cell::Cell::new(None) };
    }

    impl StochasticBackend<TimeoutProbeIsa> for TimeoutProbeIsa {
        type State = ();
        type LiveOut = ();

        fn registers_from_config(_config: &SearchConfig) -> Vec<TimeoutProbeRegister> {
            vec![TimeoutProbeRegister]
        }

        fn immediates_from_config(_config: &SearchConfig) -> Vec<i64> {
            vec![0]
        }

        fn make_mutator(_config: &SearchConfig) -> TimeoutProbeMutator {
            TimeoutProbeMutator
        }

        fn make_test_inputs(
            _regs: &[TimeoutProbeRegister],
            _width: u32,
            count: usize,
        ) -> Vec<Self::State> {
            vec![(); count]
        }

        fn make_edge_inputs(_regs: &[TimeoutProbeRegister], _width: u32) -> Vec<Self::State> {
            Vec::new()
        }

        fn apply_sequence(state: Self::State, _seq: &[TimeoutProbeInstruction]) -> Self::State {
            state
        }

        fn states_equal(_s1: &Self::State, _s2: &Self::State, _live_out: &Self::LiveOut) -> bool {
            true
        }

        fn sequence_cost(
            seq: &[TimeoutProbeInstruction],
            _metric: &CostMetric,
            _width: u32,
        ) -> u64 {
            seq.len() as u64
        }

        fn is_encodable(_seq: &[TimeoutProbeInstruction]) -> bool {
            true
        }

        fn check_equivalence(
            _target: &[TimeoutProbeInstruction],
            _proposal: &[TimeoutProbeInstruction],
            _live_out: &Self::LiveOut,
            _width: u32,
            timeout: Duration,
        ) -> (EquivalenceResult, crate::semantics::EquivalenceMetrics) {
            RECORDED_SMT_TIMEOUT_MS.with(|recorded| recorded.set(Some(timeout.as_millis() as u64)));
            (
                EquivalenceResult::Equivalent,
                crate::semantics::EquivalenceMetrics::default(),
            )
        }

        fn random_sequence<R: rand::RngExt>(
            _rng: &mut R,
            len: usize,
            _regs: &[TimeoutProbeRegister],
            _imms: &[i64],
            _config: &SearchConfig,
        ) -> Vec<TimeoutProbeInstruction> {
            vec![TimeoutProbeInstruction(1); len]
        }

        fn width(_config: &SearchConfig) -> u32 {
            64
        }
    }

    fn run_timeout_probe_search(symbolic_config: SymbolicConfig) -> Option<u64> {
        RECORDED_SMT_TIMEOUT_MS.with(|recorded| recorded.set(None));

        let mut search: StochasticSearch<TimeoutProbeIsa> = StochasticSearch::new();
        let config = SearchConfig::default()
            .with_stochastic(
                StochasticConfig::default()
                    .with_iterations(1)
                    .with_test_count(0)
                    .with_seed(1),
            )
            .with_symbolic(symbolic_config);
        let target = [TimeoutProbeInstruction(1), TimeoutProbeInstruction(2)];
        let result = search.search(&target, &(), &config);
        assert_eq!(result.statistics.smt_queries, 1);

        RECORDED_SMT_TIMEOUT_MS.with(|recorded| recorded.get())
    }

    #[test]
    fn stochastic_search_uses_symbolic_solver_timeout_for_smt() {
        let recorded_timeout = run_timeout_probe_search(
            SymbolicConfig::default().with_timeout(Duration::from_millis(17)),
        );

        assert_eq!(recorded_timeout, Some(17));
    }

    #[test]
    fn stochastic_search_falls_back_to_five_seconds_when_solver_timeout_unset() {
        let symbolic_config = SymbolicConfig {
            solver_timeout: None,
            ..SymbolicConfig::default()
        };

        let recorded_timeout = run_timeout_probe_search(symbolic_config);

        assert_eq!(recorded_timeout, Some(5000));
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
    /// instantiates, runs an MCMC loop end-to-end on a 2-instruction
    /// x86 target, and finishes without panic. The target is the
    /// canonical zeroing fusion `mov rax, 0; add rax, rbx` — the
    /// search should at minimum *not crash*, and the iteration counter
    /// should advance.
    #[test]
    fn x86_stochastic_runs_end_to_end() {
        use crate::isa::X86_64;
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::semantics::state::X86LiveOutMask;

        let mut search: StochasticSearch<X86_64> = StochasticSearch::new();
        let config = SearchConfig::default()
            .with_stochastic(
                StochasticConfig::default()
                    .with_iterations(500)
                    .with_seed(7),
            )
            .with_x86_registers(vec![X86Register::RAX, X86Register::RBX, X86Register::RCX])
            .with_immediates(vec![0, 1])
            .with_x86_width(64);

        let live_out = X86LiveOutMask::from_registers(vec![X86Register::RAX]).with_flags(false);

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
        let stats = result.statistics;

        assert_eq!(stats.algorithm, Algorithm::Stochastic);
        assert_eq!(stats.iterations, 500);
        // The search may or may not find an optimisation in 500
        // iterations; we only require that the loop made progress.
        assert!(stats.candidates_evaluated > 0);
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
        use crate::semantics::state::X86LiveOutMask;

        let mut search: StochasticSearch<X86_32> = StochasticSearch::new();
        let config = SearchConfig::default()
            .with_stochastic(
                StochasticConfig::default()
                    .with_iterations(200)
                    .with_seed(11),
            )
            // Mode32 restricts to the low-8 GPRs.
            .with_x86_registers(vec![X86Register::RAX, X86Register::RBX, X86Register::RCX])
            .with_immediates(vec![0, 1])
            .with_x86_width(32);

        let live_out = X86LiveOutMask::from_registers(vec![X86Register::RAX]).with_flags(false);
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
