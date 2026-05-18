//! Markov Chain Monte Carlo (MCMC) search implementation
//!
//! Implements stochastic superoptimization using Metropolis-Hastings MCMC.
//! The algorithm:
//! 1. Generate test cases for fast validation
//! 2. Start with a random initial program (or copy of target)
//! 3. Loop for N iterations:
//!    a. Mutate current program
//!    b. Evaluate on tests (fast rejection if fails)
//!    c. If passes tests with zero cost → verify with SMT

#![allow(dead_code)]
//!    d. Accept/reject based on Metropolis-Hastings criterion
//! 4. Return best found optimization

use crate::ir::Instruction;
use crate::isa::{ISA, ISAMutator};
use crate::search::config::SearchConfig;
use crate::search::result::{SearchResultFor, SearchStatistics};
use crate::search::stochastic::acceptance::AcceptanceCriterion;
use crate::search::stochastic::backend::StochasticBackend;
use crate::search::{Algorithm, SearchAlgorithm};
use crate::semantics::EquivalenceResult;
use crate::semantics::concrete::{apply_sequence_concrete, states_equal_for_live_out};
use crate::semantics::live_out::LiveOutRegisters;
use crate::semantics::state::ConcreteMachineState;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// Stochastic search using Metropolis-Hastings MCMC, generic over ISA.
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

        // Start with target sequence or random sequence of same length
        let mut current = if rng.random_bool(0.5) {
            target.to_vec()
        } else {
            loop {
                let seq = <I as StochasticBackend<I>>::random_sequence(
                    &mut rng,
                    target.len(),
                    &regs,
                    &imms,
                    config,
                );
                if <I as StochasticBackend<I>>::is_encodable(&seq) {
                    break seq;
                }
            }
        };
        let mut current_cost =
            <I as StochasticBackend<I>>::sequence_cost(&current, &config.cost_metric, width);

        let mut best_equivalent: Option<Vec<I::Instruction>> = None;
        let mut best_cost = original_cost;

        let min_length = 1;
        let max_length = target.len();
        let smt_timeout = Duration::from_secs(5);

        for iteration in 0..config.stochastic.iterations {
            self.statistics.iterations = iteration + 1;

            if config.timeout.is_some_and(|t| start_time.elapsed() >= t) {
                if config.verbose {
                    println!("Search timed out after {} iterations", iteration);
                }
                break;
            }

            // Occasionally try a different length
            if rng.random_bool(0.1) && max_length > min_length {
                let new_len = rng.random_range(min_length..=max_length);
                if new_len != current.len() {
                    loop {
                        let seq = <I as StochasticBackend<I>>::random_sequence(
                            &mut rng, new_len, &regs, &imms, config,
                        );
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

                match <I as StochasticBackend<I>>::check_equivalence(
                    target,
                    &proposal,
                    live_out,
                    width,
                    smt_timeout,
                ) {
                    EquivalenceResult::Equivalent => {
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
                    _ => {}
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
    live_out: &LiveOutRegisters,
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
    use crate::isa::AArch64;
    use crate::search::config::StochasticConfig;
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
        }];

        let input = ConcreteMachineState::new_zeroed();
        let target_output = apply_sequence_concrete(input.clone(), &target);

        let live_out = LiveOutRegisters::from_registers(vec![Register::X0]);
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

        let live_out = LiveOutRegisters::from_registers(vec![Register::X0]);
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
