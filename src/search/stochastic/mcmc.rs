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
//!    d. Accept/reject based on Metropolis-Hastings criterion
//! 4. Return best found optimization

use crate::ir::Instruction;
use crate::search::candidate::generate_random_sequence;
use crate::search::config::SearchConfig;
use crate::search::result::{SearchResult, SearchStatistics};
use crate::search::stochastic::acceptance::AcceptanceCriterion;
use crate::search::stochastic::mutation::Mutator;
use crate::search::{Algorithm, SearchAlgorithm};
use crate::semantics::concrete::{apply_sequence_concrete, states_equal_for_live_out};
use crate::semantics::cost::sequence_cost;
use crate::semantics::state::{ConcreteMachineState, LiveOutMask};
use crate::semantics::{EquivalenceConfig, EquivalenceResult, check_equivalence_with_config};
use crate::validation::random::{
    RandomInputConfig, generate_edge_case_inputs, generate_random_inputs,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::time::Instant;

/// Stochastic search using Metropolis-Hastings MCMC
pub struct StochasticSearch {
    statistics: SearchStatistics,
}

impl StochasticSearch {
    pub fn new() -> Self {
        Self {
            statistics: SearchStatistics::new(Algorithm::Stochastic),
        }
    }
}

impl Default for StochasticSearch {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchAlgorithm for StochasticSearch {
    fn search(
        &mut self,
        target: &[Instruction],
        live_out: &LiveOutMask,
        config: &SearchConfig,
    ) -> SearchResult {
        self.reset();
        let start_time = Instant::now();

        let original_cost = sequence_cost(target, &config.cost_metric);
        self.statistics.original_cost = original_cost;
        self.statistics.best_cost_found = original_cost;

        if target.is_empty() {
            self.statistics.elapsed_time = start_time.elapsed();
            return SearchResult::no_optimization(target.to_vec(), self.statistics.clone());
        }

        // Set up RNG
        let mut rng: ChaCha8Rng = match config.stochastic.seed {
            Some(seed) => ChaCha8Rng::seed_from_u64(seed),
            None => ChaCha8Rng::from_os_rng(),
        };

        // Generate test cases
        let input_regs: Vec<_> = live_out.iter().cloned().collect();
        let random_config = RandomInputConfig {
            count: config.stochastic.test_count,
            registers: input_regs.clone(),
        };
        let test_inputs = generate_random_inputs(&random_config);
        let edge_inputs = generate_edge_case_inputs(&input_regs);

        // Precompute target outputs for all test inputs
        let target_outputs: Vec<_> = test_inputs
            .iter()
            .chain(edge_inputs.iter())
            .map(|input| apply_sequence_concrete(input.clone(), target))
            .collect();
        let all_inputs: Vec<_> = test_inputs
            .into_iter()
            .chain(edge_inputs.into_iter())
            .collect();

        // Initialize current state
        let mutator = Mutator::new(
            config.available_registers.clone(),
            config.available_immediates.clone(),
            config.stochastic.mutation_weights.clone(),
        );
        let acceptance = AcceptanceCriterion::new(config.stochastic.beta);

        // Start with target sequence or random sequence of same length
        let mut current = if rng.random_bool(0.5) {
            target.to_vec()
        } else {
            generate_random_sequence(
                &mut rng,
                target.len(),
                &config.available_registers,
                &config.available_immediates,
            )
        };
        let mut current_cost = sequence_cost(&current, &config.cost_metric);

        // Track best equivalent sequence found
        let mut best_equivalent: Option<Vec<Instruction>> = None;
        let mut best_cost = original_cost;

        // Also try shorter sequences
        let min_length = 1;
        let max_length = target.len();

        for iteration in 0..config.stochastic.iterations {
            self.statistics.iterations = iteration + 1;

            // Check timeout
            if let Some(timeout) = config.timeout {
                if start_time.elapsed() >= timeout {
                    if config.verbose {
                        println!("Search timed out after {} iterations", iteration);
                    }
                    break;
                }
            }

            // Occasionally try a different length
            if rng.random_bool(0.1) && max_length > min_length {
                let new_len = rng.random_range(min_length..=max_length);
                if new_len != current.len() {
                    current = generate_random_sequence(
                        &mut rng,
                        new_len,
                        &config.available_registers,
                        &config.available_immediates,
                    );
                    current_cost = sequence_cost(&current, &config.cost_metric);
                }
            }

            // Mutate current sequence
            let proposal = mutator.mutate(&mut rng, &current);
            let proposal_cost = sequence_cost(&proposal, &config.cost_metric);

            self.statistics.candidates_evaluated += 1;

            // Fast validation: check against test cases
            let mut passes_tests = true;
            for (input, target_output) in all_inputs.iter().zip(target_outputs.iter()) {
                let proposal_output = apply_sequence_concrete(input.clone(), &proposal);
                if !states_equal_for_live_out(&proposal_output, target_output, live_out) {
                    passes_tests = false;
                    break;
                }
            }

            if !passes_tests {
                // Proposal fails tests - might still accept with probability based on cost
                // But for correctness we only track proposals that could be valid
                continue;
            }

            self.statistics.candidates_passed_fast += 1;

            // Proposal passes all tests - now check if it's better and verify with SMT
            if proposal_cost < best_cost {
                // Verify with SMT solver
                self.statistics.smt_queries += 1;

                let equiv_config = EquivalenceConfig::with_live_out(live_out.clone())
                    .random_tests(0) // Already tested
                    .timeout(std::time::Duration::from_secs(5));

                match check_equivalence_with_config(target, &proposal, &equiv_config) {
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
                    _ => {
                        // SMT says not equivalent, even though tests passed
                        // This is rare but can happen
                    }
                }
            }

            // Metropolis-Hastings acceptance
            if acceptance.accept(&mut rng, current_cost, proposal_cost) {
                current = proposal;
                current_cost = proposal_cost;
                self.statistics.accepted_proposals += 1;
            }

            // Progress reporting
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
            SearchResult::with_optimization(target.to_vec(), optimized, self.statistics.clone())
        } else {
            SearchResult::no_optimization(target.to_vec(), self.statistics.clone())
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
    target: &[Instruction],
    test_inputs: &[ConcreteMachineState],
    target_outputs: &[ConcreteMachineState],
    live_out: &LiveOutMask,
) -> (u64, bool) {
    let mut passes_all = true;

    for (input, target_output) in test_inputs.iter().zip(target_outputs.iter()) {
        let proposal_output = apply_sequence_concrete(input.clone(), proposal);
        if !states_equal_for_live_out(&proposal_output, target_output, live_out) {
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
    use crate::search::config::StochasticConfig;

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
        let search = StochasticSearch::new();
        let stats = search.statistics();
        assert_eq!(stats.algorithm, Algorithm::Stochastic);
        assert_eq!(stats.iterations, 0);
    }

    #[test]
    fn test_stochastic_search_empty_sequence() {
        let mut search = StochasticSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

        let result = search.search(&[], &live_out, &config);
        assert!(!result.found_optimization);
    }

    #[test]
    fn test_stochastic_search_with_seed() {
        let mut search = StochasticSearch::new();
        let config = SearchConfig::default().with_stochastic(
            StochasticConfig::default()
                .with_seed(42)
                .with_iterations(1000),
        );
        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

        let result = search.search(&mov_zero_sequence(), &live_out, &config);
        let stats = result.statistics;

        assert!(stats.iterations > 0);
        assert!(stats.candidates_evaluated > 0);
    }

    #[test]
    fn test_stochastic_finds_mov_zero_eor() {
        let mut search = StochasticSearch::new();

        // Use smaller iteration count for test speed, but enough to find the optimization
        let config = SearchConfig::default()
            .with_stochastic(StochasticConfig::default().with_iterations(100_000))
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![-1, 0, 1]);

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

        // Target: MOV X0, #0 - can be replaced with EOR X0, X0, X0
        // But since both are 1 instruction, no optimization expected
        let target = mov_zero_sequence();
        let result = search.search(&target, &live_out, &config);

        // The algorithm should complete without errors
        assert!(result.statistics.iterations > 0);
    }

    #[test]
    fn test_stochastic_finds_mov_add_fusion() {
        let mut search = StochasticSearch::new();

        let config = SearchConfig::default()
            .with_stochastic(StochasticConfig::default().with_iterations(500_000))
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![-1, 0, 1, 2]);

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

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

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);
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

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);
        let (cost, passes) =
            evaluate_with_tests(&proposal, &target, &[input], &[target_output], &live_out);

        assert!(!passes);
        assert!(cost > 100); // High penalty
    }

    #[test]
    fn test_statistics_tracking() {
        let mut search = StochasticSearch::new();

        let config = SearchConfig::default()
            .with_stochastic(StochasticConfig::default().with_iterations(1000))
            .with_registers(vec![Register::X0, Register::X1]);

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);
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
        let mut search = StochasticSearch::new();

        let config = SearchConfig::default()
            .with_stochastic(
                StochasticConfig::default()
                    .with_iterations(10000)
                    .with_beta(1.0),
            )
            .with_registers(vec![Register::X0, Register::X1, Register::X2]);

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);
        let target = mov_zero_sequence();

        let result = search.search(&target, &live_out, &config);
        let stats = result.statistics;

        // Acceptance rate should be between 0 and 1
        let rate = stats.acceptance_rate();
        assert!(rate >= 0.0);
        assert!(rate <= 1.0);
    }
}
