//! SMT-based synthesis for superoptimization
//!
//! This module implements symbolic search using Z3 for equivalence verification.
//! The approach uses linear cost search: try sequences of length 1, 2, ... up to
//! the target length - 1, and for each length, enumerate candidates and verify
//! equivalence with SMT.
//!
//! Note: Full symbolic synthesis with symbolic opcodes/operands is very complex.
//! This implementation uses a hybrid approach: enumerate concrete candidates
//! and verify them with SMT, rather than synthesizing from purely symbolic sketches.

use crate::ir::Instruction;
use crate::search::candidate::generate_all_instructions;
use crate::search::config::{SearchConfig, SearchMode};
use crate::search::result::{SearchResult, SearchStatistics};
use crate::search::{Algorithm, SearchAlgorithm};
use crate::semantics::cost::sequence_cost;
use crate::semantics::state::LiveOutMask;
use crate::semantics::{EquivalenceConfig, EquivalenceResult, check_equivalence_with_config};
use std::time::{Duration, Instant};

/// Symbolic search using SMT-based synthesis
pub struct SymbolicSearch {
    statistics: SearchStatistics,
}

impl SymbolicSearch {
    pub fn new() -> Self {
        Self {
            statistics: SearchStatistics::new(Algorithm::Symbolic),
        }
    }

    /// Linear cost search: try each length from 1 to target length - 1
    fn linear_search(
        &mut self,
        target: &[Instruction],
        live_out: &LiveOutMask,
        config: &SearchConfig,
        start_time: Instant,
    ) -> Option<Vec<Instruction>> {
        let all_instructions =
            generate_all_instructions(&config.available_registers, &config.available_immediates);

        let original_cost = sequence_cost(target, &config.cost_metric);
        let mut best_solution: Option<Vec<Instruction>> = None;
        let mut best_cost = original_cost;

        // Try sequences of increasing length
        for length in 1..target.len() {
            if config.verbose {
                println!("Searching for equivalent sequences of length {}...", length);
            }

            // Check timeout
            if let Some(timeout) = config.timeout {
                if start_time.elapsed() >= timeout {
                    if config.verbose {
                        println!("Search timed out");
                    }
                    break;
                }
            }

            // Generate and test all sequences of this length
            let found = self.search_at_length(
                target,
                live_out,
                config,
                &all_instructions,
                length,
                &mut best_cost,
                start_time,
            );

            if let Some(seq) = found {
                best_solution = Some(seq);
                // In linear search, we found a solution at this length
                // Continue to see if there's an even shorter one
            }
        }

        best_solution
    }

    /// Search for equivalent sequences at a specific length
    fn search_at_length(
        &mut self,
        target: &[Instruction],
        live_out: &LiveOutMask,
        config: &SearchConfig,
        all_instructions: &[Instruction],
        length: usize,
        best_cost: &mut u64,
        start_time: Instant,
    ) -> Option<Vec<Instruction>> {
        let mut best_at_length: Option<Vec<Instruction>> = None;

        if length == 1 {
            // Single instruction search
            for instr in all_instructions {
                // Check timeout
                if let Some(timeout) = config.timeout {
                    if start_time.elapsed() >= timeout {
                        return best_at_length;
                    }
                }

                let candidate = vec![*instr];
                let candidate_cost = sequence_cost(&candidate, &config.cost_metric);

                if candidate_cost >= *best_cost {
                    continue;
                }

                self.statistics.candidates_evaluated += 1;

                if self.verify_equivalence(target, &candidate, live_out, config) {
                    *best_cost = candidate_cost;
                    best_at_length = Some(candidate);
                    self.statistics.improvements_found += 1;

                    if config.verbose {
                        println!("Found equivalent: {} (cost {})", instr, candidate_cost);
                    }
                }
            }
        } else if length == 2 {
            // Two instruction search
            for instr1 in all_instructions {
                // Check timeout periodically
                if let Some(timeout) = config.timeout {
                    if start_time.elapsed() >= timeout {
                        return best_at_length;
                    }
                }

                for instr2 in all_instructions {
                    let candidate = vec![*instr1, *instr2];
                    let candidate_cost = sequence_cost(&candidate, &config.cost_metric);

                    if candidate_cost >= *best_cost {
                        continue;
                    }

                    self.statistics.candidates_evaluated += 1;

                    if self.verify_equivalence(target, &candidate, live_out, config) {
                        *best_cost = candidate_cost;
                        best_at_length = Some(candidate);
                        self.statistics.improvements_found += 1;

                        if config.verbose {
                            println!(
                                "Found equivalent: {}; {} (cost {})",
                                instr1, instr2, candidate_cost
                            );
                        }
                    }
                }
            }
        } else {
            // For length >= 3, use iterative deepening with early termination
            // This is a simplified version - full enumeration is exponential
            let sample_size = 10000; // Limit candidates to sample
            let mut count = 0;

            for instr1 in all_instructions {
                if count >= sample_size {
                    break;
                }
                if let Some(timeout) = config.timeout {
                    if start_time.elapsed() >= timeout {
                        return best_at_length;
                    }
                }

                for instr2 in all_instructions {
                    if count >= sample_size {
                        break;
                    }

                    for instr3 in all_instructions {
                        if count >= sample_size {
                            break;
                        }

                        let candidate = if length == 3 {
                            vec![*instr1, *instr2, *instr3]
                        } else {
                            // For longer sequences, fill with first instruction
                            let mut seq = vec![*instr1, *instr2, *instr3];
                            while seq.len() < length {
                                seq.push(all_instructions[0]);
                            }
                            seq
                        };

                        let candidate_cost = sequence_cost(&candidate, &config.cost_metric);

                        if candidate_cost >= *best_cost {
                            count += 1;
                            continue;
                        }

                        self.statistics.candidates_evaluated += 1;

                        if self.verify_equivalence(target, &candidate, live_out, config) {
                            *best_cost = candidate_cost;
                            best_at_length = Some(candidate.clone());
                            self.statistics.improvements_found += 1;

                            if config.verbose {
                                println!(
                                    "Found equivalent sequence of length {} (cost {})",
                                    length, candidate_cost
                                );
                            }
                        }

                        count += 1;
                    }
                }
            }
        }

        best_at_length
    }

    /// Verify equivalence using SMT
    fn verify_equivalence(
        &mut self,
        target: &[Instruction],
        candidate: &[Instruction],
        live_out: &LiveOutMask,
        config: &SearchConfig,
    ) -> bool {
        let timeout = config
            .symbolic
            .solver_timeout
            .unwrap_or(Duration::from_secs(5));

        let equiv_config = EquivalenceConfig::with_live_out(live_out.clone())
            .random_tests(5) // Quick pre-filter with tests
            .timeout(timeout);

        self.statistics.smt_queries += 1;

        match check_equivalence_with_config(target, candidate, &equiv_config) {
            EquivalenceResult::Equivalent => {
                self.statistics.smt_equivalent += 1;
                self.statistics.candidates_passed_fast += 1;
                true
            }
            EquivalenceResult::NotEquivalentFast(_) => {
                // Failed fast test, no SMT query needed
                self.statistics.smt_queries -= 1; // Don't count as SMT query
                false
            }
            _ => false,
        }
    }

    /// Binary search on cost bound (not fully implemented yet)
    #[allow(dead_code)]
    fn binary_search(
        &mut self,
        _target: &[Instruction],
        _live_out: &LiveOutMask,
        _config: &SearchConfig,
        _start_time: Instant,
    ) -> Option<Vec<Instruction>> {
        // Binary search would use SMT with cost constraints
        // For now, fall back to linear search
        None
    }
}

impl Default for SymbolicSearch {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchAlgorithm for SymbolicSearch {
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

        if target.is_empty() || target.len() == 1 {
            self.statistics.elapsed_time = start_time.elapsed();
            return SearchResult::no_optimization(target.to_vec(), self.statistics.clone());
        }

        let result = match config.symbolic.search_mode {
            SearchMode::Linear => self.linear_search(target, live_out, config, start_time),
            SearchMode::Binary => {
                // Binary search not fully implemented, fall back to linear
                self.linear_search(target, live_out, config, start_time)
            }
        };

        self.statistics.elapsed_time = start_time.elapsed();

        if let Some(optimized) = result {
            self.statistics.best_cost_found = sequence_cost(&optimized, &config.cost_metric);
            SearchResult::with_optimization(target.to_vec(), optimized, self.statistics.clone())
        } else {
            SearchResult::no_optimization(target.to_vec(), self.statistics.clone())
        }
    }

    fn statistics(&self) -> SearchStatistics {
        self.statistics.clone()
    }

    fn reset(&mut self) {
        self.statistics = SearchStatistics::new(Algorithm::Symbolic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};
    use crate::search::config::SymbolicConfig;

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
    fn test_symbolic_search_creation() {
        let search = SymbolicSearch::new();
        let stats = search.statistics();
        assert_eq!(stats.algorithm, Algorithm::Symbolic);
    }

    #[test]
    fn test_symbolic_search_empty_sequence() {
        let mut search = SymbolicSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

        let result = search.search(&[], &live_out, &config);
        assert!(!result.found_optimization);
    }

    #[test]
    fn test_symbolic_search_single_instruction() {
        let mut search = SymbolicSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

        // Single instruction can't be optimized to shorter
        let result = search.search(&mov_zero_sequence(), &live_out, &config);
        assert!(!result.found_optimization);
    }

    #[test]
    fn test_symbolic_finds_mov_add_fusion() {
        let mut search = SymbolicSearch::new();

        let config = SearchConfig::default()
            .with_symbolic(SymbolicConfig::default().with_timeout(Duration::from_secs(10)))
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![-1, 0, 1, 2]);

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

        // Target: MOV X0, X1; ADD X0, X0, #1 (2 instructions)
        // Should find an equivalent 1-instruction sequence (e.g., ADD X0, X1, #1)
        let target = mov_add_sequence();
        let result = search.search(&target, &live_out, &config);

        assert!(result.found_optimization);
        assert_eq!(result.cost_savings(), 1);

        // Verify we found a 1-instruction equivalent sequence
        if let Some(ref optimized) = result.optimized_sequence {
            assert_eq!(optimized.len(), 1);
            // The instruction should write to X0
            assert_eq!(optimized[0].destination(), Some(Register::X0));
        }
    }

    #[test]
    fn test_symbolic_statistics() {
        let mut search = SymbolicSearch::new();

        let config = SearchConfig::default()
            .with_symbolic(SymbolicConfig::default())
            .with_registers(vec![Register::X0, Register::X1]);

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);
        let target = mov_add_sequence();

        let result = search.search(&target, &live_out, &config);
        let stats = result.statistics;

        assert_eq!(stats.algorithm, Algorithm::Symbolic);
        assert!(stats.elapsed_time.as_nanos() > 0);
        assert!(stats.candidates_evaluated > 0);
    }

    #[test]
    fn test_symbolic_respects_live_out() {
        let mut search = SymbolicSearch::new();

        let config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![0, 1]);

        // Only X0 is live-out, X1 can differ
        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

        // Target modifies both X0 and X1
        let target = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::MovImm {
                rd: Register::X1,
                imm: 1,
            },
        ];

        let result = search.search(&target, &live_out, &config);

        // Should find optimization since X1 doesn't need to match
        // MOV X0, #0 is sufficient (or EOR X0, X0, X0)
        assert!(result.found_optimization);
        assert_eq!(result.cost_savings(), 1);
    }

    #[test]
    fn test_verify_equivalence() {
        let mut search = SymbolicSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

        // These should be equivalent
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let candidate = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];

        assert!(search.verify_equivalence(&target, &candidate, &live_out, &config));
    }

    #[test]
    fn test_verify_non_equivalence() {
        let mut search = SymbolicSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

        // These should NOT be equivalent
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let candidate = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];

        assert!(!search.verify_equivalence(&target, &candidate, &live_out, &config));
    }
}
