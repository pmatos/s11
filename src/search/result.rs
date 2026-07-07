//! Search result types and statistics

#![allow(dead_code)]

use crate::ir::Instruction;
use crate::isa::ISA;
use crate::search::config::Algorithm;
use crate::semantics::{EquivalenceMetrics, EquivalenceResult};
use std::time::Duration;

/// Result of a search operation
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The best equivalent sequence found (if any)
    pub optimized_sequence: Option<Vec<Instruction>>,
    /// The original target sequence
    pub original_sequence: Vec<Instruction>,
    /// Whether an optimization was found (sequence is cheaper than original)
    pub found_optimization: bool,
    /// Statistics from the search
    pub statistics: SearchStatistics,
}

impl SearchResult {
    /// Create a new search result with no optimization found
    pub fn no_optimization(original: Vec<Instruction>, statistics: SearchStatistics) -> Self {
        Self {
            optimized_sequence: None,
            original_sequence: original,
            found_optimization: false,
            statistics,
        }
    }

    /// Create a new search result with an optimization found
    pub fn with_optimization(
        original: Vec<Instruction>,
        optimized: Vec<Instruction>,
        statistics: SearchStatistics,
    ) -> Self {
        Self {
            optimized_sequence: Some(optimized),
            original_sequence: original,
            found_optimization: true,
            statistics,
        }
    }

    /// Get the cost savings (original cost - optimized cost)
    pub fn cost_savings(&self) -> i64 {
        if let Some(ref optimized) = self.optimized_sequence {
            self.original_sequence.len() as i64 - optimized.len() as i64
        } else {
            0
        }
    }
}

/// Generic search-result type. For AArch64, callers can ignore the
/// type parameter (it defaults to `AArch64`) and treat
/// `SearchResultFor<AArch64>` as the historical `SearchResult`.
///
/// Mirrors `SearchResult` for `<I>`. Lives in this module so both
/// stochastic and symbolic search consume the same shape without
/// either depending on the other.
#[derive(Debug, Clone)]
pub struct SearchResultFor<I: ISA> {
    pub optimized_sequence: Option<Vec<I::Instruction>>,
    pub original_sequence: Vec<I::Instruction>,
    pub found_optimization: bool,
    pub statistics: SearchStatistics,
}

impl<I: ISA> SearchResultFor<I> {
    /// Cost savings = original length minus optimized length, or 0 if
    /// no optimization was found. Mirrors `SearchResult::cost_savings`.
    pub fn cost_savings(&self) -> i64 {
        if let Some(ref opt) = self.optimized_sequence {
            self.original_sequence.len() as i64 - opt.len() as i64
        } else {
            0
        }
    }

    pub fn no_optimization(original: Vec<I::Instruction>, statistics: SearchStatistics) -> Self {
        Self {
            optimized_sequence: None,
            original_sequence: original,
            found_optimization: false,
            statistics,
        }
    }

    pub fn with_optimization(
        original: Vec<I::Instruction>,
        optimized: Vec<I::Instruction>,
        statistics: SearchStatistics,
    ) -> Self {
        Self {
            optimized_sequence: Some(optimized),
            original_sequence: original,
            found_optimization: true,
            statistics,
        }
    }
}

/// Backward-compatible conversion from the generic result type into the
/// AArch64-specific `SearchResult`. Used by the parallel coordinator
/// (still AArch64-typed) and any consumer that hasn't been migrated to
/// the generic shape.
impl From<SearchResultFor<crate::isa::AArch64>> for SearchResult {
    fn from(r: SearchResultFor<crate::isa::AArch64>) -> Self {
        if let Some(opt) = r.optimized_sequence {
            SearchResult::with_optimization(r.original_sequence, opt, r.statistics)
        } else {
            SearchResult::no_optimization(r.original_sequence, r.statistics)
        }
    }
}

/// The counter deltas produced by folding one candidate verification into a
/// [`SearchStatistics`].
///
/// This separates the *policy* — what a verification outcome means for the
/// counters — from the *sink* it is applied to. The symbolic search path folds
/// the tally into plain `&mut SearchStatistics` fields; the parallel enumerative
/// path applies the same tally to its atomic counters. Both share one definition
/// via [`SearchStatistics::verification_tally`], so the two paths cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerificationTally {
    /// Wall-clock time this verification spent inside `solver.check()`. Folds
    /// into `smt_elapsed`. `Duration::ZERO` when the solver was not invoked.
    pub smt_elapsed: Duration,
    /// Whether the verification reached Z3 (`EquivalenceMetrics::smt_called`).
    ///
    /// When true the candidate counts as *both* an SMT query and a fast-
    /// validation pass, even if Z3 later disproved it: reaching the solver means
    /// it cleared the concrete pre-filter. Fast-path refutations and the pre-SMT
    /// flag-writer guard leave `smt_called` false, so neither is counted here.
    pub reached_solver: bool,
    /// Whether Z3 proved the candidate equivalent to the target. Folds into
    /// `smt_equivalent`.
    pub proved_equivalent: bool,
}

/// Statistics from a search operation
#[derive(Debug, Clone, Default)]
pub struct SearchStatistics {
    /// Algorithm used for the search
    pub algorithm: Algorithm,
    /// Total time spent searching
    pub elapsed_time: Duration,
    /// Number of candidates constructed and considered by the search.
    /// This includes candidates later rejected by a cost/best-bound gate.
    pub candidates_evaluated: u64,
    /// Number of evaluated candidates rejected before verification because
    /// they were not cheaper than the current best solution.
    pub candidates_pruned_by_cost: u64,
    /// Number of candidates that passed fast (concrete) validation
    pub candidates_passed_fast: u64,
    /// Number of SMT solver queries that reached Z3 `solver.check()`.
    /// Fast-path refutations and other pre-SMT exits are not counted.
    pub smt_queries: u64,
    /// Cumulative wall-clock time spent inside Z3 `solver.check()` calls,
    /// aggregated across every SMT-reaching candidate during the search.
    /// `Duration::ZERO` when no candidate reached the solver.
    pub smt_elapsed: Duration,
    /// Number of SMT queries that proved equivalence
    pub smt_equivalent: u64,
    /// Number of iterations (for stochastic search)
    pub iterations: u64,
    /// Number of accepted proposals (for stochastic search)
    pub accepted_proposals: u64,
    /// Best cost found during search
    pub best_cost_found: u64,
    /// Original sequence cost
    pub original_cost: u64,
    /// Number of times the search improved the current best
    pub improvements_found: u64,
}

impl SearchStatistics {
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            ..Default::default()
        }
    }

    /// The canonical policy mapping one equivalence verification to its counter
    /// deltas.
    ///
    /// This is the single source of truth for how a `(metrics, verdict)` pair
    /// updates the SMT counters, shared by both the symbolic and the parallel
    /// enumerative verification paths. See [`VerificationTally`] for what each
    /// field counts.
    pub fn verification_tally(
        metrics: &EquivalenceMetrics,
        verdict: &EquivalenceResult,
    ) -> VerificationTally {
        VerificationTally {
            smt_elapsed: metrics.smt_elapsed,
            reached_solver: metrics.smt_called,
            proved_equivalent: matches!(verdict, EquivalenceResult::Equivalent),
        }
    }

    /// Fold one equivalence verification into the (single-threaded) SMT
    /// counters, returning whether the candidate proved equivalent.
    ///
    /// Used by the symbolic search path. The parallel enumerative path applies
    /// the same [`Self::verification_tally`] to its atomic counters instead of
    /// calling this method, so both paths agree on what each counter means.
    pub fn record_verification(
        &mut self,
        metrics: &EquivalenceMetrics,
        verdict: &EquivalenceResult,
    ) -> bool {
        let tally = Self::verification_tally(metrics, verdict);
        self.smt_elapsed += tally.smt_elapsed;
        if tally.reached_solver {
            self.smt_queries += 1;
            self.candidates_passed_fast += 1;
        }
        if tally.proved_equivalent {
            self.smt_equivalent += 1;
        }
        tally.proved_equivalent
    }

    /// Record the start of timing
    pub fn start_timer(&mut self) {
        self.elapsed_time = Duration::ZERO;
    }

    /// Get acceptance rate for stochastic search (0.0 to 1.0)
    pub fn acceptance_rate(&self) -> f64 {
        if self.iterations == 0 {
            0.0
        } else {
            self.accepted_proposals as f64 / self.iterations as f64
        }
    }

    /// Get the rate of candidates passing fast validation
    pub fn fast_pass_rate(&self) -> f64 {
        if self.candidates_evaluated == 0 {
            0.0
        } else {
            self.candidates_passed_fast as f64 / self.candidates_evaluated as f64
        }
    }

    /// Get the rate of SMT queries proving equivalence
    pub fn smt_success_rate(&self) -> f64 {
        if self.smt_queries == 0 {
            0.0
        } else {
            self.smt_equivalent as f64 / self.smt_queries as f64
        }
    }

    /// Get candidates evaluated per second
    pub fn throughput(&self) -> f64 {
        let secs = self.elapsed_time.as_secs_f64();
        if secs == 0.0 {
            0.0
        } else {
            self.candidates_evaluated as f64 / secs
        }
    }

    /// Format statistics as a human-readable string
    pub fn format_summary(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Algorithm: {}\n", self.algorithm));
        s.push_str(&format!("Time: {:.2?}\n", self.elapsed_time));
        s.push_str(&format!(
            "Candidates evaluated: {}\n",
            self.candidates_evaluated
        ));
        if self.candidates_pruned_by_cost > 0 {
            s.push_str(&format!(
                "Candidates pruned by cost: {}\n",
                self.candidates_pruned_by_cost
            ));
        }
        s.push_str(&format!(
            "Throughput: {:.0} candidates/sec\n",
            self.throughput()
        ));

        if self.candidates_passed_fast > 0 {
            s.push_str(&format!(
                "Fast pass rate: {:.2}%\n",
                self.fast_pass_rate() * 100.0
            ));
        }

        if self.smt_queries > 0 {
            s.push_str(&format!("SMT queries: {}\n", self.smt_queries));
            s.push_str(&format!(
                "SMT success rate: {:.2}%\n",
                self.smt_success_rate() * 100.0
            ));
        }

        if self.algorithm == Algorithm::Stochastic && self.iterations > 0 {
            s.push_str(&format!("Iterations: {}\n", self.iterations));
            s.push_str(&format!(
                "Acceptance rate: {:.2}%\n",
                self.acceptance_rate() * 100.0
            ));
        }

        s.push_str(&format!("Original cost: {}\n", self.original_cost));
        s.push_str(&format!("Best cost found: {}\n", self.best_cost_found));
        s.push_str(&format!(
            "Improvements found: {}\n",
            self.improvements_found
        ));

        s
    }
}

impl std::fmt::Display for SearchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.found_optimization {
            writeln!(f, "Optimization found!")?;
            writeln!(
                f,
                "Original sequence ({} instructions):",
                self.original_sequence.len()
            )?;
            for instr in &self.original_sequence {
                writeln!(f, "  {}", instr)?;
            }
            if let Some(ref optimized) = self.optimized_sequence {
                writeln!(f, "Optimized sequence ({} instructions):", optimized.len())?;
                for instr in optimized {
                    writeln!(f, "  {}", instr)?;
                }
                writeln!(f, "Savings: {} instructions", self.cost_savings())?;
            }
        } else {
            writeln!(f, "No optimization found.")?;
            writeln!(
                f,
                "Original sequence ({} instructions):",
                self.original_sequence.len()
            )?;
            for instr in &self.original_sequence {
                writeln!(f, "  {}", instr)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};

    fn sample_sequence() -> Vec<Instruction> {
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

    fn optimized_sequence() -> Vec<Instruction> {
        vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }]
    }

    #[test]
    fn test_search_result_no_optimization() {
        let stats = SearchStatistics::default();
        let result = SearchResult::no_optimization(sample_sequence(), stats);

        assert!(!result.found_optimization);
        assert!(result.optimized_sequence.is_none());
        assert_eq!(result.cost_savings(), 0);
    }

    #[test]
    fn test_search_result_with_optimization() {
        let stats = SearchStatistics::default();
        let result =
            SearchResult::with_optimization(sample_sequence(), optimized_sequence(), stats);

        assert!(result.found_optimization);
        assert!(result.optimized_sequence.is_some());
        assert_eq!(result.cost_savings(), 1);
    }

    #[test]
    fn test_statistics_acceptance_rate() {
        let mut stats = SearchStatistics::new(Algorithm::Stochastic);
        stats.iterations = 1000;
        stats.accepted_proposals = 250;

        assert!((stats.acceptance_rate() - 0.25).abs() < 1e-10);
    }

    #[test]
    fn test_statistics_fast_pass_rate() {
        let mut stats = SearchStatistics::default();
        stats.candidates_evaluated = 100;
        stats.candidates_passed_fast = 10;

        assert!((stats.fast_pass_rate() - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_statistics_smt_success_rate() {
        let mut stats = SearchStatistics::default();
        stats.smt_queries = 50;
        stats.smt_equivalent = 5;

        assert!((stats.smt_success_rate() - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_statistics_throughput() {
        let mut stats = SearchStatistics::default();
        stats.candidates_evaluated = 10000;
        stats.elapsed_time = Duration::from_secs(10);

        assert!((stats.throughput() - 1000.0).abs() < 1e-10);
    }

    #[test]
    fn test_statistics_zero_division() {
        let stats = SearchStatistics::default();
        assert_eq!(stats.acceptance_rate(), 0.0);
        assert_eq!(stats.fast_pass_rate(), 0.0);
        assert_eq!(stats.smt_success_rate(), 0.0);
        assert_eq!(stats.throughput(), 0.0);
    }

    #[test]
    fn test_format_summary_includes_optional_sections() {
        let mut stats = SearchStatistics::new(Algorithm::Stochastic);
        stats.start_timer();
        stats.elapsed_time = Duration::from_millis(500);
        stats.candidates_evaluated = 100;
        stats.candidates_pruned_by_cost = 7;
        stats.candidates_passed_fast = 25;
        stats.smt_queries = 10;
        stats.smt_equivalent = 2;
        stats.iterations = 50;
        stats.accepted_proposals = 5;
        stats.original_cost = 3;
        stats.best_cost_found = 2;
        stats.improvements_found = 1;

        let summary = stats.format_summary();
        assert!(summary.contains("Algorithm: stochastic"));
        assert!(summary.contains("Candidates pruned by cost: 7"));
        assert!(summary.contains("Fast pass rate"));
        assert!(summary.contains("SMT queries"));
        assert!(summary.contains("Acceptance rate"));
        assert!(summary.contains("Improvements found: 1"));
    }

    #[test]
    fn test_display_for_search_results() {
        let stats = SearchStatistics::default();
        let no_opt = SearchResult::no_optimization(sample_sequence(), stats.clone());
        let no_opt_text = format!("{}", no_opt);
        assert!(no_opt_text.contains("No optimization found."));
        assert!(no_opt_text.contains("Original sequence"));
        assert!(no_opt_text.contains("mov x0, x1"));

        let with_opt =
            SearchResult::with_optimization(sample_sequence(), optimized_sequence(), stats);
        let with_opt_text = format!("{}", with_opt);
        assert!(with_opt_text.contains("Optimization found!"));
        assert!(with_opt_text.contains("Optimized sequence"));
        assert!(with_opt_text.contains("Savings: 1 instructions"));
    }

    // --- Verification accounting seam (verification_tally / record_verification) ---
    //
    // These pin the canonical policy for folding one candidate verification into
    // the SMT counters, shared by the symbolic and enumerative search paths.
    use crate::semantics::{EquivalenceMetrics, EquivalenceResult};

    fn reached_solver(elapsed_ms: u64) -> EquivalenceMetrics {
        EquivalenceMetrics {
            smt_called: true,
            smt_elapsed: Duration::from_millis(elapsed_ms),
            ..Default::default()
        }
    }

    fn refuted_before_solver() -> EquivalenceMetrics {
        EquivalenceMetrics {
            smt_called: false,
            ..Default::default()
        }
    }

    #[test]
    fn record_verification_counts_solver_reaching_equivalent_candidate() {
        // A candidate that reached Z3 and was proven equivalent counts as one SMT
        // query, one fast-validation pass (it cleared the concrete pre-filter to
        // reach Z3), and one proven equivalence; its solver time is accumulated.
        let mut stats = SearchStatistics::default();
        let proved = stats.record_verification(&reached_solver(7), &EquivalenceResult::Equivalent);
        assert!(proved);
        assert_eq!(stats.smt_queries, 1);
        assert_eq!(stats.candidates_passed_fast, 1);
        assert_eq!(stats.smt_equivalent, 1);
        assert_eq!(stats.smt_elapsed, Duration::from_millis(7));
    }

    #[test]
    fn record_verification_counts_solver_reaching_but_disproved_candidate() {
        // Reaching Z3 but being disproved still counts as a fast pass + an SMT
        // query (the documented meaning of candidates_passed_fast), but NOT an
        // equivalence.
        let mut stats = SearchStatistics::default();
        let proved =
            stats.record_verification(&reached_solver(3), &EquivalenceResult::NotEquivalent);
        assert!(!proved);
        assert_eq!(stats.smt_queries, 1);
        assert_eq!(stats.candidates_passed_fast, 1);
        assert_eq!(stats.smt_equivalent, 0);
        assert_eq!(stats.smt_elapsed, Duration::from_millis(3));
    }

    #[test]
    fn record_verification_ignores_candidates_that_never_reached_the_solver() {
        // A fast-path refutation (smt_called == false) is neither an SMT query
        // nor a fast pass; only the (zero) solver time is folded in.
        let mut stats = SearchStatistics::default();
        let proved = stats.record_verification(
            &refuted_before_solver(),
            &EquivalenceResult::Unknown("timeout".into()),
        );
        assert!(!proved);
        assert_eq!(stats.smt_queries, 0);
        assert_eq!(stats.candidates_passed_fast, 0);
        assert_eq!(stats.smt_equivalent, 0);
        assert_eq!(stats.smt_elapsed, Duration::ZERO);
    }

    #[test]
    fn record_verification_accumulates_across_calls() {
        let mut stats = SearchStatistics::default();
        stats.record_verification(&reached_solver(2), &EquivalenceResult::Equivalent);
        stats.record_verification(&refuted_before_solver(), &EquivalenceResult::NotEquivalent);
        stats.record_verification(&reached_solver(2), &EquivalenceResult::NotEquivalent);
        assert_eq!(stats.smt_queries, 2);
        assert_eq!(stats.candidates_passed_fast, 2);
        assert_eq!(stats.smt_equivalent, 1);
        assert_eq!(stats.smt_elapsed, Duration::from_millis(4));
    }

    #[test]
    fn verification_tally_exposes_the_three_counter_decisions() {
        // The enumerative (parallel) path applies the same tally to its atomic
        // counters, so the tally must expose exactly the decisions they need.
        let tally = SearchStatistics::verification_tally(
            &reached_solver(5),
            &EquivalenceResult::Equivalent,
        );
        assert_eq!(tally.smt_elapsed, Duration::from_millis(5));
        assert!(tally.reached_solver);
        assert!(tally.proved_equivalent);

        let refuted = SearchStatistics::verification_tally(
            &refuted_before_solver(),
            &EquivalenceResult::NotEquivalent,
        );
        assert_eq!(refuted.smt_elapsed, Duration::ZERO);
        assert!(!refuted.reached_solver);
        assert!(!refuted.proved_equivalent);
    }
}
