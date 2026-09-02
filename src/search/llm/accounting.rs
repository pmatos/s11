//! Per-run accounting seam for the LLM search loop.
//!
//! `LlmSearch::search` (see `mod.rs`) has to keep three accumulators in step as
//! it drives Codex: a [`SearchStatistics`], a [`LlmTimings`] timing breakdown,
//! and the [`UnsupportedMnemonicLedger`]. The rules for which loop event bumps
//! which counter are subtle — e.g. `candidates_evaluated` counts a Codex `Ok`
//! but not the timeout-break-before-codex path, and the SMT counters key off the
//! *verification metrics* rather than the classified outcome, so an
//! `EquivUnknown` that still reached the solver bumps `smt_calls`. This module
//! owns all of that so the rules are unit-testable without a `FakeCodex`
//! subprocess: the caller emits one [`RunEvent`] per accountable moment and the
//! counting lives behind [`RunAccounting::record`].

use std::time::Duration;

use crate::search::config::Algorithm;
use crate::search::result::SearchStatistics;
use crate::semantics::equivalence::EquivalenceMetrics;

use super::ledger::UnsupportedMnemonicLedger;
use super::outcome::IterationOutcome;

/// Per-phase timing breakdown for one `LlmSearch::search` run.
#[derive(Debug, Default, Clone, Copy)]
pub struct LlmTimings {
    /// Number of times `codex exec` was invoked.
    pub codex_calls: u32,
    /// Wall-clock time spent inside `codex exec` invocations.
    pub codex_time: Duration,
    /// Number of candidate verifications attempted (one per parseable response).
    pub verifications: u32,
    /// Wall-clock time spent in the verification pipeline (parse + fast-path
    /// random testing + Z3 SMT). Dominated by SMT for non-parse-fail outcomes.
    pub verify_time: Duration,
    /// Number of times the SMT solver was actually invoked (subset of
    /// verifications: parse-fail and fast-path-refutations don't reach SMT).
    pub smt_calls: u32,
    /// Sum of SMT formula sizes (bytes of SMT-LIB rendering) across all
    /// solver invocations in this search **whose result was Equivalent**.
    /// Sat / Unknown SMT outcomes do not contribute (we don't pay
    /// `solver.to_string()` on those paths). A run that hit SMT many times
    /// but never proved equivalence will read 0 here even though `smt_calls`
    /// is positive.
    pub smt_formula_bytes_total: usize,
    /// Largest SMT formula size (bytes) seen on an Equivalent SMT outcome.
    pub smt_formula_bytes_max: usize,
}

/// One accountable moment in the LLM search loop. The whole vocabulary a caller
/// needs to feed the accounting seam.
pub(super) enum RunEvent<'a> {
    /// One `codex exec` attempt finished. `produced` is true iff Codex returned
    /// a candidate (the `Ok` arm); false on an IO/exit error. Every iteration
    /// that actually calls Codex emits exactly one of these, before the Ok/Err
    /// split is acted on.
    Codex { elapsed: Duration, produced: bool },
    /// A produced candidate was classified. `metrics` is `Some` iff the verifier
    /// actually ran — it is `None` for the parse-fail and not-shorter
    /// short-circuits, which never reach the equivalence pipeline.
    Candidate {
        outcome: &'a IterationOutcome,
        metrics: Option<&'a EquivalenceMetrics>,
        elapsed: Duration,
    },
}

/// The three accumulators handed back to `LlmSearch` at the end of a run.
pub(super) struct RunTotals {
    pub stats: SearchStatistics,
    pub ledger: UnsupportedMnemonicLedger,
    pub timings: LlmTimings,
}

/// Owns the three search-run accumulators and every counting rule that folds a
/// loop event into them. Constructed once per `LlmSearch::search` call, fed one
/// [`RunEvent`] per accountable moment, and drained with [`Self::finish`].
pub(super) struct RunAccounting {
    stats: SearchStatistics,
    ledger: UnsupportedMnemonicLedger,
    timings: LlmTimings,
}

impl RunAccounting {
    /// Start accounting for a run over a target of `target_len` instructions.
    /// Seeds `original_cost` and `best_cost_found` to the target length (the
    /// latter is overwritten only when a shorter equivalent candidate is found)
    /// and tags the statistics with [`Algorithm::Llm`].
    pub(super) fn new(target_len: usize) -> Self {
        let mut stats = SearchStatistics::new(Algorithm::Llm);
        stats.original_cost = target_len as u64;
        stats.best_cost_found = target_len as u64;
        Self {
            stats,
            ledger: UnsupportedMnemonicLedger::new(),
            timings: LlmTimings::default(),
        }
    }

    /// Fold one loop event into the accumulators. All branching on Codex
    /// success, verifier participation, and outcome variant is hidden here.
    pub(super) fn record(&mut self, event: RunEvent<'_>) {
        match event {
            RunEvent::Codex { elapsed, produced } => {
                self.timings.codex_calls += 1;
                self.timings.codex_time += elapsed;
                if produced {
                    // A Codex `Ok` is the moment a candidate counts as
                    // "evaluated"; IO/exit errors count the call, not this.
                    self.stats.candidates_evaluated += 1;
                }
            }
            RunEvent::Candidate {
                outcome,
                metrics,
                elapsed,
            } => {
                self.record_verification(metrics, elapsed);
                self.record_outcome(outcome);
            }
        }
    }

    /// Fold the verification metrics into the accumulators. Keyed off whether
    /// the verifier ran and, within that, whether SMT was invoked — both
    /// independent of the classified outcome, so an `EquivUnknown` that still
    /// reached the solver bumps `smt_calls`/`smt_queries`.
    fn record_verification(&mut self, metrics: Option<&EquivalenceMetrics>, elapsed: Duration) {
        let Some(m) = metrics else {
            return;
        };
        self.timings.verifications += 1;
        self.timings.verify_time += elapsed;
        if m.smt_called {
            self.timings.smt_calls += 1;
            self.stats.smt_queries += 1;
            if let Some(bytes) = m.smt_formula_bytes {
                self.timings.smt_formula_bytes_total += bytes;
                self.timings.smt_formula_bytes_max = self.timings.smt_formula_bytes_max.max(bytes);
            }
        }
    }

    /// Fold the classified outcome into the statistics and ledger.
    fn record_outcome(&mut self, outcome: &IterationOutcome) {
        match outcome {
            IterationOutcome::Success(seq) => {
                self.stats.smt_equivalent += 1;
                self.stats.candidates_passed_fast += 1;
                self.stats.improvements_found += 1;
                self.stats.best_cost_found = seq.len() as u64;
            }
            IterationOutcome::ParseFail {
                unsupported_mnemonics,
            } => {
                for m in unsupported_mnemonics {
                    self.ledger.record(m);
                }
            }
            IterationOutcome::NotShorter { .. } => {
                self.stats.candidates_pruned_by_cost += 1;
            }
            IterationOutcome::EquivFail | IterationOutcome::EquivUnknown => {}
        }
    }

    /// Stamp the total elapsed time and hand back the three accumulators.
    pub(super) fn finish(mut self, elapsed: Duration) -> RunTotals {
        self.stats.elapsed_time = elapsed;
        RunTotals {
            stats: self.stats,
            ledger: self.ledger,
            timings: self.timings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(smt_called: bool, smt_formula_bytes: Option<usize>) -> EquivalenceMetrics {
        EquivalenceMetrics {
            smt_called,
            smt_formula_bytes,
            ..EquivalenceMetrics::default()
        }
    }

    #[test]
    fn new_seeds_costs_and_algorithm() {
        let totals = RunAccounting::new(3).finish(Duration::from_secs(1));
        assert_eq!(totals.stats.algorithm, Algorithm::Llm);
        assert_eq!(totals.stats.original_cost, 3);
        assert_eq!(totals.stats.best_cost_found, 3);
        assert_eq!(totals.stats.candidates_evaluated, 0);
    }

    #[test]
    fn codex_success_counts_call_and_evaluation() {
        let mut acc = RunAccounting::new(2);
        acc.record(RunEvent::Codex {
            elapsed: Duration::from_millis(10),
            produced: true,
        });
        let totals = acc.finish(Duration::ZERO);
        assert_eq!(totals.timings.codex_calls, 1);
        assert_eq!(totals.timings.codex_time, Duration::from_millis(10));
        assert_eq!(totals.stats.candidates_evaluated, 1);
    }

    #[test]
    fn codex_error_counts_call_but_not_evaluation() {
        let mut acc = RunAccounting::new(2);
        acc.record(RunEvent::Codex {
            elapsed: Duration::from_millis(7),
            produced: false,
        });
        let totals = acc.finish(Duration::ZERO);
        assert_eq!(totals.timings.codex_calls, 1);
        assert_eq!(totals.timings.codex_time, Duration::from_millis(7));
        assert_eq!(
            totals.stats.candidates_evaluated, 0,
            "a Codex error must not count as an evaluated candidate"
        );
    }

    #[test]
    fn candidate_without_verifier_records_no_verification() {
        // Parse-fail / not-shorter short-circuit before the verifier: metrics None.
        let mut acc = RunAccounting::new(2);
        let outcome = IterationOutcome::NotShorter { candidate_len: 2 };
        acc.record(RunEvent::Candidate {
            outcome: &outcome,
            metrics: None,
            elapsed: Duration::from_millis(5),
        });
        let totals = acc.finish(Duration::ZERO);
        assert_eq!(totals.timings.verifications, 0);
        assert_eq!(totals.timings.verify_time, Duration::ZERO);
        assert_eq!(totals.stats.candidates_pruned_by_cost, 1);
    }

    #[test]
    fn verification_without_smt_counts_verification_only() {
        let mut acc = RunAccounting::new(2);
        let m = metrics(false, None);
        let outcome = IterationOutcome::EquivFail;
        acc.record(RunEvent::Candidate {
            outcome: &outcome,
            metrics: Some(&m),
            elapsed: Duration::from_millis(20),
        });
        let totals = acc.finish(Duration::ZERO);
        assert_eq!(totals.timings.verifications, 1);
        assert_eq!(totals.timings.verify_time, Duration::from_millis(20));
        assert_eq!(totals.timings.smt_calls, 0);
        assert_eq!(totals.stats.smt_queries, 0);
    }

    #[test]
    fn smt_counters_key_off_metrics_not_outcome() {
        // An EquivUnknown that still reached the solver bumps smt_calls /
        // smt_queries; with no formula bytes it contributes zero to the totals.
        let mut acc = RunAccounting::new(2);
        let m = metrics(true, None);
        let outcome = IterationOutcome::EquivUnknown;
        acc.record(RunEvent::Candidate {
            outcome: &outcome,
            metrics: Some(&m),
            elapsed: Duration::from_millis(30),
        });
        let totals = acc.finish(Duration::ZERO);
        assert_eq!(totals.timings.verifications, 1);
        assert_eq!(totals.timings.smt_calls, 1);
        assert_eq!(totals.stats.smt_queries, 1);
        assert_eq!(totals.timings.smt_formula_bytes_total, 0);
        assert_eq!(totals.timings.smt_formula_bytes_max, 0);
    }

    #[test]
    fn smt_formula_bytes_accumulate_total_and_max() {
        let mut acc = RunAccounting::new(2);
        let unknown = IterationOutcome::EquivUnknown;
        let m1 = metrics(true, Some(100));
        acc.record(RunEvent::Candidate {
            outcome: &unknown,
            metrics: Some(&m1),
            elapsed: Duration::from_millis(1),
        });
        let m2 = metrics(true, Some(40));
        acc.record(RunEvent::Candidate {
            outcome: &unknown,
            metrics: Some(&m2),
            elapsed: Duration::from_millis(1),
        });
        let totals = acc.finish(Duration::ZERO);
        assert_eq!(totals.timings.smt_calls, 2);
        assert_eq!(totals.stats.smt_queries, 2);
        assert_eq!(totals.timings.smt_formula_bytes_total, 140);
        assert_eq!(totals.timings.smt_formula_bytes_max, 100);
    }

    #[test]
    fn success_outcome_records_all_success_counters() {
        let mut acc = RunAccounting::new(2);
        let m = metrics(true, Some(50));
        let seq = vec![crate::ir::Instruction::MovImm {
            rd: crate::ir::Register::X0,
            imm: 0,
        }];
        let outcome = IterationOutcome::Success(seq);
        acc.record(RunEvent::Candidate {
            outcome: &outcome,
            metrics: Some(&m),
            elapsed: Duration::from_millis(15),
        });
        let totals = acc.finish(Duration::ZERO);
        assert_eq!(totals.stats.smt_equivalent, 1);
        assert_eq!(totals.stats.candidates_passed_fast, 1);
        assert_eq!(totals.stats.improvements_found, 1);
        assert_eq!(totals.stats.best_cost_found, 1);
        // Success still routes through the metrics accounting.
        assert_eq!(totals.timings.smt_calls, 1);
        assert_eq!(totals.timings.smt_formula_bytes_total, 50);
    }

    #[test]
    fn parse_fail_records_every_mnemonic_occurrence() {
        let mut acc = RunAccounting::new(2);
        let outcome = IterationOutcome::ParseFail {
            unsupported_mnemonics: vec!["fadd".to_string(), "ld1".to_string(), "fadd".to_string()],
        };
        acc.record(RunEvent::Candidate {
            outcome: &outcome,
            metrics: None,
            elapsed: Duration::ZERO,
        });
        let totals = acc.finish(Duration::ZERO);
        assert_eq!(
            totals.ledger.sorted_entries(),
            vec![("fadd".to_string(), 2), ("ld1".to_string(), 1)]
        );
        assert_eq!(totals.timings.verifications, 0);
    }

    #[test]
    fn parse_fail_with_no_mnemonics_records_nothing() {
        let mut acc = RunAccounting::new(2);
        let outcome = IterationOutcome::ParseFail {
            unsupported_mnemonics: Vec::new(),
        };
        acc.record(RunEvent::Candidate {
            outcome: &outcome,
            metrics: None,
            elapsed: Duration::ZERO,
        });
        let totals = acc.finish(Duration::ZERO);
        assert!(totals.ledger.is_empty());
    }

    #[test]
    fn finish_stamps_elapsed_time() {
        let totals = RunAccounting::new(1).finish(Duration::from_millis(123));
        assert_eq!(totals.stats.elapsed_time, Duration::from_millis(123));
    }

    #[test]
    fn full_iteration_replay_matches_loop_accounting() {
        // A produced candidate that verifies via SMT and is not shorter would be
        // impossible (not-shorter short-circuits), so replay a realistic winning
        // iteration: codex Ok, verification with SMT, Success.
        let mut acc = RunAccounting::new(2);
        acc.record(RunEvent::Codex {
            elapsed: Duration::from_millis(200),
            produced: true,
        });
        let m = metrics(true, Some(80));
        let seq = vec![crate::ir::Instruction::MovImm {
            rd: crate::ir::Register::X0,
            imm: 0,
        }];
        let outcome = IterationOutcome::Success(seq);
        acc.record(RunEvent::Candidate {
            outcome: &outcome,
            metrics: Some(&m),
            elapsed: Duration::from_millis(50),
        });
        let totals = acc.finish(Duration::from_millis(260));

        assert_eq!(totals.stats.candidates_evaluated, 1);
        assert_eq!(totals.timings.codex_calls, 1);
        assert_eq!(totals.timings.verifications, 1);
        assert_eq!(totals.timings.smt_calls, 1);
        assert_eq!(totals.stats.smt_queries, 1);
        assert_eq!(totals.stats.smt_equivalent, 1);
        assert_eq!(totals.stats.improvements_found, 1);
        assert_eq!(totals.stats.best_cost_found, 1);
        assert_eq!(totals.timings.smt_formula_bytes_total, 80);
        assert_eq!(totals.timings.smt_formula_bytes_max, 80);
        assert_eq!(totals.stats.elapsed_time, Duration::from_millis(260));
    }
}
