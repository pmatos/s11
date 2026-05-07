//! LLM-assisted superoptimization (Codex Spark flow).
//!
//! See CONTEXT.md and docs/adr/0001-0003 for the design.

#![allow(dead_code)]

pub mod codex;
pub mod ledger;
pub mod outcome;
pub mod prompt;

use std::time::{Duration, Instant};

use crate::ir::Instruction;
use crate::search::SearchAlgorithm;
use crate::search::config::SearchConfig;
use crate::search::result::{SearchResult, SearchStatistics};
use crate::semantics::state::LiveOutMask;
use crate::validation::live_out::{compute_live_in_registers, flags_live_out};

use self::codex::invoke_codex;
use self::ledger::UnsupportedMnemonicLedger;
use self::outcome::{IterationOutcome, classify};
use self::prompt::{OUTPUT_SCHEMA, build_prompt};

/// LLM-assisted search using the Codex CLI.
///
/// Each call to `search` invokes `codex exec` up to `LlmConfig.max_codex_calls`
/// times, sequentially, with fresh prompts. The first candidate that parses,
/// is strictly shorter than the target, and is provably equivalent (per the
/// existing fast + SMT pipeline) is returned.
#[derive(Default)]
pub struct LlmSearch {
    last_stats: SearchStatistics,
    last_ledger: UnsupportedMnemonicLedger,
}

impl LlmSearch {
    pub fn new() -> Self {
        Self::default()
    }

    /// The unsupported-mnemonic ledger from the most recent search.
    pub fn ledger(&self) -> &UnsupportedMnemonicLedger {
        &self.last_ledger
    }
}

impl SearchAlgorithm for LlmSearch {
    fn search(
        &mut self,
        target: &[Instruction],
        live_out: &LiveOutMask,
        config: &SearchConfig,
    ) -> SearchResult {
        let mut stats = SearchStatistics::new(crate::search::config::Algorithm::Llm);
        stats.original_cost = target.len() as u64;
        stats.best_cost_found = target.len() as u64;
        let mut ledger = UnsupportedMnemonicLedger::new();
        let started = Instant::now();

        // Per ADR-0002: refuse targets where flags are live-out.
        if flags_live_out(target) {
            eprintln!(
                "llm-search: target has flags live-out (per ADR-0002 the LLM \
                 flow is not sound on this input). Refusing."
            );
            stats.elapsed_time = started.elapsed();
            self.last_stats = stats.clone();
            self.last_ledger = ledger;
            return SearchResult::no_optimization(target.to_vec(), stats);
        }

        let live_in = compute_live_in_registers(target);
        let prompt = build_prompt(target, &live_in, live_out);
        let timeout = config.timeout.unwrap_or(Duration::from_secs(60));
        let max_calls = config.llm.max_codex_calls;

        let mut found: Option<Vec<Instruction>> = None;

        for call_idx in 0..max_calls {
            if started.elapsed() >= timeout {
                if config.verbose {
                    eprintln!("llm-search: timeout after {} calls", call_idx);
                }
                break;
            }
            stats.candidates_evaluated += 1;

            if config.verbose {
                eprintln!(
                    "llm-search: [{:>2}/{}] calling codex (elapsed {:.2}s)",
                    call_idx + 1,
                    max_calls,
                    started.elapsed().as_secs_f64()
                );
            }
            let call_start = Instant::now();
            let raw = match invoke_codex(&config.llm, &prompt, OUTPUT_SCHEMA) {
                Ok(s) => {
                    if config.verbose {
                        eprintln!(
                            "llm-search: [{:>2}/{}]   ← codex returned in {:.2}s",
                            call_idx + 1,
                            max_calls,
                            call_start.elapsed().as_secs_f64()
                        );
                    }
                    s
                }
                Err(e) => {
                    if config.verbose {
                        eprintln!(
                            "llm-search: [{:>2}/{}]   ✗ codex error after {:.2}s: {}",
                            call_idx + 1,
                            max_calls,
                            call_start.elapsed().as_secs_f64(),
                            e
                        );
                    }
                    continue;
                }
            };

            match classify(target, &raw, live_out) {
                IterationOutcome::Success(seq) => {
                    if config.verbose {
                        eprintln!(
                            "llm-search: success on call {} ({} -> {} instructions)",
                            call_idx,
                            target.len(),
                            seq.len()
                        );
                    }
                    stats.smt_queries += 1;
                    stats.smt_equivalent += 1;
                    stats.candidates_passed_fast += 1;
                    stats.improvements_found += 1;
                    stats.best_cost_found = seq.len() as u64;
                    found = Some(seq);
                    break;
                }
                IterationOutcome::ParseFail {
                    unsupported_mnemonic,
                } => {
                    if let Some(m) = unsupported_mnemonic {
                        ledger.record(&m);
                    }
                    if config.verbose {
                        eprintln!("llm-search: parse-fail on call {}", call_idx);
                    }
                }
                IterationOutcome::NotShorter { candidate_len } => {
                    if config.verbose {
                        eprintln!(
                            "llm-search: not-shorter on call {} (got {} instructions)",
                            call_idx, candidate_len
                        );
                    }
                }
                IterationOutcome::EquivFail => {
                    stats.smt_queries += 1;
                    if config.verbose {
                        eprintln!("llm-search: equiv-fail on call {}", call_idx);
                    }
                }
                IterationOutcome::EquivUnknown => {
                    stats.smt_queries += 1;
                    if config.verbose {
                        eprintln!("llm-search: equiv-unknown on call {}", call_idx);
                    }
                }
            }
        }

        stats.elapsed_time = started.elapsed();
        self.last_stats = stats.clone();
        self.last_ledger = ledger;

        match found {
            Some(seq) => SearchResult::with_optimization(target.to_vec(), seq, stats),
            None => SearchResult::no_optimization(target.to_vec(), stats),
        }
    }

    fn statistics(&self) -> SearchStatistics {
        self.last_stats.clone()
    }

    fn reset(&mut self) {
        self.last_stats = SearchStatistics::default();
        self.last_ledger = UnsupportedMnemonicLedger::new();
    }
}
