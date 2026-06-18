//! Per-iteration outcome classification for the LLM loop.
//!
//! Given the raw assembly text returned by Codex, classify it as one of:
//! Success, ParseFail, NotShorter, EquivFail, EquivUnknown.

use std::time::Duration;

use crate::ir::Instruction;
use crate::parser::{ParseLineError, parse_assembly_string, parse_line};
use crate::semantics::equivalence::{
    EquivalenceConfig, EquivalenceMetrics, EquivalenceResult, check_equivalence_with_config_metrics,
};
use crate::semantics::live_out::LiveOut;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IterationOutcome {
    Success(Vec<Instruction>),
    ParseFail {
        /// All unsupported mnemonics observed in the raw response, lowercased,
        /// in order of appearance. May contain duplicates (one entry per
        /// occurrence). Empty if the parse failure was not due to an unknown
        /// instruction (e.g., immediate-out-of-range, malformed operands).
        unsupported_mnemonics: Vec<String>,
    },
    NotShorter {
        candidate_len: usize,
    },
    EquivFail,
    EquivUnknown,
}

/// Classify an LLM-returned candidate against the target.
///
/// Also returns optional `EquivalenceMetrics` from the verification attempt
/// (None when the candidate did not reach the verifier — i.e. parse-fail or
/// not-shorter).
pub fn classify(
    target: &[Instruction],
    raw_asm: &str,
    live_out: &LiveOut,
    smt_timeout: Duration,
) -> (IterationOutcome, Option<EquivalenceMetrics>) {
    let candidate = match parse_assembly_string(raw_asm, "<llm-output>".to_string()) {
        Ok(v) => v,
        Err(_) => {
            return (
                IterationOutcome::ParseFail {
                    unsupported_mnemonics: extract_unsupported_mnemonics(raw_asm),
                },
                None,
            );
        }
    };

    if candidate.len() >= target.len() {
        return (
            IterationOutcome::NotShorter {
                candidate_len: candidate.len(),
            },
            None,
        );
    }

    // Treat NZCV as live-out for parity with the stochastic (`mcmc.rs`) and
    // symbolic (`synthesis.rs`) verification paths. The softened
    // `flag_writers_diverge` guard relies on flags being part of the
    // comparison; without `with_flags(true)` here a future relaxation of any
    // upstream flag-liveness early-exit could silently accept flag-divergent
    // rewrites.
    let cfg = verification_config(live_out, smt_timeout);
    let (result, metrics) = check_equivalence_with_config_metrics(target, &candidate, &cfg);
    let outcome = match result {
        EquivalenceResult::Equivalent => IterationOutcome::Success(candidate),
        EquivalenceResult::NotEquivalent | EquivalenceResult::NotEquivalentFast(_) => {
            IterationOutcome::EquivFail
        }
        EquivalenceResult::Unknown(_) => IterationOutcome::EquivUnknown,
    };
    (outcome, Some(metrics))
}

fn verification_config(live_out: &LiveOut, smt_timeout: Duration) -> EquivalenceConfig {
    EquivalenceConfig::default()
        .timeout(smt_timeout)
        .live_out(live_out.clone())
        .with_flags(true)
}

/// Walk every line of the raw response and collect mnemonics the parser
/// rejected as unknown. Independent of the single-error-stop behavior of
/// `parse_assembly_string` so a response with several unsupported lines
/// contributes every mnemonic to the ledger (per ADR-0003 — full multiset).
///
/// Type-driven (matches `ParseLineError::UnknownInstruction`) rather than
/// string-matched: a parser-error wording change can't silently empty the
/// ledger.
///
/// Note: the loop above (`parse_assembly_string`) and this function each
/// re-parse the response. The two-pass shape is intentional — we only walk
/// every line a second time on the cold path (parse failure), and only when
/// we want every offending mnemonic rather than just the first error site.
/// Per-call cost is negligible at the MVP target sizes (3–20 instructions).
fn extract_unsupported_mnemonics(raw: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in raw.lines() {
        if let Err(ParseLineError::UnknownInstruction(mnem)) = parse_line(line) {
            // `parse_line` already lowercases the opcode before this branch.
            if !mnem.is_empty() {
                found.push(mnem);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};

    fn live_out_x0() -> LiveOut {
        LiveOut::from_registers(vec![Register::X0])
    }

    fn classify_with_test_timeout(
        target: &[Instruction],
        raw_asm: &str,
        live_out: &LiveOut,
    ) -> (IterationOutcome, Option<EquivalenceMetrics>) {
        classify(target, raw_asm, live_out, Duration::from_secs(5))
    }

    #[test]
    fn verification_config_uses_supplied_timeout_and_forces_flags_live() {
        let cfg = verification_config(&live_out_x0(), Duration::from_millis(17));

        assert_eq!(cfg.smt_timeout, Some(Duration::from_millis(17)));
        assert!(cfg.live_out.contains(Register::X0));
        assert!(
            cfg.live_out.flags_live(),
            "LLM verification must keep NZCV live"
        );
    }

    #[test]
    fn parse_fail_extracts_unsupported_mnemonic() {
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];
        // NEON FADD is unsupported by the parser today; use it as the
        // canonical unsupported mnemonic so the test does not fight the
        // memory-ops support added in issue #68.
        let (outcome, metrics) =
            classify_with_test_timeout(&target, "fadd v0.4s, v1.4s, v2.4s", &live_out_x0());
        assert_eq!(
            outcome,
            IterationOutcome::ParseFail {
                unsupported_mnemonics: vec!["fadd".to_string()]
            }
        );
        assert!(metrics.is_none(), "parse-fail must not invoke verifier");
    }

    #[test]
    fn parse_fail_collects_all_unsupported_mnemonics_in_response() {
        // Response with three different unsupported instructions interleaved
        // with one supported `mov`. All three unsupported should be captured.
        // Use NEON forms; memory ops were promoted to supported in issue #68.
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];
        let raw =
            "fadd v0.4s, v1.4s, v2.4s\nmov x0, x1\nfmla v3.4s, v4.4s, v5.4s\nld1 {v6.16b}, [x7]\n";
        let (outcome, metrics) = classify_with_test_timeout(&target, raw, &live_out_x0());
        let mnemonics = match outcome {
            IterationOutcome::ParseFail {
                unsupported_mnemonics,
            } => unsupported_mnemonics,
            other => panic!("expected ParseFail, got {:?}", other),
        };
        assert!(
            mnemonics.contains(&"fadd".to_string()),
            "fadd missing from {:?}",
            mnemonics
        );
        assert!(
            mnemonics.contains(&"fmla".to_string()),
            "fmla missing from {:?}",
            mnemonics
        );
        assert!(
            mnemonics.contains(&"ld1".to_string()),
            "ld1 missing from {:?}",
            mnemonics
        );
        assert!(metrics.is_none());
    }

    #[test]
    fn success_when_shorter_and_equivalent() {
        // mov x0, x1 ; add x0, x0, #1   ≡  add x0, x1, #1   (1 fewer instruction)
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
        let (outcome, metrics) =
            classify_with_test_timeout(&target, "add x0, x1, #1", &live_out_x0());
        match outcome {
            IterationOutcome::Success(seq) => {
                assert_eq!(seq.len(), 1);
                assert_eq!(
                    seq[0],
                    Instruction::Add {
                        rd: Register::X0,
                        rn: Register::X1,
                        rm: Operand::Immediate(1)
                    }
                );
            }
            other => panic!("expected Success, got {:?}", other),
        }
        let metrics = metrics.expect("success path must have metrics");
        assert!(metrics.smt_called, "success path must call SMT");
        assert!(
            metrics.smt_formula_bytes.map(|n| n > 0).unwrap_or(false),
            "smt_formula_bytes should be populated and non-zero"
        );
    }

    #[test]
    fn not_shorter_when_same_length() {
        // 1-instruction target; candidate also 1 instruction (and equivalent).
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let (outcome, metrics) = classify_with_test_timeout(&target, "mov x0, #0", &live_out_x0());
        assert_eq!(outcome, IterationOutcome::NotShorter { candidate_len: 1 });
        assert!(metrics.is_none(), "not-shorter must short-circuit verifier");
    }

    #[test]
    fn equiv_fail_when_candidate_is_wrong() {
        // 2-instruction target writes x0=2; 1-instruction candidate writes x0=5.
        let target = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        let (outcome, metrics) = classify_with_test_timeout(&target, "mov x0, #5", &live_out_x0());
        assert_eq!(outcome, IterationOutcome::EquivFail);
        let metrics = metrics.expect("equiv-fail still passes through verifier");
        // Fast-path random testing should have refuted this without reaching SMT.
        assert!(!metrics.smt_called, "fast-path refutation should skip SMT");
    }
}
