//! Per-iteration outcome classification for the LLM loop.
//!
//! Given the raw assembly text returned by Codex, classify it as one of:
//! Success, ParseFail, NotShorter, EquivFail, EquivUnknown.

use crate::ir::Instruction;
use crate::parser::{LineResult, parse_assembly_string, parse_line};
use crate::semantics::equivalence::{
    EquivalenceConfig, EquivalenceMetrics, EquivalenceResult, check_equivalence_with_config_metrics,
};
use crate::semantics::state::LiveOutMask;

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
    live_out: &LiveOutMask,
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

    let cfg = EquivalenceConfig::default().live_out(live_out.clone());
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

/// Walk every line of the raw response and collect mnemonics the parser
/// rejected as unknown. Independent of the single-error-stop behavior of
/// `parse_assembly_string` so a response with several unsupported lines
/// contributes every mnemonic to the ledger (per ADR-0003 — full multiset).
fn extract_unsupported_mnemonics(raw: &str) -> Vec<String> {
    const PREFIX: &str = "unknown instruction: ";
    let mut found = Vec::new();
    for line in raw.lines() {
        match parse_line(line) {
            Ok(LineResult::Instruction(_)) | Ok(LineResult::Skip) => {}
            Err(msg) => {
                if let Some(rest) = msg.strip_prefix(PREFIX) {
                    let mnem = rest.trim().to_lowercase();
                    if !mnem.is_empty() {
                        found.push(mnem);
                    }
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};

    fn live_out_x0() -> LiveOutMask {
        let mut m = LiveOutMask::empty();
        m.add(Register::X0);
        m
    }

    #[test]
    fn parse_fail_extracts_unsupported_mnemonic() {
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];
        let (outcome, metrics) = classify(&target, "ldr x0, [x1]", &live_out_x0());
        assert_eq!(
            outcome,
            IterationOutcome::ParseFail {
                unsupported_mnemonics: vec!["ldr".to_string()]
            }
        );
        assert!(metrics.is_none(), "parse-fail must not invoke verifier");
    }

    #[test]
    fn parse_fail_collects_all_unsupported_mnemonics_in_response() {
        // Response with three different unsupported instructions interleaved
        // with one supported `mov`. All three unsupported should be captured.
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];
        let raw = "ldr x0, [x1]\nmov x0, x1\nstr x2, [x3]\nb .Lend\n";
        let (outcome, metrics) = classify(&target, raw, &live_out_x0());
        let mnemonics = match outcome {
            IterationOutcome::ParseFail {
                unsupported_mnemonics,
            } => unsupported_mnemonics,
            other => panic!("expected ParseFail, got {:?}", other),
        };
        assert!(
            mnemonics.contains(&"ldr".to_string()),
            "ldr missing from {:?}",
            mnemonics
        );
        assert!(
            mnemonics.contains(&"str".to_string()),
            "str missing from {:?}",
            mnemonics
        );
        assert!(
            mnemonics.contains(&"b".to_string()),
            "b missing from {:?}",
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
        let (outcome, metrics) = classify(&target, "add x0, x1, #1", &live_out_x0());
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
        let (outcome, metrics) = classify(&target, "mov x0, #0", &live_out_x0());
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
        let (outcome, metrics) = classify(&target, "mov x0, #5", &live_out_x0());
        assert_eq!(outcome, IterationOutcome::EquivFail);
        let metrics = metrics.expect("equiv-fail still passes through verifier");
        // Fast-path random testing should have refuted this without reaching SMT.
        assert!(!metrics.smt_called, "fast-path refutation should skip SMT");
    }
}
