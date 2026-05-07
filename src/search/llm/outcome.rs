//! Per-iteration outcome classification for the LLM loop.
//!
//! Given the raw assembly text returned by Codex, classify it as one of:
//! Success, ParseFail, NotShorter, EquivFail, EquivUnknown.

use crate::ir::Instruction;
use crate::parser::parse_assembly_string;
use crate::semantics::equivalence::{
    EquivalenceConfig, EquivalenceResult, check_equivalence_with_config,
};
use crate::semantics::state::LiveOutMask;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IterationOutcome {
    Success(Vec<Instruction>),
    ParseFail {
        unsupported_mnemonic: Option<String>,
    },
    NotShorter {
        candidate_len: usize,
    },
    EquivFail,
    EquivUnknown,
}

/// Classify an LLM-returned candidate against the target.
pub fn classify(target: &[Instruction], raw_asm: &str, live_out: &LiveOutMask) -> IterationOutcome {
    let candidate = match parse_assembly_string(raw_asm, "<llm-output>".to_string()) {
        Ok(v) => v,
        Err(err) => {
            return IterationOutcome::ParseFail {
                unsupported_mnemonic: extract_mnemonic(&err.line_content),
            };
        }
    };

    if candidate.len() >= target.len() {
        return IterationOutcome::NotShorter {
            candidate_len: candidate.len(),
        };
    }

    let cfg = EquivalenceConfig::default().live_out(live_out.clone());
    match check_equivalence_with_config(target, &candidate, &cfg) {
        EquivalenceResult::Equivalent => IterationOutcome::Success(candidate),
        EquivalenceResult::NotEquivalent | EquivalenceResult::NotEquivalentFast(_) => {
            IterationOutcome::EquivFail
        }
        EquivalenceResult::Unknown(_) => IterationOutcome::EquivUnknown,
    }
}

/// Extract the offending mnemonic from a parser error's line_content.
/// Returns the first whitespace-separated token, lowercased, or None if the
/// line is empty/whitespace.
fn extract_mnemonic(line: &str) -> Option<String> {
    line.split_whitespace().next().map(|s| s.to_lowercase())
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
        let outcome = classify(&target, "ldr x0, [x1]", &live_out_x0());
        assert_eq!(
            outcome,
            IterationOutcome::ParseFail {
                unsupported_mnemonic: Some("ldr".to_string())
            }
        );
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
        let outcome = classify(&target, "add x0, x1, #1", &live_out_x0());
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
    }

    #[test]
    fn not_shorter_when_same_length() {
        // 1-instruction target; candidate also 1 instruction (and equivalent).
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let outcome = classify(&target, "mov x0, #0", &live_out_x0());
        assert_eq!(outcome, IterationOutcome::NotShorter { candidate_len: 1 });
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
        let outcome = classify(&target, "mov x0, #5", &live_out_x0());
        assert_eq!(outcome, IterationOutcome::EquivFail);
    }
}
