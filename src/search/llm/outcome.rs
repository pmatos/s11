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
    use crate::ir::{Operand, Register, RegisterWidth};

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
    fn near_zero_smt_timeout_classifies_as_equiv_unknown() {
        // Each target group expands addition into its carry identity:
        // a + b = (a ^ b) + 2 * (a & b). Eight independent outputs put the
        // full proof around 250 ms of Z3 time, far beyond a 1 ms budget.
        //
        // The concrete fast path cannot refute the pair either, but not
        // because the rewrite is subtle: with `fast_only` off, `run_fast_path`
        // randomizes only the live-out registers (x0-x7, all *outputs* here),
        // so the operands x10-x25 stay zero on every trial. That makes the
        // fast path vacuous, which is why the generous-budget assertion at
        // the end of this test — not the fast path — is what pins the
        // fixture's equivalence.
        let groups = [
            (Register::X0, Register::X10, Register::X11),
            (Register::X1, Register::X12, Register::X13),
            (Register::X2, Register::X14, Register::X15),
            (Register::X3, Register::X16, Register::X17),
            (Register::X4, Register::X18, Register::X19),
            (Register::X5, Register::X20, Register::X21),
            (Register::X6, Register::X22, Register::X23),
            (Register::X7, Register::X24, Register::X25),
        ];
        let mut target = Vec::new();
        let mut candidate_lines = Vec::new();

        for (output, a, b) in groups {
            target.extend([
                Instruction::Eor {
                    rd: Register::X26,
                    rn: a,
                    rm: Operand::Register(b),
                    width: RegisterWidth::X64,
                },
                Instruction::And {
                    rd: Register::X27,
                    rn: a,
                    rm: Operand::Register(b),
                    width: RegisterWidth::X64,
                },
                Instruction::Lsl {
                    rd: Register::X27,
                    rn: Register::X27,
                    shift: Operand::Immediate(1),
                },
                Instruction::Add {
                    rd: output,
                    rn: Register::X26,
                    rm: Operand::Register(Register::X27),
                },
            ]);
            candidate_lines.push(format!("add {output}, {a}, {b}"));
        }

        let live_out = LiveOut::from_registers(groups.map(|(output, _, _)| output).to_vec());
        let raw = candidate_lines.join("\n");

        let (outcome, metrics) = classify(&target, &raw, &live_out, Duration::from_millis(1));

        assert_eq!(outcome, IterationOutcome::EquivUnknown);
        let metrics = metrics.expect("equiv-unknown path must have verification metrics");
        assert!(
            metrics.smt_called,
            "near-zero timeout must reach SMT before returning equiv-unknown"
        );
        assert!(
            metrics.smt_formula_bytes.is_none(),
            "formula size is serialized only on the unsat branch"
        );

        // The budget must be the *only* reason for equiv-unknown. Without
        // this second classification the test stays green even when it has
        // stopped testing anything: a fixture that drifted into a
        // non-equivalent pair (e.g. `sub` in place of `add`) also returns
        // EquivUnknown with `smt_called` set at 1 ms, because the fast path
        // above never varies the operands.
        let (generous, _) = classify(&target, &raw, &live_out, Duration::from_secs(30));
        match generous {
            IterationOutcome::Success(seq) => assert_eq!(seq.len(), groups.len()),
            other => panic!("fixture must be equivalent under a generous budget, got {other:?}"),
        }
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
