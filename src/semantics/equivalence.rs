//! Semantic equivalence checking for instruction sequences

use crate::ir::Instruction;
use crate::semantics::smt::{MachineState, apply_sequence, states_not_equal};
use z3::{Config, Context, SatResult, Solver};

/// Result of equivalence checking
#[derive(Debug, Clone, PartialEq)]
pub enum EquivalenceResult {
    /// The sequences are equivalent
    Equivalent,
    /// The sequences are not equivalent
    NotEquivalent,
    /// Could not determine (timeout, unknown, etc.)
    Unknown(String),
}

/// Check if two instruction sequences are semantically equivalent
///
/// Returns true if for all possible initial states, both sequences
/// produce the same final state.
pub fn check_equivalence(seq1: &[Instruction], seq2: &[Instruction]) -> EquivalenceResult {
    // Create Z3 context and solver
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // Create symbolic initial state
    let initial_state = MachineState::new_symbolic(&ctx, "init");

    // Apply both sequences
    let final_state1 = apply_sequence(initial_state.clone(), seq1);
    let final_state2 = apply_sequence(initial_state, seq2);

    // Assert that the final states are NOT equal
    // If this is UNSAT, then the states are always equal
    solver.assert(&states_not_equal(&final_state1, &final_state2));

    // Check satisfiability
    match solver.check() {
        SatResult::Unsat => EquivalenceResult::Equivalent,
        SatResult::Sat => EquivalenceResult::NotEquivalent,
        SatResult::Unknown => EquivalenceResult::Unknown("SMT solver returned unknown".to_string()),
    }
}

/// Find a counterexample showing two sequences are not equivalent
///
/// Returns Some((register, value1, value2)) if sequences differ,
/// where register is the first differing register and value1/value2
/// are the values in the respective final states.
#[allow(dead_code)]
pub fn find_counterexample(
    seq1: &[Instruction],
    seq2: &[Instruction],
) -> Option<(String, i64, i64)> {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // Create symbolic initial state
    let initial_state = MachineState::new_symbolic(&ctx, "init");

    // Apply both sequences
    let final_state1 = apply_sequence(initial_state.clone(), seq1);
    let final_state2 = apply_sequence(initial_state, seq2);

    // Assert states are not equal
    solver.assert(&states_not_equal(&final_state1, &final_state2));

    if solver.check() == SatResult::Sat {
        // Get the model
        let model = solver.get_model().unwrap();

        // Check each register to find which one differs
        for i in 0..=30 {
            if let Some(reg) = crate::ir::Register::from_index(i) {
                let val1 = final_state1.get_register(reg);
                let val2 = final_state2.get_register(reg);

                // Evaluate in the model
                let eval1 = model.eval(val1, true).unwrap();
                let eval2 = model.eval(val2, true).unwrap();

                // Convert to i64 if possible
                if let (Some(v1), Some(v2)) = (eval1.as_i64(), eval2.as_i64()) {
                    if v1 != v2 {
                        return Some((format!("x{}", i), v1, v2));
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};

    #[test]
    fn test_mov_zero_eor_equivalence() {
        // MOV X0, #0
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];

        // EOR X0, X0, X0
        let seq2 = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_add_commutativity() {
        // ADD X0, X1, X2
        let seq1 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        // ADD X0, X2, X1
        let seq2 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X2,
            rm: Operand::Register(Register::X1),
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_sequence_optimization() {
        // MOV X0, X1; ADD X0, X0, #1
        let seq1 = vec![
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

        // ADD X0, X1, #1
        let seq2 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_non_equivalent_sequences() {
        // MOV X0, #1
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];

        // MOV X0, #2
        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 2,
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::NotEquivalent
        );
    }

    #[test]
    fn test_xor_self_clearing() {
        // Any register XOR'd with itself is zero
        for i in 0..5 {
            let reg = Register::from_index(i).unwrap();

            // MOV reg, #0
            let seq1 = vec![Instruction::MovImm { rd: reg, imm: 0 }];

            // EOR reg, reg, reg
            let seq2 = vec![Instruction::Eor {
                rd: reg,
                rn: reg,
                rm: Operand::Register(reg),
            }];

            assert_eq!(
                check_equivalence(&seq1, &seq2),
                EquivalenceResult::Equivalent
            );
        }
    }

    #[test]
    fn test_and_with_zero() {
        // X0 AND #0 = #0
        let seq1 = vec![Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0),
        }];

        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_or_with_zero() {
        // X1 OR #0 = X1 (so MOV X0, X1 is equivalent)
        let seq1 = vec![Instruction::Orr {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0),
        }];

        let seq2 = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_counterexample() {
        // MOV X0, #5
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 5,
        }];

        // MOV X0, #10
        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 10,
        }];

        let counter = find_counterexample(&seq1, &seq2);
        assert!(counter.is_some());
        if let Some((reg, v1, v2)) = counter {
            assert_eq!(reg, "x0");
            assert_eq!(v1, 5);
            assert_eq!(v2, 10);
        }
    }
}
