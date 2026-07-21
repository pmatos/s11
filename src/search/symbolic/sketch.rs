//! Symbolic instruction representation for SMT-based synthesis
//!
//! A sketch represents a partially-specified instruction where the opcode
//! and operands are Z3 variables rather than concrete values.
//!
//! Note: This module provides the data structures for symbolic instructions.
//! The actual synthesis in this implementation uses a hybrid approach:
//! enumerate concrete candidates and verify with SMT.

#![allow(dead_code)]

use crate::ir::{Instruction, Operand, Register};
use z3::Model;
use z3::ast::{Bool, Int};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
enum SketchOpcode {
    MovReg = 0,
    MovImm = 1,
    Add = 2,
    Sub = 3,
    And = 4,
    Orr = 5,
    Eor = 6,
    Lsl = 7,
    Lsr = 8,
    Asr = 9,
}

impl SketchOpcode {
    const fn selector(self) -> i64 {
        self as i64
    }

    const fn from_selector(selector: i64) -> Option<Self> {
        match selector {
            selector if selector == Self::MovReg.selector() => Some(Self::MovReg),
            selector if selector == Self::MovImm.selector() => Some(Self::MovImm),
            selector if selector == Self::Add.selector() => Some(Self::Add),
            selector if selector == Self::Sub.selector() => Some(Self::Sub),
            selector if selector == Self::And.selector() => Some(Self::And),
            selector if selector == Self::Orr.selector() => Some(Self::Orr),
            selector if selector == Self::Eor.selector() => Some(Self::Eor),
            selector if selector == Self::Lsl.selector() => Some(Self::Lsl),
            selector if selector == Self::Lsr.selector() => Some(Self::Lsr),
            selector if selector == Self::Asr.selector() => Some(Self::Asr),
            _ => None,
        }
    }
}

/// Number of instruction opcodes we support
pub const NUM_OPCODES: u64 =
    (SketchOpcode::Asr.selector() - SketchOpcode::MovReg.selector() + 1) as u64;
/// Number of registers (X0-X30 + XZR = 32)
pub const NUM_REGISTERS: u64 = 32;

/// A symbolic instruction where opcode and operands are Z3 variables
pub struct SymbolicInstruction {
    /// Opcode selector encoded by [`SketchOpcode`]
    pub opcode: Int,
    /// Destination register index (0-31)
    pub rd: Int,
    /// First source register index (0-31)
    pub rn: Int,
    /// Second operand - either register index or immediate selector
    pub rm_reg: Int,
    /// Whether rm is a register (true) or immediate (false)
    pub rm_is_reg: Bool,
    /// Immediate value index into the immediate table
    pub rm_imm_idx: Int,
}

impl SymbolicInstruction {
    /// Create a new symbolic instruction with unique variable names
    pub fn new(prefix: &str) -> Self {
        Self {
            opcode: Int::new_const(format!("{}_opcode", prefix)),
            rd: Int::new_const(format!("{}_rd", prefix)),
            rn: Int::new_const(format!("{}_rn", prefix)),
            rm_reg: Int::new_const(format!("{}_rm_reg", prefix)),
            rm_is_reg: Bool::new_const(format!("{}_rm_is_reg", prefix)),
            rm_imm_idx: Int::new_const(format!("{}_rm_imm_idx", prefix)),
        }
    }

    /// Add constraints to ensure variables are within valid ranges
    pub fn add_range_constraints(&self, num_immediates: usize) -> Bool {
        let zero = Int::from_i64(0);
        let min_opcode = Int::from_i64(SketchOpcode::MovReg.selector());
        let max_opcode = Int::from_i64(SketchOpcode::Asr.selector());
        let max_reg = Int::from_i64(NUM_REGISTERS as i64 - 1);
        let max_imm = Int::from_i64(num_immediates as i64 - 1);

        let opcode_valid = self.opcode.ge(&min_opcode) & self.opcode.le(&max_opcode);
        let rd_valid = self.rd.ge(&zero) & self.rd.le(&max_reg);
        let rn_valid = self.rn.ge(&zero) & self.rn.le(&max_reg);
        let rm_reg_valid = self.rm_reg.ge(&zero) & self.rm_reg.le(&max_reg);
        let rm_imm_valid = self.rm_imm_idx.ge(&zero) & self.rm_imm_idx.le(&max_imm);
        let rm_is_immediate = self.rm_is_reg.not();
        let rm_imm_valid_when_immediate = rm_is_immediate.implies(&rm_imm_valid);
        let mov_reg_uses_register = self
            .opcode
            .eq(Int::from_i64(SketchOpcode::MovReg.selector()))
            .implies(&self.rm_is_reg);
        let mov_imm_uses_immediate = self
            .opcode
            .eq(Int::from_i64(SketchOpcode::MovImm.selector()))
            .implies(&rm_is_immediate);

        opcode_valid
            & rd_valid
            & rn_valid
            & rm_reg_valid
            & rm_imm_valid_when_immediate
            & mov_reg_uses_register
            & mov_imm_uses_immediate
    }

    /// Extract a concrete instruction from a satisfying model
    pub fn extract_from_model(&self, model: &Model, immediates: &[i64]) -> Option<Instruction> {
        let opcode = SketchOpcode::from_selector(model.eval(&self.opcode, true)?.as_i64()?)?;
        let rd = Self::extract_register(model, &self.rd)?;
        let rm_is_reg = model.eval(&self.rm_is_reg, true)?.as_bool()?;

        match opcode {
            SketchOpcode::MovReg => {
                if !rm_is_reg {
                    return None;
                }
                let rn = Self::extract_register(model, &self.rn)?;
                Some(Instruction::MovReg { rd, rn })
            }
            SketchOpcode::MovImm => {
                if rm_is_reg {
                    return None;
                }
                let imm = self.extract_immediate(model, immediates)?;
                Some(Instruction::MovImm { rd, imm })
            }
            SketchOpcode::Add
            | SketchOpcode::Sub
            | SketchOpcode::And
            | SketchOpcode::Orr
            | SketchOpcode::Eor
            | SketchOpcode::Lsl
            | SketchOpcode::Lsr
            | SketchOpcode::Asr => {
                let rn = Self::extract_register(model, &self.rn)?;
                let rm = self.extract_rm_operand(model, immediates, rm_is_reg)?;
                match opcode {
                    SketchOpcode::Add => Some(Instruction::Add { rd, rn, rm }),
                    SketchOpcode::Sub => Some(Instruction::Sub { rd, rn, rm }),
                    SketchOpcode::And => Some(Instruction::And {
                        rd,
                        rn,
                        rm,
                        width: crate::ir::RegisterWidth::X64,
                    }),
                    SketchOpcode::Orr => Some(Instruction::Orr {
                        rd,
                        rn,
                        rm,
                        width: crate::ir::RegisterWidth::X64,
                    }),
                    SketchOpcode::Eor => Some(Instruction::Eor {
                        rd,
                        rn,
                        rm,
                        width: crate::ir::RegisterWidth::X64,
                    }),
                    SketchOpcode::Lsl => Some(Instruction::Lsl { rd, rn, shift: rm }),
                    SketchOpcode::Lsr => Some(Instruction::Lsr { rd, rn, shift: rm }),
                    SketchOpcode::Asr => Some(Instruction::Asr { rd, rn, shift: rm }),
                    SketchOpcode::MovReg | SketchOpcode::MovImm => unreachable!(),
                }
            }
        }
    }

    fn extract_register(model: &Model, register: &Int) -> Option<Register> {
        let idx = u8::try_from(model.eval(register, true)?.as_i64()?).ok()?;
        Register::from_index(idx)
    }

    fn extract_immediate(&self, model: &Model, immediates: &[i64]) -> Option<i64> {
        let imm_idx = usize::try_from(model.eval(&self.rm_imm_idx, true)?.as_i64()?).ok()?;
        immediates.get(imm_idx).copied()
    }

    fn extract_rm_operand(
        &self,
        model: &Model,
        immediates: &[i64],
        rm_is_reg: bool,
    ) -> Option<Operand> {
        if rm_is_reg {
            Some(Operand::Register(Self::extract_register(
                model,
                &self.rm_reg,
            )?))
        } else {
            Some(Operand::Immediate(
                self.extract_immediate(model, immediates)?,
            ))
        }
    }
}

/// A sequence of symbolic instructions (a sketch)
pub struct SymbolicSketch {
    pub instructions: Vec<SymbolicInstruction>,
}

impl SymbolicSketch {
    /// Create a new sketch with the given number of instruction slots
    pub fn new(length: usize, prefix: &str) -> Self {
        let instructions = (0..length)
            .map(|i| SymbolicInstruction::new(&format!("{}_{}", prefix, i)))
            .collect();
        Self { instructions }
    }

    /// Add range constraints for all instructions
    pub fn add_range_constraints(&self, num_immediates: usize) -> Bool {
        if self.instructions.is_empty() {
            return Bool::from_bool(true);
        }

        let constraints: Vec<_> = self
            .instructions
            .iter()
            .map(|instr| instr.add_range_constraints(num_immediates))
            .collect();

        // Combine all constraints with AND
        let mut result = constraints[0].clone();
        for c in constraints.iter().skip(1) {
            result &= c.clone();
        }
        result
    }

    /// Extract concrete instructions from a model
    pub fn extract_from_model(
        &self,
        model: &Model,
        immediates: &[i64],
    ) -> Option<Vec<Instruction>> {
        self.instructions
            .iter()
            .map(|instr| instr.extract_from_model(model, immediates))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::RegisterWidth;
    use z3::{SatResult, Solver};

    #[test]
    fn sketch_opcode_selectors_round_trip_and_extract_expected_instructions() {
        let register_operand = Operand::Register(Register::X2);
        let cases = [
            (
                SketchOpcode::MovReg,
                Instruction::MovReg {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                SketchOpcode::MovImm,
                Instruction::MovImm {
                    rd: Register::X0,
                    imm: 7,
                },
            ),
            (
                SketchOpcode::Add,
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: register_operand,
                },
            ),
            (
                SketchOpcode::Sub,
                Instruction::Sub {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: register_operand,
                },
            ),
            (
                SketchOpcode::And,
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: register_operand,
                    width: RegisterWidth::X64,
                },
            ),
            (
                SketchOpcode::Orr,
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: register_operand,
                    width: RegisterWidth::X64,
                },
            ),
            (
                SketchOpcode::Eor,
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: register_operand,
                    width: RegisterWidth::X64,
                },
            ),
            (
                SketchOpcode::Lsl,
                Instruction::Lsl {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift: register_operand,
                },
            ),
            (
                SketchOpcode::Lsr,
                Instruction::Lsr {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift: register_operand,
                },
            ),
            (
                SketchOpcode::Asr,
                Instruction::Asr {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift: register_operand,
                },
            ),
        ];
        assert_eq!(NUM_OPCODES as usize, cases.len());

        for (index, (opcode, expected)) in cases.into_iter().enumerate() {
            assert_eq!(SketchOpcode::from_selector(opcode.selector()), Some(opcode));

            let instr = SymbolicInstruction::new(&format!("extract_opcode_{index}"));
            let solver = Solver::new();
            solver.assert(instr.opcode.eq(Int::from_i64(opcode.selector())));
            solver.assert(instr.rd.eq(Int::from_i64(0)));
            solver.assert(instr.rn.eq(Int::from_i64(1)));
            solver.assert(instr.rm_reg.eq(Int::from_i64(2)));
            solver.assert(instr.rm_imm_idx.eq(Int::from_i64(0)));
            if opcode == SketchOpcode::MovImm {
                solver.assert(instr.rm_is_reg.not());
            } else {
                solver.assert(&instr.rm_is_reg);
            }

            assert_eq!(solver.check(), SatResult::Sat);
            let model = solver.get_model().unwrap();
            assert_eq!(instr.extract_from_model(&model, &[7]), Some(expected));
        }

        for (index, selector) in [
            SketchOpcode::MovReg.selector() - 1,
            SketchOpcode::Asr.selector() + 1,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(SketchOpcode::from_selector(selector), None);

            let instr = SymbolicInstruction::new(&format!("invalid_opcode_{index}"));
            let solver = Solver::new();
            solver.assert(instr.opcode.eq(Int::from_i64(selector)));
            solver.assert(instr.rd.eq(Int::from_i64(0)));
            solver.assert(&instr.rm_is_reg);
            assert_eq!(solver.check(), SatResult::Sat);

            let model = solver.get_model().unwrap();
            assert!(instr.extract_from_model(&model, &[7]).is_none());
        }
    }

    #[test]
    fn test_symbolic_instruction_creation() {
        let instr = SymbolicInstruction::new("test");

        // Just verify the instruction is created without errors
        assert!(instr.opcode.to_string().contains("test_opcode"));
    }

    #[test]
    fn test_symbolic_sketch_creation() {
        let sketch = SymbolicSketch::new(3, "sketch");

        assert_eq!(sketch.instructions.len(), 3);
    }

    #[test]
    fn test_range_constraints() {
        let instr = SymbolicInstruction::new("test");
        let constraints = instr.add_range_constraints(5);

        // Verify constraints are created
        assert!(!constraints.to_string().is_empty());
    }

    #[test]
    fn register_operand_constraints_allow_empty_immediate_table() {
        for (opcode, prefix) in [
            (SketchOpcode::MovReg, "mov_reg"),
            (SketchOpcode::Add, "add_reg"),
        ] {
            let instr = SymbolicInstruction::new(prefix);
            let solver = Solver::new();

            solver.assert(instr.add_range_constraints(0));
            solver.assert(instr.opcode.eq(Int::from_i64(opcode.selector())));
            solver.assert(instr.rd.eq(Int::from_i64(0)));
            solver.assert(instr.rn.eq(Int::from_i64(1)));
            solver.assert(instr.rm_reg.eq(Int::from_i64(2)));
            solver.assert(&instr.rm_is_reg);

            assert_eq!(solver.check(), SatResult::Sat, "{prefix}");
        }
    }

    #[test]
    fn mov_imm_constraints_require_immediate_operand() {
        let instr = SymbolicInstruction::new("mov_imm_reg_operand");
        let solver = Solver::new();
        solver.assert(instr.add_range_constraints(1));
        solver.assert(
            instr
                .opcode
                .eq(Int::from_i64(SketchOpcode::MovImm.selector())),
        );
        solver.assert(instr.rd.eq(Int::from_i64(0)));
        solver.assert(instr.rn.eq(Int::from_i64(1)));
        solver.assert(instr.rm_reg.eq(Int::from_i64(2)));
        solver.assert(instr.rm_imm_idx.eq(Int::from_i64(0)));
        solver.assert(&instr.rm_is_reg);
        assert_eq!(solver.check(), SatResult::Unsat);

        let instr = SymbolicInstruction::new("mov_imm_imm_operand");
        let solver = Solver::new();
        let immediate_operand = instr.rm_is_reg.not();
        solver.assert(instr.add_range_constraints(1));
        solver.assert(
            instr
                .opcode
                .eq(Int::from_i64(SketchOpcode::MovImm.selector())),
        );
        solver.assert(instr.rd.eq(Int::from_i64(0)));
        solver.assert(instr.rn.eq(Int::from_i64(1)));
        solver.assert(instr.rm_imm_idx.eq(Int::from_i64(0)));
        solver.assert(&immediate_operand);
        assert_eq!(solver.check(), SatResult::Sat);

        let instr = SymbolicInstruction::new("mov_imm_no_immediates");
        let solver = Solver::new();
        solver.assert(instr.add_range_constraints(0));
        solver.assert(
            instr
                .opcode
                .eq(Int::from_i64(SketchOpcode::MovImm.selector())),
        );
        solver.assert(instr.rd.eq(Int::from_i64(0)));
        solver.assert(instr.rn.eq(Int::from_i64(1)));
        solver.assert(instr.rm_reg.eq(Int::from_i64(2)));
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn extract_mov_imm_rejects_register_operand_model() {
        let instr = SymbolicInstruction::new("extract_mov_imm_reg_operand");
        let solver = Solver::new();
        solver.assert(
            instr
                .opcode
                .eq(Int::from_i64(SketchOpcode::MovImm.selector())),
        );
        solver.assert(instr.rd.eq(Int::from_i64(0)));
        solver.assert(instr.rn.eq(Int::from_i64(1)));
        solver.assert(instr.rm_reg.eq(Int::from_i64(2)));
        solver.assert(&instr.rm_is_reg);

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();

        assert!(instr.extract_from_model(&model, &[7]).is_none());
    }

    #[test]
    fn extract_mov_reg_rejects_immediate_operand_model() {
        let instr = SymbolicInstruction::new("extract_mov_reg_imm_operand");
        let solver = Solver::new();
        let immediate_operand = instr.rm_is_reg.not();
        solver.assert(
            instr
                .opcode
                .eq(Int::from_i64(SketchOpcode::MovReg.selector())),
        );
        solver.assert(instr.rd.eq(Int::from_i64(0)));
        solver.assert(instr.rn.eq(Int::from_i64(1)));
        solver.assert(instr.rm_imm_idx.eq(Int::from_i64(0)));
        solver.assert(&immediate_operand);

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();

        assert!(instr.extract_from_model(&model, &[7]).is_none());
    }
}
