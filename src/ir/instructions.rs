//! AArch64 instruction definitions for the IR

use crate::ir::types::{Condition, Operand, Register};
use std::fmt;

/// AArch64 instructions supported by the IR
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum Instruction {
    // Data movement
    MovReg {
        rd: Register,
        rn: Register,
    },
    MovImm {
        rd: Register,
        imm: i64,
    },

    // Arithmetic
    Add {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Sub {
        rd: Register,
        rn: Register,
        rm: Operand,
    },

    // Logical
    And {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Orr {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Eor {
        rd: Register,
        rn: Register,
        rm: Operand,
    },

    // Shifts
    Lsl {
        rd: Register,
        rn: Register,
        shift: Operand,
    },
    Lsr {
        rd: Register,
        rn: Register,
        shift: Operand,
    },
    Asr {
        rd: Register,
        rn: Register,
        shift: Operand,
    },

    // Multiplication and division
    Mul {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Sdiv {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Udiv {
        rd: Register,
        rn: Register,
        rm: Register,
    },

    // Comparison (set NZCV flags, no destination register)
    Cmp {
        rn: Register,
        rm: Operand,
    },
    Cmn {
        rn: Register,
        rm: Operand,
    },
    Tst {
        rn: Register,
        rm: Operand,
    },

    // Conditional select
    Csel {
        rd: Register,
        rn: Register,
        rm: Register,
        cond: Condition,
    },
    Csinc {
        rd: Register,
        rn: Register,
        rm: Register,
        cond: Condition,
    },
    Csinv {
        rd: Register,
        rn: Register,
        rm: Register,
        cond: Condition,
    },
    Csneg {
        rd: Register,
        rn: Register,
        rm: Register,
        cond: Condition,
    },

    // Bitwise NOT (alias of ORN with XZR)
    Mvn {
        rd: Register,
        rm: Register,
    },
    // Two's-complement negation (alias of SUB from XZR)
    Neg {
        rd: Register,
        rm: Register,
    },
    // Flag-setting negation (alias of SUBS from XZR)
    Negs {
        rd: Register,
        rm: Register,
    },
    // Move-negated immediate: rd = !((imm as u64) << shift), shift ∈ {0,16,32,48}
    MovN {
        rd: Register,
        imm: u16,
        shift: u8,
    },

    // Inverted-logical (second operand bitwise-NOTed before the op)
    Bic {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Bics {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Orn {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Eon {
        rd: Register,
        rn: Register,
        rm: Operand,
    },

    // Flag-setting arithmetic / logical
    Adds {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Subs {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Ands {
        rd: Register,
        rn: Register,
        rm: Operand,
    },

    // Conditional set: rd = (cond holds) ? 1 : 0
    Cset {
        rd: Register,
        cond: Condition,
    },
    // Conditional set mask: rd = (cond holds) ? -1 : 0
    Csetm {
        rd: Register,
        cond: Condition,
    },

    // Rotate right (immediate or register form)
    Ror {
        rd: Register,
        rn: Register,
        shift: Operand,
    },
}

impl Instruction {
    /// Get the destination register for this instruction (None for comparison instructions)
    #[allow(dead_code)]
    pub fn destination(&self) -> Option<Register> {
        match self {
            Instruction::MovReg { rd, .. }
            | Instruction::MovImm { rd, .. }
            | Instruction::Add { rd, .. }
            | Instruction::Sub { rd, .. }
            | Instruction::And { rd, .. }
            | Instruction::Orr { rd, .. }
            | Instruction::Eor { rd, .. }
            | Instruction::Lsl { rd, .. }
            | Instruction::Lsr { rd, .. }
            | Instruction::Asr { rd, .. }
            | Instruction::Mul { rd, .. }
            | Instruction::Sdiv { rd, .. }
            | Instruction::Udiv { rd, .. }
            | Instruction::Csel { rd, .. }
            | Instruction::Csinc { rd, .. }
            | Instruction::Csinv { rd, .. }
            | Instruction::Csneg { rd, .. }
            | Instruction::Mvn { rd, .. }
            | Instruction::Neg { rd, .. }
            | Instruction::Negs { rd, .. }
            | Instruction::MovN { rd, .. }
            | Instruction::Bic { rd, .. }
            | Instruction::Bics { rd, .. }
            | Instruction::Orn { rd, .. }
            | Instruction::Eon { rd, .. }
            | Instruction::Adds { rd, .. }
            | Instruction::Subs { rd, .. }
            | Instruction::Ands { rd, .. }
            | Instruction::Cset { rd, .. }
            | Instruction::Csetm { rd, .. }
            | Instruction::Ror { rd, .. } => Some(*rd),
            // Comparison instructions only set flags, no destination register
            Instruction::Cmp { .. } | Instruction::Cmn { .. } | Instruction::Tst { .. } => None,
        }
    }

    /// Returns true if this instruction modifies NZCV flags.
    ///
    /// Note: for flag-setting variants (NEGS, ADDS, SUBS, ANDS, BICS), this
    /// can co-occur with `destination().is_some()` — those write both a
    /// register and the NZCV flags. Earlier callers that assumed
    /// "flag-setter ⇒ no destination" must be re-verified.
    pub fn modifies_flags(&self) -> bool {
        matches!(
            self,
            Instruction::Cmp { .. }
                | Instruction::Cmn { .. }
                | Instruction::Tst { .. }
                | Instruction::Negs { .. }
                | Instruction::Bics { .. }
                | Instruction::Adds { .. }
                | Instruction::Subs { .. }
                | Instruction::Ands { .. }
        )
    }

    /// Returns true if this instruction reads NZCV flags
    #[allow(dead_code)]
    pub fn reads_flags(&self) -> bool {
        matches!(
            self,
            Instruction::Csel { .. }
                | Instruction::Csinc { .. }
                | Instruction::Csinv { .. }
                | Instruction::Csneg { .. }
                | Instruction::Cset { .. }
                | Instruction::Csetm { .. }
        )
    }

    /// Check if this instruction can be encoded in AArch64 machine code.
    ///
    /// This validates immediate operand ranges against AArch64 encoding constraints:
    /// - MOV immediate: 0 to 0xFFFF (16-bit)
    /// - ADD/SUB immediate: 0 to 0xFFF (12-bit unsigned)
    /// - CMP/CMN immediate: 0 to 0xFFF (12-bit unsigned)
    /// - LSL/LSR/ASR immediate: 0 to 63
    /// - AND/ORR/EOR immediate: register only (bitmask encoding not supported)
    /// - TST immediate: register only (bitmask encoding not supported)
    pub fn is_encodable_aarch64(&self) -> bool {
        match self {
            // MovReg is always encodable
            Instruction::MovReg { .. } => true,

            // MOV immediate: 16-bit range
            Instruction::MovImm { imm, .. } => *imm >= 0 && *imm <= 0xFFFF,

            // ADD/SUB immediate: 12-bit unsigned range
            Instruction::Add { rm, .. } | Instruction::Sub { rm, .. } => match rm {
                Operand::Register(_) => true,
                Operand::Immediate(imm) => *imm >= 0 && *imm <= 0xFFF,
            },

            // AND/ORR/EOR: only register operands supported (bitmask immediates are complex)
            Instruction::And { rm, .. }
            | Instruction::Orr { rm, .. }
            | Instruction::Eor { rm, .. } => matches!(rm, Operand::Register(_)),

            // Shift instructions: shift amount 0-63 for 64-bit registers
            Instruction::Lsl { shift, .. }
            | Instruction::Lsr { shift, .. }
            | Instruction::Asr { shift, .. } => match shift {
                Operand::Register(_) => true,
                Operand::Immediate(amt) => *amt >= 0 && *amt <= 63,
            },

            // MUL/SDIV/UDIV: always register operands, always encodable
            Instruction::Mul { .. } | Instruction::Sdiv { .. } | Instruction::Udiv { .. } => true,

            // CMP/CMN immediate: 12-bit unsigned range
            Instruction::Cmp { rm, .. } | Instruction::Cmn { rm, .. } => match rm {
                Operand::Register(_) => true,
                Operand::Immediate(imm) => *imm >= 0 && *imm <= 0xFFF,
            },

            // TST: only register operands supported
            Instruction::Tst { rm, .. } => matches!(rm, Operand::Register(_)),

            // Conditional select: always encodable (register-only)
            Instruction::Csel { .. }
            | Instruction::Csinc { .. }
            | Instruction::Csinv { .. }
            | Instruction::Csneg { .. } => true,

            // MVN / NEG / NEGS: always encodable (register-only)
            Instruction::Mvn { .. } | Instruction::Neg { .. } | Instruction::Negs { .. } => true,

            // MOVN: shift must be one of {0, 16, 32, 48}; u16 imm is always in range.
            Instruction::MovN { shift, .. } => matches!(shift, 0 | 16 | 32 | 48),

            // BIC / BICS / ORN / EON: register-only (matching AND precedent).
            Instruction::Bic { rm, .. }
            | Instruction::Bics { rm, .. }
            | Instruction::Orn { rm, .. }
            | Instruction::Eon { rm, .. } => matches!(rm, Operand::Register(_)),

            // ADDS/SUBS: imm 0..=0xFFF (same as ADD/SUB).
            Instruction::Adds { rm, .. } | Instruction::Subs { rm, .. } => match rm {
                Operand::Register(_) => true,
                Operand::Immediate(imm) => *imm >= 0 && *imm <= 0xFFF,
            },
            // ANDS: register-only (same as AND).
            Instruction::Ands { rm, .. } => matches!(rm, Operand::Register(_)),

            // CSET / CSETM: reject AL (always true ⇒ unconditional 1/-1) and
            // NV (reserved). All other 14 conditions are encodable.
            Instruction::Cset { cond, .. } | Instruction::Csetm { cond, .. } => {
                !matches!(cond, Condition::AL | Condition::NV)
            }

            // ROR: shift amount 0..=63 (same as LSL/LSR/ASR).
            Instruction::Ror { shift, .. } => match shift {
                Operand::Register(_) => true,
                Operand::Immediate(amt) => *amt >= 0 && *amt <= 63,
            },
        }
    }

    /// Get all source registers used by this instruction
    #[allow(dead_code)]
    pub fn source_registers(&self) -> Vec<Register> {
        match self {
            Instruction::MovReg { rn, .. } => vec![*rn],
            Instruction::MovImm { .. } => vec![],
            Instruction::Add { rn, rm, .. }
            | Instruction::Sub { rn, rm, .. }
            | Instruction::And { rn, rm, .. }
            | Instruction::Orr { rn, rm, .. }
            | Instruction::Eor { rn, rm, .. } => {
                let mut regs = vec![*rn];
                if let Operand::Register(r) = rm {
                    regs.push(*r);
                }
                regs
            }
            Instruction::Lsl { rn, shift, .. }
            | Instruction::Lsr { rn, shift, .. }
            | Instruction::Asr { rn, shift, .. } => {
                let mut regs = vec![*rn];
                if let Operand::Register(r) = shift {
                    regs.push(*r);
                }
                regs
            }
            Instruction::Mul { rn, rm, .. }
            | Instruction::Sdiv { rn, rm, .. }
            | Instruction::Udiv { rn, rm, .. } => vec![*rn, *rm],
            // Comparison instructions read rn and rm (if register)
            Instruction::Cmp { rn, rm }
            | Instruction::Cmn { rn, rm }
            | Instruction::Tst { rn, rm } => {
                let mut regs = vec![*rn];
                if let Operand::Register(r) = rm {
                    regs.push(*r);
                }
                regs
            }
            // Conditional select instructions read rn and rm
            Instruction::Csel { rn, rm, .. }
            | Instruction::Csinc { rn, rm, .. }
            | Instruction::Csinv { rn, rm, .. }
            | Instruction::Csneg { rn, rm, .. } => vec![*rn, *rm],
            // Unary
            Instruction::Mvn { rm, .. }
            | Instruction::Neg { rm, .. }
            | Instruction::Negs { rm, .. } => vec![*rm],
            // MOVN takes no register source
            Instruction::MovN { .. } => vec![],
            // Inverted-logical (BIC / BICS / ORN / EON) and flag-setting arith/logical
            Instruction::Bic { rn, rm, .. }
            | Instruction::Bics { rn, rm, .. }
            | Instruction::Orn { rn, rm, .. }
            | Instruction::Eon { rn, rm, .. }
            | Instruction::Adds { rn, rm, .. }
            | Instruction::Subs { rn, rm, .. }
            | Instruction::Ands { rn, rm, .. } => {
                let mut regs = vec![*rn];
                if let Operand::Register(r) = rm {
                    regs.push(*r);
                }
                regs
            }
            // CSET / CSETM have no source registers (read flags, not regs).
            Instruction::Cset { .. } | Instruction::Csetm { .. } => vec![],
            // ROR reads rn and shift (if register)
            Instruction::Ror { rn, shift, .. } => {
                let mut regs = vec![*rn];
                if let Operand::Register(r) = shift {
                    regs.push(*r);
                }
                regs
            }
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::MovReg { rd, rn } => write!(f, "mov {}, {}", rd, rn),
            Instruction::MovImm { rd, imm } => write!(f, "mov {}, #{}", rd, imm),
            Instruction::Add { rd, rn, rm } => write!(f, "add {}, {}, {}", rd, rn, rm),
            Instruction::Sub { rd, rn, rm } => write!(f, "sub {}, {}, {}", rd, rn, rm),
            Instruction::And { rd, rn, rm } => write!(f, "and {}, {}, {}", rd, rn, rm),
            Instruction::Orr { rd, rn, rm } => write!(f, "orr {}, {}, {}", rd, rn, rm),
            Instruction::Eor { rd, rn, rm } => write!(f, "eor {}, {}, {}", rd, rn, rm),
            Instruction::Lsl { rd, rn, shift } => write!(f, "lsl {}, {}, {}", rd, rn, shift),
            Instruction::Lsr { rd, rn, shift } => write!(f, "lsr {}, {}, {}", rd, rn, shift),
            Instruction::Asr { rd, rn, shift } => write!(f, "asr {}, {}, {}", rd, rn, shift),
            Instruction::Mul { rd, rn, rm } => write!(f, "mul {}, {}, {}", rd, rn, rm),
            Instruction::Sdiv { rd, rn, rm } => write!(f, "sdiv {}, {}, {}", rd, rn, rm),
            Instruction::Udiv { rd, rn, rm } => write!(f, "udiv {}, {}, {}", rd, rn, rm),
            // Comparison instructions
            Instruction::Cmp { rn, rm } => write!(f, "cmp {}, {}", rn, rm),
            Instruction::Cmn { rn, rm } => write!(f, "cmn {}, {}", rn, rm),
            Instruction::Tst { rn, rm } => write!(f, "tst {}, {}", rn, rm),
            // Conditional select instructions
            Instruction::Csel { rd, rn, rm, cond } => {
                write!(f, "csel {}, {}, {}, {}", rd, rn, rm, cond)
            }
            Instruction::Csinc { rd, rn, rm, cond } => {
                write!(f, "csinc {}, {}, {}, {}", rd, rn, rm, cond)
            }
            Instruction::Csinv { rd, rn, rm, cond } => {
                write!(f, "csinv {}, {}, {}, {}", rd, rn, rm, cond)
            }
            Instruction::Csneg { rd, rn, rm, cond } => {
                write!(f, "csneg {}, {}, {}, {}", rd, rn, rm, cond)
            }
            Instruction::Mvn { rd, rm } => write!(f, "mvn {}, {}", rd, rm),
            Instruction::Neg { rd, rm } => write!(f, "neg {}, {}", rd, rm),
            Instruction::Negs { rd, rm } => write!(f, "negs {}, {}", rd, rm),
            Instruction::MovN { rd, imm, shift } => {
                if *shift == 0 {
                    write!(f, "movn {}, #{}", rd, imm)
                } else {
                    write!(f, "movn {}, #{}, lsl #{}", rd, imm, shift)
                }
            }
            Instruction::Bic { rd, rn, rm } => write!(f, "bic {}, {}, {}", rd, rn, rm),
            Instruction::Bics { rd, rn, rm } => write!(f, "bics {}, {}, {}", rd, rn, rm),
            Instruction::Orn { rd, rn, rm } => write!(f, "orn {}, {}, {}", rd, rn, rm),
            Instruction::Eon { rd, rn, rm } => write!(f, "eon {}, {}, {}", rd, rn, rm),
            Instruction::Adds { rd, rn, rm } => write!(f, "adds {}, {}, {}", rd, rn, rm),
            Instruction::Subs { rd, rn, rm } => write!(f, "subs {}, {}, {}", rd, rn, rm),
            Instruction::Ands { rd, rn, rm } => write!(f, "ands {}, {}, {}", rd, rn, rm),
            Instruction::Cset { rd, cond } => write!(f, "cset {}, {}", rd, cond),
            Instruction::Csetm { rd, cond } => write!(f, "csetm {}, {}", rd, cond),
            Instruction::Ror { rd, rn, shift } => write!(f, "ror {}, {}, {}", rd, rn, shift),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_display() {
        let mov_reg = Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(format!("{}", mov_reg), "mov x0, x1");

        let mov_imm = Instruction::MovImm {
            rd: Register::X2,
            imm: 42,
        };
        assert_eq!(format!("{}", mov_imm), "mov x2, #42");

        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        assert_eq!(format!("{}", add), "add x0, x1, x2");

        let eor = Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        };
        assert_eq!(format!("{}", eor), "eor x0, x0, x0");
    }

    #[test]
    fn test_destination() {
        let instr = Instruction::Add {
            rd: Register::X5,
            rn: Register::X1,
            rm: Operand::Immediate(10),
        };
        assert_eq!(instr.destination(), Some(Register::X5));

        // Comparison instructions have no destination
        let cmp = Instruction::Cmp {
            rn: Register::X0,
            rm: Operand::Register(Register::X1),
        };
        assert_eq!(cmp.destination(), None);
    }

    #[test]
    fn test_source_registers() {
        let mov_reg = Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(mov_reg.source_registers(), vec![Register::X1]);

        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        assert_eq!(add.source_registers(), vec![Register::X1, Register::X2]);

        let add_imm = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(5),
        };
        assert_eq!(add_imm.source_registers(), vec![Register::X1]);
    }

    #[test]
    fn test_is_encodable_mov() {
        // MovReg is always encodable
        assert!(
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1
            }
            .is_encodable_aarch64()
        );

        // MovImm in range
        assert!(
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0xFFFF
            }
            .is_encodable_aarch64()
        );

        // MovImm out of range
        assert!(
            !Instruction::MovImm {
                rd: Register::X0,
                imm: -1
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::MovImm {
                rd: Register::X0,
                imm: 0x10000
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_is_encodable_add_sub() {
        // Register operand is always valid
        assert!(
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2)
            }
            .is_encodable_aarch64()
        );

        // Valid immediate range (0-4095)
        assert!(
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0)
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0xFFF)
            }
            .is_encodable_aarch64()
        );

        // Invalid: negative immediate
        assert!(
            !Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(-1)
            }
            .is_encodable_aarch64()
        );

        // Invalid: immediate too large
        assert!(
            !Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0x1000)
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_is_encodable_logical() {
        // Register operand is valid
        assert!(
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2)
            }
            .is_encodable_aarch64()
        );

        // Immediate operand not supported for AND/ORR/EOR
        assert!(
            !Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0xFF)
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1)
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0)
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_is_encodable_shift() {
        // Register shift is valid
        assert!(
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2)
            }
            .is_encodable_aarch64()
        );

        // Valid shift range (0-63)
        assert!(
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(0)
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(63)
            }
            .is_encodable_aarch64()
        );

        // Invalid: negative shift
        assert!(
            !Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(-1)
            }
            .is_encodable_aarch64()
        );

        // Invalid: shift too large
        assert!(
            !Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(64)
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_mvn_display_and_helpers() {
        let mvn = Instruction::Mvn {
            rd: Register::X0,
            rm: Register::X1,
        };
        assert_eq!(format!("{}", mvn), "mvn x0, x1");
        assert_eq!(mvn.destination(), Some(Register::X0));
        assert_eq!(mvn.source_registers(), vec![Register::X1]);
        assert!(!mvn.modifies_flags());
        assert!(!mvn.reads_flags());
        assert!(mvn.is_encodable_aarch64());
    }

    #[test]
    fn test_is_encodable_cmp() {
        // Register operand is valid
        assert!(
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1)
            }
            .is_encodable_aarch64()
        );

        // Valid immediate range
        assert!(
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Immediate(0xFFF)
            }
            .is_encodable_aarch64()
        );

        // Invalid immediate
        assert!(
            !Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Immediate(-1)
            }
            .is_encodable_aarch64()
        );

        // TST only supports register operands
        assert!(
            Instruction::Tst {
                rn: Register::X0,
                rm: Operand::Register(Register::X1)
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Tst {
                rn: Register::X0,
                rm: Operand::Immediate(1)
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn all_instruction_variants_cover_helpers_and_display() {
        let cases = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(2),
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Mul {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Sdiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Udiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Csel {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::EQ,
            },
            Instruction::Csinc {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::NE,
            },
            Instruction::Csinv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::LT,
            },
            Instruction::Csneg {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::GT,
            },
            Instruction::Mvn {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Neg {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Negs {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 1,
                shift: 16,
            },
            Instruction::Bic {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Bics {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Orn {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Eon {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::GE,
            },
            Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::LE,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(4),
            },
        ];

        for instr in cases {
            let rendered = format!("{}", instr);
            assert!(!rendered.is_empty());
            let _ = instr.destination();
            let _ = instr.source_registers();
            let _ = instr.modifies_flags();
            let _ = instr.reads_flags();
            let _ = instr.is_encodable_aarch64();
        }
    }
}
