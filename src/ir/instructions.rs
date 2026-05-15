//! AArch64 instruction definitions for the IR

use crate::ir::types::{Condition, Operand, Register, ShiftKind};
use std::fmt;

/// Legal `lsl` amounts for the move-wide immediate family (MOVN / MOVZ / MOVK).
/// Single source of truth shared by `is_encodable_aarch64`, the parser, and
/// every random-generation / mutation site so the four positions cannot drift
/// out of sync across the codebase.
pub const MOVW_LEGAL_SHIFTS: [u8; 4] = [0, 16, 32, 48];

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

    // Multiply-accumulate (rd = ra ± rn*rm) and high-half multiplies
    Madd {
        rd: Register,
        rn: Register,
        rm: Register,
        ra: Register,
    },
    Msub {
        rd: Register,
        rn: Register,
        rm: Register,
        ra: Register,
    },
    Mneg {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Smulh {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Umulh {
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

    // Conditional compare (subtract): if `cond` holds, set NZCV from
    // `rn - operand(rm)`; otherwise set NZCV to the 4-bit `nzcv` literal
    // (bit3=N, bit2=Z, bit1=C, bit0=V). Reads and writes NZCV.
    Ccmp {
        rn: Register,
        rm: Operand,
        nzcv: u8,
        cond: Condition,
    },
    // Conditional compare negative (add): same as Ccmp with `rn + operand(rm)`.
    Ccmn {
        rn: Register,
        rm: Operand,
        nzcv: u8,
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
    // Move-wide-zero immediate: rd = (imm as u64) << shift, shift ∈ {0,16,32,48}
    MovZ {
        rd: Register,
        imm: u16,
        shift: u8,
    },
    // Move-wide-keep immediate: writes one 16-bit chunk, preserving the rest.
    // rd = (rd & ~(0xFFFF << shift)) | ((imm as u64) << shift), shift ∈ {0,16,32,48}.
    // Unlike MovN/MovZ this reads rd, so the rd register must be live-in.
    MovK {
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

    // Single-source bit-manipulation (always register-only, {rd, rn})
    Clz {
        rd: Register,
        rn: Register,
    },
    Cls {
        rd: Register,
        rn: Register,
    },
    Rbit {
        rd: Register,
        rn: Register,
    },
    Rev {
        rd: Register,
        rn: Register,
    },
    Rev32 {
        rd: Register,
        rn: Register,
    },
    Rev16 {
        rd: Register,
        rn: Register,
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
            | Instruction::Madd { rd, .. }
            | Instruction::Msub { rd, .. }
            | Instruction::Mneg { rd, .. }
            | Instruction::Smulh { rd, .. }
            | Instruction::Umulh { rd, .. }
            | Instruction::Csel { rd, .. }
            | Instruction::Csinc { rd, .. }
            | Instruction::Csinv { rd, .. }
            | Instruction::Csneg { rd, .. }
            | Instruction::Mvn { rd, .. }
            | Instruction::Neg { rd, .. }
            | Instruction::Negs { rd, .. }
            | Instruction::MovN { rd, .. }
            | Instruction::MovZ { rd, .. }
            | Instruction::MovK { rd, .. }
            | Instruction::Bic { rd, .. }
            | Instruction::Bics { rd, .. }
            | Instruction::Orn { rd, .. }
            | Instruction::Eon { rd, .. }
            | Instruction::Adds { rd, .. }
            | Instruction::Subs { rd, .. }
            | Instruction::Ands { rd, .. }
            | Instruction::Cset { rd, .. }
            | Instruction::Csetm { rd, .. }
            | Instruction::Ror { rd, .. }
            | Instruction::Clz { rd, .. }
            | Instruction::Cls { rd, .. }
            | Instruction::Rbit { rd, .. }
            | Instruction::Rev { rd, .. }
            | Instruction::Rev32 { rd, .. }
            | Instruction::Rev16 { rd, .. } => Some(*rd),
            // Comparison instructions only set flags, no destination register
            Instruction::Cmp { .. }
            | Instruction::Cmn { .. }
            | Instruction::Tst { .. }
            | Instruction::Ccmp { .. }
            | Instruction::Ccmn { .. } => None,
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
                | Instruction::Ccmp { .. }
                | Instruction::Ccmn { .. }
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
                | Instruction::Ccmp { .. }
                | Instruction::Ccmn { .. }
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

            // ADD/SUB: register or immediate (12-bit unsigned), or shifted-register
            // (LSL/LSR/ASR only — ROR not encodable for arithmetic shifted-register form).
            // Shifted-register form forbids SP for any operand (ARM v8 spec).
            Instruction::Add { rd, rn, rm } | Instruction::Sub { rd, rn, rm } => match rm {
                Operand::Register(_) => true,
                Operand::Immediate(imm) => *imm >= 0 && *imm <= 0xFFF,
                Operand::ShiftedRegister { reg, kind, amount } => {
                    *kind != ShiftKind::Ror
                        && *amount <= 63
                        && *reg != Register::SP
                        && *rd != Register::SP
                        && *rn != Register::SP
                }
            },

            // AND/ORR/EOR: register operand or shifted-register (all 4 kinds, ROR allowed).
            // Shifted-register form forbids SP for any operand.
            Instruction::And { rd, rn, rm }
            | Instruction::Orr { rd, rn, rm }
            | Instruction::Eor { rd, rn, rm } => match rm {
                Operand::Register(_) => true,
                Operand::Immediate(_) => false,
                Operand::ShiftedRegister { reg, amount, .. } => {
                    *amount <= 63
                        && *reg != Register::SP
                        && *rd != Register::SP
                        && *rn != Register::SP
                }
            },

            // Shift instructions: shift amount 0-63 for 64-bit registers.
            // Reject Operand::ShiftedRegister in the shift slot (semantically nonsense:
            // shifting by a shifted-register result is not part of issue #59 scope).
            Instruction::Lsl { shift, .. }
            | Instruction::Lsr { shift, .. }
            | Instruction::Asr { shift, .. } => match shift {
                Operand::Register(_) => true,
                Operand::Immediate(amt) => *amt >= 0 && *amt <= 63,
                Operand::ShiftedRegister { .. } => false,
            },

            // MUL/SDIV/UDIV: always register operands, always encodable
            Instruction::Mul { .. } | Instruction::Sdiv { .. } | Instruction::Udiv { .. } => true,

            // Multiply-accumulate family: always register operands, always encodable
            Instruction::Madd { .. }
            | Instruction::Msub { .. }
            | Instruction::Mneg { .. }
            | Instruction::Smulh { .. }
            | Instruction::Umulh { .. } => true,

            // CMP/CMN: register, immediate (12-bit unsigned), or shifted-register
            // (LSL/LSR/ASR only — ROR not encodable for arithmetic shifted-register form).
            Instruction::Cmp { rn, rm } | Instruction::Cmn { rn, rm } => match rm {
                Operand::Register(_) => true,
                Operand::Immediate(imm) => *imm >= 0 && *imm <= 0xFFF,
                Operand::ShiftedRegister { reg, kind, amount } => {
                    *kind != ShiftKind::Ror
                        && *amount <= 63
                        && *reg != Register::SP
                        && *rn != Register::SP
                }
            },

            // TST: register operand or shifted-register (all 4 kinds, ROR allowed).
            Instruction::Tst { rn, rm } => match rm {
                Operand::Register(_) => true,
                Operand::Immediate(_) => false,
                Operand::ShiftedRegister { reg, amount, .. } => {
                    *amount <= 63 && *reg != Register::SP && *rn != Register::SP
                }
            },

            // Conditional select: always encodable (register-only)
            Instruction::Csel { .. }
            | Instruction::Csinc { .. }
            | Instruction::Csinv { .. }
            | Instruction::Csneg { .. } => true,

            // MVN / NEG / NEGS: always encodable (register-only)
            Instruction::Mvn { .. } | Instruction::Neg { .. } | Instruction::Negs { .. } => true,

            // MOVN / MOVZ / MOVK: shift must be one of MOVW_LEGAL_SHIFTS;
            // u16 imm is always in range.
            Instruction::MovN { shift, .. }
            | Instruction::MovZ { shift, .. }
            | Instruction::MovK { shift, .. } => MOVW_LEGAL_SHIFTS.contains(shift),

            // BIC / BICS / ORN / EON: register-only (matching AND precedent).
            Instruction::Bic { rm, .. }
            | Instruction::Bics { rm, .. }
            | Instruction::Orn { rm, .. }
            | Instruction::Eon { rm, .. } => matches!(rm, Operand::Register(_)),

            // ADDS/SUBS: imm 0..=0xFFF (same as ADD/SUB). ShiftedRegister form is
            // out of scope for issue #59 (flag-setting peers will be a follow-up).
            Instruction::Adds { rm, .. } | Instruction::Subs { rm, .. } => match rm {
                Operand::Register(_) => true,
                Operand::Immediate(imm) => *imm >= 0 && *imm <= 0xFFF,
                Operand::ShiftedRegister { .. } => false,
            },
            // ANDS: register-only (same as AND). ShiftedRegister out of scope (#59).
            Instruction::Ands { rm, .. } => matches!(rm, Operand::Register(_)),

            // CSET / CSETM: reject AL (always true ⇒ unconditional 1/-1) and
            // NV (reserved). All other 14 conditions are encodable.
            Instruction::Cset { cond, .. } | Instruction::Csetm { cond, .. } => {
                !matches!(cond, Condition::AL | Condition::NV)
            }

            // CCMP / CCMN: reject AL/NV (ARM ARM C6.2.36); reject SP in `rn`
            // (Xn slot, not XSP); the `rm` immediate is a 5-bit unsigned literal
            // (0..=31); `nzcv` is a 4-bit unsigned literal (0..=15). The
            // shifted-register form is not encoded in this IR — CCMP's
            // architectural register form is a plain Xm without shift, so we
            // reject `Operand::ShiftedRegister` here.
            Instruction::Ccmp { rn, rm, nzcv, cond } | Instruction::Ccmn { rn, rm, nzcv, cond } => {
                if matches!(cond, Condition::AL | Condition::NV) {
                    return false;
                }
                if *rn == Register::SP {
                    return false;
                }
                if *nzcv > 15 {
                    return false;
                }
                match rm {
                    Operand::Register(reg) => *reg != Register::SP,
                    Operand::Immediate(imm) => (0..=31).contains(imm),
                    Operand::ShiftedRegister { .. } => false,
                }
            }

            // ROR: shift amount 0..=63 (same as LSL/LSR/ASR). ShiftedRegister
            // in the shift slot is rejected (semantically nonsense; same as
            // LSL/LSR/ASR above).
            Instruction::Ror { shift, .. } => match shift {
                Operand::Register(_) => true,
                Operand::Immediate(amt) => *amt >= 0 && *amt <= 63,
                Operand::ShiftedRegister { .. } => false,
            },

            // Single-source bit-manipulation: register-only, Xn class (no SP).
            // AArch64 reg-31 in this slot is XZR, so SP must be rejected before
            // any caller (SMT, equivalence, LLM) reasons about the candidate.
            // XZR remains encodable.
            Instruction::Clz { rd, rn }
            | Instruction::Cls { rd, rn }
            | Instruction::Rbit { rd, rn }
            | Instruction::Rev { rd, rn }
            | Instruction::Rev32 { rd, rn }
            | Instruction::Rev16 { rd, rn } => *rd != Register::SP && *rn != Register::SP,
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
                match rm {
                    Operand::Register(r) => regs.push(*r),
                    Operand::ShiftedRegister { reg, .. } => regs.push(*reg),
                    Operand::Immediate(_) => {}
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
            Instruction::Madd { rn, rm, ra, .. } | Instruction::Msub { rn, rm, ra, .. } => {
                vec![*rn, *rm, *ra]
            }
            Instruction::Mneg { rn, rm, .. }
            | Instruction::Smulh { rn, rm, .. }
            | Instruction::Umulh { rn, rm, .. } => vec![*rn, *rm],
            // Comparison instructions read rn and rm (register form,
            // including the shifted-register form's inner register).
            Instruction::Cmp { rn, rm }
            | Instruction::Cmn { rn, rm }
            | Instruction::Tst { rn, rm } => {
                let mut regs = vec![*rn];
                match rm {
                    Operand::Register(r) => regs.push(*r),
                    Operand::ShiftedRegister { reg, .. } => regs.push(*reg),
                    Operand::Immediate(_) => {}
                }
                regs
            }
            // CCMP / CCMN read rn and rm (if register). They also read NZCV
            // (via `cond`), but the live-out machinery models flag liveness
            // separately via `reads_flags` and `modifies_flags`.
            Instruction::Ccmp { rn, rm, .. } | Instruction::Ccmn { rn, rm, .. } => {
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
            // MOVN / MOVZ take no register source
            Instruction::MovN { .. } | Instruction::MovZ { .. } => vec![],
            // MOVK reads rd (preserves the unmodified 16-bit lanes)
            Instruction::MovK { rd, .. } => vec![*rd],
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
            // Single-source bit-manipulation: rn is the only source.
            Instruction::Clz { rn, .. }
            | Instruction::Cls { rn, .. }
            | Instruction::Rbit { rn, .. }
            | Instruction::Rev { rn, .. }
            | Instruction::Rev32 { rn, .. }
            | Instruction::Rev16 { rn, .. } => vec![*rn],
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
            Instruction::Madd { rd, rn, rm, ra } => {
                write!(f, "madd {}, {}, {}, {}", rd, rn, rm, ra)
            }
            Instruction::Msub { rd, rn, rm, ra } => {
                write!(f, "msub {}, {}, {}, {}", rd, rn, rm, ra)
            }
            Instruction::Mneg { rd, rn, rm } => write!(f, "mneg {}, {}, {}", rd, rn, rm),
            Instruction::Smulh { rd, rn, rm } => write!(f, "smulh {}, {}, {}", rd, rn, rm),
            Instruction::Umulh { rd, rn, rm } => write!(f, "umulh {}, {}, {}", rd, rn, rm),
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
            Instruction::Ccmp { rn, rm, nzcv, cond } => {
                write!(f, "ccmp {}, {}, #{}, {}", rn, rm, nzcv, cond)
            }
            Instruction::Ccmn { rn, rm, nzcv, cond } => {
                write!(f, "ccmn {}, {}, #{}, {}", rn, rm, nzcv, cond)
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
            Instruction::MovZ { rd, imm, shift } => {
                if *shift == 0 {
                    write!(f, "movz {}, #{}", rd, imm)
                } else {
                    write!(f, "movz {}, #{}, lsl #{}", rd, imm, shift)
                }
            }
            Instruction::MovK { rd, imm, shift } => {
                if *shift == 0 {
                    write!(f, "movk {}, #{}", rd, imm)
                } else {
                    write!(f, "movk {}, #{}, lsl #{}", rd, imm, shift)
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
            Instruction::Clz { rd, rn } => write!(f, "clz {}, {}", rd, rn),
            Instruction::Cls { rd, rn } => write!(f, "cls {}, {}", rd, rn),
            Instruction::Rbit { rd, rn } => write!(f, "rbit {}, {}", rd, rn),
            Instruction::Rev { rd, rn } => write!(f, "rev {}, {}", rd, rn),
            Instruction::Rev32 { rd, rn } => write!(f, "rev32 {}, {}", rd, rn),
            Instruction::Rev16 { rd, rn } => write!(f, "rev16 {}, {}", rd, rn),
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
    fn test_source_registers_shifted_register() {
        // Add/Sub/And/Orr/Eor and Cmp/Cmn/Tst must extract the inner register
        // from a ShiftedRegister rm — otherwise live-out tracking silently
        // drops it.
        let shifted = Operand::ShiftedRegister {
            reg: Register::X3,
            kind: ShiftKind::Lsl,
            amount: 4,
        };
        for instr in [
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
            },
        ] {
            assert_eq!(
                instr.source_registers(),
                vec![Register::X1, Register::X3],
                "instr {} must report X1 and X3 as sources",
                instr
            );
        }
        for instr in [
            Instruction::Cmp {
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: shifted,
            },
        ] {
            assert_eq!(instr.source_registers(), vec![Register::X1, Register::X3]);
        }
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
    fn test_is_encodable_shifted_register_arith_rejects_ror() {
        // Add/Sub/Cmp/Cmn: LSL/LSR/ASR allowed; ROR rejected.
        let mk_add = |kind| Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind,
                amount: 3,
            },
        };
        assert!(mk_add(ShiftKind::Lsl).is_encodable_aarch64());
        assert!(mk_add(ShiftKind::Lsr).is_encodable_aarch64());
        assert!(mk_add(ShiftKind::Asr).is_encodable_aarch64());
        assert!(!mk_add(ShiftKind::Ror).is_encodable_aarch64());

        let mk_cmp = |kind| Instruction::Cmp {
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind,
                amount: 3,
            },
        };
        assert!(mk_cmp(ShiftKind::Lsl).is_encodable_aarch64());
        assert!(!mk_cmp(ShiftKind::Ror).is_encodable_aarch64());
    }

    #[test]
    fn test_is_encodable_shifted_register_logical_allows_ror() {
        // And/Orr/Eor/Tst accept ROR.
        for kind in [
            ShiftKind::Lsl,
            ShiftKind::Lsr,
            ShiftKind::Asr,
            ShiftKind::Ror,
        ] {
            assert!(
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind,
                        amount: 5
                    },
                }
                .is_encodable_aarch64(),
                "ORR with {:?} must be encodable",
                kind
            );
            assert!(
                Instruction::Tst {
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind,
                        amount: 5
                    },
                }
                .is_encodable_aarch64(),
                "TST with {:?} must be encodable",
                kind
            );
        }
    }

    #[test]
    fn test_is_encodable_shifted_register_rejects_sp() {
        // Shifted-register form forbids SP for any operand (rd, rn, rm).
        let lsl = ShiftKind::Lsl;
        let make = |rd, rn, reg| Instruction::Add {
            rd,
            rn,
            rm: Operand::ShiftedRegister {
                reg,
                kind: lsl,
                amount: 1,
            },
        };
        assert!(!make(Register::SP, Register::X1, Register::X2).is_encodable_aarch64());
        assert!(!make(Register::X0, Register::SP, Register::X2).is_encodable_aarch64());
        assert!(!make(Register::X0, Register::X1, Register::SP).is_encodable_aarch64());
        // Valid: no SP anywhere
        assert!(make(Register::X0, Register::X1, Register::X2).is_encodable_aarch64());
    }

    #[test]
    fn test_is_encodable_shifted_register_amount_bounds() {
        let mk = |amount| Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: ShiftKind::Lsl,
                amount,
            },
        };
        assert!(mk(0).is_encodable_aarch64());
        assert!(mk(63).is_encodable_aarch64());
        assert!(!mk(64).is_encodable_aarch64());
        assert!(!mk(255).is_encodable_aarch64());
    }

    #[test]
    fn test_is_encodable_shift_slot_rejects_shifted_register() {
        // Lsl/Lsr/Asr/Ror's shift field cannot be a ShiftedRegister.
        let nonsense = Operand::ShiftedRegister {
            reg: Register::X2,
            kind: ShiftKind::Lsl,
            amount: 1,
        };
        for instr in [
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: nonsense,
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: nonsense,
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: nonsense,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: nonsense,
            },
        ] {
            assert!(!instr.is_encodable_aarch64());
        }
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
    fn test_is_encodable_bit_manip_rejects_sp() {
        // Xn class — SP must be rejected on both rd and rn. XZR is valid.
        for instr in [
            Instruction::Clz {
                rd: Register::SP,
                rn: Register::X1,
            },
            Instruction::Cls {
                rd: Register::X0,
                rn: Register::SP,
            },
            Instruction::Rbit {
                rd: Register::SP,
                rn: Register::SP,
            },
            Instruction::Rev {
                rd: Register::SP,
                rn: Register::X1,
            },
            Instruction::Rev32 {
                rd: Register::X0,
                rn: Register::SP,
            },
            Instruction::Rev16 {
                rd: Register::SP,
                rn: Register::X1,
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected: {}",
                instr
            );
        }

        // XZR is part of the Xn class and stays encodable.
        assert!(
            Instruction::Clz {
                rd: Register::XZR,
                rn: Register::X1
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Rev {
                rd: Register::X0,
                rn: Register::XZR
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
            Instruction::Madd {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Msub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Mneg {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Smulh {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Umulh {
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
            Instruction::MovZ {
                rd: Register::X0,
                imm: 1,
                shift: 32,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 1,
                shift: 48,
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

        let cmp = Instruction::Cmp {
            rn: Register::X1,
            rm: Operand::Immediate(1),
        };
        assert_eq!(cmp.to_string(), "cmp x1, #1");
        assert_eq!(cmp.destination(), None);
        assert_eq!(cmp.source_registers(), vec![Register::X1]);
        assert!(cmp.modifies_flags());
        assert!(!cmp.reads_flags());

        let csel = Instruction::Csel {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::EQ,
        };
        assert_eq!(csel.to_string(), "csel x0, x1, x2, eq");
        assert_eq!(csel.destination(), Some(Register::X0));
        assert_eq!(csel.source_registers(), vec![Register::X1, Register::X2]);
        assert!(!csel.modifies_flags());
        assert!(csel.reads_flags());

        let adds = Instruction::Adds {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        assert_eq!(adds.to_string(), "adds x0, x1, x2");
        assert_eq!(adds.destination(), Some(Register::X0));
        assert_eq!(adds.source_registers(), vec![Register::X1, Register::X2]);
        assert!(adds.modifies_flags());
        assert!(!adds.reads_flags());

        let madd = Instruction::Madd {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X3,
        };
        assert_eq!(madd.to_string(), "madd x0, x1, x2, x3");
        assert_eq!(madd.destination(), Some(Register::X0));
        assert_eq!(
            madd.source_registers(),
            vec![Register::X1, Register::X2, Register::X3]
        );
        assert!(!madd.modifies_flags());
        assert!(!madd.reads_flags());
        assert!(madd.is_encodable_aarch64());

        let msub = Instruction::Msub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X3,
        };
        assert_eq!(msub.to_string(), "msub x0, x1, x2, x3");
        assert_eq!(msub.destination(), Some(Register::X0));
        assert_eq!(
            msub.source_registers(),
            vec![Register::X1, Register::X2, Register::X3]
        );
        assert!(!msub.modifies_flags());
        assert!(!msub.reads_flags());
        assert!(msub.is_encodable_aarch64());

        let mneg = Instruction::Mneg {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        assert_eq!(mneg.to_string(), "mneg x0, x1, x2");
        assert_eq!(mneg.destination(), Some(Register::X0));
        assert_eq!(mneg.source_registers(), vec![Register::X1, Register::X2]);
        assert!(!mneg.modifies_flags());
        assert!(!mneg.reads_flags());
        assert!(mneg.is_encodable_aarch64());

        let smulh = Instruction::Smulh {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        assert_eq!(smulh.to_string(), "smulh x0, x1, x2");
        assert_eq!(smulh.destination(), Some(Register::X0));
        assert_eq!(smulh.source_registers(), vec![Register::X1, Register::X2]);
        assert!(!smulh.modifies_flags());
        assert!(!smulh.reads_flags());
        assert!(smulh.is_encodable_aarch64());

        let umulh = Instruction::Umulh {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        assert_eq!(umulh.to_string(), "umulh x0, x1, x2");
        assert_eq!(umulh.destination(), Some(Register::X0));
        assert_eq!(umulh.source_registers(), vec![Register::X1, Register::X2]);
        assert!(!umulh.modifies_flags());
        assert!(!umulh.reads_flags());
        assert!(umulh.is_encodable_aarch64());
    }
}
