//! Mutation operators for stochastic search
//!
//! Implements four mutation operators:
//! 1. Operand mutation (50%): Change a register or immediate in a random instruction
//! 2. Opcode mutation (16%): Change the opcode while keeping operand structure
//! 3. Swap mutation (16%): Swap two instructions
//! 4. Instruction mutation (18%): Replace an entire instruction

#![allow(dead_code)]

use crate::ir::instructions::MOVW_LEGAL_SHIFTS;
use crate::ir::types::Condition;
use crate::ir::{Instruction, Operand, Register};
use crate::search::candidate::generate_random_instruction;
use crate::search::config::MutationWeights;
use rand::RngExt;

/// Drop ROR from a shifted-register operand when bridging from a logical
/// opcode (AND/ORR/EOR/TST — ROR allowed) to an arithmetic opcode
/// (ADD/SUB/CMP/CMN — ROR rejected by `is_encodable_aarch64`). Other shift
/// kinds and operand shapes pass through unchanged.
fn strip_ror_for_arith(rm: Operand) -> Operand {
    if let Operand::ShiftedRegister {
        reg,
        kind: crate::ir::ShiftKind::Ror,
        ..
    } = rm
    {
        Operand::Register(reg)
    } else {
        rm
    }
}

/// If `rm` is already a register, keep it; if it's an immediate, replace it
/// with a random register from `registers`. Used when mutating an
/// immediate-accepting opcode (ADDS/SUBS) into a register-only opcode
/// (ANDS) — keeps the resulting instruction encodable.
fn clamp_to_register<R: RngExt>(rm: Operand, registers: &[Register], rng: &mut R) -> Operand {
    match rm {
        Operand::Register(_) => rm,
        // ShiftedRegister carries a real register; preserve it as a plain
        // register (drop the shift) when the destination opcode is register-only.
        Operand::ShiftedRegister { reg, .. } => Operand::Register(reg),
        Operand::Immediate(_) => {
            if registers.is_empty() {
                rm
            } else {
                Operand::Register(registers[rng.random_range(0..registers.len())])
            }
        }
    }
}

/// Mutation operator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationType {
    /// Change a register or immediate operand
    Operand,
    /// Change the opcode (e.g., ADD -> SUB)
    Opcode,
    /// Swap two instructions
    Swap,
    /// Replace entire instruction
    Instruction,
}

/// Mutator for instruction sequences
pub struct Mutator {
    registers: Vec<Register>,
    immediates: Vec<i64>,
    weights: MutationWeights,
}

impl Mutator {
    pub fn new(registers: Vec<Register>, immediates: Vec<i64>, weights: MutationWeights) -> Self {
        Self {
            registers,
            immediates,
            weights,
        }
    }

    /// Select a mutation type based on weights
    pub fn select_mutation_type<R: RngExt>(&self, rng: &mut R) -> MutationType {
        let thresholds = self.weights.cumulative_thresholds();
        let r: f64 = rng.random();

        if r < thresholds[0] {
            MutationType::Operand
        } else if r < thresholds[1] {
            MutationType::Opcode
        } else if r < thresholds[2] {
            MutationType::Swap
        } else {
            MutationType::Instruction
        }
    }

    /// Apply a random mutation to a sequence
    pub fn mutate<R: RngExt>(&self, rng: &mut R, sequence: &[Instruction]) -> Vec<Instruction> {
        if sequence.is_empty() {
            return sequence.to_vec();
        }

        let mut result = sequence.to_vec();
        let mutation_type = self.select_mutation_type(rng);

        match mutation_type {
            MutationType::Operand => self.mutate_operand(rng, &mut result),
            MutationType::Opcode => self.mutate_opcode(rng, &mut result),
            MutationType::Swap => self.mutate_swap(rng, &mut result),
            MutationType::Instruction => self.mutate_instruction(rng, &mut result),
        }

        result
    }

    /// Operand mutation: change a register or immediate in a random instruction
    fn mutate_operand<R: RngExt>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.is_empty() || self.registers.is_empty() {
            return;
        }

        let idx = rng.random_range(0..sequence.len());
        let instr = &mut sequence[idx];

        match instr {
            Instruction::MovReg { rd, rn } => {
                if rng.random_bool(0.5) {
                    *rd = self.random_register(rng);
                } else {
                    *rn = self.random_register(rng);
                }
            }
            Instruction::MovImm { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.random_register(rng);
                } else {
                    *imm = self.random_immediate(rng);
                }
            }
            Instruction::Add { rd, rn, rm } | Instruction::Sub { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    // Add/Sub do not allow ROR in the shifted-register form.
                    _ => *rm = self.random_operand_3op(rng, false),
                }
            }
            Instruction::And { rd, rn, rm }
            | Instruction::Orr { rd, rn, rm }
            | Instruction::Eor { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    // Logical ops accept ROR in the shifted-register form.
                    _ => *rm = self.random_operand_3op(rng, true),
                }
            }
            Instruction::Lsl { rd, rn, shift }
            | Instruction::Lsr { rd, rn, shift }
            | Instruction::Asr { rd, rn, shift } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *shift = self.random_shift_operand(rng),
                }
            }
            Instruction::Mul { rd, rn, rm }
            | Instruction::Sdiv { rd, rn, rm }
            | Instruction::Udiv { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = self.random_register(rng),
                }
            }
            // Multiply-accumulate: 4 register slots so 4-way pick.
            Instruction::Madd { rd, rn, rm, ra } | Instruction::Msub { rd, rn, rm, ra } => {
                let choice = rng.random_range(0..4);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    2 => *rm = self.random_register(rng),
                    _ => *ra = self.random_register(rng),
                }
            }
            // MNEG / SMULH / UMULH: 3 register slots like MUL.
            Instruction::Mneg { rd, rn, rm }
            | Instruction::Smulh { rd, rn, rm }
            | Instruction::Umulh { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = self.random_register(rng),
                }
            }
            // Comparison instructions (no destination). Cmp/Cmn forbid ROR;
            // Tst allows it.
            Instruction::Cmp { rn, rm } | Instruction::Cmn { rn, rm } => {
                if rng.random_bool(0.5) {
                    *rn = self.random_register(rng);
                } else {
                    *rm = self.random_operand_3op(rng, false);
                }
            }
            Instruction::Tst { rn, rm } => {
                if rng.random_bool(0.5) {
                    *rn = self.random_register(rng);
                } else {
                    // Tst is register-only for non-shifted form. Use the 3op
                    // helper but force the non-shifted fallback to a Register
                    // (immediates aren't encodable for TST).
                    if rng.random_bool(0.15) && !self.registers.is_empty() {
                        *rm = self.random_shifted_register(rng, true);
                    } else {
                        *rm = Operand::Register(self.random_register(rng));
                    }
                }
            }
            // CCMP / CCMN: rn (register), rm (operand), nzcv (0..=15), cond.
            // Uniform pick among the four mutable fields. Immediate `rm`
            // operands are clamped to imm5 via rem_euclid(32) to match the
            // candidate generator (candidate.rs::generate_random_instruction)
            // and avoid avoidable is_encodable_aarch64 rejection churn.
            Instruction::Ccmp { rn, rm, nzcv, cond } | Instruction::Ccmn { rn, rm, nzcv, cond } => {
                match rng.random_range(0..4) {
                    0 => *rn = self.random_register(rng),
                    1 => {
                        *rm = match self.random_operand(rng) {
                            Operand::Register(r) => Operand::Register(r),
                            Operand::Immediate(v) => Operand::Immediate(v.rem_euclid(32)),
                            // CCMP/CCMN reject shifted-register operands;
                            // collapse to a plain register (consistent with
                            // candidate::generate_random_instruction case 27).
                            Operand::ShiftedRegister { reg, .. } => Operand::Register(reg),
                        };
                    }
                    2 => *nzcv = (rng.random::<u32>() & 0x0F) as u8,
                    _ => *cond = Condition::random_normal(rng),
                }
            }
            // Conditional select instructions
            Instruction::Csel { rd, rn, rm, .. }
            | Instruction::Csinc { rd, rn, rm, .. }
            | Instruction::Csinv { rd, rn, rm, .. }
            | Instruction::Csneg { rd, rn, rm, .. } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = self.random_register(rng),
                }
            }
            // Unary: MVN, NEG, NEGS
            Instruction::Mvn { rd, rm }
            | Instruction::Neg { rd, rm }
            | Instruction::Negs { rd, rm } => {
                if rng.random_bool(0.5) {
                    *rd = self.random_register(rng);
                } else {
                    *rm = self.random_register(rng);
                }
            }
            // Single-source bit-manipulation: CLZ, CLS, RBIT, REV, REV32, REV16,
            // plus the standalone extends SXTB/SXTH/SXTW/UXTB/UXTH (issue #60).
            Instruction::Clz { rd, rn }
            | Instruction::Cls { rd, rn }
            | Instruction::Rbit { rd, rn }
            | Instruction::Rev { rd, rn }
            | Instruction::Rev32 { rd, rn }
            | Instruction::Rev16 { rd, rn }
            | Instruction::Sxtb { rd, rn }
            | Instruction::Sxth { rd, rn }
            | Instruction::Sxtw { rd, rn }
            | Instruction::Uxtb { rd, rn }
            | Instruction::Uxth { rd, rn } => {
                if rng.random_bool(0.5) {
                    *rd = self.random_register(rng);
                } else {
                    *rn = self.random_register(rng);
                }
            }
            // MOVN / MOVZ / MOVK: mutate rd, imm, or shift. MOVK reads rd, so
            // mutating rd here additionally changes the upper-lanes source —
            // that's intentional and matches the other dest-mutating arms.
            Instruction::MovN { rd, imm, shift }
            | Instruction::MovZ { rd, imm, shift }
            | Instruction::MovK { rd, imm, shift } => match rng.random_range(0..3) {
                0 => *rd = self.random_register(rng),
                1 => *imm = (rng.random::<u32>() & 0xFFFF) as u16,
                _ => {
                    *shift = MOVW_LEGAL_SHIFTS[rng.random_range(0..MOVW_LEGAL_SHIFTS.len())];
                }
            },
            // Inverted-logical: BIC / BICS / ORN / EON — register-only rm
            Instruction::Bic { rd, rn, rm }
            | Instruction::Bics { rd, rn, rm }
            | Instruction::Orn { rd, rn, rm }
            | Instruction::Eon { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = Operand::Register(self.random_register(rng)),
                }
            }
            // Flag-setting arith/logical: ADDS/SUBS allow imm; ANDS register-only
            Instruction::Adds { rd, rn, rm } | Instruction::Subs { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = self.random_operand(rng),
                }
            }
            Instruction::Ands { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = Operand::Register(self.random_register(rng)),
                }
            }
            // CSET / CSETM: only rd and cond can change; cond from the 14
            // non-AL/NV options.
            Instruction::Cset { rd, cond } | Instruction::Csetm { rd, cond } => {
                if rng.random_bool(0.5) {
                    *rd = self.random_register(rng);
                } else {
                    *cond = Condition::random_normal(rng);
                }
            }
            // ROR: same operand shape as LSL/LSR/ASR
            Instruction::Ror { rd, rn, shift } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *shift = self.random_shift_operand(rng),
                }
            }
        }
    }

    /// Opcode mutation: change the opcode while keeping operand structure
    fn mutate_opcode<R: RngExt>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.is_empty() {
            return;
        }

        let idx = rng.random_range(0..sequence.len());
        let instr = sequence[idx];

        sequence[idx] = match instr {
            Instruction::MovReg { rd, rn } => {
                if rng.random_bool(0.5) {
                    Instruction::MovImm {
                        rd,
                        imm: self.random_immediate(rng),
                    }
                } else {
                    Instruction::MovReg { rd, rn }
                }
            }
            Instruction::MovImm { rd, .. } => {
                if rng.random_bool(0.5) {
                    Instruction::MovReg {
                        rd,
                        rn: self.random_register(rng),
                    }
                } else {
                    Instruction::MovImm {
                        rd,
                        imm: self.random_immediate(rng),
                    }
                }
            }
            Instruction::Add { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Sub { rd, rn, rm },
                1 => Instruction::And { rd, rn, rm },
                2 => Instruction::Orr { rd, rn, rm },
                3 => Instruction::Eor { rd, rn, rm },
                _ => Instruction::Add { rd, rn, rm },
            },
            Instruction::Sub { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Add { rd, rn, rm },
                1 => Instruction::And { rd, rn, rm },
                2 => Instruction::Orr { rd, rn, rm },
                3 => Instruction::Eor { rd, rn, rm },
                _ => Instruction::Sub { rd, rn, rm },
            },
            Instruction::And { rd, rn, rm } => match rng.random_range(0..5) {
                // Logical -> arithmetic: drop ROR from the shifted-register form.
                0 => Instruction::Add {
                    rd,
                    rn,
                    rm: strip_ror_for_arith(rm),
                },
                1 => Instruction::Sub {
                    rd,
                    rn,
                    rm: strip_ror_for_arith(rm),
                },
                2 => Instruction::Orr { rd, rn, rm },
                3 => Instruction::Eor { rd, rn, rm },
                _ => Instruction::And { rd, rn, rm },
            },
            Instruction::Orr { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Add {
                    rd,
                    rn,
                    rm: strip_ror_for_arith(rm),
                },
                1 => Instruction::Sub {
                    rd,
                    rn,
                    rm: strip_ror_for_arith(rm),
                },
                2 => Instruction::And { rd, rn, rm },
                3 => Instruction::Eor { rd, rn, rm },
                _ => Instruction::Orr { rd, rn, rm },
            },
            Instruction::Eor { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Add {
                    rd,
                    rn,
                    rm: strip_ror_for_arith(rm),
                },
                1 => Instruction::Sub {
                    rd,
                    rn,
                    rm: strip_ror_for_arith(rm),
                },
                2 => Instruction::And { rd, rn, rm },
                3 => Instruction::Orr { rd, rn, rm },
                _ => Instruction::Eor { rd, rn, rm },
            },
            Instruction::Lsl { rd, rn, shift } => match rng.random_range(0..3) {
                0 => Instruction::Lsr { rd, rn, shift },
                1 => Instruction::Asr { rd, rn, shift },
                _ => Instruction::Lsl { rd, rn, shift },
            },
            Instruction::Lsr { rd, rn, shift } => match rng.random_range(0..3) {
                0 => Instruction::Lsl { rd, rn, shift },
                1 => Instruction::Asr { rd, rn, shift },
                _ => Instruction::Lsr { rd, rn, shift },
            },
            Instruction::Asr { rd, rn, shift } => match rng.random_range(0..3) {
                0 => Instruction::Lsl { rd, rn, shift },
                1 => Instruction::Lsr { rd, rn, shift },
                _ => Instruction::Asr { rd, rn, shift },
            },
            Instruction::Mul { rd, rn, rm } => match rng.random_range(0..4) {
                0 => Instruction::Sdiv { rd, rn, rm },
                1 => Instruction::Udiv { rd, rn, rm },
                2 => Instruction::Mneg { rd, rn, rm },
                _ => Instruction::Mul { rd, rn, rm },
            },
            Instruction::Sdiv { rd, rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::Mul { rd, rn, rm },
                1 => Instruction::Udiv { rd, rn, rm },
                _ => Instruction::Sdiv { rd, rn, rm },
            },
            Instruction::Udiv { rd, rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::Mul { rd, rn, rm },
                1 => Instruction::Sdiv { rd, rn, rm },
                _ => Instruction::Udiv { rd, rn, rm },
            },
            // Comparison instructions can mutate between each other
            Instruction::Cmp { rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::Cmn { rn, rm },
                1 => Instruction::Tst { rn, rm },
                _ => Instruction::Cmp { rn, rm },
            },
            Instruction::Cmn { rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::Cmp { rn, rm },
                1 => Instruction::Tst { rn, rm },
                _ => Instruction::Cmn { rn, rm },
            },
            Instruction::Tst { rn, rm } => match rng.random_range(0..3) {
                // Tst (logical) -> Cmp/Cmn (arithmetic): drop ROR.
                0 => Instruction::Cmp {
                    rn,
                    rm: strip_ror_for_arith(rm),
                },
                1 => Instruction::Cmn {
                    rn,
                    rm: strip_ror_for_arith(rm),
                },
                _ => Instruction::Tst { rn, rm },
            },
            // CCMP ↔ CCMN swap (both share (rn, rm, nzcv, cond)).
            Instruction::Ccmp { rn, rm, nzcv, cond } => Instruction::Ccmn { rn, rm, nzcv, cond },
            Instruction::Ccmn { rn, rm, nzcv, cond } => Instruction::Ccmp { rn, rm, nzcv, cond },
            // Conditional select instructions can mutate between each other
            Instruction::Csel { rd, rn, rm, cond } => match rng.random_range(0..4) {
                0 => Instruction::Csinc { rd, rn, rm, cond },
                1 => Instruction::Csinv { rd, rn, rm, cond },
                2 => Instruction::Csneg { rd, rn, rm, cond },
                _ => Instruction::Csel { rd, rn, rm, cond },
            },
            Instruction::Csinc { rd, rn, rm, cond } => match rng.random_range(0..4) {
                0 => Instruction::Csel { rd, rn, rm, cond },
                1 => Instruction::Csinv { rd, rn, rm, cond },
                2 => Instruction::Csneg { rd, rn, rm, cond },
                _ => Instruction::Csinc { rd, rn, rm, cond },
            },
            Instruction::Csinv { rd, rn, rm, cond } => match rng.random_range(0..4) {
                0 => Instruction::Csel { rd, rn, rm, cond },
                1 => Instruction::Csinc { rd, rn, rm, cond },
                2 => Instruction::Csneg { rd, rn, rm, cond },
                _ => Instruction::Csinv { rd, rn, rm, cond },
            },
            Instruction::Csneg { rd, rn, rm, cond } => match rng.random_range(0..4) {
                0 => Instruction::Csel { rd, rn, rm, cond },
                1 => Instruction::Csinc { rd, rn, rm, cond },
                2 => Instruction::Csinv { rd, rn, rm, cond },
                _ => Instruction::Csneg { rd, rn, rm, cond },
            },
            // Unary peer-mutation cluster: MVN ↔ NEG ↔ NEGS
            Instruction::Mvn { rd, rm } => match rng.random_range(0..3) {
                0 => Instruction::Neg { rd, rm },
                1 => Instruction::Negs { rd, rm },
                _ => Instruction::Mvn { rd, rm },
            },
            Instruction::Neg { rd, rm } => match rng.random_range(0..3) {
                0 => Instruction::Mvn { rd, rm },
                1 => Instruction::Negs { rd, rm },
                _ => Instruction::Neg { rd, rm },
            },
            Instruction::Negs { rd, rm } => match rng.random_range(0..3) {
                0 => Instruction::Mvn { rd, rm },
                1 => Instruction::Neg { rd, rm },
                _ => Instruction::Negs { rd, rm },
            },
            // Single-source bit-manipulation: 6-way peer cluster.
            Instruction::Clz { rd, rn } => match rng.random_range(0..6) {
                0 => Instruction::Cls { rd, rn },
                1 => Instruction::Rbit { rd, rn },
                2 => Instruction::Rev { rd, rn },
                3 => Instruction::Rev32 { rd, rn },
                4 => Instruction::Rev16 { rd, rn },
                _ => Instruction::Clz { rd, rn },
            },
            Instruction::Cls { rd, rn } => match rng.random_range(0..6) {
                0 => Instruction::Clz { rd, rn },
                1 => Instruction::Rbit { rd, rn },
                2 => Instruction::Rev { rd, rn },
                3 => Instruction::Rev32 { rd, rn },
                4 => Instruction::Rev16 { rd, rn },
                _ => Instruction::Cls { rd, rn },
            },
            Instruction::Rbit { rd, rn } => match rng.random_range(0..6) {
                0 => Instruction::Clz { rd, rn },
                1 => Instruction::Cls { rd, rn },
                2 => Instruction::Rev { rd, rn },
                3 => Instruction::Rev32 { rd, rn },
                4 => Instruction::Rev16 { rd, rn },
                _ => Instruction::Rbit { rd, rn },
            },
            Instruction::Rev { rd, rn } => match rng.random_range(0..6) {
                0 => Instruction::Clz { rd, rn },
                1 => Instruction::Cls { rd, rn },
                2 => Instruction::Rbit { rd, rn },
                3 => Instruction::Rev32 { rd, rn },
                4 => Instruction::Rev16 { rd, rn },
                _ => Instruction::Rev { rd, rn },
            },
            Instruction::Rev32 { rd, rn } => match rng.random_range(0..6) {
                0 => Instruction::Clz { rd, rn },
                1 => Instruction::Cls { rd, rn },
                2 => Instruction::Rbit { rd, rn },
                3 => Instruction::Rev { rd, rn },
                4 => Instruction::Rev16 { rd, rn },
                _ => Instruction::Rev32 { rd, rn },
            },
            Instruction::Rev16 { rd, rn } => match rng.random_range(0..6) {
                0 => Instruction::Clz { rd, rn },
                1 => Instruction::Cls { rd, rn },
                2 => Instruction::Rbit { rd, rn },
                3 => Instruction::Rev { rd, rn },
                4 => Instruction::Rev32 { rd, rn },
                _ => Instruction::Rev16 { rd, rn },
            },
            // SXTB/SXTH/SXTW/UXTB/UXTH: bridging chains land in a later slice.
            // Issue #60.
            Instruction::Sxtb { rd, rn } => Instruction::Sxtb { rd, rn },
            Instruction::Sxth { rd, rn } => Instruction::Sxth { rd, rn },
            Instruction::Sxtw { rd, rn } => Instruction::Sxtw { rd, rn },
            Instruction::Uxtb { rd, rn } => Instruction::Uxtb { rd, rn },
            Instruction::Uxth { rd, rn } => Instruction::Uxth { rd, rn },
            // Move-wide cluster: MOVN ↔ MOVZ ↔ MOVK (all share rd/imm/shift),
            // plus a single MovImm bridge anchored at MOVZ.
            //
            // Topology note: before this PR, MOVN had a direct MOVN ↔ MovImm
            // edge. We removed it so MOVN now reaches MovImm via two hops
            // (MOVN → MOVZ → MovImm). Ergodicity is preserved — every move
            // family member can still reach every other — but mixing time
            // along the MOVN/MovImm corridor is one step longer. The trade
            // is intentional: MOVZ is the natural pivot, since `MovZ {imm,
            // shift=0}` is exactly the bit pattern MovImm holds, so the
            // MOVZ ↔ MovImm bridge has a clear semantic anchor that a direct
            // MOVN ↔ MovImm bridge lacked.
            Instruction::MovN { rd, imm, shift } => match rng.random_range(0..3) {
                0 => Instruction::MovZ { rd, imm, shift },
                1 => Instruction::MovK { rd, imm, shift },
                _ => Instruction::MovN { rd, imm, shift },
            },
            Instruction::MovZ { rd, imm, shift } => match rng.random_range(0..4) {
                0 => Instruction::MovN { rd, imm, shift },
                1 => Instruction::MovK { rd, imm, shift },
                // MovZ → MovImm uses the raw u16 `imm`, NOT `imm << shift`. We
                // deliberately discard the shift here: MCMC is exploring the
                // value space, and binding the new MovImm to the shifted bit
                // pattern would only widen `MovImm`'s effective range beyond
                // its 0..=0xFFFF encoding window. The neighbouring MovImm has
                // its own per-field mutator that will refine `imm` on later
                // steps.
                2 => Instruction::MovImm {
                    rd,
                    imm: imm as i64,
                },
                _ => Instruction::MovZ { rd, imm, shift },
            },
            Instruction::MovK { rd, imm, shift } => match rng.random_range(0..3) {
                0 => Instruction::MovN { rd, imm, shift },
                1 => Instruction::MovZ { rd, imm, shift },
                _ => Instruction::MovK { rd, imm, shift },
            },
            // Inverted-logical join the AND/ORR/EOR cluster.
            Instruction::Bic { rd, rn, rm } => match rng.random_range(0..7) {
                0 => Instruction::And { rd, rn, rm },
                1 => Instruction::Orr { rd, rn, rm },
                2 => Instruction::Eor { rd, rn, rm },
                3 => Instruction::Bics { rd, rn, rm },
                4 => Instruction::Orn { rd, rn, rm },
                5 => Instruction::Eon { rd, rn, rm },
                _ => Instruction::Bic { rd, rn, rm },
            },
            // Bics now mirrors Bic's 6-peer logical cluster so MCMC chains
            // starting at BICS have the same ergodicity as those starting at
            // BIC. The original 1-peer version made BICS effectively a
            // dead-end neighbour, slowing convergence.
            Instruction::Bics { rd, rn, rm } => match rng.random_range(0..7) {
                0 => Instruction::And { rd, rn, rm },
                1 => Instruction::Orr { rd, rn, rm },
                2 => Instruction::Eor { rd, rn, rm },
                3 => Instruction::Bic { rd, rn, rm },
                4 => Instruction::Orn { rd, rn, rm },
                5 => Instruction::Eon { rd, rn, rm },
                _ => Instruction::Bics { rd, rn, rm },
            },
            Instruction::Orn { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::And { rd, rn, rm },
                1 => Instruction::Orr { rd, rn, rm },
                2 => Instruction::Bic { rd, rn, rm },
                3 => Instruction::Eon { rd, rn, rm },
                _ => Instruction::Orn { rd, rn, rm },
            },
            Instruction::Eon { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::And { rd, rn, rm },
                1 => Instruction::Eor { rd, rn, rm },
                2 => Instruction::Bic { rd, rn, rm },
                3 => Instruction::Orn { rd, rn, rm },
                _ => Instruction::Eon { rd, rn, rm },
            },
            // Flag-setting cluster: ADDS↔SUBS↔ANDS, and into/out of ADD/SUB/AND.
            //
            // Note: ADDS/SUBS accept `Operand::Immediate` (12-bit), but ANDS
            // and AND are register-only (bitmask-immediate encoding is not
            // supported). Forwarding an Immediate `rm` directly into ANDS
            // would produce an un-encodable instruction that is_encodable
            // silently rejects, burning search iterations. When mutating
            // into ANDS, clamp `rm` to a register; the same logic applies
            // when mutating into AND.
            Instruction::Adds { rd, rn, rm } => match rng.random_range(0..4) {
                0 => Instruction::Add { rd, rn, rm },
                1 => Instruction::Subs { rd, rn, rm },
                2 => Instruction::Ands {
                    rd,
                    rn,
                    rm: clamp_to_register(rm, &self.registers, rng),
                },
                _ => Instruction::Adds { rd, rn, rm },
            },
            Instruction::Subs { rd, rn, rm } => match rng.random_range(0..4) {
                0 => Instruction::Sub { rd, rn, rm },
                1 => Instruction::Adds { rd, rn, rm },
                2 => Instruction::Ands {
                    rd,
                    rn,
                    rm: clamp_to_register(rm, &self.registers, rng),
                },
                _ => Instruction::Subs { rd, rn, rm },
            },
            Instruction::Ands { rd, rn, rm } => match rng.random_range(0..4) {
                0 => Instruction::And { rd, rn, rm },
                1 => Instruction::Adds { rd, rn, rm },
                2 => Instruction::Subs { rd, rn, rm },
                _ => Instruction::Ands { rd, rn, rm },
            },
            // CSET ↔ CSETM
            Instruction::Cset { rd, cond } => match rng.random_range(0..2) {
                0 => Instruction::Csetm { rd, cond },
                _ => Instruction::Cset { rd, cond },
            },
            Instruction::Csetm { rd, cond } => match rng.random_range(0..2) {
                0 => Instruction::Cset { rd, cond },
                _ => Instruction::Csetm { rd, cond },
            },
            // ROR joins the shift cluster LSL/LSR/ASR.
            Instruction::Ror { rd, rn, shift } => match rng.random_range(0..4) {
                0 => Instruction::Lsl { rd, rn, shift },
                1 => Instruction::Lsr { rd, rn, shift },
                2 => Instruction::Asr { rd, rn, shift },
                _ => Instruction::Ror { rd, rn, shift },
            },
            // Multiply-accumulate cluster — widens as SMULH/UMULH land.
            Instruction::Madd { rd, rn, rm, ra } => match rng.random_range(0..3) {
                0 => Instruction::Msub { rd, rn, rm, ra },
                1 => Instruction::Mneg { rd, rn, rm },
                _ => Instruction::Madd { rd, rn, rm, ra },
            },
            Instruction::Msub { rd, rn, rm, ra } => match rng.random_range(0..3) {
                0 => Instruction::Madd { rd, rn, rm, ra },
                1 => Instruction::Mneg { rd, rn, rm },
                _ => Instruction::Msub { rd, rn, rm, ra },
            },
            // MNEG ↔ MUL is the sign-flip bridge (MNEG = -(rn*rm), MUL = rn*rm).
            // MNEG also already receives reverse edges from MADD/MSUB above
            // (which collapse `ra` when they convert).
            Instruction::Mneg { rd, rn, rm } => match rng.random_range(0..2) {
                0 => Instruction::Mul { rd, rn, rm },
                _ => Instruction::Mneg { rd, rn, rm },
            },
            // High-half multiply cluster (signed ↔ unsigned).
            Instruction::Smulh { rd, rn, rm } => match rng.random_range(0..2) {
                0 => Instruction::Umulh { rd, rn, rm },
                _ => Instruction::Smulh { rd, rn, rm },
            },
            Instruction::Umulh { rd, rn, rm } => match rng.random_range(0..2) {
                0 => Instruction::Smulh { rd, rn, rm },
                _ => Instruction::Umulh { rd, rn, rm },
            },
        };
    }

    /// Swap mutation: swap two instructions in the sequence
    fn mutate_swap<R: RngExt>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.len() < 2 {
            return;
        }

        let idx1 = rng.random_range(0..sequence.len());
        let idx2 = rng.random_range(0..sequence.len());
        sequence.swap(idx1, idx2);
    }

    /// Instruction mutation: replace an entire instruction with a random one
    fn mutate_instruction<R: RngExt>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.is_empty() {
            return;
        }

        let idx = rng.random_range(0..sequence.len());
        sequence[idx] = generate_random_instruction(rng, &self.registers, &self.immediates);
    }

    fn random_register<R: RngExt>(&self, rng: &mut R) -> Register {
        if self.registers.is_empty() {
            Register::X0
        } else {
            self.registers[rng.random_range(0..self.registers.len())]
        }
    }

    fn random_immediate<R: RngExt>(&self, rng: &mut R) -> i64 {
        if self.immediates.is_empty() {
            0
        } else {
            self.immediates[rng.random_range(0..self.immediates.len())]
        }
    }

    fn random_operand<R: RngExt>(&self, rng: &mut R) -> Operand {
        if rng.random_bool(0.5) && !self.registers.is_empty() {
            Operand::Register(self.random_register(rng))
        } else {
            Operand::Immediate(self.random_immediate(rng))
        }
    }

    /// Random rm operand for the in-scope arithmetic/logical/comparison
    /// shifted-register opcodes (issue #59). With low probability returns a
    /// `ShiftedRegister`; otherwise falls back to the plain register/immediate
    /// distribution. `allow_ror` toggles whether ROR is in the kind pool —
    /// callers in arith bridges must pass false.
    fn random_operand_3op<R: RngExt>(&self, rng: &mut R, allow_ror: bool) -> Operand {
        if rng.random_bool(0.15) && !self.registers.is_empty() {
            self.random_shifted_register(rng, allow_ror)
        } else {
            self.random_operand(rng)
        }
    }

    fn random_shifted_register<R: RngExt>(&self, rng: &mut R, allow_ror: bool) -> Operand {
        let reg = self.random_register(rng);
        let kinds: &[crate::ir::ShiftKind] = if allow_ror {
            &[
                crate::ir::ShiftKind::Lsl,
                crate::ir::ShiftKind::Lsr,
                crate::ir::ShiftKind::Asr,
                crate::ir::ShiftKind::Ror,
            ]
        } else {
            &[
                crate::ir::ShiftKind::Lsl,
                crate::ir::ShiftKind::Lsr,
                crate::ir::ShiftKind::Asr,
            ]
        };
        let kind = kinds[rng.random_range(0..kinds.len())];
        let amounts = [1u8, 2, 3, 4, 8, 16, 32];
        let amount = amounts[rng.random_range(0..amounts.len())];
        Operand::ShiftedRegister { reg, kind, amount }
    }

    fn random_shift_operand<R: RngExt>(&self, rng: &mut R) -> Operand {
        if rng.random_bool(0.7) {
            let shifts = [0, 1, 2, 4, 8, 16, 32];
            Operand::Immediate(shifts[rng.random_range(0..shifts.len())])
        } else if !self.registers.is_empty() {
            Operand::Register(self.random_register(rng))
        } else {
            Operand::Immediate(1)
        }
    }
}

/// Perform operand mutation on a specific instruction (for testing)
pub fn mutate_operand_in_place<R: RngExt>(
    rng: &mut R,
    instr: &mut Instruction,
    registers: &[Register],
    immediates: &[i64],
) {
    let mutator = Mutator::new(
        registers.to_vec(),
        immediates.to_vec(),
        MutationWeights::default(),
    );
    let mut seq = vec![*instr];
    mutator.mutate_operand(rng, &mut seq);
    *instr = seq[0];
}

/// Change opcode while preserving operand structure (for testing)
pub fn mutate_opcode_in_place<R: RngExt>(rng: &mut R, instr: &mut Instruction) {
    let mutator = Mutator::new(
        vec![Register::X0, Register::X1, Register::X2],
        vec![0, 1],
        MutationWeights::default(),
    );
    let mut seq = vec![*instr];
    mutator.mutate_opcode(rng, &mut seq);
    *instr = seq[0];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_mutator() -> Mutator {
        Mutator::new(
            vec![Register::X0, Register::X1, Register::X2],
            vec![-1, 0, 1, 2],
            MutationWeights::default(),
        )
    }

    #[test]
    fn test_mutate_operand_can_produce_shifted_register() {
        // With many trials, mutate_operand on an Add must sometimes pick a
        // ShiftedRegister rm. Issue #59.
        let mutator = default_mutator();
        let mut rng = rand::rng();
        let mut produced_shifted = false;
        for _ in 0..1000 {
            let mut seq = vec![Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            }];
            mutator.mutate_operand(&mut rng, &mut seq);
            if let Instruction::Add {
                rm: Operand::ShiftedRegister { .. },
                ..
            } = seq[0]
            {
                produced_shifted = true;
                break;
            }
        }
        assert!(
            produced_shifted,
            "mutate_operand on Add must occasionally produce ShiftedRegister rm"
        );
    }

    #[test]
    fn test_mutate_opcode_bridge_drops_ror_for_arith() {
        // If we start with `And { rm: ShiftedRegister { kind: ROR } }` and the
        // bridge selects Add/Sub/Cmp/Cmn as the new opcode, the result must
        // not carry ROR (since it's invalid for those). Encodability gates it
        // anyway, but the bridge should produce a candidate that *is*
        // encodable.
        let mutator = default_mutator();
        let mut rng = rand::rng();
        let original = Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: crate::ir::ShiftKind::Ror,
                amount: 4,
            },
        };
        let mut saw_arith_after_bridge = false;
        for _ in 0..2000 {
            let mut seq = vec![original];
            mutator.mutate_opcode(&mut rng, &mut seq);
            match seq[0] {
                Instruction::Add { rm, .. } | Instruction::Sub { rm, .. } => {
                    saw_arith_after_bridge = true;
                    if let Operand::ShiftedRegister {
                        kind: crate::ir::ShiftKind::Ror,
                        ..
                    } = rm
                    {
                        panic!("bridge produced Add/Sub with ROR shifted-register: not encodable");
                    }
                }
                _ => {}
            }
        }
        assert!(
            saw_arith_after_bridge,
            "expected the bridge to occasionally produce Add/Sub from And"
        );
    }

    #[test]
    fn test_mutation_type_selection() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut operand_count = 0;
        let mut opcode_count = 0;
        let mut swap_count = 0;
        let mut instr_count = 0;

        for _ in 0..10000 {
            match mutator.select_mutation_type(&mut rng) {
                MutationType::Operand => operand_count += 1,
                MutationType::Opcode => opcode_count += 1,
                MutationType::Swap => swap_count += 1,
                MutationType::Instruction => instr_count += 1,
            }
        }

        // Operand should be most frequent (50%)
        assert!(operand_count > opcode_count);
        assert!(operand_count > swap_count);
        assert!(operand_count > instr_count);

        // All should have some samples
        assert!(opcode_count > 0);
        assert!(swap_count > 0);
        assert!(instr_count > 0);
    }

    #[test]
    fn test_mutate_produces_different_sequence() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];

        let mut different_count = 0;
        for _ in 0..100 {
            let mutated = mutator.mutate(&mut rng, &original);
            if mutated != original {
                different_count += 1;
            }
        }

        // Most mutations should produce different results
        assert!(different_count > 50);
    }

    #[test]
    fn test_mutate_preserves_length_except_empty() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
            Instruction::MovReg {
                rd: Register::X2,
                rn: Register::X1,
            },
        ];

        for _ in 0..100 {
            let mutated = mutator.mutate(&mut rng, &original);
            assert_eq!(mutated.len(), original.len());
        }
    }

    #[test]
    fn test_mutate_empty_sequence() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let empty: Vec<Instruction> = vec![];
        let mutated = mutator.mutate(&mut rng, &empty);
        assert!(mutated.is_empty());
    }

    #[test]
    fn test_operand_mutation_changes_operands() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut seq = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];

        let original = seq[0];
        let mut changed = false;

        for _ in 0..100 {
            seq[0] = original;
            mutator.mutate_operand(&mut rng, &mut seq);
            if seq[0] != original {
                changed = true;
                break;
            }
        }

        assert!(changed);
    }

    #[test]
    fn test_opcode_mutation_changes_opcode() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut seq = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];

        let original = seq[0];
        let mut changed_to_different_opcode = false;

        for _ in 0..100 {
            seq[0] = original;
            mutator.mutate_opcode(&mut rng, &mut seq);

            if !matches!(seq[0], Instruction::Add { .. }) {
                changed_to_different_opcode = true;
                break;
            }
        }

        assert!(changed_to_different_opcode);
    }

    #[test]
    fn test_swap_mutation() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut seq = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::MovImm {
                rd: Register::X1,
                imm: 1,
            },
        ];

        let first = seq[0];
        let second = seq[1];

        let mut swapped = false;
        for _ in 0..100 {
            seq = vec![first, second];
            mutator.mutate_swap(&mut rng, &mut seq);
            if seq[0] == second && seq[1] == first {
                swapped = true;
                break;
            }
        }

        assert!(swapped);
    }

    #[test]
    fn test_instruction_mutation_replaces() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut seq = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];

        let original = seq[0];
        let mut replaced = false;

        for _ in 0..100 {
            seq[0] = original;
            mutator.mutate_instruction(&mut rng, &mut seq);
            if seq[0] != original {
                replaced = true;
                break;
            }
        }

        assert!(replaced);
    }

    #[test]
    fn test_mutate_single_instruction_sequence() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];

        let mut mutated = mutator.mutate(&mut rng, &original);
        assert_eq!(mutated.len(), 1);

        // Swap mutation should be a no-op on single instruction
        mutator.mutate_swap(&mut rng, &mut mutated);
        assert_eq!(mutated.len(), 1);
    }
}
