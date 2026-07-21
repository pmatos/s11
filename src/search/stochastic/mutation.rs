//! Mutation operators for stochastic search
//!
//! Implements four mutation operators:
//! 1. Operand mutation (50%): Change a register or immediate in a random instruction
//! 2. Opcode mutation (16%): Change the opcode while mostly keeping operand structure
//! 3. Swap mutation (16%): Swap two instructions
//! 4. Instruction mutation (18%): Replace an entire instruction
//!
//! These operators are heuristic proposal generators. In particular,
//! opcode peer clusters are not required to have equal forward/reverse
//! transition probabilities, and the stochastic search does not apply a
//! Hastings ratio to correct that asymmetry. The search is intended as an
//! optimization heuristic, not as a detailed-balance sampler.

#![allow(dead_code)]

use crate::ir::instructions::{AARCH64_RANDOM_SHIFT_IMMEDIATES, MOVW_LEGAL_SHIFTS};
use crate::ir::types::Condition;
use crate::ir::{ExtendKind, Instruction, Operand, Register, RegisterWidth};
use crate::search::candidate::generate_random_instruction;
use crate::search::config::MutationWeights;
use rand::RngExt;

const ADDRESS_OFFSET_POOL: [i64; 8] = [0, 8, 16, 24, 32, 64, -8, -256];
const LOGICAL_IMM32_POOL: &[i64] = &[
    0x1,
    0x2,
    0x4,
    0x8,
    0xff,
    0xffff,
    0x8000_0000,
    0x5555_5555,
    0xaaaa_aaaa,
    -256, // i64 -256 = 0xFFFF_FF00 as W32: a 24-bit high run, a valid logical bitmask immediate
];
const LOGICAL_IMM64_POOL: &[i64] = &[
    0x1,
    0x2,
    0x4,
    0x8,
    0xff,
    0xffff,
    0xffff_ffff,
    0x5555_5555_5555_5555,
    0xaaaa_aaaa_aaaa_aaaa_u64 as i64,
    0xf0f0_f0f0_f0f0_f0f0_u64 as i64,
    0x8000_0000_0000_0000_u64 as i64,
    -256, // i64 -256 = 0xFFFF_FFFF_FFFF_FF00 as X64: a 56-bit high run, a valid logical bitmask immediate
];
const SHIFTED_REGISTER_OPERAND_PROBABILITY: f64 = 0.30;
/// Shift amounts proposed for X-form (64-bit) shifted-register operands.
const SHIFTED_REGISTER_AMOUNTS_X64: [u8; 7] = [1, 2, 3, 4, 8, 16, 32];
/// Shift amounts for W-form (32-bit) shifted-register operands. Caps at 31
/// because AArch64 limits `Wd` shifted-register immediates to `0..=31`
/// (ARM ARM C3.5.2); amount 32 is valid only for the X-form.
const SHIFTED_REGISTER_AMOUNTS_W32: [u8; 7] = [1, 2, 3, 4, 8, 16, 31];

/// Additional probability budget reserved for extended-register proposals,
/// stacked on top of `SHIFTED_REGISTER_OPERAND_PROBABILITY` in
/// `random_operand_3op` (issue #151). Kept as a separate constant so retuning
/// the shifted-register heat does not silently shift the extended-register
/// ceiling.
const EXTENDED_REGISTER_OPERAND_DELTA: f64 = 0.15;

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

fn single_source_opcode_peer<R: RngExt>(rng: &mut R, rd: Register, rn: Register) -> Instruction {
    match rng.random_range(0..11) {
        0 => Instruction::Clz { rd, rn },
        1 => Instruction::Cls { rd, rn },
        2 => Instruction::Rbit { rd, rn },
        3 => Instruction::Rev { rd, rn },
        4 => Instruction::Rev32 { rd, rn },
        5 => Instruction::Rev16 { rd, rn },
        6 => Instruction::Sxtb { rd, rn },
        7 => Instruction::Sxth { rd, rn },
        8 => Instruction::Sxtw { rd, rn },
        9 => Instruction::Uxtb { rd, rn },
        _ => Instruction::Uxth { rd, rn },
    }
}

fn normalized_immediate_pool(immediates: &[i64], modulus: i64) -> Vec<i64> {
    debug_assert!(modulus > 0, "immediate modulus must be positive");

    if immediates.is_empty() {
        return vec![0];
    }

    let mut normalized = Vec::new();
    for imm in immediates {
        let residue = imm.rem_euclid(modulus);
        if !normalized.contains(&residue) {
            normalized.push(residue);
        }
    }
    normalized
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
#[derive(Debug)]
pub struct Mutator {
    registers: Vec<Register>,
    immediates: Vec<i64>,
    imm12_immediates: Vec<i64>,
    imm5_immediates: Vec<i64>,
    weights: MutationWeights,
}

impl Mutator {
    pub fn new(registers: Vec<Register>, immediates: Vec<i64>, weights: MutationWeights) -> Self {
        // Keep the raw table for unrestricted immediates (MOV, move-wide,
        // instruction replacement) but precompute per-opcode-class pools for
        // bounded forms. The pools deduplicate after normalization so
        // congruent configured values do not get extra proposal weight.
        let imm12_immediates = normalized_immediate_pool(&immediates, 0x1000);
        let imm5_immediates = normalized_immediate_pool(&immediates, 32);

        Self {
            registers,
            immediates,
            imm12_immediates,
            imm5_immediates,
            weights,
        }
    }

    /// Select a mutation type based on weights
    pub fn select_mutation_type<R: RngExt>(&self, rng: &mut R) -> MutationType {
        let r: f64 = rng.random();
        match self.weights.select_index(r) {
            0 => MutationType::Operand,
            1 => MutationType::Opcode,
            2 => MutationType::Swap,
            _ => MutationType::Instruction,
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

        let rewritable = rewritable_len(sequence);
        if rewritable == 0 {
            return; // terminator-only sequence — nothing to mutate
        }
        let idx = rng.random_range(0..rewritable);
        let instr = &mut sequence[idx];

        match instr {
            Instruction::MovReg { rd, rn } | Instruction::MovRegW { rd, rn } => {
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
                    // Immediate proposals draw from the deduplicated imm12
                    // pool so congruent configured immediates do not carry
                    // extra proposal weight.
                    _ => {
                        *rm = self.random_operand_3op_from_pool(
                            rng,
                            false,
                            RegisterWidth::X64,
                            &self.imm12_immediates,
                        );
                    }
                }
            }
            Instruction::AddW { rd, rn, rm } | Instruction::SubW { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    // W-form shifted-register amounts are limited to 0..=31.
                    // Keep the same proposal heat as X-form Add/Sub while
                    // using a W-safe amount pool.
                    _ => {
                        *rm = self.random_operand_3op_from_pool(
                            rng,
                            false,
                            RegisterWidth::W32,
                            &self.imm12_immediates,
                        );
                    }
                }
            }
            Instruction::And { rd, rn, rm, width }
            | Instruction::Orr { rd, rn, rm, width }
            | Instruction::Eor { rd, rn, rm, width } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = self.random_logical_operand(rng, *width, true, true),
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
                    *rm = self.random_operand_3op_from_pool(
                        rng,
                        false,
                        RegisterWidth::X64,
                        &self.imm12_immediates,
                    );
                }
            }
            Instruction::Tst { rn, rm, width } => {
                if rng.random_bool(0.5) {
                    *rn = self.random_register(rng);
                } else {
                    *rm = self.random_logical_operand(rng, *width, true, false);
                }
            }
            // CCMP / CCMN: rn (register), rm (operand), nzcv (0..=15), cond.
            // Uniform pick among the four mutable fields. Immediate `rm`
            // operands draw from a deduplicated imm5 pool so configured
            // immediates congruent modulo 32 do not become overweighted.
            Instruction::Ccmp { rn, rm, nzcv, cond } | Instruction::Ccmn { rn, rm, nzcv, cond } => {
                match rng.random_range(0..4) {
                    0 => *rn = self.random_register(rng),
                    1 => {
                        *rm = match self.random_operand_from_pool(rng, &self.imm5_immediates) {
                            Operand::Register(r) => Operand::Register(r),
                            Operand::Immediate(v) => Operand::Immediate(v),
                            // CCMP/CCMN reject shifted-register or extended-
                            // register operands; collapse to a plain register
                            // (consistent with candidate::generate_random_-
                            // instruction's conditional-compare arm).
                            Operand::ShiftedRegister { reg, .. }
                            | Operand::ExtendedRegister { reg, .. } => Operand::Register(reg),
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
            // Flag-setting arith/logical: ADDS/SUBS allow 12-bit imm; ANDS
            // also accepts bitmask imms but we keep the mutator's `rm` table
            // tuned to the 12-bit form (see candidate.rs notes).
            Instruction::Adds { rd, rn, rm } | Instruction::Subs { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    // Same non-ROR shifted-register coverage and deduplicated
                    // imm12 immediate pool as Add/Sub, but without the
                    // extended-register branch: ADDS/SUBS do not encode an
                    // extended-register form (issue #279).
                    _ => {
                        *rm = self.random_arith_operand_no_extended(
                            rng,
                            false,
                            RegisterWidth::X64,
                            &self.imm12_immediates,
                        );
                    }
                }
            }
            // ADC/ADCS/SBC/SBCS are register-only (rd, rn, rm all registers).
            Instruction::Adc { rd, rn, rm }
            | Instruction::Adcs { rd, rn, rm }
            | Instruction::Sbc { rd, rn, rm }
            | Instruction::Sbcs { rd, rn, rm } => match rng.random_range(0..3) {
                0 => *rd = self.random_register(rng),
                1 => *rn = self.random_register(rng),
                _ => *rm = self.random_register(rng),
            },
            Instruction::Ands { rd, rn, rm, width } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = self.random_logical_operand(rng, *width, false, false),
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
            // Bit-field manipulation: 4-way operand mutation (rd, rn, lsb, width)
            // with 2D clamping so the (lsb + width <= bound) constraint is always
            // preserved, where `bound` is 32 for the W form and 64 for X. The
            // register width form itself is never changed here (that would be a
            // cross-width opcode bridge, which we deliberately avoid).
            Instruction::Ubfx {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            }
            | Instruction::Sbfx {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            }
            | Instruction::Bfi {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            }
            | Instruction::Bfxil {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            }
            | Instruction::Ubfiz {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            }
            | Instruction::Sbfiz {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            } => {
                let bound = reg_width.bit_width() as u32;
                match rng.random_range(0..4) {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    2 => {
                        // Mutate width: bound by current lsb so the pair stays valid.
                        let max_w = (bound - *lsb as u32).max(1);
                        *width = ((rng.random::<u32>() % max_w) + 1) as u8;
                    }
                    _ => {
                        // Mutate lsb; clamp width down if the new lsb would
                        // overflow the (lsb + width <= bound) constraint.
                        *lsb = (rng.random::<u32>() % bound) as u8;
                        if (*lsb as u16 + *width as u16) > bound as u16 {
                            *width = bound as u8 - *lsb;
                        }
                    }
                }
            }
            // Branches / terminators: never mutated. The rewritable_len()
            // helper above excludes the terminator slot before this fires;
            // arm is a no-op for defense in depth.
            Instruction::B { .. }
            | Instruction::BCond { .. }
            | Instruction::Ret { .. }
            | Instruction::Cbz { .. }
            | Instruction::Cbnz { .. }
            | Instruction::Tbz { .. }
            | Instruction::Tbnz { .. }
            | Instruction::Bl { .. }
            | Instruction::Br { .. } => {}

            // Memory ops (issue #68 step 16). Rotate over the small set of
            // mutable fields per variant: data register, base, optional
            // index register, optional offset. Keep address-mode and width
            // unchanged here (those are bridged via mutate_opcode in a
            // future step); the encodability filter downstream drops any
            // mutation that violates SP/XZR or writeback-aliasing rules.
            Instruction::Ldr { rt, addr, .. }
            | Instruction::Ldrs { rt, addr, .. }
            | Instruction::Str { rt, addr, .. } => {
                if rng.random_bool(0.5) {
                    *rt = self.random_register(rng);
                } else {
                    mutate_address_operand(self, rng, addr);
                }
            }
            Instruction::Ldp { rt1, rt2, addr, .. } | Instruction::Stp { rt1, rt2, addr, .. } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rt1 = self.random_register(rng),
                    1 => *rt2 = self.random_register(rng),
                    _ => mutate_address_operand(self, rng, addr),
                }
            }
        }
    }

    /// Opcode mutation: change the opcode while mostly keeping operand structure.
    ///
    /// The match arms below are intentionally heuristic. Some clusters are
    /// asymmetric because certain instructions have extra bridges or
    /// encodability clamps; acceptance uses only the Metropolis cost rule, not
    /// a Hastings correction for the proposal probabilities.
    fn mutate_opcode<R: RngExt>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.is_empty() {
            return;
        }

        let rewritable = rewritable_len(sequence);
        if rewritable == 0 {
            return;
        }
        let idx = rng.random_range(0..rewritable);
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
            Instruction::MovRegW { rd, rn } => {
                // Opcode mutation must keep the W/X family compatible, so stay
                // within the W family here (AddW/SubW already do). There is no
                // `MovImmW`, so mirror the `MovReg -> MovImm` step by mutating to
                // a W-form `AddW` with a freshly generated (clamped) rm, or
                // keeping `MovRegW`.
                if rng.random_bool(0.5) {
                    Instruction::AddW {
                        rd,
                        rn,
                        rm: self.random_operand_3op_from_pool(
                            rng,
                            false,
                            RegisterWidth::W32,
                            &self.imm12_immediates,
                        ),
                    }
                } else {
                    Instruction::MovRegW { rd, rn }
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
                1 => Instruction::And {
                    rd,
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, true),
                    width: RegisterWidth::X64,
                },
                2 => Instruction::Orr {
                    rd,
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, true),
                    width: RegisterWidth::X64,
                },
                3 => Instruction::Eor {
                    rd,
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, true),
                    width: RegisterWidth::X64,
                },
                _ => Instruction::Add { rd, rn, rm },
            },
            Instruction::AddW { rd, rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::SubW { rd, rn, rm },
                _ => Instruction::AddW { rd, rn, rm },
            },
            Instruction::Sub { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Add { rd, rn, rm },
                1 => Instruction::And {
                    rd,
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, true),
                    width: RegisterWidth::X64,
                },
                2 => Instruction::Orr {
                    rd,
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, true),
                    width: RegisterWidth::X64,
                },
                3 => Instruction::Eor {
                    rd,
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, true),
                    width: RegisterWidth::X64,
                },
                _ => Instruction::Sub { rd, rn, rm },
            },
            Instruction::SubW { rd, rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::AddW { rd, rn, rm },
                _ => Instruction::SubW { rd, rn, rm },
            },
            Instruction::And { rd, rn, rm, width } => match rng.random_range(0..5) {
                // Logical -> arithmetic: drop ROR from shifted-register form
                // and clamp bitmask immediates into ADD/SUB's imm12 range.
                0 => Instruction::Add {
                    rd,
                    rn,
                    rm: Self::clamp_imm12(strip_ror_for_arith(rm)),
                },
                1 => Instruction::Sub {
                    rd,
                    rn,
                    rm: Self::clamp_imm12(strip_ror_for_arith(rm)),
                },
                2 => Instruction::Orr { rd, rn, rm, width },
                3 => Instruction::Eor { rd, rn, rm, width },
                _ => Instruction::And { rd, rn, rm, width },
            },
            Instruction::Orr { rd, rn, rm, width } => match rng.random_range(0..5) {
                0 => Instruction::Add {
                    rd,
                    rn,
                    rm: Self::clamp_imm12(strip_ror_for_arith(rm)),
                },
                1 => Instruction::Sub {
                    rd,
                    rn,
                    rm: Self::clamp_imm12(strip_ror_for_arith(rm)),
                },
                2 => Instruction::And { rd, rn, rm, width },
                3 => Instruction::Eor { rd, rn, rm, width },
                _ => Instruction::Orr { rd, rn, rm, width },
            },
            Instruction::Eor { rd, rn, rm, width } => match rng.random_range(0..5) {
                0 => Instruction::Add {
                    rd,
                    rn,
                    rm: Self::clamp_imm12(strip_ror_for_arith(rm)),
                },
                1 => Instruction::Sub {
                    rd,
                    rn,
                    rm: Self::clamp_imm12(strip_ror_for_arith(rm)),
                },
                2 => Instruction::And { rd, rn, rm, width },
                3 => Instruction::Orr { rd, rn, rm, width },
                _ => Instruction::Eor { rd, rn, rm, width },
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
                1 => Instruction::Tst {
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, true),
                    width: RegisterWidth::X64,
                },
                _ => Instruction::Cmp { rn, rm },
            },
            Instruction::Cmn { rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::Cmp { rn, rm },
                1 => Instruction::Tst {
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, true),
                    width: RegisterWidth::X64,
                },
                _ => Instruction::Cmn { rn, rm },
            },
            Instruction::Tst { rn, rm, width } => match rng.random_range(0..3) {
                // Tst (logical) -> Cmp/Cmn (arithmetic): drop ROR and clamp
                // bitmask immediates into the arithmetic imm12 range.
                0 => Instruction::Cmp {
                    rn,
                    rm: Self::clamp_imm12(strip_ror_for_arith(rm)),
                },
                1 => Instruction::Cmn {
                    rn,
                    rm: Self::clamp_imm12(strip_ror_for_arith(rm)),
                },
                _ => Instruction::Tst { rn, rm, width },
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
            // Single-source bit-manipulation and standalone extends share an
            // 11-way peer cluster.
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
            | Instruction::Uxth { rd, rn } => single_source_opcode_peer(rng, rd, rn),
            // Move-wide cluster: MOVN ↔ MOVZ ↔ MOVK (all share rd/imm/shift),
            // plus a single MovImm bridge anchored at MOVZ.
            //
            // This is not a symmetric proposal table: MOVZ has one more
            // outgoing arm than MOVN/MOVK. The top-level search accepts it as
            // a heuristic proposal without a Hastings correction.
            //
            // Topology note: before PR #108, MOVN had a direct MOVN ↔ MovImm
            // edge. PR #108 removed it, so MOVN now reaches MovImm via two hops
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
            // Inverted-logical instructions join the AND/ORR/EOR cluster.
            // The peer counts differ across BIC/BICS/ORN/EON, so these arms
            // are also heuristic rather than detailed-balance transitions.
            Instruction::Bic { rd, rn, rm } => match rng.random_range(0..7) {
                0 => Instruction::And {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
                1 => Instruction::Orr {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
                2 => Instruction::Eor {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
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
                0 => Instruction::And {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
                1 => Instruction::Orr {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
                2 => Instruction::Eor {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
                3 => Instruction::Bic { rd, rn, rm },
                4 => Instruction::Orn { rd, rn, rm },
                5 => Instruction::Eon { rd, rn, rm },
                _ => Instruction::Bics { rd, rn, rm },
            },
            Instruction::Orn { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::And {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
                1 => Instruction::Orr {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
                2 => Instruction::Bic { rd, rn, rm },
                3 => Instruction::Eon { rd, rn, rm },
                _ => Instruction::Orn { rd, rn, rm },
            },
            Instruction::Eon { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::And {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
                1 => Instruction::Eor {
                    rd,
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
                2 => Instruction::Bic { rd, rn, rm },
                3 => Instruction::Orn { rd, rn, rm },
                _ => Instruction::Eon { rd, rn, rm },
            },
            // Flag-setting cluster: ADDS↔SUBS↔ANDS, and into/out of ADD/SUB/AND.
            // The ADD/SUB/AND bridges make this another intentionally
            // asymmetric proposal family.
            //
            // ADDS/SUBS use 12-bit arithmetic immediates; ANDS uses logical
            // bitmask immediates. Crossing into ANDS therefore resamples
            // immediate operands from the curated bitmask pool.
            Instruction::Adds { rd, rn, rm } => match rng.random_range(0..4) {
                0 => Instruction::Add { rd, rn, rm },
                1 => Instruction::Subs { rd, rn, rm },
                2 => Instruction::Ands {
                    rd,
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, false),
                    width: RegisterWidth::X64,
                },
                _ => Instruction::Adds { rd, rn, rm },
            },
            Instruction::Subs { rd, rn, rm } => match rng.random_range(0..4) {
                0 => Instruction::Sub { rd, rn, rm },
                1 => Instruction::Adds { rd, rn, rm },
                2 => Instruction::Ands {
                    rd,
                    rn,
                    rm: self.logical_rm_from_existing(rng, rm, RegisterWidth::X64, false),
                    width: RegisterWidth::X64,
                },
                _ => Instruction::Subs { rd, rn, rm },
            },
            // ADC/ADCS/SBC/SBCS toggle within the carry family (register-only).
            Instruction::Adc { rd, rn, rm } => match rng.random_range(0..2) {
                0 => Instruction::Adcs { rd, rn, rm },
                _ => Instruction::Adc { rd, rn, rm },
            },
            Instruction::Adcs { rd, rn, rm } => match rng.random_range(0..2) {
                0 => Instruction::Adc { rd, rn, rm },
                _ => Instruction::Adcs { rd, rn, rm },
            },
            Instruction::Sbc { rd, rn, rm } => match rng.random_range(0..2) {
                0 => Instruction::Sbcs { rd, rn, rm },
                _ => Instruction::Sbc { rd, rn, rm },
            },
            Instruction::Sbcs { rd, rn, rm } => match rng.random_range(0..2) {
                0 => Instruction::Sbc { rd, rn, rm },
                _ => Instruction::Sbcs { rd, rn, rm },
            },
            Instruction::Ands { rd, rn, rm, width } => match rng.random_range(0..4) {
                0 => Instruction::And { rd, rn, rm, width },
                1 => Instruction::Adds {
                    rd,
                    rn,
                    rm: Self::clamp_imm12(rm),
                },
                2 => Instruction::Subs {
                    rd,
                    rn,
                    rm: Self::clamp_imm12(rm),
                },
                _ => Instruction::Ands { rd, rn, rm, width },
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
            // Multiply-accumulate cluster. MADD/MSUB preserve or collapse
            // `ra`; MNEG introduces a fresh `ra` when expanding back to an
            // accumulating form because it has no accumulator operand.
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
            Instruction::Mneg { rd, rn, rm } => match rng.random_range(0..4) {
                0 => Instruction::Mul { rd, rn, rm },
                1 => Instruction::Madd {
                    rd,
                    rn,
                    rm,
                    ra: self.random_register(rng),
                },
                2 => Instruction::Msub {
                    rd,
                    rn,
                    rm,
                    ra: self.random_register(rng),
                },
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
            // Bit-field manipulation: 6-peer cluster. Each variant has 5
            // peers + self-identity. Note: swapping between extract (UBFX/SBFX)
            // and insert (BFI/BFXIL/UBFIZ/SBFIZ) variants changes whether rd
            // is read; MCMC tolerates this because invalid proposals fail
            // equivalence checking and are rejected by the acceptance step.
            Instruction::Ubfx {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            } => match rng.random_range(0..6) {
                0 => Instruction::Sbfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                1 => Instruction::Bfi {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                2 => Instruction::Bfxil {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                3 => Instruction::Ubfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                4 => Instruction::Sbfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                _ => Instruction::Ubfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
            },
            Instruction::Sbfx {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            } => match rng.random_range(0..6) {
                0 => Instruction::Ubfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                1 => Instruction::Bfi {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                2 => Instruction::Bfxil {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                3 => Instruction::Ubfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                4 => Instruction::Sbfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                _ => Instruction::Sbfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
            },
            Instruction::Bfi {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            } => match rng.random_range(0..6) {
                0 => Instruction::Ubfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                1 => Instruction::Sbfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                2 => Instruction::Bfxil {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                3 => Instruction::Ubfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                4 => Instruction::Sbfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                _ => Instruction::Bfi {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
            },
            Instruction::Bfxil {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            } => match rng.random_range(0..6) {
                0 => Instruction::Ubfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                1 => Instruction::Sbfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                2 => Instruction::Bfi {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                3 => Instruction::Ubfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                4 => Instruction::Sbfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                _ => Instruction::Bfxil {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
            },
            Instruction::Ubfiz {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            } => match rng.random_range(0..6) {
                0 => Instruction::Ubfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                1 => Instruction::Sbfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                2 => Instruction::Bfi {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                3 => Instruction::Bfxil {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                4 => Instruction::Sbfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                _ => Instruction::Ubfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
            },
            Instruction::Sbfiz {
                rd,
                rn,
                lsb,
                width,
                reg_width,
            } => match rng.random_range(0..6) {
                0 => Instruction::Ubfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                1 => Instruction::Sbfx {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                2 => Instruction::Bfi {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                3 => Instruction::Bfxil {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                4 => Instruction::Ubfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                _ => Instruction::Sbfiz {
                    rd,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
            },
            // Branches / terminators: never opcode-mutated. rewritable_len()
            // excludes the terminator slot before this fires; identity is
            // safe if reached.
            Instruction::B { target } => Instruction::B { target },
            Instruction::BCond { target, cond } => Instruction::BCond { target, cond },
            Instruction::Ret { rn } => Instruction::Ret { rn },
            Instruction::Cbz { rn, target } => Instruction::Cbz { rn, target },
            Instruction::Cbnz { rn, target } => Instruction::Cbnz { rn, target },
            Instruction::Tbz { rt, bit, target } => Instruction::Tbz { rt, bit, target },
            Instruction::Tbnz { rt, bit, target } => Instruction::Tbnz { rt, bit, target },
            Instruction::Bl { target } => Instruction::Bl { target },
            Instruction::Br { rn } => Instruction::Br { rn },

            // Memory ops (issue #68): width/sign-extend bridges arrive in
            // step 16. Identity-mutate for now.
            Instruction::Ldr { rt, addr, width } => Instruction::Ldr { rt, addr, width },
            Instruction::Ldrs { rt, addr, width } => Instruction::Ldrs { rt, addr, width },
            Instruction::Str { rt, addr, width } => Instruction::Str { rt, addr, width },
            Instruction::Ldp {
                rt1,
                rt2,
                addr,
                width,
                signed,
            } => Instruction::Ldp {
                rt1,
                rt2,
                addr,
                width,
                signed,
            },
            Instruction::Stp {
                rt1,
                rt2,
                addr,
                width,
            } => Instruction::Stp {
                rt1,
                rt2,
                addr,
                width,
            },
        };
    }

    /// Swap mutation: swap two instructions in the sequence
    fn mutate_swap<R: RngExt>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.len() < 2 {
            return;
        }

        let rewritable = rewritable_len(sequence);
        if rewritable < 2 {
            return; // not enough non-terminator slots to swap
        }
        let idx1 = rng.random_range(0..rewritable);
        let idx2 = rng.random_range(0..rewritable);
        sequence.swap(idx1, idx2);
    }

    /// Instruction mutation: replace an entire instruction with a random one
    fn mutate_instruction<R: RngExt>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.is_empty() {
            return;
        }

        let rewritable = rewritable_len(sequence);
        if rewritable == 0 {
            return;
        }
        let idx = rng.random_range(0..rewritable);
        sequence[idx] = generate_random_instruction(rng, &self.registers, &self.immediates);
    }

    fn random_address_offset<R: RngExt>(&self, rng: &mut R) -> i64 {
        // Favor useful positive scaled offsets while retaining signed 9-bit
        // negative coverage for unscaled and writeback memory forms.
        ADDRESS_OFFSET_POOL[rng.random_range(0..ADDRESS_OFFSET_POOL.len())]
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

    fn random_logical_immediate<R: RngExt>(&self, rng: &mut R, width: RegisterWidth) -> i64 {
        let pool = match width {
            RegisterWidth::W32 => LOGICAL_IMM32_POOL,
            RegisterWidth::X64 => LOGICAL_IMM64_POOL,
        };
        pool[rng.random_range(0..pool.len())]
    }

    fn random_logical_operand<R: RngExt>(
        &self,
        rng: &mut R,
        width: RegisterWidth,
        allow_shifted: bool,
        allow_w32_register_or_shifted: bool,
    ) -> Operand {
        // W32 flag-setting logical forms still sample bitmask immediates only.
        // Non-flag-setting AND/ORR/EOR opt into the W32 register/shifted space.
        if width == RegisterWidth::W32 && !allow_w32_register_or_shifted {
            return Operand::Immediate(self.random_logical_immediate(rng, width));
        }

        if allow_shifted
            && rng.random_bool(SHIFTED_REGISTER_OPERAND_PROBABILITY)
            && !self.registers.is_empty()
        {
            self.random_shifted_register(rng, true, width)
        } else if rng.random_bool(0.5) {
            Operand::Register(self.random_register(rng))
        } else {
            Operand::Immediate(self.random_logical_immediate(rng, width))
        }
    }

    fn logical_rm_from_existing<R: RngExt>(
        &self,
        rng: &mut R,
        rm: Operand,
        width: RegisterWidth,
        allow_shifted: bool,
    ) -> Operand {
        match rm {
            Operand::Immediate(_) => Operand::Immediate(self.random_logical_immediate(rng, width)),
            Operand::Register(reg) if width == RegisterWidth::X64 => Operand::Register(reg),
            Operand::ShiftedRegister { reg, kind, amount }
                if width == RegisterWidth::X64 && allow_shifted =>
            {
                Operand::ShiftedRegister { reg, kind, amount }
            }
            Operand::ShiftedRegister { reg, .. } if width == RegisterWidth::X64 => {
                Operand::Register(reg)
            }
            Operand::ExtendedRegister { reg, .. } if width == RegisterWidth::X64 => {
                Operand::Register(reg)
            }
            // Opcode bridges keep W32 logical operands in the historical
            // immediate-only space; W32 register/shifted sampling is limited
            // to direct AND/ORR/EOR operand mutation.
            Operand::Register(_)
            | Operand::ShiftedRegister { .. }
            | Operand::ExtendedRegister { .. } => {
                Operand::Immediate(self.random_logical_immediate(rng, width))
            }
        }
    }

    fn random_operand<R: RngExt>(&self, rng: &mut R) -> Operand {
        if rng.random_bool(0.5) && !self.registers.is_empty() {
            Operand::Register(self.random_register(rng))
        } else {
            Operand::Immediate(self.random_immediate(rng))
        }
    }

    fn random_immediate_from_pool<R: RngExt>(&self, rng: &mut R, pool: &[i64]) -> i64 {
        debug_assert!(!pool.is_empty(), "immediate pool must be non-empty");
        pool[rng.random_range(0..pool.len())]
    }

    fn random_operand_from_pool<R: RngExt>(&self, rng: &mut R, pool: &[i64]) -> Operand {
        if rng.random_bool(0.5) && !self.registers.is_empty() {
            Operand::Register(self.random_register(rng))
        } else {
            Operand::Immediate(self.random_immediate_from_pool(rng, pool))
        }
    }

    /// Issue #87. ADD/SUB/ADDS/SUBS/CMP/CMN immediates must fit the 12-bit
    /// unsigned range `0..=0xFFF` (see `Instruction::is_encodable_aarch64`).
    /// This wraps an existing operand when bridging opcode families; fresh
    /// arithmetic-immediate proposals use `imm12_immediates` instead so raw
    /// configured immediates that share a residue do not become overweighted.
    fn clamp_imm12(operand: Operand) -> Operand {
        match operand {
            Operand::Immediate(v) => Operand::Immediate(v.rem_euclid(0x1000)),
            other => other,
        }
    }

    /// Random rm operand for the in-scope arithmetic/logical/comparison
    /// shifted/extended-register opcodes (issues #59, #151). Uses the tuned
    /// shifted-register proposal rate; with an additional low probability
    /// returns an `ExtendedRegister`; otherwise falls back to the plain
    /// register/immediate distribution. `allow_ror` toggles whether ROR is in
    /// the shifted kind pool — callers in arith bridges must pass false.
    /// `width` selects the shift-amount pool (`RegisterWidth::W32` caps amounts
    /// at 31, `RegisterWidth::X64` allows 32) and is forwarded to
    /// `random_shifted_register`.
    fn random_operand_3op<R: RngExt>(
        &self,
        rng: &mut R,
        allow_ror: bool,
        width: RegisterWidth,
    ) -> Operand {
        let choice: f64 = rng.random();
        if choice < SHIFTED_REGISTER_OPERAND_PROBABILITY && !self.registers.is_empty() {
            self.random_shifted_register(rng, allow_ror, width)
        } else if choice < SHIFTED_REGISTER_OPERAND_PROBABILITY + EXTENDED_REGISTER_OPERAND_DELTA
            && self.has_extended_register_source()
        {
            self.random_extended_register(rng)
        } else {
            self.random_operand(rng)
        }
    }

    fn random_operand_3op_from_pool<R: RngExt>(
        &self,
        rng: &mut R,
        allow_ror: bool,
        width: RegisterWidth,
        immediate_pool: &[i64],
    ) -> Operand {
        let choice: f64 = rng.random();
        if choice < SHIFTED_REGISTER_OPERAND_PROBABILITY && !self.registers.is_empty() {
            self.random_shifted_register(rng, allow_ror, width)
        } else if choice < SHIFTED_REGISTER_OPERAND_PROBABILITY + EXTENDED_REGISTER_OPERAND_DELTA
            && self.has_extended_register_source()
        {
            self.random_extended_register(rng)
        } else {
            self.random_operand_from_pool(rng, immediate_pool)
        }
    }

    /// Random rm operand for flag-setting arithmetic (ADDS/SUBS). Mirrors
    /// `random_operand_3op_from_pool` — tuned non-ROR shifted-register coverage
    /// plus the deduplicated immediate pool — but intentionally omits the
    /// extended-register branch: ADDS/SUBS do not encode an extended-register
    /// form (issue #279, see `Instruction::is_encodable_aarch64`).
    fn random_arith_operand_no_extended<R: RngExt>(
        &self,
        rng: &mut R,
        allow_ror: bool,
        width: RegisterWidth,
        immediate_pool: &[i64],
    ) -> Operand {
        let choice: f64 = rng.random();
        if choice < SHIFTED_REGISTER_OPERAND_PROBABILITY && !self.registers.is_empty() {
            self.random_shifted_register(rng, allow_ror, width)
        } else {
            self.random_operand_from_pool(rng, immediate_pool)
        }
    }

    fn random_shifted_register<R: RngExt>(
        &self,
        rng: &mut R,
        allow_ror: bool,
        width: RegisterWidth,
    ) -> Operand {
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
        let amounts = match width {
            RegisterWidth::W32 => &SHIFTED_REGISTER_AMOUNTS_W32,
            RegisterWidth::X64 => &SHIFTED_REGISTER_AMOUNTS_X64,
        };
        let amount = amounts[rng.random_range(0..amounts.len())];
        Operand::ShiftedRegister { reg, kind, amount }
    }

    fn has_extended_register_source(&self) -> bool {
        self.registers
            .iter()
            .any(|reg| !matches!(reg, Register::SP | Register::XZR))
    }

    fn random_extended_register<R: RngExt>(&self, rng: &mut R) -> Operand {
        let eligible_count = self
            .registers
            .iter()
            .filter(|reg| !matches!(reg, Register::SP | Register::XZR))
            .count();
        debug_assert!(eligible_count > 0);
        let selected = rng.random_range(0..eligible_count);
        let reg = self
            .registers
            .iter()
            .copied()
            .filter(|reg| !matches!(reg, Register::SP | Register::XZR))
            .nth(selected)
            .expect("random_extended_register requires at least one non-SP/non-XZR register");
        let kinds = [
            ExtendKind::Uxtb,
            ExtendKind::Uxth,
            ExtendKind::Uxtw,
            ExtendKind::Uxtx,
            ExtendKind::Sxtb,
            ExtendKind::Sxth,
            ExtendKind::Sxtw,
            ExtendKind::Sxtx,
        ];
        let kind = kinds[rng.random_range(0..kinds.len())];
        let shift = rng.random_range(0..5);

        Operand::ExtendedRegister { reg, kind, shift }
    }

    fn random_shift_operand<R: RngExt>(&self, rng: &mut R) -> Operand {
        if rng.random_bool(0.7) {
            let shifts = AARCH64_RANDOM_SHIFT_IMMEDIATES;
            Operand::Immediate(shifts[rng.random_range(0..shifts.len())])
        } else if !self.registers.is_empty() {
            Operand::Register(self.random_register(rng))
        } else {
            Operand::Immediate(1)
        }
    }
}

/// AArch64 mutator newtype exposing the free `Mutator` through the
/// `ISAMutator<Instruction>` trait (#77 stage 1 step 10, ADR-0004 decision 2).
/// The body stays in `src/search/stochastic/mutation.rs` to avoid moving the
/// cyclic dep on `crate::search::candidate::generate_random_instruction`; the
/// newtype just re-exposes the same surface under the trait name.
#[derive(Debug)]
pub struct AArch64Mutator(Mutator);

impl AArch64Mutator {
    pub fn new(registers: Vec<Register>, immediates: Vec<i64>, weights: MutationWeights) -> Self {
        Self(Mutator::new(registers, immediates, weights))
    }

    /// Access the inner free `Mutator` for consumers that haven't migrated yet.
    pub fn inner(&self) -> &Mutator {
        &self.0
    }
}

impl crate::isa::ISAMutator<Instruction> for AArch64Mutator {
    fn mutate<R: RngExt>(&self, rng: &mut R, sequence: &[Instruction]) -> Vec<Instruction> {
        self.0.mutate(rng, sequence)
    }
}

/// Mutate one field of an `AddressOperand`. The variant kind (Imm vs Reg
/// vs Ext) and IndexMode are preserved; only the base register, optional
/// index register, optional offset, or optional shift amount changes.
/// Width / writeback are untouched here — those bridges live in
/// `mutate_opcode`.
fn mutate_address_operand<R: RngExt>(
    mutator: &Mutator,
    rng: &mut R,
    addr: &mut crate::ir::types::AddressOperand,
) {
    use crate::ir::types::AddressOperand;
    match addr {
        AddressOperand::Imm { base, offset, .. } => {
            if rng.random_bool(0.5) {
                *base = mutator.random_register(rng);
            } else {
                *offset = mutator.random_address_offset(rng);
            }
        }
        AddressOperand::Reg { base, idx, shift } => {
            let choice = rng.random_range(0..3);
            match choice {
                0 => *base = mutator.random_register(rng),
                1 => *idx = mutator.random_register(rng),
                _ => *shift = if rng.random_bool(0.5) { 0 } else { 3 },
            }
        }
        AddressOperand::Ext {
            base, idx, shift, ..
        } => {
            let choice = rng.random_range(0..3);
            match choice {
                0 => *base = mutator.random_register(rng),
                1 => *idx = mutator.random_register(rng),
                _ => *shift = if rng.random_bool(0.5) { 0 } else { 3 },
            }
        }
    }
}

/// Perform operand mutation on a specific instruction (for testing)
/// Number of instructions a mutation operator may rewrite. Equals
/// `sequence.len()` for terminator-free sequences and `sequence.len() - 1`
/// when the last instruction is a basic-block terminator (issue #69 — the
/// terminator is fixed live-out; search holds it bit-identical).
fn rewritable_len(sequence: &[Instruction]) -> usize {
    match sequence.last() {
        Some(last) if last.is_terminator() => sequence.len() - 1,
        _ => sequence.len(),
    }
}

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

/// Change opcode while mostly preserving operand structure (for testing)
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
    use crate::search::config::SearchConfig;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rand_chacha::ChaCha8Rng;
    use std::collections::BTreeMap;

    fn default_mutator() -> Mutator {
        Mutator::new(
            vec![Register::X0, Register::X1, Register::X2],
            vec![-1, 0, 1, 2],
            MutationWeights::default(),
        )
    }

    #[test]
    fn normalized_immediate_pool_keeps_unique_residues_in_first_seen_order() {
        assert_eq!(
            normalized_immediate_pool(&[0x1000, 0x2000, 0x3000, 5, 0x1005], 0x1000),
            vec![0, 5]
        );
        assert_eq!(normalized_immediate_pool(&[], 32), vec![0]);
    }

    #[test]
    fn mutator_stores_per_opcode_class_immediate_pools() {
        let config = SearchConfig::default();
        let mutator = Mutator::new(
            config.available_registers,
            config.available_immediates,
            MutationWeights::default(),
        );

        assert_eq!(mutator.immediates.len(), 20);
        assert_eq!(mutator.imm12_immediates, mutator.immediates);
        assert_eq!(
            mutator.imm5_immediates,
            vec![0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31]
        );
    }

    fn logical_immediate_instrs(imm: i64, width: RegisterWidth) -> [Instruction; 5] {
        [
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width,
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width,
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width,
            },
        ]
    }

    #[test]
    fn logical_immediate_pools_are_unique_nontrivial_and_encodable() {
        for (name, pool, width) in [
            ("W32", LOGICAL_IMM32_POOL, RegisterWidth::W32),
            ("X64", LOGICAL_IMM64_POOL, RegisterWidth::X64),
        ] {
            assert!(!pool.is_empty(), "{name} logical immediate pool is empty");

            let mut unique = pool.to_vec();
            unique.sort_unstable();
            assert!(
                unique.windows(2).all(|window| window[0] != window[1]),
                "{name} logical immediate pool contains duplicates: {pool:?}"
            );

            assert!(
                pool.iter().all(|imm| *imm != 0 && *imm != -1),
                "{name} logical immediate pool must exclude all-zero/all-one masks"
            );

            for &imm in pool {
                for instr in logical_immediate_instrs(imm, width) {
                    assert!(
                        instr.is_encodable_aarch64(),
                        "{name} pool value 0x{:x} produced non-encodable {}",
                        imm as u64,
                        instr
                    );
                }
            }
        }
    }

    #[test]
    fn random_logical_immediate_ignores_generic_immediate_pool() {
        let mutator = Mutator::new(
            vec![Register::X0, Register::X1, Register::X2],
            vec![0, -1, 5, 0x1_0000_00ff, 12345],
            MutationWeights::default(),
        );
        let mut rng = ChaCha8Rng::seed_from_u64(0x3740);

        for width in [RegisterWidth::W32, RegisterWidth::X64] {
            for _ in 0..500 {
                let imm = mutator.random_logical_immediate(&mut rng, width);
                for instr in logical_immediate_instrs(imm, width) {
                    assert!(
                        instr.is_encodable_aarch64(),
                        "sampled {:?} logical immediate 0x{:x} produced non-encodable {}",
                        width,
                        imm as u64,
                        instr
                    );
                }
            }
        }
    }

    #[test]
    fn random_shift_operand_never_samples_zero_immediate() {
        let mutator = default_mutator();
        let mut rng = ChaCha8Rng::seed_from_u64(0x263);
        let mut saw_immediate = false;

        for _ in 0..2_000 {
            let operand = mutator.random_shift_operand(&mut rng);
            if let Operand::Immediate(amount) = operand {
                assert_ne!(amount, 0, "random_shift_operand sampled shift #0");
                saw_immediate = true;
            }
        }

        assert!(
            saw_immediate,
            "random_shift_operand never returned an immediate"
        );
    }

    #[test]
    fn mutate_operand_samples_encodable_logical_immediates_for_both_widths() {
        let mutator = Mutator::new(
            vec![Register::X0, Register::X1, Register::X2],
            vec![0, -1, 5, 0x1_0000_00ff, 12345],
            MutationWeights::default(),
        );
        let starts = [
            (
                "AND W32",
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff),
                    width: RegisterWidth::W32,
                },
            ),
            (
                "ORR W32",
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff),
                    width: RegisterWidth::W32,
                },
            ),
            (
                "EOR W32",
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff),
                    width: RegisterWidth::W32,
                },
            ),
            (
                "TST W32",
                Instruction::Tst {
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff),
                    width: RegisterWidth::W32,
                },
            ),
            (
                "ANDS W32",
                Instruction::Ands {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff),
                    width: RegisterWidth::W32,
                },
            ),
            (
                "AND X64",
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                    width: RegisterWidth::X64,
                },
            ),
            (
                "ORR X64",
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                    width: RegisterWidth::X64,
                },
            ),
            (
                "EOR X64",
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                    width: RegisterWidth::X64,
                },
            ),
            (
                "TST X64",
                Instruction::Tst {
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                    width: RegisterWidth::X64,
                },
            ),
            (
                "ANDS X64",
                Instruction::Ands {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                    width: RegisterWidth::X64,
                },
            ),
        ];

        for (idx, (name, start)) in starts.into_iter().enumerate() {
            let mut rng = ChaCha8Rng::seed_from_u64(0x3741 + idx as u64);
            let mut saw_immediate = false;

            for _ in 0..5000 {
                let mut seq = vec![start];
                mutator.mutate_operand(&mut rng, &mut seq);
                assert!(
                    seq[0].is_encodable_aarch64(),
                    "{name} operand mutation produced non-encodable {}",
                    seq[0]
                );

                let rm = match seq[0] {
                    Instruction::And { rm, .. }
                    | Instruction::Orr { rm, .. }
                    | Instruction::Eor { rm, .. }
                    | Instruction::Tst { rm, .. }
                    | Instruction::Ands { rm, .. } => rm,
                    other => panic!("mutate_operand changed {name} opcode: {other:?}"),
                };
                if matches!(rm, Operand::Immediate(_)) {
                    saw_immediate = true;
                }
            }

            assert!(
                saw_immediate,
                "{name} operand mutation never sampled a logical immediate"
            );
        }
    }

    #[test]
    fn mutate_operand_can_produce_w32_logical_shifted_registers() {
        let mutator = default_mutator();
        let starts = [
            (
                "AND W32",
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff),
                    width: RegisterWidth::W32,
                },
            ),
            (
                "ORR W32",
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff),
                    width: RegisterWidth::W32,
                },
            ),
            (
                "EOR W32",
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff),
                    width: RegisterWidth::W32,
                },
            ),
        ];

        for (idx, (name, start)) in starts.into_iter().enumerate() {
            let mut rng = StdRng::seed_from_u64(0x4730 + idx as u64);
            let mut saw_shifted = false;
            let mut saw_ror = false;

            for _ in 0..20_000 {
                let mut seq = vec![start];
                mutator.mutate_operand(&mut rng, &mut seq);
                assert!(
                    seq[0].is_encodable_aarch64(),
                    "{name} operand mutation produced non-encodable {}",
                    seq[0]
                );

                let rm = match seq[0] {
                    Instruction::And { rm, .. }
                    | Instruction::Orr { rm, .. }
                    | Instruction::Eor { rm, .. } => rm,
                    other => panic!("mutate_operand changed {name} opcode: {other:?}"),
                };

                if let Operand::ShiftedRegister { kind, amount, .. } = rm {
                    saw_shifted = true;
                    saw_ror |= kind == crate::ir::ShiftKind::Ror;
                    assert!(
                        amount <= 31,
                        "{name} W32 shifted-register proposal used amount {amount}"
                    );
                }
            }

            assert!(
                saw_shifted,
                "{name} operand mutation never sampled a shifted-register rm"
            );
            assert!(
                saw_ror,
                "{name} operand mutation never sampled a ROR shifted-register rm"
            );
        }
    }

    #[test]
    fn opcode_bridges_to_logical_replace_arithmetic_immediates_with_bitmasks() {
        let mutator = Mutator::new(
            vec![Register::X0, Register::X1, Register::X2],
            vec![0, -1, 5, 12345],
            MutationWeights::default(),
        );
        let starts = [
            (
                "ADD",
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(5),
                },
            ),
            (
                "SUB",
                Instruction::Sub {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(5),
                },
            ),
            (
                "CMP",
                Instruction::Cmp {
                    rn: Register::X1,
                    rm: Operand::Immediate(5),
                },
            ),
            (
                "CMN",
                Instruction::Cmn {
                    rn: Register::X1,
                    rm: Operand::Immediate(5),
                },
            ),
            (
                "ADDS",
                Instruction::Adds {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(5),
                },
            ),
            (
                "SUBS",
                Instruction::Subs {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(5),
                },
            ),
        ];

        for (idx, (name, start)) in starts.into_iter().enumerate() {
            let mut rng = ChaCha8Rng::seed_from_u64(0x3742 + idx as u64);
            let mut saw_logical = false;

            for _ in 0..5000 {
                let mut seq = vec![start];
                mutator.mutate_opcode(&mut rng, &mut seq);

                let rm = match seq[0] {
                    Instruction::And { rm, .. }
                    | Instruction::Orr { rm, .. }
                    | Instruction::Eor { rm, .. }
                    | Instruction::Tst { rm, .. }
                    | Instruction::Ands { rm, .. } => rm,
                    _ => continue,
                };

                saw_logical = true;
                assert!(
                    seq[0].is_encodable_aarch64(),
                    "{name} logical opcode bridge produced non-encodable {}",
                    seq[0]
                );
                match rm {
                    Operand::Immediate(imm) => assert_ne!(
                        imm, 5,
                        "{name} logical opcode bridge preserved arithmetic-only #5"
                    ),
                    other => panic!(
                        "{name} logical opcode bridge from immediate source produced {other:?}"
                    ),
                }
            }

            assert!(
                saw_logical,
                "expected {name} opcode mutation to reach a logical peer"
            );
        }
    }

    #[test]
    fn opcode_bridges_from_logical_clamp_bitmask_immediates_for_arithmetic() {
        let mutator = default_mutator();
        let starts = [
            (
                "AND",
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff00),
                    width: RegisterWidth::X64,
                },
            ),
            (
                "ORR",
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff00),
                    width: RegisterWidth::X64,
                },
            ),
            (
                "EOR",
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff00),
                    width: RegisterWidth::X64,
                },
            ),
            (
                "TST",
                Instruction::Tst {
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff00),
                    width: RegisterWidth::X64,
                },
            ),
            (
                "ANDS",
                Instruction::Ands {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xff00),
                    width: RegisterWidth::X64,
                },
            ),
        ];

        for (idx, (name, start)) in starts.into_iter().enumerate() {
            let mut rng = ChaCha8Rng::seed_from_u64(0x3743 + idx as u64);
            let mut saw_arithmetic = false;

            for _ in 0..5000 {
                let mut seq = vec![start];
                mutator.mutate_opcode(&mut rng, &mut seq);

                match seq[0] {
                    Instruction::Add { .. }
                    | Instruction::Sub { .. }
                    | Instruction::Cmp { .. }
                    | Instruction::Cmn { .. }
                    | Instruction::Adds { .. }
                    | Instruction::Subs { .. } => {
                        saw_arithmetic = true;
                        assert!(
                            seq[0].is_encodable_aarch64(),
                            "{name} arithmetic opcode bridge produced non-encodable {}",
                            seq[0]
                        );
                    }
                    _ => {}
                }
            }

            assert!(
                saw_arithmetic,
                "expected {name} opcode mutation to reach an arithmetic peer"
            );
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum MoveWideOpcode {
        MovImm,
        MovK,
        MovN,
        MovZ,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum SingleSourceOpcode {
        Cls,
        Clz,
        Rbit,
        Rev,
        Rev16,
        Rev32,
        Sxtb,
        Sxth,
        Sxtw,
        Uxtb,
        Uxth,
    }

    const SINGLE_SOURCE_OPCODE_CLUSTER: [SingleSourceOpcode; 11] = [
        SingleSourceOpcode::Clz,
        SingleSourceOpcode::Cls,
        SingleSourceOpcode::Rbit,
        SingleSourceOpcode::Rev,
        SingleSourceOpcode::Rev32,
        SingleSourceOpcode::Rev16,
        SingleSourceOpcode::Sxtb,
        SingleSourceOpcode::Sxth,
        SingleSourceOpcode::Sxtw,
        SingleSourceOpcode::Uxtb,
        SingleSourceOpcode::Uxth,
    ];

    fn classify_move_wide_opcode(instr: Instruction) -> MoveWideOpcode {
        match instr {
            Instruction::MovImm { .. } => MoveWideOpcode::MovImm,
            Instruction::MovK { .. } => MoveWideOpcode::MovK,
            Instruction::MovN { .. } => MoveWideOpcode::MovN,
            Instruction::MovZ { .. } => MoveWideOpcode::MovZ,
            other => panic!("unexpected move-wide opcode mutation output: {other:?}"),
        }
    }

    fn single_source_instruction(
        opcode: SingleSourceOpcode,
        rd: Register,
        rn: Register,
    ) -> Instruction {
        match opcode {
            SingleSourceOpcode::Clz => Instruction::Clz { rd, rn },
            SingleSourceOpcode::Cls => Instruction::Cls { rd, rn },
            SingleSourceOpcode::Rbit => Instruction::Rbit { rd, rn },
            SingleSourceOpcode::Rev => Instruction::Rev { rd, rn },
            SingleSourceOpcode::Rev32 => Instruction::Rev32 { rd, rn },
            SingleSourceOpcode::Rev16 => Instruction::Rev16 { rd, rn },
            SingleSourceOpcode::Sxtb => Instruction::Sxtb { rd, rn },
            SingleSourceOpcode::Sxth => Instruction::Sxth { rd, rn },
            SingleSourceOpcode::Sxtw => Instruction::Sxtw { rd, rn },
            SingleSourceOpcode::Uxtb => Instruction::Uxtb { rd, rn },
            SingleSourceOpcode::Uxth => Instruction::Uxth { rd, rn },
        }
    }

    fn classify_single_source_opcode(
        instr: Instruction,
    ) -> (SingleSourceOpcode, Register, Register) {
        match instr {
            Instruction::Clz { rd, rn } => (SingleSourceOpcode::Clz, rd, rn),
            Instruction::Cls { rd, rn } => (SingleSourceOpcode::Cls, rd, rn),
            Instruction::Rbit { rd, rn } => (SingleSourceOpcode::Rbit, rd, rn),
            Instruction::Rev { rd, rn } => (SingleSourceOpcode::Rev, rd, rn),
            Instruction::Rev32 { rd, rn } => (SingleSourceOpcode::Rev32, rd, rn),
            Instruction::Rev16 { rd, rn } => (SingleSourceOpcode::Rev16, rd, rn),
            Instruction::Sxtb { rd, rn } => (SingleSourceOpcode::Sxtb, rd, rn),
            Instruction::Sxth { rd, rn } => (SingleSourceOpcode::Sxth, rd, rn),
            Instruction::Sxtw { rd, rn } => (SingleSourceOpcode::Sxtw, rd, rn),
            Instruction::Uxtb { rd, rn } => (SingleSourceOpcode::Uxtb, rd, rn),
            Instruction::Uxth { rd, rn } => (SingleSourceOpcode::Uxth, rd, rn),
            other => panic!("unexpected single-source opcode mutation output: {other:?}"),
        }
    }

    fn single_source_opcode_mutation_counts(
        start: SingleSourceOpcode,
        seed: u64,
    ) -> BTreeMap<SingleSourceOpcode, usize> {
        let mutator = default_mutator();
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut counts = BTreeMap::new();

        for _ in 0..5000 {
            let mut seq = vec![single_source_instruction(start, Register::X0, Register::X1)];
            mutator.mutate_opcode(&mut rng, &mut seq);
            let (opcode, rd, rn) = classify_single_source_opcode(seq[0]);
            assert_eq!(rd, Register::X0, "{start:?} bridge must preserve rd");
            assert_eq!(rn, Register::X1, "{start:?} bridge must preserve rn");
            *counts.entry(opcode).or_insert(0) += 1;
        }

        counts
    }

    fn move_wide_opcode_mutation_counts(
        start: Instruction,
        expected_mov_imm_payload: Option<(Register, i64)>,
    ) -> BTreeMap<MoveWideOpcode, usize> {
        let mutator = default_mutator();
        let mut rng = ChaCha8Rng::seed_from_u64(0x114);
        let mut counts = BTreeMap::new();

        for _ in 0..5000 {
            let mut seq = vec![start];
            mutator.mutate_opcode(&mut rng, &mut seq);

            if let Instruction::MovImm { rd, imm } = seq[0]
                && let Some((expected_rd, expected_imm)) = expected_mov_imm_payload
            {
                assert_eq!(rd, expected_rd, "MovZ -> MovImm must preserve rd");
                assert_eq!(
                    imm, expected_imm,
                    "MovZ -> MovImm must use the raw u16 immediate"
                );
            }

            *counts.entry(classify_move_wide_opcode(seq[0])).or_insert(0) += 1;
        }

        counts
    }

    fn assert_move_wide_opcode_peers(
        start: Instruction,
        expected: &[MoveWideOpcode],
        expected_mov_imm_payload: Option<(Register, i64)>,
    ) {
        let counts = move_wide_opcode_mutation_counts(start, expected_mov_imm_payload);

        for observed in counts.keys() {
            assert!(
                expected.contains(observed),
                "unexpected move-wide opcode {observed:?} from {start:?}; counts: {counts:?}"
            );
        }

        for expected_opcode in expected {
            assert!(
                counts.get(expected_opcode).copied().unwrap_or(0) > 0,
                "missing move-wide opcode {expected_opcode:?} from {start:?}; counts: {counts:?}"
            );
        }
    }

    #[test]
    fn random_address_offset_pool_is_tuned_for_positive_scaled_memory_offsets() {
        let expected = [0, 8, 16, 24, 32, 64, -8, -256];
        assert_eq!(ADDRESS_OFFSET_POOL, expected);

        let mut unique = ADDRESS_OFFSET_POOL;
        unique.sort_unstable();
        assert!(
            unique.windows(2).all(|window| window[0] != window[1]),
            "address offset mutation pool must not contain duplicates"
        );

        assert!(
            ADDRESS_OFFSET_POOL.iter().all(|offset| {
                (offset >= &0 && offset % 8 == 0) || (-256..=255).contains(offset)
            })
        );
        assert!(
            ADDRESS_OFFSET_POOL
                .iter()
                .filter(|offset| **offset >= 0 && **offset % 8 == 0)
                .count()
                >= 6,
            "pool should favor useful non-negative X-form scaled offsets"
        );
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
    fn test_mutate_operand_can_produce_shifted_register_for_flag_setting_arith() {
        let mutator = default_mutator();
        let starts = [
            (
                "ADDS",
                Instruction::Adds {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                },
            ),
            (
                "SUBS",
                Instruction::Subs {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                },
            ),
        ];

        for (idx, (name, start)) in starts.into_iter().enumerate() {
            let mut rng = ChaCha8Rng::seed_from_u64(0x2790 + idx as u64);
            let mut saw_shifted = false;

            for _ in 0..5000 {
                let mut seq = vec![start];
                mutator.mutate_operand(&mut rng, &mut seq);

                let rm = match seq[0] {
                    Instruction::Adds { rm, .. } | Instruction::Subs { rm, .. } => rm,
                    other => panic!("mutate_operand changed {name} opcode: {other:?}"),
                };

                match rm {
                    Operand::ShiftedRegister { kind, .. } => {
                        assert_ne!(
                            kind,
                            crate::ir::ShiftKind::Ror,
                            "{name} shifted-register rm must not use ROR"
                        );
                        assert!(
                            seq[0].is_encodable_aarch64(),
                            "mutated {name} must remain encodable: {}",
                            seq[0]
                        );
                        saw_shifted = true;
                        break;
                    }
                    Operand::ExtendedRegister { .. } => {
                        panic!(
                            "mutate_operand on {name} must not emit unsupported ExtendedRegister rm"
                        )
                    }
                    _ => {}
                }
            }

            assert!(
                saw_shifted,
                "mutate_operand on {name} did not produce ShiftedRegister rm"
            );
        }
    }

    #[test]
    fn random_operand_3op_uses_tuned_shifted_register_probability() {
        let mutator = default_mutator();
        let mut rng = StdRng::seed_from_u64(134);
        let trials = 10_000;
        let mut x64_shifted = 0;
        let mut x64_saw_amount_32 = false;

        for _ in 0..trials {
            match mutator.random_operand_3op(&mut rng, false, RegisterWidth::X64) {
                Operand::ShiftedRegister {
                    kind: crate::ir::ShiftKind::Ror,
                    ..
                } => panic!("arithmetic shifted-register operands must not use ROR"),
                Operand::ShiftedRegister { amount, .. } => {
                    x64_shifted += 1;
                    x64_saw_amount_32 |= amount == 32;
                }
                _ => {}
            }
        }

        assert!(
            (2_500..=3_500).contains(&x64_shifted),
            "expected X64 shifted-register proposals in the 25%-35% band, got {x64_shifted}/{trials}"
        );
        assert!(
            x64_saw_amount_32,
            "X64 shifted-register mutations should still explore amount 32"
        );

        let mut rng = StdRng::seed_from_u64(13432);
        let mut w32_shifted = 0;

        for _ in 0..trials {
            match mutator.random_operand_3op(&mut rng, false, RegisterWidth::W32) {
                Operand::ShiftedRegister {
                    kind: crate::ir::ShiftKind::Ror,
                    ..
                } => panic!("W32 arithmetic shifted-register operands must not use ROR"),
                Operand::ShiftedRegister { amount, .. } => {
                    w32_shifted += 1;
                    assert!(
                        amount <= 31,
                        "W32 shifted-register mutations must not emit amount {amount}"
                    );
                }
                _ => {}
            }
        }

        assert!(
            (2_500..=3_500).contains(&w32_shifted),
            "expected W32 shifted-register proposals in the 25%-35% band, got {w32_shifted}/{trials}"
        );
    }

    #[test]
    fn mutate_operand_uses_tuned_shifted_register_probability_for_x64_tst() {
        let mutator = default_mutator();
        let trials = 20_000;
        let mut rng = StdRng::seed_from_u64(135);
        let mut x64_shifted = 0;

        for _ in 0..trials {
            let mut seq = vec![Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            }];
            mutator.mutate_operand(&mut rng, &mut seq);
            if let Instruction::Tst {
                rm: Operand::ShiftedRegister { .. },
                ..
            } = seq[0]
            {
                x64_shifted += 1;
            }
        }

        assert!(
            (2_400..=3_600).contains(&x64_shifted),
            "expected X64 TST shifted-register proposals in the 12%-18% band, got {x64_shifted}/{trials}"
        );

        let mut rng = StdRng::seed_from_u64(136);
        for _ in 0..5_000 {
            let mut seq = vec![Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::W32,
            }];
            mutator.mutate_operand(&mut rng, &mut seq);
            if let Instruction::Tst {
                rm: Operand::ShiftedRegister { .. },
                ..
            } = seq[0]
            {
                panic!("W32 TST mutation must not emit shifted-register operands");
            }
        }
    }

    #[test]
    fn mutate_operand_keeps_w32_flag_logicals_immediate_only() {
        let mutator = default_mutator();
        let starts = [
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Immediate(0xff),
                width: RegisterWidth::W32,
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0xff),
                width: RegisterWidth::W32,
            },
        ];

        for (idx, start) in starts.into_iter().enumerate() {
            let mut rng = StdRng::seed_from_u64(0x4735 + idx as u64);
            for _ in 0..5_000 {
                let mut seq = vec![start];
                mutator.mutate_operand(&mut rng, &mut seq);
                let rm = match seq[0] {
                    Instruction::Tst { rm, .. } | Instruction::Ands { rm, .. } => rm,
                    other => panic!("mutate_operand changed W32 flag logical opcode: {other:?}"),
                };
                assert!(
                    matches!(rm, Operand::Immediate(_)),
                    "W32 flag logical mutation must stay immediate-only, got {seq:?}"
                );
            }
        }
    }

    #[test]
    fn shifted_register_operands_respect_arith_and_logical_ror_policy() {
        let mutator = default_mutator();
        let mut rng = StdRng::seed_from_u64(137);

        for _ in 0..1_000 {
            let operand = mutator.random_shifted_register(&mut rng, false, RegisterWidth::X64);
            if let Operand::ShiftedRegister {
                kind: crate::ir::ShiftKind::Ror,
                ..
            } = operand
            {
                panic!("arithmetic shifted-register operand generator must not emit ROR");
            }

            for instr in [
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: operand,
                },
                Instruction::Sub {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: operand,
                },
                Instruction::Cmp {
                    rn: Register::X1,
                    rm: operand,
                },
                Instruction::Cmn {
                    rn: Register::X1,
                    rm: operand,
                },
            ] {
                assert!(
                    instr.is_encodable_aarch64(),
                    "arithmetic shifted-register mutation must remain encodable: {instr:?}"
                );
            }
        }

        let mut saw_ror = false;
        for _ in 0..1_000 {
            let operand = mutator.random_shifted_register(&mut rng, true, RegisterWidth::X64);
            if let Operand::ShiftedRegister {
                kind: crate::ir::ShiftKind::Ror,
                ..
            } = operand
            {
                saw_ror = true;
            }

            for instr in [
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: operand,
                    width: RegisterWidth::X64,
                },
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: operand,
                    width: RegisterWidth::X64,
                },
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: operand,
                    width: RegisterWidth::X64,
                },
                Instruction::Tst {
                    rn: Register::X1,
                    rm: operand,
                    width: RegisterWidth::X64,
                },
            ] {
                assert!(
                    instr.is_encodable_aarch64(),
                    "logical shifted-register mutation must remain encodable: {instr:?}"
                );
            }
        }

        assert!(
            saw_ror,
            "logical shifted-register operand generator should still explore ROR"
        );
    }

    #[test]
    fn w32_arithmetic_shifted_register_operands_use_encodable_amounts() {
        let mutator = default_mutator();
        let mut rng = StdRng::seed_from_u64(138);

        for _ in 0..1_000 {
            let operand = mutator.random_shifted_register(&mut rng, false, RegisterWidth::W32);
            let Operand::ShiftedRegister { amount, .. } = operand else {
                panic!("shifted-register helper must produce a ShiftedRegister");
            };
            assert!(
                amount <= 31,
                "W-form shifted-register mutation must not emit amount {amount}"
            );

            for instr in [
                Instruction::AddW {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: operand,
                },
                Instruction::SubW {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: operand,
                },
            ] {
                assert!(
                    instr.is_encodable_aarch64(),
                    "W-form shifted-register mutation must remain encodable: {instr:?}"
                );
            }
        }
    }

    #[test]
    fn w32_arithmetic_mutation_call_sites_use_w32_shift_amounts() {
        let mutator = default_mutator();
        let mut rng = StdRng::seed_from_u64(139);
        let mut saw_operand_shifted = false;
        let mut saw_subw_operand_shifted = false;
        let mut saw_opcode_shifted = false;

        for _ in 0..20_000 {
            let mut seq = vec![Instruction::AddW {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            }];
            mutator.mutate_operand(&mut rng, &mut seq);
            if let Instruction::AddW {
                rm: Operand::ShiftedRegister { amount, .. },
                ..
            } = seq[0]
            {
                saw_operand_shifted = true;
                assert!(
                    amount <= 31,
                    "AddW operand mutation must not emit shifted amount {amount}"
                );
                assert!(
                    seq[0].is_encodable_aarch64(),
                    "AddW operand mutation must remain encodable: {:?}",
                    seq[0]
                );
            }

            // SubW shares the AddW match arm, so it must observe the same
            // W-safe amount pool. Probe it explicitly so the coverage is
            // self-documenting and survives a future arm split.
            let mut seq = vec![Instruction::SubW {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            }];
            mutator.mutate_operand(&mut rng, &mut seq);
            if let Instruction::SubW {
                rm: Operand::ShiftedRegister { amount, .. },
                ..
            } = seq[0]
            {
                saw_subw_operand_shifted = true;
                assert!(
                    amount <= 31,
                    "SubW operand mutation must not emit shifted amount {amount}"
                );
                assert!(
                    seq[0].is_encodable_aarch64(),
                    "SubW operand mutation must remain encodable: {:?}",
                    seq[0]
                );
            }

            let mut seq = vec![Instruction::MovRegW {
                rd: Register::X0,
                rn: Register::X1,
            }];
            mutator.mutate_opcode(&mut rng, &mut seq);
            if let Instruction::AddW {
                rm: Operand::ShiftedRegister { amount, .. },
                ..
            } = seq[0]
            {
                saw_opcode_shifted = true;
                assert!(
                    amount <= 31,
                    "MovRegW -> AddW opcode mutation must not emit shifted amount {amount}"
                );
                assert!(
                    seq[0].is_encodable_aarch64(),
                    "MovRegW -> AddW opcode mutation must remain encodable: {:?}",
                    seq[0]
                );
            }
        }

        assert!(
            saw_operand_shifted,
            "AddW operand mutation should still explore shifted-register operands"
        );
        assert!(
            saw_subw_operand_shifted,
            "SubW operand mutation should still explore shifted-register operands"
        );
        assert!(
            saw_opcode_shifted,
            "MovRegW -> AddW opcode mutation should still explore shifted-register operands"
        );
    }

    #[test]
    fn mutate_operand_can_produce_extended_register_for_add() {
        let mutator = default_mutator();
        let mut rng = ChaCha8Rng::seed_from_u64(0x151);

        for _ in 0..5000 {
            let mut seq = vec![Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            }];
            mutator.mutate_operand(&mut rng, &mut seq);

            if let Instruction::Add {
                rm: Operand::ExtendedRegister { reg, shift, .. },
                ..
            } = seq[0]
            {
                assert_ne!(reg, Register::SP);
                assert_ne!(reg, Register::XZR);
                assert!(shift <= 4);
                assert!(
                    seq[0].is_encodable_aarch64(),
                    "mutated ADD must remain encodable: {}",
                    seq[0]
                );
                return;
            }
        }

        panic!("mutate_operand on ADD did not produce ExtendedRegister rm");
    }

    #[test]
    fn mutate_operand_can_produce_extended_register_for_sub_cmp_and_cmn() {
        let mutator = default_mutator();
        let starts = [
            (
                "SUB",
                Instruction::Sub {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                },
            ),
            (
                "CMP",
                Instruction::Cmp {
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                },
            ),
            (
                "CMN",
                Instruction::Cmn {
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                },
            ),
        ];

        for (idx, (name, start)) in starts.into_iter().enumerate() {
            let mut rng = ChaCha8Rng::seed_from_u64(0x1510 + idx as u64);
            let mut saw_extended = false;

            for _ in 0..5000 {
                let mut seq = vec![start];
                mutator.mutate_operand(&mut rng, &mut seq);

                let rm = match seq[0] {
                    Instruction::Sub { rm, .. }
                    | Instruction::Cmp { rm, .. }
                    | Instruction::Cmn { rm, .. } => rm,
                    other => panic!("mutate_operand changed {name} opcode: {other:?}"),
                };

                if let Operand::ExtendedRegister { reg, shift, .. } = rm {
                    assert_ne!(reg, Register::SP);
                    assert_ne!(reg, Register::XZR);
                    assert!(shift <= 4);
                    assert!(
                        seq[0].is_encodable_aarch64(),
                        "mutated {name} must remain encodable: {}",
                        seq[0]
                    );
                    saw_extended = true;
                    break;
                }
            }

            assert!(
                saw_extended,
                "mutate_operand on {name} did not produce ExtendedRegister rm"
            );
        }
    }

    #[test]
    fn mutate_operand_extended_register_excludes_sp_and_xzr_sources() {
        let mutator = Mutator::new(
            vec![Register::SP, Register::XZR, Register::X2],
            vec![0, 1],
            MutationWeights::default(),
        );
        let mut rng = ChaCha8Rng::seed_from_u64(0x1515);
        let mut observed = 0;

        for _ in 0..5000 {
            let mut seq = vec![Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            }];
            mutator.mutate_operand(&mut rng, &mut seq);

            if let Instruction::Add {
                rm: Operand::ExtendedRegister { reg, .. },
                ..
            } = seq[0]
            {
                observed += 1;
                assert_eq!(
                    reg,
                    Register::X2,
                    "extended-register mutation must ignore SP/XZR source registers"
                );
                assert!(
                    seq[0].is_encodable_aarch64(),
                    "mutated ADD must remain encodable: {}",
                    seq[0]
                );
            }
        }

        assert!(
            observed > 0,
            "test did not observe any ExtendedRegister mutations"
        );
    }

    #[test]
    fn mutate_operand_on_ldr_can_change_base_or_rt_or_offset() {
        // Issue #68 step 16: mutate_operand must touch one of {rt, base,
        // offset} on a memory op without changing the variant or width.
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let mutator = default_mutator();
        let mut rng = rand::rng();
        let initial = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        let mut changed = false;
        for _ in 0..200 {
            let mut seq = vec![initial];
            mutator.mutate_operand(&mut rng, &mut seq);
            if seq[0] != initial {
                changed = true;
            }
            // Width and variant must be invariant under mutate_operand.
            match seq[0] {
                Instruction::Ldr {
                    width: AccessWidth::Extended,
                    addr:
                        AddressOperand::Imm {
                            mode: IndexMode::Offset,
                            ..
                        },
                    ..
                } => {}
                _ => panic!(
                    "mutate_operand changed variant/width/mode on Ldr: {:?}",
                    seq[0]
                ),
            }
        }
        assert!(changed, "mutate_operand never modified Ldr operands");
    }

    #[test]
    fn mutate_operand_on_ldr_can_reach_expanded_positive_offsets() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let mutator = default_mutator();
        let mut rng = StdRng::seed_from_u64(296);
        let initial = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        let mut saw_24 = false;
        let mut saw_32 = false;
        let mut saw_64 = false;

        for _ in 0..1000 {
            let mut seq = vec![initial];
            mutator.mutate_operand(&mut rng, &mut seq);
            match seq[0] {
                Instruction::Ldr {
                    width: AccessWidth::Extended,
                    addr:
                        AddressOperand::Imm {
                            offset,
                            mode: IndexMode::Offset,
                            ..
                        },
                    ..
                } => match offset {
                    24 => saw_24 = true,
                    32 => saw_32 = true,
                    64 => saw_64 = true,
                    _ => {}
                },
                _ => panic!(
                    "mutate_operand changed variant/width/mode on Ldr: {:?}",
                    seq[0]
                ),
            }

            if saw_24 && saw_32 && saw_64 {
                return;
            }
        }

        assert!(
            saw_24 && saw_32 && saw_64,
            "mutate_operand did not reach all expanded positive offsets: 24={saw_24}, 32={saw_32}, 64={saw_64}"
        );
    }

    #[test]
    fn generate_all_instructions_includes_memory_ops() {
        // Step 15: enumerative pool must produce at least one each of
        // Ldr / Str / Ldp / Stp for downstream search algorithms.
        use crate::search::candidate::generate_all_encodable_instructions;
        let regs = vec![Register::X0, Register::X1, Register::X2, Register::SP];
        let imms = vec![0, 8, 16];
        let pool = generate_all_encodable_instructions(&regs, &imms);
        assert!(
            pool.iter().any(|i| matches!(i, Instruction::Ldr { .. })),
            "candidate pool must contain Ldr",
        );
        assert!(
            pool.iter().any(|i| matches!(i, Instruction::Str { .. })),
            "candidate pool must contain Str",
        );
        assert!(
            pool.iter().any(|i| matches!(i, Instruction::Ldp { .. })),
            "candidate pool must contain Ldp",
        );
        assert!(
            pool.iter().any(|i| matches!(i, Instruction::Stp { .. })),
            "candidate pool must contain Stp",
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
            width: RegisterWidth::X64,
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
    fn mutate_opcode_bridge_strips_extended_register_for_logical_ops() {
        let mutator = default_mutator();
        let extended = Operand::ExtendedRegister {
            reg: Register::X2,
            kind: ExtendKind::Sxtw,
            shift: 1,
        };
        let starts = [
            (
                "ADD",
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: extended,
                },
            ),
            (
                "SUB",
                Instruction::Sub {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: extended,
                },
            ),
            (
                "CMP",
                Instruction::Cmp {
                    rn: Register::X1,
                    rm: extended,
                },
            ),
            (
                "CMN",
                Instruction::Cmn {
                    rn: Register::X1,
                    rm: extended,
                },
            ),
        ];

        for (idx, (name, start)) in starts.into_iter().enumerate() {
            let mut rng = ChaCha8Rng::seed_from_u64(0x15100 + idx as u64);
            let mut saw_logical = false;

            for _ in 0..5000 {
                let mut seq = vec![start];
                mutator.mutate_opcode(&mut rng, &mut seq);

                match seq[0] {
                    Instruction::And { rm, .. }
                    | Instruction::Orr { rm, .. }
                    | Instruction::Eor { rm, .. }
                    | Instruction::Tst { rm, .. } => {
                        saw_logical = true;
                        assert_eq!(
                            rm,
                            Operand::Register(Register::X2),
                            "{name} logical bridge must strip ExtendedRegister to plain register"
                        );
                        assert!(
                            seq[0].is_encodable_aarch64(),
                            "{name} logical bridge must remain encodable: {}",
                            seq[0]
                        );
                    }
                    _ => {}
                }
            }

            assert!(
                saw_logical,
                "expected {name} opcode mutation to reach a logical/TST peer"
            );
        }
    }

    #[test]
    fn test_single_source_opcode_mutation_reaches_extend_and_bitmanip_peers() {
        for (idx, start) in SINGLE_SOURCE_OPCODE_CLUSTER.into_iter().enumerate() {
            let counts = single_source_opcode_mutation_counts(start, 0x15160 + idx as u64);

            for observed in counts.keys() {
                assert!(
                    SINGLE_SOURCE_OPCODE_CLUSTER.contains(observed),
                    "unexpected single-source opcode {observed:?} from {start:?}; counts: {counts:?}"
                );
            }

            for expected in SINGLE_SOURCE_OPCODE_CLUSTER {
                assert!(
                    counts.get(&expected).copied().unwrap_or(0) > 0,
                    "missing single-source opcode {expected:?} from {start:?}; counts: {counts:?}"
                );
            }
        }
    }

    #[test]
    fn test_move_wide_opcode_mutation_reaches_declared_peers() {
        use MoveWideOpcode::{MovImm, MovK, MovN, MovZ};

        assert_move_wide_opcode_peers(
            Instruction::MovN {
                rd: Register::X0,
                imm: 0x1234,
                shift: 16,
            },
            &[MovN, MovZ, MovK],
            None,
        );
        assert_move_wide_opcode_peers(
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0x1234,
                shift: 16,
            },
            &[MovZ, MovN, MovK, MovImm],
            Some((Register::X0, 0x1234)),
        );
        assert_move_wide_opcode_peers(
            Instruction::MovK {
                rd: Register::X0,
                imm: 0x1234,
                shift: 16,
            },
            &[MovK, MovN, MovZ],
            None,
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
    fn select_mutation_type_maps_each_weight_bucket_to_its_variant() {
        // Concentrating all weight on one category forces `select_index` to
        // that bucket for every draw, which pins the bucket-index -> variant
        // mapping regardless of the RNG stream.
        let cases = [
            (
                MutationWeights {
                    operand: 1.0,
                    opcode: 0.0,
                    swap: 0.0,
                    instruction: 0.0,
                },
                MutationType::Operand,
            ),
            (
                MutationWeights {
                    operand: 0.0,
                    opcode: 1.0,
                    swap: 0.0,
                    instruction: 0.0,
                },
                MutationType::Opcode,
            ),
            (
                MutationWeights {
                    operand: 0.0,
                    opcode: 0.0,
                    swap: 1.0,
                    instruction: 0.0,
                },
                MutationType::Swap,
            ),
            (
                MutationWeights {
                    operand: 0.0,
                    opcode: 0.0,
                    swap: 0.0,
                    instruction: 1.0,
                },
                MutationType::Instruction,
            ),
        ];
        let mut rng = rand::rng();
        for (weights, expected) in cases {
            let mutator = Mutator::new(vec![Register::X0], vec![0], weights);
            for _ in 0..64 {
                assert_eq!(mutator.select_mutation_type(&mut rng), expected);
            }
        }
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
    fn mneg_opcode_mutation_reaches_madd_and_msub() {
        let mutator = Mutator::new(vec![Register::X3], vec![0], MutationWeights::default());
        let mut rng = StdRng::seed_from_u64(127);
        let original = Instruction::Mneg {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let mut seen_madd = false;
        let mut seen_msub = false;

        for _ in 0..200 {
            let mut seq = vec![original];
            mutator.mutate_opcode(&mut rng, &mut seq);
            assert!(
                seq[0].is_encodable_aarch64(),
                "MNEG opcode mutation must stay encodable: {}",
                seq[0]
            );

            match seq[0] {
                Instruction::Madd { rd, rn, rm, ra } => {
                    assert_eq!(
                        (rd, rn, rm, ra),
                        (Register::X0, Register::X1, Register::X2, Register::X3)
                    );
                    seen_madd = true;
                }
                Instruction::Msub { rd, rn, rm, ra } => {
                    assert_eq!(
                        (rd, rn, rm, ra),
                        (Register::X0, Register::X1, Register::X2, Register::X3)
                    );
                    seen_msub = true;
                }
                Instruction::Mul { rd, rn, rm } | Instruction::Mneg { rd, rn, rm } => {
                    assert_eq!((rd, rn, rm), (Register::X0, Register::X1, Register::X2));
                }
                other => panic!("unexpected MNEG opcode mutation: {other:?}"),
            }
        }

        assert!(seen_madd, "MNEG opcode mutation must reach MADD");
        assert!(seen_msub, "MNEG opcode mutation must reach MSUB");
    }

    #[test]
    fn w_bitfield_operand_mutation_stays_encodable_and_keeps_width() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = Instruction::Sbfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
            reg_width: crate::ir::RegisterWidth::W32,
        };
        for _ in 0..400 {
            let mut seq = vec![original];
            mutator.mutate_operand(&mut rng, &mut seq);
            assert!(
                seq[0].is_encodable_aarch64(),
                "W operand mutation must stay encodable (lsb<=31, lsb+width<=32): {}",
                seq[0]
            );
            // Operand mutation must not change the register width form.
            assert!(
                matches!(
                    seq[0],
                    Instruction::Sbfx {
                        reg_width: crate::ir::RegisterWidth::W32,
                        ..
                    }
                ),
                "operand mutation changed the W form: {}",
                seq[0]
            );
        }
    }

    #[test]
    fn w_bitfield_opcode_mutation_preserves_width() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
            reg_width: crate::ir::RegisterWidth::W32,
        };
        for _ in 0..200 {
            let mut seq = vec![original];
            mutator.mutate_opcode(&mut rng, &mut seq);
            let reg_width = match seq[0] {
                Instruction::Ubfx { reg_width, .. }
                | Instruction::Sbfx { reg_width, .. }
                | Instruction::Bfi { reg_width, .. }
                | Instruction::Bfxil { reg_width, .. }
                | Instruction::Ubfiz { reg_width, .. }
                | Instruction::Sbfiz { reg_width, .. } => Some(reg_width),
                _ => None,
            };
            assert_eq!(
                reg_width,
                Some(crate::ir::RegisterWidth::W32),
                "opcode mutation must keep the W width (no X<->W bridging): {}",
                seq[0]
            );
            assert!(seq[0].is_encodable_aarch64());
        }
    }

    #[test]
    fn test_bitfield_operand_mutation_changes_fields_and_stays_encodable() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 8,
            width: 16,
            reg_width: crate::ir::RegisterWidth::X64,
        };
        let mut changed = false;
        for _ in 0..200 {
            let mut seq = vec![original];
            mutator.mutate_operand(&mut rng, &mut seq);
            assert!(
                seq[0].is_encodable_aarch64(),
                "mutated bit-field instruction must remain encodable: {}",
                seq[0]
            );
            if seq[0] != original {
                changed = true;
            }
        }
        assert!(
            changed,
            "operand mutation must produce a different bit-field instruction within 200 trials"
        );
    }

    #[test]
    fn test_bitfield_opcode_mutation_swaps_to_peer() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 8,
            width: 16,
            reg_width: crate::ir::RegisterWidth::X64,
        };
        let mut swapped_to_peer = false;
        for _ in 0..200 {
            let mut seq = vec![original];
            mutator.mutate_opcode(&mut rng, &mut seq);
            assert!(
                seq[0].is_encodable_aarch64(),
                "opcode mutation must produce encodable bit-field: {}",
                seq[0]
            );
            // A peer is any of the other 5 bit-field variants.
            if matches!(
                seq[0],
                Instruction::Sbfx { .. }
                    | Instruction::Bfi { .. }
                    | Instruction::Bfxil { .. }
                    | Instruction::Ubfiz { .. }
                    | Instruction::Sbfiz { .. }
            ) {
                swapped_to_peer = true;
                break;
            }
        }
        assert!(
            swapped_to_peer,
            "opcode mutation must reach a peer bit-field variant within 200 trials"
        );
    }

    /// Issue #87. If `available_immediates` includes values outside the
    /// per-variant encodable range, mutate_operand must clamp them so the
    /// MCMC search never wastes iterations on candidates that
    /// `is_encodable_aarch64` will reject.
    #[test]
    fn test_mutate_operand_clamps_arith_imm_to_encodable_range() {
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![0, 1, 0xFFF, 0x1000, 8192, 0x1_0000, 1_000_000, -1];
        let mutator = Mutator::new(regs, imms, MutationWeights::default());

        let starts = [
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::Ccmp {
                rn: Register::X1,
                rm: Operand::Immediate(0),
                nzcv: 0,
                cond: Condition::EQ,
            },
            Instruction::Ccmn {
                rn: Register::X1,
                rm: Operand::Immediate(0),
                nzcv: 0,
                cond: Condition::EQ,
            },
        ];

        for seed in 0u64..200 {
            let mut rng = StdRng::seed_from_u64(seed);
            for start in &starts {
                let mut seq = vec![*start];
                mutator.mutate_operand(&mut rng, &mut seq);
                assert!(
                    seq[0].is_encodable_aarch64(),
                    "seed {seed}, start {start:?} produced non-encodable {:?}",
                    seq[0]
                );
            }
        }
    }

    #[test]
    fn arithmetic_operand_mutation_samples_unique_imm12_residues() {
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![0x1000, 0x2000, 0x3000, 5];
        let mutator = Mutator::new(regs, imms, MutationWeights::default());
        let mut rng = StdRng::seed_from_u64(0x2760);
        let mut counts = BTreeMap::new();

        for _ in 0..50_000 {
            let mut seq = vec![Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            }];
            mutator.mutate_operand(&mut rng, &mut seq);
            assert!(seq[0].is_encodable_aarch64());

            if let Instruction::Add {
                rm: Operand::Immediate(imm),
                ..
            } = seq[0]
            {
                *counts.entry(imm).or_insert(0usize) += 1;
            }
        }

        assert_eq!(
            counts.keys().copied().collect::<Vec<_>>(),
            vec![0, 5],
            "ADD should only sample unique imm12 residues"
        );
        let zero = counts[&0];
        let five = counts[&5];
        let samples = zero + five;
        assert!(
            samples > 1_000,
            "seeded run should observe enough immediate proposals, saw {samples}"
        );
        assert!(
            zero.abs_diff(five) * 5 <= samples,
            "deduplicated residues should be sampled with similar probability: {counts:?}"
        );
    }

    #[test]
    fn conditional_compare_operand_mutation_samples_unique_imm5_residues() {
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![0, 32, 64, 31];
        let mutator = Mutator::new(regs, imms, MutationWeights::default());
        let mut rng = StdRng::seed_from_u64(0x2761);
        let mut counts = BTreeMap::new();

        for _ in 0..50_000 {
            let mut seq = vec![Instruction::Ccmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                nzcv: 0,
                cond: Condition::EQ,
            }];
            mutator.mutate_operand(&mut rng, &mut seq);
            assert!(seq[0].is_encodable_aarch64());

            if let Instruction::Ccmp {
                rm: Operand::Immediate(imm),
                ..
            } = seq[0]
            {
                *counts.entry(imm).or_insert(0usize) += 1;
            }
        }

        assert_eq!(
            counts.keys().copied().collect::<Vec<_>>(),
            vec![0, 31],
            "CCMP should only sample unique imm5 residues"
        );
        let zero = counts[&0];
        let thirty_one = counts[&31];
        let samples = zero + thirty_one;
        assert!(
            samples > 1_000,
            "seeded run should observe enough immediate proposals, saw {samples}"
        );
        assert!(
            zero.abs_diff(thirty_one) * 5 <= samples,
            "deduplicated residues should be sampled with similar probability: {counts:?}"
        );
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

    // ===== Issue #69: terminator-aware mutation =====

    #[test]
    fn mutation_preserves_terminator_across_1000_iterations() {
        // Sequence ends in `ret` — every mutation must leave it intact.
        let mutator = default_mutator();
        let mut rng = rand::rng();
        let terminator = Instruction::Ret { rn: Register::X30 };
        let original = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 42,
            },
            terminator,
        ];

        for _ in 0..1000 {
            let mutated = mutator.mutate(&mut rng, &original);
            assert_eq!(
                mutated.last(),
                Some(&terminator),
                "mutation changed the terminator: got {:?}",
                mutated
            );
        }
    }

    // Issue #77 stage 1 step 2 safety net:
    // every output of `Mutator::mutate` must be a well-formed `Vec<Instruction>`
    // that the encodability filter (`crate::search::candidate::is_sequence_encodable`)
    // can classify without panicking. Stage 1 step 10 promotes the mutator to
    // <I as ISA>::Mutator and stage 1 step 11 swaps the filter to
    // <I as ISA>::Assembler::can_assemble; this invariant must keep holding.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn mutator_output_is_classifiable(seed in 0u64..10_000) {
            let mutator = default_mutator();
            let mut rng = StdRng::seed_from_u64(seed);

            let starting_sequences = vec![
                vec![Instruction::MovImm { rd: Register::X0, imm: 0 }],
                vec![Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Register(Register::X2),
                }],
                vec![
                    Instruction::MovReg { rd: Register::X0, rn: Register::X1 },
                    Instruction::Add {
                        rd: Register::X0,
                        rn: Register::X0,
                        rm: Operand::Immediate(1),
                    },
                ],
                vec![Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind: crate::ir::ShiftKind::Ror,
                        amount: 4,
                    },
                    width: RegisterWidth::X64,
                }],
            ];

            for seq in &starting_sequences {
                // Run several mutations off this seeded RNG so we cover a
                // range of MutationType selections per seed.
                for _ in 0..16 {
                    let mutated = mutator.mutate(&mut rng, seq);

                    // Encodability classification must succeed without panic.
                    let _ = crate::search::candidate::is_sequence_encodable(&mutated);

                    // Every register the mutated instruction references must
                    // be either in the configured pool or one of the special
                    // registers (XZR, SP).
                    for instr in &mutated {
                        for r in instr.source_registers() {
                            prop_assert!(
                                mutator.registers.contains(&r)
                                    || matches!(r, Register::XZR | Register::SP),
                                "mutated instruction {:?} uses source register {:?} \
                                 outside the configured pool {:?}",
                                instr, r, mutator.registers,
                            );
                        }
                        if let Some(rd) = instr.destination() {
                            prop_assert!(
                                mutator.registers.contains(&rd)
                                    || matches!(rd, Register::XZR | Register::SP),
                                "mutated instruction {:?} writes destination \
                                 register {:?} outside the configured pool {:?}",
                                instr, rd, mutator.registers,
                            );
                        }
                    }
                }
            }
        }
    }
}
