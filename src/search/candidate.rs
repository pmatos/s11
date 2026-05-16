//! Instruction generation utilities for search algorithms

use crate::ir::instructions::MOVW_LEGAL_SHIFTS;
use crate::ir::{Instruction, Operand, Register};

/// Check if all instructions in a sequence can be encoded in AArch64 machine code.
pub fn is_sequence_encodable(sequence: &[Instruction]) -> bool {
    sequence.iter().all(|instr| instr.is_encodable_aarch64())
}

/// Generate all encodable instructions using the given registers and immediates.
///
/// This filters out instructions that cannot be encoded in AArch64 machine code,
/// such as SUB with negative immediates or AND with immediate operands.
pub fn generate_all_encodable_instructions(
    registers: &[Register],
    immediates: &[i64],
) -> Vec<Instruction> {
    generate_all_instructions(registers, immediates)
        .into_iter()
        .filter(|instr| instr.is_encodable_aarch64())
        .collect()
}

/// Generate all possible instructions using the given registers and immediates
/// Curated shift amounts enumerated for shifted-register operands (issue #59).
/// 0 is intentionally excluded: `<op> rd, rn, rm, lsl #0` is identical to the
/// plain `<op> rd, rn, rm` form which `generate_all_instructions` already emits.
const SHIFTED_OP_AMOUNTS: &[u8] = &[1, 2, 3, 4, 8, 16, 32];

pub fn generate_all_instructions(registers: &[Register], immediates: &[i64]) -> Vec<Instruction> {
    let mut instrs = Vec::new();

    for &rd in registers {
        // MovImm: mov rd, #imm
        for &imm in immediates {
            instrs.push(Instruction::MovImm { rd, imm });
        }

        // MovReg: mov rd, rn
        for &rn in registers {
            instrs.push(Instruction::MovReg { rd, rn });
        }

        // Binary operations with register second operand
        for &rn in registers {
            for &rm in registers {
                let rm_op = Operand::Register(rm);

                instrs.push(Instruction::Add { rd, rn, rm: rm_op });
                instrs.push(Instruction::Sub { rd, rn, rm: rm_op });
                instrs.push(Instruction::And { rd, rn, rm: rm_op });
                instrs.push(Instruction::Orr { rd, rn, rm: rm_op });
                instrs.push(Instruction::Eor { rd, rn, rm: rm_op });
                instrs.push(Instruction::Lsl {
                    rd,
                    rn,
                    shift: rm_op,
                });
                instrs.push(Instruction::Lsr {
                    rd,
                    rn,
                    shift: rm_op,
                });
                instrs.push(Instruction::Asr {
                    rd,
                    rn,
                    shift: rm_op,
                });
            }

            // Binary operations with immediate second operand
            for &imm in immediates {
                let imm_op = Operand::Immediate(imm);

                instrs.push(Instruction::Add { rd, rn, rm: imm_op });
                instrs.push(Instruction::Sub { rd, rn, rm: imm_op });
                instrs.push(Instruction::And { rd, rn, rm: imm_op });
                instrs.push(Instruction::Orr { rd, rn, rm: imm_op });
                instrs.push(Instruction::Eor { rd, rn, rm: imm_op });
            }

            // Shifted-register form (issue #59):
            //   Add/Sub: LSL/LSR/ASR (no ROR)
            //   And/Orr/Eor: LSL/LSR/ASR/ROR
            // SP is filtered later by is_encodable_aarch64; we keep enumeration
            // simple here.
            use crate::ir::ShiftKind;
            for &rm in registers {
                for &amount in SHIFTED_OP_AMOUNTS {
                    for kind in [ShiftKind::Lsl, ShiftKind::Lsr, ShiftKind::Asr] {
                        let sr = Operand::ShiftedRegister {
                            reg: rm,
                            kind,
                            amount,
                        };
                        instrs.push(Instruction::Add { rd, rn, rm: sr });
                        instrs.push(Instruction::Sub { rd, rn, rm: sr });
                        instrs.push(Instruction::And { rd, rn, rm: sr });
                        instrs.push(Instruction::Orr { rd, rn, rm: sr });
                        instrs.push(Instruction::Eor { rd, rn, rm: sr });
                    }
                    // ROR — logical only.
                    let sr_ror = Operand::ShiftedRegister {
                        reg: rm,
                        kind: ShiftKind::Ror,
                        amount,
                    };
                    instrs.push(Instruction::And { rd, rn, rm: sr_ror });
                    instrs.push(Instruction::Orr { rd, rn, rm: sr_ror });
                    instrs.push(Instruction::Eor { rd, rn, rm: sr_ror });
                }
                // Issue #60: extended-register form for ADD/SUB. Cmp/Cmn
                // are produced once-per-(rn,rm,kind,shift) further below
                // (outside the `rd` loop), since they have no destination
                // register — duplicating them by rd just inflates the
                // candidate pool with identical instructions (codex P2 on
                // #144).
                use crate::ir::ExtendKind;
                for kind in [
                    ExtendKind::Uxtb,
                    ExtendKind::Uxth,
                    ExtendKind::Uxtw,
                    ExtendKind::Uxtx,
                    ExtendKind::Sxtb,
                    ExtendKind::Sxth,
                    ExtendKind::Sxtw,
                    ExtendKind::Sxtx,
                ] {
                    for shift in 0u8..=4 {
                        let er = Operand::ExtendedRegister {
                            reg: rm,
                            kind,
                            shift,
                        };
                        instrs.push(Instruction::Add { rd, rn, rm: er });
                        instrs.push(Instruction::Sub { rd, rn, rm: er });
                    }
                }
            }

            // Shift operations with immediate shift amount (0-63 is valid, but we use small values)
            for shift in [0i64, 1, 2, 4, 8, 16, 32] {
                let shift_op = Operand::Immediate(shift);
                instrs.push(Instruction::Lsl {
                    rd,
                    rn,
                    shift: shift_op,
                });
                instrs.push(Instruction::Lsr {
                    rd,
                    rn,
                    shift: shift_op,
                });
                instrs.push(Instruction::Asr {
                    rd,
                    rn,
                    shift: shift_op,
                });
                // ROR also accepts the same shift-amount table.
                instrs.push(Instruction::Ror {
                    rd,
                    rn,
                    shift: shift_op,
                });
            }

            // ROR with register shift amount.
            for &rm in registers {
                instrs.push(Instruction::Ror {
                    rd,
                    rn,
                    shift: Operand::Register(rm),
                });
            }

            // Tier 1 inverted-logical and flag-setting binary ops (register form).
            for &rm in registers {
                let rm_op = Operand::Register(rm);
                instrs.push(Instruction::Bic { rd, rn, rm: rm_op });
                instrs.push(Instruction::Bics { rd, rn, rm: rm_op });
                instrs.push(Instruction::Orn { rd, rn, rm: rm_op });
                instrs.push(Instruction::Eon { rd, rn, rm: rm_op });
                instrs.push(Instruction::Adds { rd, rn, rm: rm_op });
                instrs.push(Instruction::Subs { rd, rn, rm: rm_op });
                instrs.push(Instruction::Ands { rd, rn, rm: rm_op });
            }
            // ADDS / SUBS also accept the same 12-bit-class immediate table
            // ADD / SUB does — keep them in sync. ANDS is register-only.
            for &imm in immediates {
                let imm_op = Operand::Immediate(imm);
                instrs.push(Instruction::Adds { rd, rn, rm: imm_op });
                instrs.push(Instruction::Subs { rd, rn, rm: imm_op });
            }
        }

        // Tier 1 unary ops: MVN / NEG / NEGS — one source register, no rn.
        for &rm in registers {
            instrs.push(Instruction::Mvn { rd, rm });
            instrs.push(Instruction::Neg { rd, rm });
            instrs.push(Instruction::Negs { rd, rm });
        }

        // Single-source bit-manipulation: CLZ / CLS / RBIT / REV / REV32 /
        // REV16, plus the standalone extends UXTB (#60 — siblings follow).
        for &rn in registers {
            instrs.push(Instruction::Clz { rd, rn });
            instrs.push(Instruction::Cls { rd, rn });
            instrs.push(Instruction::Rbit { rd, rn });
            instrs.push(Instruction::Rev { rd, rn });
            instrs.push(Instruction::Rev32 { rd, rn });
            instrs.push(Instruction::Rev16 { rd, rn });
            instrs.push(Instruction::Uxtb { rd, rn });
            instrs.push(Instruction::Sxtb { rd, rn });
            instrs.push(Instruction::Uxth { rd, rn });
            instrs.push(Instruction::Sxth { rd, rn });
            instrs.push(Instruction::Sxtw { rd, rn });
        }

        // Multiply-accumulate family. MADD/MSUB take a 4th register slot
        // (`ra`); MNEG/SMULH/UMULH are 3-operand register-only.
        for &rn in registers {
            for &rm in registers {
                instrs.push(Instruction::Mneg { rd, rn, rm });
                instrs.push(Instruction::Smulh { rd, rn, rm });
                instrs.push(Instruction::Umulh { rd, rn, rm });
                for &ra in registers {
                    instrs.push(Instruction::Madd { rd, rn, rm, ra });
                    instrs.push(Instruction::Msub { rd, rn, rm, ra });
                }
            }
        }

        // MOVN / MOVZ / MOVK: small representative imm set × four legal shift
        // positions. Keep this small — the full u16 × 4-shift space would
        // balloon the candidate count. The same parsimony rationale applies
        // as the immediate-table choice above.
        for imm in [0u16, 1, 0xFF, 0xFFFF] {
            for shift in MOVW_LEGAL_SHIFTS {
                instrs.push(Instruction::MovN { rd, imm, shift });
                instrs.push(Instruction::MovZ { rd, imm, shift });
                instrs.push(Instruction::MovK { rd, imm, shift });
            }
        }

        // CSET / CSETM: the 14 non-AL/NV conditions defined in
        // `ir::types::NORMAL_CONDITIONS`. `is_encodable_aarch64` rejects
        // AL/NV at the encoder boundary; the exhaustive set here enumerates
        // only the encodable subset.
        for cond in crate::ir::types::NORMAL_CONDITIONS {
            instrs.push(Instruction::Cset { rd, cond });
            instrs.push(Instruction::Csetm { rd, cond });
        }
    }

    // CCMP / CCMN: nested loops over register pairs × NORMAL_CONDITIONS ×
    // a representative nzcv subset × {register, imm5} for `rm`. Keep the
    // nzcv and imm5 samples bounded so the combined space stays around
    // ~120k candidates total — already inside the enumerative budget.
    const CCMP_NZCV_SAMPLES: [u8; 4] = [0, 1, 7, 15];
    const CCMP_IMM5_SAMPLES: [i64; 4] = [0, 1, 16, 31];
    for &rn in registers {
        if rn == Register::SP {
            continue;
        }
        for &rm_reg in registers {
            if rm_reg == Register::SP {
                continue;
            }
            for cond in crate::ir::types::NORMAL_CONDITIONS {
                for &nzcv in &CCMP_NZCV_SAMPLES {
                    instrs.push(Instruction::Ccmp {
                        rn,
                        rm: Operand::Register(rm_reg),
                        nzcv,
                        cond,
                    });
                    instrs.push(Instruction::Ccmn {
                        rn,
                        rm: Operand::Register(rm_reg),
                        nzcv,
                        cond,
                    });
                }
            }
        }
        for &imm in &CCMP_IMM5_SAMPLES {
            for cond in crate::ir::types::NORMAL_CONDITIONS {
                for &nzcv in &CCMP_NZCV_SAMPLES {
                    instrs.push(Instruction::Ccmp {
                        rn,
                        rm: Operand::Immediate(imm),
                        nzcv,
                        cond,
                    });
                    instrs.push(Instruction::Ccmn {
                        rn,
                        rm: Operand::Immediate(imm),
                        nzcv,
                        cond,
                    });
                }
            }
        }
    }

    // Issue #60: ExtendedRegister CMP/CMN candidates. These instructions
    // have no destination register, so emitting them per-rd (as the
    // shifted-register block above does) produced N identical copies per
    // (rn, rm, kind, shift) tuple (codex P2 on #144). Generate once per
    // unique (rn, rm, kind, shift) instead.
    {
        use crate::ir::ExtendKind;
        for &rn in registers {
            for &rm in registers {
                for kind in [
                    ExtendKind::Uxtb,
                    ExtendKind::Uxth,
                    ExtendKind::Uxtw,
                    ExtendKind::Uxtx,
                    ExtendKind::Sxtb,
                    ExtendKind::Sxth,
                    ExtendKind::Sxtw,
                    ExtendKind::Sxtx,
                ] {
                    for shift in 0u8..=4 {
                        let er = Operand::ExtendedRegister {
                            reg: rm,
                            kind,
                            shift,
                        };
                        instrs.push(Instruction::Cmp { rn, rm: er });
                        instrs.push(Instruction::Cmn { rn, rm: er });
                    }
                }
            }
        }
    }

    // Bit-field manipulation (UBFX/SBFX/BFI/BFXIL/UBFIZ/SBFIZ): sparse
    // (lsb, width) samples to keep the enumerative budget bounded. With
    // 31 non-SP registers × 31 rn × ~24 valid (lsb,width) pairs × 6 variants
    // ≈ 138k additional candidates, comparable to the CCMP/CCMN budget.
    const BITFIELD_LSB_SAMPLES: [u8; 5] = [0, 1, 16, 32, 63];
    const BITFIELD_WIDTH_SAMPLES: [u8; 6] = [1, 4, 8, 16, 32, 64];
    for &rd in registers {
        if rd == Register::SP {
            continue;
        }
        for &rn in registers {
            if rn == Register::SP {
                continue;
            }
            for &lsb in &BITFIELD_LSB_SAMPLES {
                for &width in &BITFIELD_WIDTH_SAMPLES {
                    if (lsb as u16 + width as u16) > 64 {
                        continue;
                    }
                    instrs.push(Instruction::Ubfx { rd, rn, lsb, width });
                    instrs.push(Instruction::Sbfx { rd, rn, lsb, width });
                    instrs.push(Instruction::Bfi { rd, rn, lsb, width });
                    instrs.push(Instruction::Bfxil { rd, rn, lsb, width });
                    instrs.push(Instruction::Ubfiz { rd, rn, lsb, width });
                    instrs.push(Instruction::Sbfiz { rd, rn, lsb, width });
                }
            }
        }
    }

    instrs
}

/// Generate a random instruction using the given registers and immediates
pub fn generate_random_instruction<R: rand::RngExt>(
    rng: &mut R,
    registers: &[Register],
    immediates: &[i64],
) -> Instruction {
    if registers.is_empty() {
        return Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        };
    }

    let rd = registers[rng.random_range(0..registers.len())];
    let pick_reg = |rng: &mut R| registers[rng.random_range(0..registers.len())];

    match rng.random_range(0..31) {
        0 => {
            let imm = if immediates.is_empty() {
                0
            } else {
                immediates[rng.random_range(0..immediates.len())]
            };
            Instruction::MovImm { rd, imm }
        }
        1 => Instruction::MovReg {
            rd,
            rn: pick_reg(rng),
        },
        2 => {
            let rn = pick_reg(rng);
            let rm = random_operand(rng, registers, immediates);
            Instruction::Add { rd, rn, rm }
        }
        3 => {
            let rn = pick_reg(rng);
            let rm = random_operand(rng, registers, immediates);
            Instruction::Sub { rd, rn, rm }
        }
        // AND / ORR / EOR are deliberately register-only here. AArch64's
        // bitmask-immediate encoding for these is not supported by the
        // assembler — the `Instruction::And { rm: Operand::Immediate(_) }`
        // arm in `src/assembler/mod.rs` returns
        // `Err("AND immediate encoding not yet supported")` (and likewise
        // for ORR/EOR), so any `Operand::Immediate` candidate would be
        // silently rejected at encoding time. Picking only register-form
        // here keeps the stochastic search emitting candidates the encoder
        // actually accepts.
        4 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::And { rd, rn, rm }
        }
        5 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Orr { rd, rn, rm }
        }
        6 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Eor { rd, rn, rm }
        }
        7 => {
            let rn = pick_reg(rng);
            let shift = random_shift_operand(rng, registers);
            Instruction::Lsl { rd, rn, shift }
        }
        8 => {
            let rn = pick_reg(rng);
            let shift = random_shift_operand(rng, registers);
            Instruction::Lsr { rd, rn, shift }
        }
        9 => {
            let rn = pick_reg(rng);
            let shift = random_shift_operand(rng, registers);
            Instruction::Asr { rd, rn, shift }
        }
        // New: unary / inverted-logical / flag-setting / cond-set / ror
        10 => Instruction::Mvn {
            rd,
            rm: pick_reg(rng),
        },
        11 => Instruction::Neg {
            rd,
            rm: pick_reg(rng),
        },
        12 => Instruction::Negs {
            rd,
            rm: pick_reg(rng),
        },
        13 => {
            let imm = (rng.random::<u32>() & 0xFFFF) as u16;
            let shifts = MOVW_LEGAL_SHIFTS;
            let shift = shifts[rng.random_range(0..shifts.len())];
            Instruction::MovN { rd, imm, shift }
        }
        14 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Bic { rd, rn, rm }
        }
        15 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Bics { rd, rn, rm }
        }
        16 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Orn { rd, rn, rm }
        }
        17 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Eon { rd, rn, rm }
        }
        18 => {
            let rn = pick_reg(rng);
            let rm = random_operand(rng, registers, immediates);
            Instruction::Adds { rd, rn, rm }
        }
        19 => {
            let rn = pick_reg(rng);
            let rm = random_operand(rng, registers, immediates);
            Instruction::Subs { rd, rn, rm }
        }
        20 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Ands { rd, rn, rm }
        }
        21 => Instruction::Cset {
            rd,
            cond: crate::ir::types::Condition::random_normal(rng),
        },
        22 => Instruction::Csetm {
            rd,
            cond: crate::ir::types::Condition::random_normal(rng),
        },
        23 => {
            let rn = pick_reg(rng);
            let shift = random_shift_operand(rng, registers);
            Instruction::Ror { rd, rn, shift }
        }
        24 => {
            let imm = (rng.random::<u32>() & 0xFFFF) as u16;
            let shifts = MOVW_LEGAL_SHIFTS;
            let shift = shifts[rng.random_range(0..shifts.len())];
            Instruction::MovZ { rd, imm, shift }
        }
        25 => {
            let imm = (rng.random::<u32>() & 0xFFFF) as u16;
            let shifts = MOVW_LEGAL_SHIFTS;
            let shift = shifts[rng.random_range(0..shifts.len())];
            Instruction::MovK { rd, imm, shift }
        }
        // Single-source bit-manipulation: CLZ / CLS / RBIT / REV / REV32 / REV16.
        26 => {
            let rn = pick_reg(rng);
            match rng.random_range(0..6) {
                0 => Instruction::Clz { rd, rn },
                1 => Instruction::Cls { rd, rn },
                2 => Instruction::Rbit { rd, rn },
                3 => Instruction::Rev { rd, rn },
                4 => Instruction::Rev32 { rd, rn },
                _ => Instruction::Rev16 { rd, rn },
            }
        }
        // CCMP / CCMN: conditional compare. The dispatch picks Ccmp or Ccmn
        // uniformly; the rm operand is sampled via random_operand and then
        // clamped/coerced to a valid 5-bit immediate if it lands on the
        // immediate side. nzcv is a 4-bit literal; cond from NORMAL_CONDITIONS.
        27 => {
            // CCMP/CCMN forbid SP in `rn` and in the register form of `rm`
            // (encoded in the Xn slot, not XSP). `generate_all_instructions`
            // filters SP at enumeration time; mirror that here so the
            // mutator does not bleed avoidable is_encodable_aarch64
            // rejections. The debug_assert guards against a degenerate
            // `registers = [SP]` caller, which would otherwise spin
            // forever in the retry loop below.
            debug_assert!(
                registers.iter().any(|r| *r != Register::SP),
                "CCMP/CCMN random generator requires at least one non-SP register",
            );
            let pick_non_sp = |rng: &mut R| loop {
                let r = pick_reg(rng);
                if r != Register::SP {
                    break r;
                }
            };
            let rn = pick_non_sp(rng);
            let rm = match random_operand(rng, registers, immediates) {
                Operand::Register(r) if r == Register::SP => Operand::Register(pick_non_sp(rng)),
                Operand::Register(r) => Operand::Register(r),
                Operand::Immediate(v) => Operand::Immediate(v.rem_euclid(32)),
                // random_operand only returns Register/Immediate, but the
                // compiler can't prove that — drop ShiftedRegister/Extended-
                // Register to a plain register (CCMP rejects both forms).
                Operand::ShiftedRegister { reg, .. } | Operand::ExtendedRegister { reg, .. } => {
                    Operand::Register(reg)
                }
            };
            let nzcv = (rng.random::<u32>() & 0x0F) as u8;
            let cond = crate::ir::types::Condition::random_normal(rng);
            if rng.random_bool(0.5) {
                Instruction::Ccmp { rn, rm, nzcv, cond }
            } else {
                Instruction::Ccmn { rn, rm, nzcv, cond }
            }
        }
        // Bit-field manipulation (UBFX/SBFX/BFI/BFXIL/UBFIZ/SBFIZ).
        // SP rejected in rd and rn (matches `generate_all_instructions` and
        // `is_encodable_aarch64`); 2D constraint on (lsb, width) enforced by
        // sampling width AFTER lsb so width is bounded by `64-lsb`.
        28 => {
            debug_assert!(
                registers.iter().any(|r| *r != Register::SP),
                "bit-field random generator requires at least one non-SP register",
            );
            let pick_non_sp = |rng: &mut R| loop {
                let r = pick_reg(rng);
                if r != Register::SP {
                    break r;
                }
            };
            let rd_local = pick_non_sp(rng);
            let rn = pick_non_sp(rng);
            let lsb = (rng.random::<u32>() & 0x3F) as u8;
            let max_w = 64 - lsb as u32;
            let width = ((rng.random::<u32>() % max_w) + 1) as u8;
            match rng.random_range(0..6) {
                0 => Instruction::Ubfx {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                },
                1 => Instruction::Sbfx {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                },
                2 => Instruction::Bfi {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                },
                3 => Instruction::Bfxil {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                },
                4 => Instruction::Ubfiz {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                },
                _ => Instruction::Sbfiz {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                },
            }
        }
        // Multiply-accumulate family: MADD/MSUB (4-operand) and MNEG/SMULH/UMULH (3-operand).
        _ => {
            let rn = pick_reg(rng);
            let rm = pick_reg(rng);
            match rng.random_range(0..5) {
                0 => {
                    let ra = pick_reg(rng);
                    Instruction::Madd { rd, rn, rm, ra }
                }
                1 => {
                    let ra = pick_reg(rng);
                    Instruction::Msub { rd, rn, rm, ra }
                }
                2 => Instruction::Mneg { rd, rn, rm },
                3 => Instruction::Smulh { rd, rn, rm },
                _ => Instruction::Umulh { rd, rn, rm },
            }
        }
    }
}

fn random_operand<R: rand::RngExt>(
    rng: &mut R,
    registers: &[Register],
    immediates: &[i64],
) -> Operand {
    if rng.random_bool(0.5) && !registers.is_empty() {
        Operand::Register(registers[rng.random_range(0..registers.len())])
    } else if !immediates.is_empty() {
        Operand::Immediate(immediates[rng.random_range(0..immediates.len())])
    } else if !registers.is_empty() {
        Operand::Register(registers[rng.random_range(0..registers.len())])
    } else {
        Operand::Immediate(0)
    }
}

fn random_shift_operand<R: rand::RngExt>(rng: &mut R, registers: &[Register]) -> Operand {
    if rng.random_bool(0.7) {
        // Prefer immediate shifts
        let shifts = [0, 1, 2, 4, 8, 16, 32];
        Operand::Immediate(shifts[rng.random_range(0..shifts.len())])
    } else if !registers.is_empty() {
        Operand::Register(registers[rng.random_range(0..registers.len())])
    } else {
        Operand::Immediate(1)
    }
}

/// Generate a random sequence of instructions
pub fn generate_random_sequence<R: rand::RngExt>(
    rng: &mut R,
    length: usize,
    registers: &[Register],
    immediates: &[i64],
) -> Vec<Instruction> {
    (0..length)
        .map(|_| generate_random_instruction(rng, registers, immediates))
        .collect()
}

/// Get the opcode type as a numeric identifier (for mutation)
#[allow(dead_code)]
pub fn opcode_id(instr: &Instruction) -> u8 {
    match instr {
        Instruction::MovReg { .. } => 0,
        Instruction::MovImm { .. } => 1,
        Instruction::Add { .. } => 2,
        Instruction::Sub { .. } => 3,
        Instruction::And { .. } => 4,
        Instruction::Orr { .. } => 5,
        Instruction::Eor { .. } => 6,
        Instruction::Lsl { .. } => 7,
        Instruction::Lsr { .. } => 8,
        Instruction::Asr { .. } => 9,
        Instruction::Mul { .. } => 10,
        Instruction::Sdiv { .. } => 11,
        Instruction::Udiv { .. } => 12,
        Instruction::Cmp { .. } => 13,
        Instruction::Cmn { .. } => 14,
        Instruction::Tst { .. } => 15,
        Instruction::Csel { .. } => 16,
        Instruction::Csinc { .. } => 17,
        Instruction::Csinv { .. } => 18,
        Instruction::Csneg { .. } => 19,
        Instruction::Mvn { .. } => 20,
        Instruction::Neg { .. } => 21,
        Instruction::Negs { .. } => 22,
        Instruction::MovN { .. } => 23,
        Instruction::Bic { .. } => 24,
        Instruction::Bics { .. } => 25,
        Instruction::Orn { .. } => 26,
        Instruction::Eon { .. } => 27,
        Instruction::Adds { .. } => 28,
        Instruction::Subs { .. } => 29,
        Instruction::Ands { .. } => 30,
        Instruction::Cset { .. } => 31,
        Instruction::Csetm { .. } => 32,
        Instruction::Ror { .. } => 33,
        Instruction::MovZ { .. } => 34,
        Instruction::MovK { .. } => 35,
        Instruction::Clz { .. } => 36,
        Instruction::Cls { .. } => 37,
        Instruction::Rbit { .. } => 38,
        Instruction::Rev { .. } => 39,
        Instruction::Rev32 { .. } => 40,
        Instruction::Rev16 { .. } => 41,
        Instruction::Madd { .. } => 42,
        Instruction::Msub { .. } => 43,
        Instruction::Mneg { .. } => 44,
        Instruction::Smulh { .. } => 45,
        Instruction::Umulh { .. } => 46,
        Instruction::Ccmp { .. } => 47,
        Instruction::Ccmn { .. } => 48,
        Instruction::Sxtb { .. } => 49,
        Instruction::Sxth { .. } => 50,
        Instruction::Sxtw { .. } => 51,
        Instruction::Uxtb { .. } => 52,
        Instruction::Uxth { .. } => 53,
        Instruction::Ubfx { .. } => 49,
        Instruction::Sbfx { .. } => 50,
        Instruction::Bfi { .. } => 51,
        Instruction::Bfxil { .. } => 52,
        Instruction::Ubfiz { .. } => 53,
        Instruction::Sbfiz { .. } => 54,
        // Branches / terminators (issue #69)
        Instruction::B { .. } => 55,
        Instruction::BCond { .. } => 56,
        Instruction::Ret { .. } => 57,
        Instruction::Cbz { .. } => 58,
        Instruction::Cbnz { .. } => 59,
        Instruction::Tbz { .. } => 60,
        Instruction::Tbnz { .. } => 61,
        Instruction::Bl { .. } => 62,
        Instruction::Br { .. } => 63,
    }
}

/// Check if an instruction has immediate operand support
#[allow(dead_code)]
pub fn supports_immediate(instr: &Instruction) -> bool {
    matches!(
        instr,
        Instruction::MovImm { .. }
            | Instruction::Add { .. }
            | Instruction::Sub { .. }
            | Instruction::And { .. }
            | Instruction::Orr { .. }
            | Instruction::Eor { .. }
            | Instruction::Lsl { .. }
            | Instruction::Lsr { .. }
            | Instruction::Asr { .. }
            | Instruction::MovN { .. }
            | Instruction::MovZ { .. }
            | Instruction::MovK { .. }
            | Instruction::Adds { .. }
            | Instruction::Subs { .. }
            | Instruction::Ror { .. }
    )
}

/// Check if an instruction is a binary operation (has rd, rn, rm)
#[allow(dead_code)]
pub fn is_binary_op(instr: &Instruction) -> bool {
    matches!(
        instr,
        Instruction::Add { .. }
            | Instruction::Sub { .. }
            | Instruction::And { .. }
            | Instruction::Orr { .. }
            | Instruction::Eor { .. }
            | Instruction::Bic { .. }
            | Instruction::Bics { .. }
            | Instruction::Orn { .. }
            | Instruction::Eon { .. }
            | Instruction::Adds { .. }
            | Instruction::Subs { .. }
            | Instruction::Ands { .. }
    )
}

/// Check if an instruction is a shift operation
#[allow(dead_code)]
pub fn is_shift_op(instr: &Instruction) -> bool {
    matches!(
        instr,
        Instruction::Lsl { .. }
            | Instruction::Lsr { .. }
            | Instruction::Asr { .. }
            | Instruction::Ror { .. }
    )
}

/// Check if an instruction is a move operation
#[allow(dead_code)]
pub fn is_move_op(instr: &Instruction) -> bool {
    matches!(
        instr,
        Instruction::MovReg { .. }
            | Instruction::MovImm { .. }
            | Instruction::MovN { .. }
            | Instruction::MovZ { .. }
            | Instruction::MovK { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_registers() -> Vec<Register> {
        vec![Register::X0, Register::X1, Register::X2]
    }

    fn default_immediates() -> Vec<i64> {
        vec![-1, 0, 1, 2]
    }

    #[test]
    fn test_generate_all_instructions_not_empty() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        assert!(!instrs.is_empty());
    }

    #[test]
    fn test_generate_all_instructions_contains_mov_imm() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        let has_mov_imm = instrs
            .iter()
            .any(|i| matches!(i, Instruction::MovImm { .. }));
        assert!(has_mov_imm);
    }

    #[test]
    fn test_generate_all_instructions_contains_add() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        let has_add = instrs.iter().any(|i| matches!(i, Instruction::Add { .. }));
        assert!(has_add);
    }

    #[test]
    fn test_generate_all_instructions_contains_eor() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        let has_eor = instrs.iter().any(|i| matches!(i, Instruction::Eor { .. }));
        assert!(has_eor);
    }

    #[test]
    fn test_generate_all_instructions_contains_shifted_register_add() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        let has_shifted_add = instrs.iter().any(|i| {
            matches!(
                i,
                Instruction::Add {
                    rm: Operand::ShiftedRegister { .. },
                    ..
                }
            )
        });
        assert!(
            has_shifted_add,
            "enumerate must include Add with ShiftedRegister rm"
        );
    }

    #[test]
    fn test_generate_all_instructions_includes_all_shifted_kinds_for_logical() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        for kind in [
            crate::ir::ShiftKind::Lsl,
            crate::ir::ShiftKind::Lsr,
            crate::ir::ShiftKind::Asr,
            crate::ir::ShiftKind::Ror,
        ] {
            let has = instrs.iter().any(|i| {
                matches!(
                    i,
                    Instruction::Orr {
                        rm: Operand::ShiftedRegister { kind: k, .. }, ..
                    } if *k == kind
                )
            });
            assert!(
                has,
                "ORR must enumerate shifted-register form with {:?}",
                kind
            );
        }
    }

    #[test]
    fn test_generate_all_instructions_arith_excludes_ror() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        let any_arith_ror = instrs.iter().any(|i| {
            matches!(
                i,
                Instruction::Add {
                    rm: Operand::ShiftedRegister {
                        kind: crate::ir::ShiftKind::Ror,
                        ..
                    },
                    ..
                } | Instruction::Sub {
                    rm: Operand::ShiftedRegister {
                        kind: crate::ir::ShiftKind::Ror,
                        ..
                    },
                    ..
                }
            )
        });
        assert!(
            !any_arith_ror,
            "Add/Sub must NOT enumerate ROR shifted form (ROR is logical-only)"
        );
    }

    #[test]
    fn test_generate_random_instruction() {
        let mut rng = rand::rng();
        let regs = default_registers();
        let imms = default_immediates();

        for _ in 0..100 {
            let instr = generate_random_instruction(&mut rng, &regs, &imms);
            if let Some(dest) = instr.destination() {
                assert!(regs.contains(&dest));
            }
        }
    }

    #[test]
    fn test_generate_random_instruction_emits_bitfield_eventually() {
        let mut rng = rand::rng();
        let regs = default_registers();
        let imms = default_immediates();

        // Random generator picks among many cases; over 5000 trials it must
        // produce at least one bit-field instruction. Also: every random
        // bit-field must be encodable.
        let mut seen_bitfield = false;
        for _ in 0..5000 {
            let instr = generate_random_instruction(&mut rng, &regs, &imms);
            if matches!(
                &instr,
                Instruction::Ubfx { .. }
                    | Instruction::Sbfx { .. }
                    | Instruction::Bfi { .. }
                    | Instruction::Bfxil { .. }
                    | Instruction::Ubfiz { .. }
                    | Instruction::Sbfiz { .. }
            ) {
                seen_bitfield = true;
                assert!(
                    instr.is_encodable_aarch64(),
                    "random bit-field must be encodable: {}",
                    instr
                );
            }
        }
        assert!(
            seen_bitfield,
            "random generator must emit at least one bit-field instruction in 5000 trials"
        );
    }

    #[test]
    fn candidate_pool_excludes_terminators() {
        // Issue #69: branches are terminators and must NEVER appear in the
        // rewritable candidate pool. The enumerative and random generators
        // are the two pool sources for search; both must stay terminator-free.
        let regs = default_registers();
        let imms = default_immediates();

        let pool = generate_all_instructions(&regs, &imms);
        assert!(
            pool.iter().all(|i| !i.is_terminator()),
            "generate_all_instructions must not emit terminators"
        );

        let mut rng = rand::rng();
        for _ in 0..1000 {
            let instr = generate_random_instruction(&mut rng, &regs, &imms);
            assert!(
                !instr.is_terminator(),
                "generate_random_instruction emitted a terminator: {:?}",
                instr
            );
        }
    }

    #[test]
    fn test_generate_random_sequence() {
        let mut rng = rand::rng();
        let regs = default_registers();
        let imms = default_immediates();

        let seq = generate_random_sequence(&mut rng, 5, &regs, &imms);
        assert_eq!(seq.len(), 5);
    }

    #[test]
    fn test_opcode_id_unique() {
        let instrs = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
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
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(0),
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(0),
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(0),
            },
        ];

        let ids: Vec<_> = instrs.iter().map(opcode_id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    /// Sync test: opcode_id in candidate.rs must agree with
    /// AArch64InstructionInfo::opcode_id in isa/aarch64.rs for every bitfield
    /// variant. Catches drift between the two definitions.
    #[test]
    fn test_bitfield_opcode_id_matches_isa_backend() {
        use crate::isa::InstructionType;
        let instrs = vec![
            Instruction::Ubfx {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
            },
            Instruction::Sbfx {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
            },
            Instruction::Bfi {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
            },
            Instruction::Bfxil {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
            },
            Instruction::Ubfiz {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
            },
            Instruction::Sbfiz {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
            },
        ];
        for instr in &instrs {
            assert_eq!(
                opcode_id(instr),
                instr.opcode_id(),
                "opcode_id drift for {}",
                instr
            );
        }
    }

    #[test]
    fn test_generate_all_instructions_includes_bitfield() {
        let registers = vec![Register::X0, Register::X1];
        let immediates = vec![0];
        let all = generate_all_instructions(&registers, &immediates);
        assert!(
            all.iter().any(|i| matches!(i, Instruction::Ubfx { .. })),
            "enumerative output must contain at least one Ubfx"
        );
        assert!(
            all.iter().any(|i| matches!(i, Instruction::Sbfx { .. })),
            "enumerative output must contain at least one Sbfx"
        );
        assert!(
            all.iter().any(|i| matches!(i, Instruction::Bfi { .. })),
            "enumerative output must contain at least one Bfi"
        );
        assert!(
            all.iter().any(|i| matches!(i, Instruction::Bfxil { .. })),
            "enumerative output must contain at least one Bfxil"
        );
        assert!(
            all.iter().any(|i| matches!(i, Instruction::Ubfiz { .. })),
            "enumerative output must contain at least one Ubfiz"
        );
        assert!(
            all.iter().any(|i| matches!(i, Instruction::Sbfiz { .. })),
            "enumerative output must contain at least one Sbfiz"
        );

        // Every generated bitfield instruction must satisfy is_encodable_aarch64.
        for instr in all.iter().filter(|i| {
            matches!(
                i,
                Instruction::Ubfx { .. }
                    | Instruction::Sbfx { .. }
                    | Instruction::Bfi { .. }
                    | Instruction::Bfxil { .. }
                    | Instruction::Ubfiz { .. }
                    | Instruction::Sbfiz { .. }
            )
        }) {
            assert!(
                instr.is_encodable_aarch64(),
                "enumerative produced un-encodable: {}",
                instr
            );
        }
    }

    #[test]
    fn test_is_binary_op() {
        assert!(is_binary_op(&Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0),
        }));
        assert!(!is_binary_op(&Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }));
    }

    #[test]
    fn test_is_shift_op() {
        assert!(is_shift_op(&Instruction::Lsl {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(1),
        }));
        assert!(!is_shift_op(&Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0),
        }));
    }

    #[test]
    fn test_is_move_op() {
        assert!(is_move_op(&Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }));
        assert!(is_move_op(&Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }));
        assert!(!is_move_op(&Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0),
        }));
    }

    #[test]
    fn enumerate_emits_uxtb_for_each_register_pair() {
        // Issue #60: every (rd, rn) pair in the pool must produce a
        // candidate Instruction::Uxtb { rd, rn }, mirroring the existing
        // single-source bit-manipulation enumeration block.
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![];
        let candidates = generate_all_instructions(&regs, &imms);
        for &rd in &regs {
            for &rn in &regs {
                let expected = Instruction::Uxtb { rd, rn };
                assert!(
                    candidates.contains(&expected),
                    "enumeration missing {}",
                    expected
                );
            }
        }
    }

    #[test]
    fn enumerate_emits_add_with_extended_register() {
        // Issue #60: the enumerator must emit at least one
        // ADD candidate per (rd, rn, rm, kind, shift) tuple with the
        // extended-register operand form, so the search can discover the
        // collapse pattern UXTB+ADD ≡ ADD,UXTB.
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![];
        let candidates = generate_all_instructions(&regs, &imms);
        let has_uxtb = candidates.iter().any(|c| {
            matches!(
                c,
                Instruction::Add {
                    rm: Operand::ExtendedRegister {
                        kind: crate::ir::ExtendKind::Uxtb,
                        shift: 0,
                        ..
                    },
                    ..
                }
            )
        });
        assert!(has_uxtb, "enumeration missing ADD with UXTB extended-reg");
    }

    #[test]
    fn enumerate_emits_cmp_with_extended_register() {
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![];
        let candidates = generate_all_instructions(&regs, &imms);
        let has_sxth = candidates.iter().any(|c| {
            matches!(
                c,
                Instruction::Cmp {
                    rm: Operand::ExtendedRegister {
                        kind: crate::ir::ExtendKind::Sxth,
                        ..
                    },
                    ..
                }
            )
        });
        assert!(has_sxth, "enumeration missing CMP with SXTH extended-reg");
    }

    #[test]
    fn enumerate_does_not_duplicate_extended_register_cmp_cmn() {
        // Issue #60 follow-up (codex P2 on #144): CMP/CMN have no destination
        // register, so the per-rd loop used to emit each
        // `cmp rn, rm, <extend> #shift` candidate N times for an N-register
        // pool. The fix moves CMP/CMN out of the rd loop; each unique
        // (rn, rm, kind, shift) tuple now appears exactly once.
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![];
        let candidates = generate_all_instructions(&regs, &imms);
        let count_cmp_uxtb_x1_x2_shift0 = candidates
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    Instruction::Cmp {
                        rn: Register::X1,
                        rm: Operand::ExtendedRegister {
                            reg: Register::X2,
                            kind: crate::ir::ExtendKind::Uxtb,
                            shift: 0,
                        },
                    }
                )
            })
            .count();
        assert_eq!(
            count_cmp_uxtb_x1_x2_shift0, 1,
            "CMP X1, X2, UXTB #0 must appear exactly once (got {})",
            count_cmp_uxtb_x1_x2_shift0
        );
    }

    #[test]
    fn enumerate_emits_sxtw_for_each_register_pair() {
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![];
        let candidates = generate_all_instructions(&regs, &imms);
        for &rd in &regs {
            for &rn in &regs {
                let expected = Instruction::Sxtw { rd, rn };
                assert!(
                    candidates.contains(&expected),
                    "enumeration missing {}",
                    expected
                );
            }
        }
    }

    #[test]
    fn enumerate_emits_sxth_for_each_register_pair() {
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![];
        let candidates = generate_all_instructions(&regs, &imms);
        for &rd in &regs {
            for &rn in &regs {
                let expected = Instruction::Sxth { rd, rn };
                assert!(
                    candidates.contains(&expected),
                    "enumeration missing {}",
                    expected
                );
            }
        }
    }

    #[test]
    fn enumerate_emits_uxth_for_each_register_pair() {
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![];
        let candidates = generate_all_instructions(&regs, &imms);
        for &rd in &regs {
            for &rn in &regs {
                let expected = Instruction::Uxth { rd, rn };
                assert!(
                    candidates.contains(&expected),
                    "enumeration missing {}",
                    expected
                );
            }
        }
    }

    #[test]
    fn enumerate_emits_sxtb_for_each_register_pair() {
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![];
        let candidates = generate_all_instructions(&regs, &imms);
        for &rd in &regs {
            for &rn in &regs {
                let expected = Instruction::Sxtb { rd, rn };
                assert!(
                    candidates.contains(&expected),
                    "enumeration missing {}",
                    expected
                );
            }
        }
    }
}
