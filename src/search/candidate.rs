//! Instruction generation utilities for search algorithms

use crate::ir::instructions::{AARCH64_RANDOM_SHIFT_IMMEDIATES, MOVW_LEGAL_SHIFTS};
use crate::ir::{Instruction, Operand, Register, RegisterWidth, ShiftKind};
use crate::isa::{AArch64, Assembler, InstructionType};

/// Generic encodability check: for any `<I: InstructionType, A: Assembler<I>>`,
/// returns true iff every instruction passes `A::can_assemble`.
///
/// Added in #77 stage 1 step 11 as the canonical generic helper so x86 (stage
/// 2 step 17) and RISC-V (stage 3 step 23) reuse the same shape. Today the
/// only consumer is the AArch64 thin wrapper `is_sequence_encodable` below.
pub fn is_sequence_encodable_for<I: InstructionType, A: Assembler<I>>(
    sequence: &[I],
    assembler: &A,
) -> bool {
    sequence.iter().all(|instr| assembler.can_assemble(instr))
}

/// Check if all instructions in a sequence can be encoded in AArch64 machine
/// code. Routes through the generic `is_sequence_encodable_for` helper with
/// the AArch64 marker (step 8's `Assembler::can_assemble` bridges
/// `Instruction::is_encodable_aarch64()`).
pub fn is_sequence_encodable(sequence: &[Instruction]) -> bool {
    is_sequence_encodable_for(sequence, &AArch64)
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
const TST_LOGICAL_IMM64_SAMPLES: &[i64] = &[0xff, 0xffff, 0x5555_5555_5555_5555, i64::MIN];

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
            instrs.push(Instruction::MovRegW { rd, rn });
        }

        // Binary operations with register second operand
        for &rn in registers {
            for &rm in registers {
                let rm_op = Operand::Register(rm);

                instrs.push(Instruction::Add { rd, rn, rm: rm_op });
                instrs.push(Instruction::AddW { rd, rn, rm: rm_op });
                instrs.push(Instruction::Sub { rd, rn, rm: rm_op });
                instrs.push(Instruction::SubW { rd, rn, rm: rm_op });
                instrs.push(Instruction::And {
                    rd,
                    rn,
                    rm: rm_op,
                    width: RegisterWidth::X64,
                });
                instrs.push(Instruction::Orr {
                    rd,
                    rn,
                    rm: rm_op,
                    width: RegisterWidth::X64,
                });
                instrs.push(Instruction::Eor {
                    rd,
                    rn,
                    rm: rm_op,
                    width: RegisterWidth::X64,
                });
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
                instrs.push(Instruction::AddW { rd, rn, rm: imm_op });
                instrs.push(Instruction::Sub { rd, rn, rm: imm_op });
                instrs.push(Instruction::SubW { rd, rn, rm: imm_op });
                instrs.push(Instruction::And {
                    rd,
                    rn,
                    rm: imm_op,
                    width: RegisterWidth::X64,
                });
                instrs.push(Instruction::Orr {
                    rd,
                    rn,
                    rm: imm_op,
                    width: RegisterWidth::X64,
                });
                instrs.push(Instruction::Eor {
                    rd,
                    rn,
                    rm: imm_op,
                    width: RegisterWidth::X64,
                });
            }

            // Shifted-register form (issue #59):
            //   Add/Sub: LSL/LSR/ASR (no ROR)
            //   And/Orr/Eor: LSL/LSR/ASR/ROR
            // AArch64 shifted-register encodings cannot use SP in rd/rn/rm, so
            // hoist the rd/rn filter while keeping rm filtered per tuple.
            use crate::ir::ShiftKind;
            let shifted_register_allows_rd_rn = rd != Register::SP && rn != Register::SP;
            for &rm in registers {
                if shifted_register_allows_rd_rn && rm != Register::SP {
                    for &amount in SHIFTED_OP_AMOUNTS {
                        for kind in [ShiftKind::Lsl, ShiftKind::Lsr, ShiftKind::Asr] {
                            let sr = Operand::ShiftedRegister {
                                reg: rm,
                                kind,
                                amount,
                            };
                            instrs.push(Instruction::Add { rd, rn, rm: sr });
                            if amount <= 31 {
                                instrs.push(Instruction::AddW { rd, rn, rm: sr });
                            }
                            instrs.push(Instruction::Sub { rd, rn, rm: sr });
                            if amount <= 31 {
                                instrs.push(Instruction::SubW { rd, rn, rm: sr });
                            }
                            instrs.push(Instruction::And {
                                rd,
                                rn,
                                rm: sr,
                                width: RegisterWidth::X64,
                            });
                            instrs.push(Instruction::Orr {
                                rd,
                                rn,
                                rm: sr,
                                width: RegisterWidth::X64,
                            });
                            instrs.push(Instruction::Eor {
                                rd,
                                rn,
                                rm: sr,
                                width: RegisterWidth::X64,
                            });
                        }
                        // ROR — logical only.
                        let sr_ror = Operand::ShiftedRegister {
                            reg: rm,
                            kind: ShiftKind::Ror,
                            amount,
                        };
                        instrs.push(Instruction::And {
                            rd,
                            rn,
                            rm: sr_ror,
                            width: RegisterWidth::X64,
                        });
                        instrs.push(Instruction::Orr {
                            rd,
                            rn,
                            rm: sr_ror,
                            width: RegisterWidth::X64,
                        });
                        instrs.push(Instruction::Eor {
                            rd,
                            rn,
                            rm: sr_ror,
                            width: RegisterWidth::X64,
                        });
                    }
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
                instrs.push(Instruction::Ands {
                    rd,
                    rn,
                    rm: rm_op,
                    width: RegisterWidth::X64,
                });
            }
            // ADDS / SUBS also accept the same 12-bit-class immediate table
            // ADD / SUB does — keep them in sync. ANDS accepts bitmask
            // immediates, but the curated 12-bit table here would mostly
            // miss-encode, so we omit it for enumerative parity with AND.
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

        // Multiply / divide (register-only; rm is `Register`, not `Operand`).
        // The closely-related multiply-accumulate family follows.
        for &rn in registers {
            for &rm in registers {
                instrs.push(Instruction::Mul { rd, rn, rm });
                instrs.push(Instruction::Sdiv { rd, rn, rm });
                instrs.push(Instruction::Udiv { rd, rn, rm });
            }
        }

        // Multiply-accumulate family. MADD/MSUB take a 4th register slot
        // (`ra`); MNEG/SMULH/UMULH are 3-operand register-only.
        // At the default 8-register scope this block emits
        // `2 * 8^4 + 3 * 8^3` = 9,728 candidates per length bucket; keep
        // docs/capability.md (and the README/TUTORIAL notes) in sync if the
        // instruction mix here changes.
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

        // CSEL / CSINC / CSINV / CSNEG (issue #66): register-only with a
        // 14-condition sweep matching CSET/CSETM. AL collapses to MOV rd,rn
        // and NV is reserved — both excluded by `NORMAL_CONDITIONS`.
        for &rn in registers {
            for &rm in registers {
                for cond in crate::ir::types::NORMAL_CONDITIONS {
                    instrs.push(Instruction::Csel { rd, rn, rm, cond });
                    instrs.push(Instruction::Csinc { rd, rn, rm, cond });
                    instrs.push(Instruction::Csinv { rd, rn, rm, cond });
                    instrs.push(Instruction::Csneg { rd, rn, rm, cond });
                }
            }
        }
    }

    // CCMP / CCMN: nested loops over register pairs × NORMAL_CONDITIONS ×
    // a representative nzcv subset × {register, imm5} for `rm`. Keep the
    // nzcv and imm5 samples bounded so the combined space stays around
    // ~120k candidates total — already inside the enumerative budget.
    const CCMP_NZCV_SAMPLES: [u8; 5] = [0, 1, 7, 8, 15];
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

    // CMP / CMN / TST plain forms (issue #66). These instructions have no
    // destination register, so they live outside the `rd` loop (same
    // rationale as the ExtendedRegister CMP/CMN block below). CMP/CMN
    // accept reg and imm operands; TST accepts reg and encodable bitmask
    // immediates. Negative/non-bitmask immediates are emitted unconditionally
    // and filtered downstream by `generate_all_encodable_instructions`,
    // matching the ADD/SUB precedent inside the `rd` loop.
    for &rn in registers {
        for &rm in registers {
            let rm_op = Operand::Register(rm);
            instrs.push(Instruction::Cmp { rn, rm: rm_op });
            instrs.push(Instruction::Cmn { rn, rm: rm_op });
            instrs.push(Instruction::Tst {
                rn,
                rm: rm_op,
                width: RegisterWidth::X64,
            });
        }
        for &imm in immediates {
            let imm_op = Operand::Immediate(imm);
            instrs.push(Instruction::Cmp { rn, rm: imm_op });
            instrs.push(Instruction::Cmn { rn, rm: imm_op });
            instrs.push(Instruction::Tst {
                rn,
                rm: imm_op,
                width: RegisterWidth::X64,
            });
        }
    }

    // Shifted-register CMP / CMN / TST candidates. These are destinationless
    // like the plain/extended compare forms above, so generate them once per
    // unique source tuple instead of once per `rd`. Arithmetic compares reject
    // ROR; TST follows the logical shifted-register encoding and accepts it.
    {
        use crate::ir::ShiftKind;
        for &rn in registers {
            if rn == Register::SP {
                continue;
            }
            for &rm in registers {
                if rm == Register::SP {
                    continue;
                }
                for &amount in SHIFTED_OP_AMOUNTS {
                    for kind in [ShiftKind::Lsl, ShiftKind::Lsr, ShiftKind::Asr] {
                        let sr = Operand::ShiftedRegister {
                            reg: rm,
                            kind,
                            amount,
                        };
                        instrs.push(Instruction::Cmp { rn, rm: sr });
                        instrs.push(Instruction::Cmn { rn, rm: sr });
                        instrs.push(Instruction::Tst {
                            rn,
                            rm: sr,
                            width: RegisterWidth::X64,
                        });
                    }
                    instrs.push(Instruction::Tst {
                        rn,
                        rm: Operand::ShiftedRegister {
                            reg: rm,
                            kind: ShiftKind::Ror,
                            amount,
                        },
                        width: RegisterWidth::X64,
                    });
                }
            }
        }
    }

    // Issue #60: ExtendedRegister CMP/CMN candidates. These instructions
    // have no destination register, so emitting them inside the per-rd binary
    // blocks produced N identical copies per (rn, rm, kind, shift) tuple
    // (codex P2 on #144). Generate once per unique tuple instead.
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

    // Memory ops (issue #68, step 15). Sparse enumeration covering the
    // common addressing modes for LDR/STR/LDP/STP. Width=Extended only
    // (W-form variants land via stochastic mutation in step 16) so the
    // candidate budget stays bounded — full width × addressing-mode ×
    // signed coverage would explode the pool by ~30x. See ADR-0007 for
    // the soundness argument; the SMT layer reasons over all widths
    // regardless of which forms search enumerates.
    {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode, PairAccessWidth};
        const MEM_IMM_SAMPLES: [i64; 5] = [0, 8, 16, 32, -8];
        for &rt in registers {
            if rt == Register::SP || rt == Register::XZR {
                continue;
            }
            for &base in registers {
                if base == Register::XZR {
                    continue;
                }
                // Imm + Offset
                for &offset in &MEM_IMM_SAMPLES {
                    let addr = AddressOperand::Imm {
                        base,
                        offset,
                        mode: IndexMode::Offset,
                    };
                    instrs.push(Instruction::Ldr {
                        rt,
                        addr,
                        width: AccessWidth::Extended,
                    });
                    instrs.push(Instruction::Str {
                        rt,
                        addr,
                        width: AccessWidth::Extended,
                    });
                }
                // Reg-offset, X-form index, LSL #0 and #3
                for &shift in &[0u8, 3] {
                    for &idx in registers {
                        if idx == Register::SP {
                            continue;
                        }
                        let addr = AddressOperand::Reg { base, idx, shift };
                        instrs.push(Instruction::Ldr {
                            rt,
                            addr,
                            width: AccessWidth::Extended,
                        });
                        instrs.push(Instruction::Str {
                            rt,
                            addr,
                            width: AccessWidth::Extended,
                        });
                    }
                }
            }
        }
        // Pair forms (LDP/STP) — exhaust (rt1, rt2, base) over a tiny offset
        // set. Constrain rt1 < rt2 numeric index to avoid duplicates; the
        // is_encodable_pair filter downstream still drops rt1==rt2.
        const MEM_PAIR_IMM_SAMPLES: [i64; 3] = [0, 16, -16];
        for &rt1 in registers {
            if rt1 == Register::SP || rt1 == Register::XZR {
                continue;
            }
            for &rt2 in registers {
                if rt2 == Register::SP || rt2 == Register::XZR || rt1 == rt2 {
                    continue;
                }
                for &base in registers {
                    if base == Register::XZR {
                        continue;
                    }
                    for &offset in &MEM_PAIR_IMM_SAMPLES {
                        let addr = AddressOperand::Imm {
                            base,
                            offset,
                            mode: IndexMode::Offset,
                        };
                        instrs.push(Instruction::Ldp {
                            rt1,
                            rt2,
                            addr,
                            width: PairAccessWidth::Extended,
                            signed: false,
                        });
                        instrs.push(Instruction::Stp {
                            rt1,
                            rt2,
                            addr,
                            width: PairAccessWidth::Extended,
                        });
                    }
                }
            }
        }
    }

    // Bit-field manipulation (UBFX/SBFX/BFI/BFXIL/UBFIZ/SBFIZ): sparse
    // (lsb, width) samples to keep the enumerative budget bounded, emitted for
    // both the X (64-bit) and W (32-bit) register forms. The shared sample
    // tables are filtered per width against the encodability bound
    // (lsb < bound, lsb+width <= bound), so the W form naturally drops lsb=32/63
    // and width=64. This roughly doubles the bit-field slice of the pool.
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
            for reg_width in [RegisterWidth::X64, RegisterWidth::W32] {
                let bound = reg_width.bit_width() as u16;
                for &lsb in &BITFIELD_LSB_SAMPLES {
                    if lsb as u16 >= bound {
                        continue;
                    }
                    for &width in &BITFIELD_WIDTH_SAMPLES {
                        if width as u16 > bound || (lsb as u16 + width as u16) > bound {
                            continue;
                        }
                        instrs.push(Instruction::Ubfx {
                            rd,
                            rn,
                            lsb,
                            width,
                            reg_width,
                        });
                        instrs.push(Instruction::Sbfx {
                            rd,
                            rn,
                            lsb,
                            width,
                            reg_width,
                        });
                        instrs.push(Instruction::Bfi {
                            rd,
                            rn,
                            lsb,
                            width,
                            reg_width,
                        });
                        instrs.push(Instruction::Bfxil {
                            rd,
                            rn,
                            lsb,
                            width,
                            reg_width,
                        });
                        instrs.push(Instruction::Ubfiz {
                            rd,
                            rn,
                            lsb,
                            width,
                            reg_width,
                        });
                        instrs.push(Instruction::Sbfiz {
                            rd,
                            rn,
                            lsb,
                            width,
                            reg_width,
                        });
                    }
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

    // See also `src/isa/aarch64.rs::AArch64InstructionGenerator::generate_random`:
    // this is a parallel 38-slot sampler, but its slot numbers differ
    // (notably, ROR is slot 37 there and slot 23 here).
    match rng.random_range(0..38) {
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
            let rm = random_arith_rm_operand(rng, registers, immediates);
            Instruction::Add { rd, rn, rm }
        }
        3 => {
            let rn = pick_reg(rng);
            let rm = random_arith_rm_operand(rng, registers, immediates);
            Instruction::Sub { rd, rn, rm }
        }
        // AND / ORR / EOR are deliberately register-only here. The assembler
        // now accepts encodable AArch64 bitmask immediates (issue #65), but
        // the generic `immediates` table passed in is a 12-bit-class set tuned
        // for ADD/SUB and would mostly miss the bitmask form — most picks
        // would round-trip through `is_encodable_aarch64` as `false` and burn
        // iterations. Wiring a curated bitmask-immediate table for these
        // opcodes is left to a follow-up; for now stochastic search keeps
        // emitting register-only AND/ORR/EOR candidates.
        4 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::And {
                rd,
                rn,
                rm,
                width: RegisterWidth::X64,
            }
        }
        5 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Orr {
                rd,
                rn,
                rm,
                width: RegisterWidth::X64,
            }
        }
        6 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Eor {
                rd,
                rn,
                rm,
                width: RegisterWidth::X64,
            }
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
            let rm = random_arith_rm_operand(rng, registers, immediates);
            Instruction::Adds { rd, rn, rm }
        }
        19 => {
            let rn = pick_reg(rng);
            let rm = random_arith_rm_operand(rng, registers, immediates);
            Instruction::Subs { rd, rn, rm }
        }
        20 => {
            let rn = pick_reg(rng);
            let rm = Operand::Register(pick_reg(rng));
            Instruction::Ands {
                rd,
                rn,
                rm,
                width: RegisterWidth::X64,
            }
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
        // Single-source bit-manipulation opcodes each keep a top-level slot
        // so stochastic search does not starve CLZ/RBIT/REV-shaped targets.
        26 => Instruction::Clz {
            rd,
            rn: pick_reg(rng),
        },
        27 => Instruction::Cls {
            rd,
            rn: pick_reg(rng),
        },
        28 => Instruction::Rbit {
            rd,
            rn: pick_reg(rng),
        },
        29 => Instruction::Rev {
            rd,
            rn: pick_reg(rng),
        },
        30 => Instruction::Rev32 {
            rd,
            rn: pick_reg(rng),
        },
        31 => Instruction::Rev16 {
            rd,
            rn: pick_reg(rng),
        },
        // CCMP / CCMN: conditional compare. The dispatch picks Ccmp or Ccmn
        // uniformly; the rm operand is sampled via random_operand and then
        // clamped/coerced to a valid 5-bit immediate if it lands on the
        // immediate side. nzcv is a 4-bit literal; cond from NORMAL_CONDITIONS.
        32 => {
            // CCMP/CCMN forbid SP in `rn` and in the register form of `rm`
            // (encoded in the Xn slot, not XSP). `generate_all_instructions`
            // filters SP at enumeration time; mirror that here so the
            // mutator does not bleed avoidable is_encodable_aarch64
            // rejections. Build a filtered pool up front so pathological
            // SP-only inputs fall back finitely instead of retrying forever.
            let non_sp: Vec<Register> = registers
                .iter()
                .copied()
                .filter(|r| *r != Register::SP)
                .collect();
            if non_sp.is_empty() {
                return Instruction::Mneg {
                    rd,
                    rn: pick_reg(rng),
                    rm: pick_reg(rng),
                };
            }
            let pick_non_sp = |rng: &mut R| non_sp[rng.random_range(0..non_sp.len())];
            let rn = pick_non_sp(rng);
            let rm = match random_operand(rng, registers, immediates) {
                Operand::Register(Register::SP) => Operand::Register(pick_non_sp(rng)),
                Operand::Register(r) => Operand::Register(r),
                Operand::Immediate(v) => Operand::Immediate(v.rem_euclid(32)),
                // random_operand only returns Register/Immediate, but the
                // compiler can't prove that — drop ShiftedRegister/Extended-
                // Register to a plain register (CCMP rejects both forms).
                Operand::ShiftedRegister { reg, .. } | Operand::ExtendedRegister { reg, .. }
                    if reg != Register::SP =>
                {
                    Operand::Register(reg)
                }
                Operand::ShiftedRegister { .. } | Operand::ExtendedRegister { .. } => {
                    Operand::Register(pick_non_sp(rng))
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
        // `is_encodable_aarch64`). The register width is picked first; the 2D
        // constraint on (lsb, width) is enforced relative to that width's bound
        // (32 for W, 64 for X) by sampling width AFTER lsb.
        33 => {
            let non_sp: Vec<Register> = registers
                .iter()
                .copied()
                .filter(|r| *r != Register::SP)
                .collect();
            if non_sp.is_empty() {
                return Instruction::Mneg {
                    rd,
                    rn: pick_reg(rng),
                    rm: pick_reg(rng),
                };
            }
            let pick_non_sp = |rng: &mut R| non_sp[rng.random_range(0..non_sp.len())];
            let rd_local = pick_non_sp(rng);
            let rn = pick_non_sp(rng);
            let reg_width = if rng.random_bool(0.5) {
                RegisterWidth::W32
            } else {
                RegisterWidth::X64
            };
            let bound = reg_width.bit_width() as u32;
            let lsb = (rng.random::<u32>() % bound) as u8;
            let max_w = bound - lsb as u32;
            let width = ((rng.random::<u32>() % max_w) + 1) as u8;
            match rng.random_range(0..6) {
                0 => Instruction::Ubfx {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                1 => Instruction::Sbfx {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                2 => Instruction::Bfi {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                3 => Instruction::Bfxil {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                4 => Instruction::Ubfiz {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
                _ => Instruction::Sbfiz {
                    rd: rd_local,
                    rn,
                    lsb,
                    width,
                    reg_width,
                },
            }
        }
        // Multiply-accumulate family: MADD/MSUB (4-operand) and MNEG/SMULH/UMULH (3-operand).
        34 => {
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
        // Issue #66 multiply / divide: MUL/SDIV/UDIV. All register-only.
        35 => {
            let rn = pick_reg(rng);
            let rm = pick_reg(rng);
            match rng.random_range(0..3) {
                0 => Instruction::Mul { rd, rn, rm },
                1 => Instruction::Sdiv { rd, rn, rm },
                _ => Instruction::Udiv { rd, rn, rm },
            }
        }
        // Issue #66 compares/tests. CMP/CMN sample register, clamped
        // immediate, and arithmetic shifted-register forms. TST samples
        // register, logical-bitmask immediate, and logical shifted-register
        // forms including ROR.
        36 => random_compare_or_test_instruction(rng, registers, immediates),
        // Issue #66 conditional selects: CSEL/CSINC/CSINV/CSNEG. Register-only,
        // condition sampled from NORMAL_CONDITIONS (AL/NV excluded — AL
        // collapses to MOV rd,rn and NV is reserved).
        37 => {
            let rn = pick_reg(rng);
            let rm = pick_reg(rng);
            let cond = crate::ir::types::Condition::random_normal(rng);
            match rng.random_range(0..4) {
                0 => Instruction::Csel { rd, rn, rm, cond },
                1 => Instruction::Csinc { rd, rn, rm, cond },
                2 => Instruction::Csinv { rd, rn, rm, cond },
                _ => Instruction::Csneg { rd, rn, rm, cond },
            }
        }
        _ => unreachable!(),
    }
}

fn random_compare_or_test_instruction<R: rand::RngExt>(
    rng: &mut R,
    registers: &[Register],
    immediates: &[i64],
) -> Instruction {
    let family = rng.random_range(0..3);
    let shape = rng.random_range(0..3);
    match shape {
        0 => random_register_compare_or_test(rng, registers, family),
        1 if family == 2 => {
            let non_sp = non_sp_registers(registers);
            if non_sp.is_empty() {
                return random_register_compare_or_test(rng, registers, family);
            }
            let rn = non_sp[rng.random_range(0..non_sp.len())];
            let imm = random_tst_bitmask_immediate(rng, rn, immediates);
            Instruction::Tst {
                rn,
                rm: Operand::Immediate(imm),
                width: RegisterWidth::X64,
            }
        }
        1 => {
            let rn = pick_register(rng, registers);
            let imm = if immediates.is_empty() {
                0
            } else {
                immediates[rng.random_range(0..immediates.len())].rem_euclid(0x1000)
            };
            match family {
                0 => Instruction::Cmp {
                    rn,
                    rm: Operand::Immediate(imm),
                },
                1 => Instruction::Cmn {
                    rn,
                    rm: Operand::Immediate(imm),
                },
                _ => unreachable!(),
            }
        }
        _ => {
            let non_sp = non_sp_registers(registers);
            if non_sp.is_empty() {
                return random_register_compare_or_test(rng, registers, family);
            }
            let rn = non_sp[rng.random_range(0..non_sp.len())];
            let rm = random_compare_shifted_operand(rng, &non_sp, family == 2);
            match family {
                0 => Instruction::Cmp { rn, rm },
                1 => Instruction::Cmn { rn, rm },
                _ => Instruction::Tst {
                    rn,
                    rm,
                    width: RegisterWidth::X64,
                },
            }
        }
    }
}

fn random_register_compare_or_test<R: rand::RngExt>(
    rng: &mut R,
    registers: &[Register],
    family: u32,
) -> Instruction {
    let rn = pick_register(rng, registers);
    let rm = Operand::Register(pick_register(rng, registers));
    match family {
        0 => Instruction::Cmp { rn, rm },
        1 => Instruction::Cmn { rn, rm },
        _ => Instruction::Tst {
            rn,
            rm,
            width: RegisterWidth::X64,
        },
    }
}

fn random_compare_shifted_operand<R: rand::RngExt>(
    rng: &mut R,
    non_sp: &[Register],
    allow_ror: bool,
) -> Operand {
    let reg = non_sp[rng.random_range(0..non_sp.len())];
    let kind = if allow_ror {
        match rng.random_range(0..4) {
            0 => ShiftKind::Lsl,
            1 => ShiftKind::Lsr,
            2 => ShiftKind::Asr,
            _ => ShiftKind::Ror,
        }
    } else {
        match rng.random_range(0..3) {
            0 => ShiftKind::Lsl,
            1 => ShiftKind::Lsr,
            _ => ShiftKind::Asr,
        }
    };
    let amount = SHIFTED_OP_AMOUNTS[rng.random_range(0..SHIFTED_OP_AMOUNTS.len())];
    Operand::ShiftedRegister { reg, kind, amount }
}

fn random_tst_bitmask_immediate<R: rand::RngExt>(
    rng: &mut R,
    rn: Register,
    immediates: &[i64],
) -> i64 {
    let encodable: Vec<i64> = immediates
        .iter()
        .copied()
        .filter(|imm| {
            Instruction::Tst {
                rn,
                rm: Operand::Immediate(*imm),
                width: RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        })
        .collect();
    if encodable.is_empty() {
        TST_LOGICAL_IMM64_SAMPLES[rng.random_range(0..TST_LOGICAL_IMM64_SAMPLES.len())]
    } else {
        encodable[rng.random_range(0..encodable.len())]
    }
}

fn pick_register<R: rand::RngExt>(rng: &mut R, registers: &[Register]) -> Register {
    if registers.is_empty() {
        Register::X0
    } else {
        registers[rng.random_range(0..registers.len())]
    }
}

fn non_sp_registers(registers: &[Register]) -> Vec<Register> {
    registers
        .iter()
        .copied()
        .filter(|reg| *reg != Register::SP)
        .collect()
}

fn random_operand<R: rand::RngExt>(
    rng: &mut R,
    registers: &[Register],
    immediates: &[i64],
) -> Operand {
    if rng.random_bool(0.5) && !registers.is_empty() {
        Operand::Register(registers[rng.random_range(0..registers.len())])
    } else if !immediates.is_empty() {
        Operand::Immediate(immediates[rng.random_range(0..immediates.len())].rem_euclid(0x1000))
    } else if !registers.is_empty() {
        Operand::Register(registers[rng.random_range(0..registers.len())])
    } else {
        Operand::Immediate(0)
    }
}

fn random_arith_rm_operand<R: rand::RngExt>(
    rng: &mut R,
    registers: &[Register],
    immediates: &[i64],
) -> Operand {
    let non_sp = non_sp_registers(registers);
    if !non_sp.is_empty() && rng.random_range(0..3) == 2 {
        random_compare_shifted_operand(rng, &non_sp, false)
    } else {
        match random_operand(rng, registers, immediates) {
            Operand::Immediate(imm) => Operand::Immediate(imm.rem_euclid(0x1000)),
            other => other,
        }
    }
}

fn random_shift_operand<R: rand::RngExt>(rng: &mut R, registers: &[Register]) -> Operand {
    if rng.random_bool(0.7) {
        // Prefer immediate shifts
        let shifts = AARCH64_RANDOM_SHIFT_IMMEDIATES;
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
    use crate::isa::InstructionGenerator;
    use crate::isa::aarch64::AArch64InstructionGenerator;
    use std::convert::Infallible;

    fn default_registers() -> Vec<Register> {
        vec![Register::X0, Register::X1, Register::X2]
    }

    fn default_immediates() -> Vec<i64> {
        vec![-1, 0, 1, 2]
    }

    struct BudgetedRng {
        words: Vec<u32>,
        next_word: usize,
        fallback: u32,
        remaining_draws: usize,
    }

    impl BudgetedRng {
        fn new(words: Vec<u32>) -> Self {
            Self {
                words,
                next_word: 0,
                fallback: 0,
                remaining_draws: 64,
            }
        }

        fn draw_word(&mut self) -> u32 {
            assert!(
                self.remaining_draws > 0,
                "random generator exceeded its draw budget"
            );
            self.remaining_draws -= 1;
            let word = self
                .words
                .get(self.next_word)
                .copied()
                .unwrap_or(self.fallback);
            self.next_word += 1;
            word
        }
    }

    impl rand::TryRng for BudgetedRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.draw_word())
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let low = u64::from(self.draw_word());
            let high = u64::from(self.draw_word());
            Ok(low | (high << 32))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(4) {
                let bytes = self.draw_word().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    // Inverts `random_range`'s Lemire mapping: returns the smallest 32-bit
    // word `w` such that `(w * range) >> 32 == value`, so a `BudgetedRng` can
    // be primed to force a specific `random_range(0..range)` outcome.
    fn word_for_range(range: u32, value: u32) -> u32 {
        assert!(range > 0);
        assert!(value < range);
        let numerator = (u128::from(value)) << 32;
        let word = numerator.div_ceil(u128::from(range)) as u32;
        debug_assert_eq!(((u64::from(word) * u64::from(range)) >> 32) as u32, value);
        word
    }

    // Primes a `BudgetedRng` to steer `generate_random_instruction` down a
    // chosen opcode arm: the first draw is the `rd` index (`random_range(0..2)`
    // for these 2-register pools), the second is the opcode slot
    // (`random_range(0..38)`). Slot 32 = CCMP/CCMN arm, slot 33 = bit-field arm
    // — keep these in sync with the match in `generate_random_instruction`.
    fn rng_for_opcode_slot(slot: u32, rd_index: u32) -> BudgetedRng {
        BudgetedRng::new(vec![word_for_range(2, rd_index), word_for_range(38, slot)])
    }

    fn rng_for_compare_slot(family: u32, shape: u32, tail: Vec<u32>) -> BudgetedRng {
        let mut words = vec![
            word_for_range(2, 0),
            word_for_range(38, 36),
            word_for_range(3, family),
            word_for_range(3, shape),
        ];
        words.extend(tail);
        BudgetedRng::new(words)
    }

    fn rng_for_shifted_arith_slot(slot: u32, kind_index: u32) -> BudgetedRng {
        BudgetedRng::new(vec![
            word_for_range(2, 0),
            word_for_range(38, slot),
            word_for_range(2, 0),
            word_for_range(3, 2),
            word_for_range(2, 1),
            word_for_range(3, kind_index),
            word_for_range(SHIFTED_OP_AMOUNTS.len() as u32, 0),
        ])
    }

    #[test]
    fn random_operand_clamps_immediates_to_imm12_range() {
        let immediates = [0, 1, 0xFFF, 0x1000, 8192, 0x1_0000, 1_000_000, -1];

        for (index, &raw_imm) in immediates.iter().enumerate() {
            let mut rng = BudgetedRng::new(vec![
                0,
                0,
                word_for_range(immediates.len() as u32, index as u32),
            ]);
            let operand = random_operand(&mut rng, &[], &immediates);
            assert_eq!(
                operand,
                Operand::Immediate(raw_imm.rem_euclid(0x1000)),
                "immediate table value {raw_imm} must be clamped to imm12"
            );
        }
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
    fn generate_encodable_instructions_contains_w_add_sub_mov() {
        let instrs = generate_all_encodable_instructions(
            &[Register::X0, Register::X1, Register::X2],
            &[0, 1],
        );

        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::MovRegW {
                rd: Register::X0,
                rn: Register::X1
            }
        )));
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::AddW {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2)
            }
        )));
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::SubW {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1)
            }
        )));
        assert!(instrs.iter().all(Instruction::is_encodable_aarch64));
    }

    #[test]
    fn test_generate_all_instructions_contains_eor() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        let has_eor = instrs.iter().any(|i| matches!(i, Instruction::Eor { .. }));
        assert!(has_eor);
    }

    #[test]
    fn test_generate_all_instructions_contains_mul_div_family() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        assert!(instrs.iter().any(|i| matches!(i, Instruction::Mul { .. })));
        assert!(instrs.iter().any(|i| matches!(i, Instruction::Sdiv { .. })));
        assert!(instrs.iter().any(|i| matches!(i, Instruction::Udiv { .. })));
    }

    #[test]
    fn test_generate_all_instructions_covers_opcode_count() {
        // Candidate generation intentionally uses `InstructionType::opcode_id`
        // from `src/isa/aarch64.rs`; add a sync guard beside any future
        // candidate-local table instead of letting the two drift silently.
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        let ids: std::collections::BTreeSet<u8> =
            instrs.iter().map(InstructionType::opcode_id).collect();
        let generator = AArch64InstructionGenerator;
        for id in 0..generator.opcode_count() {
            assert!(
                ids.contains(&id),
                "missing opcode_id {} in generate_all",
                id
            );
        }
    }

    fn random_opcode_ids(seed: u64, draws: usize) -> std::collections::BTreeSet<u8> {
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        let regs = default_registers();
        let imms = default_immediates();
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        (0..draws)
            .map(|_| generate_random_instruction(&mut rng, &regs, &imms).opcode_id())
            .collect()
    }

    #[test]
    fn generate_random_instruction_promotes_single_source_bit_ops_to_top_level_slots() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::collections::HashMap;

        let regs = default_registers();
        let imms = default_immediates();
        let mut rng = ChaCha8Rng::seed_from_u64(0x115);
        let mut counts: HashMap<u8, u32> = HashMap::new();
        const N: u32 = 30_000;

        for _ in 0..N {
            let id = generate_random_instruction(&mut rng, &regs, &imms).opcode_id();
            *counts.entry(id).or_default() += 1;
        }

        for (label, instr) in [
            (
                "Clz",
                Instruction::Clz {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Cls",
                Instruction::Cls {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Rbit",
                Instruction::Rbit {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Rev",
                Instruction::Rev {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Rev32",
                Instruction::Rev32 {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Rev16",
                Instruction::Rev16 {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
        ] {
            let id = instr.opcode_id();
            let count = counts.get(&id).copied().unwrap_or(0);
            assert!(
                count >= 500,
                "expected >= 500 samples for {} (id {}) in {} draws, got {}",
                label,
                id,
                N,
                count
            );
        }
    }

    #[test]
    fn test_generate_random_reaches_mul_div_family() {
        let ids = random_opcode_ids(0x66, 5_000);
        for (label, instr) in [
            (
                "Mul",
                Instruction::Mul {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                },
            ),
            (
                "Sdiv",
                Instruction::Sdiv {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                },
            ),
            (
                "Udiv",
                Instruction::Udiv {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                },
            ),
        ] {
            assert!(
                ids.contains(&instr.opcode_id()),
                "random never produced {}",
                label
            );
        }
    }

    #[test]
    fn test_generate_random_reaches_compare_family() {
        let ids = random_opcode_ids(0x66, 5_000);
        for (label, instr) in [
            (
                "Cmp",
                Instruction::Cmp {
                    rn: Register::X0,
                    rm: Operand::Register(Register::X1),
                },
            ),
            (
                "Cmn",
                Instruction::Cmn {
                    rn: Register::X0,
                    rm: Operand::Register(Register::X1),
                },
            ),
            (
                "Tst",
                Instruction::Tst {
                    rn: Register::X0,
                    rm: Operand::Register(Register::X1),
                    width: RegisterWidth::X64,
                },
            ),
        ] {
            assert!(
                ids.contains(&instr.opcode_id()),
                "random never produced {}",
                label
            );
        }
    }

    #[test]
    fn generate_random_compare_slot_samples_tst_immediate_and_shifted_forms() {
        let regs = [Register::X0, Register::X1];

        let mut cmp_rng = rng_for_compare_slot(
            0,
            2,
            vec![
                word_for_range(2, 0),
                word_for_range(2, 1),
                word_for_range(3, 0),
                word_for_range(SHIFTED_OP_AMOUNTS.len() as u32, 0),
            ],
        );
        let cmp = generate_random_instruction(&mut cmp_rng, &regs, &[]);
        assert_eq!(
            cmp,
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::ShiftedRegister {
                    reg: Register::X1,
                    kind: crate::ir::ShiftKind::Lsl,
                    amount: 1,
                },
            }
        );
        assert!(cmp.is_encodable_aarch64());

        let mut cmn_rng = rng_for_compare_slot(
            1,
            2,
            vec![
                word_for_range(2, 0),
                word_for_range(2, 1),
                word_for_range(3, 2),
                word_for_range(SHIFTED_OP_AMOUNTS.len() as u32, 0),
            ],
        );
        let cmn = generate_random_instruction(&mut cmn_rng, &regs, &[]);
        assert_eq!(
            cmn,
            Instruction::Cmn {
                rn: Register::X0,
                rm: Operand::ShiftedRegister {
                    reg: Register::X1,
                    kind: crate::ir::ShiftKind::Asr,
                    amount: 1,
                },
            }
        );
        assert!(cmn.is_encodable_aarch64());

        let mut tst_shifted_rng = rng_for_compare_slot(
            2,
            2,
            vec![
                word_for_range(2, 0),
                word_for_range(2, 1),
                word_for_range(4, 3),
                word_for_range(SHIFTED_OP_AMOUNTS.len() as u32, 0),
            ],
        );
        let tst_shifted = generate_random_instruction(&mut tst_shifted_rng, &regs, &[]);
        assert_eq!(
            tst_shifted,
            Instruction::Tst {
                rn: Register::X0,
                rm: Operand::ShiftedRegister {
                    reg: Register::X1,
                    kind: crate::ir::ShiftKind::Ror,
                    amount: 1,
                },
                width: RegisterWidth::X64,
            }
        );
        assert!(tst_shifted.is_encodable_aarch64());

        let mut tst_imm_rng =
            rng_for_compare_slot(2, 1, vec![word_for_range(2, 0), word_for_range(1, 0)]);
        let tst_imm = generate_random_instruction(&mut tst_imm_rng, &regs, &[0xff]);
        assert_eq!(
            tst_imm,
            Instruction::Tst {
                rn: Register::X0,
                rm: Operand::Immediate(0xff),
                width: RegisterWidth::X64,
            }
        );
        assert!(tst_imm.is_encodable_aarch64());
    }

    #[test]
    fn generate_random_instruction_samples_shifted_arith_forms() {
        let regs = [Register::X0, Register::X1];
        let cases = [
            (2, 0, "ADD"),
            (3, 1, "SUB"),
            (18, 2, "ADDS"),
            (19, 0, "SUBS"),
        ];

        for (slot, kind_index, name) in cases {
            let mut rng = rng_for_shifted_arith_slot(slot, kind_index);
            let instr = generate_random_instruction(&mut rng, &regs, &[0x1234]);
            let rm = match instr {
                Instruction::Add { rm, .. }
                | Instruction::Sub { rm, .. }
                | Instruction::Adds { rm, .. }
                | Instruction::Subs { rm, .. } => rm,
                other => panic!("slot {slot} should generate {name}, got {other:?}"),
            };

            match rm {
                Operand::ShiftedRegister { kind, amount, .. } => {
                    assert_ne!(kind, ShiftKind::Ror, "{name} must not sample ROR");
                    assert_eq!(amount, 1);
                }
                other => panic!("{name} should sample shifted-register rm, got {other:?}"),
            }
            assert!(
                instr.is_encodable_aarch64(),
                "{name} shifted-register candidate must be encodable: {instr}"
            );
        }
    }

    #[test]
    fn test_generate_random_reaches_csel_family() {
        let ids = random_opcode_ids(0x66, 5_000);
        for (label, instr) in [
            (
                "Csel",
                Instruction::Csel {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                    cond: crate::ir::types::Condition::EQ,
                },
            ),
            (
                "Csinc",
                Instruction::Csinc {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                    cond: crate::ir::types::Condition::EQ,
                },
            ),
            (
                "Csinv",
                Instruction::Csinv {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                    cond: crate::ir::types::Condition::EQ,
                },
            ),
            (
                "Csneg",
                Instruction::Csneg {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                    cond: crate::ir::types::Condition::EQ,
                },
            ),
        ] {
            assert!(
                ids.contains(&instr.opcode_id()),
                "random never produced {}",
                label
            );
        }
    }

    #[test]
    fn test_generate_random_reaches_madd_family() {
        let ids = random_opcode_ids(0x66, 5_000);
        for (label, instr) in [
            (
                "Madd",
                Instruction::Madd {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                    ra: Register::X0,
                },
            ),
            (
                "Msub",
                Instruction::Msub {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                    ra: Register::X0,
                },
            ),
            (
                "Mneg",
                Instruction::Mneg {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                },
            ),
            (
                "Smulh",
                Instruction::Smulh {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                },
            ),
            (
                "Umulh",
                Instruction::Umulh {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                },
            ),
        ] {
            assert!(
                ids.contains(&instr.opcode_id()),
                "random never produced {}",
                label
            );
        }
    }

    #[test]
    fn generate_random_instruction_samples_bitfield_and_madd_families_evenly() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let regs = default_registers();
        let imms = default_immediates();
        let mut rng = ChaCha8Rng::seed_from_u64(0x153);
        let mut bitfield_count = 0u32;
        let mut madd_count = 0u32;

        // Both families occupy exactly one top-level slot in the
        // `rng.random_range(0..SLOTS)` dispatch, so "equal sampling weight" means
        // equal probability of *entering* the slot (~1/SLOTS), not equal per-variant
        // weight: slot 33 makes a secondary 0..6 draw (plus SP-rejection retries) and
        // slot 34 a 0..5 draw. DRAWS is sized so each family is expected EXPECTED_PER_FAMILY times.
        const SLOTS: u32 = 38;
        const EXPECTED_PER_FAMILY: u32 = 2_000;
        const DRAWS: u32 = SLOTS * EXPECTED_PER_FAMILY;

        for _ in 0..DRAWS {
            let instr = generate_random_instruction(&mut rng, &regs, &imms);
            match instr {
                Instruction::Ubfx { .. }
                | Instruction::Sbfx { .. }
                | Instruction::Bfi { .. }
                | Instruction::Bfxil { .. }
                | Instruction::Ubfiz { .. }
                | Instruction::Sbfiz { .. } => bitfield_count += 1,
                Instruction::Madd { .. }
                | Instruction::Msub { .. }
                | Instruction::Mneg { .. }
                | Instruction::Smulh { .. }
                | Instruction::Umulh { .. } => madd_count += 1,
                _ => {}
            }
        }

        // Each count is ~Binomial(DRAWS, 1/SLOTS); the std-dev of their difference is
        // sqrt(2 * DRAWS * (1/38) * (37/38)) ≈ 63, so a tolerance of 250 is ≈ 4σ
        // (p_fail ≈ 1e-5) — tight enough to catch a slot-weight regression, loose
        // enough not to flake.
        let delta = bitfield_count.abs_diff(madd_count);
        assert!(
            delta <= 250,
            "bit-field and multiply-accumulate should have equal top-level sampling weight \
             over {DRAWS} draws, got bitfield={bitfield_count}, madd={madd_count}, delta={delta}",
        );

        // Delta alone would still pass if both families collapsed to the same wrong
        // rate (e.g. ~500 each), so bound each absolute count near the expected value
        // to also catch a degenerate dispatch.
        for (name, count) in [
            ("bit-field", bitfield_count),
            ("multiply-accumulate", madd_count),
        ] {
            assert!(
                (1_500..=2_500).contains(&count),
                "{name} family count {count} is far from the expected {EXPECTED_PER_FAMILY} over {DRAWS} draws",
            );
        }
    }

    #[test]
    fn test_generate_all_instructions_contains_csel_family() {
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        assert!(instrs.iter().any(|i| matches!(i, Instruction::Csel { .. })));
        assert!(
            instrs
                .iter()
                .any(|i| matches!(i, Instruction::Csinc { .. }))
        );
        assert!(
            instrs
                .iter()
                .any(|i| matches!(i, Instruction::Csinv { .. }))
        );
        assert!(
            instrs
                .iter()
                .any(|i| matches!(i, Instruction::Csneg { .. }))
        );
    }

    #[test]
    fn test_generate_all_instructions_contains_plain_compare_family() {
        // Cmp/Cmn must appear in plain Register and Immediate forms (the
        // ExtendedRegister form is handled separately by the #60 block).
        // Tst must appear in plain Register and bitmask-immediate forms.
        let instrs = generate_all_instructions(&default_registers(), &default_immediates());
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::Cmp {
                rm: Operand::Register(_),
                ..
            }
        )));
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::Cmp {
                rm: Operand::Immediate(_),
                ..
            }
        )));
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::Cmn {
                rm: Operand::Register(_),
                ..
            }
        )));
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::Cmn {
                rm: Operand::Immediate(_),
                ..
            }
        )));
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::Tst {
                rm: Operand::Register(_),
                ..
            }
        )));
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::Tst {
                rm: Operand::Immediate(_),
                ..
            }
        )));
    }

    #[test]
    fn generate_encodable_instructions_contains_tst_bitmask_immediate() {
        let instrs = generate_all_encodable_instructions(&[Register::X0, Register::X1], &[0xff]);

        assert!(instrs.contains(&Instruction::Tst {
            rn: Register::X0,
            rm: Operand::Immediate(0xff),
            width: RegisterWidth::X64,
        }));
        assert!(instrs.iter().all(Instruction::is_encodable_aarch64));
    }

    #[test]
    fn test_generate_all_instructions_includes_n_only_conditional_compare_nzcv_sample() {
        let instrs = generate_all_instructions(&[Register::X0, Register::X1], &[0]);
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::Ccmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
                nzcv: 8,
                cond: crate::ir::types::Condition::MI
            }
        )));
        assert!(instrs.iter().any(|i| matches!(
            i,
            Instruction::Ccmn {
                rn: Register::X0,
                rm: Operand::Immediate(0),
                nzcv: 8,
                cond: crate::ir::types::Condition::PL
            }
        )));
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
    fn generate_encodable_instructions_contains_shifted_compare_and_test_forms() {
        let instrs = generate_all_encodable_instructions(&[Register::X0, Register::X1], &[]);

        assert!(instrs.contains(&Instruction::Cmp {
            rn: Register::X0,
            rm: Operand::ShiftedRegister {
                reg: Register::X1,
                kind: crate::ir::ShiftKind::Lsl,
                amount: 1,
            },
        }));
        assert!(instrs.contains(&Instruction::Cmn {
            rn: Register::X0,
            rm: Operand::ShiftedRegister {
                reg: Register::X1,
                kind: crate::ir::ShiftKind::Asr,
                amount: 1,
            },
        }));
        assert!(instrs.contains(&Instruction::Tst {
            rn: Register::X0,
            rm: Operand::ShiftedRegister {
                reg: Register::X1,
                kind: crate::ir::ShiftKind::Ror,
                amount: 1,
            },
            width: RegisterWidth::X64,
        }));
        assert!(!instrs.iter().any(|i| matches!(
            i,
            Instruction::Cmp {
                rm: Operand::ShiftedRegister {
                    kind: crate::ir::ShiftKind::Ror,
                    ..
                },
                ..
            } | Instruction::Cmn {
                rm: Operand::ShiftedRegister {
                    kind: crate::ir::ShiftKind::Ror,
                    ..
                },
                ..
            }
        )));
        assert!(instrs.iter().all(Instruction::is_encodable_aarch64));
    }

    #[test]
    fn shifted_compare_and_test_generation_is_unique_and_prefilters_sp() {
        let instrs = generate_all_instructions(&[Register::X0, Register::X1, Register::SP], &[]);

        for expected in [
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::ShiftedRegister {
                    reg: Register::X1,
                    kind: crate::ir::ShiftKind::Lsl,
                    amount: 1,
                },
            },
            Instruction::Cmn {
                rn: Register::X0,
                rm: Operand::ShiftedRegister {
                    reg: Register::X1,
                    kind: crate::ir::ShiftKind::Asr,
                    amount: 1,
                },
            },
            Instruction::Tst {
                rn: Register::X0,
                rm: Operand::ShiftedRegister {
                    reg: Register::X1,
                    kind: crate::ir::ShiftKind::Ror,
                    amount: 1,
                },
                width: RegisterWidth::X64,
            },
        ] {
            let count = instrs.iter().filter(|instr| **instr == expected).count();
            assert_eq!(count, 1, "{expected} must appear exactly once");
        }

        for instr in &instrs {
            match instr {
                Instruction::Cmp {
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                }
                | Instruction::Cmn {
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                }
                | Instruction::Tst {
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                    ..
                } => {
                    assert_ne!(
                        *rn,
                        Register::SP,
                        "shifted compare/test rn uses SP: {instr}"
                    );
                    assert_ne!(
                        *reg,
                        Register::SP,
                        "shifted compare/test rm uses SP: {instr}"
                    );
                }
                _ => {}
            }
        }
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
    fn test_generate_all_instructions_shifted_register_prefilters_sp() {
        let registers = vec![Register::X0, Register::X1, Register::SP];
        let instrs = generate_all_instructions(&registers, &[]);

        let mut shifted_count = 0;
        for instr in &instrs {
            match instr {
                Instruction::Add {
                    rd,
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                }
                | Instruction::AddW {
                    rd,
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                }
                | Instruction::Sub {
                    rd,
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                }
                | Instruction::SubW {
                    rd,
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                }
                | Instruction::And {
                    rd,
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                    ..
                }
                | Instruction::Orr {
                    rd,
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                    ..
                }
                | Instruction::Eor {
                    rd,
                    rn,
                    rm: Operand::ShiftedRegister { reg, .. },
                    ..
                } => {
                    shifted_count += 1;
                    assert_ne!(*rd, Register::SP, "shifted-register rd uses SP: {instr}");
                    assert_ne!(*rn, Register::SP, "shifted-register rn uses SP: {instr}");
                    assert_ne!(*reg, Register::SP, "shifted-register rm uses SP: {instr}");
                }
                _ => {}
            }
        }

        // 2 non-SP choices for each of rd/rn/rm, with 162 shifted-register
        // binary candidates per tuple from the current AArch64 candidate matrix.
        assert_eq!(
            shifted_count, 1296,
            "enumeration must retain the expected shifted-register candidate count"
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
    fn generate_random_instruction_never_samples_zero_shift_immediates() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let regs = default_registers();
        let imms = default_immediates();
        let mut rng = ChaCha8Rng::seed_from_u64(0x263);
        let mut seen = std::collections::BTreeSet::new();

        for _ in 0..50_000 {
            let instr = generate_random_instruction(&mut rng, &regs, &imms);
            let sampled = match instr {
                Instruction::Lsl {
                    shift: Operand::Immediate(amount),
                    ..
                } => Some(("lsl", amount)),
                Instruction::Lsr {
                    shift: Operand::Immediate(amount),
                    ..
                } => Some(("lsr", amount)),
                Instruction::Asr {
                    shift: Operand::Immediate(amount),
                    ..
                } => Some(("asr", amount)),
                Instruction::Ror {
                    shift: Operand::Immediate(amount),
                    ..
                } => Some(("ror", amount)),
                _ => None,
            };

            if let Some((mnemonic, amount)) = sampled {
                assert_ne!(amount, 0, "random {mnemonic} sampled immediate shift #0");
                seen.insert(mnemonic);
            }
        }

        assert_eq!(
            seen,
            std::collections::BTreeSet::from(["asr", "lsl", "lsr", "ror"])
        );
    }

    #[test]
    fn generate_random_instruction_handles_sp_only_ccmp_and_bitfield_slots() {
        let regs = [Register::SP];
        let imms = default_immediates();

        for slot in [32, 33] {
            let mut rng = rng_for_opcode_slot(slot, 0);
            let instr = generate_random_instruction(&mut rng, &regs, &imms);
            assert!(
                matches!(
                    instr,
                    Instruction::Mneg {
                        rd: Register::SP,
                        rn: Register::SP,
                        rm: Register::SP,
                    }
                ),
                "slot {slot} should fall back finitely for an SP-only pool, got {instr:?}"
            );
        }
    }

    #[test]
    fn generate_random_instruction_filters_sp_from_ccmp_and_bitfield_operands() {
        let regs = [Register::SP, Register::X0];
        let imms = default_immediates();

        let mut ccmp_rng = rng_for_opcode_slot(32, 0);
        let ccmp = generate_random_instruction(&mut ccmp_rng, &regs, &imms);
        match ccmp {
            Instruction::Ccmp {
                rn,
                rm: Operand::Register(rm),
                ..
            }
            | Instruction::Ccmn {
                rn,
                rm: Operand::Register(rm),
                ..
            } => {
                assert_eq!(rn, Register::X0);
                assert_eq!(rm, Register::X0);
            }
            other => panic!("expected register-form CCMP/CCMN, got {other:?}"),
        }

        let mut bitfield_rng = rng_for_opcode_slot(33, 0);
        let bitfield = generate_random_instruction(&mut bitfield_rng, &regs, &imms);
        match bitfield {
            Instruction::Ubfx { rd, rn, .. }
            | Instruction::Sbfx { rd, rn, .. }
            | Instruction::Bfi { rd, rn, .. }
            | Instruction::Bfxil { rd, rn, .. }
            | Instruction::Ubfiz { rd, rn, .. }
            | Instruction::Sbfiz { rd, rn, .. } => {
                assert_eq!(rd, Register::X0);
                assert_eq!(rn, Register::X0);
            }
            other => panic!("expected bit-field instruction, got {other:?}"),
        }
    }

    fn rng_for_arith_immediate_slot(slot: u32, imm_count: u32, imm_index: u32) -> BudgetedRng {
        // ADD/SUB/ADDS/SUBS (slots 2, 3, 18, 19) consume, in order: `rd`, the
        // opcode slot, `rn`, then `random_arith_rm_operand`. The latter first
        // draws a 0..3 shape selector (2 = shifted register, issue #279) and,
        // when that is not 2, falls through to `random_operand`, whose
        // `random_bool(0.5)` register/immediate coin pulls a u64 (two words).
        // Drive shape != 2 and bias the coin toward the immediate branch so the
        // imm12 clamp is exercised. The high word governs the 0.5 split, so
        // `u32::MAX, u32::MAX` selects the immediate (non-register) arm.
        BudgetedRng::new(vec![
            word_for_range(3, 0), // rd register pick
            word_for_range(38, slot),
            word_for_range(3, 0), // rn register pick
            word_for_range(3, 0), // shape selector: != 2 → not shifted
            u32::MAX,             // random_bool low word
            u32::MAX,             // random_bool high word → false → immediate
            word_for_range(imm_count, imm_index),
        ])
    }

    fn rng_for_compare_immediate_slot(choice: u32, imm_count: u32, imm_index: u32) -> BudgetedRng {
        // `random_compare_or_test_instruction` consumes, in order: `family`
        // (0=CMP, 1=CMN, 2=TST), then `shape` (0=register, 1=immediate,
        // 2=shifted), then for the immediate shape an `rn` register pick and the
        // immediate index. Drive `family = choice` (CMP/CMN) with the immediate
        // shape so both choices exercise the imm12-clamped compare path.
        BudgetedRng::new(vec![
            word_for_range(3, 0),      // rd register pick (unused by CMP/CMN)
            word_for_range(38, 36),    // slot 36: compare / test
            word_for_range(3, choice), // family: 0=CMP, 1=CMN
            word_for_range(3, 1),      // shape: 1=immediate
            word_for_range(3, 0),      // rn register pick
            word_for_range(imm_count, imm_index),
        ])
    }

    fn assert_imm12_arith_or_compare(instr: &Instruction, raw_imm: i64) {
        let imm = match instr {
            Instruction::Add {
                rm: Operand::Immediate(imm),
                ..
            }
            | Instruction::Sub {
                rm: Operand::Immediate(imm),
                ..
            }
            | Instruction::Adds {
                rm: Operand::Immediate(imm),
                ..
            }
            | Instruction::Subs {
                rm: Operand::Immediate(imm),
                ..
            }
            | Instruction::Cmp {
                rm: Operand::Immediate(imm),
                ..
            }
            | Instruction::Cmn {
                rm: Operand::Immediate(imm),
                ..
            } => *imm,
            other => panic!("expected immediate arithmetic/compare instruction, got {other:?}"),
        };

        assert_eq!(imm, raw_imm.rem_euclid(0x1000));
        assert!(
            instr.is_encodable_aarch64(),
            "random arithmetic/compare instruction must be encodable: {instr}"
        );
    }

    #[test]
    fn generate_random_instruction_clamps_arith_compare_immediates_to_imm12() {
        let regs = [Register::X0, Register::X1, Register::X2];
        let imms = [0, 1, 0xFFF, 0x1000, 8192, 0x1_0000, 1_000_000, -1];
        let imm_count = imms.len() as u32;

        for slot in [2, 3, 18, 19] {
            for (imm_index, &raw_imm) in imms.iter().enumerate() {
                let mut rng = rng_for_arith_immediate_slot(slot, imm_count, imm_index as u32);
                let instr = generate_random_instruction(&mut rng, &regs, &imms);
                assert_imm12_arith_or_compare(&instr, raw_imm);
            }
        }

        for choice in [0, 1] {
            for (imm_index, &raw_imm) in imms.iter().enumerate() {
                let mut rng = rng_for_compare_immediate_slot(choice, imm_count, imm_index as u32);
                let instr = generate_random_instruction(&mut rng, &regs, &imms);
                assert_imm12_arith_or_compare(&instr, raw_imm);
            }
        }
    }

    #[test]
    fn generate_random_instruction_keeps_ccmp_immediates_in_imm5_range() {
        let regs = [Register::X0, Register::X1, Register::X2];
        let imms = [0, 31, 32, 0xFFF, 0x1000, 1_000_000, -1];
        let imm_count = imms.len() as u32;

        for (imm_index, &raw_imm) in imms.iter().enumerate() {
            let mut rng = BudgetedRng::new(vec![
                word_for_range(3, 0),
                word_for_range(38, 32),
                word_for_range(3, 0),
                u32::MAX,
                u32::MAX,
                word_for_range(imm_count, imm_index as u32),
            ]);
            let instr = generate_random_instruction(&mut rng, &regs, &imms);
            let imm = match instr {
                Instruction::Ccmp {
                    rm: Operand::Immediate(imm),
                    ..
                }
                | Instruction::Ccmn {
                    rm: Operand::Immediate(imm),
                    ..
                } => imm,
                other => panic!("expected immediate-form CCMP/CCMN, got {other:?}"),
            };

            assert_eq!(imm, raw_imm.rem_euclid(32));
            assert!(
                instr.is_encodable_aarch64(),
                "random CCMP/CCMN instruction must be encodable: {instr}"
            );
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
                width: RegisterWidth::X64,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
                width: RegisterWidth::X64,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
                width: RegisterWidth::X64,
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
            Instruction::Sxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sxth {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sxtw {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Uxth {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Ubfx {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Sbfx {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Bfi {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Bfxil {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Ubfiz {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Sbfiz {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 1,
                reg_width: crate::ir::RegisterWidth::X64,
            },
        ];

        let ids: Vec<_> = instrs.iter().map(InstructionType::opcode_id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_generate_all_instructions_includes_w_bitfield() {
        let registers = vec![Register::X0, Register::X1];
        let all = generate_all_instructions(&registers, &[0]);
        let is_w = |i: &Instruction| {
            matches!(
                i,
                Instruction::Ubfx {
                    reg_width: RegisterWidth::W32,
                    ..
                } | Instruction::Sbfx {
                    reg_width: RegisterWidth::W32,
                    ..
                } | Instruction::Bfi {
                    reg_width: RegisterWidth::W32,
                    ..
                } | Instruction::Bfxil {
                    reg_width: RegisterWidth::W32,
                    ..
                } | Instruction::Ubfiz {
                    reg_width: RegisterWidth::W32,
                    ..
                } | Instruction::Sbfiz {
                    reg_width: RegisterWidth::W32,
                    ..
                }
            )
        };
        assert!(
            all.iter().any(is_w),
            "enumerative output must contain W-form bit-field instructions"
        );
        // Every W-form bit-field instruction must satisfy is_encodable_aarch64
        // (lsb<=31, lsb+width<=32).
        for instr in all.iter().filter(|i| is_w(i)) {
            assert!(
                instr.is_encodable_aarch64(),
                "enumerative produced un-encodable W bit-field: {instr}"
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
    fn enumerate_extended_register_add_sub_allows_sp_rd_rn() {
        let regs = vec![Register::SP, Register::X0];
        let imms = vec![];
        let candidates = generate_all_instructions(&regs, &imms);
        let extended_x0_uxtb = Operand::ExtendedRegister {
            reg: Register::X0,
            kind: crate::ir::ExtendKind::Uxtb,
            shift: 0,
        };

        for expected in [
            Instruction::Add {
                rd: Register::SP,
                rn: Register::SP,
                rm: extended_x0_uxtb,
            },
            Instruction::Sub {
                rd: Register::SP,
                rn: Register::SP,
                rm: extended_x0_uxtb,
            },
        ] {
            assert!(
                candidates.contains(&expected),
                "enumeration missing SP-bearing extended-register candidate: {}",
                expected
            );
        }
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
