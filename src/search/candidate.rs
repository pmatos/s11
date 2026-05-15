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

    match rng.random_range(0..26) {
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
        _ => {
            let imm = (rng.random::<u32>() & 0xFFFF) as u16;
            let shifts = MOVW_LEGAL_SHIFTS;
            let shift = shifts[rng.random_range(0..shifts.len())];
            Instruction::MovK { rd, imm, shift }
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
}
