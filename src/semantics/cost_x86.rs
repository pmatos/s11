//! Cost model for the x86 backend.
//!
//! x86 is variable-length, so `CodeSize` is an approximation per variant.
//! `InstructionCount` and `Latency` mirror the AArch64 module's shape.
//! Width-aware: x86-32 encodings save one byte per REX prefix.

#![allow(dead_code)]

use crate::isa::x86::X86Instruction;
use crate::semantics::cost::CostMetric;

/// Cost of a single x86 instruction at the given operand width.
pub fn instruction_cost(instr: &X86Instruction, metric: &CostMetric, width: u32) -> u64 {
    match metric {
        CostMetric::InstructionCount => 1,
        CostMetric::Latency => instruction_latency(instr),
        CostMetric::CodeSize => instruction_code_size(instr, width),
    }
}

fn instruction_latency(_instr: &X86Instruction) -> u64 {
    // Every variant in the minimal core set is a single-cycle ALU op on
    // modern x86 cores. Refine when MUL / IDIV / shifts arrive.
    1
}

/// Approximate encoded length in bytes. Conservative upper bounds.
///
/// - REX prefix adds 1 byte to x86-64 ops touching r0..r15 with REX.W.
/// - Register-register: opcode + ModR/M = 2 bytes, plus REX for x86-64
///   = 3 bytes.
/// - Register-immediate (32-bit imm): opcode + ModR/M + 4-byte imm
///   = 6 bytes plus REX for x86-64 = 7 bytes.
/// - MOV reg, imm is immediate-dependent (see `MovImm` arm): x86-32 uses the
///   5-byte `B8+rd id`; x86-64 uses the 7-byte `REX.W C7 /0 id` when the
///   immediate fits in i32, else the 10-byte `REX.W B8+rd io` movabs. These
///   match the assembler exactly (a flat cost previously underestimated
///   movabs, which is unsound for length-based pruning).
fn instruction_code_size(instr: &X86Instruction, width: u32) -> u64 {
    let rex = if width == 64 { 1 } else { 0 };
    match instr {
        X86Instruction::MovReg { .. } => 2 + rex,
        // See the module doc-comment: immediate-dependent to stay a valid
        // upper bound on the assembler's MovImm encoding (issue #225).
        X86Instruction::MovImm { imm, .. } => {
            if width == 64 {
                if i32::try_from(*imm).is_ok() { 7 } else { 10 }
            } else {
                5
            }
        }
        X86Instruction::AddReg { .. }
        | X86Instruction::SubReg { .. }
        | X86Instruction::AndReg { .. }
        | X86Instruction::OrReg { .. }
        | X86Instruction::XorReg { .. }
        | X86Instruction::CmpReg { .. }
        | X86Instruction::TestReg { .. }
        // NEG / NOT are single-operand `F7 /3` / `F7 /2` = 2 bytes (+REX.W).
        | X86Instruction::Neg { .. }
        | X86Instruction::Not { .. }
        // INC / DEC are single-operand `FF /0` / `FF /1` = 2 bytes (+REX.W).
        | X86Instruction::Inc { .. }
        | X86Instruction::Dec { .. } => 2 + rex,
        // SHL / SHR / SAR / ROL / ROR by imm8 are `C1 /n ib` = opcode + ModR/M
        // + imm8 = 3 bytes (+REX.W).
        X86Instruction::Shl { .. }
        | X86Instruction::Shr { .. }
        | X86Instruction::Sar { .. }
        | X86Instruction::Rol { .. }
        | X86Instruction::Ror { .. } => 3 + rex,
        X86Instruction::AddImm { .. }
        | X86Instruction::SubImm { .. }
        | X86Instruction::AndImm { .. }
        | X86Instruction::OrImm { .. }
        | X86Instruction::XorImm { .. }
        | X86Instruction::CmpImm { .. }
        | X86Instruction::TestImm { .. } => 6 + rex,
        // CMOV is `0F 4x ModR/M` = 3 bytes plus REX.W on 64-bit.
        X86Instruction::Cmov { .. } => 3 + rex,
        // Short-form Jcc is `7x rel8` = 2 bytes (no REX). Long-form
        // `0F 8x rel32` = 6 bytes is used when the displacement doesn't
        // fit. The optimizer never emits Jcc bytes (terminators stay
        // pinned in the binary), so this is only the IR accounting
        // baseline; patching splices the original branch bytes back.
        X86Instruction::Jcc { .. } => 2,
    }
}

/// Total cost of a sequence at the given width.
pub fn sequence_cost(seq: &[X86Instruction], metric: &CostMetric, width: u32) -> u64 {
    seq.iter().map(|i| instruction_cost(i, metric, width)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::x86::X86Register;

    #[test]
    fn instruction_count_is_always_one() {
        let i = X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        assert_eq!(instruction_cost(&i, &CostMetric::InstructionCount, 64), 1);
        assert_eq!(instruction_cost(&i, &CostMetric::InstructionCount, 32), 1);
    }

    #[test]
    fn latency_is_one_for_minimal_set() {
        let cases = [
            X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 0,
            },
        ];
        for i in cases {
            assert_eq!(instruction_cost(&i, &CostMetric::Latency, 64), 1);
        }
    }

    #[test]
    fn code_size_x86_64_includes_rex_prefix() {
        let rr = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let ri = X86Instruction::AddImm {
            rd: X86Register::RAX,
            imm: 5,
        };
        assert_eq!(instruction_cost(&rr, &CostMetric::CodeSize, 64), 3);
        assert_eq!(instruction_cost(&ri, &CostMetric::CodeSize, 64), 7);
    }

    #[test]
    fn code_size_x86_32_drops_rex_prefix() {
        let rr = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let ri = X86Instruction::AddImm {
            rd: X86Register::RAX,
            imm: 5,
        };
        assert_eq!(instruction_cost(&rr, &CostMetric::CodeSize, 32), 2);
        assert_eq!(instruction_cost(&ri, &CostMetric::CodeSize, 32), 6);
    }

    #[test]
    fn test_code_size_and_latency_mirror_cmp() {
        let reg = X86Instruction::TestReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let imm = X86Instruction::TestImm {
            rn: X86Register::RAX,
            imm: 5,
        };
        // Same sizes as CMP: reg-reg 2(+rex), reg-imm 6(+rex); latency 1.
        assert_eq!(instruction_cost(&reg, &CostMetric::CodeSize, 64), 3);
        assert_eq!(instruction_cost(&reg, &CostMetric::CodeSize, 32), 2);
        assert_eq!(instruction_cost(&imm, &CostMetric::CodeSize, 64), 7);
        assert_eq!(instruction_cost(&imm, &CostMetric::CodeSize, 32), 6);
        assert_eq!(instruction_cost(&reg, &CostMetric::Latency, 64), 1);
        assert_eq!(instruction_cost(&imm, &CostMetric::Latency, 64), 1);
    }

    #[test]
    fn sequence_cost_sums_individual_costs() {
        let seq = [
            X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RCX,
            },
        ];
        // 3 + 3 = 6 bytes on x86-64.
        assert_eq!(sequence_cost(&seq, &CostMetric::CodeSize, 64), 6);
        // 2 + 2 = 4 bytes on x86-32.
        assert_eq!(sequence_cost(&seq, &CostMetric::CodeSize, 32), 4);
    }

    #[test]
    fn mov_imm_code_size_is_immediate_dependent() {
        let zero = X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        };
        let small = X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: i32::MAX as i64,
        };
        let big = X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: i64::MAX,
        };
        // x86-64: imm fitting i32 -> 7-byte `REX.W C7 /0 id`; full 64-bit imm
        // -> 10-byte `REX.W B8+rd io` movabs. (The old flat `5 + rex` = 6
        // underestimated both, breaking length-pruning soundness.)
        assert_eq!(instruction_cost(&zero, &CostMetric::CodeSize, 64), 7);
        assert_eq!(instruction_cost(&small, &CostMetric::CodeSize, 64), 7);
        assert_eq!(instruction_cost(&big, &CostMetric::CodeSize, 64), 10);
        // x86-32: `B8+rd id` is 5 bytes (no REX; the assembler rejects
        // immediates that do not fit imm32 rather than emitting movabs).
        assert_eq!(instruction_cost(&zero, &CostMetric::CodeSize, 32), 5);
        assert_eq!(instruction_cost(&small, &CostMetric::CodeSize, 32), 5);
    }

    // --- CMOV / Jcc cost ---

    #[test]
    fn cmov_code_size_includes_rex_on_64_bit() {
        use crate::isa::x86::X86Condition;
        let cmov = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        };
        // CMOV is `0F 4x ModR/M` = 3 bytes, +1 for REX.W on x86-64.
        assert_eq!(instruction_cost(&cmov, &CostMetric::CodeSize, 64), 4);
        assert_eq!(instruction_cost(&cmov, &CostMetric::CodeSize, 32), 3);
    }

    #[test]
    fn rotate_code_size_and_latency_mirror_shifts() {
        // ROL / ROR by imm8 are `C1 /n ib` = 3 bytes (+REX.W on x86-64 -> 4),
        // identical to the shifts; latency 1.
        for instr in [
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 3,
            },
            X86Instruction::Ror {
                rd: X86Register::RBX,
                imm: 5,
            },
        ] {
            // Mirror the shift cost exactly.
            let shift = X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 3,
            };
            assert_eq!(
                instruction_cost(&instr, &CostMetric::CodeSize, 64),
                instruction_cost(&shift, &CostMetric::CodeSize, 64),
            );
            assert_eq!(instruction_cost(&instr, &CostMetric::CodeSize, 64), 4);
            assert_eq!(instruction_cost(&instr, &CostMetric::CodeSize, 32), 3);
            assert_eq!(instruction_cost(&instr, &CostMetric::Latency, 64), 1);
        }
    }

    #[test]
    fn jcc_short_form_costs_two_bytes() {
        use crate::isa::x86::X86Condition;
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::NE,
        };
        // 0x7x + rel8 = 2 bytes regardless of mode.
        assert_eq!(instruction_cost(&jcc, &CostMetric::CodeSize, 64), 2);
        assert_eq!(instruction_cost(&jcc, &CostMetric::CodeSize, 32), 2);
    }
}
