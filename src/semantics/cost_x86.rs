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
/// - MOV reg, imm32: opcode + ModR/M + 4-byte imm = 6 bytes (x86-32)
///   or 7 bytes (x86-64 with REX.W); for full 64-bit immediates the
///   MOV reg, imm64 encoding takes 10 bytes — we use 7 as an upper
///   bound for small/sign-extendable immediates and document the
///   approximation.
fn instruction_code_size(instr: &X86Instruction, width: u32) -> u64 {
    let rex = if width == 64 { 1 } else { 0 };
    match instr {
        X86Instruction::MovReg { .. } => 2 + rex,
        X86Instruction::MovImm { .. } => 5 + rex,
        X86Instruction::AddReg { .. }
        | X86Instruction::SubReg { .. }
        | X86Instruction::AndReg { .. }
        | X86Instruction::OrReg { .. }
        | X86Instruction::XorReg { .. }
        | X86Instruction::CmpReg { .. } => 2 + rex,
        X86Instruction::AddImm { .. }
        | X86Instruction::SubImm { .. }
        | X86Instruction::AndImm { .. }
        | X86Instruction::OrImm { .. }
        | X86Instruction::XorImm { .. }
        | X86Instruction::CmpImm { .. } => 6 + rex,
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
}
