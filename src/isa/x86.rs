//! x86 ISA backend (x86-64 primary, x86-32 secondary).
//!
//! Mirrors the dual-variant pattern of `src/isa/riscv.rs`: a single set of
//! `X86Register` / `X86Operand` / `X86Instruction` enums shared by the
//! `X86_64` and `X86_32` ISA marker structs.
//!
//! **Initial instruction set**: MOV, ADD, SUB, AND, OR, XOR, CMP — each with
//! register and immediate forms (14 variants total: 7 mnemonics × 2 forms).

#![allow(dead_code)]
// x86 register names are conventionally uppercase (RAX, RBX, ...) in every
// Intel/AMD manual, Capstone disassembly output, GAS/Intel syntax, and gdb
// `info registers`. Lowercasing to `Rax`/`Rbx` per Rust's default
// upper_case_acronyms lint would make the IR diverge from every external
// reference. Keep the uppercase names and silence the lint module-wide.
#![allow(clippy::upper_case_acronyms)]

use crate::isa::traits::{ISA, InstructionGenerator, InstructionType, OperandType, RegisterType};
use rand::{Rng, RngExt};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum X86Register {
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl X86Register {
    pub fn index(&self) -> Option<u8> {
        Some(match self {
            X86Register::RAX => 0,
            X86Register::RCX => 1,
            X86Register::RDX => 2,
            X86Register::RBX => 3,
            X86Register::RSP => 4,
            X86Register::RBP => 5,
            X86Register::RSI => 6,
            X86Register::RDI => 7,
            X86Register::R8 => 8,
            X86Register::R9 => 9,
            X86Register::R10 => 10,
            X86Register::R11 => 11,
            X86Register::R12 => 12,
            X86Register::R13 => 13,
            X86Register::R14 => 14,
            X86Register::R15 => 15,
        })
    }

    pub fn mnemonic(&self) -> &'static str {
        match self {
            X86Register::RAX => "rax",
            X86Register::RCX => "rcx",
            X86Register::RDX => "rdx",
            X86Register::RBX => "rbx",
            X86Register::RSP => "rsp",
            X86Register::RBP => "rbp",
            X86Register::RSI => "rsi",
            X86Register::RDI => "rdi",
            X86Register::R8 => "r8",
            X86Register::R9 => "r9",
            X86Register::R10 => "r10",
            X86Register::R11 => "r11",
            X86Register::R12 => "r12",
            X86Register::R13 => "r13",
            X86Register::R14 => "r14",
            X86Register::R15 => "r15",
        }
    }

    pub fn from_index(i: u8) -> Option<Self> {
        Some(match i {
            0 => X86Register::RAX,
            1 => X86Register::RCX,
            2 => X86Register::RDX,
            3 => X86Register::RBX,
            4 => X86Register::RSP,
            5 => X86Register::RBP,
            6 => X86Register::RSI,
            7 => X86Register::RDI,
            8 => X86Register::R8,
            9 => X86Register::R9,
            10 => X86Register::R10,
            11 => X86Register::R11,
            12 => X86Register::R12,
            13 => X86Register::R13,
            14 => X86Register::R14,
            15 => X86Register::R15,
            _ => return None,
        })
    }
}

impl fmt::Display for X86Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}

impl RegisterType for X86Register {
    fn index(&self) -> Option<u8> {
        X86Register::index(self)
    }

    fn from_index(idx: u8) -> Option<Self> {
        X86Register::from_index(idx)
    }

    fn is_zero_register(&self) -> bool {
        false
    }

    fn is_special(&self) -> bool {
        // Only RSP. RBP is not special — modern x86-64 ABIs do not require
        // a frame pointer, so excluding it would bias the search away from
        // valid scratch-register uses.
        matches!(self, X86Register::RSP)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum X86Operand {
    Register(X86Register),
    Immediate(i64),
}

impl fmt::Display for X86Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            X86Operand::Register(r) => write!(f, "{}", r),
            X86Operand::Immediate(imm) => write!(f, "{}", imm),
        }
    }
}

/// x86 instruction variants for the initial minimal core set.
///
/// **Intentional divergence from AArch64/RISC-V**: x86 arithmetic and
/// logic ops use the two-operand destructive form (`add rd, rs` reads
/// AND writes `rd`). `source_registers()` therefore includes `rd` for
/// these variants — see `validation::live_out::compute_live_in_registers`
/// for why this matters for liveness analysis. A future refactor that
/// "normalises" with the other ISAs (where `source_registers()` excludes
/// the destination) would silently regress liveness for x86.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum X86Instruction {
    /// `mov rd, rs` — non-destructive register copy; no EFLAGS effect.
    MovReg { rd: X86Register, rs: X86Register },
    /// `mov rd, imm` — load immediate; no EFLAGS effect.
    MovImm { rd: X86Register, imm: i64 },
    /// `add rd, rs` — `rd = rd + rs`; sets EFLAGS.
    AddReg { rd: X86Register, rs: X86Register },
    /// `add rd, imm` — `rd = rd + imm`; sets EFLAGS.
    AddImm { rd: X86Register, imm: i64 },
    /// `sub rd, rs` — `rd = rd - rs`; sets EFLAGS.
    SubReg { rd: X86Register, rs: X86Register },
    /// `sub rd, imm` — `rd = rd - imm`; sets EFLAGS.
    SubImm { rd: X86Register, imm: i64 },
    /// `and rd, rs` — `rd = rd & rs`; clears CF/OF, sets SF/ZF/PF.
    AndReg { rd: X86Register, rs: X86Register },
    /// `and rd, imm` — `rd = rd & imm`; clears CF/OF, sets SF/ZF/PF.
    AndImm { rd: X86Register, imm: i64 },
    /// `or rd, rs` — `rd = rd | rs`; clears CF/OF, sets SF/ZF/PF.
    OrReg { rd: X86Register, rs: X86Register },
    /// `or rd, imm` — `rd = rd | imm`; clears CF/OF, sets SF/ZF/PF.
    OrImm { rd: X86Register, imm: i64 },
    /// `xor rd, rs` — `rd = rd ^ rs`; clears CF/OF, sets SF/ZF/PF.
    XorReg { rd: X86Register, rs: X86Register },
    /// `xor rd, imm` — `rd = rd ^ imm`; clears CF/OF, sets SF/ZF/PF.
    XorImm { rd: X86Register, imm: i64 },
    /// `cmp rn, rs` — `rn - rs` discarding the result; sets EFLAGS.
    CmpReg { rn: X86Register, rs: X86Register },
    /// `cmp rn, imm` — `rn - imm` discarding the result; sets EFLAGS.
    CmpImm { rn: X86Register, imm: i64 },
}

impl X86Instruction {
    pub fn destination(&self) -> Option<X86Register> {
        match self {
            X86Instruction::MovReg { rd, .. }
            | X86Instruction::MovImm { rd, .. }
            | X86Instruction::AddReg { rd, .. }
            | X86Instruction::AddImm { rd, .. }
            | X86Instruction::SubReg { rd, .. }
            | X86Instruction::SubImm { rd, .. }
            | X86Instruction::AndReg { rd, .. }
            | X86Instruction::AndImm { rd, .. }
            | X86Instruction::OrReg { rd, .. }
            | X86Instruction::OrImm { rd, .. }
            | X86Instruction::XorReg { rd, .. }
            | X86Instruction::XorImm { rd, .. } => Some(*rd),
            X86Instruction::CmpReg { .. } | X86Instruction::CmpImm { .. } => None,
        }
    }

    pub fn mnemonic(&self) -> &'static str {
        match self {
            X86Instruction::MovReg { .. } | X86Instruction::MovImm { .. } => "mov",
            X86Instruction::AddReg { .. } | X86Instruction::AddImm { .. } => "add",
            X86Instruction::SubReg { .. } | X86Instruction::SubImm { .. } => "sub",
            X86Instruction::AndReg { .. } | X86Instruction::AndImm { .. } => "and",
            X86Instruction::OrReg { .. } | X86Instruction::OrImm { .. } => "or",
            X86Instruction::XorReg { .. } | X86Instruction::XorImm { .. } => "xor",
            X86Instruction::CmpReg { .. } | X86Instruction::CmpImm { .. } => "cmp",
        }
    }

    /// Registers this instruction reads.
    ///
    /// **x86 destructive-form divergence**: for `AddReg/SubReg/AndReg/OrReg/XorReg`
    /// and their immediate forms, `rd` is BOTH source and destination, so it
    /// appears here. `MovReg`/`MovImm` are non-destructive (rd is purely
    /// written), so rd is NOT in the source list. See the enum doc-comment.
    pub fn source_registers(&self) -> Vec<X86Register> {
        match self {
            X86Instruction::MovReg { rs, .. } => vec![*rs],
            X86Instruction::MovImm { .. } => vec![],
            X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => vec![*rd, *rs],
            X86Instruction::AddImm { rd, .. }
            | X86Instruction::SubImm { rd, .. }
            | X86Instruction::AndImm { rd, .. }
            | X86Instruction::OrImm { rd, .. }
            | X86Instruction::XorImm { rd, .. } => vec![*rd],
            X86Instruction::CmpReg { rn, rs } => vec![*rn, *rs],
            X86Instruction::CmpImm { rn, .. } => vec![*rn],
        }
    }
}

impl InstructionType for X86Instruction {
    type Register = X86Register;
    type Operand = X86Operand;

    fn destination(&self) -> Option<X86Register> {
        X86Instruction::destination(self)
    }

    fn source_registers(&self) -> Vec<X86Register> {
        X86Instruction::source_registers(self)
    }

    fn opcode_id(&self) -> u8 {
        match self {
            X86Instruction::MovReg { .. } => 0,
            X86Instruction::MovImm { .. } => 1,
            X86Instruction::AddReg { .. } => 2,
            X86Instruction::AddImm { .. } => 3,
            X86Instruction::SubReg { .. } => 4,
            X86Instruction::SubImm { .. } => 5,
            X86Instruction::AndReg { .. } => 6,
            X86Instruction::AndImm { .. } => 7,
            X86Instruction::OrReg { .. } => 8,
            X86Instruction::OrImm { .. } => 9,
            X86Instruction::XorReg { .. } => 10,
            X86Instruction::XorImm { .. } => 11,
            X86Instruction::CmpReg { .. } => 12,
            X86Instruction::CmpImm { .. } => 13,
        }
    }

    fn mnemonic(&self) -> &'static str {
        X86Instruction::mnemonic(self)
    }

    fn has_side_effects(&self) -> bool {
        // x86 MOV does not touch EFLAGS. Every other variant in the minimal
        // core set sets or clobbers flag bits, which is observable state
        // beyond the destination register.
        !matches!(
            self,
            X86Instruction::MovReg { .. } | X86Instruction::MovImm { .. }
        )
    }
}

impl fmt::Display for X86Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mn = self.mnemonic();
        match self {
            X86Instruction::MovReg { rd, rs }
            | X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => write!(f, "{} {}, {}", mn, rd, rs),
            X86Instruction::MovImm { rd, imm }
            | X86Instruction::AddImm { rd, imm }
            | X86Instruction::SubImm { rd, imm }
            | X86Instruction::AndImm { rd, imm }
            | X86Instruction::OrImm { rd, imm }
            | X86Instruction::XorImm { rd, imm } => write!(f, "{} {}, {}", mn, rd, imm),
            X86Instruction::CmpReg { rn, rs } => write!(f, "{} {}, {}", mn, rn, rs),
            X86Instruction::CmpImm { rn, imm } => write!(f, "{} {}, {}", mn, rn, imm),
        }
    }
}

/// Marker type for the x86-64 ISA. Shares the `X86Register` / `X86Operand`
/// / `X86Instruction` enums with `X86_32`; differs only in metadata.
#[derive(Clone, Copy, Debug, Default)]
pub struct X86_64;

impl ISA for X86_64 {
    type Register = X86Register;
    type Operand = X86Operand;
    type Instruction = X86Instruction;

    fn name(&self) -> &'static str {
        "x86-64"
    }

    fn register_count(&self) -> usize {
        16
    }

    fn register_width(&self) -> u32 {
        64
    }

    fn instruction_size(&self) -> Option<usize> {
        // x86 is variable-length.
        None
    }

    fn general_registers(&self) -> Vec<X86Register> {
        // Return all 16 GPRs including RSP — matches the RISC-V pattern
        // where general_registers() does not pre-filter is_special. CLI
        // is responsible for excluding RSP from the search-available pool.
        (0..16u8).filter_map(X86Register::from_index).collect()
    }

    fn zero_register(&self) -> Option<X86Register> {
        None
    }
}

/// Marker type for the x86-32 (i386) ISA. Shares enums with `X86_64`,
/// differs in register width (32) and the GPR set (low 8 only).
#[derive(Clone, Copy, Debug, Default)]
pub struct X86_32;

impl ISA for X86_32 {
    type Register = X86Register;
    type Operand = X86Operand;
    type Instruction = X86Instruction;

    fn name(&self) -> &'static str {
        "x86-32"
    }

    fn register_count(&self) -> usize {
        8
    }

    fn register_width(&self) -> u32 {
        32
    }

    fn instruction_size(&self) -> Option<usize> {
        None
    }

    fn general_registers(&self) -> Vec<X86Register> {
        (0..8u8).filter_map(X86Register::from_index).collect()
    }

    fn zero_register(&self) -> Option<X86Register> {
        None
    }
}

/// Stateless generator producing every reg/imm combination of the 14 x86
/// variants for a given register and immediate pool. Mirrors
/// `RiscVInstructionGenerator` in shape and complexity.
#[derive(Clone, Copy, Debug, Default)]
pub struct X86InstructionGenerator;

const X86_OPCODE_COUNT: u8 = 14;

impl InstructionGenerator<X86Instruction> for X86InstructionGenerator {
    fn generate_all(&self, registers: &[X86Register], immediates: &[i64]) -> Vec<X86Instruction> {
        let mut out = Vec::new();
        // Register-register variants (7 mnemonics).
        for &rd in registers {
            for &rs in registers {
                out.push(X86Instruction::MovReg { rd, rs });
                out.push(X86Instruction::AddReg { rd, rs });
                out.push(X86Instruction::SubReg { rd, rs });
                out.push(X86Instruction::AndReg { rd, rs });
                out.push(X86Instruction::OrReg { rd, rs });
                out.push(X86Instruction::XorReg { rd, rs });
                out.push(X86Instruction::CmpReg { rn: rd, rs });
            }
        }
        // Register-immediate variants (7 mnemonics).
        for &rd in registers {
            for &imm in immediates {
                out.push(X86Instruction::MovImm { rd, imm });
                out.push(X86Instruction::AddImm { rd, imm });
                out.push(X86Instruction::SubImm { rd, imm });
                out.push(X86Instruction::AndImm { rd, imm });
                out.push(X86Instruction::OrImm { rd, imm });
                out.push(X86Instruction::XorImm { rd, imm });
                out.push(X86Instruction::CmpImm { rn: rd, imm });
            }
        }
        out
    }

    fn generate_random<R: Rng>(
        &self,
        rng: &mut R,
        registers: &[X86Register],
        immediates: &[i64],
    ) -> X86Instruction {
        let opcode = rng.random_range(0..X86_OPCODE_COUNT);
        let rd = registers[rng.random_range(0..registers.len())];
        let rs = registers[rng.random_range(0..registers.len())];
        let imm = immediates[rng.random_range(0..immediates.len())];
        match opcode {
            0 => X86Instruction::MovReg { rd, rs },
            1 => X86Instruction::MovImm { rd, imm },
            2 => X86Instruction::AddReg { rd, rs },
            3 => X86Instruction::AddImm { rd, imm },
            4 => X86Instruction::SubReg { rd, rs },
            5 => X86Instruction::SubImm { rd, imm },
            6 => X86Instruction::AndReg { rd, rs },
            7 => X86Instruction::AndImm { rd, imm },
            8 => X86Instruction::OrReg { rd, rs },
            9 => X86Instruction::OrImm { rd, imm },
            10 => X86Instruction::XorReg { rd, rs },
            11 => X86Instruction::XorImm { rd, imm },
            12 => X86Instruction::CmpReg { rn: rd, rs },
            13 => X86Instruction::CmpImm { rn: rd, imm },
            _ => unreachable!("opcode out of range"),
        }
    }

    fn mutate<R: Rng>(
        &self,
        rng: &mut R,
        instruction: &X86Instruction,
        registers: &[X86Register],
        immediates: &[i64],
    ) -> X86Instruction {
        // Three strategies, matching the RISC-V mutator:
        //   0: completely fresh instruction (opcode change)
        //   1: keep opcode + sources, change destination
        //   2: keep opcode + destination, change sources/immediate
        match rng.random_range(0..3) {
            0 => self.generate_random(rng, registers, immediates),
            1 => {
                let new_rd = registers[rng.random_range(0..registers.len())];
                with_destination(*instruction, new_rd)
            }
            2 => {
                let new_rs = registers[rng.random_range(0..registers.len())];
                let new_imm = immediates[rng.random_range(0..immediates.len())];
                with_sources(*instruction, new_rs, new_imm)
            }
            _ => unreachable!(),
        }
    }

    fn opcode_count(&self) -> u8 {
        X86_OPCODE_COUNT
    }
}

fn with_destination(instr: X86Instruction, new_rd: X86Register) -> X86Instruction {
    match instr {
        X86Instruction::MovReg { rs, .. } => X86Instruction::MovReg { rd: new_rd, rs },
        X86Instruction::MovImm { imm, .. } => X86Instruction::MovImm { rd: new_rd, imm },
        X86Instruction::AddReg { rs, .. } => X86Instruction::AddReg { rd: new_rd, rs },
        X86Instruction::AddImm { imm, .. } => X86Instruction::AddImm { rd: new_rd, imm },
        X86Instruction::SubReg { rs, .. } => X86Instruction::SubReg { rd: new_rd, rs },
        X86Instruction::SubImm { imm, .. } => X86Instruction::SubImm { rd: new_rd, imm },
        X86Instruction::AndReg { rs, .. } => X86Instruction::AndReg { rd: new_rd, rs },
        X86Instruction::AndImm { imm, .. } => X86Instruction::AndImm { rd: new_rd, imm },
        X86Instruction::OrReg { rs, .. } => X86Instruction::OrReg { rd: new_rd, rs },
        X86Instruction::OrImm { imm, .. } => X86Instruction::OrImm { rd: new_rd, imm },
        X86Instruction::XorReg { rs, .. } => X86Instruction::XorReg { rd: new_rd, rs },
        X86Instruction::XorImm { imm, .. } => X86Instruction::XorImm { rd: new_rd, imm },
        // CMP variants have rn instead of rd; mutate rn for symmetry.
        X86Instruction::CmpReg { rs, .. } => X86Instruction::CmpReg { rn: new_rd, rs },
        X86Instruction::CmpImm { imm, .. } => X86Instruction::CmpImm { rn: new_rd, imm },
    }
}

fn with_sources(instr: X86Instruction, new_rs: X86Register, new_imm: i64) -> X86Instruction {
    match instr {
        X86Instruction::MovReg { rd, .. } => X86Instruction::MovReg { rd, rs: new_rs },
        X86Instruction::MovImm { rd, .. } => X86Instruction::MovImm { rd, imm: new_imm },
        X86Instruction::AddReg { rd, .. } => X86Instruction::AddReg { rd, rs: new_rs },
        X86Instruction::AddImm { rd, .. } => X86Instruction::AddImm { rd, imm: new_imm },
        X86Instruction::SubReg { rd, .. } => X86Instruction::SubReg { rd, rs: new_rs },
        X86Instruction::SubImm { rd, .. } => X86Instruction::SubImm { rd, imm: new_imm },
        X86Instruction::AndReg { rd, .. } => X86Instruction::AndReg { rd, rs: new_rs },
        X86Instruction::AndImm { rd, .. } => X86Instruction::AndImm { rd, imm: new_imm },
        X86Instruction::OrReg { rd, .. } => X86Instruction::OrReg { rd, rs: new_rs },
        X86Instruction::OrImm { rd, .. } => X86Instruction::OrImm { rd, imm: new_imm },
        X86Instruction::XorReg { rd, .. } => X86Instruction::XorReg { rd, rs: new_rs },
        X86Instruction::XorImm { rd, .. } => X86Instruction::XorImm { rd, imm: new_imm },
        X86Instruction::CmpReg { rn, .. } => X86Instruction::CmpReg { rn, rs: new_rs },
        X86Instruction::CmpImm { rn, .. } => X86Instruction::CmpImm { rn, imm: new_imm },
    }
}

impl OperandType for X86Operand {
    type Register = X86Register;

    fn as_register(&self) -> Option<X86Register> {
        match self {
            X86Operand::Register(r) => Some(*r),
            _ => None,
        }
    }

    fn as_immediate(&self) -> Option<i64> {
        match self {
            X86Operand::Immediate(imm) => Some(*imm),
            _ => None,
        }
    }

    fn from_register(reg: X86Register) -> Self {
        X86Operand::Register(reg)
    }

    fn from_immediate(imm: i64) -> Self {
        X86Operand::Immediate(imm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_generator_generate_all_covers_every_opcode() {
        use crate::isa::traits::{InstructionGenerator, InstructionType};
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1, -1];
        let all = X86InstructionGenerator.generate_all(&regs, &imms);

        // For each opcode_id, at least one variant must appear.
        let opcode_count = X86InstructionGenerator.opcode_count();
        let mut seen = vec![false; opcode_count as usize];
        for instr in &all {
            seen[instr.opcode_id() as usize] = true;
        }
        for (id, present) in seen.iter().enumerate() {
            assert!(*present, "opcode_id {} never generated", id);
        }

        // Sanity: every generated instruction's destination (if any) is
        // drawn from the supplied register pool, and source registers too.
        for instr in &all {
            if let Some(dst) = instr.destination() {
                assert!(regs.contains(&dst));
            }
            for src in instr.source_registers() {
                assert!(regs.contains(&src));
            }
        }
    }

    #[test]
    fn x86_generator_random_within_opcode_range() {
        use crate::isa::traits::{InstructionGenerator, InstructionType};
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let regs = [X86Register::RAX, X86Register::RBX, X86Register::RCX];
        let imms = [0i64, 1];
        let count = X86InstructionGenerator.opcode_count();
        for _ in 0..200 {
            let instr = X86InstructionGenerator.generate_random(&mut rng, &regs, &imms);
            assert!(
                instr.opcode_id() < count,
                "{} out of range",
                instr.opcode_id()
            );
        }
    }

    #[test]
    fn x86_generator_mutate_changes_instruction() {
        use crate::isa::traits::{InstructionGenerator, InstructionType};
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1, 2, 3];
        // Mutator can mutate any starting variant without panicking,
        // and the result is always a valid opcode.
        let start = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let count = X86InstructionGenerator.opcode_count();
        for _ in 0..50 {
            let mutated = X86InstructionGenerator.mutate(&mut rng, &start, &regs, &imms);
            assert!(mutated.opcode_id() < count);
        }
    }

    #[test]
    fn x86_32_isa_metadata() {
        use crate::isa::traits::ISA;
        let isa = X86_32;
        assert_eq!(isa.name(), "x86-32");
        // i386 ABI exposes the low 8 GPRs.
        assert_eq!(isa.register_count(), 8);
        assert_eq!(isa.register_width(), 32);
        assert_eq!(isa.instruction_size(), None);
        assert_eq!(isa.zero_register(), None);
        let regs = isa.general_registers();
        assert_eq!(regs.len(), 8);
        for i in 0..8u8 {
            assert!(regs.contains(&X86Register::from_index(i).unwrap()));
        }
        // R8..R15 are absent from x86-32.
        for i in 8..16u8 {
            assert!(!regs.contains(&X86Register::from_index(i).unwrap()));
        }
    }

    #[test]
    fn x86_64_isa_metadata() {
        use crate::isa::traits::ISA;
        let isa = X86_64;
        assert_eq!(isa.name(), "x86-64");
        assert_eq!(isa.register_count(), 16);
        assert_eq!(isa.register_width(), 64);
        // Variable-length encoding.
        assert_eq!(isa.instruction_size(), None);
        assert_eq!(isa.zero_register(), None);
        let regs = isa.general_registers();
        // All 16 GPRs surface; CLI is responsible for filtering RSP from the
        // search-available pool (mirroring main.rs:479-488 for AArch64).
        assert_eq!(regs.len(), 16);
        for i in 0..16u8 {
            assert!(regs.contains(&X86Register::from_index(i).unwrap()));
        }
    }

    #[test]
    fn x86_instruction_type_trait_conformance() {
        use crate::isa::traits::InstructionType;
        let rd = X86Register::RAX;
        let rs = X86Register::RBX;
        let variants = [
            X86Instruction::MovReg { rd, rs },
            X86Instruction::MovImm { rd, imm: 0 },
            X86Instruction::AddReg { rd, rs },
            X86Instruction::AddImm { rd, imm: 0 },
            X86Instruction::SubReg { rd, rs },
            X86Instruction::SubImm { rd, imm: 0 },
            X86Instruction::AndReg { rd, rs },
            X86Instruction::AndImm { rd, imm: 0 },
            X86Instruction::OrReg { rd, rs },
            X86Instruction::OrImm { rd, imm: 0 },
            X86Instruction::XorReg { rd, rs },
            X86Instruction::XorImm { rd, imm: 0 },
            X86Instruction::CmpReg { rn: rd, rs },
            X86Instruction::CmpImm { rn: rd, imm: 0 },
        ];

        // 7 mnemonics × {reg, imm} forms = 14 variants.
        assert_eq!(variants.len(), 14);
        let ids: Vec<u8> = variants
            .iter()
            .map(<X86Instruction as InstructionType>::opcode_id)
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ids.len(),
            "opcode_id values must be unique: {:?}",
            ids
        );

        // mnemonic via trait equals inherent.
        for v in variants.iter() {
            assert_eq!(
                <X86Instruction as InstructionType>::mnemonic(v),
                v.mnemonic()
            );
        }

        // EFLAGS side-effects: every variant except MOV mutates EFLAGS.
        for v in variants.iter() {
            let is_mov = matches!(
                v,
                X86Instruction::MovReg { .. } | X86Instruction::MovImm { .. }
            );
            assert_eq!(
                <X86Instruction as InstructionType>::has_side_effects(v),
                !is_mov,
                "has_side_effects wrong for {:?}",
                v
            );
        }
    }

    #[test]
    fn x86_instruction_display_intel_syntax() {
        let rd = X86Register::RAX;
        let rs = X86Register::RBX;
        let cases: &[(X86Instruction, &str)] = &[
            (X86Instruction::MovReg { rd, rs }, "mov rax, rbx"),
            (X86Instruction::MovImm { rd, imm: 42 }, "mov rax, 42"),
            (X86Instruction::AddReg { rd, rs }, "add rax, rbx"),
            (X86Instruction::AddImm { rd, imm: -1 }, "add rax, -1"),
            (X86Instruction::SubReg { rd, rs }, "sub rax, rbx"),
            (X86Instruction::SubImm { rd, imm: 1 }, "sub rax, 1"),
            (X86Instruction::AndReg { rd, rs }, "and rax, rbx"),
            (X86Instruction::AndImm { rd, imm: 0xff }, "and rax, 255"),
            (X86Instruction::OrReg { rd, rs }, "or rax, rbx"),
            (X86Instruction::OrImm { rd, imm: 0 }, "or rax, 0"),
            (X86Instruction::XorReg { rd, rs }, "xor rax, rbx"),
            (X86Instruction::XorImm { rd, imm: 1 }, "xor rax, 1"),
            (X86Instruction::CmpReg { rn: rd, rs }, "cmp rax, rbx"),
            (X86Instruction::CmpImm { rn: rd, imm: 7 }, "cmp rax, 7"),
        ];
        for (instr, expected) in cases {
            assert_eq!(format!("{}", instr), *expected);
        }
    }

    #[test]
    fn x86_instruction_mnemonic_matches_display_prefix() {
        let rd = X86Register::RAX;
        let rs = X86Register::RBX;
        let cases: &[(X86Instruction, &str)] = &[
            (X86Instruction::MovReg { rd, rs }, "mov"),
            (X86Instruction::MovImm { rd, imm: 0 }, "mov"),
            (X86Instruction::AddReg { rd, rs }, "add"),
            (X86Instruction::AddImm { rd, imm: 0 }, "add"),
            (X86Instruction::SubReg { rd, rs }, "sub"),
            (X86Instruction::SubImm { rd, imm: 0 }, "sub"),
            (X86Instruction::AndReg { rd, rs }, "and"),
            (X86Instruction::AndImm { rd, imm: 0 }, "and"),
            (X86Instruction::OrReg { rd, rs }, "or"),
            (X86Instruction::OrImm { rd, imm: 0 }, "or"),
            (X86Instruction::XorReg { rd, rs }, "xor"),
            (X86Instruction::XorImm { rd, imm: 0 }, "xor"),
            (X86Instruction::CmpReg { rn: rd, rs }, "cmp"),
            (X86Instruction::CmpImm { rn: rd, imm: 0 }, "cmp"),
        ];
        for (instr, expected) in cases {
            assert_eq!(instr.mnemonic(), *expected);
        }
    }

    #[test]
    fn x86_instruction_source_registers_destructive_form() {
        let rd = X86Register::RAX;
        let rs = X86Register::RBX;
        // MOV is non-destructive: rd not in sources.
        assert_eq!(
            X86Instruction::MovReg { rd, rs }.source_registers(),
            vec![rs]
        );
        assert_eq!(
            X86Instruction::MovImm { rd, imm: 7 }.source_registers(),
            Vec::<X86Register>::new()
        );
        // Two-operand destructive arithmetic/logic: rd is BOTH source and dest.
        let reg_destructive = [
            X86Instruction::AddReg { rd, rs },
            X86Instruction::SubReg { rd, rs },
            X86Instruction::AndReg { rd, rs },
            X86Instruction::OrReg { rd, rs },
            X86Instruction::XorReg { rd, rs },
        ];
        for instr in reg_destructive {
            assert_eq!(
                instr.source_registers(),
                vec![rd, rs],
                "expected [rd, rs] for {:?}",
                instr
            );
        }
        // Immediate forms still read rd (destructive).
        let imm_destructive = [
            X86Instruction::AddImm { rd, imm: 1 },
            X86Instruction::SubImm { rd, imm: 1 },
            X86Instruction::AndImm { rd, imm: 1 },
            X86Instruction::OrImm { rd, imm: 1 },
            X86Instruction::XorImm { rd, imm: 1 },
        ];
        for instr in imm_destructive {
            assert_eq!(
                instr.source_registers(),
                vec![rd],
                "expected [rd] for {:?}",
                instr
            );
        }
        // CMP reads both registers (or just rn for immediate form), writes none.
        assert_eq!(
            X86Instruction::CmpReg { rn: rd, rs }.source_registers(),
            vec![rd, rs]
        );
        assert_eq!(
            X86Instruction::CmpImm { rn: rd, imm: 0 }.source_registers(),
            vec![rd]
        );
    }

    #[test]
    fn x86_instruction_destination_writes_rd() {
        // MOV / ADD / SUB / AND / OR / XOR variants write rd.
        let rd = X86Register::RAX;
        let rs = X86Register::RBX;
        let cases: &[(X86Instruction, Option<X86Register>)] = &[
            (X86Instruction::MovReg { rd, rs }, Some(rd)),
            (X86Instruction::MovImm { rd, imm: 0 }, Some(rd)),
            (X86Instruction::AddReg { rd, rs }, Some(rd)),
            (X86Instruction::AddImm { rd, imm: 0 }, Some(rd)),
            (X86Instruction::SubReg { rd, rs }, Some(rd)),
            (X86Instruction::SubImm { rd, imm: 0 }, Some(rd)),
            (X86Instruction::AndReg { rd, rs }, Some(rd)),
            (X86Instruction::AndImm { rd, imm: 0 }, Some(rd)),
            (X86Instruction::OrReg { rd, rs }, Some(rd)),
            (X86Instruction::OrImm { rd, imm: 0 }, Some(rd)),
            (X86Instruction::XorReg { rd, rs }, Some(rd)),
            (X86Instruction::XorImm { rd, imm: 0 }, Some(rd)),
            // CMP variants never write a register.
            (X86Instruction::CmpReg { rn: rd, rs }, None),
            (X86Instruction::CmpImm { rn: rd, imm: 0 }, None),
        ];
        for (instr, want) in cases {
            assert_eq!(
                instr.destination(),
                *want,
                "destination wrong for {:?}",
                instr
            );
        }
    }

    #[test]
    fn x86_operand_display_intel_syntax() {
        assert_eq!(format!("{}", X86Operand::Register(X86Register::RAX)), "rax");
        // Intel syntax: bare integer for immediates (no '#' or '$').
        assert_eq!(format!("{}", X86Operand::Immediate(42)), "42");
        assert_eq!(format!("{}", X86Operand::Immediate(-1)), "-1");
    }

    #[test]
    fn x86_operand_type_trait_conformance() {
        use crate::isa::traits::OperandType;
        let r = X86Operand::Register(X86Register::RDI);
        let imm = X86Operand::Immediate(7);
        assert_eq!(r.as_register(), Some(X86Register::RDI));
        assert_eq!(r.as_immediate(), None);
        assert!(r.is_register());
        assert!(!r.is_immediate());
        assert_eq!(imm.as_register(), None);
        assert_eq!(imm.as_immediate(), Some(7));
        assert!(!imm.is_register());
        assert!(imm.is_immediate());
        // Constructors.
        assert_eq!(
            X86Operand::from_register(X86Register::RAX),
            X86Operand::Register(X86Register::RAX)
        );
        assert_eq!(X86Operand::from_immediate(-9), X86Operand::Immediate(-9));
    }

    #[test]
    fn x86_register_type_trait_conformance() {
        use crate::isa::traits::RegisterType;
        // No x86 GPR is a zero register (no hard-coded zero like XZR / x0).
        for i in 0..16u8 {
            let r = X86Register::from_index(i).unwrap();
            assert!(!r.is_zero_register(), "{:?} should not be zero reg", r);
        }
        // Only RSP is special; RBP is NOT special (no frame-pointer assumption).
        for i in 0..16u8 {
            let r = X86Register::from_index(i).unwrap();
            let expected_special = r == X86Register::RSP;
            assert_eq!(
                r.is_special(),
                expected_special,
                "is_special wrong for {:?}",
                r
            );
        }
        // Trait index() matches inherent index().
        assert_eq!(
            <X86Register as RegisterType>::index(&X86Register::R8),
            Some(8)
        );
        // Trait from_index matches inherent.
        assert_eq!(
            <X86Register as RegisterType>::from_index(15),
            Some(X86Register::R15)
        );
    }

    #[test]
    fn x86_register_display_lowercase_intel() {
        let cases = [
            (X86Register::RAX, "rax"),
            (X86Register::RCX, "rcx"),
            (X86Register::RDX, "rdx"),
            (X86Register::RBX, "rbx"),
            (X86Register::RSP, "rsp"),
            (X86Register::RBP, "rbp"),
            (X86Register::RSI, "rsi"),
            (X86Register::RDI, "rdi"),
            (X86Register::R8, "r8"),
            (X86Register::R9, "r9"),
            (X86Register::R10, "r10"),
            (X86Register::R11, "r11"),
            (X86Register::R12, "r12"),
            (X86Register::R13, "r13"),
            (X86Register::R14, "r14"),
            (X86Register::R15, "r15"),
        ];
        for (r, expected) in cases {
            assert_eq!(format!("{}", r), expected);
        }
    }

    #[test]
    fn x86_register_index_intel_order() {
        assert_eq!(X86Register::RAX.index(), Some(0));
        assert_eq!(X86Register::RCX.index(), Some(1));
        assert_eq!(X86Register::RDX.index(), Some(2));
        assert_eq!(X86Register::RBX.index(), Some(3));
        assert_eq!(X86Register::RSP.index(), Some(4));
        assert_eq!(X86Register::RBP.index(), Some(5));
        assert_eq!(X86Register::RSI.index(), Some(6));
        assert_eq!(X86Register::RDI.index(), Some(7));
        assert_eq!(X86Register::R8.index(), Some(8));
        assert_eq!(X86Register::R9.index(), Some(9));
        assert_eq!(X86Register::R10.index(), Some(10));
        assert_eq!(X86Register::R11.index(), Some(11));
        assert_eq!(X86Register::R12.index(), Some(12));
        assert_eq!(X86Register::R13.index(), Some(13));
        assert_eq!(X86Register::R14.index(), Some(14));
        assert_eq!(X86Register::R15.index(), Some(15));
    }

    #[test]
    fn x86_register_from_index_round_trip() {
        for i in 0..16u8 {
            let r = X86Register::from_index(i).expect("valid index");
            assert_eq!(r.index(), Some(i));
        }
        assert!(X86Register::from_index(16).is_none());
        assert!(X86Register::from_index(255).is_none());
    }
}
