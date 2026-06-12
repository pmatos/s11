//! x86 ISA backend (x86-64 primary, x86-32 secondary).
//!
//! Mirrors the dual-variant pattern of `src/isa/riscv.rs`: a single set of
//! `X86Register` / `X86Operand` / `X86Instruction` enums shared by the
//! `X86_64` and `X86_32` ISA marker structs.
//!
//! **Initial instruction set**: MOV, ADD, SUB, AND, OR, XOR, CMP — each with
//! register and immediate forms — plus rewritable CMOVcc and fixed Jcc
//! terminators.

// x86 register names are conventionally uppercase (RAX, RBX, ...) in every
// Intel/AMD manual, Capstone disassembly output, GAS/Intel syntax, and gdb
// `info registers`. Lowercasing to `Rax`/`Rbx` per Rust's default
// upper_case_acronyms lint would make the IR diverge from every external
// reference. Keep the uppercase names and silence the lint module-wide.
#![allow(clippy::upper_case_acronyms)]

use crate::isa::traits::{ISA, InstructionGenerator, InstructionType, OperandType, RegisterType};
use rand::{Rng, RngExt};
use std::fmt;

/// x86 condition codes consumed by CMOVcc / Jcc.
///
/// The 16 canonical codes here cover every short-form jump / cmov GAS
/// emits. Aliases (`NB` for `AE`, `Z` for `E`, etc.) are normalized to
/// the canonical variant by the parser, not represented here.
///
/// Kept distinct from AArch64's `Condition` because (a) x86's CF on
/// subtraction has inverted polarity vs AArch64's C, and (b) the
/// mnemonics differ (`e`/`ne` vs `eq`/`ne`), so a shared enum would
/// invite cross-arch bugs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum X86Condition {
    E,  // equal / zero            (ZF=1)
    NE, // not equal / not zero    (ZF=0)
    B,  // below   (unsigned <)    (CF=1)
    AE, // above-or-equal          (CF=0)
    BE, // below-or-equal          (CF=1 | ZF=1)
    A,  // above                   (CF=0 & ZF=0)
    L,  // less    (signed <)      (SF!=OF)
    GE, // greater-or-equal        (SF==OF)
    LE, // less-or-equal           (ZF=1 | SF!=OF)
    G,  // greater                 (ZF=0 & SF==OF)
    S,  // sign (negative)         (SF=1)
    NS, // not sign                (SF=0)
    O,  // overflow                (OF=1)
    NO, // not overflow            (OF=0)
    P,  // parity-even             (PF=1)
    NP, // parity-odd              (PF=0)
}

impl X86Condition {
    pub const ALL: [Self; 16] = [
        Self::E,
        Self::NE,
        Self::B,
        Self::AE,
        Self::BE,
        Self::A,
        Self::L,
        Self::GE,
        Self::LE,
        Self::G,
        Self::S,
        Self::NS,
        Self::O,
        Self::NO,
        Self::P,
        Self::NP,
    ];
}

impl fmt::Display for X86Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            X86Condition::E => "e",
            X86Condition::NE => "ne",
            X86Condition::B => "b",
            X86Condition::AE => "ae",
            X86Condition::BE => "be",
            X86Condition::A => "a",
            X86Condition::L => "l",
            X86Condition::GE => "ge",
            X86Condition::LE => "le",
            X86Condition::G => "g",
            X86Condition::S => "s",
            X86Condition::NS => "ns",
            X86Condition::O => "o",
            X86Condition::NO => "no",
            X86Condition::P => "p",
            X86Condition::NP => "np",
        };
        f.write_str(s)
    }
}

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
    /// `cmovCC rd, rs` — conditional move. Reads EFLAGS;
    /// when `cond` holds, writes `rd = rs`; otherwise `rd` is unchanged.
    /// Does not modify EFLAGS.
    Cmov {
        rd: X86Register,
        rs: X86Register,
        cond: X86Condition,
    },
    /// `jCC <target>` — conditional branch. Reads EFLAGS;
    /// modelled as an opaque terminator. The branch target is recovered
    /// from the surrounding ELF disassembly and is not carried in the IR
    /// — search holds terminators fixed (see `split_terminator_x86`).
    Jcc { cond: X86Condition },
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
            | X86Instruction::XorImm { rd, .. }
            | X86Instruction::Cmov { rd, .. } => Some(*rd),
            X86Instruction::CmpReg { .. }
            | X86Instruction::CmpImm { .. }
            | X86Instruction::Jcc { .. } => None,
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
            X86Instruction::Cmov { .. } => "cmov",
            X86Instruction::Jcc { .. } => "jcc",
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
            // Cmov reads both rd (kept on false branch) and rs.
            X86Instruction::Cmov { rd, rs, .. } => vec![*rd, *rs],
            X86Instruction::Jcc { .. } => vec![],
        }
    }

    /// Whether this instruction transfers control out of the
    /// optimization window. Jcc terminators are held fixed by
    /// `split_terminator_x86`; the search never synthesizes them.
    pub fn is_terminator(&self) -> bool {
        matches!(self, X86Instruction::Jcc { .. })
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
            X86Instruction::Cmov { .. } => 14,
            X86Instruction::Jcc { .. } => 15,
        }
    }

    fn mnemonic(&self) -> &'static str {
        X86Instruction::mnemonic(self)
    }

    fn has_side_effects(&self) -> bool {
        // MOV / CMOV / Jcc do not write EFLAGS (CMOV and Jcc read them,
        // but reading is not a side effect on observable state). Every
        // other variant sets or clobbers flag bits, which is observable
        // state beyond the destination register.
        !matches!(
            self,
            X86Instruction::MovReg { .. }
                | X86Instruction::MovImm { .. }
                | X86Instruction::Cmov { .. }
                | X86Instruction::Jcc { .. }
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
            // Render as e.g. `cmove rax, rbx` (mnemonic + condition suffix).
            X86Instruction::Cmov { rd, rs, cond } => write!(f, "cmov{} {}, {}", cond, rd, rs),
            // Target is opaque to the IR; render with a placeholder.
            X86Instruction::Jcc { cond } => write!(f, "j{} <target>", cond),
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
    type Width = crate::isa::traits::U64;
    type Flags = crate::semantics::state::Eflags;
    type Mutator = X86Mutator;

    fn name(&self) -> &'static str {
        "x86-64"
    }

    fn register_count(&self) -> usize {
        16
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
    type Width = crate::isa::traits::U32;
    type Flags = crate::semantics::state::Eflags;
    type Mutator = X86Mutator;

    fn name(&self) -> &'static str {
        "x86-32"
    }

    fn register_count(&self) -> usize {
        8
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

/// Helper used by both `FlagsAnalysis<X86Instruction> for X86_64` and
/// `for X86_32`. MOV / CMOV / Jcc do not write EFLAGS — CMOV and Jcc
/// read them via `x86_reads_flags` but do not modify any flag bit.
/// Every other variant in the current set writes EFLAGS.
fn x86_modifies_flags(instr: &X86Instruction) -> bool {
    !matches!(
        instr,
        X86Instruction::MovReg { .. }
            | X86Instruction::MovImm { .. }
            | X86Instruction::Cmov { .. }
            | X86Instruction::Jcc { .. }
    )
}

/// CMOV and Jcc read EFLAGS; every other variant in the current set
/// is flag-agnostic on the read side. Crate-visible so external
/// callers (e.g. `find_shorter_equivalent_x86`) can route through one
/// authoritative match arm — adding a future flag-reader like SETcc
/// then updates exactly one place.
pub fn x86_reads_flags(instr: &X86Instruction) -> bool {
    matches!(
        instr,
        X86Instruction::Cmov { .. } | X86Instruction::Jcc { .. }
    )
}

impl crate::isa::traits::FlagsAnalysis<X86Instruction> for X86_64 {
    fn modifies_flags(instr: &X86Instruction) -> bool {
        x86_modifies_flags(instr)
    }

    fn reads_flags(instr: &X86Instruction) -> bool {
        x86_reads_flags(instr)
    }
}

impl crate::isa::traits::FlagsAnalysis<X86Instruction> for X86_32 {
    fn modifies_flags(instr: &X86Instruction) -> bool {
        x86_modifies_flags(instr)
    }

    fn reads_flags(instr: &X86Instruction) -> bool {
        x86_reads_flags(instr)
    }
}

// --- Trait surface impls (#77 stage 2 step 17) ---
// Each impl delegates to the existing free function so the parallel
// pipeline files (concrete_x86.rs / smt_x86.rs / cost_x86.rs /
// assembler/x86.rs) can be deleted in stage 2 step 18 once stage 1's
// SearchAlgorithm<I> follow-up wires the consumer side through these
// trait impls.

impl crate::isa::traits::ConcreteExecutor<X86Instruction> for X86_64 {
    type Value = u64;
    type State = crate::semantics::state::X86ConcreteMachineState;

    fn execute_instruction(&self, state: Self::State, instruction: &X86Instruction) -> Self::State {
        crate::semantics::concrete_x86::apply_instruction_concrete_x86(state, instruction)
    }

    fn new_zeroed_state(&self) -> Self::State {
        crate::semantics::state::X86ConcreteMachineState::new_zeroed(64)
    }

    fn state_from_values(
        &self,
        values: std::collections::HashMap<X86Register, u64>,
    ) -> Self::State {
        let mut state = crate::semantics::state::X86ConcreteMachineState::new_zeroed(64);
        for (reg, val) in values {
            state.set_register(reg, crate::semantics::state::ConcreteValue::new(val));
        }
        state
    }

    fn get_register(&self, state: &Self::State, reg: X86Register) -> u64 {
        state.get_register(reg).as_u64()
    }

    fn set_register(&self, state: &mut Self::State, reg: X86Register, value: u64) {
        state.set_register(reg, crate::semantics::state::ConcreteValue::new(value));
    }
}

impl crate::isa::traits::ConcreteExecutor<X86Instruction> for X86_32 {
    type Value = u64;
    type State = crate::semantics::state::X86ConcreteMachineState;

    fn execute_instruction(&self, state: Self::State, instruction: &X86Instruction) -> Self::State {
        crate::semantics::concrete_x86::apply_instruction_concrete_x86(state, instruction)
    }

    fn new_zeroed_state(&self) -> Self::State {
        crate::semantics::state::X86ConcreteMachineState::new_zeroed(32)
    }

    fn state_from_values(
        &self,
        values: std::collections::HashMap<X86Register, u64>,
    ) -> Self::State {
        let mut state = crate::semantics::state::X86ConcreteMachineState::new_zeroed(32);
        for (reg, val) in values {
            state.set_register(reg, crate::semantics::state::ConcreteValue::new(val));
        }
        state
    }

    fn get_register(&self, state: &Self::State, reg: X86Register) -> u64 {
        state.get_register(reg).as_u64()
    }

    fn set_register(&self, state: &mut Self::State, reg: X86Register, value: u64) {
        state.set_register(reg, crate::semantics::state::ConcreteValue::new(value));
    }
}

impl crate::isa::traits::SymbolicExecutor<X86Instruction> for X86_64 {
    type State = crate::semantics::smt_x86::MachineStateX86;

    fn execute_instruction(&self, state: Self::State, instruction: &X86Instruction) -> Self::State {
        crate::semantics::smt_x86::apply_instruction(state, instruction)
    }

    fn new_symbolic_state(&self, prefix: &str) -> Self::State {
        crate::semantics::smt_x86::MachineStateX86::new_symbolic(prefix, 64)
    }
}

impl crate::isa::traits::SymbolicExecutor<X86Instruction> for X86_32 {
    type State = crate::semantics::smt_x86::MachineStateX86;

    fn execute_instruction(&self, state: Self::State, instruction: &X86Instruction) -> Self::State {
        crate::semantics::smt_x86::apply_instruction(state, instruction)
    }

    fn new_symbolic_state(&self, prefix: &str) -> Self::State {
        crate::semantics::smt_x86::MachineStateX86::new_symbolic(prefix, 32)
    }
}

impl crate::isa::traits::CostModel<X86Instruction> for X86_64 {
    fn instruction_cost(&self, instruction: &X86Instruction) -> u64 {
        crate::semantics::cost_x86::instruction_cost(
            instruction,
            &crate::semantics::cost::CostMetric::InstructionCount,
            64,
        )
    }
}

impl crate::isa::traits::CostModel<X86Instruction> for X86_32 {
    fn instruction_cost(&self, instruction: &X86Instruction) -> u64 {
        crate::semantics::cost_x86::instruction_cost(
            instruction,
            &crate::semantics::cost::CostMetric::InstructionCount,
            32,
        )
    }
}

impl crate::isa::traits::Assembler<X86Instruction> for X86_64 {
    fn assemble(&mut self, instructions: &[X86Instruction]) -> Result<Vec<u8>, String> {
        crate::assembler::x86::X86Assembler::new_64().assemble_instructions(instructions)
    }

    fn can_assemble(&self, _instruction: &X86Instruction) -> bool {
        // Every x86 variant in this enum is encodable in 64-bit mode.
        true
    }
}

impl crate::isa::traits::Assembler<X86Instruction> for X86_32 {
    fn assemble(&mut self, instructions: &[X86Instruction]) -> Result<Vec<u8>, String> {
        crate::assembler::x86::X86Assembler::new_32().assemble_instructions(instructions)
    }

    fn can_assemble(&self, instruction: &X86Instruction) -> bool {
        // In 32-bit mode, R8..R15 are illegal. The x86 assembler's reg_index_32
        // rejects them; reproduce the same check here so trait dispatch can
        // pre-filter sequences before invoking the heavier assemble path.
        fn reg_ok_32(r: X86Register) -> bool {
            r.index().is_some_and(|i| i < 8)
        }
        match instruction {
            X86Instruction::MovReg { rd, rs }
            | X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => reg_ok_32(*rd) && reg_ok_32(*rs),
            X86Instruction::MovImm { rd, .. }
            | X86Instruction::AddImm { rd, .. }
            | X86Instruction::SubImm { rd, .. }
            | X86Instruction::AndImm { rd, .. }
            | X86Instruction::OrImm { rd, .. }
            | X86Instruction::XorImm { rd, .. } => reg_ok_32(*rd),
            X86Instruction::CmpReg { rn, rs } => reg_ok_32(*rn) && reg_ok_32(*rs),
            X86Instruction::CmpImm { rn, .. } => reg_ok_32(*rn),
            X86Instruction::Cmov { rd, rs, .. } => reg_ok_32(*rd) && reg_ok_32(*rs),
            X86Instruction::Jcc { .. } => true,
        }
    }
}

/// x86 mutator for stochastic search. Carries a filtered register pool
/// (Mode32 excludes R8-R15 once at construction), an immediate pool and
/// the four operator weights borrowed from the AArch64 `Mutator`.
///
/// **Destructive-form invariant** (`src/isa/x86.rs:150-158`): every
/// non-MOV variant has `rd` in `source_registers()`. Mutating any
/// single operand slot preserves this — there is no path that
/// "splits" rd and rs into a shape that drops a source.
///
/// `Default` yields the x86-64 / 8-register baseline so
/// `<X86_64 as ISA>::Mutator = X86Mutator` produces a usable instance
/// from `X86Mutator::default()` if a caller has nothing better.
#[derive(Debug, Clone)]
pub struct X86Mutator {
    registers: Vec<X86Register>,
    immediates: Vec<i64>,
    weights: crate::search::config::MutationWeights,
}

impl X86Mutator {
    /// Construct a mutator. `mode` is consumed here to filter extended
    /// registers (Mode32 excludes R8-R15) once at construction; it is
    /// not retained as a field. Downstream mutation therefore cannot
    /// reintroduce extended registers.
    pub fn new(
        registers: Vec<X86Register>,
        immediates: Vec<i64>,
        weights: crate::search::config::MutationWeights,
        mode: crate::assembler::x86::X86Mode,
    ) -> Self {
        let registers = registers
            .into_iter()
            .filter(|r| {
                mode != crate::assembler::x86::X86Mode::Mode32
                    || matches!(r.index(), Some(i) if i < 8)
            })
            .collect();
        Self {
            registers,
            immediates,
            weights,
        }
    }

    fn pick_register<R: rand::RngExt>(&self, rng: &mut R) -> X86Register {
        if self.registers.is_empty() {
            X86Register::RAX
        } else {
            self.registers[rng.random_range(0..self.registers.len())]
        }
    }

    fn pick_immediate<R: rand::RngExt>(&self, rng: &mut R) -> i64 {
        if self.immediates.is_empty() {
            0
        } else {
            self.immediates[rng.random_range(0..self.immediates.len())]
        }
    }

    fn random_instruction<R: rand::RngExt>(&self, rng: &mut R) -> X86Instruction {
        // Rewritable variants only: 7 reg-reg + 7 reg-imm + CMOVcc.
        let opcode = rng.random_range(0..u32::from(X86_REWRITABLE_OPCODE_COUNT));
        let rd = self.pick_register(rng);
        let rs = self.pick_register(rng);
        let imm = self.pick_immediate(rng);
        let cond = X86Condition::ALL[rng.random_range(0..X86Condition::ALL.len())];
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
            _ => X86Instruction::Cmov { rd, rs, cond },
        }
    }

    fn mutate_operand<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.is_empty() {
            return;
        }
        let idx = rng.random_range(0..sequence.len());
        match &mut sequence[idx] {
            X86Instruction::MovReg { rd, rs } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng);
                } else {
                    *rs = self.pick_register(rng);
                }
            }
            X86Instruction::MovImm { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng);
                } else {
                    *imm = self.pick_immediate(rng);
                }
            }
            X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng);
                } else {
                    *rs = self.pick_register(rng);
                }
            }
            X86Instruction::AddImm { rd, imm }
            | X86Instruction::SubImm { rd, imm }
            | X86Instruction::AndImm { rd, imm }
            | X86Instruction::OrImm { rd, imm }
            | X86Instruction::XorImm { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng);
                } else {
                    *imm = self.pick_immediate(rng);
                }
            }
            X86Instruction::CmpReg { rn, rs } => {
                if rng.random_bool(0.5) {
                    *rn = self.pick_register(rng);
                } else {
                    *rs = self.pick_register(rng);
                }
            }
            X86Instruction::CmpImm { rn, imm } => {
                if rng.random_bool(0.5) {
                    *rn = self.pick_register(rng);
                } else {
                    *imm = self.pick_immediate(rng);
                }
            }
            X86Instruction::Cmov { rd, rs, .. } => {
                // Cond stays fixed — stochastic mutation only swaps registers
                // for now; cycle 16+ may add condition-bridging.
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng);
                } else {
                    *rs = self.pick_register(rng);
                }
            }
            // Jcc is a terminator; mutation never reaches it because the
            // search pool excludes terminators. Keep the arm as a no-op
            // so an accidental call doesn't panic.
            X86Instruction::Jcc { .. } => {}
        }
    }

    /// Swap the variant of a randomly-chosen instruction while keeping
    /// its operand shape (reg-reg → reg-reg, reg-imm → reg-imm). CMP
    /// has no rd so CMP variants stay within CMP.
    fn mutate_opcode<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.is_empty() {
            return;
        }
        let idx = rng.random_range(0..sequence.len());
        let current = sequence[idx];
        sequence[idx] = match current {
            X86Instruction::MovReg { rd, rs }
            | X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => match rng.random_range(0..6u32) {
                0 => X86Instruction::MovReg { rd, rs },
                1 => X86Instruction::AddReg { rd, rs },
                2 => X86Instruction::SubReg { rd, rs },
                3 => X86Instruction::AndReg { rd, rs },
                4 => X86Instruction::OrReg { rd, rs },
                _ => X86Instruction::XorReg { rd, rs },
            },
            X86Instruction::MovImm { rd, imm }
            | X86Instruction::AddImm { rd, imm }
            | X86Instruction::SubImm { rd, imm }
            | X86Instruction::AndImm { rd, imm }
            | X86Instruction::OrImm { rd, imm }
            | X86Instruction::XorImm { rd, imm } => match rng.random_range(0..6u32) {
                0 => X86Instruction::MovImm { rd, imm },
                1 => X86Instruction::AddImm { rd, imm },
                2 => X86Instruction::SubImm { rd, imm },
                3 => X86Instruction::AndImm { rd, imm },
                4 => X86Instruction::OrImm { rd, imm },
                _ => X86Instruction::XorImm { rd, imm },
            },
            X86Instruction::CmpReg { .. } | X86Instruction::CmpImm { .. } => current,
            // Cmov has a unique shape (rd, rs, cond) with no opcode-shape
            // siblings; keep it unchanged in the opcode-bridge mutator.
            X86Instruction::Cmov { .. } => current,
            // Jcc is a terminator and should never reach mutation; preserve it.
            X86Instruction::Jcc { .. } => current,
        };
    }

    fn mutate_swap<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.len() < 2 {
            return;
        }
        let a = rng.random_range(0..sequence.len());
        let mut b = rng.random_range(0..sequence.len());
        while b == a {
            b = rng.random_range(0..sequence.len());
        }
        sequence.swap(a, b);
    }

    fn mutate_instruction<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.is_empty() {
            return;
        }
        let idx = rng.random_range(0..sequence.len());
        sequence[idx] = self.random_instruction(rng);
    }
}

impl Default for X86Mutator {
    fn default() -> Self {
        Self::new(
            (0..8u8).filter_map(X86Register::from_index).collect(),
            vec![
                0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
            ],
            crate::search::config::MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        )
    }
}

impl crate::isa::traits::ISAMutator<X86Instruction> for X86Mutator {
    fn mutate<R: rand::RngExt>(
        &self,
        rng: &mut R,
        sequence: &[X86Instruction],
    ) -> Vec<X86Instruction> {
        if sequence.is_empty() {
            return sequence.to_vec();
        }
        let mut out = sequence.to_vec();
        let thresholds = self.weights.cumulative_thresholds();
        let r: f64 = rng.random();
        if r < thresholds[0] {
            self.mutate_operand(rng, &mut out);
        } else if r < thresholds[1] {
            self.mutate_opcode(rng, &mut out);
        } else if r < thresholds[2] {
            self.mutate_swap(rng, &mut out);
        } else {
            self.mutate_instruction(rng, &mut out);
        }
        out
    }
}

/// Stateless generator producing every rewritable x86 variant for a
/// given register and immediate pool. Jcc is intentionally excluded:
/// it is a fixed terminator, not a search candidate.
#[derive(Clone, Copy, Debug, Default)]
pub struct X86InstructionGenerator;

// One entry per rewritable opcode family: 7 reg-reg + 7 reg-imm + CMOVcc.
// CMOVcc counts as a single family here even though `generate_all` expands
// it across all 16 `X86Condition::ALL` variants per register pair.
const X86_REWRITABLE_OPCODE_COUNT: u8 = 15;

impl InstructionGenerator<X86Instruction> for X86InstructionGenerator {
    fn generate_all(&self, registers: &[X86Register], immediates: &[i64]) -> Vec<X86Instruction> {
        let mut out = Vec::new();
        // Register-register variants (7 data mnemonics).
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
        // Register-immediate variants (7 data mnemonics).
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
        // CMOVcc is rewritable and reads flags, so enumerate every
        // condition for each register pair. Jcc remains excluded.
        for &rd in registers {
            for &rs in registers {
                for &cond in &X86Condition::ALL {
                    out.push(X86Instruction::Cmov { rd, rs, cond });
                }
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
        let opcode = rng.random_range(0..X86_REWRITABLE_OPCODE_COUNT);
        let rd = registers[rng.random_range(0..registers.len())];
        let rs = registers[rng.random_range(0..registers.len())];
        let imm = immediates[rng.random_range(0..immediates.len())];
        let cond = X86Condition::ALL[rng.random_range(0..X86Condition::ALL.len())];
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
            14 => X86Instruction::Cmov { rd, rs, cond },
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
        X86_REWRITABLE_OPCODE_COUNT
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
        X86Instruction::Cmov { rs, cond, .. } => X86Instruction::Cmov {
            rd: new_rd,
            rs,
            cond,
        },
        // Jcc has no register operand; ignore the requested rd swap.
        X86Instruction::Jcc { cond } => X86Instruction::Jcc { cond },
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
        // Cmov's `rs` is mutated; `cond` and `rd` carry through unchanged.
        X86Instruction::Cmov { rd, cond, .. } => X86Instruction::Cmov {
            rd,
            rs: new_rs,
            cond,
        },
        X86Instruction::Jcc { cond } => X86Instruction::Jcc { cond },
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
    fn x86_generator_includes_cmov_but_excludes_jcc() {
        use crate::isa::traits::InstructionGenerator;
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64];
        let all = X86InstructionGenerator.generate_all(&regs, &imms);

        assert!(
            all.contains(&X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            }),
            "trait generator must enumerate CMOVcc candidates"
        );
        assert!(
            all.iter()
                .all(|instr| !matches!(instr, X86Instruction::Jcc { .. })),
            "trait generator must not enumerate fixed Jcc terminators"
        );
    }

    #[test]
    fn x86_generator_random_can_emit_cmov_without_emitting_jcc() {
        use crate::isa::traits::InstructionGenerator;
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(74);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1];
        let mut saw_cmov = false;

        for _ in 0..2000 {
            let instr = X86InstructionGenerator.generate_random(&mut rng, &regs, &imms);
            saw_cmov |= matches!(instr, X86Instruction::Cmov { .. });
            assert!(
                !matches!(instr, X86Instruction::Jcc { .. }),
                "random trait generator must not emit fixed Jcc terminators"
            );
        }

        assert!(saw_cmov, "random trait generator never emitted CMOVcc");
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
            X86Instruction::Cmov {
                rd,
                rs,
                cond: X86Condition::E,
            },
        ];

        // Rewritable non-terminator variants: 14 data forms + CMOVcc.
        assert_eq!(variants.len(), 15);
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

        // EFLAGS side-effects: MOV and CMOV do not mutate EFLAGS.
        for v in variants.iter() {
            let leaves_flags = matches!(
                v,
                X86Instruction::MovReg { .. }
                    | X86Instruction::MovImm { .. }
                    | X86Instruction::Cmov { .. }
            );
            assert_eq!(
                <X86Instruction as InstructionType>::has_side_effects(v),
                !leaves_flags,
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

    // ---- X86Mutator (issue #73 Phase B) ----

    #[test]
    fn x86_mutator_eventually_changes_the_sequence() {
        use crate::isa::traits::ISAMutator;
        use crate::search::candidate_x86::{default_x86_immediates, default_x86_registers};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            default_x86_registers(),
            default_x86_immediates(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut changed = false;
        for _ in 0..200 {
            let mutated = mutator.mutate(&mut rng, &target);
            if mutated != target {
                changed = true;
                break;
            }
        }
        assert!(
            changed,
            "200 mutations produced no change \u{2014} stub still wired?"
        );
    }

    #[test]
    fn x86_mutator_preserves_sequence_length() {
        use crate::isa::traits::ISAMutator;
        use crate::search::candidate_x86::{default_x86_immediates, default_x86_registers};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            default_x86_registers(),
            default_x86_immediates(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 5,
            },
        ];
        for seed in 0..50u64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let mutated = mutator.mutate(&mut rng, &target);
            assert_eq!(
                mutated.len(),
                target.len(),
                "seed {} changed sequence length",
                seed
            );
        }
    }

    #[test]
    fn x86_mutator_mode32_never_emits_extended_registers() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        // Pool deliberately includes R8-R15 to verify Mode32 filters
        // them out at construction time.
        let pool = vec![
            X86Register::RAX,
            X86Register::RCX,
            X86Register::R8,
            X86Register::R9,
            X86Register::R15,
        ];
        let mutator = X86Mutator::new(
            pool,
            vec![0i64, 1],
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode32,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut seq = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        for _ in 0..500 {
            seq = mutator.mutate(&mut rng, &seq);
            for instr in &seq {
                if let Some(rd) = instr.destination() {
                    assert!(
                        matches!(rd.index(), Some(i) if i < 8),
                        "Mode32 produced extended rd {:?}",
                        rd
                    );
                }
                for rs in instr.source_registers() {
                    assert!(
                        matches!(rs.index(), Some(i) if i < 8),
                        "Mode32 produced extended rs {:?}",
                        rs
                    );
                }
            }
        }
    }

    #[test]
    fn x86_mutator_destructive_form_invariant() {
        // For every destructive variant (non-MOV, non-CMP that writes
        // rd), `rd` must appear in `source_registers()` per
        // src/isa/x86.rs:228-245. The mutator must preserve that.
        use crate::isa::traits::ISAMutator;
        use crate::search::candidate_x86::{default_x86_immediates, default_x86_registers};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            default_x86_registers(),
            default_x86_immediates(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );
        let seed_target = vec![X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        let mut seq = seed_target;
        for _ in 0..300 {
            seq = mutator.mutate(&mut rng, &seq);
            for instr in &seq {
                let destructive = matches!(
                    instr,
                    X86Instruction::AddReg { .. }
                        | X86Instruction::SubReg { .. }
                        | X86Instruction::AndReg { .. }
                        | X86Instruction::OrReg { .. }
                        | X86Instruction::XorReg { .. }
                        | X86Instruction::AddImm { .. }
                        | X86Instruction::SubImm { .. }
                        | X86Instruction::AndImm { .. }
                        | X86Instruction::OrImm { .. }
                        | X86Instruction::XorImm { .. }
                );
                if destructive && let Some(rd) = instr.destination() {
                    assert!(
                        instr.source_registers().contains(&rd),
                        "destructive {:?} dropped rd from sources",
                        instr
                    );
                }
            }
        }
    }

    // --- Jcc IR + is_terminator ---

    #[test]
    fn jcc_is_terminator() {
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::E,
        };
        assert!(jcc.is_terminator());
    }

    #[test]
    fn non_jcc_x86_instructions_are_not_terminators() {
        assert!(
            !X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0
            }
            .is_terminator()
        );
        assert!(
            !X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX
            }
            .is_terminator()
        );
        assert!(
            !X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E
            }
            .is_terminator()
        );
    }

    #[test]
    fn jcc_has_no_destination_and_no_source_registers() {
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::NE,
        };
        assert_eq!(jcc.destination(), None);
        assert!(jcc.source_registers().is_empty());
    }

    #[test]
    fn jcc_does_not_modify_flags_and_has_no_side_effects() {
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::B,
        };
        assert!(!x86_modifies_flags(&jcc));
        assert!(!jcc.has_side_effects());
    }

    // --- FlagsAnalysis::reads_flags wired for Cmov / Jcc ---

    #[test]
    fn x86_64_reads_flags_returns_true_for_cmov_and_jcc() {
        use crate::isa::traits::FlagsAnalysis;
        let cmov = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        };
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::NE,
        };
        assert!(<X86_64 as FlagsAnalysis<X86Instruction>>::reads_flags(
            &cmov
        ));
        assert!(<X86_64 as FlagsAnalysis<X86Instruction>>::reads_flags(&jcc));
    }

    #[test]
    fn x86_32_reads_flags_returns_true_for_cmov_and_jcc() {
        use crate::isa::traits::FlagsAnalysis;
        let cmov = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        };
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::NE,
        };
        assert!(<X86_32 as FlagsAnalysis<X86Instruction>>::reads_flags(
            &cmov
        ));
        assert!(<X86_32 as FlagsAnalysis<X86Instruction>>::reads_flags(&jcc));
    }

    #[test]
    fn x86_reads_flags_returns_false_for_non_condition_ops() {
        use crate::isa::traits::FlagsAnalysis;
        let mov = X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        };
        let add = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        assert!(!<X86_64 as FlagsAnalysis<X86Instruction>>::reads_flags(
            &mov
        ));
        assert!(!<X86_64 as FlagsAnalysis<X86Instruction>>::reads_flags(
            &add
        ));
    }
}
