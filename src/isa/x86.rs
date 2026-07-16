//! x86 ISA backend (x86-64 primary, x86-32 secondary).
//!
//! Mirrors the dual-variant pattern of `src/isa/riscv.rs`: a single
//! `X86Register` view type plus shared `X86Operand` / `X86Instruction` enums
//! serve the `X86_64` and `X86_32` ISA marker structs.
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

    pub const fn suffix(self) -> &'static str {
        match self {
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
        }
    }

    pub const fn cmov_mnemonic(self) -> &'static str {
        match self {
            X86Condition::E => "cmove",
            X86Condition::NE => "cmovne",
            X86Condition::B => "cmovb",
            X86Condition::AE => "cmovae",
            X86Condition::BE => "cmovbe",
            X86Condition::A => "cmova",
            X86Condition::L => "cmovl",
            X86Condition::GE => "cmovge",
            X86Condition::LE => "cmovle",
            X86Condition::G => "cmovg",
            X86Condition::S => "cmovs",
            X86Condition::NS => "cmovns",
            X86Condition::O => "cmovo",
            X86Condition::NO => "cmovno",
            X86Condition::P => "cmovp",
            X86Condition::NP => "cmovnp",
        }
    }

    pub const fn jcc_mnemonic(self) -> &'static str {
        match self {
            X86Condition::E => "je",
            X86Condition::NE => "jne",
            X86Condition::B => "jb",
            X86Condition::AE => "jae",
            X86Condition::BE => "jbe",
            X86Condition::A => "ja",
            X86Condition::L => "jl",
            X86Condition::GE => "jge",
            X86Condition::LE => "jle",
            X86Condition::G => "jg",
            X86Condition::S => "js",
            X86Condition::NS => "jns",
            X86Condition::O => "jo",
            X86Condition::NO => "jno",
            X86Condition::P => "jp",
            X86Condition::NP => "jnp",
        }
    }
}

impl fmt::Display for X86Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.suffix())
    }
}

/// The bit slice selected by an x86 register operand.
///
/// `Native` preserves the historical programmatic IR convention: it means the
/// machine mode's full GPR width (64 bits for [`X86_64`], 32 for [`X86_32`]).
/// Parsed aliases retain an explicit narrower view. The high-byte view is the
/// legacy AH/CH/DH/BH slice at bits 15:8, not the low byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum X86RegisterView {
    Native,
    Dword,
    Word,
    LowByte,
    HighByte,
}

impl X86RegisterView {
    pub const fn bit_width(self, mode_width: u32) -> u32 {
        match self {
            X86RegisterView::Native => mode_width,
            X86RegisterView::Dword => 32,
            X86RegisterView::Word => 16,
            X86RegisterView::LowByte | X86RegisterView::HighByte => 8,
        }
    }
}

/// An x86 GPR operand: canonical architectural register plus selected view.
///
/// Machine state and liveness key on [`Self::canonical`], while instruction
/// operands retain the view so execution and assembly can distinguish RAX,
/// EAX, AX, AL, and AH without multiplying instruction variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct X86Register {
    index: u8,
    view: X86RegisterView,
}

impl X86Register {
    const fn new(index: u8, view: X86RegisterView) -> Self {
        Self { index, view }
    }

    pub const RAX: Self = Self::new(0, X86RegisterView::Native);
    pub const RCX: Self = Self::new(1, X86RegisterView::Native);
    pub const RDX: Self = Self::new(2, X86RegisterView::Native);
    pub const RBX: Self = Self::new(3, X86RegisterView::Native);
    pub const RSP: Self = Self::new(4, X86RegisterView::Native);
    pub const RBP: Self = Self::new(5, X86RegisterView::Native);
    pub const RSI: Self = Self::new(6, X86RegisterView::Native);
    pub const RDI: Self = Self::new(7, X86RegisterView::Native);
    pub const R8: Self = Self::new(8, X86RegisterView::Native);
    pub const R9: Self = Self::new(9, X86RegisterView::Native);
    pub const R10: Self = Self::new(10, X86RegisterView::Native);
    pub const R11: Self = Self::new(11, X86RegisterView::Native);
    pub const R12: Self = Self::new(12, X86RegisterView::Native);
    pub const R13: Self = Self::new(13, X86RegisterView::Native);
    pub const R14: Self = Self::new(14, X86RegisterView::Native);
    pub const R15: Self = Self::new(15, X86RegisterView::Native);

    pub const EAX: Self = Self::new(0, X86RegisterView::Dword);
    pub const ECX: Self = Self::new(1, X86RegisterView::Dword);
    pub const EDX: Self = Self::new(2, X86RegisterView::Dword);
    pub const EBX: Self = Self::new(3, X86RegisterView::Dword);
    pub const ESP: Self = Self::new(4, X86RegisterView::Dword);
    pub const EBP: Self = Self::new(5, X86RegisterView::Dword);
    pub const ESI: Self = Self::new(6, X86RegisterView::Dword);
    pub const EDI: Self = Self::new(7, X86RegisterView::Dword);
    pub const R8D: Self = Self::new(8, X86RegisterView::Dword);
    pub const R9D: Self = Self::new(9, X86RegisterView::Dword);
    pub const R10D: Self = Self::new(10, X86RegisterView::Dword);
    pub const R11D: Self = Self::new(11, X86RegisterView::Dword);
    pub const R12D: Self = Self::new(12, X86RegisterView::Dword);
    pub const R13D: Self = Self::new(13, X86RegisterView::Dword);
    pub const R14D: Self = Self::new(14, X86RegisterView::Dword);
    pub const R15D: Self = Self::new(15, X86RegisterView::Dword);

    pub const AX: Self = Self::new(0, X86RegisterView::Word);
    pub const CX: Self = Self::new(1, X86RegisterView::Word);
    pub const DX: Self = Self::new(2, X86RegisterView::Word);
    pub const BX: Self = Self::new(3, X86RegisterView::Word);
    pub const SP: Self = Self::new(4, X86RegisterView::Word);
    pub const BP: Self = Self::new(5, X86RegisterView::Word);
    pub const SI: Self = Self::new(6, X86RegisterView::Word);
    pub const DI: Self = Self::new(7, X86RegisterView::Word);
    pub const R8W: Self = Self::new(8, X86RegisterView::Word);
    pub const R9W: Self = Self::new(9, X86RegisterView::Word);
    pub const R10W: Self = Self::new(10, X86RegisterView::Word);
    pub const R11W: Self = Self::new(11, X86RegisterView::Word);
    pub const R12W: Self = Self::new(12, X86RegisterView::Word);
    pub const R13W: Self = Self::new(13, X86RegisterView::Word);
    pub const R14W: Self = Self::new(14, X86RegisterView::Word);
    pub const R15W: Self = Self::new(15, X86RegisterView::Word);

    pub const AL: Self = Self::new(0, X86RegisterView::LowByte);
    pub const CL: Self = Self::new(1, X86RegisterView::LowByte);
    pub const DL: Self = Self::new(2, X86RegisterView::LowByte);
    pub const BL: Self = Self::new(3, X86RegisterView::LowByte);
    pub const SPL: Self = Self::new(4, X86RegisterView::LowByte);
    pub const BPL: Self = Self::new(5, X86RegisterView::LowByte);
    pub const SIL: Self = Self::new(6, X86RegisterView::LowByte);
    pub const DIL: Self = Self::new(7, X86RegisterView::LowByte);
    pub const R8B: Self = Self::new(8, X86RegisterView::LowByte);
    pub const R9B: Self = Self::new(9, X86RegisterView::LowByte);
    pub const R10B: Self = Self::new(10, X86RegisterView::LowByte);
    pub const R11B: Self = Self::new(11, X86RegisterView::LowByte);
    pub const R12B: Self = Self::new(12, X86RegisterView::LowByte);
    pub const R13B: Self = Self::new(13, X86RegisterView::LowByte);
    pub const R14B: Self = Self::new(14, X86RegisterView::LowByte);
    pub const R15B: Self = Self::new(15, X86RegisterView::LowByte);

    pub const AH: Self = Self::new(0, X86RegisterView::HighByte);
    pub const CH: Self = Self::new(1, X86RegisterView::HighByte);
    pub const DH: Self = Self::new(2, X86RegisterView::HighByte);
    pub const BH: Self = Self::new(3, X86RegisterView::HighByte);

    pub fn index(&self) -> Option<u8> {
        Some(self.index)
    }

    pub fn mnemonic(&self) -> &'static str {
        const NATIVE: [&str; 16] = [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ];
        const DWORD: [&str; 16] = [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
            "r12d", "r13d", "r14d", "r15d",
        ];
        const WORD: [&str; 16] = [
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w",
            "r13w", "r14w", "r15w",
        ];
        const LOW_BYTE: [&str; 16] = [
            "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b",
            "r12b", "r13b", "r14b", "r15b",
        ];
        const HIGH_BYTE: [&str; 4] = ["ah", "ch", "dh", "bh"];

        match self.view {
            X86RegisterView::Native => NATIVE[self.index as usize],
            X86RegisterView::Dword => DWORD[self.index as usize],
            X86RegisterView::Word => WORD[self.index as usize],
            X86RegisterView::LowByte => LOW_BYTE[self.index as usize],
            X86RegisterView::HighByte => HIGH_BYTE[self.index as usize],
        }
    }

    pub fn from_index(i: u8) -> Option<Self> {
        (i < 16).then_some(Self::new(i, X86RegisterView::Native))
    }

    pub const fn view(self) -> X86RegisterView {
        self.view
    }

    pub fn canonical(self) -> Self {
        Self::from_index(self.index).expect("x86 register index is always valid")
    }

    pub const fn effective_width(self, mode_width: u32) -> u32 {
        self.view.bit_width(mode_width)
    }

    pub const fn is_high_byte(self) -> bool {
        matches!(self.view, X86RegisterView::HighByte)
    }

    pub const fn is_byte(self) -> bool {
        matches!(
            self.view,
            X86RegisterView::LowByte | X86RegisterView::HighByte
        )
    }

    pub const fn is_native(self) -> bool {
        matches!(self.view, X86RegisterView::Native)
    }

    pub const fn fully_overwrites_architectural_register(self) -> bool {
        matches!(self.view, X86RegisterView::Native | X86RegisterView::Dword)
    }

    pub fn with_view(self, view: X86RegisterView) -> Option<Self> {
        if view == X86RegisterView::HighByte && self.index >= 4 {
            None
        } else {
            Some(Self::new(self.index, view))
        }
    }

    pub fn with_base(self, base: X86Register) -> Option<Self> {
        base.canonical().with_view(self.view)
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
        self.canonical() == X86Register::RSP
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
    /// `test rn, rs` — `rn & rs` discarding the result; clears CF/OF, sets
    /// SF/ZF/PF (AF undefined). Non-destructive sibling of `and`, just as
    /// `cmp` is the non-destructive sibling of `sub`.
    TestReg { rn: X86Register, rs: X86Register },
    /// `test rn, imm` — `rn & imm` discarding the result; clears CF/OF, sets
    /// SF/ZF/PF (AF undefined).
    TestImm { rn: X86Register, imm: i64 },
    /// `neg rd` — `rd = -rd` (two's complement). Single-operand; reads and
    /// writes `rd`. Sets EFLAGS as if computing `0 - rd`: CF = (rd != 0),
    /// OF/SF/ZF/PF per the SUB result. Flag-writing like `sub`.
    Neg { rd: X86Register },
    /// `not rd` — `rd = !rd` (bitwise complement). Single-operand; reads and
    /// writes `rd`. Affects NO flags — EFLAGS is left unchanged, like `mov`.
    Not { rd: X86Register },
    /// `inc rd` — `rd = rd + 1`. Single-operand; reads and writes `rd`. Sets
    /// OF/SF/ZF/PF as for `rd + 1` but, unlike `add`, leaves CF UNCHANGED
    /// (carry-in flows through to carry-out): the prior CF is preserved.
    Inc { rd: X86Register },
    /// `dec rd` — `rd = rd - 1`. Single-operand; reads and writes `rd`. Sets
    /// OF/SF/ZF/PF as for `rd - 1` but, unlike `sub`, leaves CF UNCHANGED:
    /// the prior CF is preserved.
    Dec { rd: X86Register },
    /// `shl rd, imm` (a.k.a. `sal`) — logical/arithmetic left shift by a
    /// compile-time COUNT. Reads and writes `rd`. `imm` is the shift count;
    /// x86 masks it to `width-1` (5 bits at width 32, 6 bits at width 64). A
    /// masked count of 0 leaves `rd` and ALL flags unchanged; otherwise
    /// SF/ZF/PF come from the result, CF is the last bit shifted out (original
    /// bit `width - eff`), and OF (architecturally defined only for count 1) is
    /// `MSB(result) XOR CF`. The CL-register-count form is not modelled.
    Shl { rd: X86Register, imm: i64 },
    /// `shr rd, imm` — logical (unsigned) right shift by a compile-time COUNT.
    /// Reads and writes `rd`. `imm` is masked like `shl`. Masked count 0 leaves
    /// `rd` and ALL flags unchanged; otherwise SF/ZF/PF from the result, CF =
    /// original bit `eff - 1`, OF (count 1 only) = MSB of the original `rd`. The
    /// CL-register-count form is not modelled.
    Shr { rd: X86Register, imm: i64 },
    /// `sar rd, imm` — arithmetic (signed) right shift by a compile-time COUNT.
    /// Reads and writes `rd`. `imm` is masked like `shl`. Masked count 0 leaves
    /// `rd` and ALL flags unchanged; otherwise SF/ZF/PF from the result, CF =
    /// original bit `eff - 1`, OF (count 1 only) = 0. The CL-register-count form
    /// is not modelled.
    Sar { rd: X86Register, imm: i64 },
    /// `rol rd, imm` — rotate left by a compile-time COUNT. Reads and writes
    /// `rd`. `imm` is masked to `width-1` like the shifts. **Unlike the shifts,
    /// rotates touch ONLY CF (plus OF for count 1); SF/ZF/PF/AF are PRESERVED**.
    /// A masked count of 0 leaves `rd` and ALL flags unchanged. Otherwise
    /// `rd = rotate_left(rd, eff)`, CF = bit 0 of the result (the bit rotated
    /// from the MSB into the LSB), and OF (architecturally defined only for
    /// count 1) = `MSB(result) XOR CF`. For count != 1 OF is UNDEFINED, so the
    /// model preserves the incoming OF. The CL-register-count form is not
    /// modelled.
    Rol { rd: X86Register, imm: i64 },
    /// `ror rd, imm` — rotate right by a compile-time COUNT. Reads and writes
    /// `rd`. `imm` is masked like `rol`, and the same partial-flag model
    /// applies: only CF (plus OF for count 1) changes; SF/ZF/PF/AF are
    /// PRESERVED; a masked count of 0 is a full no-op. Otherwise
    /// `rd = rotate_right(rd, eff)`, CF = the MSB (bit `width-1`) of the result,
    /// and OF (count 1 only) = XOR of the result's two most-significant bits
    /// (`MSB(result) XOR bit width-2`). For count != 1 OF is UNDEFINED so the
    /// incoming OF is preserved. The CL-register-count form is not modelled.
    Ror { rd: X86Register, imm: i64 },
    /// `imul rd, rs` — two-operand signed multiply: `rd = rd * rs` (low
    /// `width` bits). Reads and writes `rd`, so `rd` is both source and
    /// destination (destructive form). Only CF and OF are architecturally
    /// defined: they are set iff the FULL signed product does not fit the
    /// truncated `width`-bit destination; SF/ZF/PF/AF are Intel-UNDEFINED.
    /// We model SF/ZF/PF deterministically from the truncated result (see
    /// `concrete_x86::apply_imul`).
    ImulReg { rd: X86Register, rs: X86Register },
    /// `imul rd, rs, imm` — three-operand signed multiply: `rd = rs * imm`
    /// (low `width` bits). The project's FIRST 3-operand x86 variant. `rd` is
    /// purely WRITTEN (not read), so `source_registers()` is just `[rs]`. Same
    /// flag model as `ImulReg`: CF/OF on signed overflow, SF/ZF/PF
    /// Intel-undefined and modelled deterministically.
    ImulRegImm {
        rd: X86Register,
        rs: X86Register,
        imm: i64,
    },
    /// `lea rd, [base + disp]` — load effective address in its minimal
    /// register-base + displacement form: `rd = base + disp` (wrapping at
    /// width). NON-destructive: `base` is read, `rd` is purely WRITTEN (not
    /// read), exactly like `MovReg`. Affects NO flags. The `index*scale` and
    /// RIP-relative addressing forms are deferred; the parser rejects them as
    /// unsupported shapes.
    Lea {
        rd: X86Register,
        base: X86Register,
        disp: i64,
    },
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
    /// Canonical architectural destination used by liveness and machine-state
    /// interfaces. The encoded operand view remains available through
    /// [`Self::destination_operand`].
    pub fn destination(&self) -> Option<X86Register> {
        self.destination_operand().map(X86Register::canonical)
    }

    /// Destination exactly as encoded by this instruction, including its
    /// dword/word/byte view.
    pub fn destination_operand(&self) -> Option<X86Register> {
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
            | X86Instruction::Neg { rd }
            | X86Instruction::Not { rd }
            | X86Instruction::Inc { rd }
            | X86Instruction::Dec { rd }
            | X86Instruction::Shl { rd, .. }
            | X86Instruction::Shr { rd, .. }
            | X86Instruction::Sar { rd, .. }
            | X86Instruction::Rol { rd, .. }
            | X86Instruction::Ror { rd, .. }
            | X86Instruction::ImulReg { rd, .. }
            | X86Instruction::ImulRegImm { rd, .. }
            | X86Instruction::Lea { rd, .. }
            | X86Instruction::Cmov { rd, .. } => Some(*rd),
            // CMP and TEST discard their result; only EFLAGS is written.
            X86Instruction::CmpReg { .. }
            | X86Instruction::CmpImm { .. }
            | X86Instruction::TestReg { .. }
            | X86Instruction::TestImm { .. }
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
            X86Instruction::TestReg { .. } | X86Instruction::TestImm { .. } => "test",
            X86Instruction::Neg { .. } => "neg",
            X86Instruction::Not { .. } => "not",
            X86Instruction::Inc { .. } => "inc",
            X86Instruction::Dec { .. } => "dec",
            X86Instruction::Shl { .. } => "shl",
            X86Instruction::Shr { .. } => "shr",
            X86Instruction::Sar { .. } => "sar",
            X86Instruction::Rol { .. } => "rol",
            X86Instruction::Ror { .. } => "ror",
            X86Instruction::ImulReg { .. } | X86Instruction::ImulRegImm { .. } => "imul",
            X86Instruction::Lea { .. } => "lea",
            X86Instruction::Cmov { cond, .. } => cond.cmov_mnemonic(),
            X86Instruction::Jcc { cond } => cond.jcc_mnemonic(),
        }
    }

    /// Registers this instruction reads.
    ///
    /// **x86 destructive-form divergence**: for `AddReg/SubReg/AndReg/OrReg/XorReg`
    /// and their immediate forms, `rd` is BOTH source and destination, so it
    /// appears here. `MovReg`/`MovImm` are non-destructive (rd is purely
    /// written), so rd is NOT in the source list. See the enum doc-comment.
    pub fn source_registers(&self) -> Vec<X86Register> {
        let operands = match self {
            X86Instruction::MovReg { rs, .. } => vec![*rs],
            X86Instruction::MovImm { .. } => vec![],
            X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            // IMUL rd, rs is destructive (`rd = rd * rs`), so rd is read too.
            | X86Instruction::ImulReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => vec![*rd, *rs],
            // IMUL rd, rs, imm writes rd purely from `rs * imm`; rd is NOT read.
            X86Instruction::ImulRegImm { rs, .. } => vec![*rs],
            // LEA writes rd purely from `base + disp`; rd is NOT read (it is
            // non-destructive, like MovReg). Only `base` is a source.
            X86Instruction::Lea { base, .. } => vec![*base],
            X86Instruction::AddImm { rd, .. }
            | X86Instruction::SubImm { rd, .. }
            | X86Instruction::AndImm { rd, .. }
            | X86Instruction::OrImm { rd, .. }
            | X86Instruction::XorImm { rd, .. }
            // SHL / SHR / SAR read and write rd; the count is an immediate.
            | X86Instruction::Shl { rd, .. }
            | X86Instruction::Shr { rd, .. }
            | X86Instruction::Sar { rd, .. }
            // ROL / ROR read and write rd; the rotate count is an immediate.
            | X86Instruction::Rol { rd, .. }
            | X86Instruction::Ror { rd, .. } => vec![*rd],
            X86Instruction::CmpReg { rn, rs } => vec![*rn, *rs],
            X86Instruction::CmpImm { rn, .. } => vec![*rn],
            // TEST reads both operands (or just rn for the immediate form) and
            // writes no register — mirrors CMP.
            X86Instruction::TestReg { rn, rs } => vec![*rn, *rs],
            X86Instruction::TestImm { rn, .. } => vec![*rn],
            // NEG / NOT / INC / DEC are single-operand: each reads its own
            // destination.
            X86Instruction::Neg { rd }
            | X86Instruction::Not { rd }
            | X86Instruction::Inc { rd }
            | X86Instruction::Dec { rd } => vec![*rd],
            // Cmov reads both rd (kept on false branch) and rs.
            X86Instruction::Cmov { rd, rs, .. } => vec![*rd, *rs],
            X86Instruction::Jcc { .. } => vec![],
        };
        operands.into_iter().map(X86Register::canonical).collect()
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
            X86Instruction::TestReg { .. } => 14,
            X86Instruction::TestImm { .. } => 15,
            X86Instruction::Neg { .. } => 16,
            X86Instruction::Not { .. } => 17,
            X86Instruction::Inc { .. } => 18,
            X86Instruction::Dec { .. } => 19,
            X86Instruction::Shl { .. } => 20,
            X86Instruction::Shr { .. } => 21,
            X86Instruction::Sar { .. } => 22,
            X86Instruction::Rol { .. } => 23,
            X86Instruction::Ror { .. } => 24,
            X86Instruction::ImulReg { .. } => 25,
            X86Instruction::ImulRegImm { .. } => 26,
            X86Instruction::Lea { .. } => 27,
            // Cmov MUST stay the last rewritable opcode (COUNT - 1 == 28):
            // the CMOV distinct-register draw at both generation sites is
            // gated on `opcode == X86_REWRITABLE_OPCODE_COUNT - 1`.
            X86Instruction::Cmov { .. } => 28,
            X86Instruction::Jcc { .. } => 29,
        }
    }

    fn mnemonic(&self) -> &'static str {
        X86Instruction::mnemonic(self)
    }

    fn has_side_effects(&self) -> bool {
        // MOV / NOT / LEA / CMOV / Jcc do not write EFLAGS (CMOV and Jcc read
        // them, but reading is not a side effect on observable state; NOT
        // is bitwise complement and leaves EFLAGS untouched, exactly like
        // MOV; LEA is pure address arithmetic that writes only its destination
        // register). Every other variant — including NEG — sets or clobbers
        // flag bits, which is observable state beyond the destination register.
        !matches!(
            self,
            X86Instruction::MovReg { .. }
                | X86Instruction::MovImm { .. }
                | X86Instruction::Not { .. }
                | X86Instruction::Lea { .. }
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
            // IMUL rd, rs renders like the other two-register forms.
            | X86Instruction::ImulReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => write!(f, "{} {}, {}", mn, rd, rs),
            // The 3-operand IMUL renders `imul rd, rs, imm`.
            X86Instruction::ImulRegImm { rd, rs, imm } => write!(f, "{} {}, {}, {}", mn, rd, rs, imm),
            // LEA renders its memory operand in Intel bracket syntax. A zero
            // displacement renders as bare `[base]`; a positive disp as
            // `[base + disp]`; a negative disp as `[base - |disp|]`. All three
            // forms round-trip through the bracket parse path in
            // `parser::x86::x86_ir_from_mnemonic`.
            X86Instruction::Lea { rd, base, disp } => match (*disp).cmp(&0) {
                std::cmp::Ordering::Equal => write!(f, "{} {}, [{}]", mn, rd, base),
                std::cmp::Ordering::Greater => write!(f, "{} {}, [{} + {}]", mn, rd, base, disp),
                std::cmp::Ordering::Less => {
                    write!(f, "{} {}, [{} - {}]", mn, rd, base, disp.unsigned_abs())
                }
            },
            X86Instruction::MovImm { rd, imm }
            | X86Instruction::AddImm { rd, imm }
            | X86Instruction::SubImm { rd, imm }
            | X86Instruction::AndImm { rd, imm }
            | X86Instruction::OrImm { rd, imm }
            | X86Instruction::XorImm { rd, imm }
            // SHL / SHR / SAR / ROL / ROR render `mnemonic rd, count`.
            | X86Instruction::Shl { rd, imm }
            | X86Instruction::Shr { rd, imm }
            | X86Instruction::Sar { rd, imm }
            | X86Instruction::Rol { rd, imm }
            | X86Instruction::Ror { rd, imm } => write!(f, "{} {}, {}", mn, rd, imm),
            X86Instruction::CmpReg { rn, rs } | X86Instruction::TestReg { rn, rs } => {
                write!(f, "{} {}, {}", mn, rn, rs)
            }
            X86Instruction::CmpImm { rn, imm } | X86Instruction::TestImm { rn, imm } => {
                write!(f, "{} {}, {}", mn, rn, imm)
            }
            // Single-operand: render just the destination register.
            X86Instruction::Neg { rd }
            | X86Instruction::Not { rd }
            | X86Instruction::Inc { rd }
            | X86Instruction::Dec { rd } => write!(f, "{} {}", mn, rd),
            X86Instruction::Cmov { rd, rs, .. } => write!(f, "{} {}, {}", mn, rd, rs),
            // Target is opaque to the IR; render with a placeholder.
            X86Instruction::Jcc { .. } => write!(f, "{} <target>", mn),
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
/// `for X86_32`. MOV / NOT / LEA / CMOV / Jcc do not write EFLAGS — CMOV and
/// Jcc read them via `x86_reads_flags` but do not modify any flag bit; LEA is
/// pure address arithmetic. Every other variant in the current set writes
/// EFLAGS.
///
/// Crate-visible so the cost model's critical-path latency
/// (`crate::semantics::cost_x86::critical_path_latency`) can route flag
/// def-use edges through the same authoritative match arm as the search and
/// equivalence callers — adding a future flag-writer updates exactly one place.
pub(crate) fn x86_modifies_flags(instr: &X86Instruction) -> bool {
    !matches!(
        instr,
        X86Instruction::MovReg { .. }
            | X86Instruction::MovImm { .. }
            | X86Instruction::Not { .. }
            | X86Instruction::Lea { .. }
            | X86Instruction::Cmov { .. }
            | X86Instruction::Jcc { .. }
    )
}

/// CMOV and Jcc read EFLAGS; every other variant in the current set
/// is flag-agnostic on the read side. Crate-visible so search and
/// equivalence callers can route through one authoritative match arm —
/// adding a future flag-reader like SETcc then updates exactly one place.
pub fn x86_reads_flags(instr: &X86Instruction) -> bool {
    matches!(
        instr,
        X86Instruction::Cmov { .. } | X86Instruction::Jcc { .. }
    )
}

fn x86_signed_imm32_ok(imm: i64) -> bool {
    i32::try_from(imm).is_ok()
}

/// A shift count encodes as `imm8`, so it must fit `0..=255`. x86 masks the
/// count to the operand width at execution time, but the *encoding* still
/// only carries a single byte, so any negative or >255 count is unencodable
/// and must be rejected before the search proposes it.
fn x86_shift_count_imm8_ok(imm: i64) -> bool {
    u8::try_from(imm).is_ok()
}

fn x86_imm32_bitpattern_ok(imm: i64) -> bool {
    x86_signed_imm32_ok(imm) || u32::try_from(imm).is_ok()
}

fn x86_imm16_bitpattern_ok(imm: i64) -> bool {
    i16::try_from(imm).is_ok() || u16::try_from(imm).is_ok()
}

fn x86_imm8_bitpattern_ok(imm: i64) -> bool {
    i8::try_from(imm).is_ok() || u8::try_from(imm).is_ok()
}

fn x86_register_ok(reg: X86Register, mode_width: u32) -> bool {
    reg.index().is_some_and(|index| {
        index < if mode_width == 32 { 8 } else { 16 }
            && !(mode_width == 32 && reg.view() == X86RegisterView::LowByte && index >= 4)
    })
}

fn x86_register_pair_ok(lhs: X86Register, rhs: X86Register, mode_width: u32) -> bool {
    x86_register_ok(lhs, mode_width)
        && x86_register_ok(rhs, mode_width)
        && lhs.effective_width(mode_width) == rhs.effective_width(mode_width)
        && (!(lhs.is_high_byte() || rhs.is_high_byte())
            || (lhs.index().is_some_and(|index| index < 4)
                && rhs.index().is_some_and(|index| index < 4)))
}

fn x86_operand_immediate_ok(reg: X86Register, imm: i64, mode_width: u32) -> bool {
    match reg.effective_width(mode_width) {
        64 => x86_signed_imm32_ok(imm),
        32 => x86_imm32_bitpattern_ok(imm),
        16 => x86_imm16_bitpattern_ok(imm),
        8 => x86_imm8_bitpattern_ok(imm),
        _ => false,
    }
}

fn x86_mov_operand_immediate_ok(reg: X86Register, imm: i64, mode_width: u32) -> bool {
    match reg.effective_width(mode_width) {
        64 => true,
        32 => x86_imm32_bitpattern_ok(imm),
        16 => x86_imm16_bitpattern_ok(imm),
        8 => x86_imm8_bitpattern_ok(imm),
        _ => false,
    }
}

fn x86_mov_imm_ok(mode: crate::assembler::x86::X86Mode, imm: i64) -> bool {
    match mode {
        crate::assembler::x86::X86Mode::Mode64 => true,
        crate::assembler::x86::X86Mode::Mode32 => x86_imm32_bitpattern_ok(imm),
    }
}

fn x86_non_mov_imm_ok(mode: crate::assembler::x86::X86Mode, imm: i64) -> bool {
    match mode {
        crate::assembler::x86::X86Mode::Mode64 => x86_signed_imm32_ok(imm),
        crate::assembler::x86::X86Mode::Mode32 => x86_imm32_bitpattern_ok(imm),
    }
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

// --- Trait surface impls (#77) ---
// The x86 executor, symbolic, cost, assembler, and generator traits are the
// consumer-facing contract. The x86-specific modules remain as backend
// implementation details behind these impls.

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
    fn instruction_cost(
        &self,
        instruction: &X86Instruction,
        metric: &crate::semantics::cost::CostMetric,
    ) -> u64 {
        crate::semantics::cost_x86::instruction_cost(instruction, metric, 64)
    }

    /// Override the trait's `.sum()` default so `Latency` uses the sequence's
    /// critical path (`cost_x86::sequence_cost`) rather than a flat per-
    /// instruction sum; `InstructionCount` / `CodeSize` remain sums (issue #622).
    fn sequence_cost(
        &self,
        instructions: &[X86Instruction],
        metric: &crate::semantics::cost::CostMetric,
    ) -> u64 {
        crate::semantics::cost_x86::sequence_cost(instructions, metric, 64)
    }
}

impl crate::isa::traits::CostModel<X86Instruction> for X86_32 {
    fn instruction_cost(
        &self,
        instruction: &X86Instruction,
        metric: &crate::semantics::cost::CostMetric,
    ) -> u64 {
        crate::semantics::cost_x86::instruction_cost(instruction, metric, 32)
    }

    /// See the `X86_64` impl: `Latency` is the critical path, others are sums.
    fn sequence_cost(
        &self,
        instructions: &[X86Instruction],
        metric: &crate::semantics::cost::CostMetric,
    ) -> u64 {
        crate::semantics::cost_x86::sequence_cost(instructions, metric, 32)
    }
}

fn x86_can_assemble_instruction(instruction: &X86Instruction, mode_width: u32) -> bool {
    match instruction {
        X86Instruction::MovReg { rd, rs }
        | X86Instruction::AddReg { rd, rs }
        | X86Instruction::SubReg { rd, rs }
        | X86Instruction::AndReg { rd, rs }
        | X86Instruction::OrReg { rd, rs }
        | X86Instruction::XorReg { rd, rs } => x86_register_pair_ok(*rd, *rs, mode_width),
        X86Instruction::CmpReg { rn, rs } | X86Instruction::TestReg { rn, rs } => {
            x86_register_pair_ok(*rn, *rs, mode_width)
        }
        X86Instruction::ImulReg { rd, rs } => {
            x86_register_pair_ok(*rd, *rs, mode_width) && !rd.is_byte()
        }
        X86Instruction::ImulRegImm { rd, rs, imm } => {
            x86_register_pair_ok(*rd, *rs, mode_width)
                && !rd.is_byte()
                && x86_operand_immediate_ok(*rd, *imm, mode_width)
        }
        X86Instruction::Lea { rd, base, disp } => {
            x86_register_ok(*rd, mode_width)
                && !rd.is_byte()
                && x86_register_ok(*base, mode_width)
                && base.effective_width(mode_width) == mode_width
                && x86_signed_imm32_ok(*disp)
        }
        X86Instruction::MovImm { rd, imm } => {
            x86_register_ok(*rd, mode_width) && x86_mov_operand_immediate_ok(*rd, *imm, mode_width)
        }
        X86Instruction::AddImm { rd, imm }
        | X86Instruction::SubImm { rd, imm }
        | X86Instruction::AndImm { rd, imm }
        | X86Instruction::OrImm { rd, imm }
        | X86Instruction::XorImm { rd, imm } => {
            x86_register_ok(*rd, mode_width) && x86_operand_immediate_ok(*rd, *imm, mode_width)
        }
        X86Instruction::CmpImm { rn, imm } | X86Instruction::TestImm { rn, imm } => {
            x86_register_ok(*rn, mode_width) && x86_operand_immediate_ok(*rn, *imm, mode_width)
        }
        X86Instruction::Shl { rd, imm }
        | X86Instruction::Shr { rd, imm }
        | X86Instruction::Sar { rd, imm }
        | X86Instruction::Rol { rd, imm }
        | X86Instruction::Ror { rd, imm } => {
            x86_register_ok(*rd, mode_width) && x86_shift_count_imm8_ok(*imm)
        }
        X86Instruction::Neg { rd }
        | X86Instruction::Not { rd }
        | X86Instruction::Inc { rd }
        | X86Instruction::Dec { rd } => x86_register_ok(*rd, mode_width),
        X86Instruction::Cmov { rd, rs, .. } => {
            x86_register_pair_ok(*rd, *rs, mode_width) && !rd.is_byte()
        }
        X86Instruction::Jcc { .. } => true,
    }
}

impl crate::isa::traits::Assembler<X86Instruction> for X86_64 {
    fn assemble(&mut self, instructions: &[X86Instruction]) -> Result<Vec<u8>, String> {
        crate::assembler::x86::X86Assembler::new_64().assemble_instructions(instructions)
    }

    fn can_assemble(&self, instruction: &X86Instruction) -> bool {
        x86_can_assemble_instruction(instruction, 64)
    }
}

impl crate::isa::traits::Assembler<X86Instruction> for X86_32 {
    fn assemble(&mut self, instructions: &[X86Instruction]) -> Result<Vec<u8>, String> {
        crate::assembler::x86::X86Assembler::new_32().assemble_instructions(instructions)
    }

    fn can_assemble(&self, instruction: &X86Instruction) -> bool {
        x86_can_assemble_instruction(instruction, 32)
    }
}

/// x86 mutator for stochastic search. Carries filtered register and
/// immediate pools (Mode32 excludes R8-R15 once at construction, and
/// immediates are split by MOV vs non-MOV encodability) plus the four
/// operator weights borrowed from the AArch64 `Mutator`.
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
    mov_immediates: Vec<i64>,
    non_mov_immediates: Vec<i64>,
    // Shift counts encode as imm8 (`0..=255`), a stricter range than the
    // arithmetic/logical immediates, so they are filtered into their own pool
    // at construction. See `x86_shift_count_imm8_ok`.
    shift_counts: Vec<i64>,
    mode: crate::assembler::x86::X86Mode,
    weights: crate::search::config::MutationWeights,
}

impl X86Mutator {
    /// Construct a mutator. `mode` filters extended registers (Mode32
    /// excludes R8-R15) and immediate pools once at construction, then
    /// remains available for opcode-bridge immediate validation.
    /// Downstream mutation therefore cannot reintroduce extended
    /// registers or immediates that the target opcode class cannot encode.
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
        let mov_immediates = immediates
            .iter()
            .copied()
            .filter(|&imm| x86_mov_imm_ok(mode, imm))
            .collect();
        let shift_counts = immediates
            .iter()
            .copied()
            .filter(|&imm| x86_shift_count_imm8_ok(imm))
            .collect();
        let non_mov_immediates = immediates
            .into_iter()
            .filter(|&imm| x86_non_mov_imm_ok(mode, imm))
            .collect();
        Self {
            registers,
            mov_immediates,
            non_mov_immediates,
            shift_counts,
            mode,
            weights,
        }
    }

    fn pick_register<R: rand::RngExt>(&self, rng: &mut R) -> Option<X86Register> {
        if self.registers.is_empty() {
            None
        } else {
            Some(self.registers[rng.random_range(0..self.registers.len())])
        }
    }

    fn pick_mov_immediate<R: rand::RngExt>(&self, rng: &mut R) -> i64 {
        if self.mov_immediates.is_empty() {
            0
        } else {
            self.mov_immediates[rng.random_range(0..self.mov_immediates.len())]
        }
    }

    fn pick_non_mov_immediate<R: rand::RngExt>(&self, rng: &mut R) -> i64 {
        if self.non_mov_immediates.is_empty() {
            0
        } else {
            self.non_mov_immediates[rng.random_range(0..self.non_mov_immediates.len())]
        }
    }

    fn keep_or_pick_mov_immediate<R: rand::RngExt>(&self, rng: &mut R, imm: i64) -> i64 {
        if x86_mov_imm_ok(self.mode, imm) {
            imm
        } else {
            self.pick_mov_immediate(rng)
        }
    }

    fn keep_or_pick_non_mov_immediate<R: rand::RngExt>(&self, rng: &mut R, imm: i64) -> i64 {
        if x86_non_mov_imm_ok(self.mode, imm) {
            imm
        } else {
            self.pick_non_mov_immediate(rng)
        }
    }

    /// Draw a shift count from the imm8-encodable pool. Falls back to 1 (the
    /// canonical single-bit shift) when the pool holds no encodable count, so
    /// a drawn shift is always assemblable.
    fn pick_shift_count<R: rand::RngExt>(&self, rng: &mut R) -> i64 {
        if self.shift_counts.is_empty() {
            1
        } else {
            self.shift_counts[rng.random_range(0..self.shift_counts.len())]
        }
    }

    fn keep_or_pick_shift_count<R: rand::RngExt>(&self, rng: &mut R, imm: i64) -> i64 {
        if x86_shift_count_imm8_ok(imm) {
            imm
        } else {
            self.pick_shift_count(rng)
        }
    }

    fn pick_condition<R: rand::RngExt>(&self, rng: &mut R) -> X86Condition {
        X86Condition::ALL[rng.random_range(0..X86Condition::ALL.len())]
    }

    fn random_instruction<R: rand::RngExt>(&self, rng: &mut R) -> Option<X86Instruction> {
        if self.registers.is_empty() {
            return None;
        }
        // Rewritable variants only: 7 reg-reg + 7 reg-imm + CMOVcc.
        // The RNG draw order/count MUST stay in lock-step with the shared
        // free helper `generate_random_rewritable_x86_instruction`
        // (opcode → rd → rs → imm → cond, all four drawn unconditionally)
        // so callers that interleave the two stay deterministic. Two
        // helper behaviours must be mirrored exactly: (1) the trailing
        // CMOV opcode slot is dropped unless the pool holds a distinct
        // register pair (a self-CMOV is a no-op), and (2) CMOV draws its
        // source via an extra `pick_register_except` so `rs != rd`. The
        // #593 behaviour change is *which* prefiltered pool the single imm
        // draw indexes: opcode 1 (MOV) uses the MOVABS-capable `mov`
        // pool, every other imm form uses the non-MOV pool.
        // CMOV with rd == rs is a no-op, so the trailing CMOV opcode slot is
        // only offered when the pool holds a distinct pair. This MUST mirror
        // `generate_random_rewritable_x86_instruction` so the two stay in
        // lock-step (stream parity) while both filter self-CMOV.
        let opcode_count = if has_distinct_register_pair(&self.registers) {
            X86_REWRITABLE_OPCODE_COUNT
        } else {
            X86_REWRITABLE_OPCODE_COUNT - 1
        };
        let opcode = rng.random_range(0..u32::from(opcode_count));
        let rd = self.pick_register(rng)?;
        let rs = self.pick_register(rng)?;
        let imm = if opcode == 1 {
            self.pick_mov_immediate(rng)
        } else {
            self.pick_non_mov_immediate(rng)
        };
        let cond = X86Condition::ALL[rng.random_range(0..X86Condition::ALL.len())];
        // The CMOV slot resolves a distinct source register via an extra
        // `pick_register_except` draw; every other opcode reuses the `rs`
        // drawn above. This extra draw MUST stay conditional on the CMOV
        // opcode to preserve the RNG stream that the parity test
        // `x86_mutator_random_instruction_matches_shared_generator_stream`
        // pins against `generate_random_rewritable_x86_instruction`.
        let opcode = u8::try_from(opcode).expect("opcode index fits in u8");
        let final_rs = if opcode == X86_REWRITABLE_OPCODE_COUNT - 1 {
            pick_register_except(rng, &self.registers, rd)
                .expect("CMOV opcode requires a distinct register pair")
        } else {
            rs
        };
        Some(build_x86_instruction_by_opcode(
            opcode, rd, final_rs, imm, cond,
        ))
    }

    fn mutate_operand<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.is_empty() {
            return;
        }
        let idx = rng.random_range(0..sequence.len());
        if self.registers.is_empty() {
            match &mut sequence[idx] {
                X86Instruction::MovImm { imm, .. } => *imm = self.pick_mov_immediate(rng),
                X86Instruction::AddImm { imm, .. }
                | X86Instruction::SubImm { imm, .. }
                | X86Instruction::AndImm { imm, .. }
                | X86Instruction::OrImm { imm, .. }
                | X86Instruction::XorImm { imm, .. }
                | X86Instruction::CmpImm { imm, .. }
                // The 3-operand IMUL immediate draws from the imm32 pool too.
                | X86Instruction::ImulRegImm { imm, .. }
                | X86Instruction::TestImm { imm, .. } => *imm = self.pick_non_mov_immediate(rng),
                // LEA's displacement is a signed disp32; mutate it from the
                // non-MOV (imm32) pool even with no register pool.
                X86Instruction::Lea { disp, .. } => *disp = self.pick_non_mov_immediate(rng),
                // SHL / SHR / SAR / ROL / ROR carry an imm8 count; mutate it
                // from the imm8-encodable pool even with no register pool.
                X86Instruction::Shl { imm, .. }
                | X86Instruction::Shr { imm, .. }
                | X86Instruction::Sar { imm, .. }
                | X86Instruction::Rol { imm, .. }
                | X86Instruction::Ror { imm, .. } => *imm = self.pick_shift_count(rng),
                X86Instruction::MovReg { .. }
                | X86Instruction::AddReg { .. }
                | X86Instruction::SubReg { .. }
                | X86Instruction::AndReg { .. }
                | X86Instruction::OrReg { .. }
                | X86Instruction::XorReg { .. }
                | X86Instruction::CmpReg { .. }
                | X86Instruction::TestReg { .. }
                | X86Instruction::Neg { .. }
                | X86Instruction::Not { .. }
                | X86Instruction::Inc { .. }
                | X86Instruction::Dec { .. }
                // IMUL rd, rs has no immediate, so it is a no-op with no pool.
                | X86Instruction::ImulReg { .. }
                | X86Instruction::Jcc { .. } => {}
                X86Instruction::Cmov { cond, .. } => *cond = self.pick_condition(rng),
            }
            return;
        }
        match &mut sequence[idx] {
            X86Instruction::MovReg { rd, rs } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *rs = self.pick_register(rng).expect("register pool is non-empty");
                }
            }
            X86Instruction::MovImm { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *imm = self.pick_mov_immediate(rng);
                }
            }
            X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            // IMUL rd, rs mutates either register slot, like the other reg-reg
            // forms.
            | X86Instruction::ImulReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *rs = self.pick_register(rng).expect("register pool is non-empty");
                }
            }
            // IMUL rd, rs, imm mutates one of the three operand slots.
            X86Instruction::ImulRegImm { rd, rs, imm } => match rng.random_range(0..3u32) {
                0 => *rd = self.pick_register(rng).expect("register pool is non-empty"),
                1 => *rs = self.pick_register(rng).expect("register pool is non-empty"),
                _ => *imm = self.pick_non_mov_immediate(rng),
            },
            // LEA rd, [base + disp] mutates one of the three operand slots: the
            // destination register, the base register, or the disp32.
            X86Instruction::Lea { rd, base, disp } => match rng.random_range(0..3u32) {
                0 => *rd = self.pick_register(rng).expect("register pool is non-empty"),
                1 => *base = self.pick_register(rng).expect("register pool is non-empty"),
                _ => *disp = self.pick_non_mov_immediate(rng),
            },
            X86Instruction::AddImm { rd, imm }
            | X86Instruction::SubImm { rd, imm }
            | X86Instruction::AndImm { rd, imm }
            | X86Instruction::OrImm { rd, imm }
            | X86Instruction::XorImm { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *imm = self.pick_non_mov_immediate(rng);
                }
            }
            X86Instruction::CmpReg { rn, rs } | X86Instruction::TestReg { rn, rs } => {
                if rng.random_bool(0.5) {
                    *rn = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *rs = self.pick_register(rng).expect("register pool is non-empty");
                }
            }
            X86Instruction::CmpImm { rn, imm } | X86Instruction::TestImm { rn, imm } => {
                if rng.random_bool(0.5) {
                    *rn = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *imm = self.pick_non_mov_immediate(rng);
                }
            }
            // SHL / SHR / SAR / ROL / ROR mutate either the destination register
            // or the imm8 count.
            X86Instruction::Shl { rd, imm }
            | X86Instruction::Shr { rd, imm }
            | X86Instruction::Sar { rd, imm }
            | X86Instruction::Rol { rd, imm }
            | X86Instruction::Ror { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *imm = self.pick_shift_count(rng);
                }
            }
            // NEG / NOT / INC / DEC have a single register operand; mutate it.
            X86Instruction::Neg { rd }
            | X86Instruction::Not { rd }
            | X86Instruction::Inc { rd }
            | X86Instruction::Dec { rd } => {
                *rd = self.pick_register(rng).expect("register pool is non-empty");
            }
            X86Instruction::Cmov { rd, rs, cond } => {
                // Treat the condition code as a mutable operand alongside
                // the destination and source registers. CMOVcc with rd == rs
                // is a no-op, so register mutation samples from the pool minus
                // the other operand to avoid collapsing into a self-CMOV.
                match rng.random_range(0..3u32) {
                    0 => *rd = pick_register_except(rng, &self.registers, *rs).unwrap_or(*rd),
                    1 => *rs = pick_register_except(rng, &self.registers, *rd).unwrap_or(*rs),
                    _ => *cond = self.pick_condition(rng),
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
    /// has no rd, so it only swaps between register and immediate CMP
    /// forms.
    ///
    /// Note the deliberate asymmetry: the reg-reg and reg-imm groups
    /// sample from a range that includes the current variant, so they may
    /// produce an identity mutation. CMP, by contrast, always bridges
    /// `CmpReg` ↔ `CmpImm`, so a CMP opcode mutation is guaranteed to
    /// change the form. This is intentional, not an oversight.
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
                0 => X86Instruction::MovImm {
                    rd,
                    imm: self.keep_or_pick_mov_immediate(rng, imm),
                },
                1 => X86Instruction::AddImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
                2 => X86Instruction::SubImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
                3 => X86Instruction::AndImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
                4 => X86Instruction::OrImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
                _ => X86Instruction::XorImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
            },
            X86Instruction::CmpReg { rn, .. } => X86Instruction::CmpImm {
                rn,
                imm: self.pick_non_mov_immediate(rng),
            },
            X86Instruction::CmpImm { rn, .. } => match self.pick_register(rng) {
                Some(rs) => X86Instruction::CmpReg { rn, rs },
                None => current,
            },
            // TEST mirrors CMP: the opcode-bridge mutation always flips
            // between its register and immediate forms.
            X86Instruction::TestReg { rn, .. } => X86Instruction::TestImm {
                rn,
                imm: self.pick_non_mov_immediate(rng),
            },
            X86Instruction::TestImm { rn, .. } => match self.pick_register(rng) {
                Some(rs) => X86Instruction::TestReg { rn, rs },
                None => current,
            },
            // NEG / NOT / INC / DEC share the single-operand (rd-only) shape,
            // so the opcode-bridge mutation swaps among the four. Like the
            // reg-reg / reg-imm groups (and unlike the guaranteed-change
            // CMP↔TEST pair), the draw range includes the current variant, so
            // it may produce an identity mutation.
            X86Instruction::Neg { rd }
            | X86Instruction::Not { rd }
            | X86Instruction::Inc { rd }
            | X86Instruction::Dec { rd } => match rng.random_range(0..4u32) {
                0 => X86Instruction::Neg { rd },
                1 => X86Instruction::Not { rd },
                2 => X86Instruction::Inc { rd },
                _ => X86Instruction::Dec { rd },
            },
            // SHL / SHR / SAR share the reg-plus-count shape, so the
            // opcode-bridge mutation swaps among the three, carrying the
            // current count through (re-drawing it only if it became
            // unencodable). Like the reg-reg / reg-imm groups, the draw range
            // includes the current variant, so it may be an identity mutation.
            X86Instruction::Shl { rd, imm }
            | X86Instruction::Shr { rd, imm }
            | X86Instruction::Sar { rd, imm } => {
                let imm = self.keep_or_pick_shift_count(rng, imm);
                match rng.random_range(0..3u32) {
                    0 => X86Instruction::Shl { rd, imm },
                    1 => X86Instruction::Shr { rd, imm },
                    _ => X86Instruction::Sar { rd, imm },
                }
            }
            // ROL / ROR share the reg-plus-count shape but a distinct
            // (CF/OF-only) flag model, so they bridge only to each other —
            // never to a shift, whose SF/ZF/PF semantics differ. Carry the
            // current count through, re-drawing only if it became unencodable.
            // The draw range includes the current variant, so it may be an
            // identity mutation.
            X86Instruction::Rol { rd, imm } | X86Instruction::Ror { rd, imm } => {
                let imm = self.keep_or_pick_shift_count(rng, imm);
                if rng.random_bool(0.5) {
                    X86Instruction::Rol { rd, imm }
                } else {
                    X86Instruction::Ror { rd, imm }
                }
            }
            // IMUL has a distinct (CF/OF-only-defined) flag model that no other
            // family shares, so — like Cmov — it has no opcode-shape sibling to
            // bridge to. Keep both IMUL forms unchanged here; operand mutation
            // and whole-instruction replacement still explore them.
            X86Instruction::ImulReg { .. } | X86Instruction::ImulRegImm { .. } => current,
            // LEA has a unique (rd, base, disp) shape and a flag-free model that
            // no other family shares, so — like IMUL and Cmov — it has no
            // opcode-shape sibling to bridge to. Keep it unchanged; operand
            // mutation and whole-instruction replacement still explore it.
            X86Instruction::Lea { .. } => current,
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
        let n = sequence.len();
        let a = rng.random_range(0..n);
        let offset = rng.random_range(0..(n - 1));
        let b = (a + 1 + offset) % n;
        sequence.swap(a, b);
    }

    fn mutate_instruction<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.is_empty() {
            return;
        }
        let idx = rng.random_range(0..sequence.len());
        if let Some(instr) = self.random_instruction(rng) {
            sequence[idx] = instr;
        }
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
        let r: f64 = rng.random();
        match self.weights.select_index(r) {
            0 => self.mutate_operand(rng, &mut out),
            1 => self.mutate_opcode(rng, &mut out),
            2 => self.mutate_swap(rng, &mut out),
            _ => self.mutate_instruction(rng, &mut out),
        }
        out
    }
}

/// Stateless generator producing every rewritable x86 variant for a
/// given register and immediate pool. Jcc is intentionally excluded:
/// it is a fixed terminator, not a search candidate.
#[derive(Clone, Copy, Debug, Default)]
pub struct X86InstructionGenerator;

// One entry per rewritable opcode family: 6 reg-reg + 6 reg-imm + CMP + TEST
// (each reg/imm) + NEG + NOT + INC + DEC + SHL + SHR + SAR + ROL + ROR +
// IMUL (2-op) + IMUL (3-op) + CMOVcc. CMOVcc counts as a single family here
// even though `generate_all` expands it across all 16 `X86Condition::ALL`
// variants per register pair.
//
// CMOV MUST remain the LAST opcode (index COUNT - 1 == 28): both
// `X86Mutator::random_instruction` and
// `generate_random_rewritable_x86_instruction` gate the extra distinct-source
// CMOV draw on `opcode == X86_REWRITABLE_OPCODE_COUNT - 1`. New flag-only
// families (CMP, TEST), single-operand families (NEG, NOT, INC, DEC), the
// immediate-count shift families (SHL, SHR, SAR), the immediate-count
// rotate families (ROL, ROR), the two IMUL forms, and LEA are inserted before
// CMOV in `build_x86_instruction_by_opcode` to preserve that invariant.
const X86_REWRITABLE_OPCODE_COUNT: u8 = 29;

fn has_distinct_register_pair(registers: &[X86Register]) -> bool {
    let Some(first) = registers.first() else {
        return false;
    };
    registers.iter().any(|reg| reg != first)
}

/// Maps a rewritable opcode index in `0..X86_REWRITABLE_OPCODE_COUNT` to the
/// `X86Instruction` variant it denotes, using operands the caller has already
/// drawn. This is the single source of truth for the opcode → variant table;
/// `X86Mutator::random_instruction` and
/// `generate_random_rewritable_x86_instruction` both delegate here so the two
/// dispatch tables cannot drift (see issue #348). Operand drawing and RNG draw
/// order stay at the call sites; the CMOV slot (the last index,
/// `X86_REWRITABLE_OPCODE_COUNT - 1`) consumes the `rs` the caller resolved
/// via `pick_register_except` so `rs != rd`.
///
/// Keep this in lock-step with `X86_REWRITABLE_OPCODE_COUNT` and the
/// `opcode_dispatch_is_consistent` test, which pins the full mapping.
pub(crate) fn build_x86_instruction_by_opcode(
    opcode: u8,
    rd: X86Register,
    rs: X86Register,
    imm: i64,
    cond: X86Condition,
) -> X86Instruction {
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
        14 => X86Instruction::TestReg { rn: rd, rs },
        15 => X86Instruction::TestImm { rn: rd, imm },
        // NEG / NOT / INC / DEC are single-operand: they consume only `rd`
        // (rs/imm/cond are ignored).
        16 => X86Instruction::Neg { rd },
        17 => X86Instruction::Not { rd },
        18 => X86Instruction::Inc { rd },
        19 => X86Instruction::Dec { rd },
        // SHL / SHR / SAR consume `rd` plus the shared `imm` shift count. The
        // count is only checked for imm8-encodability at `can_assemble` time,
        // so no extra RNG draw is introduced here — the two dispatch sites stay
        // in lock-step on the shared `imm`.
        20 => X86Instruction::Shl { rd, imm },
        21 => X86Instruction::Shr { rd, imm },
        22 => X86Instruction::Sar { rd, imm },
        // ROL / ROR consume `rd` plus the shared `imm` rotate count, exactly
        // like the shifts — no extra RNG draw, so the two dispatch sites stay
        // in lock-step on the shared `imm`.
        23 => X86Instruction::Rol { rd, imm },
        24 => X86Instruction::Ror { rd, imm },
        // IMUL (2-op) consumes rd + rs; IMUL (3-op) consumes rd + rs + the
        // shared `imm`. No extra RNG draw, so the two dispatch sites stay in
        // lock-step on the shared operands.
        25 => X86Instruction::ImulReg { rd, rs },
        26 => X86Instruction::ImulRegImm { rd, rs, imm },
        // LEA consumes rd as the destination, rs as the base register, and the
        // shared `imm` as the displacement. No extra RNG draw, so the two
        // dispatch sites stay in lock-step on the shared operands.
        27 => X86Instruction::Lea {
            rd,
            base: rs,
            disp: imm,
        },
        // Cmov stays last (index 28 == X86_REWRITABLE_OPCODE_COUNT - 1) so the
        // CMOV distinct-register draw at the two generation sites stays correct.
        28 => X86Instruction::Cmov { rd, rs, cond },
        _ => unreachable!("opcode out of range"),
    }
}

fn pick_register_except<R: Rng + ?Sized>(
    rng: &mut R,
    registers: &[X86Register],
    excluded: X86Register,
) -> Option<X86Register> {
    let available = registers.iter().filter(|&&reg| reg != excluded).count();
    if available == 0 {
        return None;
    }
    let target = rng.random_range(0..available);
    registers
        .iter()
        .copied()
        .filter(|&reg| reg != excluded)
        .nth(target)
}

fn generate_random_rewritable_x86_instruction<R: Rng + ?Sized>(
    rng: &mut R,
    registers: &[X86Register],
    immediates: &[i64],
) -> X86Instruction {
    assert!(
        !registers.is_empty(),
        "x86 random instruction generation requires a register pool"
    );
    assert!(
        !immediates.is_empty(),
        "x86 random instruction generation requires an immediate pool"
    );

    // CMOVcc with rd == rs is a no-op, so it is only a candidate when the
    // register pool holds two distinct registers. Drop the trailing CMOV
    // opcode slot when no distinct pair exists.
    let opcode_count = if has_distinct_register_pair(registers) {
        X86_REWRITABLE_OPCODE_COUNT
    } else {
        X86_REWRITABLE_OPCODE_COUNT - 1
    };
    let opcode = rng.random_range(0..u32::from(opcode_count));
    let rd = registers[rng.random_range(0..registers.len())];
    let rs = registers[rng.random_range(0..registers.len())];
    let imm = immediates[rng.random_range(0..immediates.len())];
    let cond = X86Condition::ALL[rng.random_range(0..X86Condition::ALL.len())];
    // Mirror `X86Mutator::random_instruction`: the CMOV slot draws a distinct
    // source register; every other opcode reuses `rs`. Keep this draw
    // conditional on the CMOV opcode so both paths share one RNG stream.
    let opcode = u8::try_from(opcode).expect("opcode index fits in u8");
    let final_rs = if opcode == X86_REWRITABLE_OPCODE_COUNT - 1 {
        pick_register_except(rng, registers, rd)
            .expect("CMOV opcode requires a distinct register pair")
    } else {
        rs
    };
    build_x86_instruction_by_opcode(opcode, rd, final_rs, imm, cond)
}

/// Default register pool for x86 stochastic / symbolic search.
///
/// Mirrors the AArch64 baseline of a small GPR subset. RSP and RBP are
/// deliberately excluded so search never touches the stack frame.
pub fn default_x86_registers() -> Vec<X86Register> {
    vec![
        X86Register::RAX,
        X86Register::RCX,
        X86Register::RDX,
        X86Register::RBX,
        X86Register::RSI,
        X86Register::RDI,
        X86Register::R8,
        X86Register::R9,
    ]
}

/// Default immediate pool for x86 search. Same constants as the AArch64
/// search baseline so the two backends use comparable candidate spaces.
pub fn default_x86_immediates() -> Vec<i64> {
    vec![
        0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
    ]
}

impl InstructionGenerator<X86Instruction> for X86InstructionGenerator {
    fn generate_all(&self, registers: &[X86Register], immediates: &[i64]) -> Vec<X86Instruction> {
        let mut out = Vec::new();
        // Register-register variants (8 data mnemonics).
        for &rd in registers {
            for &rs in registers {
                if !x86_register_pair_ok(rd, rs, 64) {
                    continue;
                }
                out.push(X86Instruction::MovReg { rd, rs });
                out.push(X86Instruction::AddReg { rd, rs });
                out.push(X86Instruction::SubReg { rd, rs });
                out.push(X86Instruction::AndReg { rd, rs });
                out.push(X86Instruction::OrReg { rd, rs });
                out.push(X86Instruction::XorReg { rd, rs });
                out.push(X86Instruction::CmpReg { rn: rd, rs });
                out.push(X86Instruction::TestReg { rn: rd, rs });
            }
        }
        // Register-immediate variants (8 data mnemonics).
        for &rd in registers {
            for &imm in immediates {
                if x86_mov_operand_immediate_ok(rd, imm, 64) {
                    out.push(X86Instruction::MovImm { rd, imm });
                }
                if x86_operand_immediate_ok(rd, imm, 64) {
                    out.push(X86Instruction::AddImm { rd, imm });
                    out.push(X86Instruction::SubImm { rd, imm });
                    out.push(X86Instruction::AndImm { rd, imm });
                    out.push(X86Instruction::OrImm { rd, imm });
                    out.push(X86Instruction::XorImm { rd, imm });
                    out.push(X86Instruction::CmpImm { rn: rd, imm });
                    out.push(X86Instruction::TestImm { rn: rd, imm });
                }
            }
        }
        // Single-operand variants (NEG, NOT, INC, DEC): one per register.
        for &rd in registers {
            out.push(X86Instruction::Neg { rd });
            out.push(X86Instruction::Not { rd });
            out.push(X86Instruction::Inc { rd });
            out.push(X86Instruction::Dec { rd });
        }
        // Immediate-count shifts (SHL, SHR, SAR): one per (register, count).
        // The count encodes as imm8, so only imm8-encodable immediates yield a
        // candidate; larger pool entries are skipped here rather than emitted
        // and later rejected by `can_assemble`.
        for &rd in registers {
            for &imm in immediates {
                if !x86_shift_count_imm8_ok(imm) {
                    continue;
                }
                out.push(X86Instruction::Shl { rd, imm });
                out.push(X86Instruction::Shr { rd, imm });
                out.push(X86Instruction::Sar { rd, imm });
            }
        }
        // Immediate-count rotates (ROL, ROR): same imm8-count shape as the
        // shifts, so only imm8-encodable counts yield a candidate.
        for &rd in registers {
            for &imm in immediates {
                if !x86_shift_count_imm8_ok(imm) {
                    continue;
                }
                out.push(X86Instruction::Rol { rd, imm });
                out.push(X86Instruction::Ror { rd, imm });
            }
        }
        // IMUL (2-operand): `imul rd, rs` for every (register, register) pair,
        // including rd == rs (self-multiply is meaningful, unlike self-CMOV).
        for &rd in registers {
            for &rs in registers {
                if !x86_register_pair_ok(rd, rs, 64) || rd.is_byte() {
                    continue;
                }
                out.push(X86Instruction::ImulReg { rd, rs });
            }
        }
        // IMUL (3-operand): `imul rd, rs, imm` for every (rd, rs, imm) triple.
        // The immediate encodes as imm32, so non-imm32 pool entries are skipped
        // here rather than emitted and later rejected by `can_assemble`.
        for &rd in registers {
            for &rs in registers {
                if !x86_register_pair_ok(rd, rs, 64) || rd.is_byte() {
                    continue;
                }
                for &imm in immediates {
                    if !x86_operand_immediate_ok(rd, imm, 64) {
                        continue;
                    }
                    out.push(X86Instruction::ImulRegImm { rd, rs, imm });
                }
            }
        }
        // LEA: `lea rd, [base + disp]` for every (rd, base, disp) triple,
        // including rd == base (self-base is meaningful: it adds disp to rd).
        // The displacement encodes as a signed disp32, so non-imm32 pool
        // entries are skipped here rather than emitted and later rejected by
        // `can_assemble`.
        for &rd in registers {
            for &base in registers {
                if rd.is_byte()
                    || !matches!(
                        base.view(),
                        X86RegisterView::Native | X86RegisterView::Dword
                    )
                    || !x86_register_ok(rd, 64)
                {
                    continue;
                }
                for &disp in immediates {
                    if i32::try_from(disp).is_err() {
                        continue;
                    }
                    out.push(X86Instruction::Lea { rd, base, disp });
                }
            }
        }
        // CMOVcc is rewritable and reads flags, so enumerate every
        // condition for each non-identical register pair. Jcc remains
        // excluded.
        for &rd in registers {
            for &rs in registers {
                if rd == rs || !x86_register_pair_ok(rd, rs, 64) || rd.is_byte() {
                    continue;
                }
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
        generate_random_rewritable_x86_instruction(rng, registers, immediates)
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
            1 => match *instruction {
                X86Instruction::Cmov { rd, rs, cond } => X86Instruction::Cmov {
                    rd: pick_register_except(rng, registers, rs).unwrap_or(rd),
                    rs,
                    cond,
                },
                _ => {
                    let new_rd = registers[rng.random_range(0..registers.len())];
                    with_destination(*instruction, new_rd)
                }
            },
            2 => match *instruction {
                X86Instruction::Cmov { rd, rs, cond } => X86Instruction::Cmov {
                    rd,
                    rs: pick_register_except(rng, registers, rd).unwrap_or(rs),
                    cond,
                },
                _ => {
                    let new_rs = registers[rng.random_range(0..registers.len())];
                    let new_imm = immediates[rng.random_range(0..immediates.len())];
                    with_sources(*instruction, new_rs, new_imm)
                }
            },
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
        // CMP / TEST variants have rn instead of rd; mutate rn for symmetry.
        X86Instruction::CmpReg { rs, .. } => X86Instruction::CmpReg { rn: new_rd, rs },
        X86Instruction::CmpImm { imm, .. } => X86Instruction::CmpImm { rn: new_rd, imm },
        X86Instruction::TestReg { rs, .. } => X86Instruction::TestReg { rn: new_rd, rs },
        X86Instruction::TestImm { imm, .. } => X86Instruction::TestImm { rn: new_rd, imm },
        // NEG / NOT / INC / DEC have only a destination register; redirect it.
        X86Instruction::Neg { .. } => X86Instruction::Neg { rd: new_rd },
        X86Instruction::Not { .. } => X86Instruction::Not { rd: new_rd },
        X86Instruction::Inc { .. } => X86Instruction::Inc { rd: new_rd },
        X86Instruction::Dec { .. } => X86Instruction::Dec { rd: new_rd },
        // SHL / SHR / SAR redirect the destination, carrying the count.
        X86Instruction::Shl { imm, .. } => X86Instruction::Shl { rd: new_rd, imm },
        X86Instruction::Shr { imm, .. } => X86Instruction::Shr { rd: new_rd, imm },
        X86Instruction::Sar { imm, .. } => X86Instruction::Sar { rd: new_rd, imm },
        // ROL / ROR likewise redirect the destination, carrying the count.
        X86Instruction::Rol { imm, .. } => X86Instruction::Rol { rd: new_rd, imm },
        X86Instruction::Ror { imm, .. } => X86Instruction::Ror { rd: new_rd, imm },
        // IMUL redirects the destination, carrying the source (and imm).
        X86Instruction::ImulReg { rs, .. } => X86Instruction::ImulReg { rd: new_rd, rs },
        X86Instruction::ImulRegImm { rs, imm, .. } => X86Instruction::ImulRegImm {
            rd: new_rd,
            rs,
            imm,
        },
        // LEA redirects the destination, carrying the base and displacement.
        X86Instruction::Lea { base, disp, .. } => X86Instruction::Lea {
            rd: new_rd,
            base,
            disp,
        },
        X86Instruction::Cmov { rd, rs, cond } => X86Instruction::Cmov {
            rd: if new_rd == rs { rd } else { new_rd },
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
        X86Instruction::TestReg { rn, .. } => X86Instruction::TestReg { rn, rs: new_rs },
        X86Instruction::TestImm { rn, .. } => X86Instruction::TestImm { rn, imm: new_imm },
        // NEG / NOT / INC / DEC have no source operand to vary; carry through
        // unchanged.
        X86Instruction::Neg { rd } => X86Instruction::Neg { rd },
        X86Instruction::Not { rd } => X86Instruction::Not { rd },
        X86Instruction::Inc { rd } => X86Instruction::Inc { rd },
        X86Instruction::Dec { rd } => X86Instruction::Dec { rd },
        // SHL / SHR / SAR vary the shift count via `new_imm`, but only when it
        // is imm8-encodable; otherwise keep the existing count so the result
        // stays assemblable.
        X86Instruction::Shl { rd, imm } => X86Instruction::Shl {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        X86Instruction::Shr { rd, imm } => X86Instruction::Shr {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        X86Instruction::Sar { rd, imm } => X86Instruction::Sar {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        // ROL / ROR vary the rotate count via `new_imm` when it is imm8-encodable;
        // otherwise keep the existing count so the result stays assemblable.
        X86Instruction::Rol { rd, imm } => X86Instruction::Rol {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        X86Instruction::Ror { rd, imm } => X86Instruction::Ror {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        // IMUL (2-op) varies its source register; (3-op) varies both source
        // register and immediate.
        X86Instruction::ImulReg { rd, .. } => X86Instruction::ImulReg { rd, rs: new_rs },
        X86Instruction::ImulRegImm { rd, .. } => X86Instruction::ImulRegImm {
            rd,
            rs: new_rs,
            imm: new_imm,
        },
        // LEA varies both its base register and the displacement.
        X86Instruction::Lea { rd, .. } => X86Instruction::Lea {
            rd,
            base: new_rs,
            disp: new_imm,
        },
        // Cmov's `rs` is mutated; `cond` and `rd` carry through unchanged.
        X86Instruction::Cmov { rd, rs, cond } => X86Instruction::Cmov {
            rd,
            rs: if new_rs == rd { rs } else { new_rs },
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

    type ImmForm = (&'static str, fn(i64) -> X86Instruction);
    type RegImmForm = (&'static str, fn(X86Register, i64) -> X86Instruction);

    #[test]
    fn x86_generator_generate_all_covers_every_opcode() {
        use crate::isa::traits::{InstructionGenerator, InstructionType};
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1, -1];
        let all = X86InstructionGenerator.generate_all(&regs, &imms);

        let n = regs.len();
        let m = imms.len();
        // Shifts only enumerate over imm8-encodable counts (e.g. -1 is dropped).
        let shift_m = imms
            .iter()
            .filter(|&&imm| u8::try_from(imm).is_ok())
            .count();
        // The 3-operand IMUL only enumerates over imm32-encodable immediates;
        // LEA enumerates over imm32-encodable displacements with the same filter.
        let imul_m = imms
            .iter()
            .filter(|&&imm| i32::try_from(imm).is_ok())
            .count();
        let lea_m = imul_m;
        // 8 reg-reg families + 8 reg-imm families + 4 single-operand families
        // (NEG, NOT, INC, DEC) + 3 shift families (SHL, SHR, SAR over imm8
        // counts) + 2 rotate families (ROL, ROR over imm8 counts) + IMUL 2-op
        // (every register pair) + IMUL 3-op (every (rd, rs, imm32) triple) +
        // LEA (every (rd, base, disp32) triple) + CMOVcc over distinct pairs.
        let expected_len = 8 * n * n
            + 8 * n * m
            + 4 * n
            + 3 * n * shift_m
            + 2 * n * shift_m
            + n * n
            + n * n * imul_m
            + n * n * lea_m
            + n * (n - 1) * X86Condition::ALL.len();
        assert_eq!(
            all.len(),
            expected_len,
            "generate_all should only prune CMOV self-pairs and non-imm8 shift/rotate / non-imm32 imul/lea counts from the full pool"
        );

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
    fn x86_generator_filters_self_cmov_candidates() {
        use crate::isa::traits::InstructionGenerator;
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64];
        let all = X86InstructionGenerator.generate_all(&regs, &imms);

        for &cond in &X86Condition::ALL {
            assert!(
                all.contains(&X86Instruction::Cmov {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    cond,
                }),
                "generator must keep cross-register cmov{} rax, rbx",
                cond
            );
            assert!(
                all.contains(&X86Instruction::Cmov {
                    rd: X86Register::RBX,
                    rs: X86Register::RAX,
                    cond,
                }),
                "generator must keep cross-register cmov{} rbx, rax",
                cond
            );
        }

        assert!(
            !all.iter()
                .any(|instr| matches!(instr, X86Instruction::Cmov { rd, rs, .. } if rd == rs)),
            "generate_all must skip no-op CMOV candidates where rd == rs"
        );
    }

    /// Safety invariant (restored from the deleted `candidate_x86.rs`): the
    /// default search register pool must never include the stack or frame
    /// pointer, and must contain no duplicates. A regression here would let
    /// search clobber RSP/RBP in a patched binary.
    #[test]
    fn default_register_pool_excludes_stack_pointer_and_base_pointer() {
        use std::collections::HashSet;
        let pool = default_x86_registers();
        assert!(
            !pool.contains(&X86Register::RSP),
            "RSP must not be in the default search pool"
        );
        assert!(
            !pool.contains(&X86Register::RBP),
            "RBP must not be in the default search pool"
        );
        let unique: HashSet<_> = pool.iter().collect();
        assert_eq!(
            unique.len(),
            pool.len(),
            "default register pool must not contain duplicates"
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
    fn x86_generator_random_filters_self_cmov_candidates() {
        use crate::isa::traits::InstructionGenerator;
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(453);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1];
        let mut saw_cmov = false;

        for _ in 0..2000 {
            let instr = X86InstructionGenerator.generate_random(&mut rng, &regs, &imms);
            if let X86Instruction::Cmov { rd, rs, .. } = instr {
                saw_cmov = true;
                assert_ne!(rd, rs, "random generator emitted self-CMOV {instr:?}");
            }
        }

        assert!(saw_cmov, "random trait generator never emitted CMOVcc");
    }

    #[test]
    fn shared_x86_random_generator_uses_rewritable_pool() {
        use crate::isa::traits::InstructionType;
        use rand::SeedableRng;

        fn assert_from_pools(instr: X86Instruction, regs: &[X86Register], imms: &[i64]) {
            if let Some(dst) = instr.destination() {
                assert!(regs.contains(&dst), "destination {:?} outside pool", dst);
            }
            for src in instr.source_registers() {
                assert!(regs.contains(&src), "source {:?} outside pool", src);
            }
            match instr {
                X86Instruction::MovImm { imm, .. }
                | X86Instruction::AddImm { imm, .. }
                | X86Instruction::SubImm { imm, .. }
                | X86Instruction::AndImm { imm, .. }
                | X86Instruction::OrImm { imm, .. }
                | X86Instruction::XorImm { imm, .. }
                | X86Instruction::CmpImm { imm, .. }
                | X86Instruction::TestImm { imm, .. }
                // Shifts and rotates draw their count from the same shared
                // `imm` slot in `generate_random_rewritable_x86_instruction`,
                // so it is in the pool too.
                | X86Instruction::Shl { imm, .. }
                | X86Instruction::Shr { imm, .. }
                | X86Instruction::Sar { imm, .. }
                | X86Instruction::Rol { imm, .. }
                | X86Instruction::Ror { imm, .. }
                // The 3-operand IMUL draws its immediate from the shared pool.
                | X86Instruction::ImulRegImm { imm, .. }
                // LEA draws its displacement from the same shared `imm` slot.
                | X86Instruction::Lea { disp: imm, .. } => {
                    assert!(imms.contains(&imm), "immediate {} outside pool", imm);
                }
                X86Instruction::MovReg { .. }
                | X86Instruction::AddReg { .. }
                | X86Instruction::SubReg { .. }
                | X86Instruction::AndReg { .. }
                | X86Instruction::OrReg { .. }
                | X86Instruction::XorReg { .. }
                | X86Instruction::CmpReg { .. }
                | X86Instruction::TestReg { .. }
                | X86Instruction::Neg { .. }
                | X86Instruction::Not { .. }
                | X86Instruction::Inc { .. }
                | X86Instruction::Dec { .. }
                | X86Instruction::ImulReg { .. }
                | X86Instruction::Cmov { .. }
                | X86Instruction::Jcc { .. } => {}
            }
        }

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(252);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1];
        let count = X86InstructionGenerator.opcode_count();
        let mut saw_cmov = false;

        for _ in 0..2000 {
            let instr = generate_random_rewritable_x86_instruction(&mut rng, &regs, &imms);
            saw_cmov |= matches!(instr, X86Instruction::Cmov { .. });
            assert!(instr.opcode_id() < count);
            assert!(!matches!(instr, X86Instruction::Jcc { .. }));
            assert_from_pools(instr, &regs, &imms);
        }

        assert!(saw_cmov, "shared generator never emitted CMOVcc");
    }

    #[test]
    fn x86_32_generic_encodability_rejects_extended_registers() {
        let seq = [X86Instruction::MovReg {
            rd: X86Register::R8,
            rs: X86Register::RAX,
        }];
        assert!(!crate::search::candidate::is_sequence_encodable_for(
            &seq, &X86_32
        ));
        assert!(crate::search::candidate::is_sequence_encodable_for(
            &seq, &X86_64
        ));
    }

    #[test]
    fn x86_generic_encodability_rejects_out_of_range_immediates() {
        let add_imm64 = [X86Instruction::AddImm {
            rd: X86Register::RAX,
            imm: i64::MAX,
        }];
        assert!(!crate::search::candidate::is_sequence_encodable_for(
            &add_imm64, &X86_64
        ));
        assert!(!crate::search::candidate::is_sequence_encodable_for(
            &add_imm64, &X86_32
        ));

        let mov_imm64 = [X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: i64::MAX,
        }];
        assert!(crate::search::candidate::is_sequence_encodable_for(
            &mov_imm64, &X86_64
        ));
        assert!(!crate::search::candidate::is_sequence_encodable_for(
            &mov_imm64, &X86_32
        ));

        let add_imm32_high_bit = [X86Instruction::AddImm {
            rd: X86Register::RAX,
            imm: i64::from(u32::MAX),
        }];
        assert!(
            !crate::search::candidate::is_sequence_encodable_for(&add_imm32_high_bit, &X86_64),
            "x86-64 non-MOV immediates sign-extend imm32 and cannot encode positive u32::MAX"
        );
        assert!(
            crate::search::candidate::is_sequence_encodable_for(&add_imm32_high_bit, &X86_32),
            "x86-32 non-MOV immediates can encode canonical u32 bit patterns"
        );
    }

    #[test]
    fn x86_64_can_assemble_rejects_non_mov_immediates_outside_imm32() {
        fn can_assemble(instruction: X86Instruction) -> bool {
            <X86_64 as crate::isa::traits::Assembler<X86Instruction>>::can_assemble(
                &X86_64,
                &instruction,
            )
        }

        let immediate_forms: [ImmForm; 6] = [
            ("add", |imm| X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("sub", |imm| X86Instruction::SubImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("and", |imm| X86Instruction::AndImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("or", |imm| X86Instruction::OrImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("xor", |imm| X86Instruction::XorImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("cmp", |imm| X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm,
            }),
        ];

        for (name, form) in immediate_forms {
            assert!(
                can_assemble(form(i64::from(i32::MIN))),
                "{name} should accept i32::MIN"
            );
            assert!(
                can_assemble(form(i64::from(i32::MAX))),
                "{name} should accept i32::MAX"
            );
            assert!(
                !can_assemble(form(i64::from(i32::MIN) - 1)),
                "{name} should reject values below signed imm32"
            );
            assert!(
                !can_assemble(form(i64::from(i32::MAX) + 1)),
                "{name} should reject values above signed imm32"
            );
        }

        assert!(can_assemble(X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: i64::MAX,
        }));
    }

    #[test]
    fn x86_32_can_assemble_rejects_extended_registers_and_out_of_range_immediates() {
        fn can_assemble(instruction: X86Instruction) -> bool {
            <X86_32 as crate::isa::traits::Assembler<X86Instruction>>::can_assemble(
                &X86_32,
                &instruction,
            )
        }

        let immediate_forms: [RegImmForm; 7] = [
            ("mov", |rd, imm| X86Instruction::MovImm { rd, imm }),
            ("add", |rd, imm| X86Instruction::AddImm { rd, imm }),
            ("sub", |rd, imm| X86Instruction::SubImm { rd, imm }),
            ("and", |rd, imm| X86Instruction::AndImm { rd, imm }),
            ("or", |rd, imm| X86Instruction::OrImm { rd, imm }),
            ("xor", |rd, imm| X86Instruction::XorImm { rd, imm }),
            ("cmp", |rn, imm| X86Instruction::CmpImm { rn, imm }),
        ];

        for (name, form) in immediate_forms {
            assert!(
                can_assemble(form(X86Register::RAX, i64::from(i32::MIN))),
                "{name} should accept low registers with i32::MIN"
            );
            assert!(
                can_assemble(form(X86Register::RAX, i64::from(i32::MAX))),
                "{name} should accept low registers with i32::MAX"
            );
            assert!(
                can_assemble(form(X86Register::RAX, i64::from(u32::MAX))),
                "{name} should accept low registers with u32::MAX bit pattern"
            );
            assert!(
                can_assemble(form(X86Register::RDX, 0)),
                "{name} should accept another low register"
            );
            assert!(
                !can_assemble(form(X86Register::RAX, i64::from(i32::MIN) - 1)),
                "{name} should reject non-canonical values below signed imm32"
            );
            assert!(
                !can_assemble(form(X86Register::RAX, i64::from(u32::MAX) + 1)),
                "{name} should reject values above canonical u32 bit pattern range"
            );
            assert!(
                !can_assemble(form(X86Register::R8, 0)),
                "{name} should reject extended registers"
            );
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
    fn x86_generator_mutate_filters_self_cmov_candidates() {
        use crate::isa::traits::InstructionGenerator;
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(453);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1];
        let mut saw_cmov = false;

        for start in [
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            },
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RAX,
                cond: X86Condition::E,
            },
        ] {
            for _ in 0..2000 {
                let mutated = X86InstructionGenerator.mutate(&mut rng, &start, &regs, &imms);
                if let X86Instruction::Cmov { rd, rs, .. } = mutated {
                    saw_cmov = true;
                    assert_ne!(rd, rs, "generator mutate emitted self-CMOV {mutated:?}");
                }
            }
        }

        assert!(saw_cmov, "generator mutate never returned CMOVcc");
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
            X86Instruction::TestReg { rn: rd, rs },
            X86Instruction::TestImm { rn: rd, imm: 0 },
            X86Instruction::Neg { rd },
            X86Instruction::Not { rd },
            X86Instruction::Cmov {
                rd,
                rs,
                cond: X86Condition::E,
            },
        ];

        // Rewritable non-terminator variants: 16 data forms + NEG + NOT + CMOVcc.
        assert_eq!(variants.len(), 19);
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

        // EFLAGS side-effects: MOV, NOT, and CMOV do not mutate EFLAGS.
        for v in variants.iter() {
            let leaves_flags = matches!(
                v,
                X86Instruction::MovReg { .. }
                    | X86Instruction::MovImm { .. }
                    | X86Instruction::Not { .. }
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
            (X86Instruction::TestReg { rn: rd, rs }, "test rax, rbx"),
            (X86Instruction::TestImm { rn: rd, imm: 5 }, "test rax, 5"),
            (X86Instruction::Neg { rd }, "neg rax"),
            (X86Instruction::Not { rd }, "not rax"),
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
            (X86Instruction::TestReg { rn: rd, rs }, "test"),
            (X86Instruction::TestImm { rn: rd, imm: 0 }, "test"),
            (X86Instruction::Neg { rd }, "neg"),
            (X86Instruction::Not { rd }, "not"),
        ];
        for (instr, expected) in cases {
            assert_eq!(instr.mnemonic(), *expected);
        }
    }

    #[test]
    fn x86_condition_mnemonics_include_suffixes() {
        use crate::isa::traits::InstructionType;
        let cmove = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        };
        let cmovne = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::NE,
        };
        let je = X86Instruction::Jcc {
            cond: X86Condition::E,
        };
        let jne = X86Instruction::Jcc {
            cond: X86Condition::NE,
        };

        let cases = [
            (cmove, "cmove", "cmove rax, rbx"),
            (cmovne, "cmovne", "cmovne rax, rbx"),
            (je, "je", "je <target>"),
            (jne, "jne", "jne <target>"),
        ];

        for (instr, mnemonic, display) in cases {
            assert_eq!(instr.mnemonic(), mnemonic);
            assert_eq!(
                <X86Instruction as InstructionType>::mnemonic(&instr),
                mnemonic
            );
            assert_eq!(instr.to_string(), display);
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
        // TEST mirrors CMP: reads both registers (or just rn), writes none.
        assert_eq!(
            X86Instruction::TestReg { rn: rd, rs }.source_registers(),
            vec![rd, rs]
        );
        assert_eq!(
            X86Instruction::TestImm { rn: rd, imm: 0 }.source_registers(),
            vec![rd]
        );
        // NEG / NOT are single-operand: each reads its own destination.
        assert_eq!(X86Instruction::Neg { rd }.source_registers(), vec![rd]);
        assert_eq!(X86Instruction::Not { rd }.source_registers(), vec![rd]);
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
            // CMP and TEST variants never write a register.
            (X86Instruction::CmpReg { rn: rd, rs }, None),
            (X86Instruction::CmpImm { rn: rd, imm: 0 }, None),
            (X86Instruction::TestReg { rn: rd, rs }, None),
            (X86Instruction::TestImm { rn: rd, imm: 0 }, None),
            // NEG and NOT write rd.
            (X86Instruction::Neg { rd }, Some(rd)),
            (X86Instruction::Not { rd }, Some(rd)),
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

    #[test]
    fn x86_cost_model_preserves_width_sensitive_code_size() {
        use crate::isa::traits::CostModel;
        use crate::semantics::cost::CostMetric;

        let cmov = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        };
        assert_eq!(
            <X86_64 as CostModel<X86Instruction>>::instruction_cost(
                &X86_64,
                &cmov,
                &CostMetric::CodeSize,
            ),
            4
        );
        assert_eq!(
            <X86_32 as CostModel<X86Instruction>>::instruction_cost(
                &X86_32,
                &cmov,
                &CostMetric::CodeSize,
            ),
            3
        );

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
        assert_eq!(
            <X86_64 as CostModel<X86Instruction>>::sequence_cost(
                &X86_64,
                &seq,
                &CostMetric::CodeSize,
            ),
            6
        );
        assert_eq!(
            <X86_32 as CostModel<X86Instruction>>::sequence_cost(
                &X86_32,
                &seq,
                &CostMetric::CodeSize,
            ),
            4
        );
    }

    // ---- X86Mutator (issue #73 Phase B) ----

    struct BudgetedRng {
        words: Vec<u32>,
        next_word: usize,
    }

    impl BudgetedRng {
        fn new(words: Vec<u32>) -> Self {
            Self {
                words,
                next_word: 0,
            }
        }

        fn draw_word(&mut self) -> u32 {
            let word = self
                .words
                .get(self.next_word)
                .copied()
                .expect("random generator exceeded its draw budget");
            self.next_word += 1;
            word
        }
    }

    impl rand::TryRng for BudgetedRng {
        type Error = std::convert::Infallible;

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

    fn word_for_range(range: u32, value: u32) -> u32 {
        assert!(range > 0);
        assert!(value < range);
        let numerator = (u128::from(value)) << 32;
        let word = numerator.div_ceil(u128::from(range)) as u32;
        debug_assert_eq!(((u64::from(word) * u64::from(range)) >> 32) as u32, value);
        word
    }

    #[test]
    fn x86_mutator_swap_uses_two_draws_with_modular_second_index() {
        let mutator = X86Mutator::default();
        let mut sequence = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddReg {
                rd: X86Register::RBX,
                rs: X86Register::RCX,
            },
            X86Instruction::SubImm {
                rd: X86Register::RDX,
                imm: 1,
            },
        ];
        let mut rng = BudgetedRng::new(vec![word_for_range(3, 1), word_for_range(2, 1)]);

        mutator.mutate_swap(&mut rng, &mut sequence);

        assert_eq!(
            sequence,
            vec![
                X86Instruction::AddReg {
                    rd: X86Register::RBX,
                    rs: X86Register::RCX,
                },
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 0,
                },
                X86Instruction::SubImm {
                    rd: X86Register::RDX,
                    imm: 1,
                },
            ]
        );
    }

    #[test]
    fn x86_mutator_eventually_changes_the_sequence() {
        use super::{default_x86_immediates, default_x86_registers};
        use crate::isa::traits::ISAMutator;
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
    fn x86_mutator_opcode_mutates_cmp_reg_to_cmp_imm() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RBX],
            vec![7],
            MutationWeights {
                operand: 0.0,
                opcode: 1.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);

        let mutated = mutator.mutate(&mut rng, &target);

        assert_eq!(
            mutated,
            vec![X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 7,
            }]
        );
    }

    #[test]
    fn x86_mutator_opcode_mutates_cmp_imm_to_cmp_reg() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RBX],
            // Unused by CmpImm → CmpReg (which calls pick_register, not
            // an immediate picker); a value absent from the target makes that clear.
            vec![0],
            MutationWeights {
                operand: 0.0,
                opcode: 1.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        // rn is a non-RAX register so the "rn is preserved" assertion can't be
        // satisfied coincidentally by the pick_register RAX fallback default.
        let target = vec![X86Instruction::CmpImm {
            rn: X86Register::RCX,
            imm: 5,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);

        let mutated = mutator.mutate(&mut rng, &target);

        assert_eq!(
            mutated,
            vec![X86Instruction::CmpReg {
                rn: X86Register::RCX,
                rs: X86Register::RBX,
            }]
        );
    }

    #[test]
    fn x86_mutator_empty_register_pool_does_not_invent_writable_registers() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            Vec::new(),
            vec![0],
            MutationWeights {
                operand: 0.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 1.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::CmpImm {
            rn: X86Register::R10,
            imm: 1,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);

        assert_eq!(mutator.mutate(&mut rng, &target), target);
    }

    #[test]
    fn x86_mutator_cmov_operand_mutates_condition_with_empty_register_pool() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            Vec::new(),
            vec![0],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut changed = None;

        for _ in 0..200 {
            let mutated = mutator.mutate(&mut rng, &target);
            match mutated.as_slice() {
                [X86Instruction::Cmov { rd, rs, cond }]
                    if *rd == X86Register::RAX && *rs == X86Register::RBX =>
                {
                    if *cond != X86Condition::E {
                        changed = Some(*cond);
                        break;
                    }
                }
                other => panic!("unexpected CMOV mutation with empty register pool: {other:?}"),
            }
        }

        assert!(
            changed.is_some(),
            "CMOV condition did not change after repeated operand mutations"
        );
    }

    #[test]
    fn x86_mutator_cmov_operand_reaches_all_conditions() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::collections::HashSet;

        let pool = vec![X86Register::RAX, X86Register::RBX, X86Register::RCX];
        let mutator = X86Mutator::new(
            pool.clone(),
            vec![0],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let mut seq = vec![X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let mut observed = HashSet::from([X86Condition::E]);

        for _ in 0..2_000 {
            seq = mutator.mutate(&mut rng, &seq);
            match seq.as_slice() {
                [X86Instruction::Cmov { rd, rs, cond }] => {
                    assert!(pool.contains(rd), "CMOV rd left mutator pool: {rd:?}");
                    assert!(pool.contains(rs), "CMOV rs left mutator pool: {rs:?}");
                    observed.insert(*cond);
                }
                other => panic!("CMOV operand mutation changed instruction shape: {other:?}"),
            }
            if observed.len() == X86Condition::ALL.len() {
                break;
            }
        }

        assert_eq!(
            observed.len(),
            X86Condition::ALL.len(),
            "CMOV operand mutation reached only {observed:?}"
        );
    }

    #[test]
    fn x86_mutator_random_instruction_uses_zero_for_empty_immediate_pool() {
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX, X86Register::RBX],
            Vec::new(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(252);
        let mut saw_immediate_form = false;

        for _ in 0..2000 {
            match mutator
                .random_instruction(&mut rng)
                .expect("non-empty register pool should generate an instruction")
            {
                X86Instruction::MovImm { imm, .. }
                | X86Instruction::AddImm { imm, .. }
                | X86Instruction::SubImm { imm, .. }
                | X86Instruction::AndImm { imm, .. }
                | X86Instruction::OrImm { imm, .. }
                | X86Instruction::XorImm { imm, .. }
                | X86Instruction::CmpImm { imm, .. }
                | X86Instruction::TestImm { imm, .. }
                // Shifts and rotates carry the same shared `imm` draw (0 for an
                // empty pool).
                | X86Instruction::Shl { imm, .. }
                | X86Instruction::Shr { imm, .. }
                | X86Instruction::Sar { imm, .. }
                | X86Instruction::Rol { imm, .. }
                | X86Instruction::Ror { imm, .. }
                // The 3-operand IMUL draws its immediate from the same shared
                // slot, so the empty pool yields 0 here too.
                | X86Instruction::ImulRegImm { imm, .. }
                // LEA's displacement comes from the same shared slot (0 here).
                | X86Instruction::Lea { disp: imm, .. } => {
                    saw_immediate_form = true;
                    assert_eq!(imm, 0);
                }
                X86Instruction::MovReg { .. }
                | X86Instruction::AddReg { .. }
                | X86Instruction::SubReg { .. }
                | X86Instruction::AndReg { .. }
                | X86Instruction::OrReg { .. }
                | X86Instruction::XorReg { .. }
                | X86Instruction::CmpReg { .. }
                | X86Instruction::TestReg { .. }
                | X86Instruction::Neg { .. }
                | X86Instruction::Not { .. }
                | X86Instruction::Inc { .. }
                | X86Instruction::Dec { .. }
                | X86Instruction::ImulReg { .. }
                | X86Instruction::Cmov { .. }
                | X86Instruction::Jcc { .. } => {}
            }
        }

        assert!(
            saw_immediate_form,
            "mutator did not exercise the empty-immediate fallback"
        );
    }

    #[test]
    fn x86_mutator_random_instruction_matches_shared_generator_stream() {
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let regs = [X86Register::RAX, X86Register::RBX, X86Register::RCX];
        let imms = [0i64, 1, -1];
        let mutator = X86Mutator::new(
            regs.to_vec(),
            imms.to_vec(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );

        for seed in 0..32u64 {
            let mut mutator_rng = ChaCha8Rng::seed_from_u64(seed);
            let mut helper_rng = ChaCha8Rng::seed_from_u64(seed);

            for _ in 0..32 {
                assert_eq!(
                    mutator.random_instruction(&mut mutator_rng),
                    Some(generate_random_rewritable_x86_instruction(
                        &mut helper_rng,
                        &regs,
                        &imms,
                    )),
                    "seed {seed} diverged from shared generator"
                );
            }
        }
    }

    #[test]
    fn opcode_dispatch_is_consistent() {
        // Pin the full opcode → instruction-family mapping that the shared
        // `build_x86_instruction_by_opcode` constructor produces. Both
        // `X86Mutator::random_instruction` and
        // `generate_random_rewritable_x86_instruction` delegate here, so this
        // guards the consolidated table against future drift (issue #348).
        let rd = X86Register::RAX;
        let rs = X86Register::RBX;
        let imm = 7i64;
        let cond = X86Condition::E;

        let expected: [(u8, X86Instruction); X86_REWRITABLE_OPCODE_COUNT as usize] = [
            (0, X86Instruction::MovReg { rd, rs }),
            (1, X86Instruction::MovImm { rd, imm }),
            (2, X86Instruction::AddReg { rd, rs }),
            (3, X86Instruction::AddImm { rd, imm }),
            (4, X86Instruction::SubReg { rd, rs }),
            (5, X86Instruction::SubImm { rd, imm }),
            (6, X86Instruction::AndReg { rd, rs }),
            (7, X86Instruction::AndImm { rd, imm }),
            (8, X86Instruction::OrReg { rd, rs }),
            (9, X86Instruction::OrImm { rd, imm }),
            (10, X86Instruction::XorReg { rd, rs }),
            (11, X86Instruction::XorImm { rd, imm }),
            (12, X86Instruction::CmpReg { rn: rd, rs }),
            (13, X86Instruction::CmpImm { rn: rd, imm }),
            (14, X86Instruction::TestReg { rn: rd, rs }),
            (15, X86Instruction::TestImm { rn: rd, imm }),
            (16, X86Instruction::Neg { rd }),
            (17, X86Instruction::Not { rd }),
            (18, X86Instruction::Inc { rd }),
            (19, X86Instruction::Dec { rd }),
            (20, X86Instruction::Shl { rd, imm }),
            (21, X86Instruction::Shr { rd, imm }),
            (22, X86Instruction::Sar { rd, imm }),
            (23, X86Instruction::Rol { rd, imm }),
            (24, X86Instruction::Ror { rd, imm }),
            (25, X86Instruction::ImulReg { rd, rs }),
            (26, X86Instruction::ImulRegImm { rd, rs, imm }),
            (
                27,
                X86Instruction::Lea {
                    rd,
                    base: rs,
                    disp: imm,
                },
            ),
            // Cmov stays last at COUNT - 1 == 28.
            (28, X86Instruction::Cmov { rd, rs, cond }),
        ];

        for (opcode, want) in expected {
            assert_eq!(
                build_x86_instruction_by_opcode(opcode, rd, rs, imm, cond),
                want,
                "opcode {opcode} built the wrong instruction"
            );
        }

        // Sanity-check the mnemonic family for each opcode too, so a future
        // variant swap that preserves struct shape still trips the guard.
        let mnemonics: [(u8, &str); X86_REWRITABLE_OPCODE_COUNT as usize] = [
            (0, "mov"),
            (1, "mov"),
            (2, "add"),
            (3, "add"),
            (4, "sub"),
            (5, "sub"),
            (6, "and"),
            (7, "and"),
            (8, "or"),
            (9, "or"),
            (10, "xor"),
            (11, "xor"),
            (12, "cmp"),
            (13, "cmp"),
            (14, "test"),
            (15, "test"),
            (16, "neg"),
            (17, "not"),
            (18, "inc"),
            (19, "dec"),
            (20, "shl"),
            (21, "shr"),
            (22, "sar"),
            (23, "rol"),
            (24, "ror"),
            (25, "imul"),
            (26, "imul"),
            (27, "lea"),
            (28, "cmove"),
        ];
        for (opcode, mnem) in mnemonics {
            assert_eq!(
                build_x86_instruction_by_opcode(opcode, rd, rs, imm, cond).mnemonic(),
                mnem,
                "opcode {opcode} mnemonic drifted"
            );
        }
    }

    #[test]
    fn x86_mutator_preserves_sequence_length() {
        use super::{default_x86_immediates, default_x86_registers};
        use crate::isa::traits::ISAMutator;
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
    fn x86_mutator_instruction_replacement_filters_self_cmov_candidates() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX, X86Register::RBX],
            vec![0i64, 1],
            MutationWeights {
                operand: 0.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 1.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(453);
        let mut saw_cmov = false;

        for _ in 0..2000 {
            let mutated = mutator.mutate(&mut rng, &target);
            if let X86Instruction::Cmov { rd, rs, .. } = mutated[0] {
                saw_cmov = true;
                assert_ne!(rd, rs, "replacement mutator emitted self-CMOV {mutated:?}");
            }
        }

        assert!(saw_cmov, "replacement mutator never emitted CMOVcc");
    }

    #[test]
    fn x86_mutator_operand_keeps_cmov_registers_distinct() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX, X86Register::RBX],
            vec![0i64, 1],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(453);

        for _ in 0..2000 {
            let mutated = mutator.mutate(&mut rng, &target);
            let X86Instruction::Cmov { rd, rs, .. } = mutated[0] else {
                panic!("operand mutator changed CMOV opcode: {mutated:?}");
            };
            assert_ne!(rd, rs, "operand mutator emitted self-CMOV {mutated:?}");
        }
    }

    #[test]
    fn x86_stochastic_cmov_filters_handle_degenerate_register_pools() {
        use crate::isa::traits::{ISAMutator, InstructionGenerator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        for regs in [
            vec![X86Register::RAX],
            vec![X86Register::RAX, X86Register::RAX],
        ] {
            let imms = [0i64, 1];
            let mut generator_rng = ChaCha8Rng::seed_from_u64(453);
            for _ in 0..500 {
                let instr =
                    X86InstructionGenerator.generate_random(&mut generator_rng, &regs, &imms);
                assert!(
                    !matches!(instr, X86Instruction::Cmov { .. }),
                    "random generator emitted CMOV from degenerate pool {regs:?}: {instr:?}"
                );
            }

            let replacement_mutator = X86Mutator::new(
                regs.clone(),
                imms.to_vec(),
                MutationWeights {
                    operand: 0.0,
                    opcode: 0.0,
                    swap: 0.0,
                    instruction: 1.0,
                },
                crate::assembler::x86::X86Mode::Mode64,
            );
            let target = vec![X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            }];
            let mut replacement_rng = ChaCha8Rng::seed_from_u64(453);
            for _ in 0..500 {
                let mutated = replacement_mutator.mutate(&mut replacement_rng, &target);
                assert!(
                    !matches!(mutated[0], X86Instruction::Cmov { .. }),
                    "replacement mutator emitted CMOV from degenerate pool {regs:?}: {mutated:?}"
                );
            }

            let operand_mutator = X86Mutator::new(
                regs,
                imms.to_vec(),
                MutationWeights {
                    operand: 1.0,
                    opcode: 0.0,
                    swap: 0.0,
                    instruction: 0.0,
                },
                crate::assembler::x86::X86Mode::Mode64,
            );
            let cmov_target = vec![X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            }];
            let mut operand_rng = ChaCha8Rng::seed_from_u64(453);
            for _ in 0..100 {
                let mutated = operand_mutator.mutate(&mut operand_rng, &cmov_target);
                let X86Instruction::Cmov { rd, rs, .. } = mutated[0] else {
                    panic!("operand mutator changed CMOV opcode: {mutated:?}");
                };
                assert_ne!(
                    rd, rs,
                    "operand mutator collapsed CMOV with degenerate pool: {mutated:?}"
                );
            }
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
    fn x86_mutator_mode32_filters_immediate_pool_to_encodable_bitpatterns() {
        use crate::isa::traits::{Assembler, ISAMutator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::collections::BTreeSet;

        let mutator = X86Mutator::new(
            Vec::new(),
            vec![
                i64::from(i32::MIN) - 1,
                i64::from(i32::MIN),
                i64::from(i32::MAX),
                i64::from(u32::MAX),
                i64::from(u32::MAX) + 1,
                i64::MAX,
            ],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode32,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(500);
        let mut seq = vec![X86Instruction::AddImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mut seen = BTreeSet::new();

        for _ in 0..1000 {
            seq = mutator.mutate(&mut rng, &seq);
            let [X86Instruction::AddImm { rd, imm }] = seq.as_slice() else {
                panic!("operand-only mutation changed instruction shape: {seq:?}");
            };
            let instr = X86Instruction::AddImm { rd: *rd, imm: *imm };
            assert!(
                <X86_32 as Assembler<X86Instruction>>::can_assemble(&X86_32, &instr),
                "Mode32 mutator emitted unencodable immediate {imm}"
            );
            seen.insert(*imm);
        }

        assert!(seen.contains(&i64::from(i32::MIN)));
        assert!(seen.contains(&i64::from(i32::MAX)));
        assert!(seen.contains(&i64::from(u32::MAX)));
    }

    #[test]
    fn x86_mutator_mode64_splits_movabs_from_non_mov_immediate_pool() {
        use crate::isa::traits::{Assembler, ISAMutator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::collections::BTreeSet;

        let mutator = X86Mutator::new(
            Vec::new(),
            vec![
                i64::MAX,
                i64::from(i32::MIN),
                i64::from(i32::MAX),
                i64::from(i32::MAX) + 1,
            ],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );

        let mut mov_rng = ChaCha8Rng::seed_from_u64(501);
        let mut mov_seq = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mut saw_movabs = false;
        for _ in 0..1000 {
            mov_seq = mutator.mutate(&mut mov_rng, &mov_seq);
            let [X86Instruction::MovImm { imm, .. }] = mov_seq.as_slice() else {
                panic!("operand-only mutation changed MOV shape: {mov_seq:?}");
            };
            saw_movabs |= *imm == i64::MAX;
        }
        assert!(saw_movabs, "Mode64 MOV immediate pool lost MOVABS values");

        let non_mov_forms: [ImmForm; 6] = [
            ("add", |imm| X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("sub", |imm| X86Instruction::SubImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("and", |imm| X86Instruction::AndImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("or", |imm| X86Instruction::OrImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("xor", |imm| X86Instruction::XorImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("cmp", |imm| X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm,
            }),
        ];

        for (name, form) in non_mov_forms {
            let mut rng = ChaCha8Rng::seed_from_u64(502);
            let mut seq = vec![form(0)];
            let mut seen = BTreeSet::new();
            for _ in 0..1000 {
                seq = mutator.mutate(&mut rng, &seq);
                let [instr] = seq.as_slice() else {
                    panic!("operand-only mutation changed {name} sequence length: {seq:?}");
                };
                assert!(
                    <X86_64 as Assembler<X86Instruction>>::can_assemble(&X86_64, instr),
                    "Mode64 mutator emitted unencodable {name} immediate: {instr:?}"
                );
                let imm = match instr {
                    X86Instruction::AddImm { imm, .. }
                    | X86Instruction::SubImm { imm, .. }
                    | X86Instruction::AndImm { imm, .. }
                    | X86Instruction::OrImm { imm, .. }
                    | X86Instruction::XorImm { imm, .. }
                    | X86Instruction::CmpImm { imm, .. } => *imm,
                    other => panic!("operand-only mutation changed {name} shape: {other:?}"),
                };
                seen.insert(imm);
            }
            assert!(seen.contains(&i64::from(i32::MIN)), "{name} lost i32::MIN");
            assert!(seen.contains(&i64::from(i32::MAX)), "{name} lost i32::MAX");
        }
    }

    #[test]
    fn x86_mutator_mode64_operand_and_instruction_mutations_keep_non_mov_immediates_encodable() {
        use crate::isa::traits::{Assembler, ISAMutator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX, X86Register::RBX],
            vec![i64::MAX, 17, i64::from(i32::MAX) + 1],
            MutationWeights {
                operand: 0.5,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.5,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(503);
        let mut seq = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 0,
            },
        ];
        let mut saw_movabs = false;
        let mut saw_non_mov_immediate = false;

        for _ in 0..5000 {
            seq = mutator.mutate(&mut rng, &seq);
            for instr in &seq {
                match instr {
                    X86Instruction::MovImm { imm, .. } => {
                        saw_movabs |= *imm == i64::MAX;
                    }
                    X86Instruction::AddImm { .. }
                    | X86Instruction::SubImm { .. }
                    | X86Instruction::AndImm { .. }
                    | X86Instruction::OrImm { .. }
                    | X86Instruction::XorImm { .. }
                    | X86Instruction::CmpImm { .. }
                    | X86Instruction::TestImm { .. }
                    // Shifts and rotates carry an imm8 count; the same
                    // encodability invariant applies — `can_assemble` must
                    // accept them.
                    | X86Instruction::Shl { .. }
                    | X86Instruction::Shr { .. }
                    | X86Instruction::Sar { .. }
                    | X86Instruction::Rol { .. }
                    | X86Instruction::Ror { .. }
                    // The 3-operand IMUL immediate is imm32; same encodability
                    // invariant. LEA's displacement is also a disp32 with the
                    // same encodability requirement.
                    | X86Instruction::ImulRegImm { .. }
                    | X86Instruction::Lea { .. } => {
                        saw_non_mov_immediate = true;
                        assert!(
                            <X86_64 as Assembler<X86Instruction>>::can_assemble(&X86_64, instr),
                            "Mode64 mutation emitted unencodable non-MOV immediate: {instr:?}"
                        );
                    }
                    X86Instruction::MovReg { .. }
                    | X86Instruction::AddReg { .. }
                    | X86Instruction::SubReg { .. }
                    | X86Instruction::AndReg { .. }
                    | X86Instruction::OrReg { .. }
                    | X86Instruction::XorReg { .. }
                    | X86Instruction::CmpReg { .. }
                    | X86Instruction::TestReg { .. }
                    | X86Instruction::Neg { .. }
                    | X86Instruction::Not { .. }
                    | X86Instruction::Inc { .. }
                    | X86Instruction::Dec { .. }
                    | X86Instruction::ImulReg { .. }
                    | X86Instruction::Cmov { .. }
                    | X86Instruction::Jcc { .. } => {}
                }
            }
        }

        assert!(saw_movabs, "Mode64 MOV mutation never drew i64::MAX");
        assert!(
            saw_non_mov_immediate,
            "test never observed a non-MOV immediate mutation"
        );
    }

    #[test]
    fn x86_mutator_mode64_opcode_mutation_replaces_movabs_immediate_for_non_mov_forms() {
        use crate::isa::traits::{Assembler, ISAMutator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX],
            vec![7],
            MutationWeights {
                operand: 0.0,
                opcode: 1.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: i64::MAX,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(504);
        let mut saw_non_mov_bridge = false;

        for _ in 0..100 {
            let mutated = mutator.mutate(&mut rng, &target);
            let [instr] = mutated.as_slice() else {
                panic!("opcode-only mutation changed sequence length: {mutated:?}");
            };
            match instr {
                X86Instruction::MovImm { imm, .. } => {
                    assert_eq!(*imm, i64::MAX, "MOVABS immediate should stay valid for MOV");
                }
                X86Instruction::AddImm { .. }
                | X86Instruction::SubImm { .. }
                | X86Instruction::AndImm { .. }
                | X86Instruction::OrImm { .. }
                | X86Instruction::XorImm { .. } => {
                    saw_non_mov_bridge = true;
                    assert!(
                        <X86_64 as Assembler<X86Instruction>>::can_assemble(&X86_64, instr),
                        "opcode mutation carried a MOVABS immediate into {instr:?}"
                    );
                }
                other => panic!("unexpected opcode mutation from MOV immediate: {other:?}"),
            }
        }

        assert!(
            saw_non_mov_bridge,
            "test never observed MOV immediate bridge to a non-MOV form"
        );
    }

    #[test]
    fn x86_mutator_destructive_form_invariant() {
        // For every destructive variant (non-MOV, non-CMP that writes
        // rd), `rd` must appear in `source_registers()` per
        // src/isa/x86.rs:228-245. The mutator must preserve that.
        use super::{default_x86_immediates, default_x86_registers};
        use crate::isa::traits::ISAMutator;
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
    fn jcc_display_emits_target_placeholder() {
        // The branch target is opaque to the IR, so Display renders a fixed
        // `<target>` placeholder rather than a concrete address/offset.
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::E,
        };
        let rendered = jcc.to_string();
        assert_eq!(rendered, "je <target>");
        assert!(rendered.ends_with("<target>"));
    }

    #[test]
    fn jcc_display_output_does_not_parse_back() {
        // The `<target>` placeholder is intentionally non-parseable: a Jcc
        // terminator must never round-trip from its Display text back into
        // rewritable IR (the search holds terminators fixed). Splitting the
        // Display output and feeding it to the parser must NOT yield a Jcc.
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::E,
        };
        let rendered = jcc.to_string();
        let (mnemonic, operand) = rendered
            .split_once(' ')
            .expect("Jcc Display has a mnemonic and an operand placeholder");
        assert_eq!(mnemonic, "je");
        assert_eq!(operand, "<target>");
        let parsed = crate::parser::x86::x86_ir_from_mnemonic(mnemonic, operand);
        assert!(
            !matches!(parsed, Ok(Some(_))),
            "Jcc Display placeholder must not parse back into an instruction, got {parsed:?}"
        );
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
