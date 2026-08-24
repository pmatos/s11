//! x86 ISA backend (x86-64 primary, x86-32 secondary).
//!
//! Mirrors the dual-variant pattern of `src/isa/riscv.rs`: a single
//! `X86Register` view type plus shared `X86Operand` / `X86Instruction` enums
//! serve the `X86_64` and `X86_32` ISA marker structs.
//!
//! The shared instruction set includes data movement (including narrow-source
//! MOVZX/MOVSX), integer arithmetic and logical operations, shifts/rotates,
//! comparisons, conditional moves (CMOVcc), conditional byte-set (SETcc), and
//! fixed Jcc terminators.

// x86 register names are conventionally uppercase (RAX, RBX, ...) in every
// Intel/AMD manual, Capstone disassembly output, GAS/Intel syntax, and gdb
// `info registers`. Lowercasing to `Rax`/`Rbx` per Rust's default
// upper_case_acronyms lint would make the IR diverge from every external
// reference. Keep the uppercase names and silence the lint module-wide.
#![allow(clippy::upper_case_acronyms)]

mod encoding;
mod stochastic;
pub(crate) use encoding::{x86_extension_source_ok, x86_register_ok, x86_register_pair_ok};
pub use stochastic::{
    X86InstructionGenerator, X86Mutator, default_x86_immediates, default_x86_registers,
};

use crate::isa::traits::{ISA, InstructionType, OperandType, RegisterType};
use std::fmt;

/// x86 condition codes consumed by SETcc / CMOVcc / Jcc.
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

    pub const fn set_mnemonic(self) -> &'static str {
        match self {
            X86Condition::E => "sete",
            X86Condition::NE => "setne",
            X86Condition::B => "setb",
            X86Condition::AE => "setae",
            X86Condition::BE => "setbe",
            X86Condition::A => "seta",
            X86Condition::L => "setl",
            X86Condition::GE => "setge",
            X86Condition::LE => "setle",
            X86Condition::G => "setg",
            X86Condition::S => "sets",
            X86Condition::NS => "setns",
            X86Condition::O => "seto",
            X86Condition::NO => "setno",
            X86Condition::P => "setp",
            X86Condition::NP => "setnp",
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

    /// Render this canonical GPR using its low sub-register spelling.
    ///
    /// The core x86 IR normally renders canonical full-width names. Width-
    /// changing moves are the exception: their source spelling is semantic, so
    /// `movzx rax, bl` must retain `bl` rather than render `rbx`.
    pub fn mnemonic_for_width(&self, width: u32) -> Option<&'static str> {
        let index = usize::from(self.index()?);
        match width {
            8 => Some(
                [
                    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b",
                    "r11b", "r12b", "r13b", "r14b", "r15b",
                ][index],
            ),
            16 => Some(
                [
                    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w",
                    "r12w", "r13w", "r14w", "r15w",
                ][index],
            ),
            32 => Some(
                [
                    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d",
                    "r11d", "r12d", "r13d", "r14d", "r15d",
                ][index],
            ),
            64 => Some(self.mnemonic()),
            _ => None,
        }
    }

    pub fn from_index(i: u8) -> Option<Self> {
        (i < 16).then_some(Self::new(i, X86RegisterView::Native))
    }

    pub const fn view(self) -> X86RegisterView {
        self.view
    }

    pub const fn canonical(self) -> Self {
        Self::new(self.index, X86RegisterView::Native)
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

    /// True when this individual GPR view has an encoding in `mode`.
    ///
    /// In 32-bit mode, indices 0..=7 are available, but low-byte views are
    /// limited to the legacy AL/CL/DL/BL encodings at indices 0..=3. In 64-bit
    /// mode, all sixteen GPRs and the REX-only low-byte views SPL/BPL/SIL/DIL
    /// are available. Whole-instruction constraints, such as pairing a legacy
    /// high-byte register with a REX-requiring operand, remain the encoding
    /// prefilter's responsibility.
    pub fn is_available_in(self, mode: crate::assembler::x86::X86Mode) -> bool {
        let mode_width = match mode {
            crate::assembler::x86::X86Mode::Mode64 => 64,
            crate::assembler::x86::X86Mode::Mode32 => 32,
        };
        encoding::x86_register_ok(self, mode_width)
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
    /// `mov rd, rs` — register copy; no EFLAGS effect. Word and byte
    /// destinations implicitly read `rd` because their writes preserve the
    /// surrounding bits of its canonical register.
    MovReg { rd: X86Register, rs: X86Register },
    /// `mov rd, imm` — load immediate; no EFLAGS effect. Word and byte
    /// destinations implicitly read `rd` to preserve surrounding bits.
    MovImm { rd: X86Register, imm: i64 },
    /// `movzx rd, rs_sub` — zero-extend the low `src_width` bits of `rs`
    /// into the mode-width destination. The supported source widths are 8 and
    /// 16 bits. No EFLAGS effect.
    Movzx {
        rd: X86Register,
        rs: X86Register,
        src_width: u32,
    },
    /// `movsx rd, rs_sub` — sign-extend the low `src_width` bits of `rs`
    /// into the mode-width destination. The supported source widths are 8 and
    /// 16 bits. No EFLAGS effect.
    Movsx {
        rd: X86Register,
        rs: X86Register,
        src_width: u32,
    },
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
    /// purely WRITTEN at native/dword width, so `source_registers()` is just
    /// `[rs]` there. A word destination also reads `rd` to preserve its
    /// surrounding bits. Same flag model as `ImulReg`: CF/OF on signed
    /// overflow, SF/ZF/PF Intel-undefined and modelled deterministically.
    ImulRegImm {
        rd: X86Register,
        rs: X86Register,
        imm: i64,
    },
    /// `lea rd, [base + disp]` — load effective address in its minimal
    /// register-base + displacement form: `rd = base + disp` (wrapping at
    /// width). NON-destructive at native/dword width: `base` is read and `rd`
    /// is purely written. A word destination also reads `rd` to preserve its
    /// surrounding bits. Affects NO flags. The `index*scale` and RIP-relative
    /// addressing forms are deferred; the parser rejects them as unsupported
    /// shapes.
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
    /// `setCC rd` — full-width pseudo-instruction that materializes an EFLAGS
    /// condition as native-width 0 or 1.
    ///
    /// Architectural SETcc writes only the low byte, so binary input is rejected
    /// until sub-register widths are represented by the x86 IR (#75). Candidate
    /// assembly lowers this variant to byte SETcc followed by same-register
    /// MOVZX. It reads but does not modify EFLAGS.
    Setcc { rd: X86Register, cond: X86Condition },
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
            | X86Instruction::Movzx { rd, .. }
            | X86Instruction::Movsx { rd, .. }
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
            | X86Instruction::Cmov { rd, .. }
            | X86Instruction::Setcc { rd, .. } => Some(*rd),
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
            X86Instruction::Movzx { .. } => "movzx",
            X86Instruction::Movsx { .. } => "movsx",
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
            X86Instruction::Setcc { cond, .. } => cond.set_mnemonic(),
            X86Instruction::Jcc { cond } => cond.jcc_mnemonic(),
        }
    }

    /// Registers this instruction reads.
    ///
    /// **x86 destructive-form divergence**: for `AddReg/SubReg/AndReg/OrReg/XorReg`
    /// and their immediate forms, `rd` is BOTH source and destination, so it
    /// appears here. Nominally pure writes also include `rd` when a word or
    /// byte destination preserves surrounding bits of the canonical register.
    /// Native and dword destinations fully overwrite it. See the enum
    /// doc-comment.
    pub fn source_registers(&self) -> Vec<X86Register> {
        let pure_write_sources = |rd: X86Register, sources: Vec<X86Register>| -> Vec<X86Register> {
            if rd.fully_overwrites_architectural_register() {
                sources
            } else {
                std::iter::once(rd).chain(sources).collect()
            }
        };
        let operands = match self {
            X86Instruction::MovReg { rd, rs } => pure_write_sources(*rd, vec![*rs]),
            X86Instruction::MovImm { rd, .. } => pure_write_sources(*rd, vec![]),
            X86Instruction::Movzx { rs, .. } | X86Instruction::Movsx { rs, .. } => vec![*rs],
            X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            // IMUL rd, rs is destructive (`rd = rd * rs`), so rd is read too.
            | X86Instruction::ImulReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => vec![*rd, *rs],
            // At native/dword width these write rd purely from the explicit
            // sources. A word destination also reads rd to preserve the
            // surrounding canonical-register bits.
            X86Instruction::ImulRegImm { rd, rs, .. } => {
                pure_write_sources(*rd, vec![*rs])
            }
            X86Instruction::Lea { rd, base, .. } => pure_write_sources(*rd, vec![*base]),
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
            // SETcc reads only EFLAGS and fully overwrites rd in the interim IR.
            X86Instruction::Setcc { .. } => vec![],
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
            X86Instruction::Movzx { .. } => 28,
            X86Instruction::Movsx { .. } => 29,
            // The CMOV distinct-register draw at both generation sites is gated
            // on `opcode == X86_CMOV_OPCODE`, so CMOV need not be positioned
            // last; SETcc follows it as the final rewritable opcode.
            X86Instruction::Cmov { .. } => 30,
            X86Instruction::Setcc { .. } => 31,
            X86Instruction::Jcc { .. } => 32,
        }
    }

    fn mnemonic(&self) -> &'static str {
        X86Instruction::mnemonic(self)
    }

    fn has_side_effects(&self) -> bool {
        // MOV / NOT / LEA / SETcc / CMOV / Jcc do not write EFLAGS (the
        // conditional families read them, but reading is not a side effect on
        // observable state; NOT
        // is bitwise complement and leaves EFLAGS untouched, exactly like
        // MOV; LEA is pure address arithmetic that writes only its destination
        // register). Every other variant — including NEG — sets or clobbers
        // flag bits, which is observable state beyond the destination register.
        !matches!(
            self,
            X86Instruction::MovReg { .. }
                | X86Instruction::MovImm { .. }
                | X86Instruction::Movzx { .. }
                | X86Instruction::Movsx { .. }
                | X86Instruction::Not { .. }
                | X86Instruction::Lea { .. }
                | X86Instruction::Cmov { .. }
                | X86Instruction::Setcc { .. }
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
            X86Instruction::Movzx {
                rd,
                rs,
                src_width,
            }
            | X86Instruction::Movsx {
                rd,
                rs,
                src_width,
            } => {
                let source = rs.mnemonic_for_width(*src_width).ok_or(fmt::Error)?;
                write!(f, "{} {}, {}", mn, rd, source)
            }
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
            X86Instruction::Setcc { rd, .. } => write!(f, "{} {}", mn, rd),
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
/// `for X86_32`. MOV / MOVZX / MOVSX / NOT / LEA / SETcc / CMOV / Jcc do not
/// write EFLAGS — the conditional families (SETcc, CMOV, Jcc) read them via
/// `x86_reads_flags` but do not modify any flag bit; LEA is pure address
/// arithmetic. Every other variant in the current set writes EFLAGS.
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
            | X86Instruction::Movzx { .. }
            | X86Instruction::Movsx { .. }
            | X86Instruction::Not { .. }
            | X86Instruction::Lea { .. }
            | X86Instruction::Cmov { .. }
            | X86Instruction::Setcc { .. }
            | X86Instruction::Jcc { .. }
    )
}

/// SETcc, CMOV, and Jcc read EFLAGS; every other variant in the current set
/// is flag-agnostic on the read side. Public so search and equivalence callers
/// can route through one authoritative match arm.
pub fn x86_reads_flags(instr: &X86Instruction) -> bool {
    matches!(
        instr,
        X86Instruction::Cmov { .. } | X86Instruction::Setcc { .. } | X86Instruction::Jcc { .. }
    )
}

// The mode-width encodability ruleset lives in `encoding`. Only the
// `Assembler::can_assemble` prefilter is needed here; the register / immediate
// predicates it is built from are used by the mutator and generator over in
// `stochastic`, and the `imm{8,16,32}` bit-pattern helpers stay private to
// `encoding`.
use encoding::x86_can_assemble_instruction;

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
    fn register_views_share_a_canonical_architectural_gpr() {
        for view in [
            X86Register::RAX,
            X86Register::EAX,
            X86Register::AX,
            X86Register::AL,
            X86Register::AH,
        ] {
            assert_eq!(view.canonical(), X86Register::RAX, "unexpected view {view}");
        }
        for view in [
            X86Register::R8,
            X86Register::R8D,
            X86Register::R8W,
            X86Register::R8B,
        ] {
            assert_eq!(view.canonical(), X86Register::R8, "unexpected view {view}");
        }
    }

    #[test]
    fn register_view_width_and_high_byte_classification_are_explicit() {
        for (reg, width64, width32, high_byte) in [
            (X86Register::RAX, 64, 32, false),
            (X86Register::EAX, 32, 32, false),
            (X86Register::AX, 16, 16, false),
            (X86Register::AL, 8, 8, false),
            (X86Register::AH, 8, 8, true),
            (X86Register::SPL, 8, 8, false),
            (X86Register::R8B, 8, 8, false),
        ] {
            assert_eq!(reg.effective_width(64), width64, "x86-64 width for {reg}");
            assert_eq!(reg.effective_width(32), width32, "x86-32 width for {reg}");
            assert_eq!(reg.is_high_byte(), high_byte, "high-byte marker for {reg}");
        }
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
    fn x86_search_encodability_rejects_high_byte_with_rex_register() {
        let rex_conflict = [X86Instruction::MovReg {
            rd: X86Register::AH,
            rs: X86Register::R8B,
        }];
        assert!(
            !crate::search::candidate::is_sequence_encodable_for(&rex_conflict, &X86_64),
            "the search filter must drop high-byte candidates that require REX"
        );

        let legacy_pair = [X86Instruction::MovReg {
            rd: X86Register::AH,
            rs: X86Register::BL,
        }];
        assert!(
            crate::search::candidate::is_sequence_encodable_for(&legacy_pair, &X86_64),
            "the search filter must retain encodable legacy-byte pairs"
        );
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
    fn x86_setcc_encodability_requires_native_view_and_available_low_byte_register() {
        use crate::isa::traits::Assembler;

        let setne = |rd| X86Instruction::Setcc {
            rd,
            cond: X86Condition::NE,
        };
        assert!(<X86_64 as Assembler<X86Instruction>>::can_assemble(
            &X86_64,
            &setne(X86Register::R15)
        ));
        for rd in [
            X86Register::EAX,
            X86Register::AX,
            X86Register::AL,
            X86Register::AH,
            X86Register::R15D,
            X86Register::R15B,
        ] {
            assert!(
                !<X86_64 as Assembler<X86Instruction>>::can_assemble(&X86_64, &setne(rd)),
                "x86-64 SETcc pseudo-op should reject non-native destination {rd}"
            );
        }
        assert!(<X86_32 as Assembler<X86Instruction>>::can_assemble(
            &X86_32,
            &setne(X86Register::RAX)
        ));
        for rd in [
            X86Register::EAX,
            X86Register::AX,
            X86Register::AL,
            X86Register::AH,
        ] {
            assert!(
                !<X86_32 as Assembler<X86Instruction>>::can_assemble(&X86_32, &setne(rd)),
                "x86-32 SETcc pseudo-op should reject non-native destination {rd}"
            );
        }
        assert!(!<X86_32 as Assembler<X86Instruction>>::can_assemble(
            &X86_32,
            &setne(X86Register::RSI)
        ));
        assert!(!<X86_32 as Assembler<X86Instruction>>::can_assemble(
            &X86_32,
            &setne(X86Register::R8)
        ));
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
    fn movzx_movsx_metadata_marks_a_pure_write_from_one_source() {
        use crate::isa::traits::{FlagsAnalysis, InstructionType};

        for (instruction, mnemonic, opcode) in [
            (
                X86Instruction::Movzx {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    src_width: 8,
                },
                "movzx",
                28,
            ),
            (
                X86Instruction::Movsx {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    src_width: 16,
                },
                "movsx",
                29,
            ),
        ] {
            assert_eq!(instruction.destination(), Some(X86Register::RAX));
            assert_eq!(instruction.source_registers(), vec![X86Register::RBX]);
            assert_eq!(instruction.mnemonic(), mnemonic);
            assert_eq!(instruction.opcode_id(), opcode);
            assert!(!instruction.is_terminator());
            assert!(!instruction.has_side_effects());
            assert!(!<X86_64 as FlagsAnalysis<X86Instruction>>::modifies_flags(
                &instruction
            ));
            assert!(!<X86_64 as FlagsAnalysis<X86Instruction>>::reads_flags(
                &instruction
            ));
        }
    }

    #[test]
    fn extension_encodability_tracks_mode_specific_byte_register_rules() {
        use crate::isa::traits::Assembler;

        let low_byte = X86Instruction::Movzx {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            src_width: 8,
        };
        let rex_byte = X86Instruction::Movsx {
            rd: X86Register::RAX,
            rs: X86Register::RSP,
            src_width: 8,
        };
        let invalid_width = X86Instruction::Movzx {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            src_width: 32,
        };
        let view_carrying_destination = X86Instruction::Movzx {
            rd: X86Register::EAX,
            rs: X86Register::RBX,
            src_width: 8,
        };
        let view_carrying_source = X86Instruction::Movsx {
            rd: X86Register::RAX,
            rs: X86Register::BL,
            src_width: 8,
        };

        assert!(X86_64.can_assemble(&low_byte));
        assert!(X86_32.can_assemble(&low_byte));
        assert!(X86_64.can_assemble(&rex_byte));
        assert!(!X86_32.can_assemble(&rex_byte));
        assert!(!X86_64.can_assemble(&invalid_width));
        assert!(!X86_32.can_assemble(&invalid_width));
        for instruction in [view_carrying_destination, view_carrying_source] {
            assert!(!X86_64.can_assemble(&instruction));
            assert!(!X86_32.can_assemble(&instruction));
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
    fn setcc_metadata_models_a_flag_reading_full_register_write() {
        use crate::isa::traits::InstructionType;

        let setne = X86Instruction::Setcc {
            rd: X86Register::RAX,
            cond: X86Condition::NE,
        };
        assert_eq!(setne.destination(), Some(X86Register::RAX));
        assert!(setne.source_registers().is_empty());
        assert_eq!(setne.mnemonic(), "setne");
        assert_eq!(setne.to_string(), "setne rax");
        assert!(!setne.is_terminator());
        assert!(!setne.has_side_effects());
        assert!(!x86_modifies_flags(&setne));
        assert!(x86_reads_flags(&setne));
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
    fn partial_pure_writes_read_the_preserved_canonical_destination() {
        let cases = [
            (
                X86Instruction::MovReg {
                    rd: X86Register::AL,
                    rs: X86Register::BL,
                },
                vec![X86Register::RAX, X86Register::RBX],
            ),
            (
                X86Instruction::MovImm {
                    rd: X86Register::AH,
                    imm: 1,
                },
                vec![X86Register::RAX],
            ),
            (
                X86Instruction::ImulRegImm {
                    rd: X86Register::AX,
                    rs: X86Register::BX,
                    imm: 3,
                },
                vec![X86Register::RAX, X86Register::RBX],
            ),
            (
                X86Instruction::Lea {
                    rd: X86Register::AX,
                    base: X86Register::RBX,
                    disp: 1,
                },
                vec![X86Register::RAX, X86Register::RBX],
            ),
        ];

        for (instruction, expected) in cases {
            assert_eq!(
                instruction.source_registers(),
                expected,
                "{instruction} must read the canonical destination bits it preserves"
            );
        }

        for rd in [X86Register::RAX, X86Register::EAX] {
            assert!(
                X86Instruction::MovImm { rd, imm: 1 }
                    .source_registers()
                    .is_empty(),
                "{rd} fully overwrites the architectural register"
            );
        }
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
    fn x86_register_availability_by_mode() {
        use crate::assembler::x86::X86Mode;

        // 64-bit mode addresses all sixteen GPRs, including the extended file
        // and the REX-only low-byte views.
        for r in [
            X86Register::RAX,
            X86Register::RDI,
            X86Register::R8,
            X86Register::R15,
            X86Register::SPL,
            X86Register::BPL,
            X86Register::SIL,
            X86Register::DIL,
        ] {
            assert!(
                r.is_available_in(X86Mode::Mode64),
                "{:?} must be available in 64-bit mode",
                r
            );
        }

        // 32-bit mode has no encoding for the extended registers R8..R15 or
        // the REX-only low-byte views SPL/BPL/SIL/DIL. Native views of the
        // eight legacy GPRs and the legacy low-byte views remain addressable.
        for r in [
            X86Register::RAX,
            X86Register::RSP,
            X86Register::RDI,
            X86Register::AL,
            X86Register::CL,
            X86Register::DL,
            X86Register::BL,
        ] {
            assert!(
                r.is_available_in(X86Mode::Mode32),
                "{:?} must be available in 32-bit mode",
                r
            );
        }
        for r in [
            X86Register::R8,
            X86Register::R9,
            X86Register::R12,
            X86Register::R15,
            X86Register::SPL,
            X86Register::BPL,
            X86Register::SIL,
            X86Register::DIL,
        ] {
            assert!(
                !r.is_available_in(X86Mode::Mode32),
                "{:?} must be unavailable in 32-bit mode",
                r
            );
        }
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

    // --- FlagsAnalysis::reads_flags wired for SETcc / Cmov / Jcc ---

    #[test]
    fn x86_64_reads_flags_returns_true_for_setcc_cmov_and_jcc() {
        use crate::isa::traits::FlagsAnalysis;
        let setcc = X86Instruction::Setcc {
            rd: X86Register::RAX,
            cond: X86Condition::E,
        };
        let cmov = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        };
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::NE,
        };
        assert!(<X86_64 as FlagsAnalysis<X86Instruction>>::reads_flags(
            &setcc
        ));
        assert!(<X86_64 as FlagsAnalysis<X86Instruction>>::reads_flags(
            &cmov
        ));
        assert!(<X86_64 as FlagsAnalysis<X86Instruction>>::reads_flags(&jcc));
    }

    #[test]
    fn x86_32_reads_flags_returns_true_for_setcc_cmov_and_jcc() {
        use crate::isa::traits::FlagsAnalysis;
        let setcc = X86Instruction::Setcc {
            rd: X86Register::RAX,
            cond: X86Condition::E,
        };
        let cmov = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        };
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::NE,
        };
        assert!(<X86_32 as FlagsAnalysis<X86Instruction>>::reads_flags(
            &setcc
        ));
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
