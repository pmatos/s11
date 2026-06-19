//! AArch64 instruction definitions for the IR

use crate::ir::aarch64_encoding::logical_imm64_encodable;
use crate::ir::types::{
    AccessWidth, AddressOperand, Condition, ExtendKind, IndexMode, LabelId, Operand, Register,
    RegisterWidth, ShiftKind,
};
use std::fmt;

/// Legal `lsl` amounts for the move-wide immediate family (MOVN / MOVZ / MOVK).
/// Single source of truth shared by `is_encodable_aarch64`, the parser, and
/// every random-generation / mutation site so the four positions cannot drift
/// out of sync across the codebase.
pub const MOVW_LEGAL_SHIFTS: [u8; 4] = [0, 16, 32, 48];

pub(crate) fn logical_imm32_value(imm: i64) -> Option<u32> {
    if imm >= 0 {
        u32::try_from(imm).ok()
    } else {
        Some(imm as u32)
    }
}

/// True iff `imm` is representable as an AArch64 32-bit logical bitmask
/// immediate. Positive literals must fit in 32 bits; negative literals are
/// interpreted as two's-complement W-width masks.
pub(crate) fn logical_imm32_encodable(imm: i64) -> bool {
    logical_imm32_value(imm)
        .and_then(dynasmrt::aarch64::encode_logical_immediate_32bit)
        .is_some()
}

fn is_x_or_xzr(reg: Register) -> bool {
    reg != Register::SP
}

fn is_xsp(reg: Register) -> bool {
    reg != Register::XZR
}

fn is_plain_x(reg: Register) -> bool {
    reg != Register::SP && reg != Register::XZR
}

/// Helper for `Instruction::destinations` on single-register memory ops: the
/// data register is always written, and PreIndex/PostIndex modes additionally
/// write the base register through writeback. See ADR-0007.
#[allow(dead_code)]
fn writeback_destinations(rt: Register, addr: &AddressOperand) -> Vec<Register> {
    match addr {
        AddressOperand::Imm {
            base,
            mode: IndexMode::PreIndex,
            ..
        }
        | AddressOperand::Imm {
            base,
            mode: IndexMode::PostIndex,
            ..
        } => vec![rt, *base],
        _ => vec![rt],
    }
}

/// Helper for `Instruction::destinations` on LDP-family ops: two register
/// destinations plus the writeback base when applicable. See ADR-0007.
#[allow(dead_code)]
fn pair_load_destinations(rt1: Register, rt2: Register, addr: &AddressOperand) -> Vec<Register> {
    match addr {
        AddressOperand::Imm {
            base,
            mode: IndexMode::PreIndex,
            ..
        }
        | AddressOperand::Imm {
            base,
            mode: IndexMode::PostIndex,
            ..
        } => vec![rt1, rt2, *base],
        _ => vec![rt1, rt2],
    }
}

/// Helper for `Instruction::destinations` on store ops: `rt` is read (not
/// written), so the only destination is the writeback base — and only in
/// PreIndex / PostIndex modes. See ADR-0007.
#[allow(dead_code)]
fn store_destinations(addr: &AddressOperand) -> Vec<Register> {
    match addr {
        AddressOperand::Imm {
            base,
            mode: IndexMode::PreIndex,
            ..
        }
        | AddressOperand::Imm {
            base,
            mode: IndexMode::PostIndex,
            ..
        } => vec![*base],
        _ => vec![],
    }
}

/// AArch64 instructions supported by the IR
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum Instruction {
    // Data movement
    MovReg {
        rd: Register,
        rn: Register,
    },
    MovRegW {
        rd: Register,
        rn: Register,
    },
    MovImm {
        rd: Register,
        imm: i64,
    },

    // Arithmetic
    Add {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    AddW {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Sub {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    SubW {
        rd: Register,
        rn: Register,
        rm: Operand,
    },

    // Logical
    And {
        rd: Register,
        rn: Register,
        rm: Operand,
        width: RegisterWidth,
    },
    Orr {
        rd: Register,
        rn: Register,
        rm: Operand,
        width: RegisterWidth,
    },
    Eor {
        rd: Register,
        rn: Register,
        rm: Operand,
        width: RegisterWidth,
    },

    // Shifts
    Lsl {
        rd: Register,
        rn: Register,
        shift: Operand,
    },
    Lsr {
        rd: Register,
        rn: Register,
        shift: Operand,
    },
    Asr {
        rd: Register,
        rn: Register,
        shift: Operand,
    },

    // Multiplication and division
    Mul {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Sdiv {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Udiv {
        rd: Register,
        rn: Register,
        rm: Register,
    },

    // Multiply-accumulate (rd = ra ± rn*rm) and high-half multiplies
    Madd {
        rd: Register,
        rn: Register,
        rm: Register,
        ra: Register,
    },
    Msub {
        rd: Register,
        rn: Register,
        rm: Register,
        ra: Register,
    },
    Mneg {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Smulh {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Umulh {
        rd: Register,
        rn: Register,
        rm: Register,
    },

    // Comparison (set NZCV flags, no destination register)
    Cmp {
        rn: Register,
        rm: Operand,
    },
    Cmn {
        rn: Register,
        rm: Operand,
    },
    Tst {
        rn: Register,
        rm: Operand,
        width: RegisterWidth,
    },

    // Conditional select
    Csel {
        rd: Register,
        rn: Register,
        rm: Register,
        cond: Condition,
    },
    Csinc {
        rd: Register,
        rn: Register,
        rm: Register,
        cond: Condition,
    },
    Csinv {
        rd: Register,
        rn: Register,
        rm: Register,
        cond: Condition,
    },
    Csneg {
        rd: Register,
        rn: Register,
        rm: Register,
        cond: Condition,
    },

    // Conditional compare (subtract): if `cond` holds, set NZCV from
    // `rn - operand(rm)`; otherwise set NZCV to the 4-bit `nzcv` literal
    // (bit3=N, bit2=Z, bit1=C, bit0=V). Reads and writes NZCV.
    Ccmp {
        rn: Register,
        rm: Operand,
        nzcv: u8,
        cond: Condition,
    },
    // Conditional compare negative (add): same as Ccmp with `rn + operand(rm)`.
    Ccmn {
        rn: Register,
        rm: Operand,
        nzcv: u8,
        cond: Condition,
    },

    // Bitwise NOT (alias of ORN with XZR)
    Mvn {
        rd: Register,
        rm: Register,
    },
    // Two's-complement negation (alias of SUB from XZR)
    Neg {
        rd: Register,
        rm: Register,
    },
    // Flag-setting negation (alias of SUBS from XZR)
    Negs {
        rd: Register,
        rm: Register,
    },
    // Move-negated immediate: rd = !((imm as u64) << shift), shift ∈ {0,16,32,48}
    MovN {
        rd: Register,
        imm: u16,
        shift: u8,
    },
    // Move-wide-zero immediate: rd = (imm as u64) << shift, shift ∈ {0,16,32,48}
    MovZ {
        rd: Register,
        imm: u16,
        shift: u8,
    },
    // Move-wide-keep immediate: writes one 16-bit chunk, preserving the rest.
    // rd = (rd & ~(0xFFFF << shift)) | ((imm as u64) << shift), shift ∈ {0,16,32,48}.
    // Unlike MovN/MovZ this reads rd, so the rd register must be live-in.
    MovK {
        rd: Register,
        imm: u16,
        shift: u8,
    },

    // Inverted-logical (second operand bitwise-NOTed before the op)
    Bic {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Bics {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Orn {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Eon {
        rd: Register,
        rn: Register,
        rm: Operand,
    },

    // Flag-setting arithmetic / logical
    Adds {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Subs {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    // Add/subtract with carry. AArch64 has only the register form (no
    // immediate, no shifted-register), so `rm` is a plain `Register`.
    // Adc/Sbc read the carry flag; Adcs/Sbcs additionally write NZCV.
    Adc {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Adcs {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Sbc {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Sbcs {
        rd: Register,
        rn: Register,
        rm: Register,
    },
    Ands {
        rd: Register,
        rn: Register,
        rm: Operand,
        width: RegisterWidth,
    },

    // Conditional set: rd = (cond holds) ? 1 : 0
    Cset {
        rd: Register,
        cond: Condition,
    },
    // Conditional set mask: rd = (cond holds) ? -1 : 0
    Csetm {
        rd: Register,
        cond: Condition,
    },

    // Rotate right (immediate or register form)
    Ror {
        rd: Register,
        rn: Register,
        shift: Operand,
    },

    // Single-source bit-manipulation (always register-only, {rd, rn})
    Clz {
        rd: Register,
        rn: Register,
    },
    Cls {
        rd: Register,
        rn: Register,
    },
    Rbit {
        rd: Register,
        rn: Register,
    },
    Rev {
        rd: Register,
        rn: Register,
    },
    Rev32 {
        rd: Register,
        rn: Register,
    },
    Rev16 {
        rd: Register,
        rn: Register,
    },

    // Standalone sign/zero-extend (UBFM/SBFM aliases). Issue #60.
    // The Rn slot is architecturally a W-register for byte/half/word
    // extends and X-register for the (out-of-scope) UXTX/SXTX. The IR
    // models Rn as 64-bit X; semantics mask the low N bits explicitly.
    Sxtb {
        rd: Register,
        rn: Register,
    },
    Sxth {
        rd: Register,
        rn: Register,
    },
    Sxtw {
        rd: Register,
        rn: Register,
    },
    Uxtb {
        rd: Register,
        rn: Register,
    },
    Uxth {
        rd: Register,
        rn: Register,
    },
    // Bit-field manipulation (64-bit, aliases of UBFM/SBFM/BFM per ARM ARM C6.2).
    // `lsb` is the bit position of the least-significant bit of the field in the
    // source; `width` is the field width. Constraint: lsb ∈ [0..=63],
    // width ∈ [1..=64-lsb]. Enforced in `is_encodable_aarch64`.
    Ubfx {
        rd: Register,
        rn: Register,
        lsb: u8,
        width: u8,
    },
    Sbfx {
        rd: Register,
        rn: Register,
        lsb: u8,
        width: u8,
    },
    Bfi {
        rd: Register,
        rn: Register,
        lsb: u8,
        width: u8,
    },
    Bfxil {
        rd: Register,
        rn: Register,
        lsb: u8,
        width: u8,
    },
    Ubfiz {
        rd: Register,
        rn: Register,
        lsb: u8,
        width: u8,
    },
    Sbfiz {
        rd: Register,
        rn: Register,
        lsb: u8,
        width: u8,
    },

    // Branches / control flow (terminators only — never appear in the
    // rewritable prefix; search holds them fixed).
    B {
        target: LabelId,
    },
    BCond {
        target: LabelId,
        cond: Condition,
    },
    Ret {
        rn: Register,
    },
    Cbz {
        rn: Register,
        target: LabelId,
    },
    Cbnz {
        rn: Register,
        target: LabelId,
    },
    Tbz {
        rt: Register,
        bit: u8,
        target: LabelId,
    },
    Tbnz {
        rt: Register,
        bit: u8,
        target: LabelId,
    },
    Bl {
        target: LabelId,
    },
    Br {
        rn: Register,
    },

    // Memory ops — see ADR-0007.
    /// LDR / LDRB / LDRH — zero-extended load into `rt`. With PreIndex or
    /// PostIndex mode the base register is also written (writeback).
    Ldr {
        rt: Register,
        addr: AddressOperand,
        width: AccessWidth,
    },
    /// LDRSB / LDRSH / LDRSW — sign-extending load into `rt` (always
    /// X-form destination). Writeback handled identically to `Ldr`.
    Ldrs {
        rt: Register,
        addr: AddressOperand,
        width: AccessWidth,
    },
    /// STR / STRB / STRH — store `rt` into memory. `rt` is a *source*
    /// register (no register destination); PreIndex / PostIndex modes
    /// still write the base register through writeback.
    Str {
        rt: Register,
        addr: AddressOperand,
        width: AccessWidth,
    },
    /// LDP / LDPSW — load a pair of registers. Writeback writes the base
    /// register as a third destination. `signed=true` is legal only when
    /// `width == Word` (LDPSW); this is enforced by `is_encodable_aarch64`.
    Ldp {
        rt1: Register,
        rt2: Register,
        addr: AddressOperand,
        width: AccessWidth,
        signed: bool,
    },
    /// STP — store a pair of registers. `rt1`/`rt2` are read; writeback
    /// addressing modes mutate the base register.
    Stp {
        rt1: Register,
        rt2: Register,
        addr: AddressOperand,
        width: AccessWidth,
    },
}

impl Instruction {
    /// Registers this instruction writes (in canonical order). Empty for
    /// pure flag-setters and branches; one entry for single-destination
    /// arithmetic and logical ops; two entries for LDP and writeback
    /// addressing modes (post-/pre-index update the base register as well
    /// as the data register). See ADR-0007.
    #[allow(dead_code)]
    pub fn destinations(&self) -> Vec<Register> {
        match self {
            Instruction::Ldr { rt, addr, .. } | Instruction::Ldrs { rt, addr, .. } => {
                writeback_destinations(*rt, addr)
            }
            Instruction::Str { addr, .. } => store_destinations(addr),
            Instruction::Ldp { rt1, rt2, addr, .. } => pair_load_destinations(*rt1, *rt2, addr),
            Instruction::Stp { addr, .. } => store_destinations(addr),
            _ => match self.destination() {
                Some(r) => vec![r],
                None => Vec::new(),
            },
        }
    }

    /// Get the destination register for this instruction (None for comparison instructions)
    #[allow(dead_code)]
    pub fn destination(&self) -> Option<Register> {
        match self {
            Instruction::MovReg { rd, .. }
            | Instruction::MovRegW { rd, .. }
            | Instruction::MovImm { rd, .. }
            | Instruction::Add { rd, .. }
            | Instruction::AddW { rd, .. }
            | Instruction::Sub { rd, .. }
            | Instruction::SubW { rd, .. }
            | Instruction::And { rd, .. }
            | Instruction::Orr { rd, .. }
            | Instruction::Eor { rd, .. }
            | Instruction::Lsl { rd, .. }
            | Instruction::Lsr { rd, .. }
            | Instruction::Asr { rd, .. }
            | Instruction::Mul { rd, .. }
            | Instruction::Sdiv { rd, .. }
            | Instruction::Udiv { rd, .. }
            | Instruction::Madd { rd, .. }
            | Instruction::Msub { rd, .. }
            | Instruction::Mneg { rd, .. }
            | Instruction::Smulh { rd, .. }
            | Instruction::Umulh { rd, .. }
            | Instruction::Csel { rd, .. }
            | Instruction::Csinc { rd, .. }
            | Instruction::Csinv { rd, .. }
            | Instruction::Csneg { rd, .. }
            | Instruction::Mvn { rd, .. }
            | Instruction::Neg { rd, .. }
            | Instruction::Negs { rd, .. }
            | Instruction::MovN { rd, .. }
            | Instruction::MovZ { rd, .. }
            | Instruction::MovK { rd, .. }
            | Instruction::Bic { rd, .. }
            | Instruction::Bics { rd, .. }
            | Instruction::Orn { rd, .. }
            | Instruction::Eon { rd, .. }
            | Instruction::Adds { rd, .. }
            | Instruction::Subs { rd, .. }
            | Instruction::Adc { rd, .. }
            | Instruction::Adcs { rd, .. }
            | Instruction::Sbc { rd, .. }
            | Instruction::Sbcs { rd, .. }
            | Instruction::Ands { rd, .. }
            | Instruction::Cset { rd, .. }
            | Instruction::Csetm { rd, .. }
            | Instruction::Ror { rd, .. }
            | Instruction::Clz { rd, .. }
            | Instruction::Cls { rd, .. }
            | Instruction::Rbit { rd, .. }
            | Instruction::Rev { rd, .. }
            | Instruction::Rev32 { rd, .. }
            | Instruction::Rev16 { rd, .. }
            | Instruction::Sxtb { rd, .. }
            | Instruction::Sxth { rd, .. }
            | Instruction::Sxtw { rd, .. }
            | Instruction::Uxtb { rd, .. }
            | Instruction::Uxth { rd, .. }
            | Instruction::Ubfx { rd, .. }
            | Instruction::Sbfx { rd, .. }
            | Instruction::Bfi { rd, .. }
            | Instruction::Bfxil { rd, .. }
            | Instruction::Ubfiz { rd, .. }
            | Instruction::Sbfiz { rd, .. } => Some(*rd),
            // Comparison instructions only set flags, no destination register
            Instruction::Cmp { .. }
            | Instruction::Cmn { .. }
            | Instruction::Tst { .. }
            | Instruction::Ccmp { .. }
            | Instruction::Ccmn { .. } => None,
            // Branches / terminators have no destination register.
            Instruction::B { .. }
            | Instruction::BCond { .. }
            | Instruction::Ret { .. }
            | Instruction::Cbz { .. }
            | Instruction::Cbnz { .. }
            | Instruction::Tbz { .. }
            | Instruction::Tbnz { .. }
            | Instruction::Bl { .. }
            | Instruction::Br { .. } => None,
            // Memory ops may have multiple destinations (writeback) — callers
            // must use `destinations()` instead. `destination()` is retained
            // only for migration; it returns `None` here to avoid silently
            // hiding the base-register writeback. See ADR-0007.
            Instruction::Ldr { .. }
            | Instruction::Ldrs { .. }
            | Instruction::Str { .. }
            | Instruction::Ldp { .. }
            | Instruction::Stp { .. } => None,
        }
    }

    /// Returns true if this instruction is a basic-block terminator (branch /
    /// control flow). Terminators are held fixed by the search: mutation and
    /// synthesis never produce or rewrite them, and the equivalence layer
    /// strips them before applying prefix semantics.
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            Instruction::B { .. }
                | Instruction::BCond { .. }
                | Instruction::Ret { .. }
                | Instruction::Cbz { .. }
                | Instruction::Cbnz { .. }
                | Instruction::Tbz { .. }
                | Instruction::Tbnz { .. }
                | Instruction::Bl { .. }
                | Instruction::Br { .. }
        )
    }
}

/// Split an instruction sequence into `(prefix, terminator)`. Returns the
/// full slice as prefix and `None` if the sequence does not end with a
/// terminator. Issue #69: shared by the search splitter (`find_shorter_equivalent`)
/// and the equivalence precheck (`check_equivalence*`).
pub fn split_terminator(seq: &[Instruction]) -> (&[Instruction], Option<&Instruction>) {
    match seq.last() {
        Some(last) if last.is_terminator() => (&seq[..seq.len() - 1], Some(last)),
        _ => (seq, None),
    }
}

/// x86 mirror of `split_terminator`. Peels a trailing Jcc
/// off the sequence so the optimizer can reason about the straight-line
/// prefix while leaving the branch terminator pinned in the binary.
pub fn split_terminator_x86(
    seq: &[crate::isa::x86::X86Instruction],
) -> (
    &[crate::isa::x86::X86Instruction],
    Option<&crate::isa::x86::X86Instruction>,
) {
    match seq.last() {
        Some(last) if last.is_terminator() => (&seq[..seq.len() - 1], Some(last)),
        _ => (seq, None),
    }
}

impl Instruction {
    /// Returns true if this instruction modifies NZCV flags.
    ///
    /// Note: for flag-setting variants (NEGS, ADDS, SUBS, ANDS, BICS), this
    /// can co-occur with `destination().is_some()` — those write both a
    /// register and the NZCV flags. Earlier callers that assumed
    /// "flag-setter ⇒ no destination" must be re-verified.
    pub fn modifies_flags(&self) -> bool {
        matches!(
            self,
            Instruction::Cmp { .. }
                | Instruction::Cmn { .. }
                | Instruction::Tst { .. }
                | Instruction::Negs { .. }
                | Instruction::Bics { .. }
                | Instruction::Adds { .. }
                | Instruction::Subs { .. }
                | Instruction::Adcs { .. }
                | Instruction::Sbcs { .. }
                | Instruction::Ands { .. }
                | Instruction::Ccmp { .. }
                | Instruction::Ccmn { .. }
        )
    }

    /// Returns true if this instruction reads NZCV flags
    #[allow(dead_code)]
    pub fn reads_flags(&self) -> bool {
        matches!(
            self,
            Instruction::Csel { .. }
                | Instruction::Csinc { .. }
                | Instruction::Csinv { .. }
                | Instruction::Csneg { .. }
                | Instruction::Cset { .. }
                | Instruction::Csetm { .. }
                | Instruction::Ccmp { .. }
                | Instruction::Ccmn { .. }
                | Instruction::BCond { .. }
                // ADC/SBC family reads the carry flag as a live-in.
                | Instruction::Adc { .. }
                | Instruction::Adcs { .. }
                | Instruction::Sbc { .. }
                | Instruction::Sbcs { .. }
        )
    }

    /// Check if this instruction can be encoded in AArch64 machine code.
    ///
    /// This validates immediate operand ranges against AArch64 encoding constraints:
    /// - MOV immediate: 0 to 0xFFFF (16-bit)
    /// - ADD/SUB immediate: 0 to 0xFFF (12-bit unsigned); rd/rn ≠ XZR (Xn|SP slot, SP allowed)
    /// - CMP/CMN immediate: 0 to 0xFFF (12-bit unsigned)
    /// - LSL/LSR/ASR immediate: 0 to 63
    /// - AND/ORR/EOR immediate: register, or encodable bitmask immediate
    ///   (rd ≠ XZR for the imm form — Xn|SP slot rejects the zero register)
    /// - TST immediate: register, or encodable bitmask immediate
    pub fn is_encodable_aarch64(&self) -> bool {
        match self {
            // MOV register forms use plain X/W register slots: XZR is encodable, SP is not.
            Instruction::MovReg { rd, rn } | Instruction::MovRegW { rd, rn } => {
                is_x_or_xzr(*rd) && is_x_or_xzr(*rn)
            }

            // MOV immediate: 16-bit range
            Instruction::MovImm { rd, imm } => is_x_or_xzr(*rd) && *imm >= 0 && *imm <= 0xFFFF,

            // ADD/SUB: register or immediate (12-bit unsigned), or shifted-register
            // (LSL/LSR/ASR only — ROR not encodable for arithmetic shifted-register form).
            // Shifted-register form forbids SP for any operand (ARM v8 spec).
            Instruction::Add { rd, rn, rm } | Instruction::Sub { rd, rn, rm } => match rm {
                Operand::Register(reg) => is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && is_x_or_xzr(*reg),
                // Immediate form: rd and rn occupy the Xn|SP slot, so SP is
                // permitted but XZR (also reg 31) must be rejected — it would
                // alias to SP. Mirrors the assembler's register_to_dynasm_xsp
                // so can_assemble() stays consistent with the real encoder.
                Operand::Immediate(imm) => *imm >= 0 && *imm <= 0xFFF && is_xsp(*rd) && is_xsp(*rn),
                Operand::ShiftedRegister { reg, kind, amount } => {
                    *kind != ShiftKind::Ror
                        && *amount <= 63
                        && is_x_or_xzr(*reg)
                        && is_x_or_xzr(*rd)
                        && is_x_or_xzr(*rn)
                }
                // Issue #60: extended-register form. Shift 0..=4. rd/rn use
                // the Xn|SP class, while the inner operand uses a plain X slot.
                Operand::ExtendedRegister { reg, shift, .. } => {
                    *shift <= 4 && is_x_or_xzr(*reg) && is_xsp(*rd) && is_xsp(*rn)
                }
            },
            Instruction::AddW { rd, rn, rm } | Instruction::SubW { rd, rn, rm } => match rm {
                Operand::Register(reg) => is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && is_x_or_xzr(*reg),
                Operand::Immediate(imm) => *imm >= 0 && *imm <= 0xFFF && is_xsp(*rd) && is_xsp(*rn),
                Operand::ShiftedRegister { reg, kind, amount } => {
                    *kind != ShiftKind::Ror
                        && *amount <= 31
                        && is_x_or_xzr(*reg)
                        && is_x_or_xzr(*rd)
                        && is_x_or_xzr(*rn)
                }
                Operand::ExtendedRegister { .. } => false,
            },

            // AND/ORR/EOR: register, encodable bitmask immediate (issue #65), or
            // shifted-register (all 4 kinds incl. ROR; shifted-register form
            // forbids SP for any operand). The immediate form encodes Rd in
            // the Xn|SP slot, which forbids XZR (would alias to SP and
            // silently miscompile).
            Instruction::And { rd, rn, rm, width }
            | Instruction::Orr { rd, rn, rm, width }
            | Instruction::Eor { rd, rn, rm, width } => match rm {
                Operand::Register(reg) => {
                    *width == RegisterWidth::X64
                        && is_x_or_xzr(*rd)
                        && is_x_or_xzr(*rn)
                        && is_x_or_xzr(*reg)
                }
                // rd in the Xn|SP slot (SP allowed, XZR forbidden); rn in the
                // plain Xn slot (XZR allowed via reg 31, SP forbidden).
                Operand::Immediate(imm) => match width {
                    RegisterWidth::X64 => {
                        is_xsp(*rd) && is_x_or_xzr(*rn) && logical_imm64_encodable(*imm)
                    }
                    RegisterWidth::W32 => {
                        is_xsp(*rd) && is_x_or_xzr(*rn) && logical_imm32_encodable(*imm)
                    }
                },
                Operand::ShiftedRegister { reg, amount, .. } => {
                    *width == RegisterWidth::X64
                        && *amount <= 63
                        && is_x_or_xzr(*reg)
                        && is_x_or_xzr(*rd)
                        && is_x_or_xzr(*rn)
                }
                // Logical opcodes do not accept the extended-register form.
                Operand::ExtendedRegister { .. } => false,
            },

            // Shift instructions: shift amount 0-63 for 64-bit registers.
            // Reject Operand::ShiftedRegister in the shift slot (semantically nonsense:
            // shifting by a shifted-register result is not part of issue #59 scope).
            Instruction::Lsl { rd, rn, shift }
            | Instruction::Lsr { rd, rn, shift }
            | Instruction::Asr { rd, rn, shift } => match shift {
                Operand::Register(reg) => is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && is_x_or_xzr(*reg),
                Operand::Immediate(amt) => {
                    is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && *amt >= 0 && *amt <= 63
                }
                Operand::ShiftedRegister { .. } => false,
                Operand::ExtendedRegister { .. } => false,
            },

            // Three-register multiply/divide forms use plain Xn register
            // slots, so reg31 is XZR and SP must be rejected.
            Instruction::Mul { rd, rn, rm }
            | Instruction::Sdiv { rd, rn, rm }
            | Instruction::Udiv { rd, rn, rm }
            | Instruction::Mneg { rd, rn, rm }
            | Instruction::Smulh { rd, rn, rm }
            | Instruction::Umulh { rd, rn, rm } => {
                is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && is_x_or_xzr(*rm)
            }

            // Multiply-accumulate family: plain Xn register slots, so reg31
            // is XZR and SP must be rejected.
            Instruction::Madd { rd, rn, rm, ra } | Instruction::Msub { rd, rn, rm, ra } => {
                is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && is_x_or_xzr(*rm) && is_x_or_xzr(*ra)
            }

            // CMP/CMN: register, immediate (12-bit unsigned), or shifted-register
            // (LSL/LSR/ASR only — ROR not encodable for arithmetic shifted-register form).
            Instruction::Cmp { rn, rm } | Instruction::Cmn { rn, rm } => match rm {
                Operand::Register(reg) => is_x_or_xzr(*rn) && is_x_or_xzr(*reg),
                Operand::Immediate(imm) => *imm >= 0 && *imm <= 0xFFF && is_xsp(*rn),
                Operand::ShiftedRegister { reg, kind, amount } => {
                    *kind != ShiftKind::Ror
                        && *amount <= 63
                        && is_x_or_xzr(*reg)
                        && is_x_or_xzr(*rn)
                }
                // Issue #60: extended-register form for CMP/CMN. rn uses the
                // Xn|SP class, while the inner operand uses a plain X slot.
                Operand::ExtendedRegister { reg, shift, .. } => {
                    *shift <= 4 && is_x_or_xzr(*reg) && is_xsp(*rn)
                }
            },

            // TST: register, encodable bitmask immediate (issue #65), or
            // shifted-register (all 4 kinds incl. ROR). No rd, so no XZR-slot
            // guard needed for the immediate form — but rn is the plain Xn slot
            // (rejects SP).
            Instruction::Tst { rn, rm, width } => match rm {
                Operand::Register(reg) => {
                    *width == RegisterWidth::X64 && is_x_or_xzr(*rn) && is_x_or_xzr(*reg)
                }
                Operand::Immediate(imm) => match width {
                    RegisterWidth::X64 => is_x_or_xzr(*rn) && logical_imm64_encodable(*imm),
                    RegisterWidth::W32 => is_x_or_xzr(*rn) && logical_imm32_encodable(*imm),
                },
                Operand::ShiftedRegister { reg, amount, .. } => {
                    *width == RegisterWidth::X64
                        && *amount <= 63
                        && is_x_or_xzr(*reg)
                        && is_x_or_xzr(*rn)
                }
                Operand::ExtendedRegister { .. } => false,
            },

            // Conditional select: register-only plain X slots.
            Instruction::Csel { rd, rn, rm, .. }
            | Instruction::Csinc { rd, rn, rm, .. }
            | Instruction::Csinv { rd, rn, rm, .. }
            | Instruction::Csneg { rd, rn, rm, .. } => {
                is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && is_x_or_xzr(*rm)
            }

            // MVN / NEG / NEGS: register-only plain X slots.
            Instruction::Mvn { rd, rm }
            | Instruction::Neg { rd, rm }
            | Instruction::Negs { rd, rm } => is_x_or_xzr(*rd) && is_x_or_xzr(*rm),

            // MOVN / MOVZ / MOVK: shift must be one of MOVW_LEGAL_SHIFTS;
            // u16 imm is always in range.
            Instruction::MovN { rd, shift, .. }
            | Instruction::MovZ { rd, shift, .. }
            | Instruction::MovK { rd, shift, .. } => {
                is_x_or_xzr(*rd) && MOVW_LEGAL_SHIFTS.contains(shift)
            }

            // BIC / BICS / ORN / EON: register-only (matching AND precedent).
            Instruction::Bic { rd, rn, rm }
            | Instruction::Bics { rd, rn, rm }
            | Instruction::Orn { rd, rn, rm }
            | Instruction::Eon { rd, rn, rm } => match rm {
                Operand::Register(reg) => is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && is_x_or_xzr(*reg),
                Operand::Immediate(_)
                | Operand::ShiftedRegister { .. }
                | Operand::ExtendedRegister { .. } => false,
            },

            // ADDS/SUBS: register, imm 0..=0xFFF, or shifted-register
            // (LSL/LSR/ASR only — ROR not encodable for arithmetic shifted-register form).
            Instruction::Adds { rd, rn, rm } | Instruction::Subs { rd, rn, rm } => match rm {
                Operand::Register(reg) => is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && is_x_or_xzr(*reg),
                Operand::Immediate(imm) => {
                    *imm >= 0 && *imm <= 0xFFF && is_x_or_xzr(*rd) && is_xsp(*rn)
                }
                Operand::ShiftedRegister { reg, kind, amount } => {
                    *kind != ShiftKind::Ror
                        && *amount <= 63
                        && is_x_or_xzr(*reg)
                        && is_x_or_xzr(*rd)
                        && is_x_or_xzr(*rn)
                }
                Operand::ExtendedRegister { .. } => false,
            },
            // ADC/ADCS/SBC/SBCS: register-only form, always encodable.
            Instruction::Adc { .. }
            | Instruction::Adcs { .. }
            | Instruction::Sbc { .. }
            | Instruction::Sbcs { .. } => true,
            // ANDS: register or encodable bitmask immediate (issue #65).
            // ShiftedRegister out of scope (#59). The immediate form uses the
            // plain X slot for both rd and rn (rejects SP); XZR is fine for rd
            // (encodes as the TST shape).
            Instruction::Ands { rd, rn, rm, width } => match rm {
                Operand::Register(reg) => {
                    *width == RegisterWidth::X64
                        && is_x_or_xzr(*rd)
                        && is_x_or_xzr(*rn)
                        && is_x_or_xzr(*reg)
                }
                Operand::Immediate(imm) => match width {
                    RegisterWidth::X64 => {
                        is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && logical_imm64_encodable(*imm)
                    }
                    RegisterWidth::W32 => {
                        is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && logical_imm32_encodable(*imm)
                    }
                },
                Operand::ShiftedRegister { .. } => false,
                Operand::ExtendedRegister { .. } => false,
            },

            // CSET / CSETM: reject AL (always true ⇒ unconditional 1/-1) and
            // NV (reserved). All other 14 conditions are encodable.
            Instruction::Cset { rd, cond } | Instruction::Csetm { rd, cond } => {
                is_x_or_xzr(*rd) && !matches!(cond, Condition::AL | Condition::NV)
            }

            // CCMP / CCMN: reject AL/NV (ARM ARM C6.2.36); reject SP in `rn`
            // (Xn slot, not XSP); the `rm` immediate is a 5-bit unsigned literal
            // (0..=31); `nzcv` is a 4-bit unsigned literal (0..=15). The
            // shifted-register form is not encoded in this IR — CCMP's
            // architectural register form is a plain Xm without shift, so we
            // reject `Operand::ShiftedRegister` here.
            Instruction::Ccmp { rn, rm, nzcv, cond } | Instruction::Ccmn { rn, rm, nzcv, cond } => {
                if matches!(cond, Condition::AL | Condition::NV) {
                    return false;
                }
                if !is_x_or_xzr(*rn) {
                    return false;
                }
                if *nzcv > 15 {
                    return false;
                }
                match rm {
                    Operand::Register(reg) => is_x_or_xzr(*reg),
                    Operand::Immediate(imm) => (0..=31).contains(imm),
                    Operand::ShiftedRegister { .. } => false,
                    Operand::ExtendedRegister { .. } => false,
                }
            }

            // ROR: shift amount 0..=63 (same as LSL/LSR/ASR). ShiftedRegister
            // in the shift slot is rejected (semantically nonsense; same as
            // LSL/LSR/ASR above).
            Instruction::Ror { rd, rn, shift } => match shift {
                Operand::Register(reg) => is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && is_x_or_xzr(*reg),
                Operand::Immediate(amt) => {
                    is_x_or_xzr(*rd) && is_x_or_xzr(*rn) && *amt >= 0 && *amt <= 63
                }
                Operand::ShiftedRegister { .. } => false,
                Operand::ExtendedRegister { .. } => false,
            },

            // Single-source bit-manipulation: register-only, Xn class (no SP).
            // AArch64 reg-31 in this slot is XZR, so SP must be rejected before
            // any caller (SMT, equivalence, LLM) reasons about the candidate.
            // XZR remains encodable.
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
            | Instruction::Uxth { rd, rn } => is_x_or_xzr(*rd) && is_x_or_xzr(*rn),
            // Bit-field aliases of UBFM/SBFM/BFM. Constraint: lsb ∈ [0..=63],
            // width ∈ [1..=64-lsb]. SP rejected in rd and rn.
            Instruction::Ubfx { rd, rn, lsb, width }
            | Instruction::Sbfx { rd, rn, lsb, width }
            | Instruction::Bfi { rd, rn, lsb, width }
            | Instruction::Bfxil { rd, rn, lsb, width }
            | Instruction::Ubfiz { rd, rn, lsb, width }
            | Instruction::Sbfiz { rd, rn, lsb, width } => {
                is_x_or_xzr(*rd)
                    && is_x_or_xzr(*rn)
                    && *lsb <= 63
                    && *width >= 1
                    && (*lsb as u16 + *width as u16) <= 64
            }

            // Branches: encodability is checked against PC-relative range at
            // assembly time. IR-level shape:
            //   - `B`, `Bl`: always shape-valid.
            //   - `Cbz`, `Cbnz`: register operand uses a plain X slot.
            //   - `BCond`: reject `AL` (use plain `B`) and `NV` (reserved).
            //   - `Tbz`, `Tbnz`: bit must be in 0..=63 for 64-bit operand.
            //   - `Ret`, `Br`: register operand uses a plain X slot.
            Instruction::B { .. } | Instruction::Bl { .. } => true,
            Instruction::Cbz { rn, .. }
            | Instruction::Cbnz { rn, .. }
            | Instruction::Ret { rn }
            | Instruction::Br { rn } => is_x_or_xzr(*rn),
            Instruction::BCond { cond, .. } => !matches!(cond, Condition::AL | Condition::NV),
            Instruction::Tbz { rt, bit, .. } | Instruction::Tbnz { rt, bit, .. } => {
                is_x_or_xzr(*rt) && *bit <= 63
            }

            // Memory ops (issue #68). See ADR-0007.
            Instruction::Ldr { rt, addr, width } | Instruction::Str { rt, addr, width } => {
                is_encodable_ldr_like(*rt, addr, *width)
            }
            // LDRSB/LDRSH/LDRSW — no LDRSX, so reject Extended.
            Instruction::Ldrs { rt, addr, width } => {
                if *width == AccessWidth::Extended {
                    return false;
                }
                is_encodable_ldr_like(*rt, addr, *width)
            }
            // LDP additionally rejects rt1==rt2 (UNPREDICTABLE).
            Instruction::Ldp {
                rt1,
                rt2,
                addr,
                width,
                signed,
            } => *rt1 != *rt2 && is_encodable_pair(*rt1, *rt2, addr, *width, *signed),
            // STP allows rt1==rt2 (stores the same value twice).
            Instruction::Stp {
                rt1,
                rt2,
                addr,
                width,
            } => is_encodable_pair(*rt1, *rt2, addr, *width, false),
        }
    }

    /// Get all source registers used by this instruction
    #[allow(dead_code)]
    pub fn source_registers(&self) -> Vec<Register> {
        match self {
            Instruction::MovReg { rn, .. } | Instruction::MovRegW { rn, .. } => vec![*rn],
            Instruction::MovImm { .. } => vec![],
            Instruction::Add { rn, rm, .. }
            | Instruction::AddW { rn, rm, .. }
            | Instruction::Sub { rn, rm, .. }
            | Instruction::SubW { rn, rm, .. }
            | Instruction::And { rn, rm, .. }
            | Instruction::Orr { rn, rm, .. }
            | Instruction::Eor { rn, rm, .. } => {
                let mut regs = vec![*rn];
                match rm {
                    Operand::Register(r) => regs.push(*r),
                    Operand::ShiftedRegister { reg, .. } => regs.push(*reg),
                    Operand::ExtendedRegister { reg, .. } => regs.push(*reg),
                    Operand::Immediate(_) => {}
                }
                regs
            }
            Instruction::Lsl { rn, shift, .. }
            | Instruction::Lsr { rn, shift, .. }
            | Instruction::Asr { rn, shift, .. } => {
                let mut regs = vec![*rn];
                match shift {
                    Operand::Register(r) => regs.push(*r),
                    Operand::ShiftedRegister { reg, .. } => regs.push(*reg),
                    Operand::ExtendedRegister { reg, .. } => regs.push(*reg),
                    Operand::Immediate(_) => {}
                }
                regs
            }
            Instruction::Mul { rn, rm, .. }
            | Instruction::Sdiv { rn, rm, .. }
            | Instruction::Udiv { rn, rm, .. } => vec![*rn, *rm],
            Instruction::Madd { rn, rm, ra, .. } | Instruction::Msub { rn, rm, ra, .. } => {
                vec![*rn, *rm, *ra]
            }
            Instruction::Mneg { rn, rm, .. }
            | Instruction::Smulh { rn, rm, .. }
            | Instruction::Umulh { rn, rm, .. } => vec![*rn, *rm],
            // Comparison instructions read rn and rm (register form,
            // including the shifted-register form's inner register).
            Instruction::Cmp { rn, rm }
            | Instruction::Cmn { rn, rm }
            | Instruction::Tst { rn, rm, .. } => {
                let mut regs = vec![*rn];
                match rm {
                    Operand::Register(r) => regs.push(*r),
                    Operand::ShiftedRegister { reg, .. } => regs.push(*reg),
                    Operand::ExtendedRegister { reg, .. } => regs.push(*reg),
                    Operand::Immediate(_) => {}
                }
                regs
            }
            // CCMP / CCMN read rn and rm (if register). They also read NZCV
            // (via `cond`), but the live-out machinery models flag liveness
            // separately via `reads_flags` and `modifies_flags`.
            Instruction::Ccmp { rn, rm, .. } | Instruction::Ccmn { rn, rm, .. } => {
                let mut regs = vec![*rn];
                if let Operand::Register(r) = rm {
                    regs.push(*r);
                }
                regs
            }
            // Conditional select instructions read rn and rm
            Instruction::Csel { rn, rm, .. }
            | Instruction::Csinc { rn, rm, .. }
            | Instruction::Csinv { rn, rm, .. }
            | Instruction::Csneg { rn, rm, .. } => vec![*rn, *rm],
            // Unary
            Instruction::Mvn { rm, .. }
            | Instruction::Neg { rm, .. }
            | Instruction::Negs { rm, .. } => vec![*rm],
            // MOVN / MOVZ take no register source
            Instruction::MovN { .. } | Instruction::MovZ { .. } => vec![],
            // MOVK reads rd (preserves the unmodified 16-bit lanes)
            Instruction::MovK { rd, .. } => vec![*rd],
            // Inverted-logical (BIC / BICS / ORN / EON) and flag-setting arith/logical
            Instruction::Bic { rn, rm, .. }
            | Instruction::Bics { rn, rm, .. }
            | Instruction::Orn { rn, rm, .. }
            | Instruction::Eon { rn, rm, .. }
            | Instruction::Adds { rn, rm, .. }
            | Instruction::Subs { rn, rm, .. }
            | Instruction::Ands { rn, rm, .. } => {
                let mut regs = vec![*rn];
                if let Operand::Register(r) = rm {
                    regs.push(*r);
                }
                regs
            }
            // ADC/ADCS/SBC/SBCS read rn and rm (both plain registers).
            Instruction::Adc { rn, rm, .. }
            | Instruction::Adcs { rn, rm, .. }
            | Instruction::Sbc { rn, rm, .. }
            | Instruction::Sbcs { rn, rm, .. } => {
                vec![*rn, *rm]
            }
            // CSET / CSETM have no source registers (read flags, not regs).
            Instruction::Cset { .. } | Instruction::Csetm { .. } => vec![],
            // ROR reads rn and shift (if register)
            Instruction::Ror { rn, shift, .. } => {
                let mut regs = vec![*rn];
                match shift {
                    Operand::Register(r) => regs.push(*r),
                    Operand::ShiftedRegister { reg, .. } => regs.push(*reg),
                    Operand::ExtendedRegister { reg, .. } => regs.push(*reg),
                    Operand::Immediate(_) => {}
                }
                regs
            }
            // Single-source bit-manipulation: rn is the only source.
            Instruction::Clz { rn, .. }
            | Instruction::Cls { rn, .. }
            | Instruction::Rbit { rn, .. }
            | Instruction::Rev { rn, .. }
            | Instruction::Rev32 { rn, .. }
            | Instruction::Rev16 { rn, .. }
            | Instruction::Sxtb { rn, .. }
            | Instruction::Sxth { rn, .. }
            | Instruction::Sxtw { rn, .. }
            | Instruction::Uxtb { rn, .. }
            | Instruction::Uxth { rn, .. } => vec![*rn],
            // Bit-field extracts: only `rn` is read.
            Instruction::Ubfx { rn, .. }
            | Instruction::Sbfx { rn, .. }
            | Instruction::Ubfiz { rn, .. }
            | Instruction::Sbfiz { rn, .. } => vec![*rn],
            // BFI / BFXIL preserve unmodified bits of `rd`, so they also read `rd`.
            Instruction::Bfi { rd, rn, .. } | Instruction::Bfxil { rd, rn, .. } => {
                vec![*rd, *rn]
            }

            // Branches: per-variant source-register sets.
            //   B / BCond / Bl: no register operands.
            //   Cbz / Cbnz: read `rn`.
            //   Tbz / Tbnz: read `rt`.
            //   Ret / Br: read `rn` (return address / indirect-branch target).
            Instruction::B { .. } | Instruction::BCond { .. } | Instruction::Bl { .. } => vec![],
            Instruction::Cbz { rn, .. } | Instruction::Cbnz { rn, .. } => vec![*rn],
            Instruction::Tbz { rt, .. } | Instruction::Tbnz { rt, .. } => vec![*rt],
            Instruction::Ret { rn } | Instruction::Br { rn } => vec![*rn],
            // Memory ops read the base register; register-offset / register-
            // extend modes also read the index register. Stores additionally
            // read the data register, but LDR does not (the data register is
            // a destination).
            Instruction::Ldr { addr, .. } | Instruction::Ldrs { addr, .. } => {
                address_source_registers(addr)
            }
            Instruction::Str { rt, addr, .. } => {
                let mut regs = vec![*rt];
                regs.extend(address_source_registers(addr));
                regs
            }
            // LDP reads only the address operand (base/idx); rt1 and rt2 are
            // destinations.
            Instruction::Ldp { addr, .. } => address_source_registers(addr),
            // STP reads rt1, rt2, and the address operand.
            Instruction::Stp { rt1, rt2, addr, .. } => {
                let mut regs = vec![*rt1, *rt2];
                regs.extend(address_source_registers(addr));
                regs
            }
        }
    }
}

/// Helper for `Instruction::source_registers` on memory ops. Returns the
/// registers read by an `AddressOperand`: always the base, plus the index
/// register for Reg/Ext modes.
fn address_source_registers(addr: &AddressOperand) -> Vec<Register> {
    match addr {
        AddressOperand::Imm { base, .. } => vec![*base],
        AddressOperand::Reg { base, idx, .. } | AddressOperand::Ext { base, idx, .. } => {
            vec![*base, *idx]
        }
    }
}

/// Encodability gate for the LDR / LDRS / STR family. Rules per ADR-0007:
/// (a) base register cannot be XZR (the XSP slot rejects the zero register
/// — SP is accepted); (b) `rt` cannot be SP (loads/stores use Xt/Wt
/// slots); XZR is legal — `str xzr, [x0]` zero-stores and `ldr xzr, [x0]`
/// discards the load per ARM ARM C6.2.131 / C6.2.205; (c) writeback
/// `rt == base` is CONSTRAINED UNPREDICTABLE and rejected at the IR
/// level; (d) signed loads only support B/H/W access widths (LDRSX does
/// not exist — LDR handles 64-bit zero-extension); (e) for `Reg` / `Ext`
/// address modes the index register cannot be SP — the Rm field encodes
/// X0..X30 / XZR, not SP (`register_to_dynasm(SP)` returns None); (f)
/// memory `Ext` modes only accept UXTW/SXTW/UXTX/SXTX with shift 0 or the
/// access-size scale shift.
fn is_encodable_ldr_like(rt: Register, addr: &AddressOperand, width: AccessWidth) -> bool {
    if !is_x_or_xzr(rt) {
        return false;
    }
    if !is_xsp(address_base(addr)) {
        return false;
    }
    if is_writeback(addr) && rt == address_base(addr) {
        return false;
    }
    match addr {
        AddressOperand::Reg { idx, .. } => {
            if !is_x_or_xzr(*idx) {
                return false;
            }
        }
        AddressOperand::Ext {
            idx, kind, shift, ..
        } => {
            if !is_x_or_xzr(*idx) {
                return false;
            }
            if !matches!(
                kind,
                ExtendKind::Uxtw | ExtendKind::Sxtw | ExtendKind::Uxtx | ExtendKind::Sxtx
            ) {
                return false;
            }
            let scaled_shift = width.scale_shift();
            if *shift != 0 && *shift != scaled_shift {
                return false;
            }
        }
        AddressOperand::Imm { .. } => {}
    }
    if width == AccessWidth::Extended {
        // The caller decides whether Extended is valid (LDR allows it, but
        // is_encodable_ldr_like is also used for LDRS where it isn't). The
        // Ldrs arm of is_encodable_aarch64 rejects Extended explicitly
        // below; this helper conservatively allows it and the variant arm
        // layers on the narrower rule.
    }
    true
}

/// Encodability gate for the LDP / STP family. See `is_encodable_ldr_like`
/// for the shared base/XZR rules; pair-specific rules layered below.
///
/// Reject paths (codex P2 + claude review #8):
///   * Non-immediate addressing — LDP/STP only accept `[base{, #imm}]`,
///     `[base, #imm]!`, `[base], #imm`. `AddressOperand::Reg` / `Ext`
///     parse cleanly today but the assembler errors at emit time, so
///     drop them at the IR layer for parity with `parse_line`'s gate.
///   * Out-of-range scaled-7-bit signed immediate — the LDP/STP imm7
///     field encodes `-64..=63` scaled by the access width. Offsets
///     outside that range pass IR validation but panic at dynasm.
fn is_encodable_pair(
    rt1: Register,
    rt2: Register,
    addr: &AddressOperand,
    width: AccessWidth,
    signed: bool,
) -> bool {
    if !is_plain_x(rt1) || !is_plain_x(rt2) {
        return false;
    }
    if !is_xsp(address_base(addr)) {
        return false;
    }
    // LDP rejects rt1 == rt2 (UNPREDICTABLE per ARM ARM). STP allows it —
    // stores the same value twice — so this rule fires only for the
    // load-pair caller.
    if signed && width != AccessWidth::Word {
        // LDPSW is the only "signed pair" form; it is always 32→64.
        return false;
    }
    // LDP/STP only have Word and Extended forms at the architecture level
    // (no LDPB/LDPH/STPB/STPH). Byte/Half pair widths construct cleanly
    // but the assembler errors at emit time — reject at the IR gate so
    // parser and search candidates can't smuggle them through.
    if !matches!(width, AccessWidth::Word | AccessWidth::Extended) {
        return false;
    }
    // LDP/STP have no register-offset / register-extend addressing form.
    let imm_offset = match addr {
        AddressOperand::Imm { offset, .. } => *offset,
        AddressOperand::Reg { .. } | AddressOperand::Ext { .. } => return false,
    };
    // Offset must fit the 7-bit signed scaled immediate. Pair access
    // width is the per-register transfer width (4 or 8 bytes).
    let scale = width.bytes() as i64;
    if scale == 0 || imm_offset % scale != 0 {
        return false;
    }
    let scaled = imm_offset / scale;
    if !(-64..=63).contains(&scaled) {
        return false;
    }
    // Writeback `base == rtN` is rejected.
    if is_writeback(addr) {
        let base = address_base(addr);
        if base == rt1 || base == rt2 {
            return false;
        }
    }
    true
}

/// True if the address operand performs writeback (PreIndex / PostIndex).
fn is_writeback(addr: &AddressOperand) -> bool {
    matches!(
        addr,
        AddressOperand::Imm {
            mode: IndexMode::PreIndex,
            ..
        } | AddressOperand::Imm {
            mode: IndexMode::PostIndex,
            ..
        }
    )
}

/// Extract the base register from an `AddressOperand`. All three variants
/// carry one.
fn address_base(addr: &AddressOperand) -> Register {
    match addr {
        AddressOperand::Imm { base, .. }
        | AddressOperand::Reg { base, .. }
        | AddressOperand::Ext { base, .. } => *base,
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::MovReg { rd, rn } => write!(f, "mov {}, {}", rd, rn),
            Instruction::MovRegW { rd, rn } => write!(
                f,
                "mov {}, {}",
                RegisterWidth::W32.register_name(*rd),
                RegisterWidth::W32.register_name(*rn)
            ),
            Instruction::MovImm { rd, imm } => write!(f, "mov {}, #{}", rd, imm),
            Instruction::Add { rd, rn, rm } => write!(f, "add {}, {}, {}", rd, rn, rm),
            Instruction::AddW { rd, rn, rm } => write!(
                f,
                "add {}, {}, {}",
                RegisterWidth::W32.register_name(*rd),
                RegisterWidth::W32.register_name(*rn),
                rm.display_with_width(RegisterWidth::W32)
            ),
            Instruction::Sub { rd, rn, rm } => write!(f, "sub {}, {}, {}", rd, rn, rm),
            Instruction::SubW { rd, rn, rm } => write!(
                f,
                "sub {}, {}, {}",
                RegisterWidth::W32.register_name(*rd),
                RegisterWidth::W32.register_name(*rn),
                rm.display_with_width(RegisterWidth::W32)
            ),
            Instruction::And { rd, rn, rm, width } => write!(
                f,
                "and {}, {}, {}",
                width.register_name(*rd),
                width.register_name(*rn),
                rm
            ),
            Instruction::Orr { rd, rn, rm, width } => write!(
                f,
                "orr {}, {}, {}",
                width.register_name(*rd),
                width.register_name(*rn),
                rm
            ),
            Instruction::Eor { rd, rn, rm, width } => write!(
                f,
                "eor {}, {}, {}",
                width.register_name(*rd),
                width.register_name(*rn),
                rm
            ),
            Instruction::Lsl { rd, rn, shift } => write!(f, "lsl {}, {}, {}", rd, rn, shift),
            Instruction::Lsr { rd, rn, shift } => write!(f, "lsr {}, {}, {}", rd, rn, shift),
            Instruction::Asr { rd, rn, shift } => write!(f, "asr {}, {}, {}", rd, rn, shift),
            Instruction::Mul { rd, rn, rm } => write!(f, "mul {}, {}, {}", rd, rn, rm),
            Instruction::Sdiv { rd, rn, rm } => write!(f, "sdiv {}, {}, {}", rd, rn, rm),
            Instruction::Udiv { rd, rn, rm } => write!(f, "udiv {}, {}, {}", rd, rn, rm),
            Instruction::Madd { rd, rn, rm, ra } => {
                write!(f, "madd {}, {}, {}, {}", rd, rn, rm, ra)
            }
            Instruction::Msub { rd, rn, rm, ra } => {
                write!(f, "msub {}, {}, {}, {}", rd, rn, rm, ra)
            }
            Instruction::Mneg { rd, rn, rm } => write!(f, "mneg {}, {}, {}", rd, rn, rm),
            Instruction::Smulh { rd, rn, rm } => write!(f, "smulh {}, {}, {}", rd, rn, rm),
            Instruction::Umulh { rd, rn, rm } => write!(f, "umulh {}, {}, {}", rd, rn, rm),
            // Comparison instructions
            Instruction::Cmp { rn, rm } => write!(f, "cmp {}, {}", rn, rm),
            Instruction::Cmn { rn, rm } => write!(f, "cmn {}, {}", rn, rm),
            Instruction::Tst { rn, rm, width } => {
                write!(f, "tst {}, {}", width.register_name(*rn), rm)
            }
            // Conditional select instructions
            Instruction::Csel { rd, rn, rm, cond } => {
                write!(f, "csel {}, {}, {}, {}", rd, rn, rm, cond)
            }
            Instruction::Csinc { rd, rn, rm, cond } => {
                write!(f, "csinc {}, {}, {}, {}", rd, rn, rm, cond)
            }
            Instruction::Csinv { rd, rn, rm, cond } => {
                write!(f, "csinv {}, {}, {}, {}", rd, rn, rm, cond)
            }
            Instruction::Csneg { rd, rn, rm, cond } => {
                write!(f, "csneg {}, {}, {}, {}", rd, rn, rm, cond)
            }
            Instruction::Ccmp { rn, rm, nzcv, cond } => {
                write!(f, "ccmp {}, {}, #{}, {}", rn, rm, nzcv, cond)
            }
            Instruction::Ccmn { rn, rm, nzcv, cond } => {
                write!(f, "ccmn {}, {}, #{}, {}", rn, rm, nzcv, cond)
            }
            Instruction::Mvn { rd, rm } => write!(f, "mvn {}, {}", rd, rm),
            Instruction::Neg { rd, rm } => write!(f, "neg {}, {}", rd, rm),
            Instruction::Negs { rd, rm } => write!(f, "negs {}, {}", rd, rm),
            Instruction::MovN { rd, imm, shift } => {
                if *shift == 0 {
                    write!(f, "movn {}, #{}", rd, imm)
                } else {
                    write!(f, "movn {}, #{}, lsl #{}", rd, imm, shift)
                }
            }
            Instruction::MovZ { rd, imm, shift } => {
                if *shift == 0 {
                    write!(f, "mov {}, #{}", rd, imm)
                } else {
                    write!(f, "movz {}, #{}, lsl #{}", rd, imm, shift)
                }
            }
            Instruction::MovK { rd, imm, shift } => {
                if *shift == 0 {
                    write!(f, "movk {}, #{}", rd, imm)
                } else {
                    write!(f, "movk {}, #{}, lsl #{}", rd, imm, shift)
                }
            }
            Instruction::Bic { rd, rn, rm } => write!(f, "bic {}, {}, {}", rd, rn, rm),
            Instruction::Bics { rd, rn, rm } => write!(f, "bics {}, {}, {}", rd, rn, rm),
            Instruction::Orn { rd, rn, rm } => write!(f, "orn {}, {}, {}", rd, rn, rm),
            Instruction::Eon { rd, rn, rm } => write!(f, "eon {}, {}, {}", rd, rn, rm),
            Instruction::Adds { rd, rn, rm } => write!(f, "adds {}, {}, {}", rd, rn, rm),
            Instruction::Subs { rd, rn, rm } => write!(f, "subs {}, {}, {}", rd, rn, rm),
            Instruction::Adc { rd, rn, rm } => write!(f, "adc {}, {}, {}", rd, rn, rm),
            Instruction::Adcs { rd, rn, rm } => write!(f, "adcs {}, {}, {}", rd, rn, rm),
            Instruction::Sbc { rd, rn, rm } => write!(f, "sbc {}, {}, {}", rd, rn, rm),
            Instruction::Sbcs { rd, rn, rm } => write!(f, "sbcs {}, {}, {}", rd, rn, rm),
            Instruction::Ands { rd, rn, rm, width } => write!(
                f,
                "ands {}, {}, {}",
                width.register_name(*rd),
                width.register_name(*rn),
                rm
            ),
            Instruction::Cset { rd, cond } => write!(f, "cset {}, {}", rd, cond),
            Instruction::Csetm { rd, cond } => write!(f, "csetm {}, {}", rd, cond),
            Instruction::Ror { rd, rn, shift } => write!(f, "ror {}, {}, {}", rd, rn, shift),
            Instruction::Clz { rd, rn } => write!(f, "clz {}, {}", rd, rn),
            Instruction::Cls { rd, rn } => write!(f, "cls {}, {}", rd, rn),
            Instruction::Rbit { rd, rn } => write!(f, "rbit {}, {}", rd, rn),
            Instruction::Rev { rd, rn } => write!(f, "rev {}, {}", rd, rn),
            Instruction::Rev32 { rd, rn } => write!(f, "rev32 {}, {}", rd, rn),
            Instruction::Rev16 { rd, rn } => write!(f, "rev16 {}, {}", rd, rn),
            Instruction::Sxtb { rd, rn } => write!(
                f,
                "sxtb {}, {}",
                RegisterWidth::X64.register_name(*rd),
                RegisterWidth::W32.register_name(*rn)
            ),
            Instruction::Sxth { rd, rn } => write!(
                f,
                "sxth {}, {}",
                RegisterWidth::X64.register_name(*rd),
                RegisterWidth::W32.register_name(*rn)
            ),
            Instruction::Sxtw { rd, rn } => write!(
                f,
                "sxtw {}, {}",
                RegisterWidth::X64.register_name(*rd),
                RegisterWidth::W32.register_name(*rn)
            ),
            Instruction::Uxtb { rd, rn } => write!(
                f,
                "uxtb {}, {}",
                RegisterWidth::W32.register_name(*rd),
                RegisterWidth::W32.register_name(*rn)
            ),
            Instruction::Uxth { rd, rn } => write!(
                f,
                "uxth {}, {}",
                RegisterWidth::W32.register_name(*rd),
                RegisterWidth::W32.register_name(*rn)
            ),
            Instruction::Ubfx { rd, rn, lsb, width } => {
                write!(f, "ubfx {}, {}, #{}, #{}", rd, rn, lsb, width)
            }
            Instruction::Sbfx { rd, rn, lsb, width } => {
                write!(f, "sbfx {}, {}, #{}, #{}", rd, rn, lsb, width)
            }
            Instruction::Bfi { rd, rn, lsb, width } => {
                write!(f, "bfi {}, {}, #{}, #{}", rd, rn, lsb, width)
            }
            Instruction::Bfxil { rd, rn, lsb, width } => {
                write!(f, "bfxil {}, {}, #{}, #{}", rd, rn, lsb, width)
            }
            Instruction::Ubfiz { rd, rn, lsb, width } => {
                write!(f, "ubfiz {}, {}, #{}, #{}", rd, rn, lsb, width)
            }
            Instruction::Sbfiz { rd, rn, lsb, width } => {
                write!(f, "sbfiz {}, {}, #{}, #{}", rd, rn, lsb, width)
            }

            Instruction::B { target } => write!(f, "b {}", target),
            Instruction::BCond { target, cond } => write!(f, "b.{} {}", cond, target),
            Instruction::Ret { rn } => write!(f, "ret {}", rn),
            Instruction::Cbz { rn, target } => write!(f, "cbz {}, {}", rn, target),
            Instruction::Cbnz { rn, target } => write!(f, "cbnz {}, {}", rn, target),
            Instruction::Tbz { rt, bit, target } => {
                write!(f, "tbz {}, #{}, {}", rt, bit, target)
            }
            Instruction::Tbnz { rt, bit, target } => {
                write!(f, "tbnz {}, #{}, {}", rt, bit, target)
            }
            Instruction::Bl { target } => write!(f, "bl {}", target),
            Instruction::Br { rn } => write!(f, "br {}", rn),

            Instruction::Ldr { rt, addr, width } => {
                write!(f, "{} {}, {}", ldr_mnemonic(*width), rt, addr)
            }
            Instruction::Ldrs { rt, addr, width } => {
                write!(f, "{} {}, {}", ldrs_mnemonic(*width), rt, addr)
            }
            Instruction::Str { rt, addr, width } => {
                write!(f, "{} {}, {}", str_mnemonic(*width), rt, addr)
            }
            Instruction::Ldp {
                rt1,
                rt2,
                addr,
                signed,
                ..
            } => write!(
                f,
                "{} {}, {}, {}",
                if *signed { "ldpsw" } else { "ldp" },
                rt1,
                rt2,
                addr
            ),
            Instruction::Stp { rt1, rt2, addr, .. } => write!(f, "stp {}, {}, {}", rt1, rt2, addr),
        }
    }
}

/// Mnemonic for an LDR-family instruction at the given access width.
/// Zero-extending loads only — `ldr` is the X/W form, `ldrb` / `ldrh` are
/// the byte / half forms.
fn ldr_mnemonic(width: AccessWidth) -> &'static str {
    match width {
        AccessWidth::Byte => "ldrb",
        AccessWidth::Half => "ldrh",
        AccessWidth::Word | AccessWidth::Extended => "ldr",
    }
}

/// Mnemonic for the sign-extending load family. Always X-form destination;
/// `Extended` width is meaningless for LDRS (no LDRSX exists — LDR handles
/// the 64-bit zero-extending case).
fn ldrs_mnemonic(width: AccessWidth) -> &'static str {
    match width {
        AccessWidth::Byte => "ldrsb",
        AccessWidth::Half => "ldrsh",
        AccessWidth::Word => "ldrsw",
        AccessWidth::Extended => "ldrsw", // Should be rejected by is_encodable
    }
}

/// Mnemonic for the store family.
fn str_mnemonic(width: AccessWidth) -> &'static str {
    match width {
        AccessWidth::Byte => "strb",
        AccessWidth::Half => "strh",
        AccessWidth::Word | AccessWidth::Extended => "str",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_display() {
        let mov_reg = Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(format!("{}", mov_reg), "mov x0, x1");

        let mov_imm = Instruction::MovImm {
            rd: Register::X2,
            imm: 42,
        };
        assert_eq!(format!("{}", mov_imm), "mov x2, #42");

        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        assert_eq!(format!("{}", add), "add x0, x1, x2");

        let eor = Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
            width: crate::ir::RegisterWidth::X64,
        };
        assert_eq!(format!("{}", eor), "eor x0, x0, x0");
    }

    #[test]
    fn movz_shift0_display_uses_mov_alias() {
        let shift0 = Instruction::MovZ {
            rd: Register::X0,
            imm: 0x1234,
            shift: 0,
        };
        assert_eq!(shift0.to_string(), "mov x0, #4660");

        let shift16 = Instruction::MovZ {
            rd: Register::X0,
            imm: 0x1234,
            shift: 16,
        };
        assert_eq!(shift16.to_string(), "movz x0, #4660, lsl #16");
    }

    #[test]
    fn test_ubfx_display() {
        let ubfx = Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 5,
            width: 10,
        };
        assert_eq!(format!("{}", ubfx), "ubfx x0, x1, #5, #10");
    }

    #[test]
    fn test_destination() {
        let instr = Instruction::Add {
            rd: Register::X5,
            rn: Register::X1,
            rm: Operand::Immediate(10),
        };
        assert_eq!(instr.destination(), Some(Register::X5));

        // Comparison instructions have no destination
        let cmp = Instruction::Cmp {
            rn: Register::X0,
            rm: Operand::Register(Register::X1),
        };
        assert_eq!(cmp.destination(), None);
    }

    #[test]
    fn destinations_returns_single_element_for_one_dest_variant() {
        let add = Instruction::Add {
            rd: Register::X5,
            rn: Register::X1,
            rm: Operand::Immediate(10),
        };
        assert_eq!(add.destinations(), vec![Register::X5]);
    }

    #[test]
    fn destinations_returns_empty_for_zero_dest_variant() {
        let cmp = Instruction::Cmp {
            rn: Register::X0,
            rm: Operand::Register(Register::X1),
        };
        assert!(cmp.destinations().is_empty());
    }

    #[test]
    fn ldr_offset_mode_writes_only_rt() {
        let ldr = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert_eq!(ldr.destinations(), vec![Register::X0]);
    }

    #[test]
    fn ldr_pre_index_writes_both_rt_and_base() {
        let ldr = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Extended,
        };
        assert_eq!(ldr.destinations(), vec![Register::X0, Register::X1]);
    }

    #[test]
    fn ldr_post_index_writes_both_rt_and_base() {
        let ldr = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::PostIndex,
            },
            width: AccessWidth::Extended,
        };
        assert_eq!(ldr.destinations(), vec![Register::X0, Register::X1]);
    }

    #[test]
    fn ldrs_byte_width_displays_as_ldrsb() {
        let ldrs = Instruction::Ldrs {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 4,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Byte,
        };
        assert_eq!(format!("{}", ldrs), "ldrsb x0, [x1, #4]");
    }

    #[test]
    fn ldrs_word_width_displays_as_ldrsw() {
        let ldrs = Instruction::Ldrs {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Word,
        };
        assert_eq!(format!("{}", ldrs), "ldrsw x0, [x1]");
    }

    #[test]
    fn str_offset_mode_has_no_destinations() {
        let st = Instruction::Str {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert!(st.destinations().is_empty());
    }

    #[test]
    fn str_pre_index_writes_only_base_through_writeback() {
        let st = Instruction::Str {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Extended,
        };
        assert_eq!(st.destinations(), vec![Register::X1]);
    }

    #[test]
    fn str_reads_rt_and_base() {
        let st = Instruction::Str {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        let sources = st.source_registers();
        assert!(sources.contains(&Register::X0));
        assert!(sources.contains(&Register::X1));
    }

    #[test]
    fn str_byte_width_displays_as_strb() {
        let st = Instruction::Str {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 4,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Byte,
        };
        assert_eq!(format!("{}", st), "strb x0, [x1, #4]");
    }

    #[test]
    fn ldp_offset_writes_both_rt1_and_rt2() {
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 16,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert_eq!(ldp.destinations(), vec![Register::X0, Register::X1]);
    }

    #[test]
    fn ldp_writeback_adds_base_to_destinations() {
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: -16,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert_eq!(
            ldp.destinations(),
            vec![Register::X0, Register::X1, Register::SP]
        );
    }

    #[test]
    fn ldp_signed_word_width_displays_as_ldpsw() {
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Word,
            signed: true,
        };
        assert_eq!(format!("{}", ldp), "ldpsw x0, x1, [sp]");
    }

    #[test]
    fn ldp_unsigned_extended_displays_as_ldp() {
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 16,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert_eq!(format!("{}", ldp), "ldp x0, x1, [sp, #16]");
    }

    #[test]
    fn str_xzr_is_encodable() {
        // ARM ARM C6.2.205: `str xzr, [x0]` stores a zero doubleword.
        // Previously rejected because is_encodable_ldr_like bailed on
        // `rt == XZR` (codex P2).
        let str_xzr = Instruction::Str {
            rt: Register::XZR,
            addr: AddressOperand::Imm {
                base: Register::X0,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert!(str_xzr.is_encodable_aarch64());
    }

    #[test]
    fn ldr_xzr_is_encodable() {
        // ARM ARM C6.2.131: `ldr xzr, [x0]` is legal — the loaded value
        // is discarded (write to ZR has no architectural effect).
        let ldr_xzr = Instruction::Ldr {
            rt: Register::XZR,
            addr: AddressOperand::Imm {
                base: Register::X0,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert!(ldr_xzr.is_encodable_aarch64());
    }

    #[test]
    fn ldr_with_sp_index_rejected() {
        // SP is encoded via the XSP slot (base only), not the Rm slot.
        // `register_to_dynasm(SP)` returns None, so the assembler errors;
        // reject at IR layer to keep parse/encode in sync (codex P1).
        let ldr = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Reg {
                base: Register::X1,
                idx: Register::SP,
                shift: 0,
            },
            width: AccessWidth::Extended,
        };
        assert!(!ldr.is_encodable_aarch64());
    }

    #[test]
    fn ldr_with_sp_index_via_ext_mode_rejected() {
        use crate::ir::ExtendKind;
        let ldr = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Ext {
                base: Register::X1,
                idx: Register::SP,
                kind: ExtendKind::Uxtx,
                shift: 0,
            },
            width: AccessWidth::Extended,
        };
        assert!(!ldr.is_encodable_aarch64());
    }

    #[test]
    fn memory_register_extend_shift_encodability_matches_access_width() {
        use crate::ir::ExtendKind;

        for (width, shift) in [
            (AccessWidth::Byte, 1),
            (AccessWidth::Half, 2),
            (AccessWidth::Word, 3),
            (AccessWidth::Extended, 4),
        ] {
            let ldr = Instruction::Ldr {
                rt: Register::X0,
                addr: AddressOperand::Ext {
                    base: Register::X1,
                    idx: Register::X2,
                    kind: ExtendKind::Uxtw,
                    shift,
                },
                width,
            };
            assert!(
                !ldr.is_encodable_aarch64(),
                "{width:?} access should reject extend shift {shift}"
            );
        }

        let bad_str = Instruction::Str {
            rt: Register::X0,
            addr: AddressOperand::Ext {
                base: Register::X1,
                idx: Register::X2,
                kind: ExtendKind::Sxtx,
                shift: 2,
            },
            width: AccessWidth::Extended,
        };
        assert!(!bad_str.is_encodable_aarch64());

        let bad_kind = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Ext {
                base: Register::X1,
                idx: Register::X2,
                kind: ExtendKind::Uxtb,
                shift: 0,
            },
            width: AccessWidth::Byte,
        };
        assert!(!bad_kind.is_encodable_aarch64());
    }

    #[test]
    fn memory_register_extend_shift_encodability_allows_scaled_forms() {
        use crate::ir::ExtendKind;

        for (width, kind, shift) in [
            (AccessWidth::Byte, ExtendKind::Uxtw, 0),
            (AccessWidth::Half, ExtendKind::Sxtw, 1),
            (AccessWidth::Word, ExtendKind::Uxtw, 2),
            (AccessWidth::Extended, ExtendKind::Uxtx, 3),
            (AccessWidth::Extended, ExtendKind::Sxtx, 0),
        ] {
            let ldr = Instruction::Ldr {
                rt: Register::X0,
                addr: AddressOperand::Ext {
                    base: Register::X1,
                    idx: Register::X2,
                    kind,
                    shift,
                },
                width,
            };
            assert!(
                ldr.is_encodable_aarch64(),
                "{width:?} access should accept {kind:?} shift {shift}"
            );
        }
    }

    #[test]
    fn pair_byte_width_rejected_at_encodability() {
        // LDP/STP have no Byte form at the architecture level.
        let stp_byte = Instruction::Stp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::X2,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Byte,
        };
        assert!(!stp_byte.is_encodable_aarch64());
    }

    #[test]
    fn pair_half_width_rejected_at_encodability() {
        let ldp_half = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::X2,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Half,
            signed: false,
        };
        assert!(!ldp_half.is_encodable_aarch64());
    }

    #[test]
    fn pair_reg_offset_mode_rejected_at_encodability() {
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Reg {
                base: Register::X2,
                idx: Register::X3,
                shift: 0,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert!(!ldp.is_encodable_aarch64());
        let stp = Instruction::Stp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Reg {
                base: Register::X2,
                idx: Register::X3,
                shift: 3,
            },
            width: AccessWidth::Word,
        };
        assert!(!stp.is_encodable_aarch64());
    }

    #[test]
    fn pair_ext_mode_rejected_at_encodability() {
        use crate::ir::ExtendKind;
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Ext {
                base: Register::X2,
                idx: Register::X3,
                kind: ExtendKind::Uxtw,
                shift: 0,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert!(!ldp.is_encodable_aarch64());
    }

    #[test]
    fn pair_imm_offset_out_of_range_rejected() {
        // 7-bit signed scaled immediate: at width=Extended (×8) the legal
        // range is -512..=504 in steps of 8; 512 is just out of range.
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 512,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert!(!ldp.is_encodable_aarch64());
    }

    #[test]
    fn pair_imm_offset_unscaled_rejected() {
        // Offset must be divisible by access width. 12 % 8 != 0.
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 12,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert!(!ldp.is_encodable_aarch64());
    }

    #[test]
    fn pair_imm_offset_in_range_accepted() {
        // Boundary check: scaled = 63 (max positive) at width=Extended.
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 504,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert!(ldp.is_encodable_aarch64());
    }

    #[test]
    fn stp_offset_has_no_destinations() {
        let stp = Instruction::Stp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 16,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert!(stp.destinations().is_empty());
    }

    #[test]
    fn stp_pre_index_writes_base_through_writeback() {
        let stp = Instruction::Stp {
            rt1: Register::X29,
            rt2: Register::X30,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: -16,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Extended,
        };
        assert_eq!(stp.destinations(), vec![Register::SP]);
    }

    #[test]
    fn stp_reads_both_rt1_and_rt2_plus_base() {
        let stp = Instruction::Stp {
            rt1: Register::X29,
            rt2: Register::X30,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        let sources = stp.source_registers();
        assert!(sources.contains(&Register::X29));
        assert!(sources.contains(&Register::X30));
        assert!(sources.contains(&Register::SP));
    }

    #[test]
    fn stp_pre_index_displays_with_trailing_bang() {
        let stp = Instruction::Stp {
            rt1: Register::X29,
            rt2: Register::X30,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: -16,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Extended,
        };
        assert_eq!(format!("{}", stp), "stp x29, x30, [sp, #-16]!");
    }

    // ---- is_encodable_aarch64 rules for memory ops ----

    #[test]
    fn ldr_rejects_xzr_base() {
        let ldr = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::XZR,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert!(!ldr.is_encodable_aarch64());
    }

    #[test]
    fn ldr_accepts_sp_base() {
        let ldr = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert!(ldr.is_encodable_aarch64());
    }

    #[test]
    fn ldr_rejects_writeback_when_rt_equals_base() {
        let ldr_pre = Instruction::Ldr {
            rt: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Extended,
        };
        assert!(!ldr_pre.is_encodable_aarch64());

        let ldr_post = Instruction::Ldr {
            rt: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::PostIndex,
            },
            width: AccessWidth::Extended,
        };
        assert!(!ldr_post.is_encodable_aarch64());
    }

    #[test]
    fn ldr_offset_mode_allows_rt_equals_base() {
        // Offset mode does not writeback, so rt==base is fine.
        let ldr = Instruction::Ldr {
            rt: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert!(ldr.is_encodable_aarch64());
    }

    #[test]
    fn ldp_rejects_same_pair_registers() {
        let ldp = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert!(!ldp.is_encodable_aarch64());
    }

    #[test]
    fn stp_allows_same_pair_registers() {
        // STP X0, X0, [base] is well-defined (stores X0 twice).
        let stp = Instruction::Stp {
            rt1: Register::X0,
            rt2: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert!(stp.is_encodable_aarch64());
    }

    #[test]
    fn ldp_writeback_rejects_base_equals_either_rt() {
        let ldp = Instruction::Ldp {
            rt1: Register::SP,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: -16,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        assert!(!ldp.is_encodable_aarch64());
    }

    #[test]
    fn ldp_signed_only_valid_at_word_width() {
        let ldpsw_word = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Word,
            signed: true,
        };
        assert!(ldpsw_word.is_encodable_aarch64());

        let ldpsw_extended = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
            signed: true,
        };
        assert!(!ldpsw_extended.is_encodable_aarch64());
    }

    #[test]
    fn ldrs_rejects_extended_width() {
        // No LDRSX exists — extended-width zero-extends via LDR, not LDRS.
        let bad = Instruction::Ldrs {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        assert!(!bad.is_encodable_aarch64());
    }

    #[test]
    fn test_source_registers() {
        let mov_reg = Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(mov_reg.source_registers(), vec![Register::X1]);

        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        assert_eq!(add.source_registers(), vec![Register::X1, Register::X2]);

        let add_imm = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(5),
        };
        assert_eq!(add_imm.source_registers(), vec![Register::X1]);
    }

    #[test]
    fn test_source_registers_shifted_register() {
        // Add/Sub/And/Orr/Eor and Cmp/Cmn/Tst must extract the inner register
        // from a ShiftedRegister rm — otherwise live-out tracking silently
        // drops it.
        let shifted = Operand::ShiftedRegister {
            reg: Register::X3,
            kind: ShiftKind::Lsl,
            amount: 4,
        };
        for instr in [
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: shifted,
                width: crate::ir::RegisterWidth::X64,
            },
        ] {
            assert_eq!(
                instr.source_registers(),
                vec![Register::X1, Register::X3],
                "instr {} must report X1 and X3 as sources",
                instr
            );
        }
        for instr in [
            Instruction::Cmp {
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: shifted,
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: shifted,
                width: crate::ir::RegisterWidth::X64,
            },
        ] {
            assert_eq!(instr.source_registers(), vec![Register::X1, Register::X3]);
        }
    }

    #[test]
    fn test_source_registers_shift_slot_shifted_register_defensive() {
        use crate::ir::ExtendKind;
        // Shift-slot ShiftedRegister and ExtendedRegister operands are not
        // encodable, but source_registers should still be conservative for
        // programmatic IR and report the inner register either way.
        let shifted = Operand::ShiftedRegister {
            reg: Register::X5,
            kind: ShiftKind::Lsl,
            amount: 1,
        };
        let extended = Operand::ExtendedRegister {
            reg: Register::X5,
            kind: ExtendKind::Uxtx,
            shift: 0,
        };
        for shift in [shifted, extended] {
            for instr in [
                Instruction::Lsl {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift,
                },
                Instruction::Lsr {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift,
                },
                Instruction::Asr {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift,
                },
                Instruction::Ror {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift,
                },
            ] {
                assert!(
                    !instr.is_encodable_aarch64(),
                    "instr {} should remain unencodable",
                    instr
                );
                assert_eq!(
                    instr.source_registers(),
                    vec![Register::X1, Register::X5],
                    "instr {} must report the inner shift-slot register",
                    instr
                );
            }
        }
    }

    #[test]
    fn test_is_encodable_mov() {
        // MovReg uses plain register slots: XZR is encodable, SP is not.
        assert!(
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::MovReg {
                rd: Register::XZR,
                rn: Register::XZR,
            }
            .is_encodable_aarch64()
        );
        for instr in [
            Instruction::MovReg {
                rd: Register::SP,
                rn: Register::X1,
            },
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::SP,
            },
            Instruction::MovRegW {
                rd: Register::SP,
                rn: Register::X1,
            },
            Instruction::MovRegW {
                rd: Register::X0,
                rn: Register::SP,
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected in plain move slots: {}",
                instr
            );
        }

        // MovImm in range
        assert!(
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0xFFFF
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::MovImm {
                rd: Register::XZR,
                imm: 1
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::MovImm {
                rd: Register::SP,
                imm: 1
            }
            .is_encodable_aarch64()
        );

        // MovImm out of range
        assert!(
            !Instruction::MovImm {
                rd: Register::X0,
                imm: -1
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::MovImm {
                rd: Register::X0,
                imm: 0x10000
            }
            .is_encodable_aarch64()
        );

        for instr in [
            Instruction::MovN {
                rd: Register::SP,
                imm: 1,
                shift: 0,
            },
            Instruction::MovZ {
                rd: Register::SP,
                imm: 1,
                shift: 16,
            },
            Instruction::MovK {
                rd: Register::SP,
                imm: 1,
                shift: 32,
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected in move-wide destinations: {}",
                instr
            );
        }
        for instr in [
            Instruction::MovN {
                rd: Register::XZR,
                imm: 1,
                shift: 0,
            },
            Instruction::MovZ {
                rd: Register::XZR,
                imm: 1,
                shift: 16,
            },
            Instruction::MovK {
                rd: Register::XZR,
                imm: 1,
                shift: 32,
            },
        ] {
            assert!(
                instr.is_encodable_aarch64(),
                "XZR must remain encodable in move-wide destinations: {}",
                instr
            );
        }
    }

    #[test]
    fn test_is_encodable_shifted_register_arith_rejects_ror() {
        // Add/Sub/Adds/Subs/Cmp/Cmn: LSL/LSR/ASR allowed; ROR rejected.
        let mk_add = |kind| Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind,
                amount: 3,
            },
        };
        assert!(mk_add(ShiftKind::Lsl).is_encodable_aarch64());
        assert!(mk_add(ShiftKind::Lsr).is_encodable_aarch64());
        assert!(mk_add(ShiftKind::Asr).is_encodable_aarch64());
        assert!(!mk_add(ShiftKind::Ror).is_encodable_aarch64());

        let mk_sub = |kind| Instruction::Sub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind,
                amount: 3,
            },
        };
        assert!(mk_sub(ShiftKind::Lsl).is_encodable_aarch64());
        assert!(!mk_sub(ShiftKind::Ror).is_encodable_aarch64());

        let mk_adds = |kind, amount| Instruction::Adds {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind,
                amount,
            },
        };
        assert!(mk_adds(ShiftKind::Lsl, 3).is_encodable_aarch64());
        assert!(mk_adds(ShiftKind::Lsr, 3).is_encodable_aarch64());
        assert!(mk_adds(ShiftKind::Asr, 3).is_encodable_aarch64());
        assert!(!mk_adds(ShiftKind::Ror, 3).is_encodable_aarch64());
        assert!(!mk_adds(ShiftKind::Lsl, 64).is_encodable_aarch64());

        let mk_subs = |kind, amount| Instruction::Subs {
            rd: Register::X3,
            rn: Register::X4,
            rm: Operand::ShiftedRegister {
                reg: Register::X5,
                kind,
                amount,
            },
        };
        assert!(mk_subs(ShiftKind::Lsl, 3).is_encodable_aarch64());
        assert!(mk_subs(ShiftKind::Lsr, 3).is_encodable_aarch64());
        assert!(mk_subs(ShiftKind::Asr, 3).is_encodable_aarch64());
        assert!(!mk_subs(ShiftKind::Ror, 3).is_encodable_aarch64());
        assert!(!mk_subs(ShiftKind::Lsl, 64).is_encodable_aarch64());

        for instr in [
            Instruction::Adds {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::ShiftedRegister {
                    reg: Register::X2,
                    kind: ShiftKind::Lsl,
                    amount: 1,
                },
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::ShiftedRegister {
                    reg: Register::X2,
                    kind: ShiftKind::Lsl,
                    amount: 1,
                },
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::ShiftedRegister {
                    reg: Register::SP,
                    kind: ShiftKind::Lsl,
                    amount: 1,
                },
            },
            Instruction::Subs {
                rd: Register::SP,
                rn: Register::X4,
                rm: Operand::ShiftedRegister {
                    reg: Register::X5,
                    kind: ShiftKind::Lsl,
                    amount: 1,
                },
            },
            Instruction::Subs {
                rd: Register::X3,
                rn: Register::SP,
                rm: Operand::ShiftedRegister {
                    reg: Register::X5,
                    kind: ShiftKind::Lsl,
                    amount: 1,
                },
            },
            Instruction::Subs {
                rd: Register::X3,
                rn: Register::X4,
                rm: Operand::ShiftedRegister {
                    reg: Register::SP,
                    kind: ShiftKind::Lsl,
                    amount: 1,
                },
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected in shifted-register flag-setting arithmetic: {instr}"
            );
        }

        let mk_cmp = |kind| Instruction::Cmp {
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind,
                amount: 3,
            },
        };
        assert!(mk_cmp(ShiftKind::Lsl).is_encodable_aarch64());
        assert!(!mk_cmp(ShiftKind::Ror).is_encodable_aarch64());
    }

    #[test]
    fn test_is_encodable_add_sub_immediate_rejects_xzr_allows_sp() {
        // ADD/SUB immediate Rd/Rn occupy the Xn|SP slot: SP is encodable,
        // XZR is not (it would alias to SP). The predicate must stay in
        // lockstep with the assembler's register_to_dynasm_xsp behaviour so
        // can_assemble() never admits candidates the encoder rejects.
        let add = |rd, rn| Instruction::Add {
            rd,
            rn,
            rm: Operand::Immediate(8),
        };
        let sub = |rd, rn| Instruction::Sub {
            rd,
            rn,
            rm: Operand::Immediate(8),
        };

        // SP as rd and/or rn is encodable.
        assert!(add(Register::SP, Register::SP).is_encodable_aarch64());
        assert!(sub(Register::SP, Register::SP).is_encodable_aarch64());
        assert!(add(Register::X0, Register::SP).is_encodable_aarch64());
        assert!(sub(Register::X0, Register::SP).is_encodable_aarch64());

        // XZR in either slot is rejected for the immediate form.
        assert!(!add(Register::XZR, Register::X0).is_encodable_aarch64());
        assert!(!add(Register::X0, Register::XZR).is_encodable_aarch64());
        assert!(!sub(Register::XZR, Register::X0).is_encodable_aarch64());
        assert!(!sub(Register::X0, Register::XZR).is_encodable_aarch64());

        // Register form with XZR stays encodable (plain Xn slot, 31 = XZR).
        assert!(
            Instruction::Add {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::X1),
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Sub {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::X1),
            }
            .is_encodable_aarch64()
        );
        for instr in [
            Instruction::Add {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
            },
            Instruction::Sub {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected in ADD/SUB register form: {}",
                instr
            );
        }
    }

    #[test]
    fn test_is_encodable_shifted_register_logical_allows_ror() {
        // And/Orr/Eor/Tst accept ROR.
        for kind in [
            ShiftKind::Lsl,
            ShiftKind::Lsr,
            ShiftKind::Asr,
            ShiftKind::Ror,
        ] {
            assert!(
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind,
                        amount: 5
                    },
                    width: crate::ir::RegisterWidth::X64,
                }
                .is_encodable_aarch64(),
                "ORR with {:?} must be encodable",
                kind
            );
            assert!(
                Instruction::Tst {
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind,
                        amount: 5
                    },
                    width: crate::ir::RegisterWidth::X64,
                }
                .is_encodable_aarch64(),
                "TST with {:?} must be encodable",
                kind
            );
        }
    }

    #[test]
    fn test_is_encodable_shifted_register_rejects_sp() {
        // Shifted-register form forbids SP for any operand (rd, rn, rm).
        let lsl = ShiftKind::Lsl;
        let make = |rd, rn, reg| Instruction::Add {
            rd,
            rn,
            rm: Operand::ShiftedRegister {
                reg,
                kind: lsl,
                amount: 1,
            },
        };
        assert!(!make(Register::SP, Register::X1, Register::X2).is_encodable_aarch64());
        assert!(!make(Register::X0, Register::SP, Register::X2).is_encodable_aarch64());
        assert!(!make(Register::X0, Register::X1, Register::SP).is_encodable_aarch64());
        // Valid: no SP anywhere
        assert!(make(Register::X0, Register::X1, Register::X2).is_encodable_aarch64());
    }

    #[test]
    fn test_is_encodable_shifted_register_amount_bounds() {
        let mk = |amount| Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: ShiftKind::Lsl,
                amount,
            },
        };
        assert!(mk(0).is_encodable_aarch64());
        assert!(mk(63).is_encodable_aarch64());
        assert!(!mk(64).is_encodable_aarch64());
        assert!(!mk(255).is_encodable_aarch64());
    }

    #[test]
    fn test_is_encodable_shift_slot_rejects_shifted_register() {
        // Lsl/Lsr/Asr/Ror's shift field cannot be a ShiftedRegister.
        let nonsense = Operand::ShiftedRegister {
            reg: Register::X2,
            kind: ShiftKind::Lsl,
            amount: 1,
        };
        for instr in [
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: nonsense,
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: nonsense,
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: nonsense,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: nonsense,
            },
        ] {
            assert!(!instr.is_encodable_aarch64());
        }
    }

    #[test]
    fn test_is_encodable_add_sub() {
        // Register operand is always valid
        assert!(
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2)
            }
            .is_encodable_aarch64()
        );

        // Valid immediate range (0-4095)
        assert!(
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0)
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0xFFF)
            }
            .is_encodable_aarch64()
        );

        // Invalid: negative immediate
        assert!(
            !Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(-1)
            }
            .is_encodable_aarch64()
        );

        // Invalid: immediate too large
        assert!(
            !Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0x1000)
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_is_encodable_logical() {
        // Register operand is valid
        assert!(
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );

        // Encodable bitmask immediates are accepted (issue #65).
        assert!(
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0xFF),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );

        // Non-bitmask immediates are still rejected.
        assert!(
            !Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_is_encodable_logical_and_compare_register_classes() {
        for instr in [
            Instruction::And {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
                width: RegisterWidth::X64,
            },
            Instruction::Tst {
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
                width: RegisterWidth::X64,
            },
            Instruction::Cmp {
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
            },
            Instruction::Cmn {
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected in plain logical/compare register slots: {}",
                instr
            );
        }

        for instr in [
            Instruction::Cmp {
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
            Instruction::Cmn {
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "CMP/CMN immediate rn uses XSP and must reject XZR: {}",
                instr
            );
        }

        for instr in [
            Instruction::And {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
                width: RegisterWidth::X64,
            },
            Instruction::Orr {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
                width: RegisterWidth::X64,
            },
            Instruction::Eor {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
                width: RegisterWidth::X64,
            },
            Instruction::Tst {
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
                width: RegisterWidth::X64,
            },
            Instruction::Cmp {
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
            },
            Instruction::Cmn {
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
            },
            Instruction::Cmp {
                rn: Register::SP,
                rm: Operand::Immediate(1),
            },
            Instruction::Cmn {
                rn: Register::SP,
                rm: Operand::Immediate(1),
            },
        ] {
            assert!(
                instr.is_encodable_aarch64(),
                "valid logical/compare register class must remain encodable: {}",
                instr
            );
        }
    }

    #[test]
    fn test_is_encodable_bit_manip_rejects_sp() {
        // Xn class — SP must be rejected on both rd and rn. XZR is valid.
        for instr in [
            Instruction::Clz {
                rd: Register::SP,
                rn: Register::X1,
            },
            Instruction::Cls {
                rd: Register::X0,
                rn: Register::SP,
            },
            Instruction::Rbit {
                rd: Register::SP,
                rn: Register::SP,
            },
            Instruction::Rev {
                rd: Register::SP,
                rn: Register::X1,
            },
            Instruction::Rev32 {
                rd: Register::X0,
                rn: Register::SP,
            },
            Instruction::Rev16 {
                rd: Register::SP,
                rn: Register::X1,
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected: {}",
                instr
            );
        }

        // XZR is part of the Xn class and stays encodable.
        assert!(
            Instruction::Clz {
                rd: Register::XZR,
                rn: Register::X1
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Rev {
                rd: Register::X0,
                rn: Register::XZR
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_is_encodable_multiply_family_rejects_sp_all_slots() {
        for instr in [
            Instruction::Mul {
                rd: Register::SP,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Mul {
                rd: Register::X0,
                rn: Register::SP,
                rm: Register::X2,
            },
            Instruction::Mul {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::SP,
            },
            Instruction::Sdiv {
                rd: Register::SP,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Sdiv {
                rd: Register::X0,
                rn: Register::SP,
                rm: Register::X2,
            },
            Instruction::Sdiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::SP,
            },
            Instruction::Udiv {
                rd: Register::SP,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Udiv {
                rd: Register::X0,
                rn: Register::SP,
                rm: Register::X2,
            },
            Instruction::Udiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::SP,
            },
            Instruction::Madd {
                rd: Register::SP,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Madd {
                rd: Register::X0,
                rn: Register::SP,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Madd {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::SP,
                ra: Register::X3,
            },
            Instruction::Madd {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::SP,
            },
            Instruction::Msub {
                rd: Register::SP,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Msub {
                rd: Register::X0,
                rn: Register::SP,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Msub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::SP,
                ra: Register::X3,
            },
            Instruction::Msub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::SP,
            },
            Instruction::Mneg {
                rd: Register::SP,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Mneg {
                rd: Register::X0,
                rn: Register::SP,
                rm: Register::X2,
            },
            Instruction::Mneg {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::SP,
            },
            Instruction::Smulh {
                rd: Register::SP,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Smulh {
                rd: Register::X0,
                rn: Register::SP,
                rm: Register::X2,
            },
            Instruction::Smulh {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::SP,
            },
            Instruction::Umulh {
                rd: Register::SP,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Umulh {
                rd: Register::X0,
                rn: Register::SP,
                rm: Register::X2,
            },
            Instruction::Umulh {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::SP,
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected: {}",
                instr
            );
        }

        for instr in [
            Instruction::Mul {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Register::XZR,
            },
            Instruction::Sdiv {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Register::XZR,
            },
            Instruction::Udiv {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Register::XZR,
            },
            Instruction::Madd {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Register::XZR,
                ra: Register::XZR,
            },
            Instruction::Msub {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Register::XZR,
                ra: Register::XZR,
            },
            Instruction::Mneg {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Register::XZR,
            },
            Instruction::Smulh {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Register::XZR,
            },
            Instruction::Umulh {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Register::XZR,
            },
        ] {
            assert!(
                instr.is_encodable_aarch64(),
                "XZR must remain encodable: {}",
                instr
            );
        }
    }

    #[test]
    fn test_is_encodable_flag_and_inverted_logical_register_classes() {
        for instr in [
            Instruction::Adds {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
            },
            Instruction::Subs {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
            },
            Instruction::Ands {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
                width: RegisterWidth::X64,
            },
            Instruction::Bic {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Bics {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Orn {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::SP),
            },
            Instruction::Eon {
                rd: Register::SP,
                rn: Register::SP,
                rm: Operand::Register(Register::SP),
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected in plain flag/logical register slots: {}",
                instr
            );
        }

        for instr in [
            Instruction::Adds {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "ADDS/SUBS immediate must preserve rd plain-X and rn XSP classes: {}",
                instr
            );
        }

        for instr in [
            Instruction::Adds {
                rd: Register::XZR,
                rn: Register::SP,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::XZR,
                rn: Register::SP,
                rm: Operand::Immediate(1),
            },
            Instruction::Ands {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
                width: RegisterWidth::X64,
            },
            Instruction::Bic {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
            },
            Instruction::Bics {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
            },
            Instruction::Orn {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
            },
            Instruction::Eon {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Operand::Register(Register::XZR),
            },
        ] {
            assert!(
                instr.is_encodable_aarch64(),
                "XZR must remain encodable in plain flag/logical register slots: {}",
                instr
            );
        }
    }

    #[test]
    fn test_is_encodable_register_only_forms_reject_sp() {
        for instr in [
            Instruction::Csel {
                rd: Register::SP,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::EQ,
            },
            Instruction::Csinc {
                rd: Register::X0,
                rn: Register::SP,
                rm: Register::X2,
                cond: Condition::EQ,
            },
            Instruction::Csinv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::SP,
                cond: Condition::EQ,
            },
            Instruction::Csneg {
                rd: Register::SP,
                rn: Register::SP,
                rm: Register::SP,
                cond: Condition::EQ,
            },
            Instruction::Mvn {
                rd: Register::SP,
                rm: Register::X1,
            },
            Instruction::Mvn {
                rd: Register::X0,
                rm: Register::SP,
            },
            Instruction::Neg {
                rd: Register::SP,
                rm: Register::X1,
            },
            Instruction::Neg {
                rd: Register::X0,
                rm: Register::SP,
            },
            Instruction::Negs {
                rd: Register::SP,
                rm: Register::X1,
            },
            Instruction::Negs {
                rd: Register::X0,
                rm: Register::SP,
            },
            Instruction::Cset {
                rd: Register::SP,
                cond: Condition::EQ,
            },
            Instruction::Csetm {
                rd: Register::SP,
                cond: Condition::EQ,
            },
            Instruction::Lsl {
                rd: Register::SP,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::SP,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::SP),
            },
            Instruction::Ror {
                rd: Register::SP,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::SP,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::SP),
            },
            Instruction::Ret { rn: Register::SP },
            Instruction::Br { rn: Register::SP },
            Instruction::Cbz {
                rn: Register::SP,
                target: LabelId(4),
            },
            Instruction::Cbnz {
                rn: Register::SP,
                target: LabelId(4),
            },
            Instruction::Tbz {
                rt: Register::SP,
                bit: 3,
                target: LabelId(4),
            },
            Instruction::Tbnz {
                rt: Register::SP,
                bit: 3,
                target: LabelId(4),
            },
        ] {
            assert!(
                !instr.is_encodable_aarch64(),
                "SP must be rejected in plain register-only form: {}",
                instr
            );
        }

        for instr in [
            Instruction::Csel {
                rd: Register::XZR,
                rn: Register::XZR,
                rm: Register::XZR,
                cond: Condition::EQ,
            },
            Instruction::Mvn {
                rd: Register::XZR,
                rm: Register::XZR,
            },
            Instruction::Neg {
                rd: Register::XZR,
                rm: Register::XZR,
            },
            Instruction::Negs {
                rd: Register::XZR,
                rm: Register::XZR,
            },
            Instruction::Cset {
                rd: Register::XZR,
                cond: Condition::EQ,
            },
            Instruction::Csetm {
                rd: Register::XZR,
                cond: Condition::EQ,
            },
            Instruction::Lsl {
                rd: Register::XZR,
                rn: Register::XZR,
                shift: Operand::Register(Register::XZR),
            },
            Instruction::Ror {
                rd: Register::XZR,
                rn: Register::XZR,
                shift: Operand::Immediate(1),
            },
            Instruction::Ret { rn: Register::XZR },
            Instruction::Br { rn: Register::XZR },
            Instruction::Cbz {
                rn: Register::XZR,
                target: LabelId(4),
            },
            Instruction::Cbnz {
                rn: Register::XZR,
                target: LabelId(4),
            },
            Instruction::Tbz {
                rt: Register::XZR,
                bit: 3,
                target: LabelId(4),
            },
            Instruction::Tbnz {
                rt: Register::XZR,
                bit: 3,
                target: LabelId(4),
            },
        ] {
            assert!(
                instr.is_encodable_aarch64(),
                "XZR must remain encodable in plain register-only form: {}",
                instr
            );
        }
    }

    #[test]
    fn test_is_encodable_bitfield() {
        // Valid combinations.
        for (lsb, width) in [(0u8, 1u8), (0, 64), (5, 10), (32, 16), (63, 1)] {
            let instr = Instruction::Ubfx {
                rd: Register::X0,
                rn: Register::X1,
                lsb,
                width,
            };
            assert!(
                instr.is_encodable_aarch64(),
                "valid (lsb={}, width={}) must be encodable",
                lsb,
                width
            );
        }

        // SP rejection in rd.
        assert!(
            !Instruction::Ubfx {
                rd: Register::SP,
                rn: Register::X1,
                lsb: 0,
                width: 8,
            }
            .is_encodable_aarch64()
        );

        // SP rejection in rn.
        assert!(
            !Instruction::Sbfx {
                rd: Register::X0,
                rn: Register::SP,
                lsb: 0,
                width: 8,
            }
            .is_encodable_aarch64()
        );

        // XZR is OK.
        assert!(
            Instruction::Ubfx {
                rd: Register::XZR,
                rn: Register::X1,
                lsb: 0,
                width: 8,
            }
            .is_encodable_aarch64()
        );

        // width=0 rejected.
        assert!(
            !Instruction::Bfi {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 0,
                width: 0,
            }
            .is_encodable_aarch64()
        );

        // lsb+width > 64 rejected.
        assert!(
            !Instruction::Bfxil {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 60,
                width: 10,
            }
            .is_encodable_aarch64()
        );

        // The (lsb=63, width=1) boundary stays valid: lsb<=63 and lsb+width==64.
        assert!(
            Instruction::Ubfiz {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 63,
                width: 1,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_is_encodable_shift() {
        // Register shift is valid
        assert!(
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2)
            }
            .is_encodable_aarch64()
        );

        // Valid shift range (0-63)
        assert!(
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(0)
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(63)
            }
            .is_encodable_aarch64()
        );

        // Invalid: negative shift
        assert!(
            !Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(-1)
            }
            .is_encodable_aarch64()
        );

        // Invalid: shift too large
        assert!(
            !Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(64)
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_mvn_display_and_helpers() {
        let mvn = Instruction::Mvn {
            rd: Register::X0,
            rm: Register::X1,
        };
        assert_eq!(format!("{}", mvn), "mvn x0, x1");
        assert_eq!(mvn.destination(), Some(Register::X0));
        assert_eq!(mvn.source_registers(), vec![Register::X1]);
        assert!(!mvn.modifies_flags());
        assert!(!mvn.reads_flags());
        assert!(mvn.is_encodable_aarch64());
    }

    #[test]
    fn test_is_encodable_cmp() {
        // Register operand is valid
        assert!(
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1)
            }
            .is_encodable_aarch64()
        );

        // Valid immediate range
        assert!(
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Immediate(0xFFF)
            }
            .is_encodable_aarch64()
        );

        // Invalid immediate
        assert!(
            !Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Immediate(-1)
            }
            .is_encodable_aarch64()
        );

        // TST: register form and encodable bitmask immediates both accepted.
        assert!(
            Instruction::Tst {
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Tst {
                rn: Register::X0,
                rm: Operand::Immediate(1),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
        // Non-bitmask immediates are rejected.
        assert!(
            !Instruction::Tst {
                rn: Register::X0,
                rm: Operand::Immediate(5),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn all_instruction_variants_cover_helpers_and_display() {
        let cases = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(2),
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Mul {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Sdiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Udiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Madd {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Msub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Mneg {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Smulh {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Umulh {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Csel {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::EQ,
            },
            Instruction::Csinc {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::NE,
            },
            Instruction::Csinv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::LT,
            },
            Instruction::Csneg {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::GT,
            },
            Instruction::Mvn {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Neg {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Negs {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 1,
                shift: 16,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 1,
                shift: 32,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 1,
                shift: 48,
            },
            Instruction::Bic {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Bics {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Orn {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Eon {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::GE,
            },
            Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::LE,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(4),
            },
        ];

        for instr in cases {
            let rendered = format!("{}", instr);
            assert!(!rendered.is_empty());
            let _ = instr.destination();
            let _ = instr.source_registers();
            let _ = instr.modifies_flags();
            let _ = instr.reads_flags();
            let _ = instr.is_encodable_aarch64();
        }

        let cmp = Instruction::Cmp {
            rn: Register::X1,
            rm: Operand::Immediate(1),
        };
        assert_eq!(cmp.to_string(), "cmp x1, #1");
        assert_eq!(cmp.destination(), None);
        assert_eq!(cmp.source_registers(), vec![Register::X1]);
        assert!(cmp.modifies_flags());
        assert!(!cmp.reads_flags());

        let csel = Instruction::Csel {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::EQ,
        };
        assert_eq!(csel.to_string(), "csel x0, x1, x2, eq");
        assert_eq!(csel.destination(), Some(Register::X0));
        assert_eq!(csel.source_registers(), vec![Register::X1, Register::X2]);
        assert!(!csel.modifies_flags());
        assert!(csel.reads_flags());

        let adds = Instruction::Adds {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        assert_eq!(adds.to_string(), "adds x0, x1, x2");
        assert_eq!(adds.destination(), Some(Register::X0));
        assert_eq!(adds.source_registers(), vec![Register::X1, Register::X2]);
        assert!(adds.modifies_flags());
        assert!(!adds.reads_flags());

        let madd = Instruction::Madd {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X3,
        };
        assert_eq!(madd.to_string(), "madd x0, x1, x2, x3");
        assert_eq!(madd.destination(), Some(Register::X0));
        assert_eq!(
            madd.source_registers(),
            vec![Register::X1, Register::X2, Register::X3]
        );
        assert!(!madd.modifies_flags());
        assert!(!madd.reads_flags());
        assert!(madd.is_encodable_aarch64());

        let msub = Instruction::Msub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X3,
        };
        assert_eq!(msub.to_string(), "msub x0, x1, x2, x3");
        assert_eq!(msub.destination(), Some(Register::X0));
        assert_eq!(
            msub.source_registers(),
            vec![Register::X1, Register::X2, Register::X3]
        );
        assert!(!msub.modifies_flags());
        assert!(!msub.reads_flags());
        assert!(msub.is_encodable_aarch64());

        let mneg = Instruction::Mneg {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        assert_eq!(mneg.to_string(), "mneg x0, x1, x2");
        assert_eq!(mneg.destination(), Some(Register::X0));
        assert_eq!(mneg.source_registers(), vec![Register::X1, Register::X2]);
        assert!(!mneg.modifies_flags());
        assert!(!mneg.reads_flags());
        assert!(mneg.is_encodable_aarch64());

        let smulh = Instruction::Smulh {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        assert_eq!(smulh.to_string(), "smulh x0, x1, x2");
        assert_eq!(smulh.destination(), Some(Register::X0));
        assert_eq!(smulh.source_registers(), vec![Register::X1, Register::X2]);
        assert!(!smulh.modifies_flags());
        assert!(!smulh.reads_flags());
        assert!(smulh.is_encodable_aarch64());

        let umulh = Instruction::Umulh {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        assert_eq!(umulh.to_string(), "umulh x0, x1, x2");
        assert_eq!(umulh.destination(), Some(Register::X0));
        assert_eq!(umulh.source_registers(), vec![Register::X1, Register::X2]);
        assert!(!umulh.modifies_flags());
        assert!(!umulh.reads_flags());
        assert!(umulh.is_encodable_aarch64());
    }

    #[test]
    fn test_extended_register_arith_encodability() {
        use crate::ir::ExtendKind;
        // ADD x0, x1, x2, UXTB #2 — within shift range, not SP, accepted.
        let ok = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ExtendedRegister {
                reg: Register::X2,
                kind: ExtendKind::Uxtb,
                shift: 2,
            },
        };
        assert!(ok.is_encodable_aarch64());

        // Shift = 4 is the boundary; still encodable.
        let max_shift = Instruction::Sub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ExtendedRegister {
                reg: Register::X2,
                kind: ExtendKind::Sxtw,
                shift: 4,
            },
        };
        assert!(max_shift.is_encodable_aarch64());

        // Shift = 5 is out of range and must be rejected.
        let bad_shift = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ExtendedRegister {
                reg: Register::X2,
                kind: ExtendKind::Uxtb,
                shift: 5,
            },
        };
        assert!(!bad_shift.is_encodable_aarch64());

        // rd/rn use the Xn|SP class: SP is valid, XZR would alias to SP.
        assert!(
            Instruction::Add {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::ExtendedRegister {
                    reg: Register::X2,
                    kind: ExtendKind::Uxtb,
                    shift: 0,
                },
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::ExtendedRegister {
                    reg: Register::X2,
                    kind: ExtendKind::Uxtb,
                    shift: 0,
                },
            }
            .is_encodable_aarch64()
        );
        for victim in [Register::XZR] {
            assert!(
                !Instruction::Add {
                    rd: victim,
                    rn: Register::X1,
                    rm: Operand::ExtendedRegister {
                        reg: Register::X2,
                        kind: ExtendKind::Uxtb,
                        shift: 0,
                    },
                }
                .is_encodable_aarch64()
            );
            assert!(
                !Instruction::Add {
                    rd: Register::X0,
                    rn: victim,
                    rm: Operand::ExtendedRegister {
                        reg: Register::X2,
                        kind: ExtendKind::Uxtb,
                        shift: 0,
                    },
                }
                .is_encodable_aarch64()
            );
        }
        // Inner-reg slot: SP rejected, XZR allowed.
        assert!(
            !Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::ExtendedRegister {
                    reg: Register::SP,
                    kind: ExtendKind::Uxtb,
                    shift: 0,
                },
            }
            .is_encodable_aarch64()
        );
        assert!(
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::ExtendedRegister {
                    reg: Register::XZR,
                    kind: ExtendKind::Uxtb,
                    shift: 0,
                },
            }
            .is_encodable_aarch64()
        );

        // CMP/CMN: rn is allowed to be non-SP; rd doesn't apply.
        let cmp_ok = Instruction::Cmp {
            rn: Register::X1,
            rm: Operand::ExtendedRegister {
                reg: Register::X2,
                kind: ExtendKind::Sxtb,
                shift: 1,
            },
        };
        assert!(cmp_ok.is_encodable_aarch64());
        let cmn_ok = Instruction::Cmn {
            rn: Register::X1,
            rm: Operand::ExtendedRegister {
                reg: Register::X2,
                kind: ExtendKind::Uxth,
                shift: 3,
            },
        };
        assert!(cmn_ok.is_encodable_aarch64());
    }

    #[test]
    fn test_extended_register_logical_rejected() {
        use crate::ir::ExtendKind;
        // AND/ORR/EOR/TST/Adds/Subs/Ands/Ror: ExtendedRegister rejected.
        let er = Operand::ExtendedRegister {
            reg: Register::X2,
            kind: ExtendKind::Uxtb,
            shift: 0,
        };
        assert!(
            !Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: er,
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: er,
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: er,
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Tst {
                rn: Register::X1,
                rm: er,
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_sxtw_metadata_and_encodability() {
        let ok = Instruction::Sxtw {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(ok.to_string(), "sxtw x0, w1");
        assert_eq!(ok.destination(), Some(Register::X0));
        assert_eq!(ok.source_registers(), vec![Register::X1]);
        assert!(!ok.modifies_flags());
        assert!(ok.is_encodable_aarch64());
        assert!(
            !Instruction::Sxtw {
                rd: Register::SP,
                rn: Register::X1,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Sxtw {
                rd: Register::X0,
                rn: Register::SP,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_sxth_metadata_and_encodability() {
        let ok = Instruction::Sxth {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(ok.to_string(), "sxth x0, w1");
        assert_eq!(ok.destination(), Some(Register::X0));
        assert_eq!(ok.source_registers(), vec![Register::X1]);
        assert!(!ok.modifies_flags());
        assert!(ok.is_encodable_aarch64());
        assert!(
            !Instruction::Sxth {
                rd: Register::SP,
                rn: Register::X1,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Sxth {
                rd: Register::X0,
                rn: Register::SP,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_uxth_metadata_and_encodability() {
        let ok = Instruction::Uxth {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(ok.to_string(), "uxth w0, w1");
        assert_eq!(ok.destination(), Some(Register::X0));
        assert_eq!(ok.source_registers(), vec![Register::X1]);
        assert!(!ok.modifies_flags());
        assert!(ok.is_encodable_aarch64());
        assert!(
            !Instruction::Uxth {
                rd: Register::SP,
                rn: Register::X1,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Uxth {
                rd: Register::X0,
                rn: Register::SP,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_sxtb_metadata_and_encodability() {
        // SXTB: register-only, single source, encodable on X-register pairs
        // except SP. Issue #60.
        let ok = Instruction::Sxtb {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(ok.to_string(), "sxtb x0, w1");
        assert_eq!(ok.destination(), Some(Register::X0));
        assert_eq!(ok.source_registers(), vec![Register::X1]);
        assert!(!ok.modifies_flags());
        assert!(ok.is_encodable_aarch64());
        assert!(
            !Instruction::Sxtb {
                rd: Register::SP,
                rn: Register::X1,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Sxtb {
                rd: Register::X0,
                rn: Register::SP,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_uxtb_metadata_and_encodability() {
        // UXTB: register-only, single source, no flag effects, encodable on
        // any X-register pair except SP. Issue #60.
        let ok = Instruction::Uxtb {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(ok.to_string(), "uxtb w0, w1");
        assert_eq!(ok.destination(), Some(Register::X0));
        assert_eq!(ok.source_registers(), vec![Register::X1]);
        assert!(!ok.modifies_flags());
        assert!(ok.is_encodable_aarch64());

        // SP rejected as rd.
        assert!(
            !Instruction::Uxtb {
                rd: Register::SP,
                rn: Register::X1,
            }
            .is_encodable_aarch64()
        );
        // SP rejected as rn.
        assert!(
            !Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::SP,
            }
            .is_encodable_aarch64()
        );
        // XZR remains encodable (per the existing single-source policy).
        assert!(
            Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::XZR,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_b_unconditional_is_terminator() {
        let b = Instruction::B {
            target: LabelId(0x1000),
        };
        assert!(b.is_terminator());
    }

    #[test]
    fn test_b_cond_is_terminator() {
        let b = Instruction::BCond {
            target: LabelId(0x1000),
            cond: Condition::EQ,
        };
        assert!(b.is_terminator());
    }

    #[test]
    fn test_ret_is_terminator() {
        let r = Instruction::Ret { rn: Register::X30 };
        assert!(r.is_terminator());
    }

    #[test]
    fn test_cbz_cbnz_are_terminators() {
        assert!(
            Instruction::Cbz {
                rn: Register::X0,
                target: LabelId(0x1000),
            }
            .is_terminator()
        );
        assert!(
            Instruction::Cbnz {
                rn: Register::X0,
                target: LabelId(0x1000),
            }
            .is_terminator()
        );
    }

    #[test]
    fn test_tbz_tbnz_are_terminators() {
        assert!(
            Instruction::Tbz {
                rt: Register::X0,
                bit: 3,
                target: LabelId(0x1000),
            }
            .is_terminator()
        );
        assert!(
            Instruction::Tbnz {
                rt: Register::X0,
                bit: 3,
                target: LabelId(0x1000),
            }
            .is_terminator()
        );
    }

    #[test]
    fn test_bl_is_terminator() {
        let b = Instruction::Bl {
            target: LabelId(0x1000),
        };
        assert!(b.is_terminator());
    }

    #[test]
    fn test_br_is_terminator() {
        let b = Instruction::Br { rn: Register::X16 };
        assert!(b.is_terminator());
    }

    #[test]
    fn test_non_branch_instructions_are_not_terminators() {
        let mov = Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        };
        assert!(!mov.is_terminator());

        let cmp = Instruction::Cmp {
            rn: Register::X0,
            rm: Operand::Register(Register::X1),
        };
        assert!(!cmp.is_terminator());
    }

    #[test]
    fn test_is_encodable_aarch64_logical_imm_accepts_valid() {
        // Canonical valid bitmask immediates from issue #65.
        for imm in [
            0xFF_i64,
            0xFFFF,
            0xF0F0F0F0F0F0F0F0_u64 as i64,
            0x5555_5555_5555_5555,
        ] {
            assert!(
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(imm),
                    width: crate::ir::RegisterWidth::X64,
                }
                .is_encodable_aarch64(),
                "AND with valid imm 0x{:x} should be encodable",
                imm as u64
            );
            assert!(
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(imm),
                    width: crate::ir::RegisterWidth::X64,
                }
                .is_encodable_aarch64(),
                "ORR with valid imm 0x{:x} should be encodable",
                imm as u64
            );
            assert!(
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(imm),
                    width: crate::ir::RegisterWidth::X64,
                }
                .is_encodable_aarch64(),
                "EOR with valid imm 0x{:x} should be encodable",
                imm as u64
            );
            assert!(
                Instruction::Tst {
                    rn: Register::X1,
                    rm: Operand::Immediate(imm),
                    width: crate::ir::RegisterWidth::X64,
                }
                .is_encodable_aarch64(),
                "TST with valid imm 0x{:x} should be encodable",
                imm as u64
            );
            assert!(
                Instruction::Ands {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(imm),
                    width: crate::ir::RegisterWidth::X64,
                }
                .is_encodable_aarch64(),
                "ANDS with valid imm 0x{:x} should be encodable",
                imm as u64
            );
        }
    }

    #[test]
    fn test_is_encodable_aarch64_logical_imm_rejects_invalid() {
        // 0 (all-zeros), -1 (all-ones reinterpret), 5 (non-replicating pattern).
        for imm in [0_i64, -1, 5] {
            for ctor in [
                |r: i64| Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(r),
                    width: crate::ir::RegisterWidth::X64,
                },
                |r| Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(r),
                    width: crate::ir::RegisterWidth::X64,
                },
                |r| Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(r),
                    width: crate::ir::RegisterWidth::X64,
                },
                |r| Instruction::Tst {
                    rn: Register::X1,
                    rm: Operand::Immediate(r),
                    width: crate::ir::RegisterWidth::X64,
                },
                |r| Instruction::Ands {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(r),
                    width: crate::ir::RegisterWidth::X64,
                },
            ] {
                let instr = ctor(imm);
                assert!(
                    !instr.is_encodable_aarch64(),
                    "{} with non-bitmask imm 0x{:x} must NOT be encodable",
                    instr,
                    imm as u64,
                );
            }
        }
    }

    fn w32_logical_immediate_instrs(imm: i64) -> [Instruction; 5] {
        [
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width: RegisterWidth::W32,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width: RegisterWidth::W32,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width: RegisterWidth::W32,
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width: RegisterWidth::W32,
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width: RegisterWidth::W32,
            },
        ]
    }

    #[test]
    fn test_is_encodable_aarch64_logical_imm32_accepts_valid_masks() {
        for imm in [0xFF_i64, 0x8000_0000, 0x5555_5555, -256] {
            for instr in w32_logical_immediate_instrs(imm) {
                assert!(
                    instr.is_encodable_aarch64(),
                    "{} with W32 imm 0x{:x} should be encodable",
                    instr,
                    imm as u64
                );
            }
        }
    }

    #[test]
    fn test_is_encodable_aarch64_logical_imm32_rejects_invalid_masks() {
        for imm in [0_i64, -1, 0xFFFF_FFFF, 5, 0x1_0000_00FF] {
            for instr in w32_logical_immediate_instrs(imm) {
                assert!(
                    !instr.is_encodable_aarch64(),
                    "{} with W32 imm 0x{:x} must NOT be encodable",
                    instr,
                    imm as u64
                );
            }
        }
    }

    #[test]
    fn test_is_encodable_aarch64_logical_imm32_enforces_wsp_wzr_slots() {
        assert!(
            Instruction::And {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Immediate(0xFF),
                width: RegisterWidth::W32,
            }
            .is_encodable_aarch64(),
            "AND WSP, Wn, #imm uses the Wn|WSP destination slot"
        );
        assert!(
            !Instruction::And {
                rd: Register::XZR,
                rn: Register::X1,
                rm: Operand::Immediate(0xFF),
                width: RegisterWidth::W32,
            }
            .is_encodable_aarch64(),
            "AND WZR, Wn, #imm would alias to WSP in the destination slot"
        );
        assert!(
            Instruction::Ands {
                rd: Register::XZR,
                rn: Register::X1,
                rm: Operand::Immediate(0xFF),
                width: RegisterWidth::W32,
            }
            .is_encodable_aarch64(),
            "ANDS WZR, Wn, #imm uses a plain W destination slot"
        );
        assert!(
            !Instruction::Ands {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Immediate(0xFF),
                width: RegisterWidth::W32,
            }
            .is_encodable_aarch64(),
            "ANDS WSP, Wn, #imm is not a plain W-register destination"
        );
        assert!(
            !Instruction::Tst {
                rn: Register::SP,
                rm: Operand::Immediate(0xFF),
                width: RegisterWidth::W32,
            }
            .is_encodable_aarch64(),
            "TST WSP, #imm is not a plain W-register source"
        );
    }

    #[test]
    fn test_is_encodable_aarch64_rejects_xzr_dest_for_and_orr_eor_imm() {
        // AND/ORR/EOR (immediate) put Rd in the Xn|SP slot — XZR aliases to SP
        // there, so the assembler will reject it. is_encodable must agree.
        for ctor in [
            |rd, imm| Instruction::And {
                rd,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width: crate::ir::RegisterWidth::X64,
            },
            |rd, imm| Instruction::Orr {
                rd,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width: crate::ir::RegisterWidth::X64,
            },
            |rd, imm| Instruction::Eor {
                rd,
                rn: Register::X1,
                rm: Operand::Immediate(imm),
                width: crate::ir::RegisterWidth::X64,
            },
        ] {
            // Same encoder accepts 0xFF for X0…
            assert!(ctor(Register::X0, 0xFF).is_encodable_aarch64());
            // …but XZR-as-dest is rejected even with the otherwise-valid imm.
            assert!(!ctor(Register::XZR, 0xFF).is_encodable_aarch64());
        }

        // ANDS uses the plain X slot for Rd, so XZR is fine there.
        assert!(
            Instruction::Ands {
                rd: Register::XZR,
                rn: Register::X1,
                rm: Operand::Immediate(0xFF),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_is_encodable_aarch64_rejects_sp_in_xn_slot_for_logical_imm() {
        // AND/ORR/EOR (immediate): rn is the plain Xn slot — rejects SP. rd in
        // Xn|SP slot accepts SP per ARM spec.
        for ctor in [
            |rn| Instruction::And {
                rd: Register::X0,
                rn,
                rm: Operand::Immediate(0xFF),
                width: crate::ir::RegisterWidth::X64,
            },
            |rn| Instruction::Orr {
                rd: Register::X0,
                rn,
                rm: Operand::Immediate(0xFF),
                width: crate::ir::RegisterWidth::X64,
            },
            |rn| Instruction::Eor {
                rd: Register::X0,
                rn,
                rm: Operand::Immediate(0xFF),
                width: crate::ir::RegisterWidth::X64,
            },
        ] {
            assert!(
                !ctor(Register::SP).is_encodable_aarch64(),
                "rn=SP must be rejected for logical-imm (Xn slot)"
            );
            assert!(
                ctor(Register::X1).is_encodable_aarch64(),
                "rn=X1 must remain encodable"
            );
        }

        // AND/ORR/EOR with rd=SP is legitimate (Xn|SP slot encodes SP).
        assert!(
            Instruction::And {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Immediate(0xFF),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );

        // TST: rn in the plain Xn slot — SP rejected.
        assert!(
            !Instruction::Tst {
                rn: Register::SP,
                rm: Operand::Immediate(0xFF),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );

        // ANDS: both rd and rn in plain Xn slots — SP rejected for either.
        assert!(
            !Instruction::Ands {
                rd: Register::SP,
                rn: Register::X1,
                rm: Operand::Immediate(0xFF),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Ands {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(0xFF),
                width: crate::ir::RegisterWidth::X64,
            }
            .is_encodable_aarch64()
        );
    }

    // --- split_terminator_x86 ---

    #[test]
    fn split_terminator_x86_peels_trailing_jcc() {
        use crate::isa::x86::{X86Condition, X86Instruction, X86Register};
        let seq = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
        ];
        let (prefix, term) = split_terminator_x86(&seq);
        assert_eq!(prefix.len(), 1);
        assert!(matches!(prefix[0], X86Instruction::CmpReg { .. }));
        assert!(matches!(term, Some(X86Instruction::Jcc { .. })));
    }

    #[test]
    fn split_terminator_x86_returns_none_when_no_terminator() {
        use crate::isa::x86::{X86Instruction, X86Register};
        let seq = vec![X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let (prefix, term) = split_terminator_x86(&seq);
        assert_eq!(prefix.len(), 1);
        assert!(term.is_none());
    }

    #[test]
    fn split_terminator_x86_handles_empty_sequence() {
        let (prefix, term) = split_terminator_x86(&[]);
        assert!(prefix.is_empty());
        assert!(term.is_none());
    }
}
