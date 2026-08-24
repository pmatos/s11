//! x86 machine-code encodability rules.
//!
//! This is the single home for "can this instruction / register / immediate be
//! encoded in `mode` (32- or 64-bit)?" The search backends must never propose a
//! candidate the assembler cannot emit, so every rule about register width,
//! REX-prefix availability, and immediate field size lives here rather than
//! being rediscovered at each call site.
//!
//! The public seam is small: [`x86_can_assemble_instruction`] is the assembler
//! prefilter, and the register / immediate predicates it is built from are the
//! shared source of truth for the mutator's register and immediate pools. The
//! `imm{8,16,32}` bit-pattern helpers stay private to this module.

use super::{X86Instruction, X86Register, X86RegisterView};

fn x86_signed_imm32_ok(imm: i64) -> bool {
    i32::try_from(imm).is_ok()
}

/// A shift count encodes as `imm8`, so it must fit `0..=255`. x86 masks the
/// count to the operand width at execution time, but the *encoding* still
/// only carries a single byte, so any negative or >255 count is unencodable
/// and must be rejected before the search proposes it.
pub(crate) fn x86_shift_count_imm8_ok(imm: i64) -> bool {
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

pub(crate) fn x86_register_ok(reg: X86Register, mode_width: u32) -> bool {
    reg.index().is_some_and(|index| {
        index < if mode_width == 32 { 8 } else { 16 }
            && !(mode_width == 32 && reg.view() == X86RegisterView::LowByte && index >= 4)
    })
}

pub(crate) fn x86_register_pair_ok(lhs: X86Register, rhs: X86Register, mode_width: u32) -> bool {
    x86_register_ok(lhs, mode_width)
        && x86_register_ok(rhs, mode_width)
        && lhs.effective_width(mode_width) == rhs.effective_width(mode_width)
        && (!(lhs.is_high_byte() || rhs.is_high_byte())
            || (lhs.index().is_some_and(|index| index < 4)
                && rhs.index().is_some_and(|index| index < 4)))
}

pub(crate) fn x86_operand_immediate_ok(reg: X86Register, imm: i64, mode_width: u32) -> bool {
    match reg.effective_width(mode_width) {
        64 => x86_signed_imm32_ok(imm),
        32 => x86_imm32_bitpattern_ok(imm),
        16 => x86_imm16_bitpattern_ok(imm),
        8 => x86_imm8_bitpattern_ok(imm),
        _ => false,
    }
}

pub(crate) fn x86_mov_operand_immediate_ok(reg: X86Register, imm: i64, mode_width: u32) -> bool {
    match reg.effective_width(mode_width) {
        64 => true,
        32 => x86_imm32_bitpattern_ok(imm),
        16 => x86_imm16_bitpattern_ok(imm),
        8 => x86_imm8_bitpattern_ok(imm),
        _ => false,
    }
}

pub(crate) fn x86_mov_imm_ok(mode: crate::assembler::x86::X86Mode, imm: i64) -> bool {
    match mode {
        crate::assembler::x86::X86Mode::Mode64 => true,
        crate::assembler::x86::X86Mode::Mode32 => x86_imm32_bitpattern_ok(imm),
    }
}

pub(crate) fn x86_non_mov_imm_ok(mode: crate::assembler::x86::X86Mode, imm: i64) -> bool {
    match mode {
        crate::assembler::x86::X86Mode::Mode64 => x86_signed_imm32_ok(imm),
        crate::assembler::x86::X86Mode::Mode32 => x86_imm32_bitpattern_ok(imm),
    }
}

pub(crate) fn x86_extension_source_ok(
    mode: crate::assembler::x86::X86Mode,
    reg: X86Register,
    src_width: u32,
) -> bool {
    if !reg.is_native() || !matches!(src_width, 8 | 16) {
        return false;
    }
    let Some(index) = reg.index() else {
        return false;
    };
    match mode {
        crate::assembler::x86::X86Mode::Mode64 => true,
        crate::assembler::x86::X86Mode::Mode32 => index < 8 && (src_width == 16 || index < 4),
    }
}

pub(crate) fn x86_can_assemble_instruction(instruction: &X86Instruction, mode_width: u32) -> bool {
    match instruction {
        X86Instruction::MovReg { rd, rs }
        | X86Instruction::AddReg { rd, rs }
        | X86Instruction::SubReg { rd, rs }
        | X86Instruction::AndReg { rd, rs }
        | X86Instruction::OrReg { rd, rs }
        | X86Instruction::XorReg { rd, rs } => x86_register_pair_ok(*rd, *rs, mode_width),
        X86Instruction::Movzx { rd, rs, src_width }
        | X86Instruction::Movsx { rd, rs, src_width } => {
            let mode = if mode_width == 64 {
                crate::assembler::x86::X86Mode::Mode64
            } else {
                crate::assembler::x86::X86Mode::Mode32
            };
            rd.is_native()
                && x86_register_ok(*rd, mode_width)
                && x86_extension_source_ok(mode, *rs, *src_width)
        }
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
        // SETcc is a full-width pseudo-op. In x86-32 only EAX..EBX
        // (slots 0..=3) name a low byte without a REX prefix, so restrict the
        // native destination there.
        X86Instruction::Setcc { rd, .. } => {
            rd.view() == X86RegisterView::Native
                && (mode_width == 64 || rd.index().is_some_and(|index| index < 4))
        }
        X86Instruction::Jcc { .. } => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::x86::X86Mode;
    use crate::isa::x86::X86Condition;

    // Shift counts encode as a single imm8 byte: 0..=255, unsigned.
    #[test]
    fn shift_count_encodes_as_unsigned_imm8() {
        assert!(x86_shift_count_imm8_ok(0), "0 is a valid imm8 shift count");
        assert!(x86_shift_count_imm8_ok(255), "255 is the largest imm8");
        assert!(!x86_shift_count_imm8_ok(256), "256 exceeds a single byte");
        assert!(
            !x86_shift_count_imm8_ok(-1),
            "the imm8 shift-count field is unsigned"
        );
    }

    // R8-R15 need a REX prefix that 32-bit mode cannot emit; SPL/BPL/SIL/DIL are
    // the REX-only low bytes, while AL/CL/DL/BL remain addressable without REX.
    #[test]
    fn register_legality_tracks_rex_availability_per_mode() {
        for reg in [X86Register::R8, X86Register::R8D, X86Register::R8B] {
            assert!(
                !x86_register_ok(reg, 32),
                "{reg} needs a REX prefix unavailable in 32-bit mode"
            );
            assert!(x86_register_ok(reg, 64), "{reg} is available in x86-64");
        }
        for reg in [
            X86Register::SPL,
            X86Register::BPL,
            X86Register::SIL,
            X86Register::DIL,
        ] {
            assert!(!x86_register_ok(reg, 32), "{reg} is a REX-only low byte");
            assert!(x86_register_ok(reg, 64), "{reg} is available in x86-64");
        }
        for reg in [
            X86Register::RAX,
            X86Register::EAX,
            X86Register::AX,
            X86Register::AL,
            X86Register::AH,
        ] {
            assert!(x86_register_ok(reg, 32), "{reg} is available without REX");
            assert!(x86_register_ok(reg, 64), "{reg} is available in x86-64");
        }
    }

    // A register pair must share an operand width and cannot mix a legacy high
    // byte (AH/CH/DH/BH, which forbids REX) with a REX-requiring register.
    #[test]
    fn register_pair_requires_matching_width() {
        assert!(x86_register_pair_ok(X86Register::RAX, X86Register::RCX, 64));
        assert!(
            !x86_register_pair_ok(X86Register::RAX, X86Register::EAX, 64),
            "a 64-bit and a 32-bit operand cannot pair"
        );
        assert!(
            !x86_register_pair_ok(X86Register::R8, X86Register::RAX, 32),
            "an extended register drags the whole pair out of 32-bit legality"
        );
        assert!(x86_register_pair_ok(X86Register::AX, X86Register::BX, 32));
        assert!(x86_register_pair_ok(X86Register::AL, X86Register::AH, 64));
        assert!(
            !x86_register_pair_ok(X86Register::EAX, X86Register::AX, 64),
            "dword and word views cannot pair"
        );
    }

    #[test]
    fn register_pair_rejects_high_byte_with_rex_register() {
        assert!(
            !x86_register_pair_ok(X86Register::AH, X86Register::DIL, 64),
            "AH forbids REX; DIL requires it"
        );
        assert!(
            x86_register_pair_ok(X86Register::AH, X86Register::AL, 64),
            "AH pairs with a legacy low byte"
        );
    }

    // Arithmetic/logical immediates on a 64-bit operand sign-extend an imm32.
    #[test]
    fn operand_immediate_on_64bit_register_takes_signed_imm32() {
        assert!(x86_operand_immediate_ok(
            X86Register::RAX,
            i64::from(i32::MAX),
            64
        ));
        assert!(x86_operand_immediate_ok(
            X86Register::RAX,
            i64::from(i32::MIN),
            64
        ));
        assert!(!x86_operand_immediate_ok(
            X86Register::RAX,
            i64::from(i32::MAX) + 1,
            64
        ));
        assert!(!x86_operand_immediate_ok(
            X86Register::RAX,
            i64::from(i32::MIN) - 1,
            64
        ));
    }

    #[test]
    fn operand_immediate_on_narrow_registers_take_their_bit_patterns() {
        // 32-bit operand: any canonical 32-bit bit pattern (signed or unsigned).
        assert!(x86_operand_immediate_ok(
            X86Register::EAX,
            i64::from(u32::MAX),
            64
        ));
        assert!(!x86_operand_immediate_ok(
            X86Register::EAX,
            i64::from(u32::MAX) + 1,
            64
        ));
        // 16-bit operand: imm16 bit patterns only.
        assert!(x86_operand_immediate_ok(
            X86Register::AX,
            i64::from(u16::MAX),
            64
        ));
        assert!(!x86_operand_immediate_ok(
            X86Register::AX,
            i64::from(u16::MAX) + 1,
            64
        ));
        // 8-bit operand: imm8 bit patterns only.
        assert!(x86_operand_immediate_ok(X86Register::AL, 255, 64));
        assert!(!x86_operand_immediate_ok(X86Register::AL, 256, 64));
    }

    // MOV into a 64-bit register is the movabs form: any 64-bit immediate.
    #[test]
    fn mov_operand_immediate_allows_full_width_movabs_on_64bit() {
        assert!(x86_mov_operand_immediate_ok(X86Register::RAX, i64::MAX, 64));
        assert!(
            !x86_mov_operand_immediate_ok(X86Register::EAX, i64::from(u32::MAX) + 1, 64),
            "a 32-bit MOV target is still bounded to a 32-bit bit pattern"
        );
    }

    #[test]
    fn mov_immediate_pool_is_unbounded_in_64bit_but_imm32_in_32bit() {
        assert!(x86_mov_imm_ok(X86Mode::Mode64, i64::MAX));
        assert!(x86_mov_imm_ok(X86Mode::Mode32, i64::from(u32::MAX)));
        assert!(!x86_mov_imm_ok(X86Mode::Mode32, i64::from(u32::MAX) + 1));
    }

    #[test]
    fn non_mov_immediate_pool_is_signed_imm32_in_64bit() {
        assert!(x86_non_mov_imm_ok(X86Mode::Mode64, i64::from(i32::MIN)));
        assert!(
            !x86_non_mov_imm_ok(X86Mode::Mode64, i64::from(u32::MAX)),
            "a positive u32::MAX cannot sign-extend from imm32 in 64-bit mode"
        );
        assert!(
            x86_non_mov_imm_ok(X86Mode::Mode32, i64::from(u32::MAX)),
            "32-bit mode encodes the canonical u32 bit pattern directly"
        );
    }

    // MOVZX/MOVSX name their source by its native register and take a byte or
    // word source; 32-bit byte sources are limited by REX availability.
    #[test]
    fn extension_source_requires_native_byte_or_word_source() {
        assert!(x86_extension_source_ok(
            X86Mode::Mode64,
            X86Register::R15,
            8
        ));
        assert!(x86_extension_source_ok(
            X86Mode::Mode64,
            X86Register::RAX,
            16
        ));
        assert!(
            !x86_extension_source_ok(X86Mode::Mode64, X86Register::RAX, 32),
            "a 32-bit source is a plain MOV, not an extension"
        );
        assert!(
            !x86_extension_source_ok(X86Mode::Mode64, X86Register::AL, 8),
            "the extension source is named by its native register"
        );
    }

    #[test]
    fn extension_byte_source_in_32bit_requires_legacy_low_register() {
        assert!(
            !x86_extension_source_ok(X86Mode::Mode32, X86Register::RSI, 8),
            "a byte source from RSI needs a REX-only low byte in 32-bit mode"
        );
        assert!(
            x86_extension_source_ok(X86Mode::Mode32, X86Register::RSI, 16),
            "word sources have no REX restriction for the legacy registers"
        );
        assert!(x86_extension_source_ok(
            X86Mode::Mode32,
            X86Register::RAX,
            8
        ));
        assert!(
            !x86_extension_source_ok(X86Mode::Mode32, X86Register::R8, 16),
            "extended registers are entirely unavailable in 32-bit mode"
        );
    }

    // The dispatcher composes the register and immediate rules per opcode class.
    #[test]
    fn can_assemble_dispatches_register_and_immediate_rules() {
        assert!(x86_can_assemble_instruction(
            &X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RCX
            },
            64
        ));
        assert!(
            !x86_can_assemble_instruction(
                &X86Instruction::MovReg {
                    rd: X86Register::R8,
                    rs: X86Register::RAX
                },
                32
            ),
            "an extended-register move is unencodable in 32-bit mode"
        );
        assert!(
            x86_can_assemble_instruction(
                &X86Instruction::Jcc {
                    cond: X86Condition::E
                },
                32
            ),
            "Jcc terminators are always encodable"
        );
    }

    // SETcc is modelled on the native register; the assembler emits its low
    // byte, which in 32-bit mode is REX-free only for the low four registers.
    #[test]
    fn can_assemble_setcc_requires_native_low_four_in_32bit() {
        let setne = |rd| X86Instruction::Setcc {
            rd,
            cond: X86Condition::NE,
        };
        assert!(x86_can_assemble_instruction(&setne(X86Register::RAX), 32));
        assert!(x86_can_assemble_instruction(&setne(X86Register::R8), 64));
        assert!(
            !x86_can_assemble_instruction(&setne(X86Register::R8), 32),
            "R8's low byte needs REX, absent in 32-bit mode"
        );
        assert!(
            !x86_can_assemble_instruction(&setne(X86Register::AL), 64),
            "the IR models SETcc on the native register, not a byte view"
        );
    }

    #[test]
    fn can_assemble_lea_bounds_displacement_to_signed_imm32() {
        let lea = |disp| X86Instruction::Lea {
            rd: X86Register::RAX,
            base: X86Register::RAX,
            disp,
        };
        assert!(x86_can_assemble_instruction(&lea(0), 64));
        assert!(x86_can_assemble_instruction(&lea(i64::from(i32::MIN)), 64));
        assert!(
            !x86_can_assemble_instruction(&lea(i64::from(i32::MAX) + 1), 64),
            "the LEA displacement is a signed 32-bit field"
        );
    }
}
