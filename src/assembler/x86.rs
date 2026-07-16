//! Dynasm-based assembler for the x86 backend.
//!
//! Two modes:
//! - `X86Assembler::new_64()` → uses `dynasmrt::x64::Assembler` and
//!   emits 64-bit instruction encodings.
//! - `X86Assembler::new_32()` → uses `dynasmrt::x86::Assembler` and
//!   emits 32-bit encodings (no REX prefix; R8..R15 not accessible).
//!
//! Capstone round-trip tests at the bottom verify byte-level correctness
//! for every variant: encode → disassemble → assert mnemonic + operand
//! strings match.

// The dynasm! macro auto-inserts `.into()` calls when accepting register
// indices, which clippy flags as `useless_conversion` whenever the supplied
// value is already the target type (here, `u8`). The conversion is dynasm's
// design, not ours, and there's no way to suppress it per-call without
// disfiguring the macro invocations. Allow at module scope.
#![allow(clippy::useless_conversion)]

use crate::isa::x86::{X86Condition, X86Instruction, X86Register, X86RegisterView};
use dynasm::dynasm;
use dynasmrt::DynasmApi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86Mode {
    Mode64,
    Mode32,
}

pub struct X86Assembler {
    mode: X86Mode,
}

impl X86Assembler {
    pub fn new_64() -> Self {
        Self {
            mode: X86Mode::Mode64,
        }
    }

    pub fn new_32() -> Self {
        Self {
            mode: X86Mode::Mode32,
        }
    }

    pub fn assemble_instructions(
        &mut self,
        instructions: &[X86Instruction],
    ) -> Result<Vec<u8>, String> {
        match self.mode {
            X86Mode::Mode64 => assemble_64(instructions),
            X86Mode::Mode32 => assemble_32(instructions),
        }
    }
}

fn reg_index(reg: X86Register) -> Result<u8, String> {
    reg.index()
        .ok_or_else(|| format!("register {:?} has no index", reg))
}

fn reg_index_32(reg: X86Register) -> Result<u8, String> {
    let i = reg_index(reg)?;
    if i >= 8 {
        return Err(format!("register {:?} not available in x86-32 mode", reg));
    }
    Ok(i)
}

fn validate_register_pair(
    lhs: X86Register,
    rhs: X86Register,
    mode_width: u32,
) -> Result<(), String> {
    validate_single_register(lhs, mode_width)?;
    validate_single_register(rhs, mode_width)?;
    if lhs.effective_width(mode_width) != rhs.effective_width(mode_width) {
        return Err(format!("register widths do not match: {} and {}", lhs, rhs));
    }
    if (lhs.is_high_byte() || rhs.is_high_byte())
        && (lhs.index().is_some_and(|index| index >= 4)
            || rhs.index().is_some_and(|index| index >= 4))
    {
        return Err(format!(
            "high-byte register cannot be encoded when a REX prefix is required: {}, {}",
            lhs, rhs
        ));
    }
    Ok(())
}

fn validate_single_register(reg: X86Register, mode_width: u32) -> Result<(), String> {
    if reg.effective_width(mode_width) > mode_width {
        return Err(format!(
            "register {} is not available in x86-{}",
            reg, mode_width
        ));
    }
    if mode_width == 32
        && reg.view() == X86RegisterView::LowByte
        && reg.index().is_some_and(|index| index >= 4)
    {
        return Err(format!(
            "register {} requires a REX prefix and is not available in x86-32",
            reg
        ));
    }
    Ok(())
}

macro_rules! legacy_byte_reg_reg_opcode {
    (mov) => {
        0x88u8
    };
    (add) => {
        0x00u8
    };
    (sub) => {
        0x28u8
    };
    (and) => {
        0x20u8
    };
    (or) => {
        0x08u8
    };
    (xor) => {
        0x30u8
    };
    (cmp) => {
        0x38u8
    };
    (test) => {
        0x84u8
    };
}

macro_rules! emit_legacy_byte_reg_reg {
    ($ops:expr, $op:ident, $dst:expr, $src:expr) => {{
        $ops.push(legacy_byte_reg_reg_opcode!($op));
        $ops.push(0xc0u8 | (($src & 7) << 3) | ($dst & 7));
    }};
}

macro_rules! emit_reg_reg_64 {
    ($ops:expr, $op:ident, $lhs:expr, $rhs:expr) => {{
        let lhs_reg = $lhs;
        let rhs_reg = $rhs;
        validate_register_pair(lhs_reg, rhs_reg, 64)?;
        let lhs = reg_index(lhs_reg)?;
        let rhs = reg_index(rhs_reg)?;
        match (lhs_reg.view(), rhs_reg.view()) {
            (X86RegisterView::Native, X86RegisterView::Native) => {
                dynasm!($ops ; .arch x64 ; $op Rq(lhs), Rq(rhs))
            }
            (X86RegisterView::Dword, X86RegisterView::Dword) => {
                dynasm!($ops ; .arch x64 ; $op Rd(lhs), Rd(rhs))
            }
            (X86RegisterView::Word, X86RegisterView::Word) => {
                dynasm!($ops ; .arch x64 ; $op Rw(lhs), Rw(rhs))
            }
            (X86RegisterView::LowByte, X86RegisterView::LowByte) => {
                dynasm!($ops ; .arch x64 ; $op Rb(lhs), Rb(rhs))
            }
            (X86RegisterView::HighByte, X86RegisterView::HighByte) => {
                let lhs = lhs + 4;
                let rhs = rhs + 4;
                dynasm!($ops ; .arch x64 ; $op Rh(lhs), Rh(rhs))
            }
            (X86RegisterView::LowByte, X86RegisterView::HighByte) => {
                let rhs = rhs + 4;
                emit_legacy_byte_reg_reg!($ops, $op, lhs, rhs)
            }
            (X86RegisterView::HighByte, X86RegisterView::LowByte) => {
                let lhs = lhs + 4;
                emit_legacy_byte_reg_reg!($ops, $op, lhs, rhs)
            }
            _ => unreachable!("validated register widths select one encoding family"),
        }
    }};
}

macro_rules! emit_reg_imm_64 {
    ($ops:expr, $op:ident, $reg:expr, $imm:expr) => {{
        let register = $reg;
        validate_single_register(register, 64)?;
        let index = reg_index(register)?;
        match register.view() {
            X86RegisterView::Native => {
                let imm = signed_imm_i32($imm)?;
                dynasm!($ops ; .arch x64 ; $op Rq(index), imm);
            }
            X86RegisterView::Dword => {
                let imm = imm32_bitpattern_i32($imm)?;
                dynasm!($ops ; .arch x64 ; $op Rd(index), imm);
            }
            X86RegisterView::Word => {
                let imm = imm16_bitpattern_i16($imm)?;
                dynasm!($ops ; .arch x64 ; $op Rw(index), WORD imm);
            }
            X86RegisterView::LowByte => {
                let imm = imm8_bitpattern_i8($imm)?;
                dynasm!($ops ; .arch x64 ; $op Rb(index), BYTE imm);
            }
            X86RegisterView::HighByte => {
                let imm = imm8_bitpattern_i8($imm)?;
                let index = index + 4;
                dynasm!($ops ; .arch x64 ; $op Rh(index), BYTE imm);
            }
        }
    }};
}

macro_rules! emit_unary_64 {
    ($ops:expr, $op:ident, $reg:expr) => {{
        let register = $reg;
        validate_single_register(register, 64)?;
        let index = reg_index(register)?;
        match register.view() {
            X86RegisterView::Native => dynasm!($ops ; .arch x64 ; $op Rq(index)),
            X86RegisterView::Dword => dynasm!($ops ; .arch x64 ; $op Rd(index)),
            X86RegisterView::Word => dynasm!($ops ; .arch x64 ; $op Rw(index)),
            X86RegisterView::LowByte => dynasm!($ops ; .arch x64 ; $op Rb(index)),
            X86RegisterView::HighByte => {
                let index = index + 4;
                dynasm!($ops ; .arch x64 ; $op Rh(index))
            }
        }
    }};
}

macro_rules! emit_shift_64 {
    ($ops:expr, $op:ident, $reg:expr, $count:expr) => {{
        let register = $reg;
        validate_single_register(register, 64)?;
        let index = reg_index(register)?;
        let count = shift_count_imm8($count)?;
        match register.view() {
            X86RegisterView::Native => dynasm!($ops ; .arch x64 ; $op Rq(index), BYTE count),
            X86RegisterView::Dword => dynasm!($ops ; .arch x64 ; $op Rd(index), BYTE count),
            X86RegisterView::Word => dynasm!($ops ; .arch x64 ; $op Rw(index), BYTE count),
            X86RegisterView::LowByte => dynasm!($ops ; .arch x64 ; $op Rb(index), BYTE count),
            X86RegisterView::HighByte => {
                let index = index + 4;
                dynasm!($ops ; .arch x64 ; $op Rh(index), BYTE count)
            }
        }
    }};
}

macro_rules! emit_reg_reg_32 {
    ($ops:expr, $op:ident, $lhs:expr, $rhs:expr) => {{
        let lhs_reg = $lhs;
        let rhs_reg = $rhs;
        validate_register_pair(lhs_reg, rhs_reg, 32)?;
        let lhs = reg_index_32(lhs_reg)?;
        let rhs = reg_index_32(rhs_reg)?;
        match (lhs_reg.view(), rhs_reg.view()) {
            (
                X86RegisterView::Native | X86RegisterView::Dword,
                X86RegisterView::Native | X86RegisterView::Dword,
            ) => {
                dynasm!($ops ; .arch x86 ; $op Rd(lhs), Rd(rhs))
            }
            (X86RegisterView::Word, X86RegisterView::Word) => {
                dynasm!($ops ; .arch x86 ; $op Rw(lhs), Rw(rhs))
            }
            (X86RegisterView::LowByte, X86RegisterView::LowByte) => {
                dynasm!($ops ; .arch x86 ; $op Rb(lhs), Rb(rhs))
            }
            (X86RegisterView::HighByte, X86RegisterView::HighByte) => {
                let lhs = lhs + 4;
                let rhs = rhs + 4;
                dynasm!($ops ; .arch x86 ; $op Rh(lhs), Rh(rhs))
            }
            (X86RegisterView::LowByte, X86RegisterView::HighByte) => {
                let rhs = rhs + 4;
                emit_legacy_byte_reg_reg!($ops, $op, lhs, rhs)
            }
            (X86RegisterView::HighByte, X86RegisterView::LowByte) => {
                let lhs = lhs + 4;
                emit_legacy_byte_reg_reg!($ops, $op, lhs, rhs)
            }
            _ => unreachable!("validated register widths select one encoding family"),
        }
    }};
}

macro_rules! emit_reg_imm_32 {
    ($ops:expr, $op:ident, $reg:expr, $imm:expr) => {{
        let register = $reg;
        validate_single_register(register, 32)?;
        let index = reg_index_32(register)?;
        match register.view() {
            X86RegisterView::Native | X86RegisterView::Dword => {
                let imm = imm32_bitpattern_i32($imm)?;
                dynasm!($ops ; .arch x86 ; $op Rd(index), imm);
            }
            X86RegisterView::Word => {
                let imm = imm16_bitpattern_i16($imm)?;
                dynasm!($ops ; .arch x86 ; $op Rw(index), WORD imm);
            }
            X86RegisterView::LowByte => {
                let imm = imm8_bitpattern_i8($imm)?;
                dynasm!($ops ; .arch x86 ; $op Rb(index), BYTE imm);
            }
            X86RegisterView::HighByte => {
                let imm = imm8_bitpattern_i8($imm)?;
                let index = index + 4;
                dynasm!($ops ; .arch x86 ; $op Rh(index), BYTE imm);
            }
        }
    }};
}

macro_rules! emit_unary_32 {
    ($ops:expr, $op:ident, $reg:expr) => {{
        let register = $reg;
        validate_single_register(register, 32)?;
        let index = reg_index_32(register)?;
        match register.view() {
            X86RegisterView::Native | X86RegisterView::Dword => {
                dynasm!($ops ; .arch x86 ; $op Rd(index))
            }
            X86RegisterView::Word => dynasm!($ops ; .arch x86 ; $op Rw(index)),
            X86RegisterView::LowByte => dynasm!($ops ; .arch x86 ; $op Rb(index)),
            X86RegisterView::HighByte => {
                let index = index + 4;
                dynasm!($ops ; .arch x86 ; $op Rh(index))
            }
        }
    }};
}

macro_rules! emit_shift_32 {
    ($ops:expr, $op:ident, $reg:expr, $count:expr) => {{
        let register = $reg;
        validate_single_register(register, 32)?;
        let index = reg_index_32(register)?;
        let count = shift_count_imm8($count)?;
        match register.view() {
            X86RegisterView::Native | X86RegisterView::Dword => {
                dynasm!($ops ; .arch x86 ; $op Rd(index), BYTE count)
            }
            X86RegisterView::Word => dynasm!($ops ; .arch x86 ; $op Rw(index), BYTE count),
            X86RegisterView::LowByte => dynasm!($ops ; .arch x86 ; $op Rb(index), BYTE count),
            X86RegisterView::HighByte => {
                let index = index + 4;
                dynasm!($ops ; .arch x86 ; $op Rh(index), BYTE count)
            }
        }
    }};
}

macro_rules! emit_cmov_64_for_family {
    ($ops:expr, $cond:expr, $family:ident, $rd:expr, $rs:expr) => {
        match $cond {
            X86Condition::E => dynasm!($ops ; .arch x64 ; cmove $family($rd), $family($rs)),
            X86Condition::NE => dynasm!($ops ; .arch x64 ; cmovne $family($rd), $family($rs)),
            X86Condition::B => dynasm!($ops ; .arch x64 ; cmovb $family($rd), $family($rs)),
            X86Condition::AE => dynasm!($ops ; .arch x64 ; cmovae $family($rd), $family($rs)),
            X86Condition::BE => dynasm!($ops ; .arch x64 ; cmovbe $family($rd), $family($rs)),
            X86Condition::A => dynasm!($ops ; .arch x64 ; cmova $family($rd), $family($rs)),
            X86Condition::L => dynasm!($ops ; .arch x64 ; cmovl $family($rd), $family($rs)),
            X86Condition::GE => dynasm!($ops ; .arch x64 ; cmovge $family($rd), $family($rs)),
            X86Condition::LE => dynasm!($ops ; .arch x64 ; cmovle $family($rd), $family($rs)),
            X86Condition::G => dynasm!($ops ; .arch x64 ; cmovg $family($rd), $family($rs)),
            X86Condition::S => dynasm!($ops ; .arch x64 ; cmovs $family($rd), $family($rs)),
            X86Condition::NS => dynasm!($ops ; .arch x64 ; cmovns $family($rd), $family($rs)),
            X86Condition::O => dynasm!($ops ; .arch x64 ; cmovo $family($rd), $family($rs)),
            X86Condition::NO => dynasm!($ops ; .arch x64 ; cmovno $family($rd), $family($rs)),
            X86Condition::P => dynasm!($ops ; .arch x64 ; cmovp $family($rd), $family($rs)),
            X86Condition::NP => dynasm!($ops ; .arch x64 ; cmovnp $family($rd), $family($rs)),
        }
    };
}

macro_rules! emit_cmov_32_for_family {
    ($ops:expr, $cond:expr, $family:ident, $rd:expr, $rs:expr) => {
        match $cond {
            X86Condition::E => dynasm!($ops ; .arch x86 ; cmove $family($rd), $family($rs)),
            X86Condition::NE => dynasm!($ops ; .arch x86 ; cmovne $family($rd), $family($rs)),
            X86Condition::B => dynasm!($ops ; .arch x86 ; cmovb $family($rd), $family($rs)),
            X86Condition::AE => dynasm!($ops ; .arch x86 ; cmovae $family($rd), $family($rs)),
            X86Condition::BE => dynasm!($ops ; .arch x86 ; cmovbe $family($rd), $family($rs)),
            X86Condition::A => dynasm!($ops ; .arch x86 ; cmova $family($rd), $family($rs)),
            X86Condition::L => dynasm!($ops ; .arch x86 ; cmovl $family($rd), $family($rs)),
            X86Condition::GE => dynasm!($ops ; .arch x86 ; cmovge $family($rd), $family($rs)),
            X86Condition::LE => dynasm!($ops ; .arch x86 ; cmovle $family($rd), $family($rs)),
            X86Condition::G => dynasm!($ops ; .arch x86 ; cmovg $family($rd), $family($rs)),
            X86Condition::S => dynasm!($ops ; .arch x86 ; cmovs $family($rd), $family($rs)),
            X86Condition::NS => dynasm!($ops ; .arch x86 ; cmovns $family($rd), $family($rs)),
            X86Condition::O => dynasm!($ops ; .arch x86 ; cmovo $family($rd), $family($rs)),
            X86Condition::NO => dynasm!($ops ; .arch x86 ; cmovno $family($rd), $family($rs)),
            X86Condition::P => dynasm!($ops ; .arch x86 ; cmovp $family($rd), $family($rs)),
            X86Condition::NP => dynasm!($ops ; .arch x86 ; cmovnp $family($rd), $family($rs)),
        }
    };
}

fn setcc_opcode(cond: X86Condition) -> u8 {
    match cond {
        X86Condition::E => 0x94,
        X86Condition::NE => 0x95,
        X86Condition::B => 0x92,
        X86Condition::AE => 0x93,
        X86Condition::BE => 0x96,
        X86Condition::A => 0x97,
        X86Condition::L => 0x9c,
        X86Condition::GE => 0x9d,
        X86Condition::LE => 0x9e,
        X86Condition::G => 0x9f,
        X86Condition::S => 0x98,
        X86Condition::NS => 0x99,
        X86Condition::O => 0x90,
        X86Condition::NO => 0x91,
        X86Condition::P => 0x9a,
        X86Condition::NP => 0x9b,
    }
}

/// Lower the full-width SETcc pseudo-instruction to an architectural byte
/// SETcc followed by a same-register MOVZX into the 32-bit destination.
///
/// Writing the 32-bit destination produces the intended native-width 0/1 in
/// both modes: x86-64 zeroes bits 63:32 on every 32-bit register write.
fn encode_full_width_setcc(ops: &mut impl DynasmApi, rd: u8, cond: X86Condition, mode64: bool) {
    let low = rd & 7;
    if mode64 {
        if rd >= 8 {
            ops.push(0x41); // REX.B selects R8B..R15B.
        } else if rd >= 4 {
            ops.push(0x40); // Bare REX selects SPL/BPL/SIL/DIL.
        }
    }
    ops.extend([0x0f, setcc_opcode(cond), 0xc0 | low]);

    if mode64 {
        if rd >= 8 {
            ops.push(0x45); // REX.R + REX.B select the same extended register.
        } else if rd >= 4 {
            ops.push(0x40); // Required for the low-byte source.
        }
    }
    ops.extend([0x0f, 0xb6, 0xc0 | (low << 3) | low]);
}

fn assemble_64(instructions: &[X86Instruction]) -> Result<Vec<u8>, String> {
    let mut ops =
        dynasmrt::x64::Assembler::new().map_err(|e| format!("dynasm x64 init failed: {:?}", e))?;
    for instr in instructions {
        encode_64(&mut ops, instr)?;
    }
    let buf = ops
        .finalize()
        .map_err(|e| format!("dynasm finalize failed: {:?}", e))?;
    Ok(buf.to_vec())
}

fn assemble_32(instructions: &[X86Instruction]) -> Result<Vec<u8>, String> {
    let mut ops =
        dynasmrt::x86::Assembler::new().map_err(|e| format!("dynasm x86 init failed: {:?}", e))?;
    for instr in instructions {
        encode_32(&mut ops, instr)?;
    }
    let buf = ops
        .finalize()
        .map_err(|e| format!("dynasm finalize failed: {:?}", e))?;
    Ok(buf.to_vec())
}

fn encode_64(ops: &mut dynasmrt::x64::Assembler, instr: &X86Instruction) -> Result<(), String> {
    match instr {
        X86Instruction::MovReg { rd, rs } => {
            emit_reg_reg_64!(ops, mov, *rd, *rs);
            Ok(())
        }
        X86Instruction::MovImm { rd, imm } => {
            if rd.view() == X86RegisterView::Native {
                let rd = reg_index(*rd)?;
                // Prefer the imm32 sign-extended encoding (`REX.W C7 /0 id`,
                // 7 bytes) when the immediate fits. Fall back to MOVABS for a
                // full 64-bit immediate.
                if let Ok(i32_imm) = i32::try_from(*imm) {
                    dynasm!(ops ; .arch x64 ; mov Rq(rd), i32_imm);
                } else {
                    let imm = *imm;
                    dynasm!(ops ; .arch x64 ; mov Rq(rd), QWORD imm);
                }
            } else {
                emit_reg_imm_64!(ops, mov, *rd, *imm);
            }
            Ok(())
        }
        X86Instruction::AddReg { rd, rs } => {
            emit_reg_reg_64!(ops, add, *rd, *rs);
            Ok(())
        }
        X86Instruction::AddImm { rd, imm } => {
            emit_reg_imm_64!(ops, add, *rd, *imm);
            Ok(())
        }
        X86Instruction::SubReg { rd, rs } => {
            emit_reg_reg_64!(ops, sub, *rd, *rs);
            Ok(())
        }
        X86Instruction::SubImm { rd, imm } => {
            emit_reg_imm_64!(ops, sub, *rd, *imm);
            Ok(())
        }
        X86Instruction::AndReg { rd, rs } => {
            emit_reg_reg_64!(ops, and, *rd, *rs);
            Ok(())
        }
        X86Instruction::AndImm { rd, imm } => {
            emit_reg_imm_64!(ops, and, *rd, *imm);
            Ok(())
        }
        X86Instruction::OrReg { rd, rs } => {
            emit_reg_reg_64!(ops, or, *rd, *rs);
            Ok(())
        }
        X86Instruction::OrImm { rd, imm } => {
            emit_reg_imm_64!(ops, or, *rd, *imm);
            Ok(())
        }
        X86Instruction::XorReg { rd, rs } => {
            emit_reg_reg_64!(ops, xor, *rd, *rs);
            Ok(())
        }
        X86Instruction::XorImm { rd, imm } => {
            emit_reg_imm_64!(ops, xor, *rd, *imm);
            Ok(())
        }
        X86Instruction::CmpReg { rn, rs } => {
            emit_reg_reg_64!(ops, cmp, *rn, *rs);
            Ok(())
        }
        X86Instruction::CmpImm { rn, imm } => {
            emit_reg_imm_64!(ops, cmp, *rn, *imm);
            Ok(())
        }
        X86Instruction::TestReg { rn, rs } => {
            emit_reg_reg_64!(ops, test, *rn, *rs);
            Ok(())
        }
        X86Instruction::TestImm { rn, imm } => {
            emit_reg_imm_64!(ops, test, *rn, *imm);
            Ok(())
        }
        X86Instruction::Neg { rd } => {
            emit_unary_64!(ops, neg, *rd);
            Ok(())
        }
        X86Instruction::Not { rd } => {
            emit_unary_64!(ops, not, *rd);
            Ok(())
        }
        X86Instruction::Inc { rd } => {
            emit_unary_64!(ops, inc, *rd);
            Ok(())
        }
        X86Instruction::Dec { rd } => {
            emit_unary_64!(ops, dec, *rd);
            Ok(())
        }
        X86Instruction::Shl { rd, imm } => {
            emit_shift_64!(ops, shl, *rd, *imm);
            Ok(())
        }
        X86Instruction::Shr { rd, imm } => {
            emit_shift_64!(ops, shr, *rd, *imm);
            Ok(())
        }
        X86Instruction::Sar { rd, imm } => {
            emit_shift_64!(ops, sar, *rd, *imm);
            Ok(())
        }
        X86Instruction::Rol { rd, imm } => {
            emit_shift_64!(ops, rol, *rd, *imm);
            Ok(())
        }
        X86Instruction::Ror { rd, imm } => {
            emit_shift_64!(ops, ror, *rd, *imm);
            Ok(())
        }
        X86Instruction::ImulReg { rd, rs } => {
            validate_register_pair(*rd, *rs, 64)?;
            let view = rd.view();
            let rd = reg_index(*rd)?;
            let rs = reg_index(*rs)?;
            match view {
                X86RegisterView::Native => dynasm!(ops ; .arch x64 ; imul Rq(rd), Rq(rs)),
                X86RegisterView::Dword => dynasm!(ops ; .arch x64 ; imul Rd(rd), Rd(rs)),
                X86RegisterView::Word => dynasm!(ops ; .arch x64 ; imul Rw(rd), Rw(rs)),
                X86RegisterView::LowByte | X86RegisterView::HighByte => {
                    return Err("IMUL has no byte-register form".to_string());
                }
            }
            Ok(())
        }
        X86Instruction::ImulRegImm { rd, rs, imm } => {
            validate_register_pair(*rd, *rs, 64)?;
            let view = rd.view();
            let rd = reg_index(*rd)?;
            let rs = reg_index(*rs)?;
            match view {
                X86RegisterView::Native => {
                    let imm = signed_imm_i32(*imm)?;
                    dynasm!(ops ; .arch x64 ; imul Rq(rd), Rq(rs), imm);
                }
                X86RegisterView::Dword => {
                    let imm = signed_imm_i32(*imm)?;
                    dynasm!(ops ; .arch x64 ; imul Rd(rd), Rd(rs), imm);
                }
                X86RegisterView::Word => {
                    let imm = imm16_bitpattern_i16(*imm)?;
                    dynasm!(ops ; .arch x64 ; imul Rw(rd), Rw(rs), WORD imm);
                }
                X86RegisterView::LowByte | X86RegisterView::HighByte => {
                    return Err("IMUL has no byte-register form".to_string());
                }
            }
            Ok(())
        }
        X86Instruction::Lea { rd, base, disp } => {
            if base.view() != X86RegisterView::Native {
                return Err(format!(
                    "64-bit LEA address base must be a native register, got {}",
                    base
                ));
            }
            let view = rd.view();
            let rd = reg_index(*rd)?;
            let base = reg_index(*base)?;
            let disp = signed_imm_i32(*disp)?;
            match view {
                X86RegisterView::Native => {
                    dynasm!(ops ; .arch x64 ; lea Rq(rd), [Rq(base) + disp])
                }
                X86RegisterView::Dword => {
                    dynasm!(ops ; .arch x64 ; lea Rd(rd), [Rq(base) + disp])
                }
                X86RegisterView::Word => {
                    dynasm!(ops ; .arch x64 ; lea Rw(rd), [Rq(base) + disp])
                }
                X86RegisterView::LowByte | X86RegisterView::HighByte => {
                    return Err("LEA has no byte-register destination".to_string());
                }
            }
            Ok(())
        }
        X86Instruction::Cmov { rd, rs, cond } => {
            validate_register_pair(*rd, *rs, 64)?;
            let view = rd.view();
            let rd = reg_index(*rd)?;
            let rs = reg_index(*rs)?;
            match view {
                X86RegisterView::Native => {
                    emit_cmov_64_for_family!(ops, cond, Rq, rd, rs)
                }
                X86RegisterView::Dword => {
                    emit_cmov_64_for_family!(ops, cond, Rd, rd, rs)
                }
                X86RegisterView::Word => {
                    emit_cmov_64_for_family!(ops, cond, Rw, rd, rs)
                }
                X86RegisterView::LowByte | X86RegisterView::HighByte => {
                    return Err("CMOV has no byte-register form".to_string());
                }
            }
            Ok(())
        }
        X86Instruction::Setcc { rd, cond } => {
            let rd = reg_index(*rd)?;
            encode_full_width_setcc(ops, rd, *cond, true);
            Ok(())
        }
        X86Instruction::Jcc { cond } => {
            // Short-form Jcc to a 0-byte displacement. The optimizer
            // never patches Jcc bytes into the binary (terminators are
            // pinned), so the placeholder is only exercised by the
            // encoder round-trip tests.
            match cond {
                X86Condition::E => dynasm!(ops ; .arch x64 ; je BYTE 0),
                X86Condition::NE => dynasm!(ops ; .arch x64 ; jne BYTE 0),
                X86Condition::B => dynasm!(ops ; .arch x64 ; jb BYTE 0),
                X86Condition::AE => dynasm!(ops ; .arch x64 ; jae BYTE 0),
                X86Condition::BE => dynasm!(ops ; .arch x64 ; jbe BYTE 0),
                X86Condition::A => dynasm!(ops ; .arch x64 ; ja BYTE 0),
                X86Condition::L => dynasm!(ops ; .arch x64 ; jl BYTE 0),
                X86Condition::GE => dynasm!(ops ; .arch x64 ; jge BYTE 0),
                X86Condition::LE => dynasm!(ops ; .arch x64 ; jle BYTE 0),
                X86Condition::G => dynasm!(ops ; .arch x64 ; jg BYTE 0),
                X86Condition::S => dynasm!(ops ; .arch x64 ; js BYTE 0),
                X86Condition::NS => dynasm!(ops ; .arch x64 ; jns BYTE 0),
                X86Condition::O => dynasm!(ops ; .arch x64 ; jo BYTE 0),
                X86Condition::NO => dynasm!(ops ; .arch x64 ; jno BYTE 0),
                X86Condition::P => dynasm!(ops ; .arch x64 ; jp BYTE 0),
                X86Condition::NP => dynasm!(ops ; .arch x64 ; jnp BYTE 0),
            }
            Ok(())
        }
    }
}

/// Truncate an `i64` immediate down to `i32` for the imm32-form opcodes.
/// Returns an error if the value would not be representable as a
/// sign-extended 32-bit immediate.
fn signed_imm_i32(imm: i64) -> Result<i32, String> {
    i32::try_from(imm).map_err(|_| format!("immediate {} does not fit in 32 bits", imm))
}

/// A shift count encodes as `imm8`. Accept `0..=255` and emit it as the raw
/// byte (dynasm takes the shift count as an `i8`); reject anything that does
/// not fit a single byte. `can_assemble` performs the same check up front, so
/// this is a defensive backstop.
fn shift_count_imm8(imm: i64) -> Result<i8, String> {
    u8::try_from(imm)
        .map(|byte| byte as i8)
        .map_err(|_| format!("shift count {} does not fit in imm8", imm))
}

/// Like [`signed_imm_i32`] but also accepts canonical 32-bit bit patterns.
/// Values in `i32::MIN..=u32::MAX` are reinterpreted as their two's-complement
/// `i32`; this is sound for the 32-bit encoder because immediates are masked to
/// the operand width, so `0xffff_ffff` and `-1` encode identically.
fn imm32_bitpattern_i32(imm: i64) -> Result<i32, String> {
    i32::try_from(imm)
        .or_else(|_| u32::try_from(imm).map(|imm| imm as i32))
        .map_err(|_| format!("immediate {} does not fit in 32 bits", imm))
}

fn imm16_bitpattern_i16(imm: i64) -> Result<i16, String> {
    i16::try_from(imm)
        .or_else(|_| u16::try_from(imm).map(|imm| imm as i16))
        .map_err(|_| format!("immediate {} does not fit in 16 bits", imm))
}

fn imm8_bitpattern_i8(imm: i64) -> Result<i8, String> {
    i8::try_from(imm)
        .or_else(|_| u8::try_from(imm).map(|imm| imm as i8))
        .map_err(|_| format!("immediate {} does not fit in 8 bits", imm))
}

fn encode_32(ops: &mut dynasmrt::x86::Assembler, instr: &X86Instruction) -> Result<(), String> {
    match instr {
        X86Instruction::MovReg { rd, rs } => {
            emit_reg_reg_32!(ops, mov, *rd, *rs);
            Ok(())
        }
        X86Instruction::MovImm { rd, imm } => {
            emit_reg_imm_32!(ops, mov, *rd, *imm);
            Ok(())
        }
        X86Instruction::AddReg { rd, rs } => {
            emit_reg_reg_32!(ops, add, *rd, *rs);
            Ok(())
        }
        X86Instruction::AddImm { rd, imm } => {
            emit_reg_imm_32!(ops, add, *rd, *imm);
            Ok(())
        }
        X86Instruction::SubReg { rd, rs } => {
            emit_reg_reg_32!(ops, sub, *rd, *rs);
            Ok(())
        }
        X86Instruction::SubImm { rd, imm } => {
            emit_reg_imm_32!(ops, sub, *rd, *imm);
            Ok(())
        }
        X86Instruction::AndReg { rd, rs } => {
            emit_reg_reg_32!(ops, and, *rd, *rs);
            Ok(())
        }
        X86Instruction::AndImm { rd, imm } => {
            emit_reg_imm_32!(ops, and, *rd, *imm);
            Ok(())
        }
        X86Instruction::OrReg { rd, rs } => {
            emit_reg_reg_32!(ops, or, *rd, *rs);
            Ok(())
        }
        X86Instruction::OrImm { rd, imm } => {
            emit_reg_imm_32!(ops, or, *rd, *imm);
            Ok(())
        }
        X86Instruction::XorReg { rd, rs } => {
            emit_reg_reg_32!(ops, xor, *rd, *rs);
            Ok(())
        }
        X86Instruction::XorImm { rd, imm } => {
            emit_reg_imm_32!(ops, xor, *rd, *imm);
            Ok(())
        }
        X86Instruction::CmpReg { rn, rs } => {
            emit_reg_reg_32!(ops, cmp, *rn, *rs);
            Ok(())
        }
        X86Instruction::CmpImm { rn, imm } => {
            emit_reg_imm_32!(ops, cmp, *rn, *imm);
            Ok(())
        }
        X86Instruction::TestReg { rn, rs } => {
            emit_reg_reg_32!(ops, test, *rn, *rs);
            Ok(())
        }
        X86Instruction::TestImm { rn, imm } => {
            emit_reg_imm_32!(ops, test, *rn, *imm);
            Ok(())
        }
        X86Instruction::Neg { rd } => {
            emit_unary_32!(ops, neg, *rd);
            Ok(())
        }
        X86Instruction::Not { rd } => {
            emit_unary_32!(ops, not, *rd);
            Ok(())
        }
        X86Instruction::Inc { rd } => {
            emit_unary_32!(ops, inc, *rd);
            Ok(())
        }
        X86Instruction::Dec { rd } => {
            emit_unary_32!(ops, dec, *rd);
            Ok(())
        }
        X86Instruction::Shl { rd, imm } => {
            emit_shift_32!(ops, shl, *rd, *imm);
            Ok(())
        }
        X86Instruction::Shr { rd, imm } => {
            emit_shift_32!(ops, shr, *rd, *imm);
            Ok(())
        }
        X86Instruction::Sar { rd, imm } => {
            emit_shift_32!(ops, sar, *rd, *imm);
            Ok(())
        }
        X86Instruction::Rol { rd, imm } => {
            emit_shift_32!(ops, rol, *rd, *imm);
            Ok(())
        }
        X86Instruction::Ror { rd, imm } => {
            emit_shift_32!(ops, ror, *rd, *imm);
            Ok(())
        }
        X86Instruction::ImulReg { rd, rs } => {
            validate_register_pair(*rd, *rs, 32)?;
            let view = rd.view();
            let rd = reg_index_32(*rd)?;
            let rs = reg_index_32(*rs)?;
            match view {
                X86RegisterView::Native | X86RegisterView::Dword => {
                    dynasm!(ops ; .arch x86 ; imul Rd(rd), Rd(rs))
                }
                X86RegisterView::Word => dynasm!(ops ; .arch x86 ; imul Rw(rd), Rw(rs)),
                X86RegisterView::LowByte | X86RegisterView::HighByte => {
                    return Err("IMUL has no byte-register form".to_string());
                }
            }
            Ok(())
        }
        X86Instruction::ImulRegImm { rd, rs, imm } => {
            validate_register_pair(*rd, *rs, 32)?;
            let view = rd.view();
            let rd = reg_index_32(*rd)?;
            let rs = reg_index_32(*rs)?;
            match view {
                X86RegisterView::Native | X86RegisterView::Dword => {
                    let imm = signed_imm_i32(*imm)?;
                    dynasm!(ops ; .arch x86 ; imul Rd(rd), Rd(rs), imm);
                }
                X86RegisterView::Word => {
                    let imm = imm16_bitpattern_i16(*imm)?;
                    dynasm!(ops ; .arch x86 ; imul Rw(rd), Rw(rs), WORD imm);
                }
                X86RegisterView::LowByte | X86RegisterView::HighByte => {
                    return Err("IMUL has no byte-register form".to_string());
                }
            }
            Ok(())
        }
        X86Instruction::Lea { rd, base, disp } => {
            if base.effective_width(32) != 32 {
                return Err(format!(
                    "32-bit LEA address base must be a 32-bit register, got {}",
                    base
                ));
            }
            let view = rd.view();
            let rd = reg_index_32(*rd)?;
            let base = reg_index_32(*base)?;
            let disp = signed_imm_i32(*disp)?;
            match view {
                X86RegisterView::Native | X86RegisterView::Dword => {
                    dynasm!(ops ; .arch x86 ; lea Rd(rd), [Rd(base) + disp])
                }
                X86RegisterView::Word => {
                    dynasm!(ops ; .arch x86 ; lea Rw(rd), [Rd(base) + disp])
                }
                X86RegisterView::LowByte | X86RegisterView::HighByte => {
                    return Err("LEA has no byte-register destination".to_string());
                }
            }
            Ok(())
        }
        X86Instruction::Cmov { rd, rs, cond } => {
            validate_register_pair(*rd, *rs, 32)?;
            let view = rd.view();
            let rd = reg_index_32(*rd)?;
            let rs = reg_index_32(*rs)?;
            match view {
                X86RegisterView::Native | X86RegisterView::Dword => {
                    emit_cmov_32_for_family!(ops, cond, Rd, rd, rs)
                }
                X86RegisterView::Word => {
                    emit_cmov_32_for_family!(ops, cond, Rw, rd, rs)
                }
                X86RegisterView::LowByte | X86RegisterView::HighByte => {
                    return Err("CMOV has no byte-register form".to_string());
                }
            }
            Ok(())
        }
        X86Instruction::Setcc { rd, cond } => {
            let rd_index = reg_index_32(*rd)?;
            if rd_index >= 4 {
                return Err(format!(
                    "register {:?} has no low-byte encoding in x86-32 mode",
                    rd
                ));
            }
            encode_full_width_setcc(ops, rd_index, *cond, false);
            Ok(())
        }
        X86Instruction::Jcc { cond } => {
            match cond {
                X86Condition::E => dynasm!(ops ; .arch x86 ; je BYTE 0),
                X86Condition::NE => dynasm!(ops ; .arch x86 ; jne BYTE 0),
                X86Condition::B => dynasm!(ops ; .arch x86 ; jb BYTE 0),
                X86Condition::AE => dynasm!(ops ; .arch x86 ; jae BYTE 0),
                X86Condition::BE => dynasm!(ops ; .arch x86 ; jbe BYTE 0),
                X86Condition::A => dynasm!(ops ; .arch x86 ; ja BYTE 0),
                X86Condition::L => dynasm!(ops ; .arch x86 ; jl BYTE 0),
                X86Condition::GE => dynasm!(ops ; .arch x86 ; jge BYTE 0),
                X86Condition::LE => dynasm!(ops ; .arch x86 ; jle BYTE 0),
                X86Condition::G => dynasm!(ops ; .arch x86 ; jg BYTE 0),
                X86Condition::S => dynasm!(ops ; .arch x86 ; js BYTE 0),
                X86Condition::NS => dynasm!(ops ; .arch x86 ; jns BYTE 0),
                X86Condition::O => dynasm!(ops ; .arch x86 ; jo BYTE 0),
                X86Condition::NO => dynasm!(ops ; .arch x86 ; jno BYTE 0),
                X86Condition::P => dynasm!(ops ; .arch x86 ; jp BYTE 0),
                X86Condition::NP => dynasm!(ops ; .arch x86 ; jnp BYTE 0),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capstone::prelude::*;

    fn disasm_x86_64(bytes: &[u8]) -> Vec<(String, String)> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone init");
        let insns = cs.disasm_all(bytes, 0x0).expect("disassemble");
        insns
            .iter()
            .map(|i| {
                (
                    i.mnemonic().unwrap_or("").to_string(),
                    i.op_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn disasm_x86_32(bytes: &[u8]) -> Vec<(String, String)> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone init");
        let insns = cs.disasm_all(bytes, 0x0).expect("disassemble");
        insns
            .iter()
            .map(|i| {
                (
                    i.mnemonic().unwrap_or("").to_string(),
                    i.op_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn check_x86_32(instr: X86Instruction, expected_mnemonic: &str, expect_operands: &[&str]) {
        let mut asm = X86Assembler::new_32();
        let bytes = asm
            .assemble_instructions(&[instr])
            .expect("32-bit encoding succeeds");
        let disasm = disasm_x86_32(&bytes);
        assert_eq!(disasm.len(), 1);
        assert_eq!(
            disasm[0].0, expected_mnemonic,
            "mnemonic mismatch (operands: {})",
            disasm[0].1
        );
        for op in expect_operands {
            assert!(
                disasm[0].1.contains(op),
                "missing operand {} (got: {})",
                op,
                disasm[0].1
            );
        }
    }

    #[test]
    fn movreg_x86_32_uses_eax_form() {
        check_x86_32(
            X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "mov",
            &["eax", "ebx"],
        );
    }

    #[test]
    fn add_imm_x86_32() {
        check_x86_32(
            X86Instruction::AddImm {
                rd: X86Register::RCX,
                imm: 9,
            },
            "add",
            &["ecx", "9"],
        );
    }

    #[test]
    fn x86_32_rejects_extended_register() {
        let mut asm = X86Assembler::new_32();
        let err = asm
            .assemble_instructions(&[X86Instruction::MovReg {
                rd: X86Register::R8,
                rs: X86Register::RAX,
            }])
            .expect_err("R8 not addressable in 32-bit mode");
        assert!(
            err.contains("not available in x86-32"),
            "unexpected error: {}",
            err
        );
    }

    fn check_x86_64(instr: X86Instruction, expected_mnemonic: &str, expect_operands: &[&str]) {
        let mut asm = X86Assembler::new_64();
        let bytes = asm
            .assemble_instructions(&[instr])
            .expect("encoding succeeds");
        let disasm = disasm_x86_64(&bytes);
        assert_eq!(disasm.len(), 1, "expected one instruction");
        assert_eq!(
            disasm[0].0, expected_mnemonic,
            "mnemonic mismatch (operands: {})",
            disasm[0].1
        );
        for op in expect_operands {
            assert!(
                disasm[0].1.contains(op),
                "missing operand {} (got: {})",
                op,
                disasm[0].1
            );
        }
    }

    #[test]
    fn x86_64_emits_each_rax_register_view() {
        for (reg, spelling) in [
            (X86Register::EAX, "eax"),
            (X86Register::AX, "ax"),
            (X86Register::AL, "al"),
            (X86Register::AH, "ah"),
        ] {
            check_x86_64(
                X86Instruction::MovImm { rd: reg, imm: 1 },
                "mov",
                &[spelling, "1"],
            );
        }
        check_x86_64(
            X86Instruction::XorReg {
                rd: X86Register::EAX,
                rs: X86Register::EBX,
            },
            "xor",
            &["eax", "ebx"],
        );
    }

    #[test]
    fn x86_64_round_trips_mixed_legacy_byte_views() {
        for (instruction, mnemonic) in [
            (
                X86Instruction::MovReg {
                    rd: X86Register::AH,
                    rs: X86Register::BL,
                },
                "mov",
            ),
            (
                X86Instruction::AddReg {
                    rd: X86Register::AH,
                    rs: X86Register::BL,
                },
                "add",
            ),
            (
                X86Instruction::SubReg {
                    rd: X86Register::AH,
                    rs: X86Register::BL,
                },
                "sub",
            ),
            (
                X86Instruction::AndReg {
                    rd: X86Register::AH,
                    rs: X86Register::BL,
                },
                "and",
            ),
            (
                X86Instruction::OrReg {
                    rd: X86Register::AH,
                    rs: X86Register::BL,
                },
                "or",
            ),
            (
                X86Instruction::XorReg {
                    rd: X86Register::AH,
                    rs: X86Register::BL,
                },
                "xor",
            ),
            (
                X86Instruction::CmpReg {
                    rn: X86Register::AH,
                    rs: X86Register::BL,
                },
                "cmp",
            ),
            (
                X86Instruction::TestReg {
                    rn: X86Register::AH,
                    rs: X86Register::BL,
                },
                "test",
            ),
        ] {
            check_x86_64(instruction, mnemonic, &["ah", "bl"]);
        }
        check_x86_64(
            X86Instruction::MovReg {
                rd: X86Register::AL,
                rs: X86Register::BH,
            },
            "mov",
            &["al", "bh"],
        );
    }

    #[test]
    fn x86_32_emits_word_and_byte_register_views() {
        for (reg, spelling) in [
            (X86Register::AX, "ax"),
            (X86Register::AL, "al"),
            (X86Register::AH, "ah"),
        ] {
            check_x86_32(
                X86Instruction::MovImm { rd: reg, imm: 1 },
                "mov",
                &[spelling, "1"],
            );
        }
    }

    #[test]
    fn x86_64_rejects_high_byte_when_rex_is_required() {
        let mut asm = X86Assembler::new_64();
        let err = asm
            .assemble_instructions(&[X86Instruction::MovReg {
                rd: X86Register::AH,
                rs: X86Register::SPL,
            }])
            .expect_err("AH cannot be encoded in an instruction requiring REX");
        assert!(err.contains("high-byte"), "unexpected error: {err}");
    }

    #[test]
    fn movimm_x86_64() {
        check_x86_64(
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 42,
            },
            "mov",
            &["rax", "0x2a"],
        );
    }

    #[test]
    fn add_variants_x86_64() {
        check_x86_64(
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "add",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 5,
            },
            "add",
            &["rax", "5"],
        );
    }

    #[test]
    fn sub_variants_x86_64() {
        check_x86_64(
            X86Instruction::SubReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "sub",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::SubImm {
                rd: X86Register::RAX,
                imm: 5,
            },
            "sub",
            &["rax", "5"],
        );
    }

    #[test]
    fn and_or_xor_variants_x86_64() {
        check_x86_64(
            X86Instruction::AndReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "and",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::OrReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "or",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::XorReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "xor",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::AndImm {
                rd: X86Register::RAX,
                imm: 0xff,
            },
            "and",
            &["rax", "0xff"],
        );
        check_x86_64(
            X86Instruction::OrImm {
                rd: X86Register::RAX,
                imm: 1,
            },
            "or",
            &["rax", "1"],
        );
        check_x86_64(
            X86Instruction::XorImm {
                rd: X86Register::RAX,
                imm: 1,
            },
            "xor",
            &["rax", "1"],
        );
    }

    #[test]
    fn cmp_variants_x86_64() {
        check_x86_64(
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "cmp",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 7,
            },
            "cmp",
            &["rax", "7"],
        );
    }

    #[test]
    fn test_variants_x86_64() {
        check_x86_64(
            X86Instruction::TestReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "test",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::TestImm {
                rn: X86Register::RAX,
                imm: 5,
            },
            "test",
            &["rax", "5"],
        );
    }

    #[test]
    fn test_variants_x86_32() {
        check_x86_32(
            X86Instruction::TestReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "test",
            &["eax", "ebx"],
        );
        check_x86_32(
            X86Instruction::TestImm {
                rn: X86Register::RAX,
                imm: 5,
            },
            "test",
            &["eax", "5"],
        );
    }

    #[test]
    fn neg_not_variants_x86_64() {
        check_x86_64(
            X86Instruction::Neg {
                rd: X86Register::RAX,
            },
            "neg",
            &["rax"],
        );
        check_x86_64(
            X86Instruction::Not {
                rd: X86Register::RBX,
            },
            "not",
            &["rbx"],
        );
    }

    #[test]
    fn neg_not_variants_x86_32() {
        check_x86_32(
            X86Instruction::Neg {
                rd: X86Register::RAX,
            },
            "neg",
            &["eax"],
        );
        check_x86_32(
            X86Instruction::Not {
                rd: X86Register::RBX,
            },
            "not",
            &["ebx"],
        );
    }

    #[test]
    fn inc_dec_variants_x86_64() {
        check_x86_64(
            X86Instruction::Inc {
                rd: X86Register::RAX,
            },
            "inc",
            &["rax"],
        );
        check_x86_64(
            X86Instruction::Dec {
                rd: X86Register::RBX,
            },
            "dec",
            &["rbx"],
        );
    }

    #[test]
    fn inc_dec_variants_x86_32() {
        check_x86_32(
            X86Instruction::Inc {
                rd: X86Register::RAX,
            },
            "inc",
            &["eax"],
        );
        check_x86_32(
            X86Instruction::Dec {
                rd: X86Register::RBX,
            },
            "dec",
            &["ebx"],
        );
    }

    #[test]
    fn shift_variants_x86_64() {
        check_x86_64(
            X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 1,
            },
            "shl",
            &["rax", "1"],
        );
        check_x86_64(
            X86Instruction::Shr {
                rd: X86Register::RBX,
                imm: 3,
            },
            "shr",
            &["rbx", "3"],
        );
        check_x86_64(
            X86Instruction::Sar {
                rd: X86Register::RCX,
                imm: 7,
            },
            "sar",
            &["rcx", "7"],
        );
    }

    #[test]
    fn shift_variants_x86_32() {
        check_x86_32(
            X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 2,
            },
            "shl",
            &["eax", "2"],
        );
        check_x86_32(
            X86Instruction::Sar {
                rd: X86Register::RBX,
                imm: 4,
            },
            "sar",
            &["ebx", "4"],
        );
    }

    #[test]
    fn rotate_variants_x86_64() {
        check_x86_64(
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 1,
            },
            "rol",
            &["rax", "1"],
        );
        check_x86_64(
            X86Instruction::Ror {
                rd: X86Register::RBX,
                imm: 5,
            },
            "ror",
            &["rbx", "5"],
        );
        // Extended register round-trips too.
        check_x86_64(
            X86Instruction::Rol {
                rd: X86Register::R9,
                imm: 7,
            },
            "rol",
            &["r9", "7"],
        );
    }

    #[test]
    fn rotate_variants_x86_32() {
        check_x86_32(
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 2,
            },
            "rol",
            &["eax", "2"],
        );
        check_x86_32(
            X86Instruction::Ror {
                rd: X86Register::RDX,
                imm: 4,
            },
            "ror",
            &["edx", "4"],
        );
    }

    #[test]
    fn imul_variants_x86_64() {
        // Two-operand `imul rd, rs` (0F AF /r).
        check_x86_64(
            X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "imul",
            &["rax", "rbx"],
        );
        // Three-operand `imul rd, rs, imm` (69 /r id).
        check_x86_64(
            X86Instruction::ImulRegImm {
                rd: X86Register::RCX,
                rs: X86Register::RDX,
                imm: 4,
            },
            "imul",
            &["rcx", "rdx", "4"],
        );
        // Extended register source round-trips too.
        check_x86_64(
            X86Instruction::ImulReg {
                rd: X86Register::R9,
                rs: X86Register::RAX,
            },
            "imul",
            &["r9", "rax"],
        );
    }

    #[test]
    fn imul_variants_x86_32() {
        check_x86_32(
            X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "imul",
            &["eax", "ebx"],
        );
        check_x86_32(
            X86Instruction::ImulRegImm {
                rd: X86Register::RCX,
                rs: X86Register::RDX,
                imm: 7,
            },
            "imul",
            &["ecx", "edx", "7"],
        );
    }

    // LEA `rd, [base + disp]` (8D /r). Capstone may canonicalize the disp
    // formatting (hex, sign placement), so we assert the mnemonic is `lea` and
    // the operand string mentions the destination and base registers plus the
    // displacement magnitude — robust against `1` vs `0x1` rendering.
    #[test]
    fn lea_variants_x86_64() {
        // Bare base (disp == 0).
        check_x86_64(
            X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: 0,
            },
            "lea",
            &["rax", "rbx"],
        );
        // Positive displacement.
        check_x86_64(
            X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: 0x10,
            },
            "lea",
            &["rax", "rbx", "0x10"],
        );
        // Extended base register round-trips.
        check_x86_64(
            X86Instruction::Lea {
                rd: X86Register::R9,
                base: X86Register::RAX,
                disp: 1,
            },
            "lea",
            &["r9", "rax"],
        );
    }

    #[test]
    fn lea_variants_x86_32() {
        check_x86_32(
            X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: 0,
            },
            "lea",
            &["eax", "ebx"],
        );
        check_x86_32(
            X86Instruction::Lea {
                rd: X86Register::RCX,
                base: X86Register::RDX,
                disp: 0x20,
            },
            "lea",
            &["ecx", "edx", "0x20"],
        );
    }

    // SAL and SHL assemble to identical bytes; Capstone disassembles the
    // encoding as `shl`. The IR has no Sal variant (the parser folds `sal`
    // into `Shl`), so we assert the `Shl` encoding round-trips as `shl`.
    #[test]
    fn shl_encoding_disassembles_as_shl_not_sal() {
        check_x86_64(
            X86Instruction::Shl {
                rd: X86Register::RDX,
                imm: 5,
            },
            "shl",
            &["rdx", "5"],
        );
    }

    #[test]
    fn movreg_with_extended_register_r9() {
        check_x86_64(
            X86Instruction::MovReg {
                rd: X86Register::R9,
                rs: X86Register::RAX,
            },
            "mov",
            &["r9", "rax"],
        );
    }

    #[test]
    fn movreg_x86_64_round_trips_through_capstone() {
        let mut asm = X86Assembler::new_64();
        let bytes = asm
            .assemble_instructions(&[X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            }])
            .expect("encode mov rax, rbx");
        let disasm = disasm_x86_64(&bytes);
        assert_eq!(disasm.len(), 1);
        assert_eq!(disasm[0].0, "mov");
        // Capstone produces "rax, rbx" (Intel syntax).
        assert!(
            disasm[0].1.contains("rax") && disasm[0].1.contains("rbx"),
            "operands: {}",
            disasm[0].1
        );
    }

    #[test]
    fn x86_32_encodes_all_minimal_variants() {
        let cases = [
            (
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "mov",
            ),
            (
                X86Instruction::AddReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "add",
            ),
            (
                X86Instruction::SubReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "sub",
            ),
            (
                X86Instruction::SubImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "sub",
            ),
            (
                X86Instruction::AndReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "and",
            ),
            (
                X86Instruction::AndImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "and",
            ),
            (
                X86Instruction::OrReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "or",
            ),
            (
                X86Instruction::OrImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "or",
            ),
            (
                X86Instruction::XorReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "xor",
            ),
            (
                X86Instruction::XorImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "xor",
            ),
            (
                X86Instruction::CmpReg {
                    rn: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "cmp",
            ),
            (
                X86Instruction::CmpImm {
                    rn: X86Register::RAX,
                    imm: 1,
                },
                "cmp",
            ),
        ];

        for (instr, mnemonic) in cases {
            let mut asm = X86Assembler::new_32();
            let bytes = asm
                .assemble_instructions(&[instr])
                .unwrap_or_else(|e| panic!("{:?} should encode: {}", instr, e));
            let disasm = disasm_x86_32(&bytes);
            assert_eq!(disasm[0].0, mnemonic);
        }
    }

    #[test]
    fn x86_32_accepts_canonical_high_bit_imm32_values() {
        // u32::MAX is a canonical 32-bit bit pattern; the encoder reinterprets
        // it as -1, so each form disassembles back to the 0xffffffff operand.
        check_x86_32(
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: i64::from(u32::MAX),
            },
            "mov",
            &["eax", "0xffffffff"],
        );
        check_x86_32(
            X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: i64::from(u32::MAX),
            },
            "add",
            &["eax", "0xffffffff"],
        );
        check_x86_32(
            X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: i64::from(u32::MAX),
            },
            "cmp",
            &["eax", "0xffffffff"],
        );
    }

    #[test]
    fn x86_64_movabs_and_immediate_range_errors() {
        let mut asm = X86Assembler::new_64();
        let bytes = asm
            .assemble_instructions(&[X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: i64::MAX,
            }])
            .expect("movabs should encode full-width immediate");
        let disasm = disasm_x86_64(&bytes);
        assert_eq!(disasm[0].0, "movabs");

        let err = asm
            .assemble_instructions(&[X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: i64::MAX,
            }])
            .expect_err("imm32-only arithmetic should reject i64::MAX");
        assert!(err.contains("does not fit in 32 bits"));

        let mut asm32 = X86Assembler::new_32();
        let err = asm32
            .assemble_instructions(&[X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: i64::MAX,
            }])
            .expect_err("x86-32 mov imm requires imm32");
        assert!(err.contains("does not fit in 32 bits"));
    }

    #[test]
    fn movimm_code_size_is_upper_bound_on_assembled_length() {
        // Cross-layer guard (issue #225): the CodeSize cost model must never
        // underestimate the assembler's real MovImm encoding, or length-based
        // search pruning becomes unsound. Assemble boundary immediates and
        // assert cost >= actual bytes for both modes.
        use crate::semantics::cost::CostMetric;
        use crate::semantics::cost_x86::instruction_cost;

        let mut a64 = X86Assembler::new_64();
        for imm in [
            0i64,
            1,
            -1,
            i32::MAX as i64,
            i32::MIN as i64,
            i64::MAX,
            i64::MIN,
        ] {
            let instr = X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm,
            };
            let bytes = a64.assemble_instructions(&[instr]).unwrap();
            let cost = instruction_cost(&instr, &CostMetric::CodeSize, 64);
            assert!(
                cost >= bytes.len() as u64,
                "x64 MovImm cost {cost} < assembled {} for imm {imm}",
                bytes.len()
            );
        }

        let mut a32 = X86Assembler::new_32();
        for imm in [0i64, 1, -1, i32::MAX as i64, i32::MIN as i64] {
            let instr = X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm,
            };
            let bytes = a32.assemble_instructions(&[instr]).unwrap();
            let cost = instruction_cost(&instr, &CostMetric::CodeSize, 32);
            assert!(
                cost >= bytes.len() as u64,
                "x86-32 MovImm cost {cost} < assembled {} for imm {imm}",
                bytes.len()
            );
        }
    }

    #[test]
    fn setcc_code_size_matches_assembled_length() {
        use crate::semantics::cost::CostMetric;
        use crate::semantics::cost_x86::instruction_cost;

        for cond in X86Condition::ALL {
            for rd in [X86Register::RAX, X86Register::RSP, X86Register::R8] {
                let instr = X86Instruction::Setcc { rd, cond };
                let bytes = X86Assembler::new_64()
                    .assemble_instructions(&[instr])
                    .expect("x86-64 SETcc lowering");
                assert_eq!(
                    instruction_cost(&instr, &CostMetric::CodeSize, 64),
                    bytes.len() as u64,
                    "x86-64 SET{} {rd:?} cost must match assembled bytes",
                    cond.suffix()
                );
            }

            let instr = X86Instruction::Setcc {
                rd: X86Register::RAX,
                cond,
            };
            let bytes = X86Assembler::new_32()
                .assemble_instructions(&[instr])
                .expect("x86-32 SETcc lowering");
            assert_eq!(
                instruction_cost(&instr, &CostMetric::CodeSize, 32),
                bytes.len() as u64,
                "x86-32 SET{} cost must match assembled bytes",
                cond.suffix()
            );
        }
    }

    // --- SETcc / CMOV encoding round-trips through Capstone ---

    #[test]
    fn all_setcc_suffixes_lower_to_setcc_movzx_in_both_x86_modes() {
        for cond in X86Condition::ALL {
            let mnemonic = cond.set_mnemonic();
            let instr = X86Instruction::Setcc {
                rd: X86Register::RAX,
                cond,
            };

            let bytes64 = X86Assembler::new_64()
                .assemble_instructions(&[instr])
                .expect("x86-64 SETcc lowering");
            assert_eq!(bytes64.len(), 6, "unexpected x86-64 {mnemonic} size");
            assert_eq!(
                disasm_x86_64(&bytes64),
                vec![
                    (mnemonic.to_string(), "al".to_string()),
                    ("movzx".to_string(), "eax, al".to_string()),
                ],
                "unexpected x86-64 {mnemonic} lowering"
            );

            let bytes32 = X86Assembler::new_32()
                .assemble_instructions(&[instr])
                .expect("x86-32 SETcc lowering");
            assert_eq!(bytes32.len(), 6, "unexpected x86-32 {mnemonic} size");
            assert_eq!(
                disasm_x86_32(&bytes32),
                vec![
                    (mnemonic.to_string(), "al".to_string()),
                    ("movzx".to_string(), "eax, al".to_string()),
                ],
                "unexpected x86-32 {mnemonic} lowering"
            );
        }
    }

    #[test]
    fn setcc_x86_64_encodes_rex_low_byte_registers() {
        for (rd, byte_name, dword_name) in [
            (X86Register::RSP, "spl", "esp"),
            (X86Register::R8, "r8b", "r8d"),
        ] {
            let bytes = X86Assembler::new_64()
                .assemble_instructions(&[X86Instruction::Setcc {
                    rd,
                    cond: X86Condition::NE,
                }])
                .expect("REX byte-register SETcc lowering");
            assert_eq!(bytes.len(), 8, "unexpected {rd:?} SETcc lowering size");
            assert_eq!(
                disasm_x86_64(&bytes),
                vec![
                    ("setne".to_string(), byte_name.to_string()),
                    ("movzx".to_string(), format!("{dword_name}, {byte_name}"),),
                ],
                "SETcc and MOVZX must use the same logical register"
            );
        }
    }

    #[test]
    fn cmove_x86_64_round_trips() {
        check_x86_64(
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            },
            "cmove",
            &["rax", "rbx"],
        );
    }

    #[test]
    fn all_cmov_suffixes_round_trip_x86_64() {
        let cases = [
            (X86Condition::E, "cmove"),
            (X86Condition::NE, "cmovne"),
            (X86Condition::B, "cmovb"),
            (X86Condition::AE, "cmovae"),
            (X86Condition::BE, "cmovbe"),
            (X86Condition::A, "cmova"),
            (X86Condition::L, "cmovl"),
            (X86Condition::GE, "cmovge"),
            (X86Condition::LE, "cmovle"),
            (X86Condition::G, "cmovg"),
            (X86Condition::S, "cmovs"),
            (X86Condition::NS, "cmovns"),
            (X86Condition::O, "cmovo"),
            (X86Condition::NO, "cmovno"),
            (X86Condition::P, "cmovp"),
            (X86Condition::NP, "cmovnp"),
        ];
        for (cond, mn) in cases {
            check_x86_64(
                X86Instruction::Cmov {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    cond,
                },
                mn,
                &["rax", "rbx"],
            );
        }
    }

    #[test]
    fn all_cmov_suffixes_round_trip_x86_32() {
        let cases = [
            (X86Condition::E, "cmove"),
            (X86Condition::NE, "cmovne"),
            (X86Condition::B, "cmovb"),
            (X86Condition::AE, "cmovae"),
            (X86Condition::BE, "cmovbe"),
            (X86Condition::A, "cmova"),
            (X86Condition::L, "cmovl"),
            (X86Condition::GE, "cmovge"),
            (X86Condition::LE, "cmovle"),
            (X86Condition::G, "cmovg"),
            (X86Condition::S, "cmovs"),
            (X86Condition::NS, "cmovns"),
            (X86Condition::O, "cmovo"),
            (X86Condition::NO, "cmovno"),
            (X86Condition::P, "cmovp"),
            (X86Condition::NP, "cmovnp"),
        ];
        for (cond, mn) in cases {
            check_x86_32(
                X86Instruction::Cmov {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    cond,
                },
                mn,
                &["eax", "ebx"],
            );
        }
    }

    // --- Jcc short-form encoding ---

    #[test]
    fn je_x86_64_encodes_to_short_form_je() {
        // Short je with rel8=0 is bytes 0x74 0x00.
        let mut asm = X86Assembler::new_64();
        let bytes = asm
            .assemble_instructions(&[X86Instruction::Jcc {
                cond: X86Condition::E,
            }])
            .expect("encode je");
        let disasm = disasm_x86_64(&bytes);
        assert_eq!(disasm.len(), 1);
        assert_eq!(disasm[0].0, "je", "got {} {}", disasm[0].0, disasm[0].1);
    }

    #[test]
    fn all_jcc_suffixes_round_trip_x86_64() {
        let cases = [
            (X86Condition::E, "je"),
            (X86Condition::NE, "jne"),
            (X86Condition::B, "jb"),
            (X86Condition::AE, "jae"),
            (X86Condition::BE, "jbe"),
            (X86Condition::A, "ja"),
            (X86Condition::L, "jl"),
            (X86Condition::GE, "jge"),
            (X86Condition::LE, "jle"),
            (X86Condition::G, "jg"),
            (X86Condition::S, "js"),
            (X86Condition::NS, "jns"),
            (X86Condition::O, "jo"),
            (X86Condition::NO, "jno"),
            (X86Condition::P, "jp"),
            (X86Condition::NP, "jnp"),
        ];
        for (cond, mn) in cases {
            let mut asm = X86Assembler::new_64();
            let bytes = asm
                .assemble_instructions(&[X86Instruction::Jcc { cond }])
                .unwrap_or_else(|e| panic!("encode {}: {}", mn, e));
            let disasm = disasm_x86_64(&bytes);
            assert_eq!(disasm.len(), 1, "expected one instr for {}", mn);
            assert_eq!(disasm[0].0, mn);
        }
    }

    #[test]
    fn all_jcc_suffixes_round_trip_x86_32() {
        let cases = [
            (X86Condition::E, "je"),
            (X86Condition::NE, "jne"),
            (X86Condition::B, "jb"),
            (X86Condition::AE, "jae"),
            (X86Condition::BE, "jbe"),
            (X86Condition::A, "ja"),
            (X86Condition::L, "jl"),
            (X86Condition::GE, "jge"),
            (X86Condition::LE, "jle"),
            (X86Condition::G, "jg"),
            (X86Condition::S, "js"),
            (X86Condition::NS, "jns"),
            (X86Condition::O, "jo"),
            (X86Condition::NO, "jno"),
            (X86Condition::P, "jp"),
            (X86Condition::NP, "jnp"),
        ];
        for (cond, mn) in cases {
            let mut asm = X86Assembler::new_32();
            let bytes = asm
                .assemble_instructions(&[X86Instruction::Jcc { cond }])
                .unwrap_or_else(|e| panic!("encode {}: {}", mn, e));
            let disasm = disasm_x86_32(&bytes);
            assert_eq!(disasm.len(), 1, "expected one instr for {}", mn);
            assert_eq!(disasm[0].0, mn);
        }
    }
}
