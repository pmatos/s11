pub mod x86;

use crate::ir::aarch64_encoding::logical_imm64_encodable;
use crate::ir::instructions::logical_imm32_value;
use crate::ir::types::{
    AccessWidth, AddressOperand, Condition, ExtendKind, IndexMode, LabelId, ShiftKind,
};
use crate::ir::{Instruction, Operand, Register, RegisterWidth};
use dynasmrt::{DynasmApi, dynasm};

/// Emits one of the four CSEL-family mnemonics with the given register
/// indices and a runtime `Condition` value. dynasm-rs requires the condition
/// suffix to be a compile-time literal, so we dispatch via a 16-arm match.
macro_rules! emit_csel {
    ($ops:expr, $mnem:ident, $rd:expr, $rn:expr, $rm:expr, $cond:expr) => {{
        match $cond {
            Condition::EQ => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), eq),
            Condition::NE => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), ne),
            Condition::CS => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), cs),
            Condition::CC => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), cc),
            Condition::MI => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), mi),
            Condition::PL => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), pl),
            Condition::VS => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), vs),
            Condition::VC => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), vc),
            Condition::HI => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), hi),
            Condition::LS => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), ls),
            Condition::GE => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), ge),
            Condition::LT => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), lt),
            Condition::GT => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), gt),
            Condition::LE => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), le),
            Condition::AL => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), al),
            Condition::NV => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), nv),
        }
    }};
}

/// Emit a 3-operand arithmetic shifted-register instruction (Add/Sub) of the
/// form `<mnem> X(rd), X(rn), X(rm), <kind> #amt`. ROR is rejected here because
/// the AArch64 ADD/SUB shifted-register encoding does not accept ROR — see ARM
/// ARM. `is_encodable_aarch64` already screens this out; the Err is defensive.
macro_rules! emit_shifted_reg_3op_arith {
    ($ops:expr, $mnem:ident, $rd:expr, $rn:expr, $rm:expr, $kind:expr, $amt:expr) => {{
        let rd_n: u8 = $rd;
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let amt_n: u32 = ($amt) as u32;
        match $kind {
            ShiftKind::Lsl => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), LSL amt_n);
                Ok(())
            }
            ShiftKind::Lsr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), LSR amt_n);
                Ok(())
            }
            ShiftKind::Asr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), ASR amt_n);
                Ok(())
            }
            ShiftKind::Ror => Err(format!(
                "{} cannot use ROR shift (rejected by is_encodable_aarch64)",
                stringify!($mnem)
            )),
        }
    }};
}

macro_rules! emit_shifted_reg_3op_arith_w {
    ($ops:expr, $mnem:ident, $rd:expr, $rn:expr, $rm:expr, $kind:expr, $amt:expr) => {{
        let rd_n: u8 = $rd;
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let amt_n: u32 = ($amt) as u32;
        match $kind {
            ShiftKind::Lsl => {
                dynasm!($ops ; .arch aarch64 ; $mnem W(rd_n), W(rn_n), W(rm_n), LSL amt_n);
                Ok(())
            }
            ShiftKind::Lsr => {
                dynasm!($ops ; .arch aarch64 ; $mnem W(rd_n), W(rn_n), W(rm_n), LSR amt_n);
                Ok(())
            }
            ShiftKind::Asr => {
                dynasm!($ops ; .arch aarch64 ; $mnem W(rd_n), W(rn_n), W(rm_n), ASR amt_n);
                Ok(())
            }
            ShiftKind::Ror => Err(format!(
                "{} cannot use ROR shift (rejected by is_encodable_aarch64)",
                stringify!($mnem)
            )),
        }
    }};
}

/// 3-operand logical shifted-register instruction (And/Orr/Eor) — accepts all
/// four ShiftKinds including ROR.
macro_rules! emit_shifted_reg_3op_logical {
    ($ops:expr, $mnem:ident, $rd:expr, $rn:expr, $rm:expr, $kind:expr, $amt:expr) => {{
        let rd_n: u8 = $rd;
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let amt_n: u32 = ($amt) as u32;
        match $kind {
            ShiftKind::Lsl => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), LSL amt_n);
                Ok(())
            }
            ShiftKind::Lsr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), LSR amt_n);
                Ok(())
            }
            ShiftKind::Asr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), ASR amt_n);
                Ok(())
            }
            ShiftKind::Ror => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), ROR amt_n);
                Ok(())
            }
        }
    }};
}

/// 2-operand arithmetic shifted-register form (Cmp/Cmn) — no ROR.
macro_rules! emit_shifted_reg_2op_arith {
    ($ops:expr, $mnem:ident, $rn:expr, $rm:expr, $kind:expr, $amt:expr) => {{
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let amt_n: u32 = ($amt) as u32;
        match $kind {
            ShiftKind::Lsl => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), LSL amt_n);
                Ok(())
            }
            ShiftKind::Lsr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), LSR amt_n);
                Ok(())
            }
            ShiftKind::Asr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), ASR amt_n);
                Ok(())
            }
            ShiftKind::Ror => Err(format!(
                "{} cannot use ROR shift (rejected by is_encodable_aarch64)",
                stringify!($mnem)
            )),
        }
    }};
}

/// 2-operand logical shifted-register form (Tst) — accepts all four kinds.
macro_rules! emit_shifted_reg_2op_logical {
    ($ops:expr, $mnem:ident, $rn:expr, $rm:expr, $kind:expr, $amt:expr) => {{
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let amt_n: u32 = ($amt) as u32;
        match $kind {
            ShiftKind::Lsl => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), LSL amt_n);
                Ok(())
            }
            ShiftKind::Lsr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), LSR amt_n);
                Ok(())
            }
            ShiftKind::Asr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), ASR amt_n);
                Ok(())
            }
            ShiftKind::Ror => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), ROR amt_n);
                Ok(())
            }
        }
    }};
}

/// 3-operand extended-register form (ADD/SUB only — logical opcodes do not
/// accept ExtendedRegister per ARM ARM). The Rd/Rn slot is `Xn|SP` (XSP in
/// dynasm-rs); the Rm slot is W-form for byte/half/word extends and X-form
/// for the 64-bit extends (UXTX/SXTX). Issue #60.
macro_rules! emit_extended_reg_3op_arith {
    ($ops:expr, $mnem:ident, $rd:expr, $rn:expr, $rm:expr, $kind:expr, $shift:expr) => {{
        let rd_n: u8 = $rd;
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let shift_n: u32 = ($shift) as u32;
        match $kind {
            ExtendKind::Uxtb => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rd_n), XSP(rn_n), W(rm_n), UXTB shift_n);
                Ok(())
            }
            ExtendKind::Uxth => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rd_n), XSP(rn_n), W(rm_n), UXTH shift_n);
                Ok(())
            }
            ExtendKind::Uxtw => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rd_n), XSP(rn_n), W(rm_n), UXTW shift_n);
                Ok(())
            }
            ExtendKind::Uxtx => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rd_n), XSP(rn_n), X(rm_n), UXTX shift_n);
                Ok(())
            }
            ExtendKind::Sxtb => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rd_n), XSP(rn_n), W(rm_n), SXTB shift_n);
                Ok(())
            }
            ExtendKind::Sxth => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rd_n), XSP(rn_n), W(rm_n), SXTH shift_n);
                Ok(())
            }
            ExtendKind::Sxtw => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rd_n), XSP(rn_n), W(rm_n), SXTW shift_n);
                Ok(())
            }
            ExtendKind::Sxtx => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rd_n), XSP(rn_n), X(rm_n), SXTX shift_n);
                Ok(())
            }
        }
    }};
}

/// 2-operand extended-register form (CMP/CMN). The Rn slot is `Xn|SP` (XSP).
/// Issue #60.
macro_rules! emit_extended_reg_2op_arith {
    ($ops:expr, $mnem:ident, $rn:expr, $rm:expr, $kind:expr, $shift:expr) => {{
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let shift_n: u32 = ($shift) as u32;
        match $kind {
            ExtendKind::Uxtb => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rn_n), W(rm_n), UXTB shift_n);
                Ok(())
            }
            ExtendKind::Uxth => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rn_n), W(rm_n), UXTH shift_n);
                Ok(())
            }
            ExtendKind::Uxtw => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rn_n), W(rm_n), UXTW shift_n);
                Ok(())
            }
            ExtendKind::Uxtx => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rn_n), X(rm_n), UXTX shift_n);
                Ok(())
            }
            ExtendKind::Sxtb => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rn_n), W(rm_n), SXTB shift_n);
                Ok(())
            }
            ExtendKind::Sxth => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rn_n), W(rm_n), SXTH shift_n);
                Ok(())
            }
            ExtendKind::Sxtw => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rn_n), W(rm_n), SXTW shift_n);
                Ok(())
            }
            ExtendKind::Sxtx => {
                dynasm!($ops ; .arch aarch64 ; $mnem XSP(rn_n), X(rm_n), SXTX shift_n);
                Ok(())
            }
        }
    }};
}

/// CCMP/CCMN reg form: `ccmp Xn, Xm, #nzcv, cond`. The condition suffix
/// must be a compile-time literal for dynasm-rs, so we expand 14 condition
/// arms; `$nzcv` is bound to a `u32`-cast value once at the top so the
/// dynasm `#` literal slot accepts it at emit time. AL and NV are forbidden
/// by `is_encodable_aarch64` and excluded from the macro arms.
macro_rules! emit_ccmp_reg {
    ($ops:expr, $mnem:ident, $rn:expr, $rm:expr, $nzcv:expr, $cond:expr) => {{
        let n = $nzcv as u32;
        match $cond {
            Condition::EQ => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, eq),
            Condition::NE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, ne),
            Condition::CS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, cs),
            Condition::CC => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, cc),
            Condition::MI => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, mi),
            Condition::PL => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, pl),
            Condition::VS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, vs),
            Condition::VC => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, vc),
            Condition::HI => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, hi),
            Condition::LS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, ls),
            Condition::GE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, ge),
            Condition::LT => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, lt),
            Condition::GT => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, gt),
            Condition::LE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, le),
            Condition::AL | Condition::NV => {
                return Err("CCMP/CCMN forbid AL/NV per ARM ARM C6.2.36".to_string());
            }
        }
    }};
}

/// CCMP/CCMN immediate form: `ccmp Xn, #imm5, #nzcv, cond`.
macro_rules! emit_ccmp_imm {
    ($ops:expr, $mnem:ident, $rn:expr, $imm5:expr, $nzcv:expr, $cond:expr) => {{
        let i = $imm5 as u32;
        let n = $nzcv as u32;
        match $cond {
            Condition::EQ => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, eq),
            Condition::NE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, ne),
            Condition::CS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, cs),
            Condition::CC => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, cc),
            Condition::MI => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, mi),
            Condition::PL => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, pl),
            Condition::VS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, vs),
            Condition::VC => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, vc),
            Condition::HI => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, hi),
            Condition::LS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, ls),
            Condition::GE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, ge),
            Condition::LT => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, lt),
            Condition::GT => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, gt),
            Condition::LE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, le),
            Condition::AL | Condition::NV => {
                return Err("CCMP/CCMN forbid AL/NV per ARM ARM C6.2.36".to_string());
            }
        }
    }};
}

// ===== Memory-op encoder macros (issue #68 / ADR-0007) =====
//
// dynasm requires the register form (X / W), the modifier kind
// (LSL / UXTW / SXTW / UXTX / SXTX), and the mnemonic itself to be
// compile-time tokens. The macros below expand to a single dynasm! call
// per addressing mode and accept the mnemonic + rt register form as
// `ident` parameters so the encoder can dispatch on width without
// duplicating the entire dynasm! invocation.

/// `[base]` and `[base, #imm]` (positive scaled offset, dynasm `RefOffset`
/// uses `Uscaled` → `u32`). The caller is responsible for routing negative
/// / unscaled offsets to the LDUR-family macro below; the cast assumes the
/// offset has already passed `can_use_scaled_offset`.
macro_rules! emit_mem_imm_offset {
    ($ops:expr, $mnem:ident, $rt_tok:ident, $rt:expr, $base:expr, $offset:expr) => {{
        let rt_n: u8 = $rt;
        let base_n: u8 = $base;
        let off: u32 = $offset as u32;
        if off == 0 {
            dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n)]);
        } else {
            dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), off]);
        }
    }};
}

/// LDUR / STUR-family (unscaled signed 9-bit). Used when the offset is
/// negative or not divisible by the access width.
macro_rules! emit_mem_imm_unscaled {
    ($ops:expr, $mnem:ident, $rt_tok:ident, $rt:expr, $base:expr, $offset:expr) => {{
        let rt_n: u8 = $rt;
        let base_n: u8 = $base;
        let off: i32 = $offset;
        dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), off]);
    }};
}

/// `[base, #imm]!` — pre-index writeback.
macro_rules! emit_mem_imm_preindex {
    ($ops:expr, $mnem:ident, $rt_tok:ident, $rt:expr, $base:expr, $offset:expr) => {{
        let rt_n: u8 = $rt;
        let base_n: u8 = $base;
        let off: i32 = $offset;
        dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), off]!);
    }};
}

/// `[base], #imm` — post-index writeback.
macro_rules! emit_mem_imm_postindex {
    ($ops:expr, $mnem:ident, $rt_tok:ident, $rt:expr, $base:expr, $offset:expr) => {{
        let rt_n: u8 = $rt;
        let base_n: u8 = $base;
        let off: i32 = $offset;
        dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n)], off);
    }};
}

/// `[base, X(idx)]` and `[base, X(idx), LSL #shift]`. dynasm encodes the
/// shift modifier; `shift` is the raw LSL amount (0 or `log2(access_bytes)`).
macro_rules! emit_mem_reg {
    ($ops:expr, $mnem:ident, $rt_tok:ident, $rt:expr, $base:expr, $idx:expr, $shift:expr) => {{
        let rt_n: u8 = $rt;
        let base_n: u8 = $base;
        let idx_n: u8 = $idx;
        let shift_n: u32 = $shift as u32;
        if shift_n == 0 {
            dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), X(idx_n)]);
        } else {
            dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), X(idx_n), LSL shift_n]);
        }
    }};
}

/// `[base, W/X(idx), UXTW/SXTW/UXTX/SXTX{, #shift}]`. UXTB/UXTH/SXTB/SXTH
/// are rejected by `is_encodable_aarch64`; the macro errors at the catch-all
/// arm for defensive depth.
macro_rules! emit_mem_ext {
    ($ops:expr, $mnem:ident, $rt_tok:ident, $rt:expr, $base:expr, $idx:expr, $kind:expr, $shift:expr) => {{
        let rt_n: u8 = $rt;
        let base_n: u8 = $base;
        let idx_n: u8 = $idx;
        let shift_n: u32 = $shift as u32;
        match $kind {
            ExtendKind::Uxtw => {
                if shift_n == 0 {
                    dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), W(idx_n), UXTW]);
                } else {
                    dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), W(idx_n), UXTW shift_n]);
                }
                Ok::<(), String>(())
            }
            ExtendKind::Sxtw => {
                if shift_n == 0 {
                    dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), W(idx_n), SXTW]);
                } else {
                    dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), W(idx_n), SXTW shift_n]);
                }
                Ok::<(), String>(())
            }
            ExtendKind::Sxtx => {
                if shift_n == 0 {
                    dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), X(idx_n), SXTX]);
                } else {
                    dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), X(idx_n), SXTX shift_n]);
                }
                Ok::<(), String>(())
            }
            // UXTX on an X-form index is architecturally equivalent to LSL
            // (both select option=011 in the LDR-register encoding). dynasm
            // disallows the UXTX token for memory operands but accepts the
            // bare/LSL form, so dispatch through that. Mirrors GNU `as`,
            // which silently rewrites `[Xn, Xm, UXTX]` to `[Xn, Xm]`.
            ExtendKind::Uxtx => {
                if shift_n == 0 {
                    dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), X(idx_n)]);
                } else {
                    dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt_n), [XSP(base_n), X(idx_n), LSL shift_n]);
                }
                Ok::<(), String>(())
            }
            _ => Err(format!(
                "{} cannot use extend kind {:?} (rejected by is_encodable_aarch64)",
                stringify!($mnem),
                $kind
            )),
        }
    }};
}

/// Pair `[base]` / `[base, #imm]` — RefOffset (signed 7-bit scaled).
macro_rules! emit_pair_imm_offset {
    ($ops:expr, $mnem:ident, $rt_tok:ident, $rt1:expr, $rt2:expr, $base:expr, $offset:expr) => {{
        let rt1_n: u8 = $rt1;
        let rt2_n: u8 = $rt2;
        let base_n: u8 = $base;
        let off: i32 = $offset;
        if off == 0 {
            dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt1_n), $rt_tok(rt2_n), [XSP(base_n)]);
        } else {
            dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt1_n), $rt_tok(rt2_n), [XSP(base_n), off]);
        }
    }};
}

/// Pair `[base, #imm]!` — pre-index writeback.
macro_rules! emit_pair_imm_preindex {
    ($ops:expr, $mnem:ident, $rt_tok:ident, $rt1:expr, $rt2:expr, $base:expr, $offset:expr) => {{
        let rt1_n: u8 = $rt1;
        let rt2_n: u8 = $rt2;
        let base_n: u8 = $base;
        let off: i32 = $offset;
        dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt1_n), $rt_tok(rt2_n), [XSP(base_n), off]!);
    }};
}

/// Pair `[base], #imm` — post-index writeback.
macro_rules! emit_pair_imm_postindex {
    ($ops:expr, $mnem:ident, $rt_tok:ident, $rt1:expr, $rt2:expr, $base:expr, $offset:expr) => {{
        let rt1_n: u8 = $rt1;
        let rt2_n: u8 = $rt2;
        let base_n: u8 = $base;
        let off: i32 = $offset;
        dynasm!($ops ; .arch aarch64 ; $mnem $rt_tok(rt1_n), $rt_tok(rt2_n), [XSP(base_n)], off);
    }};
}

/// True if `offset` fits the LDR/STR positive unsigned-scaled immediate
/// encoding for the given access width: `0..=4095 * width_bytes`, divisible
/// by `width_bytes`. Negative or unscaled offsets must route to LDUR/STUR.
fn can_use_scaled_offset(offset: i64, width_bytes: u32) -> bool {
    if offset < 0 {
        return false;
    }
    let scale = width_bytes as i64;
    if scale == 0 || offset % scale != 0 {
        return false;
    }
    let max_scaled = 4095i64 * scale;
    offset <= max_scaled
}

/// True if `offset` fits the LDUR/STUR / pre/post-index 9-bit signed
/// unscaled immediate (`-256..=255`).
fn can_use_unscaled_offset(offset: i64) -> bool {
    (-256..=255).contains(&offset)
}

/// Single-register load/store dispatcher. Selects between scaled positive
/// (LDR/STR-family) and unscaled signed (LDUR/STUR-family) encoding for the
/// `Imm + Offset` mode and routes pre-/post-index / register-offset /
/// register-extend modes to their dedicated macros.
macro_rules! encode_load_or_store_with {
    ($ops:expr, $addr:expr, $rt_n:expr, $base_n:expr, $width:expr,
     $mnem:ident, $unscaled_mnem:ident, $rt_tok:ident) => {{
        match $addr {
            AddressOperand::Imm {
                offset,
                mode: IndexMode::Offset,
                ..
            } => {
                let off = i32::try_from(*offset)
                    .map_err(|_| format!("offset {} out of i32 range", offset))?;
                if can_use_scaled_offset(*offset, $width) {
                    emit_mem_imm_offset!($ops, $mnem, $rt_tok, $rt_n, $base_n, off);
                    Ok::<(), String>(())
                } else if can_use_unscaled_offset(*offset) {
                    emit_mem_imm_unscaled!($ops, $unscaled_mnem, $rt_tok, $rt_n, $base_n, off);
                    Ok(())
                } else {
                    Err(format!(
                        "offset {} not encodable for {}/{}",
                        offset,
                        stringify!($mnem),
                        stringify!($unscaled_mnem),
                    ))
                }
            }
            AddressOperand::Imm {
                offset,
                mode: IndexMode::PreIndex,
                ..
            } => {
                let off = i32::try_from(*offset)
                    .map_err(|_| format!("offset {} out of i32 range", offset))?;
                if !can_use_unscaled_offset(*offset) {
                    return Err(format!(
                        "pre-index offset {} out of 9-bit signed range",
                        offset
                    ));
                }
                emit_mem_imm_preindex!($ops, $mnem, $rt_tok, $rt_n, $base_n, off);
                Ok(())
            }
            AddressOperand::Imm {
                offset,
                mode: IndexMode::PostIndex,
                ..
            } => {
                let off = i32::try_from(*offset)
                    .map_err(|_| format!("offset {} out of i32 range", offset))?;
                if !can_use_unscaled_offset(*offset) {
                    return Err(format!(
                        "post-index offset {} out of 9-bit signed range",
                        offset
                    ));
                }
                emit_mem_imm_postindex!($ops, $mnem, $rt_tok, $rt_n, $base_n, off);
                Ok(())
            }
            AddressOperand::Reg { idx, shift, .. } => {
                let idx_n = register_to_dynasm(*idx)?;
                emit_mem_reg!($ops, $mnem, $rt_tok, $rt_n, $base_n, idx_n, *shift);
                Ok(())
            }
            AddressOperand::Ext {
                idx, kind, shift, ..
            } => {
                let idx_n = register_to_dynasm(*idx)?;
                emit_mem_ext!($ops, $mnem, $rt_tok, $rt_n, $base_n, idx_n, *kind, *shift)
            }
        }
    }};
}

/// Pair load/store dispatcher (LDP/STP/LDPSW). Pair operations support
/// only the three immediate addressing modes; Reg/Ext are rejected at the
/// IR layer (`is_encodable_pair`).
macro_rules! encode_pair_with {
    ($ops:expr, $addr:expr, $rt1_n:expr, $rt2_n:expr, $base_n:expr,
     $mnem:ident, $rt_tok:ident) => {{
        match $addr {
            AddressOperand::Imm {
                offset,
                mode: IndexMode::Offset,
                ..
            } => {
                let off = i32::try_from(*offset)
                    .map_err(|_| format!("offset {} out of i32 range", offset))?;
                emit_pair_imm_offset!($ops, $mnem, $rt_tok, $rt1_n, $rt2_n, $base_n, off);
                Ok::<(), String>(())
            }
            AddressOperand::Imm {
                offset,
                mode: IndexMode::PreIndex,
                ..
            } => {
                let off = i32::try_from(*offset)
                    .map_err(|_| format!("offset {} out of i32 range", offset))?;
                emit_pair_imm_preindex!($ops, $mnem, $rt_tok, $rt1_n, $rt2_n, $base_n, off);
                Ok(())
            }
            AddressOperand::Imm {
                offset,
                mode: IndexMode::PostIndex,
                ..
            } => {
                let off = i32::try_from(*offset)
                    .map_err(|_| format!("offset {} out of i32 range", offset))?;
                emit_pair_imm_postindex!($ops, $mnem, $rt_tok, $rt1_n, $rt2_n, $base_n, off);
                Ok(())
            }
            AddressOperand::Reg { .. } | AddressOperand::Ext { .. } => Err(format!(
                "{} only supports immediate addressing modes",
                stringify!($mnem)
            )),
        }
    }};
}

pub struct AArch64Assembler;

impl AArch64Assembler {
    pub fn new() -> Self {
        Self
    }

    /// Assemble a sequence of AArch64 instructions to machine code.
    ///
    /// `base_address` is the virtual address at which the first instruction
    /// will execute; it is used solely to resolve PC-relative branch targets
    /// (issue #69). For sequences without branches the value is irrelevant
    /// and may be 0.
    pub fn assemble_instructions(
        &mut self,
        instructions: &[Instruction],
        base_address: u64,
    ) -> Result<Vec<u8>, String> {
        // Create a new assembler for this operation
        let mut ops = dynasmrt::aarch64::Assembler::new()
            .map_err(|e| format!("Failed to create assembler: {:?}", e))?;

        for (idx, instr) in instructions.iter().enumerate() {
            let current_pc = base_address.wrapping_add((idx as u64) * 4);
            self.encode_instruction_on(&mut ops, instr, current_pc)?;
        }

        ops.finalize()
            .map(|buf| buf.to_vec())
            .map_err(|e| format!("Failed to finalize assembly: {:?}", e))
    }

    #[allow(clippy::useless_conversion)]
    fn encode_instruction_on(
        &self,
        ops: &mut dynasmrt::aarch64::Assembler,
        instr: &Instruction,
        current_pc: u64,
    ) -> Result<(), String> {
        // `current_pc` is consumed by branch-encoding arms below; suppress
        // the unused-variable warning for the non-branch arms.
        let _ = current_pc;
        match instr {
            Instruction::MovReg { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; mov X(rd_reg), X(rn_reg)
                );
                Ok(())
            }
            Instruction::MovRegW { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; mov W(rd_reg), W(rn_reg)
                );
                Ok(())
            }
            Instruction::MovImm { rd, imm } => {
                let rd_reg = register_to_dynasm(*rd)?;

                if *imm < 0 || *imm > 0xFFFF {
                    return Err(format!("Immediate {} out of range for MOV", imm));
                }

                dynasm!(ops
                    ; .arch aarch64
                    ; mov X(rd_reg), *imm as u64
                );
                Ok(())
            }
            Instruction::Add { rd, rn, rm } => {
                // rd resolution depends on the rm operand shape: the immediate
                // and extended-register forms encode Rd in the Xn|SP slot
                // (accept SP, reject XZR), while the register and
                // shifted-register forms use the plain Xn slot. Resolve rd
                // inside each arm so the correct encoder gates it.
                match rm {
                    Operand::Register(rm_reg) => {
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; add X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for ADD", imm));
                        }
                        // ADD immediate uses the Xn|SP register type for both rd
                        // and rn per AArch64 spec (`ADD <Xd|SP>, <Xn|SP>, #imm`).
                        // register_to_dynasm_xsp accepts SP (so `ADD SP, SP, #imm`
                        // encodes) and rejects XZR, which shares index 31 and
                        // would otherwise silently alias to SP.
                        let rd_reg = register_to_dynasm_xsp(*rd)?;
                        let rn_reg = register_to_dynasm_xsp(*rn)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; add XSP(rd_reg), XSP(rn_reg), #*imm as u32
                        );
                        Ok(())
                    }
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_arith!(
                            ops, add, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
                    }
                    Operand::ExtendedRegister { reg, kind, shift } => {
                        // Use the XSP-flavoured register encoders for rd/rn:
                        // the extended-register encoding's Rd/Rn slot is
                        // `Xn|SP`, and XZR (also reg 31) would otherwise
                        // silently alias to SP. The encodability gate also
                        // rejects XZR/SP for ExtendedRegister, so this is
                        // belt-and-braces. Issue #60 (codex review on #144).
                        let rd_xsp = register_to_dynasm_xsp(*rd)?;
                        let rn_xsp = register_to_dynasm_xsp(*rn)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_extended_reg_3op_arith!(
                            ops, add, rd_xsp, rn_xsp, rm_reg_num, kind, *shift
                        )
                    }
                }
            }
            Instruction::AddW { rd, rn, rm } => match rm {
                Operand::Register(rm_reg) => {
                    let rd_reg = register_to_dynasm(*rd)?;
                    let rn_reg = register_to_dynasm(*rn)?;
                    let rm_reg_num = register_to_dynasm(*rm_reg)?;
                    dynasm!(ops
                        ; .arch aarch64
                        ; add W(rd_reg), W(rn_reg), W(rm_reg_num)
                    );
                    Ok(())
                }
                Operand::Immediate(imm) => {
                    if *imm < 0 || *imm > 0xFFF {
                        return Err(format!("Immediate {} out of range for ADD W", imm));
                    }
                    let rd_reg = register_to_dynasm_wsp(*rd)?;
                    let rn_reg = register_to_dynasm_wsp(*rn)?;
                    dynasm!(ops
                        ; .arch aarch64
                        ; add WSP(rd_reg), WSP(rn_reg), #*imm as u32
                    );
                    Ok(())
                }
                Operand::ShiftedRegister { reg, kind, amount } => {
                    let rd_reg = register_to_dynasm(*rd)?;
                    let rn_reg = register_to_dynasm(*rn)?;
                    let rm_reg_num = register_to_dynasm(*reg)?;
                    emit_shifted_reg_3op_arith_w!(
                        ops, add, rd_reg, rn_reg, rm_reg_num, kind, *amount
                    )
                }
                Operand::ExtendedRegister { .. } => Err(
                    "ADD W extended-register form is not wired in the assembler yet".to_string(),
                ),
            },
            Instruction::Sub { rd, rn, rm } => {
                // See the ADD arm: rd is resolved inside each operand branch so
                // the immediate/extended forms gate it through the Xn|SP encoder
                // and the register/shifted forms through the plain Xn encoder.
                match rm {
                    Operand::Register(rm_reg) => {
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; sub X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for SUB", imm));
                        }
                        // SUB immediate uses the Xn|SP register type for both rd
                        // and rn (`SUB <Xd|SP>, <Xn|SP>, #imm`). register_to_dynasm_xsp
                        // accepts SP (so `SUB SP, SP, #imm` encodes) and rejects
                        // XZR, which would otherwise alias to SP via index 31.
                        let rd_reg = register_to_dynasm_xsp(*rd)?;
                        let rn_reg = register_to_dynasm_xsp(*rn)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; sub XSP(rd_reg), XSP(rn_reg), #*imm as u32
                        );
                        Ok(())
                    }
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_arith!(
                            ops, sub, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
                    }
                    Operand::ExtendedRegister { reg, kind, shift } => {
                        // See the ADD arm for why we re-fetch rd/rn via
                        // register_to_dynasm_xsp. Issue #60.
                        let rd_xsp = register_to_dynasm_xsp(*rd)?;
                        let rn_xsp = register_to_dynasm_xsp(*rn)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_extended_reg_3op_arith!(
                            ops, sub, rd_xsp, rn_xsp, rm_reg_num, kind, *shift
                        )
                    }
                }
            }
            Instruction::SubW { rd, rn, rm } => match rm {
                Operand::Register(rm_reg) => {
                    let rd_reg = register_to_dynasm(*rd)?;
                    let rn_reg = register_to_dynasm(*rn)?;
                    let rm_reg_num = register_to_dynasm(*rm_reg)?;
                    dynasm!(ops
                        ; .arch aarch64
                        ; sub W(rd_reg), W(rn_reg), W(rm_reg_num)
                    );
                    Ok(())
                }
                Operand::Immediate(imm) => {
                    if *imm < 0 || *imm > 0xFFF {
                        return Err(format!("Immediate {} out of range for SUB W", imm));
                    }
                    let rd_reg = register_to_dynasm_wsp(*rd)?;
                    let rn_reg = register_to_dynasm_wsp(*rn)?;
                    dynasm!(ops
                        ; .arch aarch64
                        ; sub WSP(rd_reg), WSP(rn_reg), #*imm as u32
                    );
                    Ok(())
                }
                Operand::ShiftedRegister { reg, kind, amount } => {
                    let rd_reg = register_to_dynasm(*rd)?;
                    let rn_reg = register_to_dynasm(*rn)?;
                    let rm_reg_num = register_to_dynasm(*reg)?;
                    emit_shifted_reg_3op_arith_w!(
                        ops, sub, rd_reg, rn_reg, rm_reg_num, kind, *amount
                    )
                }
                Operand::ExtendedRegister { .. } => Err(
                    "SUB W extended-register form is not wired in the assembler yet".to_string(),
                ),
            },
            // For AND/ORR/EOR: rd resolution depends on the rm operand shape —
            // the immediate form encodes Rd in the Xn|SP slot (accepts SP,
            // rejects XZR), while the register and shifted-register forms use
            // the plain Xn slot (rejects SP). Resolving rd inside each arm
            // avoids prematurely rejecting `<op> sp, xn, #imm`.
            Instruction::And { rd, rn, rm, width } => {
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        if *width != RegisterWidth::X64 {
                            return Err("AND with W registers supports immediate operands only; register and shifted-register forms require X registers".to_string());
                        }
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; and X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        match width {
                            RegisterWidth::X64 => {
                                let val = *imm as u64;
                                if !logical_imm64_encodable(*imm) {
                                    return Err(format!(
                                        "AND immediate 0x{:x} is not a valid AArch64 logical immediate",
                                        val
                                    ));
                                }
                                // AND (immediate) encodes Rd in the Xn|SP slot.
                                let rd_reg_xsp = register_to_dynasm_xsp(*rd)?;
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; and XSP(rd_reg_xsp), X(rn_reg), #val
                                );
                            }
                            RegisterWidth::W32 => {
                                let val = logical_imm32_for_assembler("AND", *imm)?;
                                let rd_reg_wsp = register_to_dynasm_wsp(*rd)?;
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; and WSP(rd_reg_wsp), W(rn_reg), #val
                                );
                            }
                        }
                        Ok(())
                    }
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        if *width != RegisterWidth::X64 {
                            return Err("AND with W registers supports immediate operands only; register and shifted-register forms require X registers".to_string());
                        }
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_logical!(
                            ops, and, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Orr { rd, rn, rm, width } => {
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        if *width != RegisterWidth::X64 {
                            return Err("ORR with W registers supports immediate operands only; register and shifted-register forms require X registers".to_string());
                        }
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; orr X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        match width {
                            RegisterWidth::X64 => {
                                let val = *imm as u64;
                                if !logical_imm64_encodable(*imm) {
                                    return Err(format!(
                                        "ORR immediate 0x{:x} is not a valid AArch64 logical immediate",
                                        val
                                    ));
                                }
                                let rd_reg_xsp = register_to_dynasm_xsp(*rd)?;
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; orr XSP(rd_reg_xsp), X(rn_reg), #val
                                );
                            }
                            RegisterWidth::W32 => {
                                let val = logical_imm32_for_assembler("ORR", *imm)?;
                                let rd_reg_wsp = register_to_dynasm_wsp(*rd)?;
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; orr WSP(rd_reg_wsp), W(rn_reg), #val
                                );
                            }
                        }
                        Ok(())
                    }
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        if *width != RegisterWidth::X64 {
                            return Err("ORR with W registers supports immediate operands only; register and shifted-register forms require X registers".to_string());
                        }
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_logical!(
                            ops, orr, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Eor { rd, rn, rm, width } => {
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        if *width != RegisterWidth::X64 {
                            return Err("EOR with W registers supports immediate operands only; register and shifted-register forms require X registers".to_string());
                        }
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; eor X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        match width {
                            RegisterWidth::X64 => {
                                let val = *imm as u64;
                                if !logical_imm64_encodable(*imm) {
                                    return Err(format!(
                                        "EOR immediate 0x{:x} is not a valid AArch64 logical immediate",
                                        val
                                    ));
                                }
                                let rd_reg_xsp = register_to_dynasm_xsp(*rd)?;
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; eor XSP(rd_reg_xsp), X(rn_reg), #val
                                );
                            }
                            RegisterWidth::W32 => {
                                let val = logical_imm32_for_assembler("EOR", *imm)?;
                                let rd_reg_wsp = register_to_dynasm_wsp(*rd)?;
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; eor WSP(rd_reg_wsp), W(rn_reg), #val
                                );
                            }
                        }
                        Ok(())
                    }
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        if *width != RegisterWidth::X64 {
                            return Err("EOR with W registers supports immediate operands only; register and shifted-register forms require X registers".to_string());
                        }
                        let rd_reg = register_to_dynasm(*rd)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_logical!(
                            ops, eor, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Lsl { rd, rn, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match shift {
                    Operand::Register(shift_reg) => {
                        let shift_reg_num = register_to_dynasm(*shift_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; lsl X(rd_reg), X(rn_reg), X(shift_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(shift_amt) => {
                        if *shift_amt < 0 || *shift_amt > 63 {
                            return Err(format!(
                                "Shift amount {} out of range for LSL (0-63)",
                                shift_amt
                            ));
                        }
                        dynasm!(ops
                            ; .arch aarch64
                            ; lsl X(rd_reg), X(rn_reg), *shift_amt as u32
                        );
                        Ok(())
                    }
                    // Rejected by is_encodable_aarch64; shift slot is not a
                    // shifted-register form.
                    Operand::ShiftedRegister { .. } => {
                        Err("LSL shift amount cannot be a ShiftedRegister".to_string())
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Lsr { rd, rn, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match shift {
                    Operand::Register(shift_reg) => {
                        let shift_reg_num = register_to_dynasm(*shift_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; lsr X(rd_reg), X(rn_reg), X(shift_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(shift_amt) => {
                        if *shift_amt < 0 || *shift_amt > 63 {
                            return Err(format!(
                                "Shift amount {} out of range for LSR (0-63)",
                                shift_amt
                            ));
                        }
                        dynasm!(ops
                            ; .arch aarch64
                            ; lsr X(rd_reg), X(rn_reg), *shift_amt as u32
                        );
                        Ok(())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("LSR shift amount cannot be a ShiftedRegister".to_string())
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Asr { rd, rn, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match shift {
                    Operand::Register(shift_reg) => {
                        let shift_reg_num = register_to_dynasm(*shift_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; asr X(rd_reg), X(rn_reg), X(shift_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(shift_amt) => {
                        if *shift_amt < 0 || *shift_amt > 63 {
                            return Err(format!(
                                "Shift amount {} out of range for ASR (0-63)",
                                shift_amt
                            ));
                        }
                        dynasm!(ops
                            ; .arch aarch64
                            ; asr X(rd_reg), X(rn_reg), *shift_amt as u32
                        );
                        Ok(())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("ASR shift amount cannot be a ShiftedRegister".to_string())
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Mul { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; mul X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Sdiv { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; sdiv X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Udiv { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; udiv X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Madd { rd, rn, rm, ra } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                let ra_reg = register_to_dynasm(*ra)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; madd X(rd_reg), X(rn_reg), X(rm_reg), X(ra_reg)
                );
                Ok(())
            }
            Instruction::Msub { rd, rn, rm, ra } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                let ra_reg = register_to_dynasm(*ra)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; msub X(rd_reg), X(rn_reg), X(rm_reg), X(ra_reg)
                );
                Ok(())
            }
            Instruction::Mneg { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; mneg X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Smulh { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; smulh X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Umulh { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; umulh X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Cmp { rn, rm } => {
                match rm {
                    Operand::Register(rm_reg) => {
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; cmp X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for CMP", imm));
                        }
                        let rn_reg = register_to_dynasm_xsp(*rn)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; cmp XSP(rn_reg), #*imm as u32
                        );
                        Ok(())
                    }
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_2op_arith!(ops, cmp, rn_reg, rm_reg_num, kind, *amount)
                    }
                    Operand::ExtendedRegister { reg, kind, shift } => {
                        // See the ADD ExtendedRegister arm — XSP-flavoured
                        // rn encoder rejects XZR (which would alias to SP).
                        // Issue #60 (codex review on #144).
                        let rn_xsp = register_to_dynasm_xsp(*rn)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_extended_reg_2op_arith!(ops, cmp, rn_xsp, rm_reg_num, kind, *shift)
                    }
                }
            }
            Instruction::Cmn { rn, rm } => {
                match rm {
                    Operand::Register(rm_reg) => {
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; cmn X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for CMN", imm));
                        }
                        let rn_reg = register_to_dynasm_xsp(*rn)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; cmn XSP(rn_reg), #*imm as u32
                        );
                        Ok(())
                    }
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_2op_arith!(ops, cmn, rn_reg, rm_reg_num, kind, *amount)
                    }
                    Operand::ExtendedRegister { reg, kind, shift } => {
                        // XSP-flavoured rn encoder rejects XZR. See ADD.
                        // Issue #60 (codex review on #144).
                        let rn_xsp = register_to_dynasm_xsp(*rn)?;
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_extended_reg_2op_arith!(ops, cmn, rn_xsp, rm_reg_num, kind, *shift)
                    }
                }
            }
            Instruction::Tst { rn, rm, width } => {
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        if *width != RegisterWidth::X64 {
                            return Err("TST with W registers supports immediate operands only; register and shifted-register forms require X registers".to_string());
                        }
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; tst X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        match width {
                            RegisterWidth::X64 => {
                                let val = *imm as u64;
                                if !logical_imm64_encodable(*imm) {
                                    return Err(format!(
                                        "TST immediate 0x{:x} is not a valid AArch64 logical immediate",
                                        val
                                    ));
                                }
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; tst X(rn_reg), #val
                                );
                            }
                            RegisterWidth::W32 => {
                                let val = logical_imm32_for_assembler("TST", *imm)?;
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; tst W(rn_reg), #val
                                );
                            }
                        }
                        Ok(())
                    }
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        if *width != RegisterWidth::X64 {
                            return Err("TST with W registers supports immediate operands only; register and shifted-register forms require X registers".to_string());
                        }
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_2op_logical!(ops, tst, rn_reg, rm_reg_num, kind, *amount)
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Csel { rd, rn, rm, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                emit_csel!(ops, csel, rd_reg, rn_reg, rm_reg, *cond);
                Ok(())
            }
            Instruction::Csinc { rd, rn, rm, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                emit_csel!(ops, csinc, rd_reg, rn_reg, rm_reg, *cond);
                Ok(())
            }
            Instruction::Csinv { rd, rn, rm, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                emit_csel!(ops, csinv, rd_reg, rn_reg, rm_reg, *cond);
                Ok(())
            }
            Instruction::Csneg { rd, rn, rm, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                emit_csel!(ops, csneg, rd_reg, rn_reg, rm_reg, *cond);
                Ok(())
            }
            Instruction::Ccmp { rn, rm, nzcv, cond } => {
                if *nzcv > 15 {
                    return Err(format!("CCMP nzcv {} out of range (0..=15)", nzcv));
                }
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_idx = register_to_dynasm(*rm_reg)?;
                        emit_ccmp_reg!(ops, ccmp, rn_reg, rm_idx, *nzcv, *cond);
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 31 {
                            return Err(format!("CCMP imm5 {} out of range (0..=31)", imm));
                        }
                        emit_ccmp_imm!(ops, ccmp, rn_reg, *imm, *nzcv, *cond);
                    }
                    Operand::ShiftedRegister { .. } => {
                        return Err("CCMP does not support shifted-register operand".to_string());
                    }
                    Operand::ExtendedRegister { .. } => {
                        return Err("ExtendedRegister encoding not yet implemented".to_string());
                    }
                }
                Ok(())
            }
            Instruction::Ccmn { rn, rm, nzcv, cond } => {
                if *nzcv > 15 {
                    return Err(format!("CCMN nzcv {} out of range (0..=15)", nzcv));
                }
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_idx = register_to_dynasm(*rm_reg)?;
                        emit_ccmp_reg!(ops, ccmn, rn_reg, rm_idx, *nzcv, *cond);
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 31 {
                            return Err(format!("CCMN imm5 {} out of range (0..=31)", imm));
                        }
                        emit_ccmp_imm!(ops, ccmn, rn_reg, *imm, *nzcv, *cond);
                    }
                    Operand::ShiftedRegister { .. } => {
                        return Err("CCMN does not support shifted-register operand".to_string());
                    }
                    Operand::ExtendedRegister { .. } => {
                        return Err("ExtendedRegister encoding not yet implemented".to_string());
                    }
                }
                Ok(())
            }
            Instruction::Mvn { rd, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rm_reg = register_to_dynasm(*rm)?;
                dynasm!(ops ; .arch aarch64 ; mvn X(rd_reg), X(rm_reg));
                Ok(())
            }
            Instruction::Clz { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; clz X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Cls { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; cls X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Rbit { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; rbit X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Rev { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; rev X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Rev32 { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; rev32 X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Rev16 { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; rev16 X(rd_reg), X(rn_reg));
                Ok(())
            }
            // UXTB Wd, Wn — alias of UBFM Wd, Wn, #0, #7. Issue #60.
            // dynasm-rs emits the 32-bit (W) form; the upper 32 bits of Xd
            // are zeroed by the AArch64 architectural rule for 32-bit ops.
            Instruction::Uxtb { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; uxtb W(rd_reg), W(rn_reg));
                Ok(())
            }
            // SXTB Xd, Wn — alias of SBFM Xd, Xn, #0, #7. Issue #60.
            Instruction::Sxtb { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; sxtb X(rd_reg), W(rn_reg));
                Ok(())
            }
            // UXTH Wd, Wn — alias of UBFM Wd, Wn, #0, #15. Issue #60.
            Instruction::Uxth { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; uxth W(rd_reg), W(rn_reg));
                Ok(())
            }
            // SXTH Xd, Wn — alias of SBFM Xd, Xn, #0, #15. Issue #60.
            Instruction::Sxth { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; sxth X(rd_reg), W(rn_reg));
                Ok(())
            }
            // SXTW Xd, Wn — alias of SBFM Xd, Xn, #0, #31. Issue #60.
            Instruction::Sxtw { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; sxtw X(rd_reg), W(rn_reg));
                Ok(())
            }
            Instruction::Neg { rd, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rm_reg = register_to_dynasm(*rm)?;
                dynasm!(ops ; .arch aarch64 ; neg X(rd_reg), X(rm_reg));
                Ok(())
            }
            Instruction::Negs { rd, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rm_reg = register_to_dynasm(*rm)?;
                dynasm!(ops ; .arch aarch64 ; negs X(rd_reg), X(rm_reg));
                Ok(())
            }
            Instruction::MovN { rd, imm, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let imm = *imm as u32;
                match shift {
                    0 => dynasm!(ops ; .arch aarch64 ; movn X(rd_reg), imm),
                    16 => dynasm!(ops ; .arch aarch64 ; movn X(rd_reg), imm, lsl #16),
                    32 => dynasm!(ops ; .arch aarch64 ; movn X(rd_reg), imm, lsl #32),
                    48 => dynasm!(ops ; .arch aarch64 ; movn X(rd_reg), imm, lsl #48),
                    other => return Err(format!("MOVN shift {} out of range", other)),
                }
                Ok(())
            }
            Instruction::MovZ { rd, imm, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let imm = *imm as u32;
                match shift {
                    0 => dynasm!(ops ; .arch aarch64 ; movz X(rd_reg), imm),
                    16 => dynasm!(ops ; .arch aarch64 ; movz X(rd_reg), imm, lsl #16),
                    32 => dynasm!(ops ; .arch aarch64 ; movz X(rd_reg), imm, lsl #32),
                    48 => dynasm!(ops ; .arch aarch64 ; movz X(rd_reg), imm, lsl #48),
                    other => return Err(format!("MOVZ shift {} out of range", other)),
                }
                Ok(())
            }
            Instruction::MovK { rd, imm, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let imm = *imm as u32;
                match shift {
                    0 => dynasm!(ops ; .arch aarch64 ; movk X(rd_reg), imm),
                    16 => dynasm!(ops ; .arch aarch64 ; movk X(rd_reg), imm, lsl #16),
                    32 => dynasm!(ops ; .arch aarch64 ; movk X(rd_reg), imm, lsl #32),
                    48 => dynasm!(ops ; .arch aarch64 ; movk X(rd_reg), imm, lsl #48),
                    other => return Err(format!("MOVK shift {} out of range", other)),
                }
                Ok(())
            }
            Instruction::Bic { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; bic X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(_) => {
                        Err("BIC immediate encoding not supported".to_string())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("BIC shifted-register form not yet supported (issue #59 covers AND/ORR/EOR/TST only)".to_string())
                    }
                    Operand::ExtendedRegister { .. } => Err("ExtendedRegister encoding not yet implemented".to_string()),
                }
            }
            Instruction::Bics { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; bics X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(_) => {
                        Err("BICS immediate encoding not supported".to_string())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("BICS shifted-register form not yet supported".to_string())
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Orn { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; orn X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(_) => {
                        Err("ORN immediate encoding not supported".to_string())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("ORN shifted-register form not yet supported".to_string())
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Eon { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; eon X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(_) => {
                        Err("EON immediate encoding not supported".to_string())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("EON shifted-register form not yet supported".to_string())
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Adds { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                match rm {
                    Operand::Register(r) => {
                        // Shifted-register form: slot 31 = XZR; plain
                        // `register_to_dynasm` mapping is correct.
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; adds X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for ADDS", imm));
                        }
                        // The immediate-form encoding uses the `Xn|SP` slot —
                        // 31 decodes as SP, not XZR. `register_to_dynasm_xsp`
                        // accepts SP and rejects XZR, keeping the encoding
                        // unambiguous and consistent with what the parser /
                        // is_encodable_aarch64 admit.
                        let rn_reg = register_to_dynasm_xsp(*rn)?;
                        let imm = *imm as u32;
                        dynasm!(ops ; .arch aarch64 ; adds X(rd_reg), XSP(rn_reg), imm);
                        Ok(())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("ADDS shifted-register form not yet supported (issue #59 covers ADD without flags)".to_string())
                    }
                    Operand::ExtendedRegister { .. } => Err("ExtendedRegister encoding not yet implemented".to_string()),
                }
            }
            Instruction::Subs { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                match rm {
                    Operand::Register(r) => {
                        // Shifted-register form: slot 31 = XZR.
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; subs X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for SUBS", imm));
                        }
                        // Immediate form uses the Xn|SP slot — same caveat
                        // as ADDS above; `register_to_dynasm_xsp` accepts SP
                        // and rejects XZR.
                        let rn_reg = register_to_dynasm_xsp(*rn)?;
                        let imm = *imm as u32;
                        dynasm!(ops ; .arch aarch64 ; subs X(rd_reg), XSP(rn_reg), imm);
                        Ok(())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("SUBS shifted-register form not yet supported".to_string())
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            Instruction::Ands { rd, rn, rm, width } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        if *width != RegisterWidth::X64 {
                            return Err("ANDS with W registers supports immediate operands only; register and shifted-register forms require X registers".to_string());
                        }
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; ands X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        match width {
                            RegisterWidth::X64 => {
                                let val = *imm as u64;
                                if !logical_imm64_encodable(*imm) {
                                    return Err(format!(
                                        "ANDS immediate 0x{:x} is not a valid AArch64 logical immediate",
                                        val
                                    ));
                                }
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; ands X(rd_reg), X(rn_reg), #val
                                );
                            }
                            RegisterWidth::W32 => {
                                let val = logical_imm32_for_assembler("ANDS", *imm)?;
                                dynasm!(ops
                                    ; .arch aarch64
                                    ; ands W(rd_reg), W(rn_reg), #val
                                );
                            }
                        }
                        Ok(())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("ANDS shifted-register form not yet supported".to_string())
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            // CSET / CSETM lower to CSINC/CSINV with XZR sources and inverted cond.
            // Capstone canonicalises the disassembly back to `cset`/`csetm`.
            //
            // Defense-in-depth: reject AL/NV here too. `is_encodable_aarch64`
            // already filters them at the IR level, but a caller could
            // construct the variant directly and bypass that check. Without
            // this guard, `Cset { cond: AL }` would lower to `csinc ..., nv`
            // (because invert(AL) = NV), which on AArch64 writes 0 — the
            // opposite of the IR's "always 1" semantics. CSETM has the
            // symmetric issue.
            Instruction::Cset { rd, cond } => {
                if matches!(cond, Condition::AL | Condition::NV) {
                    return Err(format!(
                        "CSET with {} is not encodable (AL/NV reserved)",
                        cond
                    ));
                }
                let rd_reg = register_to_dynasm(*rd)?;
                let xzr: u8 = 31;
                let inv = cond.invert();
                emit_csel!(ops, csinc, rd_reg, xzr, xzr, inv);
                Ok(())
            }
            Instruction::Csetm { rd, cond } => {
                if matches!(cond, Condition::AL | Condition::NV) {
                    return Err(format!(
                        "CSETM with {} is not encodable (AL/NV reserved)",
                        cond
                    ));
                }
                let rd_reg = register_to_dynasm(*rd)?;
                let xzr: u8 = 31;
                let inv = cond.invert();
                emit_csel!(ops, csinv, rd_reg, xzr, xzr, inv);
                Ok(())
            }
            Instruction::Ror { rd, rn, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match shift {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; ror X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 63 {
                            return Err(format!("ROR shift {} out of range", imm));
                        }
                        let imm = *imm as u32;
                        dynasm!(ops ; .arch aarch64 ; ror X(rd_reg), X(rn_reg), imm);
                        Ok(())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("ROR shift amount cannot be a ShiftedRegister".to_string())
                    }
                    Operand::ExtendedRegister { .. } => {
                        Err("ExtendedRegister encoding not yet implemented".to_string())
                    }
                }
            }
            // Bit-field manipulation aliases (UBFX/SBFX/BFI/BFXIL/UBFIZ/SBFIZ).
            Instruction::Ubfx { rd, rn, lsb, width } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let lsb_imm = *lsb as u32;
                let width_imm = *width as u32;
                dynasm!(ops ; .arch aarch64 ; ubfx X(rd_reg), X(rn_reg), lsb_imm, width_imm);
                Ok(())
            }
            Instruction::Sbfx { rd, rn, lsb, width } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let lsb_imm = *lsb as u32;
                let width_imm = *width as u32;
                dynasm!(ops ; .arch aarch64 ; sbfx X(rd_reg), X(rn_reg), lsb_imm, width_imm);
                Ok(())
            }
            Instruction::Bfi { rd, rn, lsb, width } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let lsb_imm = *lsb as u32;
                let width_imm = *width as u32;
                dynasm!(ops ; .arch aarch64 ; bfi X(rd_reg), X(rn_reg), lsb_imm, width_imm);
                Ok(())
            }
            Instruction::Bfxil { rd, rn, lsb, width } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let lsb_imm = *lsb as u32;
                let width_imm = *width as u32;
                dynasm!(ops ; .arch aarch64 ; bfxil X(rd_reg), X(rn_reg), lsb_imm, width_imm);
                Ok(())
            }
            Instruction::Ubfiz { rd, rn, lsb, width } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let lsb_imm = *lsb as u32;
                let width_imm = *width as u32;
                dynasm!(ops ; .arch aarch64 ; ubfiz X(rd_reg), X(rn_reg), lsb_imm, width_imm);
                Ok(())
            }
            Instruction::Sbfiz { rd, rn, lsb, width } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let lsb_imm = *lsb as u32;
                let width_imm = *width as u32;
                dynasm!(ops ; .arch aarch64 ; sbfiz X(rd_reg), X(rn_reg), lsb_imm, width_imm);
                Ok(())
            }

            // ===== Issue #69: branches / control flow =====
            // RET Xn / BR Xn: register-indirect transfers. No PC-relative
            // immediate; encoding is independent of `current_pc`.
            Instruction::Ret { rn } => {
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; ret X(rn_reg));
                Ok(())
            }
            Instruction::Br { rn } => {
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; br X(rn_reg));
                Ok(())
            }
            // B (unconditional) — PC-relative ±128 MiB. imm26 field holds the
            // signed 4-byte-aligned offset; dynasm-rs takes the byte offset.
            Instruction::B { target } => {
                let offset = pc_relative_offset(*target, current_pc, BranchRange::B)?;
                dynasm!(ops ; .arch aarch64 ; b offset);
                Ok(())
            }
            // BL — same range as B but writes the return address to X30.
            Instruction::Bl { target } => {
                let offset = pc_relative_offset(*target, current_pc, BranchRange::B)?;
                dynasm!(ops ; .arch aarch64 ; bl offset);
                Ok(())
            }
            // B.cond — ±1 MiB. We pre-reject AL/NV at IR construction
            // (is_encodable_aarch64) but defend in depth.
            Instruction::BCond { target, cond } => {
                if matches!(cond, Condition::AL | Condition::NV) {
                    return Err(format!(
                        "B.{} is not encodable (use plain B; NV is reserved)",
                        cond
                    ));
                }
                let offset = pc_relative_offset(*target, current_pc, BranchRange::Cond)?;
                match cond {
                    Condition::EQ => dynasm!(ops ; .arch aarch64 ; b.eq offset),
                    Condition::NE => dynasm!(ops ; .arch aarch64 ; b.ne offset),
                    Condition::CS => dynasm!(ops ; .arch aarch64 ; b.cs offset),
                    Condition::CC => dynasm!(ops ; .arch aarch64 ; b.cc offset),
                    Condition::MI => dynasm!(ops ; .arch aarch64 ; b.mi offset),
                    Condition::PL => dynasm!(ops ; .arch aarch64 ; b.pl offset),
                    Condition::VS => dynasm!(ops ; .arch aarch64 ; b.vs offset),
                    Condition::VC => dynasm!(ops ; .arch aarch64 ; b.vc offset),
                    Condition::HI => dynasm!(ops ; .arch aarch64 ; b.hi offset),
                    Condition::LS => dynasm!(ops ; .arch aarch64 ; b.ls offset),
                    Condition::GE => dynasm!(ops ; .arch aarch64 ; b.ge offset),
                    Condition::LT => dynasm!(ops ; .arch aarch64 ; b.lt offset),
                    Condition::GT => dynasm!(ops ; .arch aarch64 ; b.gt offset),
                    Condition::LE => dynasm!(ops ; .arch aarch64 ; b.le offset),
                    Condition::AL | Condition::NV => unreachable!("rejected above"),
                }
                Ok(())
            }
            // CBZ/CBNZ — register + ±1 MiB target.
            Instruction::Cbz { rn, target } => {
                let rn_reg = register_to_dynasm(*rn)?;
                let offset = pc_relative_offset(*target, current_pc, BranchRange::Cond)?;
                dynasm!(ops ; .arch aarch64 ; cbz X(rn_reg), offset);
                Ok(())
            }
            Instruction::Cbnz { rn, target } => {
                let rn_reg = register_to_dynasm(*rn)?;
                let offset = pc_relative_offset(*target, current_pc, BranchRange::Cond)?;
                dynasm!(ops ; .arch aarch64 ; cbnz X(rn_reg), offset);
                Ok(())
            }
            // TBZ/TBNZ — register + bit + ±32 KiB target.
            Instruction::Tbz { rt, bit, target } => {
                if *bit > 63 {
                    return Err(format!("TBZ bit {} out of range (0..=63)", bit));
                }
                let rt_reg = register_to_dynasm(*rt)?;
                let bit = *bit as u32;
                let offset = pc_relative_offset(*target, current_pc, BranchRange::Test)?;
                dynasm!(ops ; .arch aarch64 ; tbz X(rt_reg), bit, offset);
                Ok(())
            }
            Instruction::Tbnz { rt, bit, target } => {
                if *bit > 63 {
                    return Err(format!("TBNZ bit {} out of range (0..=63)", bit));
                }
                let rt_reg = register_to_dynasm(*rt)?;
                let bit = *bit as u32;
                let offset = pc_relative_offset(*target, current_pc, BranchRange::Test)?;
                dynasm!(ops ; .arch aarch64 ; tbnz X(rt_reg), bit, offset);
                Ok(())
            }
            // Memory ops (issue #68). dynasm dispatch per width × mode.
            Instruction::Ldr { rt, addr, width } => {
                let rt_n = register_to_dynasm(*rt)?;
                let base_n = register_to_dynasm_xsp(address_base_of(addr))?;
                let bytes = width.bytes();
                match width {
                    AccessWidth::Byte => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, ldrb, ldurb, W)
                    }
                    AccessWidth::Half => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, ldrh, ldurh, W)
                    }
                    AccessWidth::Word => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, ldr, ldur, W)
                    }
                    AccessWidth::Extended => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, ldr, ldur, X)
                    }
                }
            }
            Instruction::Ldrs { rt, addr, width } => {
                let rt_n = register_to_dynasm(*rt)?;
                let base_n = register_to_dynasm_xsp(address_base_of(addr))?;
                let bytes = width.bytes();
                match width {
                    AccessWidth::Byte => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, ldrsb, ldursb, X)
                    }
                    AccessWidth::Half => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, ldrsh, ldursh, X)
                    }
                    AccessWidth::Word => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, ldrsw, ldursw, X)
                    }
                    AccessWidth::Extended => {
                        Err("LDRSX does not exist (Extended width rejected for Ldrs)".into())
                    }
                }
            }
            Instruction::Str { rt, addr, width } => {
                let rt_n = register_to_dynasm(*rt)?;
                let base_n = register_to_dynasm_xsp(address_base_of(addr))?;
                let bytes = width.bytes();
                match width {
                    AccessWidth::Byte => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, strb, sturb, W)
                    }
                    AccessWidth::Half => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, strh, sturh, W)
                    }
                    AccessWidth::Word => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, str, stur, W)
                    }
                    AccessWidth::Extended => {
                        encode_load_or_store_with!(ops, addr, rt_n, base_n, bytes, str, stur, X)
                    }
                }
            }
            Instruction::Ldp {
                rt1,
                rt2,
                addr,
                width,
                signed,
            } => {
                let rt1_n = register_to_dynasm(*rt1)?;
                let rt2_n = register_to_dynasm(*rt2)?;
                let base_n = register_to_dynasm_xsp(address_base_of(addr))?;
                match (width, signed) {
                    (AccessWidth::Word, false) => {
                        encode_pair_with!(ops, addr, rt1_n, rt2_n, base_n, ldp, W)
                    }
                    (AccessWidth::Word, true) => {
                        encode_pair_with!(ops, addr, rt1_n, rt2_n, base_n, ldpsw, X)
                    }
                    (AccessWidth::Extended, false) => {
                        encode_pair_with!(ops, addr, rt1_n, rt2_n, base_n, ldp, X)
                    }
                    (AccessWidth::Extended, true) => {
                        Err("LDPSW only supports 32-bit access width".into())
                    }
                    (AccessWidth::Byte, _) | (AccessWidth::Half, _) => Err(format!(
                        "LDP {:?} access width not supported (Word/Extended only)",
                        width
                    )),
                }
            }
            Instruction::Stp {
                rt1,
                rt2,
                addr,
                width,
            } => {
                let rt1_n = register_to_dynasm(*rt1)?;
                let rt2_n = register_to_dynasm(*rt2)?;
                let base_n = register_to_dynasm_xsp(address_base_of(addr))?;
                match width {
                    AccessWidth::Word => {
                        encode_pair_with!(ops, addr, rt1_n, rt2_n, base_n, stp, W)
                    }
                    AccessWidth::Extended => {
                        encode_pair_with!(ops, addr, rt1_n, rt2_n, base_n, stp, X)
                    }
                    AccessWidth::Byte | AccessWidth::Half => Err(format!(
                        "STP {:?} access width not supported (Word/Extended only)",
                        width
                    )),
                }
            }
        }
    }
}

/// PC-relative range limits for AArch64 branch encodings.
#[derive(Debug, Clone, Copy)]
enum BranchRange {
    /// B / BL: ±128 MiB (imm26 << 2).
    B,
    /// B.cond / CBZ / CBNZ: ±1 MiB (imm19 << 2).
    #[allow(dead_code)]
    Cond,
    /// TBZ / TBNZ: ±32 KiB (imm14 << 2).
    #[allow(dead_code)]
    Test,
}

impl BranchRange {
    fn max_byte_offset(self) -> i64 {
        match self {
            BranchRange::B => 1 << 27,    // 128 MiB
            BranchRange::Cond => 1 << 20, // 1 MiB
            BranchRange::Test => 1 << 15, // 32 KiB
        }
    }
}

/// Compute the byte-offset of `target` from `current_pc`, validating it lies
/// within the branch family's reachable range and is 4-byte aligned. The
/// returned `i32` is the input dynasm-rs expects for the branch immediate.
fn pc_relative_offset(target: LabelId, current_pc: u64, range: BranchRange) -> Result<i32, String> {
    let offset = (target.0 as i64).wrapping_sub(current_pc as i64);
    if offset % 4 != 0 {
        return Err(format!(
            "Branch target 0x{:x} not 4-byte aligned (offset {})",
            target.0, offset
        ));
    }
    let max = range.max_byte_offset();
    if offset >= max || offset < -max {
        return Err(format!(
            "Branch offset {} out of range for {:?} (±{} bytes)",
            offset, range, max
        ));
    }
    Ok(offset as i32)
}

impl Default for AArch64Assembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the base register from an `AddressOperand`. Mirrors
/// `ir::instructions::address_base` which is module-private; the encoder
/// keeps a local copy to avoid widening that surface.
fn address_base_of(addr: &AddressOperand) -> Register {
    match addr {
        AddressOperand::Imm { base, .. }
        | AddressOperand::Reg { base, .. }
        | AddressOperand::Ext { base, .. } => *base,
    }
}

fn register_to_dynasm(reg: Register) -> Result<u8, String> {
    reg.index()
        .ok_or_else(|| format!("Register {:?} not supported in dynasm encoding", reg))
}

/// Map a register to the `Xn|SP` encoding slot. Returns Err for XZR —
/// `Register::XZR.index() == Some(31)` would otherwise silently alias to SP.
fn register_to_dynasm_xsp(reg: Register) -> Result<u8, String> {
    match reg {
        Register::XZR => {
            Err("XZR is not encodable in the Xn|SP register slot (would decode as SP)".to_string())
        }
        Register::SP => Ok(31),
        other => other.index().ok_or_else(|| {
            format!(
                "Register {:?} not supported in dynasm Xn|SP encoding",
                other
            )
        }),
    }
}

/// Map a register to the `Wn|WSP` encoding slot. Returns Err for WZR — this
/// IR represents WZR as `Register::XZR`, whose register number 31 would decode
/// as WSP in this slot.
fn register_to_dynasm_wsp(reg: Register) -> Result<u8, String> {
    match reg {
        Register::XZR => Err(
            "WZR is not encodable in the Wn|WSP register slot (would decode as WSP)".to_string(),
        ),
        Register::SP => Ok(31),
        other => other.index().ok_or_else(|| {
            format!(
                "Register {:?} not supported in dynasm Wn|WSP encoding",
                other
            )
        }),
    }
}

fn logical_imm32_for_assembler(mnemonic: &str, imm: i64) -> Result<u32, String> {
    let val = logical_imm32_value(imm).ok_or_else(|| {
        format!(
            "{} immediate {} is out of range for a 32-bit logical immediate",
            mnemonic, imm
        )
    })?;
    if dynasmrt::aarch64::encode_logical_immediate_32bit(val).is_none() {
        return Err(format!(
            "{} immediate 0x{:x} is not a valid AArch64 32-bit logical immediate",
            mnemonic, val
        ));
    }
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mov_reg_encoding() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }];

        let result = assembler.assemble_instructions(&instructions, 0);
        assert!(result.is_ok());
        let bytes = result.expect("MOV register encoding should succeed");
        assert_eq!(bytes.len(), 4); // One 32-bit instruction
        assert_ne!(bytes, [0, 0, 0, 0]); // Should not be empty
    }

    #[test]
    fn test_mov_imm_encoding() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];

        let result = assembler.assemble_instructions(&instructions, 0);
        assert!(result.is_ok());
        let bytes = result.expect("MOV immediate encoding should succeed");
        assert_eq!(bytes.len(), 4);
        assert_ne!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_add_reg_encoding() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let result = assembler.assemble_instructions(&instructions, 0);
        assert!(result.is_ok());
        let bytes = result.expect("ADD register encoding should succeed");
        assert_eq!(bytes.len(), 4);
        assert_ne!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_add_imm_encoding() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(10),
        }];

        let result = assembler.assemble_instructions(&instructions, 0);
        assert!(result.is_ok());
        let bytes = result.expect("ADD immediate encoding should succeed");
        assert_eq!(bytes.len(), 4);
        assert_ne!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn assemble_w_add_sub_mov_forms() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![
            Instruction::MovRegW {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::AddW {
                rd: Register::X2,
                rn: Register::X3,
                rm: Operand::Register(Register::X4),
            },
            Instruction::AddW {
                rd: Register::X5,
                rn: Register::X6,
                rm: Operand::Immediate(7),
            },
            Instruction::SubW {
                rd: Register::X7,
                rn: Register::X8,
                rm: Operand::Register(Register::X9),
            },
            Instruction::SubW {
                rd: Register::X10,
                rn: Register::X11,
                rm: Operand::Immediate(12),
            },
        ];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("W register forms should assemble");
        assert_eq!(bytes.len(), instructions.len() * 4);
    }

    #[test]
    fn test_invalid_immediate() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0x10000, // Too large
        }];

        let result = assembler.assemble_instructions(&instructions, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_instructions() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 42,
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];

        let result = assembler.assemble_instructions(&instructions, 0);
        assert!(result.is_ok());
        let bytes = result.expect("Multiple instruction encoding should succeed");
        assert_eq!(bytes.len(), 8); // Two 32-bit instructions
    }

    // Disassembly-based correctness tests
    // These tests verify that generated machine code disassembles to the expected instructions

    fn disassemble_and_verify(
        bytes: &[u8],
        expected_mnemonic: &str,
        expected_operands_contain: &[&str],
    ) {
        use capstone::prelude::*;

        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .expect("Failed to create Capstone instance");

        let insns = cs.disasm_all(bytes, 0x0).expect("Failed to disassemble");

        assert_eq!(insns.len(), 1, "Expected exactly one instruction");

        let insn = insns.iter().next().expect("No instruction found");
        let mnemonic = insn.mnemonic().expect("No mnemonic");
        let op_str = insn.op_str().expect("No operands");

        assert_eq!(
            mnemonic, expected_mnemonic,
            "Mnemonic mismatch: got '{}', expected '{}'",
            mnemonic, expected_mnemonic
        );

        for expected_op in expected_operands_contain {
            assert!(
                op_str.contains(expected_op),
                "Operand string '{}' does not contain expected '{}'",
                op_str,
                expected_op
            );
        }
    }

    #[test]
    fn test_mov_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("MOV register encoding should succeed");
        disassemble_and_verify(&bytes, "mov", &["x0", "x1"]);
    }

    #[test]
    fn test_mov_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("MOV immediate encoding should succeed");
        disassemble_and_verify(&bytes, "mov", &["x0", "0x2a"]);
    }

    #[test]
    fn test_add_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("ADD register encoding should succeed");
        disassemble_and_verify(&bytes, "add", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_add_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(10),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("ADD immediate encoding should succeed");
        disassemble_and_verify(&bytes, "add", &["x0", "x1", "0xa"]);
    }

    #[test]
    fn test_sub_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Sub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("SUB register encoding should succeed");
        disassemble_and_verify(&bytes, "sub", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_sub_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Sub {
            rd: Register::X5,
            rn: Register::X5,
            rm: Operand::Immediate(1),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("SUB immediate encoding should succeed");
        disassemble_and_verify(&bytes, "sub", &["x5", "x5", "#1"]);
    }

    #[test]
    fn test_and_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("AND encoding should succeed");
        disassemble_and_verify(&bytes, "and", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_orr_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Orr {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("ORR encoding should succeed");
        disassemble_and_verify(&bytes, "orr", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_eor_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("EOR encoding should succeed");
        disassemble_and_verify(&bytes, "eor", &["x0", "x0", "x0"]);
    }

    #[test]
    fn test_and_immediate_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0xFF),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("AND immediate encoding should succeed");
        disassemble_and_verify(&bytes, "and", &["x0", "x1", "0xff"]);
    }

    #[test]
    fn test_orr_immediate_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Orr {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0xFFFF),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("ORR immediate encoding should succeed");
        disassemble_and_verify(&bytes, "orr", &["x0", "x1", "0xffff"]);
    }

    #[test]
    fn test_eor_immediate_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0xF0F0F0F0F0F0F0F0_u64 as i64),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("EOR immediate encoding should succeed");
        disassemble_and_verify(&bytes, "eor", &["x0", "x1", "0xf0f0f0f0f0f0f0f0"]);
    }

    #[test]
    fn test_tst_immediate_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Tst {
            rn: Register::X1,
            rm: Operand::Immediate(0xFF),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("TST immediate encoding should succeed");
        disassemble_and_verify(&bytes, "tst", &["x1", "0xff"]);
    }

    #[test]
    fn test_ands_immediate_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ands {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0xFF),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("ANDS immediate encoding should succeed");
        disassemble_and_verify(&bytes, "ands", &["x0", "x1", "0xff"]);
    }

    #[test]
    fn test_logical_imm_rejects_unencodable() {
        let mut assembler = AArch64Assembler::new();

        // All-zeros: bitmask immediate spec excludes 0.
        let r = assembler.assemble_instructions(
            &[Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(0),
                width: crate::ir::RegisterWidth::X64,
            }],
            0,
        );
        let err = r.expect_err("AND #0 must be rejected");
        assert!(
            err.contains("is not a valid AArch64 logical immediate"),
            "unexpected error: {err}",
        );

        // All-ones: -1 i64 reinterprets to 0xFFFF_FFFF_FFFF_FFFF, also excluded.
        let r = assembler.assemble_instructions(
            &[Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(-1),
                width: crate::ir::RegisterWidth::X64,
            }],
            0,
        );
        assert!(
            r.is_err_and(|e| e.contains("is not a valid AArch64 logical immediate")),
            "AND #-1 must be rejected",
        );

        // 0b101: non-replicating pattern.
        let r = assembler.assemble_instructions(
            &[Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(5),
                width: crate::ir::RegisterWidth::X64,
            }],
            0,
        );
        assert!(
            r.is_err_and(|e| e.contains("is not a valid AArch64 logical immediate")),
            "AND #5 must be rejected",
        );

        // TST shares the encoder path.
        let r = assembler.assemble_instructions(
            &[Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Immediate(0),
                width: crate::ir::RegisterWidth::X64,
            }],
            0,
        );
        assert!(
            r.is_err_and(|e| e.contains("is not a valid AArch64 logical immediate")),
            "TST #0 must be rejected",
        );
    }

    #[test]
    fn test_high_bit_logical_imm_encodable() {
        // Single high bit (0x8000_0000_0000_0000) is a valid AArch64 bitmask
        // immediate — pattern length 64, one bit set. Issue #65 canonical case.
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0x8000_0000_0000_0000_u64 as i64),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("AND with single high bit should encode");
        disassemble_and_verify(&bytes, "and", &["x0", "x1", "0x8000000000000000"]);
    }

    #[test]
    fn test_and_immediate_with_sp_destination_roundtrips() {
        // AArch64 AND (immediate) puts rd in the Xn|SP slot — SP-as-destination
        // is a legitimate encoding. Verifies the assembler routes rd through
        // register_to_dynasm_xsp inside the Immediate arm (not the plain Xn
        // helper used by the register/shifted-register arms).
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::And {
            rd: Register::SP,
            rn: Register::X1,
            rm: Operand::Immediate(0xFF),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("AND with SP destination (immediate form) should encode");
        disassemble_and_verify(&bytes, "and", &["sp", "x1", "0xff"]);
    }

    #[test]
    fn test_ands_immediate_with_xzr_destination_roundtrips() {
        // ANDS (immediate) with rd=XZR is the canonical TST shape per ARM ARM;
        // Capstone disassembles it back as `tst`. Verifies the assembler
        // accepts rd=XZR for ANDS (which uses the plain Xn slot, unlike
        // AND/ORR/EOR's Xn|SP slot) and that round-trip yields the TST alias.
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ands {
            rd: Register::XZR,
            rn: Register::X1,
            rm: Operand::Immediate(0xFF),
            width: crate::ir::RegisterWidth::X64,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("ANDS with XZR destination (immediate form) should encode");
        // Capstone canonicalises ANDS XZR ..., #imm → TST X..., #imm.
        disassemble_and_verify(&bytes, "tst", &["x1", "0xff"]);
    }

    #[test]
    fn test_w32_logical_immediates_roundtrip() {
        let cases: Vec<(Instruction, &str, Vec<&str>)> = vec![
            (
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xFF),
                    width: RegisterWidth::W32,
                },
                "and",
                vec!["w0", "w1", "0xff"],
            ),
            (
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xFF),
                    width: RegisterWidth::W32,
                },
                "orr",
                vec!["w0", "w1", "0xff"],
            ),
            (
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xFF),
                    width: RegisterWidth::W32,
                },
                "eor",
                vec!["w0", "w1", "0xff"],
            ),
            (
                Instruction::Tst {
                    rn: Register::X1,
                    rm: Operand::Immediate(0xFF),
                    width: RegisterWidth::W32,
                },
                "tst",
                vec!["w1", "0xff"],
            ),
            (
                Instruction::Ands {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xFF),
                    width: RegisterWidth::W32,
                },
                "ands",
                vec!["w0", "w1", "0xff"],
            ),
            (
                Instruction::And {
                    rd: Register::SP,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xFF),
                    width: RegisterWidth::W32,
                },
                "and",
                vec!["wsp", "w1", "0xff"],
            ),
        ];

        for (instr, mnemonic, operands) in cases {
            let mut assembler = AArch64Assembler::new();
            let bytes = assembler
                .assemble_instructions(&[instr], 0)
                .expect("W32 logical immediate should encode");
            disassemble_and_verify(&bytes, mnemonic, &operands);
        }
    }

    #[test]
    fn test_w32_logical_immediates_reject_invalid_masks_and_slots() {
        let mut assembler = AArch64Assembler::new();

        for imm in [0, -1, 5, 0x1_0000_00FF] {
            let err = assembler
                .assemble_instructions(
                    &[Instruction::And {
                        rd: Register::X0,
                        rn: Register::X1,
                        rm: Operand::Immediate(imm),
                        width: RegisterWidth::W32,
                    }],
                    0,
                )
                .expect_err("invalid W32 logical immediate must be rejected");
            assert!(
                err.contains("32-bit logical immediate"),
                "unexpected error for imm {imm}: {err}"
            );
        }

        assert!(
            assembler
                .assemble_instructions(
                    &[Instruction::And {
                        rd: Register::XZR,
                        rn: Register::X1,
                        rm: Operand::Immediate(0xFF),
                        width: RegisterWidth::W32,
                    }],
                    0,
                )
                .is_err(),
            "AND WZR, Wn, #imm would alias to WSP and must be rejected"
        );
        assert!(
            assembler
                .assemble_instructions(
                    &[Instruction::Ands {
                        rd: Register::SP,
                        rn: Register::X1,
                        rm: Operand::Immediate(0xFF),
                        width: RegisterWidth::W32,
                    }],
                    0,
                )
                .is_err(),
            "ANDS WSP, Wn, #imm is not encodable"
        );
        assert!(
            assembler
                .assemble_instructions(
                    &[Instruction::Tst {
                        rn: Register::SP,
                        rm: Operand::Immediate(0xFF),
                        width: RegisterWidth::W32,
                    }],
                    0,
                )
                .is_err(),
            "TST WSP, #imm is not encodable"
        );
    }

    #[test]
    fn test_lsl_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Lsl {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(5),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("LSL immediate encoding should succeed");
        disassemble_and_verify(&bytes, "lsl", &["x0", "x1", "#5"]);
    }

    #[test]
    fn test_lsr_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Lsr {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(8),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("LSR immediate encoding should succeed");
        disassemble_and_verify(&bytes, "lsr", &["x0", "x1", "#8"]);
    }

    #[test]
    fn test_asr_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Asr {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(16),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("ASR immediate encoding should succeed");
        disassemble_and_verify(&bytes, "asr", &["x0", "x1", "0x10"]);
    }

    #[test]
    fn test_lsl_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Lsl {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Register(Register::X2),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("LSL register encoding should succeed");
        disassemble_and_verify(&bytes, "lsl", &["x0", "x1", "x2"]);
    }

    fn assert_csel_family_disasm(
        cs: &capstone::Capstone,
        bytes: &[u8],
        mnem: &str,
        cond: Condition,
        expected_cond: &str,
    ) {
        let insns = cs
            .disasm_all(bytes, 0)
            .unwrap_or_else(|e| panic!("{mnem} cond={cond:?}: disasm failed: {e}"));
        assert_eq!(
            insns.len(),
            1,
            "{mnem} cond={cond:?}: expected 1 instruction, got {}",
            insns.len()
        );
        let insn = insns.iter().next().expect("one instruction");
        let got_mnem = insn.mnemonic().expect("mnemonic");
        let got_ops = insn.op_str().expect("op_str");
        assert_eq!(
            got_mnem, mnem,
            "{mnem} cond={cond:?}: wrong mnemonic '{got_mnem}' (ops='{got_ops}')"
        );
        for needle in ["x0", "x1", "x2", expected_cond] {
            assert!(
                got_ops.contains(needle),
                "{mnem} cond={cond:?}: ops '{got_ops}' missing '{needle}'"
            );
        }
    }

    /// Round-trips every (CSEL-family mnemonic, condition code) pair through
    /// the assembler and Capstone. Capstone canonicalises CS→hs and CC→lo
    /// (preferred AArch64 mnemonics).
    #[test]
    fn csel_family_round_trip_all_conditions() {
        use capstone::prelude::*;
        type CsBuild = fn(Condition) -> Instruction;

        let conds: &[(Condition, &str)] = &[
            (Condition::EQ, "eq"),
            (Condition::NE, "ne"),
            (Condition::CS, "hs"),
            (Condition::CC, "lo"),
            (Condition::MI, "mi"),
            (Condition::PL, "pl"),
            (Condition::VS, "vs"),
            (Condition::VC, "vc"),
            (Condition::HI, "hi"),
            (Condition::LS, "ls"),
            (Condition::GE, "ge"),
            (Condition::LT, "lt"),
            (Condition::GT, "gt"),
            (Condition::LE, "le"),
            (Condition::AL, "al"),
            (Condition::NV, "nv"),
        ];

        let build_csel: CsBuild = |c| Instruction::Csel {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: c,
        };
        let build_csinc: CsBuild = |c| Instruction::Csinc {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: c,
        };
        let build_csinv: CsBuild = |c| Instruction::Csinv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: c,
        };
        let build_csneg: CsBuild = |c| Instruction::Csneg {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: c,
        };
        let mnemonics: &[(&str, CsBuild)] = &[
            ("csel", build_csel),
            ("csinc", build_csinc),
            ("csinv", build_csinv),
            ("csneg", build_csneg),
        ];

        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .expect("Capstone init");
        let mut assembler = AArch64Assembler::new();
        for &(cond, cond_str) in conds {
            for &(mnem, build) in mnemonics {
                let bytes = assembler
                    .assemble_instructions(&[build(cond)], 0)
                    .unwrap_or_else(|e| panic!("{mnem} cond={cond:?}: encode failed: {e}"));
                assert_csel_family_disasm(&cs, &bytes, mnem, cond, cond_str);
            }
        }
    }

    #[test]
    fn test_ccmp_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ccmp {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            nzcv: 5,
            cond: Condition::EQ,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("CCMP register form should encode");
        disassemble_and_verify(&bytes, "ccmp", &["x1", "x2", "#5", "eq"]);
    }

    #[test]
    fn test_ccmp_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ccmp {
            rn: Register::X3,
            rm: Operand::Immediate(15),
            nzcv: 0,
            cond: Condition::NE,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("CCMP immediate form should encode");
        disassemble_and_verify(&bytes, "ccmp", &["x3", "#0xf", "#0", "ne"]);
    }

    #[test]
    fn test_ccmn_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ccmn {
            rn: Register::X0,
            rm: Operand::Register(Register::X1),
            nzcv: 15,
            cond: Condition::LT,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("CCMN register form should encode");
        disassemble_and_verify(&bytes, "ccmn", &["x0", "x1", "#0xf", "lt"]);
    }

    #[test]
    fn test_ccmn_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ccmn {
            rn: Register::X4,
            rm: Operand::Immediate(7),
            nzcv: 4,
            cond: Condition::GE,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("CCMN immediate form should encode");
        disassemble_and_verify(&bytes, "ccmn", &["x4", "#7", "#4", "ge"]);
    }

    #[test]
    fn test_ubfx_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 8,
            width: 16,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("UBFX encoding should succeed");
        disassemble_and_verify(&bytes, "ubfx", &["x0", "x1", "#8", "#0x10"]);
    }

    #[test]
    fn test_ubfx_full_width_correctness() {
        // UBFX X0, X1, #0, #64 — the maximally wide field. Exercises the
        // boundary of the (lsb+width <= 64) constraint.
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 0,
            width: 64,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("UBFX (full width) encoding should succeed");
        // UBFX with (lsb=0, width=64) is canonically `mov x0, x1` in Capstone's
        // alias decoder, since immr=0/imms=63 with the UBFM bit pattern
        // matches the LSR-by-0 form. Roundtrip pinned to "mov" is acceptable.
        // Verify just that encoding succeeded; semantic equivalence is
        // covered by the concrete + SMT tests.
        assert_eq!(bytes.len(), 4, "UBFX must encode to exactly 4 bytes");
    }

    #[test]
    fn test_sbfiz_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Sbfiz {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("SBFIZ encoding should succeed");
        disassemble_and_verify(&bytes, "sbfiz", &["x0", "x1", "#4", "#8"]);
    }

    #[test]
    fn test_ubfiz_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ubfiz {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("UBFIZ encoding should succeed");
        disassemble_and_verify(&bytes, "ubfiz", &["x0", "x1", "#4", "#8"]);
    }

    #[test]
    fn test_bfxil_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Bfxil {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 8,
            width: 8,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("BFXIL encoding should succeed");
        disassemble_and_verify(&bytes, "bfxil", &["x0", "x1", "#8", "#8"]);
    }

    #[test]
    fn test_bfi_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Bfi {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("BFI encoding should succeed");
        disassemble_and_verify(&bytes, "bfi", &["x0", "x1", "#4", "#8"]);
    }

    #[test]
    fn test_sbfx_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Sbfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 8,
            width: 16,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("SBFX encoding should succeed");
        disassemble_and_verify(&bytes, "sbfx", &["x0", "x1", "#8", "#0x10"]);
    }

    #[test]
    fn test_ubfx_high_lsb_correctness() {
        // (lsb=32, width=8) — high-half extract that doesn't collide with the
        // LSR alias. Under UBFM, LSR is the form where imms == 63
        // (i.e., lsb+width == 64); any (lsb, width) with lsb+width < 64
        // disassembles as UBFX.
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ubfx {
            rd: Register::X2,
            rn: Register::X3,
            lsb: 32,
            width: 8,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("UBFX (high lsb) encoding should succeed");
        disassemble_and_verify(&bytes, "ubfx", &["x2", "x3", "#0x20", "#8"]);
    }

    #[test]
    fn test_madd_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Madd {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X3,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("MADD encoding should succeed");
        disassemble_and_verify(&bytes, "madd", &["x0", "x1", "x2", "x3"]);
    }

    #[test]
    fn test_msub_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Msub {
            rd: Register::X4,
            rn: Register::X5,
            rm: Register::X6,
            ra: Register::X7,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("MSUB encoding should succeed");
        disassemble_and_verify(&bytes, "msub", &["x4", "x5", "x6", "x7"]);
    }

    #[test]
    fn test_mneg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Mneg {
            rd: Register::X10,
            rn: Register::X11,
            rm: Register::X12,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("MNEG encoding should succeed");
        disassemble_and_verify(&bytes, "mneg", &["x10", "x11", "x12"]);
    }

    #[test]
    fn test_smulh_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Smulh {
            rd: Register::X13,
            rn: Register::X14,
            rm: Register::X15,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("SMULH encoding should succeed");
        disassemble_and_verify(&bytes, "smulh", &["x13", "x14", "x15"]);
    }

    #[test]
    fn test_umulh_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Umulh {
            rd: Register::X16,
            rn: Register::X17,
            rm: Register::X18,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("UMULH encoding should succeed");
        disassemble_and_verify(&bytes, "umulh", &["x16", "x17", "x18"]);
    }

    #[test]
    fn test_mvn_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Mvn {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("MVN encoding should succeed");
        disassemble_and_verify(&bytes, "mvn", &["x0", "x1"]);
    }

    #[test]
    fn test_neg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Neg {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("NEG encoding should succeed");
        disassemble_and_verify(&bytes, "neg", &["x0", "x1"]);
    }

    #[test]
    fn test_negs_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Negs {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("NEGS encoding should succeed");
        disassemble_and_verify(&bytes, "negs", &["x0", "x1"]);
    }

    #[test]
    fn test_movn_correctness_shift_0() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovN {
            rd: Register::X0,
            imm: 0xFFFF,
            shift: 0,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("MOVN encoding should succeed");
        // Exact byte-level check. MOVN 64-bit base is 0x92800000; imm16<<5
        // for #0xFFFF gives 0x1FFFE0; Rd=0 contributes nothing → word
        // 0x929FFFE0, little-endian = [0xE0, 0xFF, 0x9F, 0x92]. An off-by-one
        // in either the imm16 or hw bits would fail this rather than slip
        // through a Capstone mnemonic check.
        assert_eq!(bytes, [0xE0, 0xFF, 0x9F, 0x92]);
    }

    #[test]
    fn test_cset_disassembles_to_cset() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Cset {
            rd: Register::X0,
            cond: Condition::EQ,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("CSET encoding should succeed");
        // Capstone canonicalises `csinc x0, xzr, xzr, ne` back to `cset x0, eq`
        disassemble_and_verify(&bytes, "cset", &["x0", "eq"]);
    }

    #[test]
    fn test_ror_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ror {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(5),
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("ROR imm encoding should succeed");
        // Include the literal shift amount: an off-by-one in the encoded
        // immediate would otherwise slip through.
        disassemble_and_verify(&bytes, "ror", &["x0", "x1", "#5"]);
    }

    #[test]
    fn test_ror_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ror {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Register(Register::X2),
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("ROR reg encoding should succeed");
        disassemble_and_verify(&bytes, "ror", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_csetm_disassembles_to_csetm() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Csetm {
            rd: Register::X3,
            cond: Condition::NE,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("CSETM encoding should succeed");
        disassemble_and_verify(&bytes, "csetm", &["x3", "ne"]);
    }

    /// ADDS/SUBS immediate-form accepts SP as `rn` (the `Xn|SP` encoding
    /// slot decodes 31 as SP). The parser and `is_encodable_aarch64` both
    /// admit this — the encoder must too.
    #[test]
    fn test_adds_subs_imm_accept_sp_rn() {
        let mut assembler = AArch64Assembler::new();
        for instr in [
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(8),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(8),
            },
        ] {
            let bytes = assembler
                .assemble_instructions(&[instr], 0)
                .unwrap_or_else(|e| {
                    panic!(
                        "Expected SP-as-rn to encode, got Err({}) for {:?}",
                        e, instr
                    )
                });
            assert_eq!(bytes.len(), 4);
        }
    }

    /// ADD/SUB immediate-form accepts SP as `rn` for the same `Xn|SP`
    /// source slot covered by the ADDS/SUBS regression above.
    #[test]
    fn test_add_sub_imm_accept_sp_rn() {
        let mut assembler = AArch64Assembler::new();
        for instr in [
            Instruction::Add {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(8),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(8),
            },
        ] {
            let bytes = assembler
                .assemble_instructions(&[instr], 0)
                .unwrap_or_else(|e| {
                    panic!(
                        "Expected SP-as-rn to encode, got Err({}) for {:?}",
                        e, instr
                    )
                });
            assert_eq!(bytes.len(), 4);
        }
    }

    /// CMP/CMN immediate-form also uses the `Xn|SP` source slot.
    #[test]
    fn test_cmp_cmn_imm_accept_sp_rn() {
        for (instr, mnemonic) in [
            (
                Instruction::Cmp {
                    rn: Register::SP,
                    rm: Operand::Immediate(8),
                },
                "cmp",
            ),
            (
                Instruction::Cmn {
                    rn: Register::SP,
                    rm: Operand::Immediate(8),
                },
                "cmn",
            ),
        ] {
            let mut assembler = AArch64Assembler::new();
            let bytes = assembler
                .assemble_instructions(&[instr], 0)
                .unwrap_or_else(|e| panic!("{} sp, #8 should encode: {}", mnemonic, e));
            disassemble_and_verify(&bytes, mnemonic, &["sp", "#8"]);
        }
    }

    #[test]
    fn test_add_imm_sp_rn_roundtrip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Add {
                    rd: Register::X0,
                    rn: Register::SP,
                    rm: Operand::Immediate(8),
                }],
                0,
            )
            .expect("ADD imm with SP rn should encode");
        disassemble_and_verify(&bytes, "add", &["x0", "sp", "#8"]);
    }

    #[test]
    fn test_sub_imm_sp_rn_roundtrip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Sub {
                    rd: Register::X0,
                    rn: Register::SP,
                    rm: Operand::Immediate(8),
                }],
                0,
            )
            .expect("SUB imm with SP rn should encode");
        disassemble_and_verify(&bytes, "sub", &["x0", "sp", "#8"]);
    }

    /// Capstone round-trip for ADDS with SP as `rn` — guards against silent
    /// off-by-one in the encoded slot. Capstone must disassemble back to
    /// `adds` with `sp` in the rn position.
    #[test]
    fn test_adds_imm_sp_rn_roundtrip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Adds {
                    rd: Register::X0,
                    rn: Register::SP,
                    rm: Operand::Immediate(8),
                }],
                0,
            )
            .expect("ADDS imm with SP rn should encode");
        disassemble_and_verify(&bytes, "adds", &["x0", "sp", "#8"]);
    }

    /// SUBS counterpart to `test_adds_imm_sp_rn_roundtrip`. The encoding
    /// logic is shared via `register_to_dynasm_xsp` but a regression
    /// specific to SUBS would otherwise go unnoticed.
    #[test]
    fn test_subs_imm_sp_rn_roundtrip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Subs {
                    rd: Register::X0,
                    rn: Register::SP,
                    rm: Operand::Immediate(8),
                }],
                0,
            )
            .expect("SUBS imm with SP rn should encode");
        disassemble_and_verify(&bytes, "subs", &["x0", "sp", "#8"]);
    }

    /// Defense-in-depth: SP as `rd` for ADDS/SUBS is rejected. Architecturally,
    /// the `rd` slot is `Xd|XZR` (decodes 31 as XZR), so dynasm's `X(31)`
    /// maps to XZR — but `Register::SP` has `index() == None`, so
    /// `register_to_dynasm(SP)` returns Err and the encoder bails early.
    /// Test that this remains the case.
    #[test]
    fn test_adds_subs_imm_reject_sp_rd() {
        let mut assembler = AArch64Assembler::new();
        for instr in [
            Instruction::Adds {
                rd: Register::SP,
                rn: Register::X0,
                rm: Operand::Immediate(8),
            },
            Instruction::Subs {
                rd: Register::SP,
                rn: Register::X0,
                rm: Operand::Immediate(8),
            },
        ] {
            let result = assembler.assemble_instructions(&[instr], 0);
            assert!(
                result.is_err(),
                "Expected encoder to reject SP as rd, got {:?} for {:?}",
                result,
                instr
            );
        }
    }

    /// Defense-in-depth: ADDS/SUBS with immediate `rm` and XZR as `rn` would
    /// encode to `ADDS Xd, SP, #imm` because the immediate-form encoding
    /// slot is `Xn|SP` (where register 31 means SP, not XZR). The encoder
    /// must refuse this construction rather than silently using SP.
    #[test]
    fn test_adds_subs_imm_reject_xzr_rn() {
        let mut assembler = AArch64Assembler::new();
        for instr in [
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
        ] {
            let result = assembler.assemble_instructions(&[instr], 0);
            assert!(
                result.is_err(),
                "Expected encoder to reject {:?}, got {:?}",
                instr,
                result
            );
        }
        // Register-form ADDS/SUBS with XZR as rn must still succeed — the
        // register-form encoding decodes 31 as XZR correctly.
        let ok = assembler.assemble_instructions(
            &[Instruction::Adds {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Register(Register::X1),
            }],
            0,
        );
        assert!(ok.is_ok(), "register-form ADDS with XZR should encode");
    }

    /// ADD/SUB immediate-form `rn` is also `Xn|SP`, so XZR must be rejected
    /// instead of being encoded as SP.
    #[test]
    fn test_add_sub_imm_reject_xzr_rn() {
        let mut assembler = AArch64Assembler::new();
        for instr in [
            Instruction::Add {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
        ] {
            let result = assembler.assemble_instructions(&[instr], 0);
            assert!(
                result.is_err(),
                "Expected encoder to reject {:?}, got {:?}",
                instr,
                result
            );
        }
        // Register-form ADD/SUB with XZR as rn must still succeed — the
        // register-form encoding decodes 31 as XZR correctly.
        for instr in [
            Instruction::Add {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Register(Register::X1),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Register(Register::X1),
            },
        ] {
            let result = assembler.assemble_instructions(&[instr], 0);
            assert!(
                result.is_ok(),
                "register-form ADD/SUB with XZR should encode: {:?}",
                result
            );
        }
    }

    /// ADD/SUB immediate-form `rd` is `Xd|SP`, so SP must be accepted as the
    /// destination: `ADD SP, SP, #imm` / `SUB SP, SP, #imm` are the canonical
    /// stack-pointer adjusts. Round-trip through Capstone to pin the slot
    /// (both rd and rn must decode back to `sp`).
    #[test]
    fn test_add_imm_sp_rd_roundtrip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Add {
                    rd: Register::SP,
                    rn: Register::SP,
                    rm: Operand::Immediate(16),
                }],
                0,
            )
            .expect("ADD imm with SP as rd and rn should encode");
        disassemble_and_verify(&bytes, "add", &["sp, sp", "0x10"]);
    }

    #[test]
    fn test_sub_imm_sp_rd_roundtrip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Sub {
                    rd: Register::SP,
                    rn: Register::SP,
                    rm: Operand::Immediate(16),
                }],
                0,
            )
            .expect("SUB imm with SP as rd and rn should encode");
        disassemble_and_verify(&bytes, "sub", &["sp, sp", "0x10"]);
    }

    /// ADD/SUB immediate-form `rd` is `Xd|SP` (register 31 decodes as SP, not
    /// XZR), so XZR as the destination must be rejected rather than silently
    /// encoded as SP. `register_to_dynasm(XZR) == Some(31)` previously made the
    /// shared top-of-arm `rd_reg` binding alias XZR to SP; resolving `rd` via
    /// `register_to_dynasm_xsp` inside the immediate arm guards against that.
    #[test]
    fn test_add_sub_imm_reject_xzr_rd() {
        let mut assembler = AArch64Assembler::new();
        for instr in [
            Instruction::Add {
                rd: Register::XZR,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
            Instruction::Sub {
                rd: Register::XZR,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ] {
            let result = assembler.assemble_instructions(&[instr], 0);
            assert!(
                result.is_err(),
                "Expected encoder to reject XZR as rd, got {:?} for {:?}",
                result,
                instr
            );
        }
        // Register-form ADD/SUB with XZR as rd must still succeed — the
        // register-form encoding decodes 31 as XZR correctly.
        for instr in [
            Instruction::Add {
                rd: Register::XZR,
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
            },
            Instruction::Sub {
                rd: Register::XZR,
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
            },
        ] {
            let result = assembler.assemble_instructions(&[instr], 0);
            assert!(
                result.is_ok(),
                "register-form ADD/SUB with XZR as rd should encode: {:?}",
                result
            );
        }
    }

    /// Defense-in-depth: assembler must refuse CSET/CSETM with AL or NV,
    /// even if a caller bypasses `is_encodable_aarch64`. Lowering
    /// `Cset { cond: AL }` to the alias would emit `csinc ..., nv` (because
    /// invert(AL) = NV), which on AArch64 writes 0 — the opposite of the
    /// IR's "always 1" semantics.
    #[test]
    fn test_cset_rejects_al_at_encoder() {
        let mut assembler = AArch64Assembler::new();
        let cases = [
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::AL,
            },
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::NV,
            },
            Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::AL,
            },
            Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::NV,
            },
        ];
        for instr in cases {
            let result = assembler.assemble_instructions(&[instr], 0);
            assert!(
                result.is_err(),
                "Expected encoder to reject {:?}, got {:?}",
                instr,
                result
            );
        }
    }

    #[test]
    fn test_movn_correctness_shift_16() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovN {
            rd: Register::X0,
            imm: 1,
            shift: 16,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("MOVN encoding with shift should succeed");
        // Base 0x92800000 | hw=1<<21 (shift/16=1) = 0x200000 | imm16=1<<5 = 0x20
        // → 0x92A00020, little-endian = [0x20, 0x00, 0xA0, 0x92].
        assert_eq!(bytes, [0x20, 0x00, 0xA0, 0x92]);
    }

    /// Ensures we emit the 64-bit (sf=1) form, not the 32-bit Wn form —
    /// regression for the encoding bit-pattern error.
    #[test]
    fn test_csinv_is_xform_not_wform() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Csinv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::EQ,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions, 0)
            .expect("CSINV encoding should succeed");
        // disassemble_and_verify asserts mnemonic and operand presence; here
        // we additionally assert the operands are xN, not wN.
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .expect("Capstone");
        let insns = cs.disasm_all(&bytes, 0).expect("disasm");
        let insn = insns.iter().next().expect("instruction");
        let op_str = insn.op_str().expect("op_str");
        assert!(
            op_str.contains("x0") && op_str.contains("x1") && op_str.contains("x2"),
            "Expected 64-bit Xn form, got: {}",
            op_str
        );
        assert!(
            !op_str.contains("w0") && !op_str.contains("w1") && !op_str.contains("w2"),
            "Got 32-bit Wn form (sf-bit error); op_str: {}",
            op_str
        );
    }

    #[test]
    fn assemble_remaining_success_forms() {
        let cases = [
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(5),
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
                shift: Operand::Immediate(3),
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
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(5),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Immediate(5),
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: crate::ir::RegisterWidth::X64,
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
                imm: 2,
                shift: 32,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 3,
                shift: 48,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 0,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 16,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 32,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 48,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 0,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 16,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 32,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0xABCD,
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
                rm: Operand::Register(Register::X2),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(4),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(4),
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(4),
            },
        ];

        for instr in cases {
            let mut assembler = AArch64Assembler::new();
            assembler
                .assemble_instructions(&[instr], 0)
                .unwrap_or_else(|e| panic!("{} should assemble: {}", instr, e));
        }
    }

    #[test]
    fn reject_remaining_invalid_forms() {
        let cases = [
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(4096),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(-1),
            },
            // imm 5 (0b101) is not a valid AArch64 logical bitmask immediate
            // — exercise the encoder's rejection path for AND/ORR/EOR imm.
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(5),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(5),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(5),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(64),
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(-1),
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(64),
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(4096),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Immediate(-1),
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Immediate(5),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 1,
                shift: 8,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 1,
                shift: 8,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 1,
                shift: 24,
            },
            Instruction::Bic {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Bics {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Orn {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Eon {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(4096),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(-1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(5),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(64),
            },
        ];

        for instr in cases {
            let mut assembler = AArch64Assembler::new();
            assert!(
                assembler.assemble_instructions(&[instr], 0).is_err(),
                "{} should be rejected",
                instr
            );
        }
        assert!(register_to_dynasm(Register::SP).is_err());
        assert_eq!(register_to_dynasm_xsp(Register::SP).unwrap(), 31);
    }

    #[test]
    fn test_bit_manipulation_encoders_roundtrip() {
        let cases: &[(Instruction, &str)] = &[
            (
                Instruction::Clz {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                "clz",
            ),
            (
                Instruction::Cls {
                    rd: Register::X2,
                    rn: Register::X3,
                },
                "cls",
            ),
            (
                Instruction::Rbit {
                    rd: Register::X4,
                    rn: Register::X5,
                },
                "rbit",
            ),
            (
                Instruction::Rev {
                    rd: Register::X6,
                    rn: Register::X7,
                },
                "rev",
            ),
            (
                Instruction::Rev32 {
                    rd: Register::X8,
                    rn: Register::X9,
                },
                "rev32",
            ),
            (
                Instruction::Rev16 {
                    rd: Register::X10,
                    rn: Register::X11,
                },
                "rev16",
            ),
        ];
        for (instr, mnemonic) in cases {
            let mut assembler = AArch64Assembler::new();
            let bytes = assembler
                .assemble_instructions(std::slice::from_ref(instr), 0)
                .unwrap_or_else(|e| panic!("{} encoding should succeed: {}", mnemonic, e));
            let rd = instr.destination().unwrap().to_string();
            let rn = instr.source_registers()[0].to_string();
            disassemble_and_verify(&bytes, mnemonic, &[&rd, &rn]);
        }
    }

    /// Issue #60: the standalone UXTB instruction round-trips through
    /// Capstone as `uxtb w<rd>, w<rn>` (the architectural W-form per the
    /// ARM ARM UBFM alias).
    #[test]
    fn test_uxtb_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Uxtb {
                    rd: Register::X0,
                    rn: Register::X1,
                }],
                0,
            )
            .expect("UXTB encoding should succeed");
        disassemble_and_verify(&bytes, "uxtb", &["w0", "w1"]);
    }

    /// Issue #60: the ExtendedRegister operand form for ADD/SUB/CMP/CMN.
    /// Capstone disassembles as `<mnem> <rd>, <rn>, <wm-or-xm>, <kind> #<shift>`.
    #[test]
    fn test_extended_register_encoder_round_trip() {
        use crate::ir::ExtendKind;
        let cases: Vec<(Instruction, &str, Vec<String>)> = vec![
            (
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ExtendedRegister {
                        reg: Register::X2,
                        kind: ExtendKind::Uxtb,
                        shift: 2,
                    },
                },
                "add",
                vec!["x0".into(), "x1".into(), "w2".into(), "uxtb #2".into()],
            ),
            (
                Instruction::Sub {
                    rd: Register::X3,
                    rn: Register::X4,
                    rm: Operand::ExtendedRegister {
                        reg: Register::X5,
                        kind: ExtendKind::Sxth,
                        shift: 1,
                    },
                },
                "sub",
                vec!["x3".into(), "x4".into(), "w5".into(), "sxth #1".into()],
            ),
            (
                Instruction::Cmp {
                    rn: Register::SP,
                    rm: Operand::ExtendedRegister {
                        reg: Register::X7,
                        kind: ExtendKind::Uxtw,
                        shift: 3,
                    },
                },
                "cmp",
                vec!["sp".into(), "w7".into(), "uxtw #3".into()],
            ),
            (
                Instruction::Cmn {
                    rn: Register::SP,
                    rm: Operand::ExtendedRegister {
                        reg: Register::X7,
                        kind: ExtendKind::Uxtw,
                        shift: 3,
                    },
                },
                "cmn",
                vec!["sp".into(), "w7".into(), "uxtw #3".into()],
            ),
            (
                Instruction::Add {
                    rd: Register::X8,
                    rn: Register::X9,
                    rm: Operand::ExtendedRegister {
                        reg: Register::X10,
                        kind: ExtendKind::Uxtx,
                        shift: 4,
                    },
                },
                "add",
                vec!["x8".into(), "x9".into(), "x10".into(), "uxtx #4".into()],
            ),
        ];
        for (instr, mnemonic, expected_fragments) in &cases {
            let mut assembler = AArch64Assembler::new();
            let bytes = assembler
                .assemble_instructions(std::slice::from_ref(instr), 0)
                .unwrap_or_else(|e| panic!("{:?} encoding should succeed: {}", instr, e));
            let frag_refs: Vec<&str> = expected_fragments.iter().map(|s| s.as_str()).collect();
            disassemble_and_verify(&bytes, mnemonic, &frag_refs);
        }
    }

    /// Issue #60: SXTW sign-extends the low word of Wn into 64-bit Xd.
    #[test]
    fn test_sxtw_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Sxtw {
                    rd: Register::X0,
                    rn: Register::X1,
                }],
                0,
            )
            .expect("SXTW encoding should succeed");
        disassemble_and_verify(&bytes, "sxtw", &["x0", "w1"]);
    }

    /// Issue #60: SXTH sign-extends the low halfword of Wn into 64-bit Xd.
    #[test]
    fn test_sxth_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Sxth {
                    rd: Register::X0,
                    rn: Register::X1,
                }],
                0,
            )
            .expect("SXTH encoding should succeed");
        disassemble_and_verify(&bytes, "sxth", &["x0", "w1"]);
    }

    /// Issue #60: UXTH zero-extends the low halfword of Wn, so Capstone
    /// disassembles as `uxth w<rd>, w<rn>` (32-bit form).
    #[test]
    fn test_uxth_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Uxth {
                    rd: Register::X0,
                    rn: Register::X1,
                }],
                0,
            )
            .expect("UXTH encoding should succeed");
        disassemble_and_verify(&bytes, "uxth", &["w0", "w1"]);
    }

    /// Issue #60: SXTB sign-extends the low byte of Wn into the full 64-bit
    /// Xd, so Capstone disassembles as `sxtb x<rd>, w<rn>`.
    #[test]
    fn test_sxtb_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Sxtb {
                    rd: Register::X0,
                    rn: Register::X1,
                }],
                0,
            )
            .expect("SXTB encoding should succeed");
        disassemble_and_verify(&bytes, "sxtb", &["x0", "w1"]);
    }

    /// Issue #59: shifted-register forms round-trip through Capstone with the
    /// expected `<mnem> <rd>, <rn>, <rm>, <kind> #amt` text.
    #[test]
    fn test_assemble_shifted_register_round_trip() {
        // (instruction, expected mnemonic, expected operand fragments).
        // Capstone prints the shift kind lowercase: "lsl #3" etc.
        let cases: Vec<(Instruction, &str, Vec<String>)> = vec![
            (
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind: ShiftKind::Lsl,
                        amount: 3,
                    },
                },
                "add",
                vec!["x0".into(), "x1".into(), "x2".into(), "lsl #3".into()],
            ),
            (
                Instruction::Sub {
                    rd: Register::X3,
                    rn: Register::X4,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X5,
                        kind: ShiftKind::Lsr,
                        amount: 5,
                    },
                },
                "sub",
                vec!["x3".into(), "x4".into(), "x5".into(), "lsr #5".into()],
            ),
            (
                Instruction::And {
                    rd: Register::X6,
                    rn: Register::X7,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X8,
                        kind: ShiftKind::Asr,
                        amount: 7,
                    },
                    width: crate::ir::RegisterWidth::X64,
                },
                "and",
                vec!["x6".into(), "x7".into(), "x8".into(), "asr #7".into()],
            ),
            (
                Instruction::Orr {
                    rd: Register::X9,
                    rn: Register::X10,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X11,
                        kind: ShiftKind::Ror,
                        amount: 1,
                    },
                    width: crate::ir::RegisterWidth::X64,
                },
                "orr",
                vec!["x9".into(), "x10".into(), "x11".into(), "ror #1".into()],
            ),
            (
                Instruction::Eor {
                    rd: Register::X12,
                    rn: Register::X13,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X14,
                        kind: ShiftKind::Lsl,
                        amount: 2,
                    },
                    width: crate::ir::RegisterWidth::X64,
                },
                "eor",
                vec!["x12".into(), "x13".into(), "x14".into(), "lsl #2".into()],
            ),
            (
                Instruction::Cmp {
                    rn: Register::X15,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X16,
                        kind: ShiftKind::Lsl,
                        amount: 4,
                    },
                },
                "cmp",
                vec!["x15".into(), "x16".into(), "lsl #4".into()],
            ),
            (
                Instruction::Cmn {
                    rn: Register::X17,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X18,
                        kind: ShiftKind::Asr,
                        amount: 8,
                    },
                },
                "cmn",
                vec!["x17".into(), "x18".into(), "asr #8".into()],
            ),
            (
                Instruction::Tst {
                    rn: Register::X19,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X20,
                        kind: ShiftKind::Ror,
                        amount: 16,
                    },
                    width: crate::ir::RegisterWidth::X64,
                },
                "tst",
                vec!["x19".into(), "x20".into(), "ror #16".into()],
            ),
        ];

        for (instr, mnemonic, expected_ops) in cases {
            let mut assembler = AArch64Assembler::new();
            let bytes = assembler
                .assemble_instructions(&[instr], 0)
                .unwrap_or_else(|e| panic!("{} encoding should succeed: {}", mnemonic, e));
            let refs: Vec<&str> = expected_ops.iter().map(|s| s.as_str()).collect();
            disassemble_and_verify(&bytes, mnemonic, &refs);
        }
    }

    /// ROR with arithmetic ops (Add/Sub/Cmp/Cmn) is rejected by the encoder
    /// even if a caller bypasses `is_encodable_aarch64`.
    #[test]
    fn test_assemble_shifted_arith_rejects_ror() {
        let mut assembler = AArch64Assembler::new();
        let instr = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: ShiftKind::Ror,
                amount: 1,
            },
        };
        assert!(assembler.assemble_instructions(&[instr], 0).is_err());
    }

    // ===== Issue #69: branch / control-flow encoding =====

    #[test]
    fn test_ret_x30_round_trips_through_capstone() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(&[Instruction::Ret { rn: Register::X30 }], 0)
            .expect("RET X30 should encode");
        assert_eq!(bytes.len(), 4, "AArch64 instructions are 4 bytes");
        disassemble_and_verify(&bytes, "ret", &[]);
    }

    #[test]
    fn test_br_x16_round_trips_through_capstone() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(&[Instruction::Br { rn: Register::X16 }], 0)
            .expect("BR X16 should encode");
        disassemble_and_verify(&bytes, "br", &["x16"]);
    }

    /// Re-disassemble bytes with Capstone at a specific base address and
    /// return the operand string of the (single) instruction. Useful for
    /// PC-relative branch tests where the printed target depends on the
    /// instruction's absolute address.
    fn disasm_op_str_at(bytes: &[u8], base_addr: u64) -> String {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .expect("capstone");
        let insns = cs.disasm_all(bytes, base_addr).expect("disasm");
        assert_eq!(insns.len(), 1);
        insns
            .iter()
            .next()
            .unwrap()
            .op_str()
            .unwrap_or("")
            .to_string()
    }

    #[test]
    fn test_b_unconditional_encodes_forward_offset() {
        // From PC=0x1000, branch to 0x1010 → +16 bytes / +4 instructions.
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::B {
                    target: LabelId(0x1010),
                }],
                0x1000,
            )
            .expect("B should encode");
        let op = disasm_op_str_at(&bytes, 0x1000);
        assert!(
            op.contains("0x1010"),
            "B operand should resolve to 0x1010, got '{}'",
            op
        );
    }

    #[test]
    fn test_b_unconditional_rejects_out_of_range_offset() {
        // B reaches ±128 MiB. 256 MiB is far past the limit.
        let mut assembler = AArch64Assembler::new();
        let err = assembler
            .assemble_instructions(
                &[Instruction::B {
                    target: LabelId(0x1000_0000 + 0x1000_0000),
                }],
                0,
            )
            .expect_err("B at +256MiB must be rejected");
        assert!(err.contains("out of range"), "got '{}'", err);
    }

    #[test]
    fn test_bl_encodes_forward_offset() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Bl {
                    target: LabelId(0x2000),
                }],
                0x1000,
            )
            .expect("BL should encode");
        let op = disasm_op_str_at(&bytes, 0x1000);
        assert!(
            op.contains("0x2000"),
            "BL target should resolve to 0x2000, got '{}'",
            op
        );
    }

    #[test]
    fn test_cbz_encodes_with_register_and_target() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Cbz {
                    rn: Register::X0,
                    target: LabelId(0x1100),
                }],
                0x1000,
            )
            .expect("CBZ should encode");
        let op = disasm_op_str_at(&bytes, 0x1000);
        assert!(op.contains("x0") && op.contains("0x1100"), "got '{}'", op);
    }

    #[test]
    fn test_cbnz_encodes_with_register_and_target() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Cbnz {
                    rn: Register::X5,
                    target: LabelId(0x1100),
                }],
                0x1000,
            )
            .expect("CBNZ should encode");
        let op = disasm_op_str_at(&bytes, 0x1000);
        assert!(op.contains("x5") && op.contains("0x1100"), "got '{}'", op);
    }

    #[test]
    fn test_tbz_encodes_with_bit_and_target() {
        // TBZ Xn, #bit, target — Capstone renders the register as `wN` when
        // bit < 32 and `xN` when bit ≥ 32 (the encoding shares the bit field).
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Tbz {
                    rt: Register::X3,
                    bit: 5,
                    target: LabelId(0x1100),
                }],
                0x1000,
            )
            .expect("TBZ should encode");
        let op = disasm_op_str_at(&bytes, 0x1000);
        assert!(
            (op.contains("w3") || op.contains("x3")) && op.contains("0x1100"),
            "TBZ op should contain reg and target, got '{}'",
            op
        );
    }

    #[test]
    fn test_tbnz_encodes_with_bit_and_target() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::Tbnz {
                    rt: Register::X3,
                    bit: 7,
                    target: LabelId(0x1100),
                }],
                0x1000,
            )
            .expect("TBNZ should encode");
        let op = disasm_op_str_at(&bytes, 0x1000);
        assert!(
            (op.contains("w3") || op.contains("x3")) && op.contains("0x1100"),
            "got '{}'",
            op
        );
    }

    #[test]
    fn test_b_cond_eq_encodes_with_condition_and_target() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(
                &[Instruction::BCond {
                    target: LabelId(0x1100),
                    cond: Condition::EQ,
                }],
                0x1000,
            )
            .expect("B.EQ should encode");
        let op = disasm_op_str_at(&bytes, 0x1000);
        assert!(
            op.contains("0x1100"),
            "B.EQ target should resolve, got '{}'",
            op
        );

        // Verify the mnemonic carries the .eq suffix. Capstone with base=0
        // prints the operand as raw PC-relative #imm; check the mnemonic alone.
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .unwrap();
        let insns = cs.disasm_all(&bytes, 0x1000).unwrap();
        assert_eq!(insns.iter().next().unwrap().mnemonic().unwrap(), "b.eq");
    }

    // ===== Memory-op assembler tests (issue #68 / ADR-0007) =====
    //
    // Each test assembles one IR instruction and disassembles it back via
    // Capstone, then asserts the printed (mnemonic, op_str). LDUR / STUR
    // strings appear when the encoder routes an unscaled-or-negative offset
    // to the unscaled-signed encoding; they are pinned here so any
    // regression that silently flips the dispatch wakes the test up.

    fn assemble_one(instr: Instruction) -> Vec<u8> {
        let mut a = AArch64Assembler::new();
        a.assemble_instructions(&[instr], 0)
            .unwrap_or_else(|e| panic!("encode failed: {e}"))
    }

    fn disasm_mnem_op(bytes: &[u8]) -> (String, String) {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .unwrap();
        let insns = cs.disasm_all(bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 1, "expected one instruction in {:?}", bytes);
        let i = insns.iter().next().unwrap();
        (
            i.mnemonic().unwrap_or("").to_string(),
            i.op_str().unwrap_or("").to_string(),
        )
    }

    #[test]
    fn ldr_x_offset_zero_encodes_as_ldr_xn_xn() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1]");
    }

    #[test]
    fn ldr_x_offset_positive_uses_scaled_encoding() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1, #8]");
    }

    #[test]
    fn ldr_x_offset_negative_routes_to_ldur() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: -8,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldur");
        assert_eq!(op, "x0, [sp, #-8]");
    }

    #[test]
    fn ldr_w_word_width_uses_w_register_form() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X3,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 4,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Word,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "w3, [x1, #4]");
    }

    #[test]
    fn ldrb_emits_byte_load_into_w_form() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X2,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Byte,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldrb");
        assert_eq!(op, "w2, [x1]");
    }

    #[test]
    fn ldrsb_emits_sign_extending_byte_load_into_x_form() {
        let bytes = assemble_one(Instruction::Ldrs {
            rt: Register::X2,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Byte,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldrsb");
        assert_eq!(op, "x2, [x1]");
    }

    #[test]
    fn ldrsw_emits_sign_extending_word_load() {
        let bytes = assemble_one(Instruction::Ldrs {
            rt: Register::X4,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Word,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldrsw");
        assert_eq!(op, "x4, [x1, #8]");
    }

    #[test]
    fn str_x_pre_index_emits_writeback_form() {
        let bytes = assemble_one(Instruction::Str {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: -16,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "str");
        assert_eq!(op, "x0, [sp, #-0x10]!");
    }

    #[test]
    fn ldr_x_post_index_emits_post_writeback_form() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::PostIndex,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1], #8");
    }

    #[test]
    fn ldr_x_register_offset_lsl_three() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Reg {
                base: Register::X1,
                idx: Register::X2,
                shift: 3,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1, x2, lsl #3]");
    }

    #[test]
    fn ldr_x_register_offset_no_shift_omits_lsl() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Reg {
                base: Register::X1,
                idx: Register::X2,
                shift: 0,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1, x2]");
    }

    #[test]
    fn ldr_x_uxtw_extended_index() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Ext {
                base: Register::X1,
                idx: Register::X2,
                kind: ExtendKind::Uxtw,
                shift: 3,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1, w2, uxtw #3]");
    }

    #[test]
    fn ldr_x_sxtw_extended_index_no_shift() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Ext {
                base: Register::X1,
                idx: Register::X2,
                kind: ExtendKind::Sxtw,
                shift: 0,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1, w2, sxtw]");
    }

    #[test]
    fn ldr_x_sxtx_extended_index() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Ext {
                base: Register::X1,
                idx: Register::X2,
                kind: ExtendKind::Sxtx,
                shift: 3,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1, x2, sxtx #3]");
    }

    #[test]
    fn ldr_x_uxtx_extended_index_no_shift() {
        // UXTX on an X-form index is architecturally equivalent to LSL #0.
        // Capstone renders the canonical form (`[x1, x2]`) since dynasm
        // emits option=011 with shift=0.
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Ext {
                base: Register::X1,
                idx: Register::X2,
                kind: ExtendKind::Uxtx,
                shift: 0,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1, x2]");
    }

    #[test]
    fn ldr_x_uxtx_extended_index_shift_three() {
        let bytes = assemble_one(Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Ext {
                base: Register::X1,
                idx: Register::X2,
                kind: ExtendKind::Uxtx,
                shift: 3,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldr");
        assert_eq!(op, "x0, [x1, x2, lsl #3]");
    }

    #[test]
    fn ldp_x_offset_zero() {
        let bytes = assemble_one(Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
            signed: false,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldp");
        assert_eq!(op, "x0, x1, [sp]");
    }

    #[test]
    fn ldp_x_pre_index_negative_offset() {
        let bytes = assemble_one(Instruction::Ldp {
            rt1: Register::X29,
            rt2: Register::X30,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: -16,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Extended,
            signed: false,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldp");
        assert_eq!(op, "x29, x30, [sp, #-0x10]!");
    }

    #[test]
    fn stp_x_post_index_positive_offset() {
        let bytes = assemble_one(Instruction::Stp {
            rt1: Register::X29,
            rt2: Register::X30,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 16,
                mode: IndexMode::PostIndex,
            },
            width: AccessWidth::Extended,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "stp");
        assert_eq!(op, "x29, x30, [sp], #0x10");
    }

    #[test]
    fn ldpsw_word_width_signed_emits_ldpsw() {
        let bytes = assemble_one(Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::SP,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Word,
            signed: true,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldpsw");
        assert_eq!(op, "x0, x1, [sp]");
    }

    #[test]
    fn ldp_w_word_width_uses_w_form() {
        let bytes = assemble_one(Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::X2,
                offset: 8,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Word,
            signed: false,
        });
        let (m, op) = disasm_mnem_op(&bytes);
        assert_eq!(m, "ldp");
        assert_eq!(op, "w0, w1, [x2, #8]");
    }

    #[test]
    fn ldrs_extended_width_is_rejected() {
        let mut a = AArch64Assembler::new();
        let res = a.assemble_instructions(
            &[Instruction::Ldrs {
                rt: Register::X0,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 0,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Extended,
            }],
            0,
        );
        assert!(
            res.is_err(),
            "LDRSX does not exist — encoder must reject Extended-width Ldrs"
        );
    }

    #[test]
    fn ldp_byte_width_is_rejected() {
        let mut a = AArch64Assembler::new();
        let res = a.assemble_instructions(
            &[Instruction::Ldp {
                rt1: Register::X0,
                rt2: Register::X1,
                addr: AddressOperand::Imm {
                    base: Register::X2,
                    offset: 0,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Byte,
                signed: false,
            }],
            0,
        );
        assert!(res.is_err(), "LDP only supports Word/Extended widths");
    }
}
