//! AArch64 encoding predicates shared by IR validation and assembly lowering.

/// True iff `imm` (reinterpreted as `u64`) is representable as an AArch64
/// 64-bit logical bitmask immediate (the `N:immr:imms` encoding used by
/// AND/ORR/EOR/TST/ANDS immediate forms).
pub(crate) fn logical_imm64_encodable(imm: i64) -> bool {
    dynasmrt::aarch64::encode_logical_immediate_64bit(imm as u64).is_some()
}

#[cfg(test)]
mod tests {
    use super::logical_imm64_encodable;

    #[test]
    fn logical_imm64_encodable_accepts_valid_bitmasks() {
        for imm in [
            0xff,
            0xffff,
            0xf0f0_f0f0_f0f0_f0f0_u64 as i64,
            0x5555_5555_5555_5555,
            i64::MIN,
        ] {
            assert!(
                logical_imm64_encodable(imm),
                "expected 0x{:x} to be encodable",
                imm as u64
            );
        }
    }

    #[test]
    fn logical_imm64_encodable_rejects_invalid_bitmasks() {
        for imm in [0_i64, -1, 5] {
            assert!(
                !logical_imm64_encodable(imm),
                "expected 0x{:x} to be rejected",
                imm as u64
            );
        }
    }
}
