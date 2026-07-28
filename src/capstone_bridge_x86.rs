//! x86 Capstone → IR bridge.
//!
//! Capstone renders x86-64/x86-32 instructions in Intel syntax; this module
//! turns each `(mnemonic, op_str)` pair into an [`crate::isa::x86::X86Instruction`]
//! by delegating to [`crate::parser::x86::x86_ir_from_mnemonic_for_mode`], which
//! is the single source of truth for the supported x86 mnemonic set. Keeping the
//! delegation here is what guarantees the asm-text path and the ELF/Capstone path
//! support exactly the same mnemonics — the x86 analogue of the AArch64
//! [`crate::capstone_bridge`] guarantee (see CLAUDE.md "Adding a new AArch64
//! instruction" for the two-entry-point drift hazard this closes for x86).

use crate::isa::x86::X86Instruction;
use crate::parser::x86::{X86ParseMode, x86_ir_from_mnemonic_for_mode};

/// Convert every instruction in a Capstone x86 disassembly into IR, refusing the
/// whole window on the first unsupported or unparseable instruction.
pub fn convert_to_x86_ir(
    instructions: &capstone::Instructions,
    mode: X86ParseMode,
) -> Result<Vec<X86Instruction>, String> {
    let mut out = Vec::new();
    for instruction in instructions.iter() {
        let mn = instruction.mnemonic().unwrap_or("");
        let ops = instruction.op_str().unwrap_or("");
        out.push(convert_x86_capstone_op_for_optimization(
            mn,
            ops,
            instruction.address(),
            mode,
        )?);
    }
    Ok(out)
}

/// Convert one Capstone `(mnemonic, op_str)` pair into x86 IR by delegating to
/// `parser::x86::x86_ir_from_mnemonic_for_mode`. Keeping a single shared parser
/// is what guarantees the asm-text path and the ELF/Capstone path support
/// exactly the same mnemonic set.
pub fn convert_x86_capstone_op_for_optimization(
    mnemonic: &str,
    op_str: &str,
    address: u64,
    mode: X86ParseMode,
) -> Result<X86Instruction, String> {
    match x86_ir_from_mnemonic_for_mode(mnemonic, op_str, mode) {
        Ok(Some(ir)) => Ok(ir),
        Ok(None) => {
            // Refusing the window is safer than silently dropping the
            // unsupported instruction: the patcher overwrites the entire
            // byte window with the reassembled IR, so a dropped `lea`,
            // `call`, etc. would lose its side effect from the binary.
            Err(format!(
                "x86 window contains unsupported mnemonic '{} {}' at 0x{:x}; \
                 narrow the --start-addr/--end-addr range \
                 to exclude it, or add the mnemonic to the supported set.",
                mnemonic, op_str, address
            ))
        }
        Err(error) => Err(format!(
            "failed to parse x86 instruction '{} {}' at 0x{:x}: {}",
            mnemonic, op_str, address, error
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::convert_x86_capstone_op_for_optimization;
    use crate::parser::x86::X86ParseMode;

    /// Locks in that the x86 Capstone→IR bridge covers every mnemonic the docs
    /// capability matrix lists as rewritable-from-binary or a fixed terminator,
    /// in BOTH decode modes. Mirrors the AArch64
    /// `convert_capstone_op_handles_all_supported_aarch64_mnemonics` tripwire:
    /// the x86 side had the identical two-entry-point drift hazard (this Capstone
    /// bridge vs. `parser::x86`) with no pinned guard. `set<cond>` is deliberately
    /// excluded — it is synthesizable-only (architectural byte SETcc is rejected
    /// from binary until issue #75), so it never survives the bridge.
    #[test]
    fn convert_x86_capstone_op_handles_all_supported_x86_mnemonics() {
        // (mnemonic, Mode64 operands, Mode32 operands). MOVSX/MOVZX require a
        // mode-width destination (RAX in 64-bit, EAX in 32-bit); the remaining
        // families share operands across modes. Shifts/rotates pin the
        // immediate-count form (the CL register-count form is deferred) and
        // `lea` pins the register-base + displacement form.
        let cases: &[(&str, &str, &str)] = &[
            ("mov", "eax, ebx", "eax, ebx"),
            ("movzx", "rax, bl", "eax, bl"),
            ("movsx", "rax, bl", "eax, bl"),
            ("add", "eax, ebx", "eax, ebx"),
            ("sub", "eax, ebx", "eax, ebx"),
            ("and", "eax, ebx", "eax, ebx"),
            ("or", "eax, ebx", "eax, ebx"),
            ("xor", "eax, ebx", "eax, ebx"),
            ("cmp", "eax, ebx", "eax, ebx"),
            ("test", "eax, ebx", "eax, ebx"),
            ("neg", "eax", "eax"),
            ("not", "eax", "eax"),
            ("inc", "eax", "eax"),
            ("dec", "eax", "eax"),
            ("shl", "eax, 3", "eax, 3"),
            ("sal", "eax, 3", "eax, 3"),
            ("shr", "eax, 3", "eax, 3"),
            ("sar", "eax, 3", "eax, 3"),
            ("rol", "eax, 3", "eax, 3"),
            ("ror", "eax, 3", "eax, 3"),
            ("imul", "eax, ebx", "eax, ebx"),
            ("lea", "eax, [ebx + 8]", "eax, [ebx + 8]"),
            ("cmovne", "eax, ebx", "eax, ebx"),
            ("jne", "0x1000", "0x1000"),
        ];

        fn docs_mnemonic(mnemonic: &'static str) -> &'static str {
            if mnemonic.starts_with("cmov") {
                "cmov<cond>"
            } else if mnemonic.starts_with('j') {
                "j<cond>"
            } else {
                mnemonic
            }
        }

        let case_mnemonics: std::collections::BTreeSet<&'static str> = cases
            .iter()
            .map(|(mnemonic, _, _)| docs_mnemonic(mnemonic))
            .collect();
        let documented_mnemonics: std::collections::BTreeSet<&'static str> =
            crate::docs_support::X86_REWRITABLE_MNEMONICS
                .iter()
                .chain(crate::docs_support::X86_FIXED_TERMINATORS.iter())
                .copied()
                .collect();
        assert_eq!(case_mnemonics, documented_mnemonics);

        for (mnem, ops64, ops32) in cases {
            for (ops, mode) in [
                (*ops64, X86ParseMode::Mode64),
                (*ops32, X86ParseMode::Mode32),
            ] {
                match convert_x86_capstone_op_for_optimization(mnem, ops, 0x1000, mode) {
                    Ok(_) => {}
                    Err(err) => {
                        panic!("expected Ok for `{mnem} {ops}` in {mode:?}, got Err: {err}")
                    }
                }
            }
        }

        // Capstone renders the x86-64 full-width immediate-move encoding as
        // `movabs`, which the parser accepts at the shared `"mov" | "movabs"`
        // dispatch arm. The spelling never appears in 32-bit disassembly, so
        // it is pinned Mode64-only here — outside the both-modes table and its
        // set accounting, since `movabs` is a disassembler spelling of the
        // documented `mov` family rather than a family of its own.
        if let Err(err) = convert_x86_capstone_op_for_optimization(
            "movabs",
            "rax, 0x1122334455667788",
            0x1000,
            X86ParseMode::Mode64,
        ) {
            panic!("expected Ok for `movabs rax, 0x1122334455667788` in Mode64, got Err: {err}");
        }
    }

    #[test]
    fn convert_x86_capstone_op_rejects_unsupported_mnemonic() {
        // A mnemonic outside the supported core set surfaces as a window-rejection
        // error naming the raw spelling, so the optimizer refuses the window
        // rather than silently dropping a side-effecting instruction.
        let err =
            convert_x86_capstone_op_for_optimization("cpuid", "", 0x2000, X86ParseMode::Mode64)
                .expect_err("cpuid is not a supported x86 mnemonic");
        assert!(
            err.contains("unsupported mnemonic"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("cpuid"),
            "diagnostic should name the mnemonic: {err}"
        );
    }

    #[test]
    fn convert_x86_capstone_op_rejects_architectural_setcc_byte_destination() {
        // SETcc is synthesizable-only: an architectural byte SETcc from binary is
        // rejected at the string seam with the parser's #75 diagnostic surfaced.
        let err =
            convert_x86_capstone_op_for_optimization("setne", "al", 0x3000, X86ParseMode::Mode64)
                .expect_err("architectural byte SETcc must not enter the full-width pseudo-IR");
        assert!(err.contains("failed to parse"), "unexpected error: {err}");
        assert!(
            err.contains("cannot be represented until #75"),
            "unexpected error: {err}"
        );
    }
}
