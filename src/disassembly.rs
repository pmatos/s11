//! Disassembly listing — the pure presentation seam for `s11 disasm`.
//!
//! The `disasm` command reads an ELF, disassembles its executable sections with
//! Capstone, and prints one `0x{addr}: {bytes} {mnemonic} {operands}` line per
//! instruction. Deciding *which* sections to disassemble and *how* each line is
//! rendered are pure rules that used to live inline in the `disasm` driver
//! (`disassemble_elf_binary`) in the binary's `main.rs`, interleaved with file
//! I/O, ELF parsing, and
//! Capstone — a shallow arrangement where the only way to exercise "an
//! `SHF_EXECINSTR` section with bytes is disassembled" or "a one-byte opcode is
//! padded to the byte column" was to run the whole command and scrape stdout.
//!
//! This module lifts those rules into a pure seam: plain data in
//! ([`DisassembledInstruction`]), `String`s out, no CLI, ELF, or Capstone in the
//! interface. The driver stays a thin adapter that parses the ELF, decodes each
//! executable section into [`DisassembledInstruction`]s, and prints the lines
//! this module renders — mirroring how [`report`](crate::report) owns the
//! optimizer's result rendering. It is a *separate* module from `report` on
//! purpose: `report` renders search/optimization results (it speaks
//! `SearchStatistics`, `LlmTimings`, equivalence counterexamples); this module
//! renders a raw disassembly listing, a disjoint concern with disjoint inputs
//! and no shared logic. See the `CONTEXT.md` glossary for the domain terms.

/// One decoded instruction in a disassembly listing: the raw encoded bytes plus
/// the resolved mnemonic and operand text.
///
/// Deliberately free of Capstone types so the listing renderer is a pure,
/// fixture-free seam. The adapter resolves Capstone's optional mnemonic/operand
/// strings (to `"???"` / `""` when absent) before building this value, so the
/// renderer never has to know about Capstone's failure modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassembledInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

/// Whether a section should be disassembled by `disasm`: it must be flagged
/// executable (`SHF_EXECINSTR`) and carry at least one byte.
///
/// Takes the raw `sh_flags` and `sh_size` header fields rather than an ELF
/// section type so the rule stays a fixture-free unit — the driver reads the
/// header, this decides. An executable-but-empty section (`sh_size == 0`) has
/// nothing to decode and is skipped, matching the pre-refactor `disasm` filter.
pub fn section_is_executable(sh_flags: u64, sh_size: u64) -> bool {
    sh_flags & (elf::abi::SHF_EXECINSTR as u64) != 0 && sh_size > 0
}

/// Render a run of decoded instructions as the `disasm` command's listing: one
/// `0x{addr}: {bytes} {mnemonic} {operands}` line per instruction, in order.
///
/// The byte column is the instruction's raw bytes as lowercase hex with no
/// separators, left-justified in an 8-wide column (trailing spaces) so the
/// mnemonic column stays aligned for both AArch64 (always four bytes, exactly
/// eight hex digits) and shorter variable-length x86 opcodes.
pub fn format_disassembly(instructions: &[DisassembledInstruction]) -> Vec<String> {
    instructions
        .iter()
        .map(|instruction| {
            let hex_bytes: String = instruction
                .bytes
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect();
            format!(
                "0x{:x}: {:8} {} {}",
                instruction.address, hex_bytes, instruction.mnemonic, instruction.operands
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_single_four_byte_instruction_line() {
        let instructions = vec![DisassembledInstruction {
            address: 0x1000,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
            mnemonic: "add".to_string(),
            operands: "x0, x1, x2".to_string(),
        }];

        assert_eq!(
            format_disassembly(&instructions),
            vec!["0x1000: deadbeef add x0, x1, x2".to_string()],
        );
    }

    #[test]
    fn pads_short_byte_column_and_renders_empty_operands_and_order() {
        let instructions = vec![
            DisassembledInstruction {
                address: 0x2000,
                bytes: vec![0xcc],
                mnemonic: "int3".to_string(),
                operands: String::new(),
            },
            DisassembledInstruction {
                address: 0x2004,
                bytes: vec![0x01, 0x02, 0x03, 0x04],
                mnemonic: "mov".to_string(),
                operands: "rax, rbx".to_string(),
            },
        ];

        // A one-byte opcode pads to the 8-wide byte column (so the mnemonic stays
        // aligned) and empty operands leave a trailing space, exactly as the
        // pre-refactor `disasm` listing printed. Lines keep input order.
        assert_eq!(
            format_disassembly(&instructions),
            vec![
                "0x2000: cc       int3 ".to_string(),
                "0x2004: 01020304 mov rax, rbx".to_string(),
            ],
        );
    }

    #[test]
    fn renders_no_lines_for_an_empty_section() {
        assert_eq!(format_disassembly(&[]), Vec::<String>::new());
    }

    // SHF_EXECINSTR is 0x4; SHF_ALLOC|SHF_WRITE (a typical data section) is 0x3.
    const SHF_EXECINSTR: u64 = 0x4;
    const SHF_ALLOC_WRITE: u64 = 0x3;

    #[test]
    fn selects_executable_sections_with_bytes() {
        // A `.text`-style section: executable and non-empty.
        assert!(section_is_executable(SHF_EXECINSTR | 0x2, 128));
    }

    #[test]
    fn skips_executable_but_empty_sections() {
        // An executable section header with zero size has nothing to decode.
        assert!(!section_is_executable(SHF_EXECINSTR, 0));
    }

    #[test]
    fn skips_non_executable_sections() {
        // A writable data section is never disassembled, even when it has bytes.
        assert!(!section_is_executable(SHF_ALLOC_WRITE, 4096));
    }
}
