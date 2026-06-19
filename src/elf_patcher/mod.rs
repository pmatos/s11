use elf::{ElfBytes, endian::AnyEndian};
use std::fs;
use std::path::Path;

/// Intel SDM canonical multi-byte NOP sequences, indexed by length.
/// Index 0 is the empty slice (fallback for `len == 0`); indices 1..=9
/// are the recommended sequences from the Intel optimization reference.
const X86_NOP_TABLE: [&[u8]; 10] = [
    &[],
    &[0x90],
    &[0x66, 0x90],
    &[0x0f, 0x1f, 0x00],
    &[0x0f, 0x1f, 0x40, 0x00],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
    &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
];

/// Architecture detected from the ELF `e_machine` field. Drives
/// per-arch behaviours: instruction alignment for window validation
/// and NOP byte choice for padding.
///
/// Issue #77 stage 3 step 24: this enum will gain `RiscV32` and `RiscV64`
/// variants alongside the assembler stub from step 23.
/// `instruction_alignment` will return 4 for both; `nop_bytes` will return
/// `[0x13, 0x00, 0x00, 0x00]` (addi x0, x0, 0). `from_e_machine` extends
/// to consume `e_ident[EI_CLASS]` so the `EM_RISCV` machine number can
/// disambiguate RV32 vs RV64. Blocked on the from-scratch RISC-V
/// semantics work tracked in the same follow-up that completes step 23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedArch {
    Aarch64,
    X86_64,
    X86_32,
}

impl DetectedArch {
    /// Required byte alignment for an instruction-window start/end.
    pub fn instruction_alignment(&self) -> u64 {
        match self {
            DetectedArch::Aarch64 => 4,
            DetectedArch::X86_64 | DetectedArch::X86_32 => 1,
        }
    }

    /// Canonical NOP byte sequence to pad up to `len` remaining bytes.
    /// Callers loop until the gap is filled. For x86-64 the function
    /// returns the Intel-recommended sequence of `min(len, 9)` bytes
    /// (`len == 0` returns `&[]`). For x86-32 it always returns the
    /// single-byte `0x90` NOP — the multi-byte `0f 1f` family is
    /// Pentium Pro / P6+, and `EM_386` does not encode a CPU baseline
    /// stronger than i386, so emitting them could fault on legacy
    /// hardware. For AArch64 it returns the 4-byte NOP and asserts
    /// the caller respects 4-byte alignment.
    pub fn nop_sequence(&self, len: usize) -> &'static [u8] {
        match self {
            DetectedArch::Aarch64 => {
                assert!(
                    len.is_multiple_of(4),
                    "AArch64 nop_sequence requires len % 4 == 0, got {}",
                    len
                );
                if len == 0 {
                    &[]
                } else {
                    &[0x1f, 0x20, 0x03, 0xd5]
                }
            }
            DetectedArch::X86_64 => X86_NOP_TABLE[len.min(9)],
            DetectedArch::X86_32 => {
                if len == 0 {
                    &[]
                } else {
                    &[0x90]
                }
            }
        }
    }

    fn from_e_machine(machine: u16) -> Option<Self> {
        match machine {
            elf::abi::EM_AARCH64 => Some(DetectedArch::Aarch64),
            elf::abi::EM_X86_64 => Some(DetectedArch::X86_64),
            elf::abi::EM_386 => Some(DetectedArch::X86_32),
            _ => None,
        }
    }
}

pub struct ElfPatcher {
    file_data: Vec<u8>,
    arch: DetectedArch,
}

#[derive(Debug, Clone)]
pub struct AddressWindow {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone)]
pub struct TextSection {
    pub name: String,
    pub file_offset: u64,
    pub virtual_addr: u64,
    pub size: u64,
}

impl ElfPatcher {
    pub fn new(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let file_data = fs::read(path)?;
        let elf = ElfBytes::<AnyEndian>::minimal_parse(&file_data)?;
        let arch = DetectedArch::from_e_machine(elf.ehdr.e_machine).ok_or_else(|| {
            format!(
                "Unsupported architecture (e_machine: {})",
                elf.ehdr.e_machine
            )
        })?;
        Ok(Self { file_data, arch })
    }

    pub fn arch(&self) -> DetectedArch {
        self.arch
    }

    pub fn get_text_sections(&self) -> Result<Vec<TextSection>, Box<dyn std::error::Error>> {
        let elf = ElfBytes::<AnyEndian>::minimal_parse(&self.file_data)?;
        let section_headers = elf
            .section_headers()
            .ok_or("Failed to get section headers")?;
        let (_, string_table) = elf.section_headers_with_strtab()?;
        let string_table = string_table.ok_or("Failed to get string table")?;

        let mut text_sections = Vec::new();

        for section_header in section_headers.iter() {
            let section_name = string_table.get(section_header.sh_name as usize)?;

            // Look for executable sections
            if section_header.sh_flags & elf::abi::SHF_EXECINSTR as u64 != 0
                && section_header.sh_size > 0
            {
                text_sections.push(TextSection {
                    name: section_name.to_string(),
                    file_offset: section_header.sh_offset,
                    virtual_addr: section_header.sh_addr,
                    size: section_header.sh_size,
                });
            }
        }

        Ok(text_sections)
    }

    pub fn validate_address_window(&self, window: &AddressWindow) -> Result<TextSection, String> {
        let text_sections = self
            .get_text_sections()
            .map_err(|e| format!("Failed to get text sections: {}", e))?;

        // Find which section contains this address window
        for section in text_sections {
            let section_start = section.virtual_addr;
            let section_end = section.virtual_addr + section.size;

            if window.start >= section_start && window.end <= section_end {
                if window.start >= window.end {
                    return Err("Start address must be less than end address".to_string());
                }

                let align = self.arch.instruction_alignment();
                if align > 1
                    && (!window.start.is_multiple_of(align) || !window.end.is_multiple_of(align))
                {
                    return Err(format!(
                        "Addresses must be {}-byte aligned for {:?} instructions",
                        align, self.arch
                    ));
                }

                return Ok(section);
            }
        }

        Err(format!(
            "Address window 0x{:x}-0x{:x} is not within any executable section",
            window.start, window.end
        ))
    }

    pub fn get_instructions_in_window(
        &self,
        window: &AddressWindow,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let section = self
            .validate_address_window(window)
            .map_err(|e| format!("Invalid address window: {}", e))?;

        let offset_in_section = window.start - section.virtual_addr;
        let length = window.end - window.start;

        let file_start = section.file_offset + offset_in_section;
        let file_end = file_start + length;

        if file_end > self.file_data.len() as u64 {
            return Err("Address window extends beyond file".into());
        }

        Ok(self.file_data[file_start as usize..file_end as usize].to_vec())
    }

    pub fn create_patched_copy(
        &self,
        output_path: &Path,
        window: &AddressWindow,
        new_code: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let section = self
            .validate_address_window(window)
            .map_err(|e| format!("Invalid address window: {}", e))?;

        let window_size = (window.end - window.start) as usize;

        if new_code.len() > window_size {
            return Err(format!(
                "New code ({} bytes) is larger than window size ({} bytes)",
                new_code.len(),
                window_size
            )
            .into());
        }

        // Create a copy of the original file data
        let mut patched_data = self.file_data.clone();

        // Calculate file offset for the patch
        let offset_in_section = window.start - section.virtual_addr;
        let file_offset = (section.file_offset + offset_in_section) as usize;

        // Apply the patch
        let patch_end = file_offset + new_code.len();
        patched_data[file_offset..patch_end].copy_from_slice(new_code);

        // If new code is smaller than window, pad with arch-appropriate NOPs.
        if new_code.len() < window_size {
            let mut cursor = patch_end;
            let gap_end = file_offset + window_size;
            while cursor < gap_end {
                let nop = self.arch.nop_sequence(gap_end - cursor);
                debug_assert!(
                    !nop.is_empty(),
                    "nop_sequence returned empty slice with {} bytes remaining",
                    gap_end - cursor
                );
                patched_data[cursor..cursor + nop.len()].copy_from_slice(nop);
                cursor += nop.len();
            }
        }

        // Write the patched file
        fs::write(output_path, patched_data)?;

        Ok(())
    }
}

pub fn parse_hex_address(addr_str: &str) -> Result<u64, String> {
    let addr_str = if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
        &addr_str[2..]
    } else {
        addr_str
    };

    u64::from_str_radix(addr_str, 16).map_err(|_| format!("Invalid hex address: {}", addr_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detected_arch_alignment() {
        assert_eq!(DetectedArch::Aarch64.instruction_alignment(), 4);
        assert_eq!(DetectedArch::X86_64.instruction_alignment(), 1);
        assert_eq!(DetectedArch::X86_32.instruction_alignment(), 1);
    }

    #[test]
    fn x86_nop_sequence_canonical_five_byte() {
        assert_eq!(
            DetectedArch::X86_64.nop_sequence(5),
            &[0x0f, 0x1f, 0x44, 0x00, 0x00][..]
        );
    }

    #[test]
    fn x86_64_nop_sequence_canonical_lengths_one_through_nine() {
        let canonical: [&[u8]; 10] = [
            &[],
            &[0x90],
            &[0x66, 0x90],
            &[0x0f, 0x1f, 0x00],
            &[0x0f, 0x1f, 0x40, 0x00],
            &[0x0f, 0x1f, 0x44, 0x00, 0x00],
            &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
            &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
            &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];
        for (len, expected) in canonical.iter().enumerate() {
            assert_eq!(
                DetectedArch::X86_64.nop_sequence(len),
                *expected,
                "X86_64 nop_sequence({}) mismatch",
                len
            );
        }
    }

    #[test]
    fn x86_32_nop_sequence_uses_single_byte_only_for_pre_p6_safety() {
        let empty: &[u8] = &[];
        let one: &[u8] = &[0x90];
        assert_eq!(DetectedArch::X86_32.nop_sequence(0), empty);
        for len in [1usize, 2, 3, 5, 9, 17, 100] {
            assert_eq!(
                DetectedArch::X86_32.nop_sequence(len),
                one,
                "X86_32 nop_sequence({}) must stay at single-byte 0x90 (pre-P6 safety)",
                len
            );
        }
    }

    #[test]
    #[should_panic(expected = "len % 4 == 0")]
    fn aarch64_nop_sequence_panics_on_misaligned_len() {
        let _ = DetectedArch::Aarch64.nop_sequence(3);
    }

    #[test]
    fn aarch64_nop_sequence_returns_four_byte_nop_or_empty() {
        let nop: &[u8] = &[0x1f, 0x20, 0x03, 0xd5];
        let empty: &[u8] = &[];
        assert_eq!(DetectedArch::Aarch64.nop_sequence(0), empty);
        for len in [4usize, 8, 12, 16, 64] {
            assert_eq!(
                DetectedArch::Aarch64.nop_sequence(len),
                nop,
                "Aarch64 nop_sequence({}) should be the 4-byte NOP",
                len
            );
        }
    }

    #[test]
    fn x86_64_nop_sequence_clamps_lengths_above_nine() {
        let nine: &[u8] = &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
        for len in [10usize, 17, 100, 1024] {
            assert_eq!(
                DetectedArch::X86_64.nop_sequence(len),
                nine,
                "X86_64 nop_sequence({}) should clamp to 9-byte canonical",
                len
            );
        }
    }

    #[test]
    fn detected_arch_from_e_machine() {
        assert_eq!(
            DetectedArch::from_e_machine(elf::abi::EM_AARCH64),
            Some(DetectedArch::Aarch64)
        );
        assert_eq!(
            DetectedArch::from_e_machine(elf::abi::EM_X86_64),
            Some(DetectedArch::X86_64)
        );
        assert_eq!(
            DetectedArch::from_e_machine(elf::abi::EM_386),
            Some(DetectedArch::X86_32)
        );
        assert_eq!(DetectedArch::from_e_machine(0xffff), None);
    }

    #[test]
    fn test_parse_hex_address() {
        assert_eq!(parse_hex_address("0x1000").unwrap(), 0x1000);
        assert_eq!(parse_hex_address("0X1000").unwrap(), 0x1000);
        assert_eq!(parse_hex_address("1000").unwrap(), 0x1000);
        assert_eq!(parse_hex_address("abcd").unwrap(), 0xabcd);

        assert!(parse_hex_address("xyz").is_err());
        assert!(parse_hex_address("0xghi").is_err());
    }

    #[test]
    fn test_address_window_validation() {
        let window = AddressWindow {
            start: 0x1000,
            end: 0x1004,
        };
        assert!(window.start < window.end);

        let invalid_window = AddressWindow {
            start: 0x1004,
            end: 0x1000,
        };
        assert!(invalid_window.start >= invalid_window.end);
    }

    /// Hand-rolled minimal ELF64 used only by integration tests in this
    /// module. Layout: header, .text data, .shstrtab data, then a section
    /// header table with NULL / .text / .shstrtab. Only the fields
    /// `ElfPatcher` actually reads are populated.
    fn build_minimal_elf64(text_bytes: &[u8], text_vaddr: u64, machine: u16) -> Vec<u8> {
        let elf_header_size = 64usize;
        let shentsize = 64usize;
        let shnum = 3usize;
        let shstrtab: &[u8] = b"\0.text\0.shstrtab\0";
        let text_offset = elf_header_size;
        let shstrtab_offset = text_offset + text_bytes.len();
        let shoff = shstrtab_offset + shstrtab.len();
        let total_size = shoff + shentsize * shnum;

        let mut buf = vec![0u8; total_size];

        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = elf::abi::ELFCLASS64;
        buf[5] = elf::abi::ELFDATA2LSB;
        buf[6] = elf::abi::EV_CURRENT;
        buf[16..18].copy_from_slice(&elf::abi::ET_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&machine.to_le_bytes());
        buf[20..24].copy_from_slice(&(elf::abi::EV_CURRENT as u32).to_le_bytes());
        buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        buf[52..54].copy_from_slice(&(elf_header_size as u16).to_le_bytes());
        buf[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
        buf[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
        buf[62..64].copy_from_slice(&2u16.to_le_bytes());

        buf[text_offset..text_offset + text_bytes.len()].copy_from_slice(text_bytes);
        buf[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(shstrtab);

        let mut write_shdr = |index: usize, fields: [u64; 10]| {
            let base = shoff + index * shentsize;
            buf[base..base + 4].copy_from_slice(&(fields[0] as u32).to_le_bytes());
            buf[base + 4..base + 8].copy_from_slice(&(fields[1] as u32).to_le_bytes());
            buf[base + 8..base + 16].copy_from_slice(&fields[2].to_le_bytes());
            buf[base + 16..base + 24].copy_from_slice(&fields[3].to_le_bytes());
            buf[base + 24..base + 32].copy_from_slice(&fields[4].to_le_bytes());
            buf[base + 32..base + 40].copy_from_slice(&fields[5].to_le_bytes());
            buf[base + 40..base + 44].copy_from_slice(&(fields[6] as u32).to_le_bytes());
            buf[base + 44..base + 48].copy_from_slice(&(fields[7] as u32).to_le_bytes());
            buf[base + 48..base + 56].copy_from_slice(&fields[8].to_le_bytes());
            buf[base + 56..base + 64].copy_from_slice(&fields[9].to_le_bytes());
        };
        write_shdr(0, [0; 10]);
        write_shdr(
            1,
            [
                1,
                elf::abi::SHT_PROGBITS as u64,
                (elf::abi::SHF_ALLOC | elf::abi::SHF_EXECINSTR) as u64,
                text_vaddr,
                text_offset as u64,
                text_bytes.len() as u64,
                0,
                0,
                1,
                0,
            ],
        );
        write_shdr(
            2,
            [
                7,
                elf::abi::SHT_STRTAB as u64,
                0,
                0,
                shstrtab_offset as u64,
                shstrtab.len() as u64,
                0,
                0,
                1,
                0,
            ],
        );

        buf
    }

    fn build_minimal_x86_64_elf(text_bytes: &[u8], text_vaddr: u64) -> Vec<u8> {
        build_minimal_elf64(text_bytes, text_vaddr, elf::abi::EM_X86_64)
    }

    fn build_minimal_aarch64_elf(text_bytes: &[u8], text_vaddr: u64) -> Vec<u8> {
        build_minimal_elf64(text_bytes, text_vaddr, elf::abi::EM_AARCH64)
    }

    #[test]
    fn create_patched_copy_emits_canonical_x86_nop_padding() {
        use crate::test_utils::TempFile;

        let text_vaddr: u64 = 0x100000;
        let text_bytes = [0xc3u8; 8];
        let elf_bytes = build_minimal_x86_64_elf(&text_bytes, text_vaddr);

        let input = TempFile::new_bytes("s11-elf-padding-in", "elf", &elf_bytes);
        let output = TempFile::new_bytes("s11-elf-padding-out", "elf", &[]);

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");
        assert_eq!(patcher.arch(), DetectedArch::X86_64);

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 8,
        };
        let payload = [0x90u8, 0x90, 0x90];
        patcher
            .create_patched_copy(output.path(), &window, &payload)
            .expect("patch should succeed");

        let patched = std::fs::read(output.path()).expect("output should be readable");
        let text_file_offset = 64usize;
        let patched_window = &patched[text_file_offset..text_file_offset + 8];
        assert_eq!(&patched_window[..3], &payload[..], "payload bytes mismatch");
        assert_eq!(
            &patched_window[3..],
            &[0x0f, 0x1f, 0x44, 0x00, 0x00][..],
            "padding should be the canonical 5-byte Intel NOP",
        );
    }

    #[test]
    fn create_patched_copy_emits_canonical_aarch64_nop_padding() {
        use crate::test_utils::TempFile;

        let text_vaddr: u64 = 0x100000;
        let text_bytes = [0xdeu8; 16];
        let elf_bytes = build_minimal_aarch64_elf(&text_bytes, text_vaddr);

        let input = TempFile::new_bytes("s11-elf-aarch64-padding-in", "elf", &elf_bytes);
        let output = TempFile::new_bytes("s11-elf-aarch64-padding-out", "elf", &[]);

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");
        assert_eq!(patcher.arch(), DetectedArch::Aarch64);

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 16,
        };
        let payload = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];
        patcher
            .create_patched_copy(output.path(), &window, &payload)
            .expect("patch should succeed");

        let patched = std::fs::read(output.path()).expect("output should be readable");
        let text_file_offset = 64usize;
        let patched_window = &patched[text_file_offset..text_file_offset + 16];
        assert_eq!(&patched_window[..8], &payload[..], "payload bytes mismatch");
        assert_eq!(
            &patched_window[8..],
            &[0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5][..],
            "padding should be repeated canonical AArch64 NOPs",
        );
    }

    #[test]
    fn create_patched_copy_emits_no_aarch64_padding_when_payload_fills_window() {
        use crate::test_utils::TempFile;

        let text_vaddr: u64 = 0x100000;
        let text_bytes = [0xdeu8; 16];
        let elf_bytes = build_minimal_aarch64_elf(&text_bytes, text_vaddr);

        let input = TempFile::new_bytes("s11-elf-aarch64-no-padding-in", "elf", &elf_bytes);
        let output = TempFile::new_bytes("s11-elf-aarch64-no-padding-out", "elf", &[]);

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 16,
        };
        let payload = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xab, 0xcd,
        ];
        patcher
            .create_patched_copy(output.path(), &window, &payload)
            .expect("patch should succeed");

        let patched = std::fs::read(output.path()).expect("output should be readable");
        let text_file_offset = 64usize;
        let patched_window = &patched[text_file_offset..text_file_offset + 16];
        assert_eq!(
            patched_window,
            &payload[..],
            "payload that fills the window should not receive AArch64 padding",
        );
    }

    #[test]
    fn create_patched_copy_emits_no_x86_padding_when_payload_fills_window() {
        use crate::test_utils::TempFile;

        let text_vaddr: u64 = 0x100000;
        let text_bytes = [0xc3u8; 8];
        let elf_bytes = build_minimal_x86_64_elf(&text_bytes, text_vaddr);

        let input = TempFile::new_bytes("s11-elf-x86-no-padding-in", "elf", &elf_bytes);
        let output = TempFile::new_bytes("s11-elf-x86-no-padding-out", "elf", &[]);

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 8,
        };
        let payload = [0xcc, 0x31, 0xc0, 0x48, 0x83, 0xc0, 0x01, 0xc3];
        patcher
            .create_patched_copy(output.path(), &window, &payload)
            .expect("patch should succeed");

        let patched = std::fs::read(output.path()).expect("output should be readable");
        let text_file_offset = 64usize;
        let patched_window = &patched[text_file_offset..text_file_offset + 8];
        assert_eq!(
            patched_window,
            &payload[..],
            "payload that fills the window should not receive x86 padding",
        );
    }

    #[test]
    fn create_patched_copy_pads_gap_larger_than_nine_bytes_with_two_nops() {
        use crate::test_utils::TempFile;

        let text_vaddr: u64 = 0x100000;
        let text_bytes = [0xc3u8; 20];
        let elf_bytes = build_minimal_x86_64_elf(&text_bytes, text_vaddr);

        let input = TempFile::new_bytes("s11-elf-padding-big-in", "elf", &elf_bytes);
        let output = TempFile::new_bytes("s11-elf-padding-big-out", "elf", &[]);

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 20,
        };
        let payload = [0x90u8, 0x90, 0x90];
        patcher
            .create_patched_copy(output.path(), &window, &payload)
            .expect("patch should succeed");

        let patched = std::fs::read(output.path()).expect("output should be readable");
        let text_file_offset = 64usize;
        let patched_window = &patched[text_file_offset..text_file_offset + 20];
        assert_eq!(&patched_window[..3], &payload[..], "payload bytes mismatch");
        // 17-byte gap should pack as the canonical 9-byte NOP followed by the
        // canonical 8-byte NOP — proves the cursor loop iterates correctly.
        assert_eq!(
            &patched_window[3..12],
            &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00][..],
            "first pad should be the canonical 9-byte Intel NOP",
        );
        assert_eq!(
            &patched_window[12..20],
            &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00][..],
            "second pad should be the canonical 8-byte Intel NOP",
        );
    }

    #[test]
    fn create_patched_copy_pads_large_aarch64_gap_with_repeated_nops() {
        use crate::test_utils::TempFile;

        let text_vaddr: u64 = 0x100000;
        let text_bytes = [0xdeu8; 20];
        let elf_bytes = build_minimal_aarch64_elf(&text_bytes, text_vaddr);

        let input = TempFile::new_bytes("s11-elf-aarch64-padding-big-in", "elf", &elf_bytes);
        let output = TempFile::new_bytes("s11-elf-aarch64-padding-big-out", "elf", &[]);

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 20,
        };
        let payload = [0xaa, 0xbb, 0xcc, 0xdd];
        patcher
            .create_patched_copy(output.path(), &window, &payload)
            .expect("patch should succeed");

        let patched = std::fs::read(output.path()).expect("output should be readable");
        let text_file_offset = 64usize;
        let patched_window = &patched[text_file_offset..text_file_offset + 20];
        assert_eq!(&patched_window[..4], &payload[..], "payload bytes mismatch");
        assert_eq!(
            &patched_window[4..],
            &[
                0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20,
                0x03, 0xd5,
            ][..],
            "padding should be four repeated canonical AArch64 NOPs",
        );
    }

    #[test]
    fn elf_patcher_does_not_reread_file_after_construction() {
        // Pins the invariant the issue-88 dispatch refactor relies on:
        // once an ElfPatcher is constructed, every accessor it exposes serves
        // data from the in-memory buffer rather than reopening the file.
        // Callers (the `s11 opt` dispatch) can therefore construct the patcher
        // once and thread it into the per-arch helpers without paying for a
        // second `fs::read` + `ElfBytes::minimal_parse`.
        use crate::test_utils::TempFile;

        let text_vaddr: u64 = 0x100000;
        let text_bytes = [0xc3u8; 8];
        let elf_bytes = build_minimal_x86_64_elf(&text_bytes, text_vaddr);

        let input = TempFile::new_bytes("s11-elf-no-reread", "elf", &elf_bytes);
        let saved_path = input.path().to_path_buf();
        let patcher = ElfPatcher::new(&saved_path).expect("patcher should accept minimal ELF");

        std::fs::remove_file(&saved_path).expect("remove input before exercising patcher");
        assert!(
            !saved_path.exists(),
            "precondition: input file removed so any disk read would fail",
        );

        assert_eq!(patcher.arch(), DetectedArch::X86_64);

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 8,
        };
        let section = patcher
            .validate_address_window(&window)
            .expect("validate should not reopen the file");
        assert_eq!(section.virtual_addr, text_vaddr);

        let bytes = patcher
            .get_instructions_in_window(&window)
            .expect("get_instructions should not reopen the file");
        assert_eq!(bytes, text_bytes.to_vec());

        // TempFile::drop tolerates a missing file (test_utils.rs:33-37).
    }
}
