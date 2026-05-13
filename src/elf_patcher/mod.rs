use elf::{ElfBytes, endian::AnyEndian};
use std::fs;
use std::path::Path;

/// Architecture detected from the ELF `e_machine` field. Drives
/// per-arch behaviours: instruction alignment for window validation
/// and NOP byte choice for padding.
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

    /// Per-instruction NOP bytes used to pad a shorter patch back up to
    /// the original window size. AArch64 NOP is 0xd5_03_20_1f (LE); x86
    /// NOP is the single-byte 0x90.
    pub fn nop_bytes(&self) -> &'static [u8] {
        match self {
            DetectedArch::Aarch64 => &[0x1f, 0x20, 0x03, 0xd5],
            DetectedArch::X86_64 | DetectedArch::X86_32 => &[0x90],
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
            let remaining = window_size - new_code.len();
            let nop = self.arch.nop_bytes();
            let n = nop.len();
            for i in 0..remaining / n {
                let nop_start = patch_end + i * n;
                if nop_start + n <= file_offset + window_size {
                    patched_data[nop_start..nop_start + n].copy_from_slice(nop);
                }
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
    fn detected_arch_nop_bytes() {
        assert_eq!(
            DetectedArch::Aarch64.nop_bytes(),
            &[0x1f, 0x20, 0x03, 0xd5][..]
        );
        assert_eq!(DetectedArch::X86_64.nop_bytes(), &[0x90][..]);
        assert_eq!(DetectedArch::X86_32.nop_bytes(), &[0x90][..]);
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
}
