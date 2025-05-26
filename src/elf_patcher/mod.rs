use elf::{ElfBytes, endian::AnyEndian};
use std::fs;
use std::path::Path;

pub struct ElfPatcher {
    file_data: Vec<u8>,
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

        // Verify it's AArch64
        if elf.ehdr.e_machine != elf::abi::EM_AARCH64 {
            return Err(format!(
                "Not an AArch64 binary (machine type: {})",
                elf.ehdr.e_machine
            )
            .into());
        }

        Ok(Self { file_data })
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

                // Ensure addresses are 4-byte aligned (AArch64 instruction alignment)
                if window.start % 4 != 0 || window.end % 4 != 0 {
                    return Err(
                        "Addresses must be 4-byte aligned for AArch64 instructions".to_string()
                    );
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

        // If new code is smaller than window, pad with NOPs
        if new_code.len() < window_size {
            let remaining = window_size - new_code.len();
            let nop_bytes = vec![0x1f, 0x20, 0x03, 0xd5]; // AArch64 NOP instruction

            for i in 0..remaining / 4 {
                let nop_start = patch_end + i * 4;
                if nop_start + 4 <= file_offset + window_size {
                    patched_data[nop_start..nop_start + 4].copy_from_slice(&nop_bytes);
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
