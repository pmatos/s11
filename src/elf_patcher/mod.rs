use elf::ElfBytes;
use elf::endian::{AnyEndian, EndianParse};
use elf::file::Class;
use elf::parse::ParseAt;
use elf::relocation::{Rel, Rela};
use elf::section::{SectionHeader, SectionHeaderTable};
use elf::symbol::{Symbol, SymbolTable};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::output_path::ResolvedOutput;

/// Intel SDM canonical multi-byte NOP sequences, indexed by length.
/// Index 0 is the empty slice; indices 1..=9
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

/// Standard compact relative-relocation section type. `elf` 0.8 predates the
/// public `SHT_RELR` constant even though contemporary toolchains emit it.
const SHT_RELR: u32 = 19;

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
            DetectedArch::X86_64 => {
                if len == 0 {
                    &[]
                } else {
                    X86_NOP_TABLE[len.min(9)]
                }
            }
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

    /// Collect executable addresses conservatively named by ELF metadata that
    /// can describe indirect control-flow entry points (ADR-0009 Decision 5).
    ///
    /// Relocations can name code through several fields depending on ELF type
    /// and relocation kind, so this deliberately considers the application
    /// site, linked symbol, explicit addend, and symbol-plus-addend. Only values
    /// inside an executable section survive. Malformed metadata is an error: a
    /// partial exclusion set would make whole-binary candidate discovery
    /// unsound.
    pub fn indirect_control_flow_targets(
        &self,
    ) -> Result<HashSet<u64>, Box<dyn std::error::Error>> {
        let elf = ElfBytes::<AnyEndian>::minimal_parse(&self.file_data)?;
        let section_headers = elf
            .section_headers()
            .ok_or("indirect-target analysis requires ELF section headers")?;
        let executable_ranges = executable_section_ranges(&section_headers)?;
        let mut targets = HashSet::new();

        for (section_index, relocation_section) in section_headers.iter().enumerate() {
            match relocation_section.sh_type {
                elf::abi::SHT_REL => {
                    validate_table_layout::<Rel>(&elf, &relocation_section, section_index)?;
                    let (data, compression) = elf.section_data(&relocation_section)?;
                    if compression.is_some() {
                        return Err(format!(
                            "compressed relocation section {section_index} cannot be analyzed"
                        )
                        .into());
                    }
                    let mut offset = 0usize;
                    while offset < data.len() {
                        let relocation =
                            Rel::parse_at(elf.ehdr.endianness, elf.ehdr.class, &mut offset, data)?;
                        collect_relocation_targets(
                            &elf,
                            &section_headers,
                            &relocation_section,
                            relocation.r_offset,
                            relocation.r_sym,
                            None,
                            &executable_ranges,
                            &mut targets,
                        )?;
                    }
                }
                elf::abi::SHT_RELA => {
                    validate_table_layout::<Rela>(&elf, &relocation_section, section_index)?;
                    let (data, compression) = elf.section_data(&relocation_section)?;
                    if compression.is_some() {
                        return Err(format!(
                            "compressed relocation section {section_index} cannot be analyzed"
                        )
                        .into());
                    }
                    let mut offset = 0usize;
                    while offset < data.len() {
                        let relocation =
                            Rela::parse_at(elf.ehdr.endianness, elf.ehdr.class, &mut offset, data)?;
                        collect_relocation_targets(
                            &elf,
                            &section_headers,
                            &relocation_section,
                            relocation.r_offset,
                            relocation.r_sym,
                            Some(relocation.r_addend),
                            &executable_ranges,
                            &mut targets,
                        )?;
                    }
                }
                SHT_RELR => {
                    let (data, compression) = elf.section_data(&relocation_section)?;
                    if compression.is_some() {
                        return Err(format!(
                            "compressed RELR section {section_index} cannot be analyzed"
                        )
                        .into());
                    }
                    collect_relr_targets(
                        &elf,
                        &section_headers,
                        &relocation_section,
                        section_index,
                        data,
                        &executable_ranges,
                        &mut targets,
                    )?;
                }
                _ => {}
            }
        }

        let (_, section_names) = elf.section_headers_with_strtab()?;
        let section_names = section_names
            .ok_or("indirect-target analysis requires an ELF section-name string table")?;
        for (section_index, section) in section_headers.iter().enumerate() {
            let section_name = section_names
                .get(section.sh_name as usize)
                .map_err(|error| format!("section {section_index} has an invalid name: {error}"))?;
            if !matches!(section_name, ".rodata" | ".data.rel.ro") {
                continue;
            }

            let (data, compression) = elf.section_data(&section)?;
            if compression.is_some() {
                return Err(format!(
                    "compressed pointer section '{section_name}' cannot be analyzed"
                )
                .into());
            }
            collect_pointer_values(
                data,
                elf.ehdr.class,
                elf.ehdr.endianness,
                &executable_ranges,
                &mut targets,
            )?;
        }

        Ok(targets)
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
        output: &ResolvedOutput,
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
        output.write(&patched_data)?;

        Ok(())
    }

    pub fn create_unmodified_copy(
        &self,
        output: &ResolvedOutput,
    ) -> Result<(), Box<dyn std::error::Error>> {
        output.write(&self.file_data)?;

        Ok(())
    }
}

fn executable_section_ranges(
    section_headers: &SectionHeaderTable<'_, AnyEndian>,
) -> Result<Vec<std::ops::Range<u64>>, Box<dyn std::error::Error>> {
    section_headers
        .iter()
        .filter(|section| {
            section.sh_flags & elf::abi::SHF_EXECINSTR as u64 != 0 && section.sh_size > 0
        })
        .map(|section| {
            let end = section
                .sh_addr
                .checked_add(section.sh_size)
                .ok_or_else(|| {
                    format!(
                        "executable section range overflows: start 0x{:x}, size {}",
                        section.sh_addr, section.sh_size
                    )
                })?;
            Ok(section.sh_addr..end)
        })
        .collect()
}

fn validate_table_layout<P: ParseAt>(
    elf: &ElfBytes<'_, AnyEndian>,
    section: &SectionHeader,
    section_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry_size = P::validate_entsize(elf.ehdr.class, section.sh_entsize.try_into()?)?;
    let section_size: usize = section.sh_size.try_into()?;
    if !section_size.is_multiple_of(entry_size) {
        return Err(format!(
            "ELF table section {section_index} size {} is not a multiple of entry size {entry_size}",
            section.sh_size
        )
        .into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_relocation_targets(
    elf: &ElfBytes<'_, AnyEndian>,
    section_headers: &SectionHeaderTable<'_, AnyEndian>,
    relocation_section: &SectionHeader,
    r_offset: u64,
    r_sym: u32,
    addend: Option<i64>,
    executable_ranges: &[std::ops::Range<u64>],
    targets: &mut HashSet<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let relocation_site =
        resolve_relocation_site(elf, section_headers, relocation_section, r_offset)?;
    insert_executable_address(relocation_site, executable_ranges, targets);

    let symbol_value = resolve_relocation_symbol(elf, section_headers, relocation_section, r_sym)?;
    if let Some(value) = symbol_value {
        insert_executable_address(value, executable_ranges, targets);
    }

    if let Some(addend) = addend {
        if let Ok(value) = u64::try_from(addend) {
            insert_executable_address(value, executable_ranges, targets);
        }
        if let Some(symbol_value) = symbol_value {
            let relocated_value = symbol_value.checked_add_signed(addend).ok_or_else(|| {
                format!(
                    "relocation symbol-plus-addend overflows: symbol 0x{symbol_value:x}, addend {addend}"
                )
            })?;
            insert_executable_address(relocated_value, executable_ranges, targets);
        }
    }

    Ok(())
}

fn collect_relr_targets(
    elf: &ElfBytes<'_, AnyEndian>,
    section_headers: &SectionHeaderTable<'_, AnyEndian>,
    relocation_section: &SectionHeader,
    section_index: usize,
    data: &[u8],
    executable_ranges: &[std::ops::Range<u64>],
    targets: &mut HashSet<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (entry_size, word_bits) = match elf.ehdr.class {
        Class::ELF32 => (4usize, 32u32),
        Class::ELF64 => (8usize, 64u32),
    };
    if relocation_section.sh_entsize != entry_size as u64 {
        return Err(format!(
            "RELR section {section_index} has entry size {}, expected {entry_size}",
            relocation_section.sh_entsize
        )
        .into());
    }
    if !data.len().is_multiple_of(entry_size) {
        return Err(format!(
            "RELR section {section_index} size {} is not a multiple of entry size {entry_size}",
            data.len()
        )
        .into());
    }

    let mut next_bitmap_address = None;
    for start in (0..data.len()).step_by(entry_size) {
        let mut offset = start;
        let entry = match elf.ehdr.class {
            Class::ELF32 => u64::from(elf.ehdr.endianness.parse_u32_at(&mut offset, data)?),
            Class::ELF64 => elf.ehdr.endianness.parse_u64_at(&mut offset, data)?,
        };
        if entry & 1 == 0 {
            let relocation_site =
                resolve_relocation_site(elf, section_headers, relocation_section, entry)?;
            insert_executable_address(relocation_site, executable_ranges, targets);
            next_bitmap_address = Some(
                entry
                    .checked_add(entry_size as u64)
                    .ok_or_else(|| format!("RELR direct entry address overflows: 0x{entry:x}"))?,
            );
            continue;
        }

        let bitmap_base = next_bitmap_address
            .ok_or_else(|| format!("RELR section {section_index} begins with a bitmap entry"))?;
        let bitmap = entry >> 1;
        for bit in 0..(word_bits - 1) {
            if bitmap & (1u64 << bit) == 0 {
                continue;
            }
            let byte_offset = u64::from(bit)
                .checked_mul(entry_size as u64)
                .ok_or("RELR bitmap byte offset overflow")?;
            let raw_address = bitmap_base.checked_add(byte_offset).ok_or_else(|| {
                format!(
                    "RELR bitmap address overflows: base 0x{bitmap_base:x}, offset {byte_offset}"
                )
            })?;
            let relocation_site =
                resolve_relocation_site(elf, section_headers, relocation_section, raw_address)?;
            insert_executable_address(relocation_site, executable_ranges, targets);
        }
        let bitmap_span = u64::from(word_bits - 1)
            .checked_mul(entry_size as u64)
            .ok_or("RELR bitmap span overflow")?;
        next_bitmap_address = Some(bitmap_base.checked_add(bitmap_span).ok_or_else(|| {
            format!("RELR bitmap base overflows: base 0x{bitmap_base:x}, span {bitmap_span}")
        })?);
    }

    Ok(())
}

fn resolve_relocation_site(
    elf: &ElfBytes<'_, AnyEndian>,
    section_headers: &SectionHeaderTable<'_, AnyEndian>,
    relocation_section: &SectionHeader,
    r_offset: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    if elf.ehdr.e_type != elf::abi::ET_REL {
        return Ok(r_offset);
    }

    let target_section = section_headers
        .get(relocation_section.sh_info as usize)
        .map_err(|error| {
            format!(
                "relocation target section {} is invalid: {error}",
                relocation_section.sh_info
            )
        })?;
    target_section.sh_addr.checked_add(r_offset).ok_or_else(|| {
        format!(
            "section-relative relocation offset overflows: base 0x{:x}, offset 0x{r_offset:x}",
            target_section.sh_addr
        )
        .into()
    })
}

fn resolve_relocation_symbol(
    elf: &ElfBytes<'_, AnyEndian>,
    section_headers: &SectionHeaderTable<'_, AnyEndian>,
    relocation_section: &SectionHeader,
    r_sym: u32,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    if r_sym == 0 {
        return Ok(None);
    }

    let symbol_section_index = relocation_section.sh_link as usize;
    let symbol_section = section_headers.get(symbol_section_index).map_err(|error| {
        format!("relocation-linked symbol table {symbol_section_index} is invalid: {error}")
    })?;
    if !matches!(
        symbol_section.sh_type,
        elf::abi::SHT_SYMTAB | elf::abi::SHT_DYNSYM
    ) {
        return Err(format!(
            "relocation section links to section {symbol_section_index} of type {}, not a symbol table",
            symbol_section.sh_type
        )
        .into());
    }
    validate_table_layout::<Symbol>(elf, &symbol_section, symbol_section_index)?;
    let (symbol_data, compression) = elf.section_data(&symbol_section)?;
    if compression.is_some() {
        return Err(format!(
            "compressed symbol table section {symbol_section_index} cannot be analyzed"
        )
        .into());
    }
    let symbol = SymbolTable::new(elf.ehdr.endianness, elf.ehdr.class, symbol_data)
        .get(r_sym as usize)
        .map_err(|error| format!("relocation symbol index {r_sym} is invalid: {error}"))?;
    if symbol.is_undefined() {
        return Ok(None);
    }

    let value = if elf.ehdr.e_type != elf::abi::ET_REL || symbol.st_shndx == elf::abi::SHN_ABS {
        symbol.st_value
    } else if symbol.st_shndx >= elf::abi::SHN_LORESERVE {
        return Err(format!(
            "relocatable symbol {r_sym} uses unsupported reserved section index 0x{:x}",
            symbol.st_shndx
        )
        .into());
    } else {
        let defining_section = section_headers
            .get(symbol.st_shndx as usize)
            .map_err(|error| {
                format!(
                    "relocation symbol {r_sym} defining section {} is invalid: {error}",
                    symbol.st_shndx
                )
            })?;
        defining_section
            .sh_addr
            .checked_add(symbol.st_value)
            .ok_or_else(|| {
                format!(
                    "section-relative symbol value overflows: base 0x{:x}, value 0x{:x}",
                    defining_section.sh_addr, symbol.st_value
                )
            })?
    };
    Ok(Some(value))
}

fn insert_executable_address(
    value: u64,
    executable_ranges: &[std::ops::Range<u64>],
    targets: &mut HashSet<u64>,
) {
    if executable_ranges.iter().any(|range| range.contains(&value)) {
        targets.insert(value);
    }
}

fn collect_pointer_values(
    data: &[u8],
    class: Class,
    endianness: AnyEndian,
    executable_ranges: &[std::ops::Range<u64>],
    targets: &mut HashSet<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pointer_width = match class {
        Class::ELF32 => 4,
        Class::ELF64 => 8,
    };
    let Some(last_start) = data.len().checked_sub(pointer_width) else {
        return Ok(());
    };

    // Scan at every byte offset rather than assuming natural alignment. This
    // intentionally over-approximates: an unaligned code pointer must not evade
    // the soundness gate, and false positives only suppress optimization.
    for start in 0..=last_start {
        let mut offset = start;
        let value = match class {
            Class::ELF32 => u64::from(endianness.parse_u32_at(&mut offset, data)?),
            Class::ELF64 => endianness.parse_u64_at(&mut offset, data)?,
        };
        insert_executable_address(value, executable_ranges, targets);
    }
    Ok(())
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
    use crate::output_path::resolve_output_path;

    /// A [`ResolvedOutput`] over a not-yet-existing path in a fresh temp dir.
    ///
    /// The padding tests care about the bytes `create_patched_copy` writes, not
    /// about overwrite policy, so resolving against an absent target keeps
    /// `force` out of them entirely. The returned `TempDir` owns the cleanup and
    /// must stay alive for as long as the output is used.
    fn resolved_test_output(input: &Path) -> (tempfile::TempDir, ResolvedOutput) {
        let dir = tempfile::tempdir().expect("create output directory");
        let output = dir.path().join("patched.elf");
        let resolved =
            resolve_output_path(input, Some(&output), false).expect("resolve test output path");
        (dir, resolved)
    }

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
    fn x86_64_nop_sequence_canonical_lengths_zero_through_nine() {
        let empty: &[u8] = &[];
        assert_eq!(DetectedArch::X86_64.nop_sequence(0), empty);

        let canonical: [&[u8]; 9] = [
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
        for (idx, expected) in canonical.iter().enumerate() {
            let len = idx + 1;
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

        // `fields` follows the Elf64_Shdr layout:
        // fields[0] => sh_name (u32), fields[1] => sh_type (u32),
        // fields[2] => sh_flags (u64), fields[3] => sh_addr (u64),
        // fields[4] => sh_offset (u64), fields[5] => sh_size (u64),
        // fields[6] => sh_link (u32), fields[7] => sh_info (u32),
        // fields[8] => sh_addralign (u64), fields[9] => sh_entsize (u64).
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

    /// ELF64 fixture with `.text`, one `.rela.text` entry, and a linked
    /// `.symtab`. The relocation names three independently useful values: its
    /// application site, its symbol, and symbol-plus-addend.
    fn build_x86_64_rela_fixture(
        text_vaddr: u64,
        relocation_offset: u64,
        symbol_value: u64,
        addend: i64,
    ) -> Vec<u8> {
        let elf_header_size = 64usize;
        let shentsize = 64usize;
        let shnum = 6usize;
        let text = [0x90u8; 16];

        let mut rela = Vec::with_capacity(24);
        rela.extend_from_slice(&relocation_offset.to_le_bytes());
        let r_info = (1u64 << 32) | u64::from(elf::abi::R_X86_64_64);
        rela.extend_from_slice(&r_info.to_le_bytes());
        rela.extend_from_slice(&addend.to_le_bytes());

        let mut symtab = vec![0u8; 24];
        symtab.extend_from_slice(&1u32.to_le_bytes()); // st_name -> "target"
        symtab.push((elf::abi::STB_GLOBAL << 4) | elf::abi::STT_FUNC);
        symtab.push(0); // st_other
        symtab.extend_from_slice(&1u16.to_le_bytes()); // st_shndx -> .text
        symtab.extend_from_slice(&symbol_value.to_le_bytes());
        symtab.extend_from_slice(&0u64.to_le_bytes()); // st_size

        let strtab = b"\0target\0";
        let shstrtab = b"\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0";
        let text_name = 1u64;
        let rela_name = 7u64;
        let symtab_name = 18u64;
        let strtab_name = 26u64;
        let shstrtab_name = 34u64;

        let text_offset = elf_header_size;
        let rela_offset = text_offset + text.len();
        let symtab_offset = rela_offset + rela.len();
        let strtab_offset = symtab_offset + symtab.len();
        let shstrtab_offset = strtab_offset + strtab.len();
        let shoff = shstrtab_offset + shstrtab.len();
        let mut buf = vec![0u8; shoff + shentsize * shnum];

        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = elf::abi::ELFCLASS64;
        buf[5] = elf::abi::ELFDATA2LSB;
        buf[6] = elf::abi::EV_CURRENT;
        buf[16..18].copy_from_slice(&elf::abi::ET_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&elf::abi::EM_X86_64.to_le_bytes());
        buf[20..24].copy_from_slice(&(elf::abi::EV_CURRENT as u32).to_le_bytes());
        buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        buf[52..54].copy_from_slice(&(elf_header_size as u16).to_le_bytes());
        buf[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
        buf[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
        buf[62..64].copy_from_slice(&5u16.to_le_bytes());

        buf[text_offset..rela_offset].copy_from_slice(&text);
        buf[rela_offset..symtab_offset].copy_from_slice(&rela);
        buf[symtab_offset..strtab_offset].copy_from_slice(&symtab);
        buf[strtab_offset..shstrtab_offset].copy_from_slice(strtab);
        buf[shstrtab_offset..shoff].copy_from_slice(shstrtab);

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
                text_name,
                elf::abi::SHT_PROGBITS as u64,
                (elf::abi::SHF_ALLOC | elf::abi::SHF_EXECINSTR) as u64,
                text_vaddr,
                text_offset as u64,
                text.len() as u64,
                0,
                0,
                1,
                0,
            ],
        );
        write_shdr(
            2,
            [
                rela_name,
                elf::abi::SHT_RELA as u64,
                0,
                0,
                rela_offset as u64,
                rela.len() as u64,
                3, // linked symbol table
                1, // target section: .text
                8,
                24,
            ],
        );
        write_shdr(
            3,
            [
                symtab_name,
                elf::abi::SHT_SYMTAB as u64,
                0,
                0,
                symtab_offset as u64,
                symtab.len() as u64,
                4, // linked .strtab
                1,
                8,
                24,
            ],
        );
        write_shdr(
            4,
            [
                strtab_name,
                elf::abi::SHT_STRTAB as u64,
                0,
                0,
                strtab_offset as u64,
                strtab.len() as u64,
                0,
                0,
                1,
                0,
            ],
        );
        write_shdr(
            5,
            [
                shstrtab_name,
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

    fn build_x86_64_pointer_sections_fixture(
        text_vaddr: u64,
        rodata: &[u8],
        data_rel_ro: &[u8],
        relr: &[u8],
    ) -> Vec<u8> {
        let elf_header_size = 64usize;
        let shentsize = 64usize;
        let shnum = 6usize;
        let text = [0x90u8; 16];
        let shstrtab = b"\0.text\0.rodata\0.data.rel.ro\0.relr.dyn\0.shstrtab\0";

        let text_offset = elf_header_size;
        let rodata_offset = text_offset + text.len();
        let data_rel_ro_offset = rodata_offset + rodata.len();
        let relr_offset = data_rel_ro_offset + data_rel_ro.len();
        let shstrtab_offset = relr_offset + relr.len();
        let shoff = shstrtab_offset + shstrtab.len();
        let mut buf = vec![0u8; shoff + shentsize * shnum];

        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = elf::abi::ELFCLASS64;
        buf[5] = elf::abi::ELFDATA2LSB;
        buf[6] = elf::abi::EV_CURRENT;
        buf[16..18].copy_from_slice(&elf::abi::ET_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&elf::abi::EM_X86_64.to_le_bytes());
        buf[20..24].copy_from_slice(&(elf::abi::EV_CURRENT as u32).to_le_bytes());
        buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        buf[52..54].copy_from_slice(&(elf_header_size as u16).to_le_bytes());
        buf[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
        buf[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
        buf[62..64].copy_from_slice(&5u16.to_le_bytes());

        buf[text_offset..rodata_offset].copy_from_slice(&text);
        buf[rodata_offset..data_rel_ro_offset].copy_from_slice(rodata);
        buf[data_rel_ro_offset..relr_offset].copy_from_slice(data_rel_ro);
        buf[relr_offset..shstrtab_offset].copy_from_slice(relr);
        buf[shstrtab_offset..shoff].copy_from_slice(shstrtab);

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
                text.len() as u64,
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
                elf::abi::SHT_PROGBITS as u64,
                elf::abi::SHF_ALLOC as u64,
                0x2000,
                rodata_offset as u64,
                rodata.len() as u64,
                0,
                0,
                1,
                0,
            ],
        );
        write_shdr(
            3,
            [
                15,
                elf::abi::SHT_PROGBITS as u64,
                (elf::abi::SHF_ALLOC | elf::abi::SHF_WRITE) as u64,
                0x3000,
                data_rel_ro_offset as u64,
                data_rel_ro.len() as u64,
                0,
                0,
                1,
                0,
            ],
        );
        write_shdr(
            4,
            [
                28,
                19, // SHT_RELR (not yet exposed by elf 0.8)
                elf::abi::SHF_ALLOC as u64,
                0x4000,
                relr_offset as u64,
                relr.len() as u64,
                0,
                0,
                8,
                8,
            ],
        );
        write_shdr(
            5,
            [
                38,
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

    #[test]
    fn indirect_targets_include_relocation_site_symbol_and_symbol_plus_addend() {
        use crate::test_utils::TempFile;

        let elf_bytes = build_x86_64_rela_fixture(0x1000, 0x1004, 0x1008, 4);
        let input = TempFile::new_bytes("s11-elf-indirect-rela", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("fixture ELF should parse");

        let targets = patcher
            .indirect_control_flow_targets()
            .expect("valid relocation metadata should be analyzed");

        assert!(
            targets.contains(&0x1004),
            "relocation site must be excluded"
        );
        assert!(targets.contains(&0x1008), "linked symbol must be excluded");
        assert!(
            targets.contains(&0x100c),
            "symbol-plus-addend value must be excluded"
        );
    }

    #[test]
    fn indirect_targets_include_code_pointers_from_rodata_and_data_rel_ro() {
        use crate::test_utils::TempFile;

        let mut rodata = vec![0xa5]; // force the first pointer to be unaligned
        rodata.extend_from_slice(&0x1004u64.to_le_bytes());
        rodata.extend_from_slice(&0xfeed_face_cafe_beefu64.to_le_bytes());
        let data_rel_ro = 0x1008u64.to_le_bytes();
        let elf_bytes = build_x86_64_pointer_sections_fixture(0x1000, &rodata, &data_rel_ro, &[]);
        let input = TempFile::new_bytes("s11-elf-indirect-pointers", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("fixture ELF should parse");

        let targets = patcher
            .indirect_control_flow_targets()
            .expect("valid pointer sections should be analyzed");

        assert!(
            targets.contains(&0x1004),
            "unaligned .rodata code pointer must be excluded"
        );
        assert!(
            targets.contains(&0x1008),
            ".data.rel.ro code pointer must be excluded"
        );
        assert_eq!(targets.len(), 2, "non-code data values must be ignored");
    }

    #[test]
    fn indirect_targets_include_compact_relr_direct_and_bitmap_addresses() {
        use crate::test_utils::TempFile;

        let mut relr = Vec::new();
        relr.extend_from_slice(&0x1000u64.to_le_bytes()); // direct relocation
        relr.extend_from_slice(&3u64.to_le_bytes()); // bitmap bit 1 -> 0x1008
        let elf_bytes = build_x86_64_pointer_sections_fixture(0x1000, &[], &[], &relr);
        let input = TempFile::new_bytes("s11-elf-indirect-relr", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("fixture ELF should parse");

        let targets = patcher
            .indirect_control_flow_targets()
            .expect("valid RELR metadata should be analyzed");

        assert!(targets.contains(&0x1000), "direct RELR address is named");
        assert!(targets.contains(&0x1008), "RELR bitmap address is named");
    }

    #[test]
    fn create_patched_copy_emits_canonical_x86_nop_padding() {
        use crate::test_utils::TempFile;

        let text_vaddr: u64 = 0x100000;
        let text_bytes = [0xc3u8; 8];
        let elf_bytes = build_minimal_x86_64_elf(&text_bytes, text_vaddr);

        let input = TempFile::new_bytes("s11-elf-padding-in", "elf", &elf_bytes);
        let (_output_dir, output) = resolved_test_output(input.path());

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");
        assert_eq!(patcher.arch(), DetectedArch::X86_64);

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 8,
        };
        let payload = [0x90u8, 0x90, 0x90];
        patcher
            .create_patched_copy(&output, &window, &payload)
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
        let (_output_dir, output) = resolved_test_output(input.path());

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");
        assert_eq!(patcher.arch(), DetectedArch::Aarch64);

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 16,
        };
        let payload = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];
        patcher
            .create_patched_copy(&output, &window, &payload)
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
        let (_output_dir, output) = resolved_test_output(input.path());

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
            .create_patched_copy(&output, &window, &payload)
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
        let (_output_dir, output) = resolved_test_output(input.path());

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 8,
        };
        let payload = [0xcc, 0x31, 0xc0, 0x48, 0x83, 0xc0, 0x01, 0xc3];
        patcher
            .create_patched_copy(&output, &window, &payload)
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
        let (_output_dir, output) = resolved_test_output(input.path());

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 20,
        };
        let payload = [0x90u8, 0x90, 0x90];
        patcher
            .create_patched_copy(&output, &window, &payload)
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
        let (_output_dir, output) = resolved_test_output(input.path());

        let patcher = ElfPatcher::new(input.path()).expect("patcher should accept minimal ELF");

        let window = AddressWindow {
            start: text_vaddr,
            end: text_vaddr + 20,
        };
        let payload = [0xaa, 0xbb, 0xcc, 0xdd];
        patcher
            .create_patched_copy(&output, &window, &payload)
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
