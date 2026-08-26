//! Pure ELF indirect-control-flow-target analysis.
//!
//! This is a stateless seam lifted out of [`crate::elf_patcher::ElfPatcher`]:
//! the byte-patcher stays responsible for validating windows and writing
//! images, while all knowledge of ELF relocation formats (REL/RELA, compact
//! RELR bitmaps, symbol resolution, and `.rodata`/`.data.rel.ro` pointer
//! scanning) lives here behind a single entry point that maps raw ELF bytes to
//! the set of executable addresses named by that metadata (ADR-0009 Decision
//! 5). Keeping it pure — `&[u8]` in, `HashSet<u64>` out — lets the soundness
//! gate be exercised directly from crafted fixtures without constructing a
//! patcher or touching the filesystem.

use elf::ElfBytes;
use elf::endian::{AnyEndian, EndianParse};
use elf::file::Class;
use elf::parse::ParseAt;
use elf::relocation::{Rel, Rela};
use elf::section::{SectionHeader, SectionHeaderTable};
use elf::symbol::{Symbol, SymbolTable};
use std::collections::HashSet;

/// Standard compact relative-relocation section type. `elf` 0.8 predates the
/// public `SHT_RELR` constant even though contemporary toolchains emit it.
const SHT_RELR: u32 = 19;

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
    file_data: &[u8],
) -> Result<HashSet<u64>, Box<dyn std::error::Error>> {
    let elf = ElfBytes::<AnyEndian>::minimal_parse(file_data)?;
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
            return Err(
                format!("compressed pointer section '{section_name}' cannot be analyzed").into(),
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture `.text` base for addresses that need to be nowhere near the top
    /// of the address space.
    const TEXT_VADDR: u64 = 0x1000;
    const TEXT_SIZE: u64 = 16;
    /// Highest `.text` base that still leaves room for [`TEXT_SIZE`] bytes of
    /// code, so overflow fixtures can name addresses past the end of the
    /// address space without overflowing the executable range itself.
    const HIGH_TEXT_VADDR: u64 = u64::MAX - 0xff;
    /// ELF64 compression-header size, which prefixes every `SHF_COMPRESSED`
    /// payload the `elf` crate hands back.
    const CHDR_SIZE: usize = 24;

    /// One section header plus its bytes in a synthetic ELF image.
    struct Section {
        name: &'static str,
        sh_type: u32,
        sh_flags: u64,
        sh_addr: u64,
        sh_link: u32,
        sh_info: u32,
        sh_entsize: u64,
        data: Vec<u8>,
    }

    impl Section {
        fn new(name: &'static str, sh_type: u32, data: Vec<u8>) -> Self {
            Self {
                name,
                sh_type,
                sh_flags: 0,
                sh_addr: 0,
                sh_link: 0,
                sh_info: 0,
                sh_entsize: 0,
                data,
            }
        }

        fn flags(mut self, sh_flags: u32) -> Self {
            self.sh_flags = u64::from(sh_flags);
            self
        }

        fn addr(mut self, sh_addr: u64) -> Self {
            self.sh_addr = sh_addr;
            self
        }

        /// Index of the linked section: for a relocation table, its symbol
        /// table.
        fn link(mut self, sh_link: u32) -> Self {
            self.sh_link = sh_link;
            self
        }

        /// Index of the section a relocation table applies to.
        fn info(mut self, sh_info: u32) -> Self {
            self.sh_info = sh_info;
            self
        }

        fn entsize(mut self, sh_entsize: u64) -> Self {
            self.sh_entsize = sh_entsize;
            self
        }
    }

    /// Assemble a little-endian ELF image carrying exactly `sections`, which
    /// occupy indices 1..=sections.len(): index 0 is the mandatory null header
    /// and the auto-generated `.shstrtab` follows the caller's sections.
    fn build_elf(class: Class, e_type: u16, sections: Vec<Section>) -> Vec<u8> {
        let (ehdr_size, shentsize, machine) = match class {
            Class::ELF32 => (52usize, 40usize, elf::abi::EM_386),
            Class::ELF64 => (64usize, 64usize, elf::abi::EM_X86_64),
        };

        let mut shstrtab = vec![0u8];
        let mut name_offsets = Vec::with_capacity(sections.len());
        for section in &sections {
            name_offsets.push(shstrtab.len() as u64);
            shstrtab.extend_from_slice(section.name.as_bytes());
            shstrtab.push(0);
        }
        let shstrtab_name = shstrtab.len() as u64;
        shstrtab.extend_from_slice(b".shstrtab\0");

        let mut buf = vec![0u8; ehdr_size];
        let mut data_offsets = Vec::with_capacity(sections.len());
        for section in &sections {
            data_offsets.push(buf.len() as u64);
            buf.extend_from_slice(&section.data);
        }
        let shstrtab_offset = buf.len() as u64;
        buf.extend_from_slice(&shstrtab);
        let shoff = buf.len();
        let shnum = sections.len() + 2;
        let shstrndx = sections.len() + 1;
        buf.resize(shoff + shnum * shentsize, 0);

        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = match class {
            Class::ELF32 => elf::abi::ELFCLASS32,
            Class::ELF64 => elf::abi::ELFCLASS64,
        };
        buf[5] = elf::abi::ELFDATA2LSB;
        buf[6] = elf::abi::EV_CURRENT;
        buf[16..18].copy_from_slice(&e_type.to_le_bytes());
        buf[18..20].copy_from_slice(&machine.to_le_bytes());
        buf[20..24].copy_from_slice(&u32::from(elf::abi::EV_CURRENT).to_le_bytes());
        match class {
            Class::ELF32 => {
                buf[32..36].copy_from_slice(&(shoff as u32).to_le_bytes());
                buf[40..42].copy_from_slice(&(ehdr_size as u16).to_le_bytes());
                buf[46..48].copy_from_slice(&(shentsize as u16).to_le_bytes());
                buf[48..50].copy_from_slice(&(shnum as u16).to_le_bytes());
                buf[50..52].copy_from_slice(&(shstrndx as u16).to_le_bytes());
            }
            Class::ELF64 => {
                buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
                buf[52..54].copy_from_slice(&(ehdr_size as u16).to_le_bytes());
                buf[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
                buf[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
                buf[62..64].copy_from_slice(&(shstrndx as u16).to_le_bytes());
            }
        }

        // sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
        // sh_info, sh_addralign, sh_entsize. ELF32 stores all ten as words;
        // ELF64 widens the address-sized ones.
        let mut write_shdr = |index: usize, fields: [u64; 10]| {
            let base = shoff + index * shentsize;
            let widths = match class {
                Class::ELF32 => [4usize; 10],
                Class::ELF64 => [4, 4, 8, 8, 8, 8, 4, 4, 8, 8],
            };
            let mut at = base;
            for (width, value) in widths.iter().zip(fields.iter()) {
                if *width == 4 {
                    buf[at..at + 4].copy_from_slice(&(*value as u32).to_le_bytes());
                } else {
                    buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
                }
                at += width;
            }
        };

        write_shdr(0, [0; 10]);
        for (index, section) in sections.iter().enumerate() {
            write_shdr(
                index + 1,
                [
                    name_offsets[index],
                    u64::from(section.sh_type),
                    section.sh_flags,
                    section.sh_addr,
                    data_offsets[index],
                    section.data.len() as u64,
                    u64::from(section.sh_link),
                    u64::from(section.sh_info),
                    1,
                    section.sh_entsize,
                ],
            );
        }
        write_shdr(
            shstrndx,
            [
                shstrtab_name,
                u64::from(elf::abi::SHT_STRTAB),
                0,
                0,
                shstrtab_offset,
                shstrtab.len() as u64,
                0,
                0,
                1,
                0,
            ],
        );

        buf
    }

    /// Executable `.text` based at `vaddr`, always fixture section index 1.
    fn text_section(vaddr: u64) -> Section {
        Section::new(
            ".text",
            elf::abi::SHT_PROGBITS,
            vec![0x90; TEXT_SIZE as usize],
        )
        .flags(elf::abi::SHF_ALLOC | elf::abi::SHF_EXECINSTR)
        .addr(vaddr)
    }

    fn rel_entry(r_offset: u64, r_sym: u32) -> Vec<u8> {
        let mut entry = r_offset.to_le_bytes().to_vec();
        let r_info = (u64::from(r_sym) << 32) | u64::from(elf::abi::R_X86_64_64);
        entry.extend_from_slice(&r_info.to_le_bytes());
        entry
    }

    fn rela_entry(r_offset: u64, r_sym: u32, r_addend: i64) -> Vec<u8> {
        let mut entry = rel_entry(r_offset, r_sym);
        entry.extend_from_slice(&r_addend.to_le_bytes());
        entry
    }

    /// ELF64 `.symtab` holding the mandatory null entry plus one function
    /// symbol at index 1.
    fn symtab_section(st_shndx: u16, st_value: u64) -> Section {
        let mut data = vec![0u8; 24];
        data.extend_from_slice(&0u32.to_le_bytes()); // st_name
        data.push((elf::abi::STB_GLOBAL << 4) | elf::abi::STT_FUNC);
        data.push(0); // st_other
        data.extend_from_slice(&st_shndx.to_le_bytes());
        data.extend_from_slice(&st_value.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes()); // st_size
        Section::new(".symtab", elf::abi::SHT_SYMTAB, data).entsize(24)
    }

    /// A `SHF_COMPRESSED` payload of `size` bytes: a well-formed ELF64
    /// compression header the analysis must refuse rather than misread as
    /// relocations, symbols, or pointers.
    fn compressed_payload(size: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(size);
        data.extend_from_slice(&elf::abi::ELFCOMPRESS_ZLIB.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // ch_reserved
        data.extend_from_slice(&64u64.to_le_bytes()); // ch_size
        data.extend_from_slice(&8u64.to_le_bytes()); // ch_addralign
        data.resize(size, 0);
        data
    }

    fn relr_section(entries: Vec<u8>) -> Section {
        Section::new(".relr.dyn", SHT_RELR, entries)
            .flags(elf::abi::SHF_ALLOC)
            .entsize(8)
    }

    fn relr_entries(entries: &[u64]) -> Vec<u8> {
        entries.iter().flat_map(|e| e.to_le_bytes()).collect()
    }

    /// Assert the analysis refuses `elf_bytes` for the stated reason. A partial
    /// exclusion set would silently unsound whole-binary candidate discovery,
    /// so every malformed input must surface as an error.
    fn expect_rejection(elf_bytes: &[u8], case: &str, expectation: &str) {
        let error = indirect_control_flow_targets(elf_bytes)
            .expect_err(&format!("{case} must be rejected"))
            .to_string();
        assert!(
            error.contains(expectation),
            "{case}: expected an error containing {expectation:?}, got {error:?}"
        );
    }

    #[test]
    fn indirect_targets_include_relocation_site_symbol_and_symbol_plus_addend() {
        let elf_bytes = build_elf(
            Class::ELF64,
            elf::abi::ET_EXEC,
            vec![
                text_section(TEXT_VADDR),
                Section::new(".rela.text", elf::abi::SHT_RELA, rela_entry(0x1004, 1, 4))
                    .entsize(24)
                    .link(3)
                    .info(1),
                symtab_section(1, 0x1008),
            ],
        );

        let targets = indirect_control_flow_targets(&elf_bytes)
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
    fn indirect_targets_include_rel_site_and_symbol_without_an_addend() {
        let elf_bytes = build_elf(
            Class::ELF64,
            elf::abi::ET_EXEC,
            vec![
                text_section(TEXT_VADDR),
                Section::new(".rel.text", elf::abi::SHT_REL, rel_entry(0x1004, 1))
                    .entsize(16)
                    .link(3)
                    .info(1),
                symtab_section(1, 0x1008),
            ],
        );

        let targets = indirect_control_flow_targets(&elf_bytes)
            .expect("valid REL metadata should be analyzed");

        assert_eq!(
            targets,
            HashSet::from([0x1004, 0x1008]),
            "REL names only its site and symbol, never an addend"
        );
    }

    #[test]
    fn indirect_targets_ignore_relocations_without_a_symbol() {
        let elf_bytes = build_elf(
            Class::ELF64,
            elf::abi::ET_EXEC,
            vec![
                text_section(TEXT_VADDR),
                Section::new(
                    ".rela.text",
                    elf::abi::SHT_RELA,
                    rela_entry(0x1004, 0, 0x1008),
                )
                .entsize(24)
                .link(3)
                .info(1),
                symtab_section(1, 0x100c),
            ],
        );

        let targets = indirect_control_flow_targets(&elf_bytes)
            .expect("a symbol-less relocation should be analyzed");

        assert_eq!(
            targets,
            HashSet::from([0x1004, 0x1008]),
            "an unlinked relocation names its site and bare addend only"
        );
    }

    #[test]
    fn indirect_targets_ignore_undefined_symbols() {
        let elf_bytes = build_elf(
            Class::ELF64,
            elf::abi::ET_EXEC,
            vec![
                text_section(TEXT_VADDR),
                Section::new(".rela.text", elf::abi::SHT_RELA, rela_entry(0x1004, 1, 0))
                    .entsize(24)
                    .link(3)
                    .info(1),
                symtab_section(elf::abi::SHN_UNDEF, 0x1008),
            ],
        );

        let targets = indirect_control_flow_targets(&elf_bytes)
            .expect("an undefined symbol should be analyzed");

        assert_eq!(
            targets,
            HashSet::from([0x1004]),
            "an undefined symbol has no address to exclude"
        );
    }

    #[test]
    fn indirect_targets_resolve_section_relative_sites_and_symbols() {
        let elf_bytes = build_elf(
            Class::ELF64,
            elf::abi::ET_REL,
            vec![
                text_section(0),
                Section::new(".rel.text", elf::abi::SHT_REL, rel_entry(4, 1))
                    .entsize(16)
                    .link(3)
                    .info(1),
                symtab_section(1, 8),
            ],
        );

        let targets = indirect_control_flow_targets(&elf_bytes)
            .expect("relocatable-object metadata should be analyzed");

        assert_eq!(
            targets,
            HashSet::from([4, 8]),
            "sites and symbols in a relocatable object are section-relative"
        );
    }

    #[test]
    fn indirect_targets_include_absolute_symbols_of_relocatable_objects() {
        let elf_bytes = build_elf(
            Class::ELF64,
            elf::abi::ET_REL,
            vec![
                text_section(TEXT_VADDR),
                Section::new(".rel.text", elf::abi::SHT_REL, rel_entry(4, 1))
                    .entsize(16)
                    .link(3)
                    .info(1),
                symtab_section(elf::abi::SHN_ABS, 0x1008),
            ],
        );

        let targets = indirect_control_flow_targets(&elf_bytes)
            .expect("an absolute symbol should be analyzed");

        assert!(
            targets.contains(&0x1008),
            "an absolute symbol value is already a final address"
        );
    }

    #[test]
    fn indirect_targets_include_code_pointers_from_rodata_and_data_rel_ro() {
        let mut rodata = vec![0xa5]; // force the first pointer to be unaligned
        rodata.extend_from_slice(&0x1004u64.to_le_bytes());
        rodata.extend_from_slice(&0xfeed_face_cafe_beefu64.to_le_bytes());
        let elf_bytes = build_elf(
            Class::ELF64,
            elf::abi::ET_EXEC,
            vec![
                text_section(TEXT_VADDR),
                Section::new(".rodata", elf::abi::SHT_PROGBITS, rodata)
                    .flags(elf::abi::SHF_ALLOC)
                    .addr(0x2000),
                Section::new(
                    ".data.rel.ro",
                    elf::abi::SHT_PROGBITS,
                    0x1008u64.to_le_bytes().to_vec(),
                )
                .flags(elf::abi::SHF_ALLOC | elf::abi::SHF_WRITE)
                .addr(0x3000),
            ],
        );

        let targets = indirect_control_flow_targets(&elf_bytes)
            .expect("valid pointer sections should be analyzed");

        assert_eq!(
            targets,
            HashSet::from([0x1004, 0x1008]),
            "code pointers are excluded at any alignment, other data is ignored"
        );
    }

    #[test]
    fn indirect_targets_ignore_pointer_sections_too_short_to_hold_a_pointer() {
        let elf_bytes = build_elf(
            Class::ELF64,
            elf::abi::ET_EXEC,
            vec![
                text_section(TEXT_VADDR),
                Section::new(
                    ".rodata",
                    elf::abi::SHT_PROGBITS,
                    0x1004u32.to_le_bytes().to_vec(),
                )
                .flags(elf::abi::SHF_ALLOC)
                .addr(0x2000),
            ],
        );

        let targets = indirect_control_flow_targets(&elf_bytes)
            .expect("a short pointer section should be analyzed");

        assert!(
            targets.is_empty(),
            "four bytes cannot hold a 64-bit code pointer"
        );
    }

    #[test]
    fn indirect_targets_include_compact_relr_direct_and_bitmap_addresses() {
        let elf_bytes = build_elf(
            Class::ELF64,
            elf::abi::ET_EXEC,
            vec![
                text_section(TEXT_VADDR),
                relr_section(relr_entries(&[
                    0x1000, // direct relocation
                    3,      // bitmap bit 0 -> 0x1008
                ])),
            ],
        );

        let targets = indirect_control_flow_targets(&elf_bytes)
            .expect("valid RELR metadata should be analyzed");

        assert_eq!(
            targets,
            HashSet::from([0x1000, 0x1008]),
            "RELR names its direct entry and every address its bitmap sets"
        );
    }

    #[test]
    fn indirect_targets_read_elf32_pointers_and_relr_entries() {
        let mut rodata = 0x1004u32.to_le_bytes().to_vec();
        rodata.extend_from_slice(&0xdead_beefu32.to_le_bytes());
        let relr: Vec<u8> = [0x1000u32, 3]
            .iter()
            .flat_map(|entry| entry.to_le_bytes())
            .collect();
        let elf_bytes = build_elf(
            Class::ELF32,
            elf::abi::ET_EXEC,
            vec![
                text_section(TEXT_VADDR),
                Section::new(".rodata", elf::abi::SHT_PROGBITS, rodata)
                    .flags(elf::abi::SHF_ALLOC)
                    .addr(0x2000),
                Section::new(".relr.dyn", SHT_RELR, relr)
                    .flags(elf::abi::SHF_ALLOC)
                    .entsize(4),
            ],
        );

        let targets =
            indirect_control_flow_targets(&elf_bytes).expect("32-bit metadata should be analyzed");

        assert_eq!(
            targets,
            HashSet::from([0x1000, 0x1004]),
            "32-bit pointers and RELR entries are four bytes wide"
        );
    }

    #[test]
    fn analysis_rejects_every_compressed_section_it_must_read() {
        let cases = [
            (
                "compressed REL",
                vec![
                    text_section(TEXT_VADDR),
                    Section::new(
                        ".rel.text",
                        elf::abi::SHT_REL,
                        compressed_payload(CHDR_SIZE + 8),
                    )
                    .flags(elf::abi::SHF_COMPRESSED)
                    .entsize(16)
                    .info(1),
                ],
                "compressed relocation section 2 cannot be analyzed",
            ),
            (
                "compressed RELA",
                vec![
                    text_section(TEXT_VADDR),
                    Section::new(
                        ".rela.text",
                        elf::abi::SHT_RELA,
                        compressed_payload(CHDR_SIZE + 24),
                    )
                    .flags(elf::abi::SHF_COMPRESSED)
                    .entsize(24)
                    .info(1),
                ],
                "compressed relocation section 2 cannot be analyzed",
            ),
            (
                "compressed RELR",
                vec![
                    text_section(TEXT_VADDR),
                    Section::new(".relr.dyn", SHT_RELR, compressed_payload(CHDR_SIZE + 8))
                        .flags(elf::abi::SHF_COMPRESSED)
                        .entsize(8),
                ],
                "compressed RELR section 2 cannot be analyzed",
            ),
            (
                "compressed symbol table",
                vec![
                    text_section(TEXT_VADDR),
                    Section::new(".rela.text", elf::abi::SHT_RELA, rela_entry(0x1004, 1, 0))
                        .entsize(24)
                        .link(3)
                        .info(1),
                    Section::new(
                        ".symtab",
                        elf::abi::SHT_SYMTAB,
                        compressed_payload(CHDR_SIZE + 24),
                    )
                    .flags(elf::abi::SHF_COMPRESSED)
                    .entsize(24),
                ],
                "compressed symbol table section 3 cannot be analyzed",
            ),
            (
                "compressed pointer section",
                vec![
                    text_section(TEXT_VADDR),
                    Section::new(
                        ".rodata",
                        elf::abi::SHT_PROGBITS,
                        compressed_payload(CHDR_SIZE + 8),
                    )
                    .flags(elf::abi::SHF_ALLOC | elf::abi::SHF_COMPRESSED)
                    .addr(0x2000),
                ],
                "compressed pointer section '.rodata' cannot be analyzed",
            ),
        ];

        for (case, sections, expectation) in cases {
            let elf_bytes = build_elf(Class::ELF64, elf::abi::ET_EXEC, sections);
            expect_rejection(&elf_bytes, case, expectation);
        }
    }

    #[test]
    fn analysis_rejects_malformed_relocation_tables() {
        let cases = [
            (
                "RELA size that is not a whole number of entries",
                elf::abi::ET_EXEC,
                vec![
                    text_section(TEXT_VADDR),
                    Section::new(".rela.text", elf::abi::SHT_RELA, vec![0u8; 25])
                        .entsize(24)
                        .info(1),
                ],
                "size 25 is not a multiple of entry size 24",
            ),
            (
                "relocation applied to a section that does not exist",
                elf::abi::ET_REL,
                vec![
                    text_section(TEXT_VADDR),
                    Section::new(".rel.text", elf::abi::SHT_REL, rel_entry(4, 0))
                        .entsize(16)
                        .info(99),
                ],
                "relocation target section 99 is invalid",
            ),
            (
                "RELR entry size that does not match the ELF class",
                elf::abi::ET_EXEC,
                vec![
                    text_section(TEXT_VADDR),
                    relr_section(relr_entries(&[0x1000])).entsize(4),
                ],
                "RELR section 2 has entry size 4, expected 8",
            ),
            (
                "RELR size that is not a whole number of entries",
                elf::abi::ET_EXEC,
                vec![text_section(TEXT_VADDR), relr_section(vec![0u8; 12])],
                "RELR section 2 size 12 is not a multiple of entry size 8",
            ),
            (
                "RELR table that opens with a bitmap",
                elf::abi::ET_EXEC,
                vec![text_section(TEXT_VADDR), relr_section(relr_entries(&[1]))],
                "RELR section 2 begins with a bitmap entry",
            ),
        ];

        for (case, e_type, sections, expectation) in cases {
            let elf_bytes = build_elf(Class::ELF64, e_type, sections);
            expect_rejection(&elf_bytes, case, expectation);
        }
    }

    #[test]
    fn analysis_rejects_unusable_symbol_tables() {
        let relocation = || {
            Section::new(".rela.text", elf::abi::SHT_RELA, rela_entry(4, 1, 0))
                .entsize(24)
                .link(3)
                .info(1)
        };
        let cases = [
            (
                "relocation linked to a section that does not exist",
                elf::abi::ET_EXEC,
                vec![
                    text_section(TEXT_VADDR),
                    relocation().link(99),
                    symtab_section(1, 0x1008),
                ],
                "relocation-linked symbol table 99 is invalid",
            ),
            (
                "relocation linked to something other than a symbol table",
                elf::abi::ET_EXEC,
                vec![
                    text_section(TEXT_VADDR),
                    relocation().link(1),
                    symtab_section(1, 0x1008),
                ],
                "links to section 1 of type 1, not a symbol table",
            ),
            (
                "symbol in a reserved section of a relocatable object",
                elf::abi::ET_REL,
                vec![
                    text_section(TEXT_VADDR),
                    relocation(),
                    symtab_section(elf::abi::SHN_LORESERVE, 0x1008),
                ],
                "unsupported reserved section index 0xff00",
            ),
            (
                "symbol defined by a section that does not exist",
                elf::abi::ET_REL,
                vec![
                    text_section(TEXT_VADDR),
                    relocation(),
                    symtab_section(99, 0x1008),
                ],
                "defining section 99 is invalid",
            ),
        ];

        for (case, e_type, sections, expectation) in cases {
            let elf_bytes = build_elf(Class::ELF64, e_type, sections);
            expect_rejection(&elf_bytes, case, expectation);
        }
    }

    #[test]
    fn analysis_rejects_addresses_that_overflow() {
        let cases = [
            (
                "executable section running past the address space",
                elf::abi::ET_EXEC,
                vec![text_section(u64::MAX)],
                "executable section range overflows",
            ),
            (
                "section-relative site past the address space",
                elf::abi::ET_REL,
                vec![
                    text_section(HIGH_TEXT_VADDR),
                    Section::new(".rel.text", elf::abi::SHT_REL, rel_entry(0x200, 0))
                        .entsize(16)
                        .link(3)
                        .info(1),
                    symtab_section(1, 0),
                ],
                "section-relative relocation offset overflows",
            ),
            (
                "section-relative symbol past the address space",
                elf::abi::ET_REL,
                vec![
                    text_section(HIGH_TEXT_VADDR),
                    Section::new(".rel.text", elf::abi::SHT_REL, rel_entry(4, 1))
                        .entsize(16)
                        .link(3)
                        .info(1),
                    symtab_section(1, 0x200),
                ],
                "section-relative symbol value overflows",
            ),
            (
                "symbol-plus-addend past the address space",
                elf::abi::ET_EXEC,
                vec![
                    text_section(HIGH_TEXT_VADDR),
                    Section::new(
                        ".rela.text",
                        elf::abi::SHT_RELA,
                        rela_entry(HIGH_TEXT_VADDR, 1, i64::MAX),
                    )
                    .entsize(24)
                    .link(3)
                    .info(1),
                    symtab_section(1, HIGH_TEXT_VADDR),
                ],
                "relocation symbol-plus-addend overflows",
            ),
            (
                "RELR bitmap address past the address space",
                elf::abi::ET_EXEC,
                vec![
                    text_section(TEXT_VADDR),
                    relr_section(relr_entries(&[u64::MAX - 0xf, 5])),
                ],
                "RELR bitmap address overflows",
            ),
            (
                "RELR bitmap window past the address space",
                elf::abi::ET_EXEC,
                vec![
                    text_section(TEXT_VADDR),
                    relr_section(relr_entries(&[u64::MAX - 0x107, 3])),
                ],
                "RELR bitmap base overflows",
            ),
        ];

        for (case, e_type, sections, expectation) in cases {
            let elf_bytes = build_elf(Class::ELF64, e_type, sections);
            expect_rejection(&elf_bytes, case, expectation);
        }
    }
}
