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
        let elf_bytes = build_x86_64_rela_fixture(0x1000, 0x1004, 0x1008, 4);

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
    fn indirect_targets_include_code_pointers_from_rodata_and_data_rel_ro() {
        let mut rodata = vec![0xa5]; // force the first pointer to be unaligned
        rodata.extend_from_slice(&0x1004u64.to_le_bytes());
        rodata.extend_from_slice(&0xfeed_face_cafe_beefu64.to_le_bytes());
        let data_rel_ro = 0x1008u64.to_le_bytes();
        let elf_bytes = build_x86_64_pointer_sections_fixture(0x1000, &rodata, &data_rel_ro, &[]);

        let targets = indirect_control_flow_targets(&elf_bytes)
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
        let mut relr = Vec::new();
        relr.extend_from_slice(&0x1000u64.to_le_bytes()); // direct relocation
        relr.extend_from_slice(&3u64.to_le_bytes()); // bitmap bit 1 -> 0x1008
        let elf_bytes = build_x86_64_pointer_sections_fixture(0x1000, &[], &[], &relr);

        let targets = indirect_control_flow_targets(&elf_bytes)
            .expect("valid RELR metadata should be analyzed");

        assert!(targets.contains(&0x1000), "direct RELR address is named");
        assert!(targets.contains(&0x1008), "RELR bitmap address is named");
    }
}
