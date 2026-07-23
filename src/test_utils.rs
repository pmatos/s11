use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

// `main.rs` includes this shared test utility module without compiling the
// library-only instruction tests that consume these fixtures.
#[allow(dead_code)]
#[path = "test_utils/instruction_fixtures.rs"]
pub(crate) mod instruction_fixtures;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct TempFile {
    path: PathBuf,
}

impl TempFile {
    pub(crate) fn new(prefix: &str, extension: &str, content: &str) -> Self {
        Self::new_bytes(prefix, extension, content.as_bytes())
    }

    pub(crate) fn new_bytes(prefix: &str, extension: &str, content: &[u8]) -> Self {
        let id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "{}-{}-{}.{}",
            prefix,
            std::process::id(),
            id,
            extension
        ));
        std::fs::write(&path, content).unwrap();
        Self { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Build a minimal, self-contained ELF64 image with a single executable
/// `.text` section holding `text_bytes` at virtual address `text_vaddr`.
///
/// Just enough of the ELF layout is populated for `ElfPatcher::new` to parse
/// the file and expose one `.text` `TextSection`. Shared by the tests that
/// exercise binary-reading code paths across modules.
#[allow(dead_code)]
pub(crate) fn build_minimal_elf64(text_bytes: &[u8], text_vaddr: u64, machine: u16) -> Vec<u8> {
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

#[allow(dead_code)]
pub(crate) fn build_minimal_aarch64_elf(text_bytes: &[u8], text_vaddr: u64) -> Vec<u8> {
    build_minimal_elf64(text_bytes, text_vaddr, elf::abi::EM_AARCH64)
}

#[allow(dead_code)]
pub(crate) fn build_minimal_x86_64_elf(text_bytes: &[u8], text_vaddr: u64) -> Vec<u8> {
    build_minimal_elf64(text_bytes, text_vaddr, elf::abi::EM_X86_64)
}
