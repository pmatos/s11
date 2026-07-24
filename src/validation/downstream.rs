//! Downstream (fall-through) liveness scanning.
//!
//! When s11 optimizes a straight-line window inside a `.text` section, the
//! live-out contract must keep alive any architectural state the *fall-through
//! successor* can still observe. Computing that means walking the bytes that
//! follow the window one instruction at a time, converting each to IR, and
//! applying a per-instruction liveness rule until the answer is settled.
//!
//! That walk is identical across AArch64 and x86 and across the two things we
//! scan for (condition flags, written registers); only two knobs vary:
//!
//! * how a Capstone `(mnemonic, op_str)` pair converts to the optimizer IR
//!   (the AArch64 Capstone bridge vs. `x86_ir_from_mnemonic`), and
//! * the per-instruction liveness rule applied to a decoded instruction.
//!
//! [`scan_flags_live`] and [`scan_regs_live`] own the shared scanning discipline
//! once — including the soundness default that an *un-analyzable* suffix keeps
//! everything live — taking those two knobs as closures. On top of them this
//! module supplies the per-architecture wiring (the Capstone→IR decoders and the
//! fall-through suffix resolution) and exposes one small section-level entry
//! point per (architecture, scanned state): [`aarch64_downstream_flags_live`],
//! [`aarch64_downstream_regs_live`], [`x86_downstream_flags_live`], and
//! [`x86_downstream_regs_live`]. That wiring used to be copy-pasted in the CLI
//! binary root, out of reach of library tests; consolidating it here keeps every
//! downstream-liveness decision — and its soundness default — in one place.
//!
//! The per-instruction liveness primitives themselves live next door in
//! [`super::live_out`] (`aarch64_reg_downstream_liveness`,
//! `x86_reg_downstream_liveness`, `flags_read_before_overwrite_after_window`).

use capstone::prelude::*;

use super::live_out::DownstreamRegLiveness;
use crate::capstone_bridge::{ConvertOutcome, convert_capstone_op};
use crate::elf_patcher::{AddressWindow, DetectedArch, ElfPatcher, TextSection};
use crate::ir::{Instruction, Register};
use crate::isa::x86::{X86Instruction, X86Register};
use crate::isa::{FlagsAnalysis, RegisterType, X86_32, X86_64};
use crate::parser::x86::x86_ir_from_mnemonic;
use crate::semantics::live_out::RegisterSet;

/// One decoded step of a downstream suffix scan — the caller's `decode` closure
/// maps a Capstone `(mnemonic, op_str)` pair into one of these.
pub enum ScanStep<I> {
    /// An instruction the optimizer IR can reason about.
    Decoded(I),
    /// A no-op with no observable reads or writes; stepped over.
    Skipped,
    /// An instruction we cannot reason about (unsupported by the IR, a decode
    /// failure, or otherwise opaque). Forces the conservative "all live"
    /// default: the scan can no longer prove anything downstream is dead.
    Opaque,
}

/// Scan the fall-through suffix `bytes` (disassembled with `cs`, starting at
/// `start_addr`) and decide whether the architecture's condition flags are
/// *live* — i.e. some later instruction may read them before they are
/// overwritten.
///
/// Returns `true` (flags live) conservatively whenever the scan cannot prove
/// they are dead: an empty/undecodable suffix, an [`ScanStep::Opaque`]
/// instruction, a terminator, or reaching the end of the analyzable bytes with
/// no flag-writing instruction seen. Returns `false` only when a decoded
/// instruction is proven to overwrite the flags before any read.
///
/// The three policy closures decode over a decoded instruction `I`:
/// * `reads_flags` — does it read the flags before overwriting them?
/// * `modifies_flags` — does it (fully) overwrite the flags?
/// * `is_terminator` — does it hand control out of the linear suffix?
pub fn scan_flags_live<I>(
    cs: &Capstone,
    bytes: &[u8],
    start_addr: u64,
    mut decode: impl FnMut(&str, &str) -> ScanStep<I>,
    reads_flags: impl Fn(&I) -> bool,
    modifies_flags: impl Fn(&I) -> bool,
    is_terminator: impl Fn(&I) -> bool,
) -> bool {
    if bytes.is_empty() {
        return true;
    }

    let mut remaining = bytes;
    let mut address = start_addr;

    while !remaining.is_empty() {
        let Ok(instructions) = cs.disasm_count(remaining, address, 1) else {
            return true;
        };
        let Some(instruction) = instructions.iter().next() else {
            return true;
        };
        let instruction_len = instruction.bytes().len();
        if instruction_len == 0 || instruction_len > remaining.len() {
            return true;
        }

        let mnemonic = instruction.mnemonic().unwrap_or("");
        let op_str = instruction.op_str().unwrap_or("");
        match decode(mnemonic, op_str) {
            ScanStep::Decoded(instr) => {
                if reads_flags(&instr) {
                    return true;
                }
                if modifies_flags(&instr) {
                    return false;
                }
                if is_terminator(&instr) {
                    return true;
                }
            }
            ScanStep::Skipped => {}
            ScanStep::Opaque => return true,
        }

        remaining = &remaining[instruction_len..];
        address += instruction_len as u64;
    }

    false
}

/// Compute the subset of `candidates` (registers the window writes) that are
/// provably *live* in the fall-through suffix `bytes`.
///
/// **Soundness discipline.** A candidate register stays live unless the scan can
/// prove it dead. A candidate `R` is dropped only when the first instruction
/// mentioning it fully overwrites it before reading it
/// ([`DownstreamRegLiveness::Dead`]). Every other situation keeps `R` live: a
/// read before overwrite ([`DownstreamRegLiveness::Read`]), a terminator, an
/// [`ScanStep::Opaque`] instruction, an undecodable byte, or reaching the end
/// of the analyzable suffix with the candidate still undecided.
///
/// [`ScanStep::Skipped`] instructions neither read nor write and are stepped
/// over.
pub fn scan_regs_live<R, I>(
    cs: &Capstone,
    bytes: &[u8],
    start_addr: u64,
    candidates: &RegisterSet<R>,
    mut decode: impl FnMut(&str, &str) -> ScanStep<I>,
    is_terminator: impl Fn(&I) -> bool,
    reg_liveness: impl Fn(R, &I) -> DownstreamRegLiveness,
) -> RegisterSet<R>
where
    R: RegisterType,
{
    // Registers not yet proven dead. We start with everything the window wrote
    // and remove a register only on a provable full overwrite.
    let mut undecided: Vec<R> = candidates.iter().copied().collect();
    let mut live = RegisterSet::<R>::empty();

    if undecided.is_empty() {
        return live;
    }

    // Pins every still-undecided candidate live and returns.
    macro_rules! pin_all_remaining_live {
        () => {{
            for &reg in &undecided {
                live.add(reg);
            }
            return live;
        }};
    }

    if bytes.is_empty() {
        pin_all_remaining_live!();
    }

    let mut remaining = bytes;
    let mut address = start_addr;

    while !remaining.is_empty() && !undecided.is_empty() {
        let Ok(instructions) = cs.disasm_count(remaining, address, 1) else {
            pin_all_remaining_live!();
        };
        let Some(instruction) = instructions.iter().next() else {
            pin_all_remaining_live!();
        };
        let instruction_len = instruction.bytes().len();
        if instruction_len == 0 || instruction_len > remaining.len() {
            pin_all_remaining_live!();
        }

        let mnemonic = instruction.mnemonic().unwrap_or("");
        let op_str = instruction.op_str().unwrap_or("");
        match decode(mnemonic, op_str) {
            ScanStep::Decoded(instr) => {
                if is_terminator(&instr) {
                    // Control leaves the window; any window-written register may
                    // be observed downstream or across the call/ret ABI.
                    pin_all_remaining_live!();
                }
                undecided.retain(|&reg| match reg_liveness(reg, &instr) {
                    DownstreamRegLiveness::Read => {
                        live.add(reg);
                        false
                    }
                    DownstreamRegLiveness::Dead => false,
                    DownstreamRegLiveness::Uncertain => true,
                });
            }
            ScanStep::Skipped => {}
            ScanStep::Opaque => pin_all_remaining_live!(),
        }

        remaining = &remaining[instruction_len..];
        address += instruction_len as u64;
    }

    // Reached the end of the analyzable suffix without resolving these
    // candidates: control falls through to whatever lies past the analyzed
    // bytes, so keep them live.
    pin_all_remaining_live!();
}

// ---------------------------------------------------------------------------
// Per-architecture wiring. The scanners above own the shared discipline; the
// functions below supply the two knobs (Capstone→IR decode, per-instruction
// rule), resolve the fall-through suffix from the ELF section, and expose one
// small section-level entry point per (architecture, scanned state). These used
// to live in the CLI binary root, out of reach of library tests; keeping them
// here co-locates all downstream-liveness logic in one module.
// ---------------------------------------------------------------------------

/// Resolve the in-section fall-through suffix after an optimization window
/// ending at `end_addr`. `None` means there is no analyzable suffix — the
/// window already reaches the section end, or the bytes are unavailable — in
/// which case downstream liveness is unknown and the caller keeps every
/// candidate live (the conservative default). The section-level entry points
/// below all funnel through here rather than repeating the suffix math.
fn fall_through_suffix(
    patcher: &ElfPatcher,
    section: &TextSection,
    end_addr: u64,
) -> Option<Vec<u8>> {
    let section_end = section.virtual_addr + section.size;
    if end_addr >= section_end {
        return None;
    }
    let suffix_window = AddressWindow {
        start: end_addr,
        end: section_end,
    };
    patcher.get_instructions_in_window(&suffix_window).ok()
}

/// Decode one AArch64 Capstone `(mnemonic, op_str)` pair into a downstream scan
/// step, reusing the shared Capstone→IR bridge so the fall-through scan honors
/// exactly the same supported-mnemonic set as the optimizer.
fn aarch64_scan_step(mnemonic: &str, op_str: &str) -> ScanStep<Instruction> {
    match convert_capstone_op(mnemonic, op_str) {
        ConvertOutcome::Instruction(instr) => ScanStep::Decoded(instr),
        ConvertOutcome::Skip => ScanStep::Skipped,
        ConvertOutcome::Unsupported(_) => ScanStep::Opaque,
    }
}

fn aarch64_downstream_flags_live_from_bytes(cs: &Capstone, bytes: &[u8], start_addr: u64) -> bool {
    scan_flags_live(
        cs,
        bytes,
        start_addr,
        aarch64_scan_step,
        |instr: &Instruction| {
            super::live_out::flags_read_before_overwrite_after_window(std::slice::from_ref(instr))
        },
        |instr: &Instruction| instr.modifies_flags(),
        |instr: &Instruction| instr.is_terminator(),
    )
}

fn aarch64_downstream_regs_live_from_bytes(
    cs: &Capstone,
    bytes: &[u8],
    start_addr: u64,
    candidates: &RegisterSet<Register>,
) -> RegisterSet<Register> {
    scan_regs_live(
        cs,
        bytes,
        start_addr,
        candidates,
        aarch64_scan_step,
        |instr: &Instruction| instr.is_terminator(),
        |reg: Register, instr: &Instruction| {
            super::live_out::aarch64_reg_downstream_liveness(reg, std::slice::from_ref(instr))
        },
    )
}

/// Decode one x86 Capstone `(mnemonic, op_str)` pair into a downstream scan
/// step. `nop` carries no observable state and is stepped over; anything the
/// shared x86 IR does not model (including `call`/`ret`) is opaque and pins the
/// remaining state live.
fn x86_scan_step(mnemonic: &str, op_str: &str) -> ScanStep<X86Instruction> {
    match x86_ir_from_mnemonic(mnemonic, op_str) {
        Ok(Some(instr)) => ScanStep::Decoded(instr),
        Ok(None) if mnemonic.eq_ignore_ascii_case("nop") => ScanStep::Skipped,
        Ok(None) => ScanStep::Opaque,
        Err(_) => ScanStep::Opaque,
    }
}

fn x86_downstream_flags_live_from_bytes<I>(cs: &Capstone, bytes: &[u8], start_addr: u64) -> bool
where
    I: FlagsAnalysis<X86Instruction>,
{
    scan_flags_live(
        cs,
        bytes,
        start_addr,
        x86_scan_step,
        |instr: &X86Instruction| <I as FlagsAnalysis<X86Instruction>>::reads_flags(instr),
        |instr: &X86Instruction| <I as FlagsAnalysis<X86Instruction>>::modifies_flags(instr),
        |instr: &X86Instruction| instr.is_terminator(),
    )
}

fn x86_downstream_regs_live_from_bytes(
    cs: &Capstone,
    bytes: &[u8],
    start_addr: u64,
    candidates: &RegisterSet<X86Register>,
) -> RegisterSet<X86Register> {
    scan_regs_live(
        cs,
        bytes,
        start_addr,
        candidates,
        x86_scan_step,
        |instr: &X86Instruction| instr.is_terminator(),
        |reg: X86Register, instr: &X86Instruction| {
            super::live_out::x86_reg_downstream_liveness(reg, std::slice::from_ref(instr))
        },
    )
}

/// Whether the AArch64 condition flags (NZCV) may be read downstream of a window
/// ending at `end_addr`. Returns the conservative `true` whenever the
/// fall-through suffix is unavailable or the window already reaches the section
/// end; otherwise scans the suffix and returns `false` only when a decoded
/// instruction is proven to overwrite the flags before any read.
pub fn aarch64_downstream_flags_live(
    patcher: &ElfPatcher,
    section: &TextSection,
    end_addr: u64,
    cs: &Capstone,
) -> bool {
    match fall_through_suffix(patcher, section, end_addr) {
        Some(bytes) => aarch64_downstream_flags_live_from_bytes(cs, &bytes, end_addr),
        None => true,
    }
}

/// The subset of `candidates` (registers the AArch64 window writes) that are
/// provably live downstream of the window. Returns every candidate live when the
/// suffix is unavailable or the window already reaches the section end (issue
/// #621's conservative default).
pub fn aarch64_downstream_regs_live(
    patcher: &ElfPatcher,
    section: &TextSection,
    end_addr: u64,
    cs: &Capstone,
    candidates: &RegisterSet<Register>,
) -> RegisterSet<Register> {
    match fall_through_suffix(patcher, section, end_addr) {
        Some(bytes) => aarch64_downstream_regs_live_from_bytes(cs, &bytes, end_addr, candidates),
        None => candidates.clone(),
    }
}

/// Whether the x86 condition flags (EFLAGS) may be read downstream of a window
/// ending at `end_addr`. Dispatches to the mode-specific flag analysis; an
/// unavailable suffix and non-x86 `arch` values return the conservative `true`.
pub fn x86_downstream_flags_live(
    arch: DetectedArch,
    patcher: &ElfPatcher,
    section: &TextSection,
    end_addr: u64,
    cs: &Capstone,
) -> bool {
    let Some(bytes) = fall_through_suffix(patcher, section, end_addr) else {
        return true;
    };

    match arch {
        DetectedArch::X86_64 => {
            x86_downstream_flags_live_from_bytes::<X86_64>(cs, &bytes, end_addr)
        }
        DetectedArch::X86_32 => {
            x86_downstream_flags_live_from_bytes::<X86_32>(cs, &bytes, end_addr)
        }
        DetectedArch::Aarch64 => true,
    }
}

/// The subset of `candidates` (registers the x86 window writes) that are provably
/// live downstream. Register liveness is width-independent, so the
/// mode-configured `cs` drives the correct x86-32/x86-64 disassembly; an
/// unavailable suffix and non-x86 `arch` values return every candidate live.
pub fn x86_downstream_regs_live(
    arch: DetectedArch,
    patcher: &ElfPatcher,
    section: &TextSection,
    end_addr: u64,
    cs: &Capstone,
    candidates: &RegisterSet<X86Register>,
) -> RegisterSet<X86Register> {
    let Some(bytes) = fall_through_suffix(patcher, section, end_addr) else {
        return candidates.clone();
    };

    match arch {
        DetectedArch::X86_64 | DetectedArch::X86_32 => {
            x86_downstream_regs_live_from_bytes(cs, &bytes, end_addr, candidates)
        }
        DetectedArch::Aarch64 => candidates.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::AArch64Assembler;
    use crate::assembler::x86::X86Assembler;
    use crate::ir::{Condition, Instruction, LabelId, Operand, Register};
    use crate::isa::x86::{X86Instruction, X86Register};
    use crate::test_utils::{TempFile, build_minimal_aarch64_elf, build_minimal_x86_64_elf};

    /// AArch64 `NOP` (`0xD503201F`, little-endian). Decodes to exactly one
    /// instruction so the scripted `decode` closure is invoked once per copy.
    const AARCH64_NOP: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5];

    fn aarch64_capstone() -> Capstone {
        Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .build()
            .expect("test capstone should build")
    }

    fn nops(count: usize) -> Vec<u8> {
        AARCH64_NOP.repeat(count)
    }

    /// A synthetic decoded instruction whose flag/terminator behavior the test
    /// dictates directly, decoupling the scan's control flow from any real IR
    /// converter.
    #[derive(Clone)]
    struct FakeInsn {
        reads_flags: bool,
        modifies_flags: bool,
        terminator: bool,
        read_regs: Vec<Register>,
        dead_regs: Vec<Register>,
    }

    impl FakeInsn {
        fn inert() -> Self {
            FakeInsn {
                reads_flags: false,
                modifies_flags: false,
                terminator: false,
                read_regs: Vec::new(),
                dead_regs: Vec::new(),
            }
        }
    }

    /// Turn a fixed script of steps into a `decode` closure that yields one per
    /// call, in order.
    fn scripted(steps: Vec<ScanStep<FakeInsn>>) -> impl FnMut(&str, &str) -> ScanStep<FakeInsn> {
        let mut it = steps.into_iter();
        move |_mnemonic, _op_str| it.next().expect("decode called more times than scripted")
    }

    fn flags_scan(bytes: &[u8], steps: Vec<ScanStep<FakeInsn>>) -> bool {
        let cs = aarch64_capstone();
        scan_flags_live(
            &cs,
            bytes,
            0x1000,
            scripted(steps),
            |i: &FakeInsn| i.reads_flags,
            |i: &FakeInsn| i.modifies_flags,
            |i: &FakeInsn| i.terminator,
        )
    }

    #[test]
    fn flags_live_for_empty_suffix() {
        assert!(flags_scan(&[], vec![]));
    }

    #[test]
    fn flags_live_when_instruction_reads_flags() {
        let step = ScanStep::Decoded(FakeInsn {
            reads_flags: true,
            ..FakeInsn::inert()
        });
        assert!(flags_scan(&nops(1), vec![step]));
    }

    #[test]
    fn flags_dead_when_instruction_modifies_flags_before_read() {
        let step = ScanStep::Decoded(FakeInsn {
            modifies_flags: true,
            ..FakeInsn::inert()
        });
        assert!(!flags_scan(&nops(1), vec![step]));
    }

    #[test]
    fn flags_live_on_terminator() {
        let step = ScanStep::Decoded(FakeInsn {
            terminator: true,
            ..FakeInsn::inert()
        });
        assert!(flags_scan(&nops(1), vec![step]));
    }

    #[test]
    fn flags_live_on_opaque_instruction() {
        assert!(flags_scan(&nops(1), vec![ScanStep::Opaque]));
    }

    #[test]
    fn flags_dead_when_suffix_clean_to_end() {
        // A single non-flag, non-terminator instruction then the suffix ends:
        // nothing can read the flags, so they are dead.
        assert!(!flags_scan(
            &nops(1),
            vec![ScanStep::Decoded(FakeInsn::inert())]
        ));
    }

    #[test]
    fn flags_scan_steps_over_skipped() {
        // First step is a NOP (Skipped); the second overwrites the flags.
        let steps = vec![
            ScanStep::Skipped,
            ScanStep::Decoded(FakeInsn {
                modifies_flags: true,
                ..FakeInsn::inert()
            }),
        ];
        assert!(!flags_scan(&nops(2), steps));
    }

    fn regset(regs: &[Register]) -> RegisterSet<Register> {
        RegisterSet::from_registers(regs.to_vec())
    }

    fn regs_scan(
        bytes: &[u8],
        candidates: &[Register],
        steps: Vec<ScanStep<FakeInsn>>,
    ) -> RegisterSet<Register> {
        let cs = aarch64_capstone();
        scan_regs_live(
            &cs,
            bytes,
            0x1000,
            &regset(candidates),
            scripted(steps),
            |i: &FakeInsn| i.terminator,
            |reg: Register, i: &FakeInsn| {
                if i.read_regs.contains(&reg) {
                    DownstreamRegLiveness::Read
                } else if i.dead_regs.contains(&reg) {
                    DownstreamRegLiveness::Dead
                } else {
                    DownstreamRegLiveness::Uncertain
                }
            },
        )
    }

    fn sorted(set: &RegisterSet<Register>) -> Vec<Register> {
        let mut regs: Vec<Register> = set.iter().copied().collect();
        regs.sort_by_key(|r| r.index());
        regs
    }

    #[test]
    fn regs_empty_when_no_candidates() {
        // Even with a modifying suffix, an empty candidate set stays empty.
        let out = regs_scan(&nops(1), &[], vec![ScanStep::Opaque]);
        assert!(out.is_empty());
    }

    #[test]
    fn regs_pin_all_on_empty_suffix() {
        let out = regs_scan(&[], &[Register::X0, Register::X1], vec![]);
        assert_eq!(sorted(&out), vec![Register::X0, Register::X1]);
    }

    #[test]
    fn regs_pin_all_on_terminator() {
        let step = ScanStep::Decoded(FakeInsn {
            terminator: true,
            ..FakeInsn::inert()
        });
        let out = regs_scan(&nops(1), &[Register::X0, Register::X1], vec![step]);
        assert_eq!(sorted(&out), vec![Register::X0, Register::X1]);
    }

    #[test]
    fn regs_pin_all_on_opaque() {
        let out = regs_scan(
            &nops(1),
            &[Register::X0, Register::X1],
            vec![ScanStep::Opaque],
        );
        assert_eq!(sorted(&out), vec![Register::X0, Register::X1]);
    }

    #[test]
    fn regs_classify_read_dead_and_uncertain() {
        // X0 read (live), X1 fully overwritten (dead), X2 undecided → pinned
        // live when the suffix ends.
        let step = ScanStep::Decoded(FakeInsn {
            read_regs: vec![Register::X0],
            dead_regs: vec![Register::X1],
            ..FakeInsn::inert()
        });
        let out = regs_scan(
            &nops(1),
            &[Register::X0, Register::X1, Register::X2],
            vec![step],
        );
        assert_eq!(sorted(&out), vec![Register::X0, Register::X2]);
    }

    // ---- Section-level entry points (the deep public interface) ----

    fn assemble_aarch64_test_bytes(instructions: &[Instruction]) -> Vec<u8> {
        AArch64Assembler::new()
            .assemble_instructions(instructions, 0x1000)
            .expect("test instruction should assemble")
    }

    fn assemble_x86_64_test_bytes(instructions: &[X86Instruction]) -> Vec<u8> {
        X86Assembler::new_64()
            .assemble_instructions(instructions)
            .expect("test instruction should assemble")
    }

    fn aarch64_test_capstone() -> Capstone {
        Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("test capstone should build")
    }

    fn x86_64_test_capstone() -> Capstone {
        Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("test capstone should build")
    }

    /// Materialize `elf` to a temp file and return its patcher plus the single
    /// `.text` section. The `TempFile` is returned so the caller keeps the
    /// backing file alive for the patcher's lifetime.
    fn patcher_with_text(elf: &[u8]) -> (TempFile, ElfPatcher, TextSection) {
        let file = TempFile::new_bytes("s11-downstream-section", "elf", elf);
        let patcher = ElfPatcher::new(file.path()).expect("synthetic ELF should parse");
        let section = patcher
            .get_text_sections()
            .expect("ELF should expose an executable section")
            .into_iter()
            .next()
            .expect("minimal ELF should contain .text");
        (file, patcher, section)
    }

    #[test]
    fn aarch64_flags_live_defaults_conservative_at_section_end() {
        // The window covers the whole section, so there is no analyzable
        // fall-through suffix and the flags stay conservatively live.
        let text = assemble_aarch64_test_bytes(&[Instruction::Add {
            rd: Register::X1,
            rn: Register::X2,
            rm: Operand::Immediate(1),
        }]);
        let (_file, patcher, section) =
            patcher_with_text(&build_minimal_aarch64_elf(&text, 0x1000));
        let cs = aarch64_test_capstone();
        let end = section.virtual_addr + section.size;
        assert!(aarch64_downstream_flags_live(&patcher, &section, end, &cs));
    }

    #[test]
    fn aarch64_flags_dead_when_suffix_proves_them_dead() {
        // Window is the empty prefix; the whole section is the fall-through
        // suffix. A lone non-flag ADD then the section ends, so nothing can
        // read the flags: they are dead.
        let text = assemble_aarch64_test_bytes(&[Instruction::Add {
            rd: Register::X1,
            rn: Register::X2,
            rm: Operand::Immediate(1),
        }]);
        let (_file, patcher, section) =
            patcher_with_text(&build_minimal_aarch64_elf(&text, 0x1000));
        let cs = aarch64_test_capstone();
        assert!(!aarch64_downstream_flags_live(
            &patcher,
            &section,
            section.virtual_addr,
            &cs
        ));
    }

    #[test]
    fn aarch64_regs_default_all_live_at_section_end() {
        let text = assemble_aarch64_test_bytes(&[Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }]);
        let (_file, patcher, section) =
            patcher_with_text(&build_minimal_aarch64_elf(&text, 0x1000));
        let cs = aarch64_test_capstone();
        let candidates = RegisterSet::from_registers(vec![Register::X0]);
        let end = section.virtual_addr + section.size;
        let live = aarch64_downstream_regs_live(&patcher, &section, end, &cs, &candidates);
        assert!(live.contains(Register::X0));
    }

    #[test]
    fn aarch64_regs_dead_when_suffix_fully_overwrites() {
        // Suffix `mov x0, x1` fully overwrites X0 before any read → dead.
        let text = assemble_aarch64_test_bytes(&[Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }]);
        let (_file, patcher, section) =
            patcher_with_text(&build_minimal_aarch64_elf(&text, 0x1000));
        let cs = aarch64_test_capstone();
        let candidates = RegisterSet::from_registers(vec![Register::X0]);
        let live = aarch64_downstream_regs_live(
            &patcher,
            &section,
            section.virtual_addr,
            &cs,
            &candidates,
        );
        assert!(!live.contains(Register::X0));
    }

    #[test]
    fn x86_flags_live_defaults_conservative_at_section_end() {
        let text = assemble_x86_64_test_bytes(&[X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }]);
        let (_file, patcher, section) = patcher_with_text(&build_minimal_x86_64_elf(&text, 0x1000));
        let cs = x86_64_test_capstone();
        let end = section.virtual_addr + section.size;
        assert!(x86_downstream_flags_live(
            DetectedArch::X86_64,
            &patcher,
            &section,
            end,
            &cs
        ));
    }

    #[test]
    fn x86_flags_dead_when_suffix_proves_them_dead() {
        // The whole section is the suffix: a lone non-flag `mov rax, 0` then the
        // section ends, so the flags are dead.
        let text = assemble_x86_64_test_bytes(&[X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }]);
        let (_file, patcher, section) = patcher_with_text(&build_minimal_x86_64_elf(&text, 0x1000));
        let cs = x86_64_test_capstone();
        assert!(!x86_downstream_flags_live(
            DetectedArch::X86_64,
            &patcher,
            &section,
            section.virtual_addr,
            &cs
        ));
    }

    #[test]
    fn x86_regs_default_all_live_at_section_end() {
        let text = assemble_x86_64_test_bytes(&[X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }]);
        let (_file, patcher, section) = patcher_with_text(&build_minimal_x86_64_elf(&text, 0x1000));
        let cs = x86_64_test_capstone();
        let candidates = RegisterSet::from_registers(vec![X86Register::RAX]);
        let end = section.virtual_addr + section.size;
        let live = x86_downstream_regs_live(
            DetectedArch::X86_64,
            &patcher,
            &section,
            end,
            &cs,
            &candidates,
        );
        assert!(live.contains(X86Register::RAX));
    }

    #[test]
    fn x86_regs_dead_when_suffix_fully_overwrites() {
        // Suffix `mov rax, 0` is a full-register write before any read → dead.
        let text = assemble_x86_64_test_bytes(&[X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }]);
        let (_file, patcher, section) = patcher_with_text(&build_minimal_x86_64_elf(&text, 0x1000));
        let cs = x86_64_test_capstone();
        let candidates = RegisterSet::from_registers(vec![X86Register::RAX]);
        let live = x86_downstream_regs_live(
            DetectedArch::X86_64,
            &patcher,
            &section,
            section.virtual_addr,
            &cs,
            &candidates,
        );
        assert!(!live.contains(X86Register::RAX));
    }

    // ---- Byte-level scanner characterization (migrated from the CLI binary) ----

    #[test]
    fn downstream_flags_live_scan_marks_dead_when_first_flag_event_writes() {
        let bytes = assemble_aarch64_test_bytes(&[
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Immediate(0),
            },
            Instruction::Csel {
                rd: Register::X1,
                rn: Register::X2,
                rm: Register::X3,
                cond: Condition::EQ,
            },
        ]);
        let cs = aarch64_test_capstone();

        assert!(!aarch64_downstream_flags_live_from_bytes(
            &cs, &bytes, 0x1000
        ));
    }

    #[test]
    fn downstream_flags_live_scan_marks_live_when_first_flag_event_reads() {
        let bytes = assemble_aarch64_test_bytes(&[Instruction::Csel {
            rd: Register::X1,
            rn: Register::X2,
            rm: Register::X3,
            cond: Condition::EQ,
        }]);
        let cs = aarch64_test_capstone();

        assert!(aarch64_downstream_flags_live_from_bytes(
            &cs, &bytes, 0x1000
        ));
    }

    #[test]
    fn downstream_flags_live_scan_marks_dead_for_known_non_flag_suffix() {
        let bytes = assemble_aarch64_test_bytes(&[Instruction::Add {
            rd: Register::X1,
            rn: Register::X2,
            rm: Operand::Immediate(1),
        }]);
        let cs = aarch64_test_capstone();

        assert!(!aarch64_downstream_flags_live_from_bytes(
            &cs, &bytes, 0x1000
        ));
    }

    #[test]
    fn downstream_flags_live_scan_is_conservative_for_unknown_context() {
        let cs = aarch64_test_capstone();

        assert!(aarch64_downstream_flags_live_from_bytes(&cs, &[], 0x1000));
        assert!(aarch64_downstream_flags_live_from_bytes(
            &cs,
            &[0xff],
            0x1000
        ));
        // LDR literal decodes in Capstone but is intentionally unsupported by
        // the AArch64 optimization IR parser.
        assert!(aarch64_downstream_flags_live_from_bytes(
            &cs,
            &[0x00, 0x00, 0x00, 0x58],
            0x1000
        ));
    }

    #[test]
    fn downstream_flags_live_scan_is_conservative_for_unanalysed_branch() {
        let bytes = assemble_aarch64_test_bytes(&[Instruction::B {
            target: LabelId(0x1000),
        }]);
        let cs = aarch64_test_capstone();

        assert!(aarch64_downstream_flags_live_from_bytes(
            &cs, &bytes, 0x1000
        ));
    }

    #[test]
    fn x86_downstream_flags_live_scan_marks_live_when_first_flag_event_reads() {
        use crate::isa::x86::X86Condition;

        let bytes = assemble_x86_64_test_bytes(&[X86Instruction::Jcc {
            cond: X86Condition::E,
        }]);
        let cs = x86_64_test_capstone();

        assert!(x86_downstream_flags_live_from_bytes::<X86_64>(
            &cs, &bytes, 0x1000
        ));
    }

    #[test]
    fn x86_downstream_flags_live_scan_marks_dead_when_first_flag_event_writes() {
        let bytes = assemble_x86_64_test_bytes(&[
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
        ]);
        let cs = x86_64_test_capstone();

        assert!(!x86_downstream_flags_live_from_bytes::<X86_64>(
            &cs, &bytes, 0x1000
        ));
    }

    #[test]
    fn x86_downstream_flags_live_scan_marks_dead_for_known_non_flag_suffix() {
        let bytes = assemble_x86_64_test_bytes(&[X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }]);
        let cs = x86_64_test_capstone();

        assert!(!x86_downstream_flags_live_from_bytes::<X86_64>(
            &cs, &bytes, 0x1000
        ));
    }

    #[test]
    fn x86_downstream_flags_live_scan_is_conservative_for_unknown_context() {
        let cs = x86_64_test_capstone();

        assert!(x86_downstream_flags_live_from_bytes::<X86_64>(
            &cs,
            &[],
            0x1000
        ));
        assert!(x86_downstream_flags_live_from_bytes::<X86_64>(
            &cs,
            &[0xff],
            0x1000
        ));
        assert!(x86_downstream_flags_live_from_bytes::<X86_64>(
            &cs,
            &[0xc3],
            0x1000
        ));
    }

    fn x86_64_regset(regs: &[X86Register]) -> RegisterSet<X86Register> {
        RegisterSet::from_registers(regs.to_vec())
    }

    fn aarch64_regset(regs: &[Register]) -> RegisterSet<Register> {
        RegisterSet::from_registers(regs.to_vec())
    }

    #[test]
    fn downstream_regs_live_scan_marks_dead_when_later_full_overwrite_precedes_any_read() {
        // Window wrote X0. Suffix `mov x0, x1` fully overwrites x0 before any
        // read, so X0 is dead/optimizable.
        let bytes = assemble_aarch64_test_bytes(&[Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }]);
        let cs = aarch64_test_capstone();
        let live = aarch64_downstream_regs_live_from_bytes(
            &cs,
            &bytes,
            0x1000,
            &aarch64_regset(&[Register::X0]),
        );
        assert!(
            !live.contains(Register::X0),
            "x0 fully overwritten before any read must be dropped from live-out"
        );
    }

    #[test]
    fn downstream_regs_live_scan_marks_live_when_read_before_overwrite() {
        // Window wrote RAX. Suffix `add x2, x0, #1` reads x0 before any
        // redefinition — x0 must stay live.
        let bytes = assemble_aarch64_test_bytes(&[Instruction::Add {
            rd: Register::X2,
            rn: Register::X0,
            rm: Operand::Immediate(1),
        }]);
        let cs = aarch64_test_capstone();
        let live = aarch64_downstream_regs_live_from_bytes(
            &cs,
            &bytes,
            0x1000,
            &aarch64_regset(&[Register::X0]),
        );
        assert!(
            live.contains(Register::X0),
            "x0 read before any overwrite must stay live"
        );
    }

    #[test]
    fn downstream_regs_live_scan_conservative_for_unknown_context() {
        let cs = aarch64_test_capstone();
        let candidates = aarch64_regset(&[Register::X0, Register::X1]);

        // Empty suffix → both candidates live.
        let empty = aarch64_downstream_regs_live_from_bytes(&cs, &[], 0x1000, &candidates);
        assert!(empty.contains(Register::X0) && empty.contains(Register::X1));

        // Undisassemblable byte → live.
        let garbage = aarch64_downstream_regs_live_from_bytes(&cs, &[0xff], 0x1000, &candidates);
        assert!(garbage.contains(Register::X0) && garbage.contains(Register::X1));

        // LDR-literal decodes in Capstone but is unsupported by the IR → live.
        let unsupported = aarch64_downstream_regs_live_from_bytes(
            &cs,
            &[0x00, 0x00, 0x00, 0x58],
            0x1000,
            &candidates,
        );
        assert!(unsupported.contains(Register::X0) && unsupported.contains(Register::X1));
    }

    #[test]
    fn downstream_regs_live_scan_marks_live_across_call_ret() {
        let cs = aarch64_test_capstone();
        let candidates = aarch64_regset(&[Register::X0, Register::X1]);

        // `bl #0` is a call terminator → every window register may be
        // observable across the ABI; keep them all live.
        let bl_bytes = assemble_aarch64_test_bytes(&[Instruction::Bl {
            target: LabelId(0x1000),
        }]);
        let across_call =
            aarch64_downstream_regs_live_from_bytes(&cs, &bl_bytes, 0x1000, &candidates);
        assert!(across_call.contains(Register::X0) && across_call.contains(Register::X1));

        // `ret` is a return terminator → same ABI-observable rule.
        let ret_bytes = assemble_aarch64_test_bytes(&[Instruction::Ret { rn: Register::X30 }]);
        let across_ret =
            aarch64_downstream_regs_live_from_bytes(&cs, &ret_bytes, 0x1000, &candidates);
        assert!(across_ret.contains(Register::X0) && across_ret.contains(Register::X1));
    }

    #[test]
    fn x86_partial_write_does_not_kill() {
        // Window wrote RAX. Suffix `mov al, 0` leaves the rest of RAX intact,
        // so the downstream scan must not treat it as a full-register kill.
        let bytes = assemble_x86_64_test_bytes(&[X86Instruction::MovImm {
            rd: X86Register::AL,
            imm: 0,
        }]);
        let cs = x86_64_test_capstone();
        let live = x86_downstream_regs_live_from_bytes(
            &cs,
            &bytes,
            0x1000,
            &x86_64_regset(&[X86Register::RAX]),
        );
        assert!(
            live.contains(X86Register::RAX),
            "an AL write preserves upper RAX bits, so RAX stays live"
        );
    }

    #[test]
    fn x86_downstream_regs_live_scan_marks_live_when_read_before_overwrite() {
        // `add rbx, rax` reads rax before any redefinition → rax stays live.
        let bytes = assemble_x86_64_test_bytes(&[X86Instruction::AddReg {
            rd: X86Register::RBX,
            rs: X86Register::RAX,
        }]);
        let cs = x86_64_test_capstone();
        let live = x86_downstream_regs_live_from_bytes(
            &cs,
            &bytes,
            0x1000,
            &x86_64_regset(&[X86Register::RAX]),
        );
        assert!(live.contains(X86Register::RAX));
    }

    #[test]
    fn x86_downstream_regs_live_scan_conservative_across_call_ret_and_unknown() {
        let cs = x86_64_test_capstone();
        let candidates = x86_64_regset(&[X86Register::RAX]);

        // Empty suffix → live.
        assert!(
            x86_downstream_regs_live_from_bytes(&cs, &[], 0x1000, &candidates)
                .contains(X86Register::RAX)
        );
        // `ret` (0xc3) is not modelled in the x86 IR → unsupported → live.
        assert!(
            x86_downstream_regs_live_from_bytes(&cs, &[0xc3], 0x1000, &candidates)
                .contains(X86Register::RAX)
        );
        // `call rel32` (e8 00 00 00 00) is likewise not modelled → live.
        assert!(
            x86_downstream_regs_live_from_bytes(
                &cs,
                &[0xe8, 0x00, 0x00, 0x00, 0x00],
                0x1000,
                &candidates
            )
            .contains(X86Register::RAX)
        );
    }
}
