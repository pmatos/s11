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
//! Both knobs are supplied by the caller as closures, so this module owns the
//! shared scanning discipline once — including the soundness default that an
//! *un-analyzable* suffix keeps everything live — instead of the four
//! copy-pasted scanners the CLI used to carry.
//!
//! The per-instruction liveness primitives themselves live next door in
//! [`super::live_out`] (`aarch64_reg_downstream_liveness`,
//! `x86_reg_downstream_liveness`, `flags_read_before_overwrite_after_window`).

use capstone::prelude::*;

use super::live_out::DownstreamRegLiveness;
use crate::isa::RegisterType;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Register;

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
}
