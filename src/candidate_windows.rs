//! Candidate-window planning for the whole-binary `--auto` driver (ADR-0009).
//!
//! The driver's entire risk budget is spent in *window selection*: a window
//! rewritten when it should not have been produces a wrong binary, so the rules
//! that split a decoded section into rewritable straight-line runs are the
//! soundness-critical core of ADR-0009 Decision 4/5.
//!
//! Those rules used to live inline in the binary's
//! `find_candidate_windows_with_backend`, interleaved with Capstone iteration
//! and ELF I/O — a shallow arrangement where the state machine could only be
//! exercised by building a full ELF fixture in memory. This module lifts the
//! run-splitting algorithm into a **pure seam**: the caller classifies each
//! decoded instruction into a [`WindowInstruction`] descriptor (Capstone stays
//! in the adapter), and [`plan_candidate_windows`] applies the split rules with
//! no knowledge of Capstone, `ElfPatcher`, or byte layout. Every rule is then a
//! fixture-free unit test.

use crate::elf_patcher::AddressWindow;
use std::collections::HashSet;

/// How a single decoded instruction participates in a straight-line run.
///
/// The adapter collapses the three "close the run and drop this instruction"
/// cases (a call, an x86-64 RIP-relative memory operand, and an unsupported
/// mnemonic) into [`WindowRole::Excluded`]: all three flush the open run at the
/// previous instruction's end without contributing the instruction itself, so
/// the planner treats them identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowRole {
    /// A rewritable body instruction: it starts or extends the current run.
    StraightLine,
    /// A supported control-flow terminator: it closes the run *inclusively*
    /// (held fixed as the run's final instruction), but only when a run is open.
    Terminator,
    /// A call, RIP-relative memory operand, or unsupported instruction: it
    /// closes the open run at the previous instruction's end and is itself
    /// excluded from every window.
    Excluded,
}

/// A decoded instruction reduced to exactly what window planning needs: its
/// start address, its end address (`address + byte length`), and its role.
///
/// Keeping the descriptor this small is the point — the overflow-checked end
/// computation and the Capstone group/operand inspection that produce it belong
/// to the adapter, not to the split algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowInstruction {
    /// The instruction's virtual address.
    pub address: u64,
    /// One past the instruction's last byte (`address + byte length`).
    pub end: u64,
    /// The instruction's role in a straight-line run.
    pub role: WindowRole,
}

impl WindowInstruction {
    /// Convenience constructor used by the adapter and tests.
    pub fn new(address: u64, end: u64, role: WindowRole) -> Self {
        Self { address, end, role }
    }
}

/// Split one section's classified instruction stream into candidate windows.
///
/// `instructions` are the section's decoded instructions in address order;
/// `branch_targets` is the *global* set of direct branch/call target addresses
/// collected across the whole binary (a target in another section can name an
/// address inside this run, so the set must be complete before planning — see
/// ADR-0009 Decision 4/5).
///
/// The rules, applied per instruction:
/// * An instruction whose address is a collected branch target and is not the
///   current run's first instruction closes the run just before it, so the
///   target begins a fresh window (a window may *begin* at a target but must not
///   contain one past its first instruction).
/// * [`WindowRole::StraightLine`] starts or extends the run.
/// * [`WindowRole::Terminator`] closes an open run inclusively; with no open run
///   it produces nothing.
/// * [`WindowRole::Excluded`] closes an open run at the previous instruction's
///   end and is itself dropped.
pub fn plan_candidate_windows(
    instructions: &[WindowInstruction],
    branch_targets: &HashSet<u64>,
) -> Vec<AddressWindow> {
    let mut candidates = Vec::new();
    // The currently open run, tracked as the window it will become. `end` is
    // extended as straight-line/terminator instructions are absorbed.
    let mut run: Option<AddressWindow> = None;

    for insn in instructions {
        // Close the current run just before an interior branch target so the
        // target begins a fresh window. A run whose first instruction *is* the
        // target is left intact — a window may begin at a target.
        let splits_here = run.as_ref().is_some_and(|open| {
            open.start != insn.address && branch_targets.contains(&insn.address)
        });
        if splits_here {
            candidates.push(run.take().expect("run is open when splits_here is true"));
        }

        match insn.role {
            WindowRole::Excluded => {
                if let Some(open) = run.take() {
                    candidates.push(open);
                }
            }
            WindowRole::StraightLine => match run.as_mut() {
                Some(open) => open.end = insn.end,
                None => {
                    run = Some(AddressWindow {
                        start: insn.address,
                        end: insn.end,
                    })
                }
            },
            WindowRole::Terminator => {
                if let Some(mut open) = run.take() {
                    open.end = insn.end;
                    candidates.push(open);
                }
            }
        }
    }

    if let Some(open) = run.take() {
        candidates.push(open);
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sl(address: u64, len: u64) -> WindowInstruction {
        WindowInstruction::new(address, address + len, WindowRole::StraightLine)
    }
    fn term(address: u64, len: u64) -> WindowInstruction {
        WindowInstruction::new(address, address + len, WindowRole::Terminator)
    }
    fn excl(address: u64, len: u64) -> WindowInstruction {
        WindowInstruction::new(address, address + len, WindowRole::Excluded)
    }
    fn targets(addrs: &[u64]) -> HashSet<u64> {
        addrs.iter().copied().collect()
    }
    /// Compare against hand-derived `(start, end)` pairs so the expected values
    /// come from the ADR rules, not from re-running the algorithm.
    fn bounds(windows: &[AddressWindow]) -> Vec<(u64, u64)> {
        windows.iter().map(|w| (w.start, w.end)).collect()
    }

    #[test]
    fn empty_stream_has_no_windows() {
        assert!(plan_candidate_windows(&[], &targets(&[])).is_empty());
    }

    #[test]
    fn contiguous_straight_line_run_is_one_window() {
        // 3 × 4-byte AArch64-style instrs at 0x1000, 0x1004, 0x1008.
        let stream = [sl(0x1000, 4), sl(0x1004, 4), sl(0x1008, 4)];
        assert_eq!(
            bounds(&plan_candidate_windows(&stream, &targets(&[]))),
            vec![(0x1000, 0x100c)],
        );
    }

    #[test]
    fn terminator_closes_the_run_inclusively() {
        // add ...; je +0  ->  the Jcc is held fixed as the window's final insn.
        let stream = [sl(0x1000, 4), term(0x1004, 2)];
        assert_eq!(
            bounds(&plan_candidate_windows(&stream, &targets(&[]))),
            vec![(0x1000, 0x1006)],
        );
    }

    #[test]
    fn lone_terminator_without_a_prefix_yields_no_window() {
        let stream = [term(0x2000, 2)];
        assert!(plan_candidate_windows(&stream, &targets(&[])).is_empty());
    }

    #[test]
    fn excluded_instruction_splits_the_run_and_is_omitted() {
        // Models a call / RIP-relative op / unsupported mnemonic in the middle:
        // the two straight-line halves survive; the excluded insn is in neither.
        let stream = [sl(0x1000, 4), excl(0x1004, 4), sl(0x1008, 4)];
        assert_eq!(
            bounds(&plan_candidate_windows(&stream, &targets(&[]))),
            vec![(0x1000, 0x1004), (0x1008, 0x100c)],
        );
    }

    #[test]
    fn interior_branch_target_starts_a_fresh_window() {
        // 0x1004 is named by some branch: the run must split there so the target
        // begins a window and is never jumped into mid-window.
        let stream = [sl(0x1000, 4), sl(0x1004, 4), sl(0x1008, 4)];
        assert_eq!(
            bounds(&plan_candidate_windows(&stream, &targets(&[0x1004]))),
            vec![(0x1000, 0x1004), (0x1004, 0x100c)],
        );
    }

    #[test]
    fn window_may_begin_at_a_branch_target() {
        // A target that coincides with the run's first instruction does NOT
        // split — the address is fixed and begins the window legitimately.
        let stream = [sl(0x1000, 4), sl(0x1004, 4)];
        assert_eq!(
            bounds(&plan_candidate_windows(&stream, &targets(&[0x1000]))),
            vec![(0x1000, 0x1008)],
        );
    }

    #[test]
    fn terminator_at_an_interior_target_closes_prefix_and_is_dropped() {
        // Ordering subtlety: the pre-split flushes the [0x1000,0x1004) prefix,
        // leaving no open run, so the terminator itself contributes no window.
        let stream = [sl(0x1000, 4), term(0x1004, 4)];
        assert_eq!(
            bounds(&plan_candidate_windows(&stream, &targets(&[0x1004]))),
            vec![(0x1000, 0x1004)],
        );
    }

    #[test]
    fn multiple_runs_separated_by_exclusions_and_terminators() {
        // sl,sl | excl | sl,term | excl | sl  ->  three surviving windows.
        let stream = [
            sl(0x1000, 4),
            sl(0x1004, 4),
            excl(0x1008, 4),
            sl(0x100c, 4),
            term(0x1010, 4),
            excl(0x1014, 4),
            sl(0x1018, 4),
        ];
        assert_eq!(
            bounds(&plan_candidate_windows(&stream, &targets(&[]))),
            vec![(0x1000, 0x1008), (0x100c, 0x1014), (0x1018, 0x101c)],
        );
    }
}
