//! ELF binary superoptimization engine for the `s11 opt` command.
//!
//! This module owns the whole `opt`/`--auto` pipeline: the per-arch
//! [`ElfOptimizationBackend`] hook layer (ADR-0004), candidate-window
//! discovery, the whole-binary auto driver (ADR-0009), the single-window
//! path, and the per-algorithm search runners. It was extracted verbatim
//! from `main.rs`; callers reach it through the entry points re-exported at
//! the crate boundary (`optimize_elf_binary`, `run_auto_optimization`, the
//! `OptimizationOptions` it takes, and the `print_*` reporters shared with
//! the `llm-opt` command).

use capstone::prelude::*;
use std::path::Path;
use std::time::Duration;

use crate::assembler::AArch64Assembler;
use crate::auto_driver::{
    AutoOptimizationAdapter, AutoRunSummary, AutoTermination, AutoWindow, ElfWindowOptimization,
    WindowSearchResult, drive_auto_optimization,
};
use crate::candidate_windows::{
    WindowInstruction, WindowRole, plan_candidate_windows, refuse_windows_with_interior_targets,
};
use crate::capstone_bridge::{ConvertOutcome, convert_capstone_op};
use crate::capstone_bridge_x86::{convert_to_x86_ir, convert_x86_capstone_op_for_optimization};
use crate::capstone_detail::{CapstoneInstructionFacts, inspect_capstone_instruction_detail};
use crate::elf_patcher::{AddressWindow, DetectedArch, ElfPatcher, TextSection};
use crate::ir::instructions::split_terminator;
use crate::ir::{Instruction, Register};
use crate::output_path::{ResolvedOutput, resolve_output_path};
use crate::report;
use crate::search::config::{
    Algorithm, LlmConfig, SearchConfig, SearchMode, StochasticConfig, SymbolicConfig,
};
use crate::search::parallel::{ParallelConfig, run_parallel_search};
use crate::search::{EnumerativeSearch, SearchAlgorithm, StochasticSearch, SymbolicSearch};
use crate::semantics::cost::CostMetric;
#[allow(unused_imports)]
use crate::{
    aarch64_search_inputs, assembler, auto_driver, candidate_windows, capstone_bridge,
    capstone_bridge_x86, capstone_detail, elf_patcher, ir, isa, output_path, parser, search,
    semantics, validation, x86_search_inputs, x86_window_reassembly,
};

pub struct OptimizationOptions {
    pub algorithm: Algorithm,
    pub timeout: Option<Duration>,
    pub cost_metric: CostMetric,
    pub verbose: bool,
    pub beta: f64,
    pub iterations: u64,
    pub seed: Option<u64>,
    pub search_mode: SearchMode,
    pub solver_timeout: Duration,
    // Parallel/Hybrid options
    pub cores: Option<usize>,
    pub no_symbolic: bool,
    // LLM options
    pub llm_max_calls: u32,
    pub llm_model: String,
}

// --- Optimization Function ---

enum OptimizedWindowBytes {
    Patch(Vec<u8>),
    LeaveInputUnchanged,
}

/// Registers proven live downstream of the window, carried per-arch.
///
/// `None` means "no downstream narrowing available" — the consumer falls back
/// to the conservative default (every window-written register is live-out).
/// This is the safe posture for any unanalyzable section (issue #621).
#[derive(Clone, Default)]
enum DownstreamLiveRegs {
    #[default]
    Unknown,
    Aarch64(semantics::live_out::RegisterSet<Register>),
    X86(semantics::live_out::RegisterSet<isa::x86::X86Register>),
}

#[derive(Clone)]
struct OptimizationContext {
    downstream_flags_live: bool,
    /// Registers the window writes that are proven live downstream. The
    /// window's live-out set is narrowed to (written ∩ this) when available;
    /// `Unknown` keeps every written register live (issue #621).
    downstream_live_regs: DownstreamLiveRegs,
}

impl Default for OptimizationContext {
    fn default() -> Self {
        Self {
            downstream_flags_live: true,
            downstream_live_regs: DownstreamLiveRegs::Unknown,
        }
    }
}

// Shared classification seam for candidate discovery and the auto driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateInstructionDisposition {
    StraightLine,
    Terminator,
}

trait ElfOptimizationBackend {
    type Instruction: std::fmt::Display;

    fn arch(&self) -> DetectedArch;

    fn arch_description(&self) -> String {
        format!("{:?}", self.arch())
    }

    fn ir_label(&self) -> &'static str {
        "IR"
    }

    fn disassembler(&self) -> Result<Capstone, Box<dyn std::error::Error>>;

    fn convert_ir(
        &self,
        instructions: &capstone::Instructions,
    ) -> Result<Vec<Self::Instruction>, String>;

    fn classify_candidate_instruction(
        &self,
        instruction: &capstone::Insn<'_>,
    ) -> Result<CandidateInstructionDisposition, String>;

    fn validate_window_ir(&self, ir: &[Self::Instruction]) -> Result<(), String>;

    /// Cost used both by the search and by the auto driver's monotonicity gate.
    /// Routed through `isa::CostModel` so the gate and the search that
    /// produced the candidate can never drift onto different cost models.
    fn sequence_cost(&self, ir: &[Self::Instruction], metric: &CostMetric) -> u64;

    /// Build the per-window `OptimizationContext`, deriving the downstream
    /// flags- and register-liveness from the bytes that follow the window in
    /// the section. The default mirrors the shared flags-only derivation; the
    /// AArch64 and x86 backends override it to also compute the downstream-live
    /// register set over the window's written registers (issue #621).
    fn optimization_context(
        &self,
        _ir: &[Self::Instruction],
        patcher: &ElfPatcher,
        section: &TextSection,
        end_addr: u64,
        cs: &Capstone,
    ) -> OptimizationContext {
        optimization_context_for_backend(self.arch(), patcher, section, end_addr, cs)
    }

    /// Run the selected search. `capstone_instructions` preserves the original
    /// instruction bytes for backends that need encoding metadata; backends
    /// that do not need it can ignore the argument.
    fn run_search(
        &self,
        ir: &[Self::Instruction],
        _capstone_instructions: &capstone::Instructions,
        options: &OptimizationOptions,
        context: OptimizationContext,
    ) -> Result<Option<Vec<Self::Instruction>>, Box<dyn std::error::Error>>;

    fn no_optimization_message(&self) -> &'static str;

    fn assemble_window(
        &self,
        original_ir: &[Self::Instruction],
        final_ir: &[Self::Instruction],
        optimized_found: bool,
        capstone_instructions: &capstone::Instructions,
        original_bytes: &[u8],
        start_addr: u64,
    ) -> Result<OptimizedWindowBytes, Box<dyn std::error::Error>>;
}

struct AArch64OptimizationBackend;

impl ElfOptimizationBackend for AArch64OptimizationBackend {
    type Instruction = Instruction;

    fn arch(&self) -> DetectedArch {
        DetectedArch::Aarch64
    }

    fn disassembler(&self) -> Result<Capstone, Box<dyn std::error::Error>> {
        Ok(Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()?)
    }

    fn convert_ir(
        &self,
        instructions: &capstone::Instructions,
    ) -> Result<Vec<Self::Instruction>, String> {
        convert_to_ir(instructions)
    }

    fn classify_candidate_instruction(
        &self,
        instruction: &capstone::Insn<'_>,
    ) -> Result<CandidateInstructionDisposition, String> {
        let converted = convert_capstone_op_for_optimization(
            instruction.mnemonic().unwrap_or(""),
            instruction.op_str().unwrap_or(""),
            instruction.address(),
        )?;
        Ok(match converted {
            Some(ir) if ir.is_terminator() => CandidateInstructionDisposition::Terminator,
            Some(_) | None => CandidateInstructionDisposition::StraightLine,
        })
    }

    fn validate_window_ir(&self, ir: &[Self::Instruction]) -> Result<(), String> {
        aarch64_search_inputs::validate_basic_block(ir)
    }

    fn sequence_cost(&self, ir: &[Self::Instruction], metric: &CostMetric) -> u64 {
        <isa::AArch64 as isa::CostModel<Instruction>>::sequence_cost(&isa::AArch64, ir, metric)
    }

    fn optimization_context(
        &self,
        ir: &[Self::Instruction],
        patcher: &ElfPatcher,
        section: &TextSection,
        end_addr: u64,
        cs: &Capstone,
    ) -> OptimizationContext {
        // Candidates are the registers the window prefix writes — the same set
        // that becomes the default (all-live) live-out contract. The
        // terminator (held fixed) is not a candidate: its reads are pinned
        // separately by `live_out_for_optimization_prefix`.
        //
        // Soundness gate: the downstream scan only follows the linear
        // fall-through successor. If the window has a held-fixed terminator,
        // the fall-through is not the sole successor (a conditional branch has
        // a branch-taken target; b/br/bl/ret transfer elsewhere), so we must
        // NOT narrow — leave `downstream_live_regs` Unknown (all written live),
        // matching the flags blanket. `live_out_for_optimization_prefix`
        // independently re-applies the same veto as defense in depth.
        let (prefix, terminator) = split_terminator(ir);
        let downstream_live_regs = if terminator.is_some() {
            DownstreamLiveRegs::Unknown
        } else {
            let candidates = validation::live_out::compute_written_registers(prefix);
            DownstreamLiveRegs::Aarch64(validation::downstream::aarch64_downstream_regs_live(
                patcher,
                section,
                end_addr,
                cs,
                &candidates,
            ))
        };
        OptimizationContext {
            downstream_flags_live: validation::downstream::aarch64_downstream_flags_live(
                patcher, section, end_addr, cs,
            ),
            downstream_live_regs,
        }
    }

    fn run_search(
        &self,
        ir: &[Self::Instruction],
        _capstone_instructions: &capstone::Instructions,
        options: &OptimizationOptions,
        context: OptimizationContext,
    ) -> Result<Option<Vec<Self::Instruction>>, Box<dyn std::error::Error>> {
        let downstream_live = match &context.downstream_live_regs {
            DownstreamLiveRegs::Aarch64(set) => Some(set.clone()),
            _ => None,
        };
        run_optimization(ir, options, context.downstream_flags_live, downstream_live)
    }

    fn no_optimization_message(&self) -> &'static str {
        "No optimization found, using original instructions."
    }

    fn assemble_window(
        &self,
        _original_ir: &[Self::Instruction],
        final_ir: &[Self::Instruction],
        _optimized_found: bool,
        _capstone_instructions: &capstone::Instructions,
        _original_bytes: &[u8],
        start_addr: u64,
    ) -> Result<OptimizedWindowBytes, Box<dyn std::error::Error>> {
        let mut assembler = AArch64Assembler::new();
        let assembled_bytes = assembler.assemble_instructions(final_ir, start_addr)?;
        Ok(OptimizedWindowBytes::Patch(assembled_bytes))
    }
}

/// The closed set of architectures the x86 optimization backend can
/// actually handle. Distinct from `DetectedArch` (which also includes
/// `Aarch64`) so the backend's match arms are exhaustive over exactly
/// the two x86 modes — no `unreachable!()` arms for an AArch64 variant
/// that can never reach this code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum X86Arch {
    X86_64,
    X86_32,
}

impl X86Arch {
    fn width(self) -> u32 {
        match self {
            X86Arch::X86_64 => 64,
            X86Arch::X86_32 => 32,
        }
    }

    fn parse_mode(self) -> parser::x86::X86ParseMode {
        match self {
            X86Arch::X86_64 => parser::x86::X86ParseMode::Mode64,
            X86Arch::X86_32 => parser::x86::X86ParseMode::Mode32,
        }
    }
}

impl From<X86Arch> for DetectedArch {
    fn from(arch: X86Arch) -> Self {
        match arch {
            X86Arch::X86_64 => DetectedArch::X86_64,
            X86Arch::X86_32 => DetectedArch::X86_32,
        }
    }
}

impl TryFrom<DetectedArch> for X86Arch {
    type Error = String;

    fn try_from(arch: DetectedArch) -> Result<Self, Self::Error> {
        match arch {
            DetectedArch::X86_64 => Ok(X86Arch::X86_64),
            DetectedArch::X86_32 => Ok(X86Arch::X86_32),
            DetectedArch::Aarch64 => Err("expected x86 binary; got AArch64".to_string()),
        }
    }
}

struct X86OptimizationBackend {
    arch: X86Arch,
}

impl X86OptimizationBackend {
    fn new(arch: X86Arch) -> Self {
        Self { arch }
    }

    fn parse_mode(&self) -> parser::x86::X86ParseMode {
        self.arch.parse_mode()
    }
}

impl ElfOptimizationBackend for X86OptimizationBackend {
    type Instruction = isa::x86::X86Instruction;

    fn arch(&self) -> DetectedArch {
        DetectedArch::from(self.arch)
    }

    fn arch_description(&self) -> String {
        format!("{:?} (width {})", self.arch, self.arch.width())
    }

    fn ir_label(&self) -> &'static str {
        "x86 IR"
    }

    fn disassembler(&self) -> Result<Capstone, Box<dyn std::error::Error>> {
        let mut builder = Capstone::new().x86();
        builder = match self.arch {
            X86Arch::X86_64 => builder.mode(capstone::arch::x86::ArchMode::Mode64),
            X86Arch::X86_32 => builder.mode(capstone::arch::x86::ArchMode::Mode32),
        };
        Ok(builder
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()?)
    }

    fn convert_ir(
        &self,
        instructions: &capstone::Instructions,
    ) -> Result<Vec<Self::Instruction>, String> {
        convert_to_x86_ir(instructions, self.parse_mode())
    }

    fn classify_candidate_instruction(
        &self,
        instruction: &capstone::Insn<'_>,
    ) -> Result<CandidateInstructionDisposition, String> {
        let ir = convert_x86_capstone_op_for_optimization(
            instruction.mnemonic().unwrap_or(""),
            instruction.op_str().unwrap_or(""),
            instruction.address(),
            self.parse_mode(),
        )?;
        Ok(if ir.is_terminator() {
            CandidateInstructionDisposition::Terminator
        } else {
            CandidateInstructionDisposition::StraightLine
        })
    }

    fn validate_window_ir(&self, ir: &[Self::Instruction]) -> Result<(), String> {
        x86_search_inputs::validate_terminator_placement(ir)
    }

    fn sequence_cost(&self, ir: &[Self::Instruction], metric: &CostMetric) -> u64 {
        match self.arch {
            X86Arch::X86_64 => <isa::X86_64 as isa::CostModel<Self::Instruction>>::sequence_cost(
                &isa::X86_64,
                ir,
                metric,
            ),
            X86Arch::X86_32 => <isa::X86_32 as isa::CostModel<Self::Instruction>>::sequence_cost(
                &isa::X86_32,
                ir,
                metric,
            ),
        }
    }

    fn optimization_context(
        &self,
        ir: &[Self::Instruction],
        patcher: &ElfPatcher,
        section: &TextSection,
        end_addr: u64,
        cs: &Capstone,
    ) -> OptimizationContext {
        // Candidates: every register the window writes (the trailing Jcc, if
        // any, has no destination and contributes nothing). This is the same
        // set `x86_live_out_from_target` marks live by default.
        //
        // Soundness gate (same as AArch64): the downstream scan only follows
        // the linear fall-through successor, so a held-fixed terminator (the
        // trailing Jcc, with its unscanned branch-taken target) vetoes
        // narrowing. We leave `downstream_live_regs` Unknown in that case.
        let has_terminator = ir.last().is_some_and(|i| i.is_terminator());
        let downstream_live_regs = if has_terminator {
            DownstreamLiveRegs::Unknown
        } else {
            let candidates = semantics::live_out::RegisterSet::from_registers(
                ir.iter().filter_map(|i| i.destination()).collect(),
            );
            DownstreamLiveRegs::X86(validation::downstream::x86_downstream_regs_live(
                self.arch(),
                patcher,
                section,
                end_addr,
                cs,
                &candidates,
            ))
        };
        OptimizationContext {
            downstream_flags_live: validation::downstream::x86_downstream_flags_live(
                self.arch(),
                patcher,
                section,
                end_addr,
                cs,
            ),
            downstream_live_regs,
        }
    }

    fn run_search(
        &self,
        ir: &[Self::Instruction],
        _capstone_instructions: &capstone::Instructions,
        options: &OptimizationOptions,
        context: OptimizationContext,
    ) -> Result<Option<Vec<Self::Instruction>>, Box<dyn std::error::Error>> {
        let width = self.arch.width();
        let downstream_live = match &context.downstream_live_regs {
            DownstreamLiveRegs::X86(set) => Some(set.clone()),
            _ => None,
        };
        let optimized = match options.algorithm {
            Algorithm::Enumerative => run_x86_enumerative(
                ir,
                width,
                options,
                context.downstream_flags_live,
                downstream_live.as_ref(),
            ),
            Algorithm::Stochastic => run_x86_stochastic(
                ir,
                width,
                options,
                context.downstream_flags_live,
                downstream_live.as_ref(),
            ),
            Algorithm::Symbolic => run_x86_symbolic(
                ir,
                width,
                options,
                context.downstream_flags_live,
                downstream_live.as_ref(),
                // See docs/adr/0010-x86-register-views.md#decision: operand
                // views remain precise through execution, costing, and
                // assembly, so same-count code-size rewrites are safe here.
                true,
            ),
            Algorithm::Hybrid | Algorithm::Llm => {
                // Rejected upstream at the CLI layer; defensive check here
                // in case a programmatic caller bypasses it.
                return Err("hybrid and llm are AArch64-only".into());
            }
        };
        Ok(optimized)
    }

    fn no_optimization_message(&self) -> &'static str {
        "No optimization found; copying the input unchanged."
    }

    fn assemble_window(
        &self,
        original_ir: &[Self::Instruction],
        final_ir: &[Self::Instruction],
        optimized_found: bool,
        capstone_instructions: &capstone::Instructions,
        original_bytes: &[u8],
        _start_addr: u64,
    ) -> Result<OptimizedWindowBytes, Box<dyn std::error::Error>> {
        if !optimized_found {
            // Without a shorter sequence to substitute there is nothing to
            // patch. Round-tripping the original IR through dynasm could emit
            // different bytes than the source compiler, so leave the input
            // untouched.
            return Ok(OptimizedWindowBytes::LeaveInputUnchanged);
        }

        // If the original window ended in a Jcc, the search holds that
        // terminator fixed. Re-encoding it via dynasm would emit a placeholder
        // zero displacement and overwrite the real branch target, so pull the
        // ORIGINAL Jcc bytes out of Capstone and hand them across the reassembly
        // seam. The seam owns the terminator-match refusal and the byte-offset
        // arithmetic; this adapter only extracts the raw Capstone bytes.
        let (_, original_terminator) = crate::ir::instructions::split_terminator_x86(original_ir);
        let pinned_terminator_bytes: Option<Vec<u8>> =
            if let Some(expected_terminator) = original_terminator {
                let last = capstone_instructions
                    .iter()
                    .last()
                    .ok_or("expected non-empty disassembly when peeling terminator")?;
                #[cfg(debug_assertions)]
                {
                    let mn = last.mnemonic().unwrap_or("");
                    let ops = last.op_str().unwrap_or("");
                    let parsed_last = match parser::x86::x86_ir_from_mnemonic(mn, ops) {
                        Ok(Some(instr)) => instr,
                        Ok(None) => panic!(
                            "last Capstone instruction must yield x86 IR when original IR has a Jcc"
                        ),
                        Err(err) => panic!(
                            "last Capstone instruction must parse when original IR has a Jcc: {err}"
                        ),
                    };
                    debug_assert_eq!(
                        parsed_last, *expected_terminator,
                        "peeled x86 Jcc terminator must correspond to the last Capstone instruction"
                    );
                }
                // Only read inside the debug_assertions block above; in a
                // release build that block is compiled out, so keep the
                // binding used or `-D warnings` rejects it as dead.
                #[cfg(not(debug_assertions))]
                let _ = expected_terminator;
                Some(last.bytes().to_vec())
            } else {
                None
            };

        let new_bytes = x86_window_reassembly::reassemble_optimized_x86_window(
            final_ir,
            original_ir,
            pinned_terminator_bytes.as_deref(),
            original_bytes.len(),
            DetectedArch::from(self.arch),
        )?;
        Ok(OptimizedWindowBytes::Patch(new_bytes))
    }
}

#[derive(Debug, Clone)]
struct SectionCandidateWindows {
    /// Which executable section the candidates came from. The auto driver
    /// consumes the windows themselves, so this is currently read only by the
    /// discovery tests that pin per-section behaviour.
    #[cfg_attr(not(test), allow(dead_code))]
    section: TextSection,
    candidates: Vec<AddressWindow>,
    /// Candidate windows this section's discovery pass dropped because an
    /// indirect target (relocation- or pointer-derived) fell in their interior.
    /// The auto driver reads it so a fixpoint is never claimed over coverage
    /// that was silently suppressed (ADR-0009 Decision 5/9).
    indirect_target_refusals: usize,
}

#[cfg(test)]
fn find_candidate_windows(
    patcher: &ElfPatcher,
) -> Result<Vec<SectionCandidateWindows>, Box<dyn std::error::Error>> {
    match patcher.arch() {
        DetectedArch::Aarch64 => {
            find_candidate_windows_with_backend(&AArch64OptimizationBackend, patcher)
        }
        DetectedArch::X86_64 | DetectedArch::X86_32 => find_candidate_windows_with_backend(
            &X86OptimizationBackend::new(X86Arch::try_from(patcher.arch())?),
            patcher,
        ),
    }
}

fn find_candidate_windows_with_backend<B: ElfOptimizationBackend>(
    backend: &B,
    patcher: &ElfPatcher,
) -> Result<Vec<SectionCandidateWindows>, Box<dyn std::error::Error>> {
    find_candidate_windows_with_detail_provider(
        backend,
        patcher,
        inspect_capstone_instruction_detail,
    )
}

fn find_candidate_windows_with_detail_provider<B, F>(
    backend: &B,
    patcher: &ElfPatcher,
    mut inspect_detail: F,
) -> Result<Vec<SectionCandidateWindows>, Box<dyn std::error::Error>>
where
    B: ElfOptimizationBackend,
    F: FnMut(
        &Capstone,
        &capstone::Insn<'_>,
        &str,
    ) -> Result<CapstoneInstructionFacts, Box<dyn std::error::Error>>,
{
    let cs = backend.disassembler()?;
    let indirect_targets = patcher.indirect_control_flow_targets()?;

    // Phase 1: disassemble every executable section's complete-instruction
    // prefix once, fail closed on any partial decode within that prefix, inspect
    // each instruction's detail once, and reduce it to an owned planning
    // descriptor while accumulating every direct branch/call target across the
    // whole binary into one set. The set must be global and complete before any
    // window is built: a branch (backward, or in another section) can name an
    // address inside a run we have not yet seen, so a single forward pass cannot
    // know all targets in time to split correctly (ADR-0009 Decision 4/5).
    let mut decoded_sections = Vec::new();
    let mut branch_targets = std::collections::HashSet::new();

    for section in patcher.get_text_sections()? {
        let raw_section_end = section
            .virtual_addr
            .checked_add(section.size)
            .ok_or_else(|| {
                format!(
                    "executable section '{}' range overflows: start 0x{:x}, size {}",
                    section.name, section.virtual_addr, section.size
                )
            })?;
        let instruction_alignment = backend.arch().instruction_alignment();
        if !section.virtual_addr.is_multiple_of(instruction_alignment) {
            return Err(format!(
                "failed to read executable section '{}' with raw range 0x{:x}-0x{:x}: section start 0x{:x} must be {}-byte aligned for {:?} instructions",
                section.name,
                section.virtual_addr,
                raw_section_end,
                section.virtual_addr,
                instruction_alignment,
                backend.arch(),
            )
            .into());
        }
        let trailing_bytes = section.size % instruction_alignment;
        let disassembly_end = raw_section_end - trailing_bytes;
        if trailing_bytes > 0 {
            println!(
                "{}",
                incomplete_executable_section_tail_log(
                    &section.name,
                    section.virtual_addr,
                    raw_section_end,
                    disassembly_end,
                    instruction_alignment,
                    trailing_bytes,
                )
            );
        }
        if disassembly_end == section.virtual_addr {
            decoded_sections.push((section, Vec::new()));
            continue;
        }
        let section_window = AddressWindow {
            start: section.virtual_addr,
            end: disassembly_end,
        };
        let bytes = patcher
            .get_instructions_in_window(&section_window)
            .map_err(|error| {
                format!(
                    "failed to read executable section '{}' at 0x{:x}-0x{:x}: {}",
                    section.name, section.virtual_addr, disassembly_end, error
                )
            })?;
        let instructions = cs
            .disasm_all(&bytes, section.virtual_addr)
            .map_err(|error| {
                format!(
                    "failed to disassemble executable section '{}' at 0x{:x}-0x{:x}: {}",
                    section.name, section.virtual_addr, disassembly_end, error
                )
            })?;
        let decoded_bytes = instructions.iter().try_fold(0usize, |total, instruction| {
            total.checked_add(instruction.bytes().len())
        });
        let decoded_bytes = decoded_bytes.ok_or_else(|| {
            format!(
                "decoded byte count overflowed for executable section '{}' at 0x{:x}-0x{:x}",
                section.name, section.virtual_addr, disassembly_end
            )
        })?;
        ensure_window_fully_decoded_for_arch(
            decode_arch_label(backend.arch()),
            decoded_bytes,
            bytes.len(),
            section.virtual_addr,
            disassembly_end,
        )
        .map_err(|error| format!("executable section '{}': {}", section.name, error))?;

        let mut planned = Vec::with_capacity(instructions.len());
        for instruction in instructions.iter() {
            let facts = inspect_detail(&cs, instruction, &section.name)?;
            branch_targets.extend(facts.direct_branch_targets);

            let instruction_end = instruction
                .address()
                .checked_add(
                    u64::try_from(instruction.bytes().len())
                        .expect("instruction byte length always fits u64"),
                )
                .ok_or_else(|| {
                    format!(
                        "instruction range overflows in executable section '{}' at 0x{:x}",
                        section.name,
                        instruction.address()
                    )
                })?;
            let role = if facts.is_call
                || (backend.arch() == DetectedArch::X86_64 && facts.has_rip_relative_memory)
            {
                WindowRole::Excluded
            } else {
                match backend.classify_candidate_instruction(instruction) {
                    Ok(CandidateInstructionDisposition::StraightLine) => WindowRole::StraightLine,
                    Ok(CandidateInstructionDisposition::Terminator) => WindowRole::Terminator,
                    Err(_) => WindowRole::Excluded,
                }
            };
            planned.push(WindowInstruction::new(
                instruction.address(),
                instruction_end,
                role,
            ));
        }

        decoded_sections.push((section, planned));
    }

    // Phase 2: build maximal supported straight-line runs from the cached owned
    // descriptors, splitting a run whenever an instruction other than the run's
    // first sits at a collected branch target. In-place patching pins the window
    // *end* but moves interior instruction addresses, so a target inside a
    // rewritten window would be jumped into mid-instruction; a window may
    // *begin* at a target (that address is fixed) but must not contain one past
    // its first instruction.
    //
    // Splitting on instruction boundaries is sound for direct branches: linear
    // disassembly always places a direct target on an instruction start, so a
    // collected target that lands inside a run coincides with a boundary in
    // that run. Mid-instruction, overlapping, and indirect targets are out of
    // scope and are issue #619's soundness gate.
    let mut section_results = Vec::new();
    for (section, planned) in decoded_sections {
        let filtered = refuse_windows_with_interior_targets(
            plan_candidate_windows(&planned, &branch_targets),
            &indirect_targets,
        );
        section_results.push(SectionCandidateWindows {
            candidates: filtered.admitted,
            indirect_target_refusals: filtered.refused,
            section,
        });
    }

    let refused = total_indirect_target_refusals(&section_results);
    if refused > 0 {
        println!("{}", indirect_target_refusal_log(refused));
    }

    Ok(section_results)
}

/// Candidate windows dropped for indirect-target reasons across every section.
fn total_indirect_target_refusals(sections: &[SectionCandidateWindows]) -> usize {
    sections
        .iter()
        .map(|section| section.indirect_target_refusals)
        .sum()
}

fn indirect_target_refusal_log(refused: usize) -> String {
    format!(
        "Auto candidate discovery: refused {refused} window(s) because indirect targets from relocations or .rodata/.data.rel.ro pointers fell inside them."
    )
}

fn incomplete_executable_section_tail_log(
    section_name: &str,
    raw_start: u64,
    raw_end: u64,
    disassembly_end: u64,
    instruction_alignment: u64,
    trailing_bytes: u64,
) -> String {
    format!(
        "Auto candidate discovery: executable section '{section_name}' has raw range 0x{raw_start:x}-0x{raw_end:x}; scanning complete {instruction_alignment}-byte-aligned instruction prefix 0x{raw_start:x}-0x{disassembly_end:x} and ignoring {trailing_bytes} trailing byte(s)."
    )
}

struct ElfAutoOptimizationAdapter<'a, B> {
    backend: B,
    patcher: &'a mut ElfPatcher,
    options: &'a OptimizationOptions,
    /// Candidate windows the most recent discovery pass refused for
    /// indirect-target reasons (ADR-0009 Decision 5). Read after the loop so
    /// the run summary never claims an unqualified fixpoint over a binary whose
    /// coverage was incomplete.
    refused_windows: usize,
    /// Windows whose rewrite this run declined to apply after searching them —
    /// a search or reassembly failure, or a replacement that does not fit.
    /// Same reason as `refused_windows`: suppressed coverage must not be
    /// silent, and a fixpoint reached over it is only a fixpoint over what was
    /// actually admitted.
    refused_rewrites: usize,
}

impl<B: ElfOptimizationBackend> ElfAutoOptimizationAdapter<'_, B> {
    /// Drop one window from this run without failing it, and account for the
    /// drop so the summary can qualify its fixpoint.
    fn refuse_rewrite(&mut self, candidate: &AutoWindow, reason: &str) -> WindowSearchResult {
        self.refused_rewrites += 1;
        println!(
            "Auto driver: refusing rewrite at 0x{:x}-0x{:x}: {reason}.",
            candidate.window.start, candidate.window.end,
        );
        WindowSearchResult::NoImprovement
    }
}

impl<B: ElfOptimizationBackend> AutoOptimizationAdapter for ElfAutoOptimizationAdapter<'_, B> {
    fn discover_windows(&mut self) -> Result<Vec<AutoWindow>, String> {
        let discovered = find_candidate_windows_with_backend(&self.backend, self.patcher)
            .map_err(|error| error.to_string())?;
        let cs = self
            .backend
            .disassembler()
            .map_err(|error| error.to_string())?;
        let mut work = Vec::new();
        self.refused_windows = total_indirect_target_refusals(&discovered);

        for section in discovered {
            for window in section.candidates {
                let bytes = self
                    .patcher
                    .get_instructions_in_window(&window)
                    .map_err(|error| error.to_string())?;
                let instructions = cs
                    .disasm_all(&bytes, window.start)
                    .map_err(|error| error.to_string())?;
                let mut seen_encodings = std::collections::HashSet::new();
                let redundancy_score = instructions
                    .iter()
                    .filter(|instruction| !seen_encodings.insert(instruction.bytes()))
                    .count();
                work.push(AutoWindow {
                    window,
                    instruction_count: instructions.len(),
                    redundancy_score,
                    instruction_bytes: bytes,
                });
            }
        }

        Ok(work)
    }

    fn optimize_window(&mut self, candidate: &AutoWindow) -> Result<WindowSearchResult, String> {
        // Gate on the window's own extent — the same number `apply_patch`
        // validates against — rather than on the byte snapshot discovery took.
        let window_len = usize::try_from(candidate.window.end - candidate.window.start)
            .map_err(|_| "candidate window length does not fit in usize".to_string())?;

        // Whatever goes wrong here is a property of this one window, not of the
        // image: nothing is on disk until the final `write_to`, so propagating
        // would abort the run and discard every rewrite accepted so far.
        // Reassembly is a live source of such errors — x86 window reassembly
        // *fails* (rather than returning oversized bytes) when an optimized
        // prefix would displace the window's pinned `Jcc`, so the `fits_window`
        // gate below never sees that case.
        let outcome = match optimize_elf_window_with_backend(
            &self.backend,
            self.patcher,
            candidate.window.start,
            candidate.window.end,
            self.options,
            false,
        ) {
            Ok(outcome) => outcome,
            Err(error) => return Ok(self.refuse_rewrite(candidate, &error.to_string())),
        };

        // `apply_patch` would reject an oversized replacement, and that error
        // would likewise abort the whole run. Refuse just this window instead.
        if !outcome.fits_window(window_len) {
            return Ok(self.refuse_rewrite(
                candidate,
                &format!("the replacement does not fit the {window_len}-byte window"),
            ));
        }

        Ok(WindowSearchResult::from(outcome))
    }

    fn apply_optimization(
        &mut self,
        candidate: &AutoWindow,
        replacement: &[u8],
    ) -> Result<(), String> {
        self.patcher
            .apply_patch(&candidate.window, replacement)
            .map_err(|error| error.to_string())
    }
}

/// Whole-binary `--auto` driver entry point.
pub fn run_auto_optimization(
    mut image: ElfPatcher,
    binary: &Path,
    output: Option<&Path>,
    force: bool,
    options: &OptimizationOptions,
    max_windows: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if image.elf_type() == elf::abi::ET_REL {
        return Err(
            "--auto does not support relocatable ELF objects (ET_REL), whose executable sections can share virtual addresses"
                .into(),
        );
    }
    let output = resolve_output_path(binary, output, force)?;
    let arch = image.arch();
    match arch {
        DetectedArch::Aarch64 => run_auto_optimization_with_backend(
            AArch64OptimizationBackend,
            &mut image,
            binary,
            &output,
            options,
            max_windows,
        ),
        DetectedArch::X86_64 | DetectedArch::X86_32 => run_auto_optimization_with_backend(
            X86OptimizationBackend::new(X86Arch::try_from(arch)?),
            &mut image,
            binary,
            &output,
            options,
            max_windows,
        ),
    }
}

fn run_auto_optimization_with_backend<B: ElfOptimizationBackend>(
    backend: B,
    image: &mut ElfPatcher,
    binary: &Path,
    output: &ResolvedOutput,
    options: &OptimizationOptions,
    max_windows: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Auto-optimizing ELF binary: {}", binary.display());
    println!("Detected: {}", backend.arch_description());
    println!("Algorithm: {:?}", options.algorithm);
    println!("Global window-search budget: {max_windows}");

    let mut adapter = ElfAutoOptimizationAdapter {
        backend,
        patcher: image,
        options,
        refused_windows: 0,
        refused_rewrites: 0,
    };
    let summary = drive_auto_optimization(&mut adapter, max_windows)?;
    let refused_windows = adapter.refused_windows;
    let refused_rewrites = adapter.refused_rewrites;

    image.write_to(output)?;
    println!("Created optimized binary: {}", output.path().display());
    println!(
        "{}",
        auto_run_summary_log(&summary, refused_windows, refused_rewrites)
    );

    Ok(())
}

/// Run-level accounting for one `--auto` invocation, as the lines the CLI
/// prints. Kept as a pure formatter beside [`indirect_target_refusal_log`] so
/// the wording integration tests assert on is pinned by a unit test first.
fn auto_run_summary_log(
    summary: &AutoRunSummary,
    refused_windows: usize,
    refused_rewrites: usize,
) -> String {
    let mut lines = vec![format!(
        "Auto summary: {} searched, {} cache hits, {} rewrites accepted.",
        summary.searches, summary.cache_hits, summary.accepted_rewrites,
    )];
    if let AutoTermination::BudgetExhausted { skipped } = summary.termination {
        lines.push(format!(
            "Auto window budget exhausted; skipped {skipped} candidate window(s) due to budget."
        ));
    }
    if refused_rewrites > 0 {
        lines.push(format!(
            "Auto coverage is incomplete: refused {refused_rewrites} rewrite(s) that search or reassembly could not apply to their window."
        ));
    }
    if refused_windows > 0 {
        lines.push(format!(
            "Auto coverage is incomplete: refused {refused_windows} candidate window(s) whose interior contained an indirect target."
        ));
    }
    if summary.termination == AutoTermination::Fixpoint {
        // A fixpoint over an incompletely covered binary is still a fixpoint,
        // but it is not "this binary is optimal" — say which one it is.
        let scope = if refused_windows > 0 || refused_rewrites > 0 {
            " over admitted windows"
        } else {
            ""
        };
        lines.push(format!(
            "Auto optimization reached a fixpoint{scope} (zero rewrites in the final pass)."
        ));
    }
    lines.join("\n")
}

fn decode_arch_label(arch: DetectedArch) -> &'static str {
    match arch {
        DetectedArch::Aarch64 => "AArch64",
        DetectedArch::X86_64 => "x86-64",
        DetectedArch::X86_32 => "x86-32",
    }
}

pub fn optimize_elf_binary(
    patcher: &ElfPatcher,
    path: &Path,
    start_addr: u64,
    end_addr: u64,
    output: &ResolvedOutput,
    options: &OptimizationOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    match patcher.arch() {
        DetectedArch::Aarch64 => optimize_elf_binary_with_backend(
            &AArch64OptimizationBackend,
            patcher,
            path,
            start_addr,
            end_addr,
            output,
            options,
        ),
        DetectedArch::X86_64 | DetectedArch::X86_32 => optimize_elf_binary_with_backend(
            // TryFrom cannot fail in this arm — the match already excluded Aarch64.
            &X86OptimizationBackend::new(X86Arch::try_from(patcher.arch())?),
            patcher,
            path,
            start_addr,
            end_addr,
            output,
            options,
        ),
    }
}

fn optimize_elf_window_with_backend<B: ElfOptimizationBackend>(
    backend: &B,
    patcher: &ElfPatcher,
    start_addr: u64,
    end_addr: u64,

    options: &OptimizationOptions,
    reassemble_on_miss: bool,
) -> Result<ElfWindowOptimization, Box<dyn std::error::Error>> {
    println!("Address window: 0x{:x} - 0x{:x}", start_addr, end_addr);

    // Create address window
    let window = AddressWindow {
        start: start_addr,
        end: end_addr,
    };

    let section = patcher.validate_address_window(&window)?;
    println!("Window is within section: {}", section.name);

    // Get the original instructions in the window
    let original_bytes = patcher.get_instructions_in_window(&window)?;
    println!("Original code: {} bytes", original_bytes.len());

    // Initialize Capstone disassembler
    let cs = backend.disassembler()?;

    // Disassemble instructions in the window
    let instructions = cs.disasm_all(&original_bytes, start_addr)?;
    println!("Disassembled {} instructions:", instructions.len());

    for instruction in instructions.iter() {
        println!(
            "  0x{:x}: {} {}",
            instruction.address(),
            instruction.mnemonic().unwrap_or("???"),
            instruction.op_str().unwrap_or("")
        );
    }

    let decoded_bytes: usize = instructions.iter().map(|i| i.bytes().len()).sum();
    ensure_window_fully_decoded_for_arch(
        decode_arch_label(backend.arch()),
        decoded_bytes,
        original_bytes.len(),
        start_addr,
        end_addr,
    )?;

    // Convert to IR
    let ir_instructions = backend.convert_ir(&instructions)?;
    // An all-NOP AArch64 window can legitimately convert to empty IR: NOPs are
    // skipped and the patcher pads the original byte window back out with NOPs.
    println!(
        "Converted {} instructions to {}:",
        ir_instructions.len(),
        backend.ir_label()
    );

    for instr in &ir_instructions {
        println!("  {}", instr);
    }

    backend.validate_window_ir(&ir_instructions)?;

    let optimization_context =
        backend.optimization_context(&ir_instructions, patcher, &section, end_addr, &cs);

    // Run optimization based on selected algorithm
    let optimized_instructions = backend.run_search(
        &ir_instructions,
        &instructions,
        options,
        optimization_context,
    )?;

    // Use optimized instructions if found, otherwise use original
    let final_instructions = optimized_instructions
        .as_deref()
        .unwrap_or(&ir_instructions);

    if optimized_instructions.is_some() {
        println!("Optimized to {} instructions:", final_instructions.len());
        for instr in final_instructions {
            println!("  {}", instr);
        }
    } else {
        println!("{}", backend.no_optimization_message());
    }

    // Reassemble the instructions
    // Reassembling a search miss is only useful to a caller that will write the
    // bytes. The auto driver discards them, so skipping the work there also
    // removes an encoder-failure surface that would otherwise abort a
    // whole-binary run over a window nothing was going to patch.
    let assembled_bytes = if optimized_instructions.is_none() && !reassemble_on_miss {
        None
    } else {
        match backend.assemble_window(
            &ir_instructions,
            final_instructions,
            optimized_instructions.is_some(),
            &instructions,
            &original_bytes,
            start_addr,
        )? {
            OptimizedWindowBytes::Patch(bytes) => {
                println!("Reassembled to {} bytes", bytes.len());
                Some(bytes)
            }
            OptimizedWindowBytes::LeaveInputUnchanged => None,
        }
    };
    match (optimized_instructions.as_ref(), assembled_bytes) {
        (Some(optimized), Some(replacement)) => Ok(ElfWindowOptimization::Improved {
            original_cost: backend.sequence_cost(&ir_instructions, &options.cost_metric),
            optimized_cost: backend.sequence_cost(optimized, &options.cost_metric),
            replacement,
        }),
        (Some(_), None) => {
            Err("backend reported an optimization but refused to assemble its replacement".into())
        }
        (None, reassembled) => Ok(ElfWindowOptimization::NoImprovement { reassembled }),
    }
}

fn optimize_elf_binary_with_backend<B: ElfOptimizationBackend>(
    backend: &B,
    patcher: &ElfPatcher,
    path: &Path,
    start_addr: u64,
    end_addr: u64,
    output: &ResolvedOutput,
    options: &OptimizationOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Optimizing ELF binary: {}", path.display());
    println!("Detected: {}", backend.arch_description());
    println!("Algorithm: {:?}", options.algorithm);

    let window = AddressWindow {
        start: start_addr,
        end: end_addr,
    };
    // Single-window mode always materializes the result file: a reassembled
    // miss is written just like an accepted rewrite, and a window the backend
    // leaves unchanged is written as an unmodified copy. The write decision and
    // its success message live in the pure `report::build_window_write_plan`
    // seam; here we perform the chosen I/O first, then print the line it
    // rendered — preserving the write-before-print ordering.
    let outcome =
        optimize_elf_window_with_backend(backend, patcher, start_addr, end_addr, options, true)?;
    let plan = report::build_window_write_plan(outcome, output.path());
    match plan.action {
        report::WindowWriteAction::Patch { bytes } => {
            patcher.create_patched_copy(output, &window, &bytes)?
        }
        report::WindowWriteAction::CopyUnmodified => patcher.create_unmodified_copy(output)?,
    }
    println!("{}", plan.line);
    Ok(())
}

/// Build the per-window AArch64 live-out contract.
///
/// Window-written registers are live-out **unless** the downstream scan proved
/// them dead. `downstream_live` is `Some(set)` of the registers proven live
/// downstream when an in-region suffix could be analyzed (issue #621); when it
/// is `None` (unanalyzable section) every written register stays live — the
/// pre-#621 default. Registers the fixed terminator reads are always pinned,
/// independent of the downstream scan, since they are consumed before control
/// transfers.
///
/// **Conditional/branch soundness gate (no-terminator narrowing).** The
/// downstream register scan only follows the *linear fall-through* successor
/// from `end_addr`. A held-fixed terminator (conditional or unconditional)
/// means the fall-through is NOT the sole successor: a conditional branch also
/// has a branch-taken target, and `b`/`br`/`bl`/`ret` transfer elsewhere
/// entirely. A register killed on the fall-through may still be read on the
/// other path, and `terminator.source_registers()` does not re-pin it
/// (`BCond`/`B`/`Ret` source-register sets are empty for the value registers).
/// So register narrowing applies ONLY when there is no terminator — exactly
/// mirroring the `flags_live = if terminator.is_some() { true }` blanket. When
/// a terminator is present we ignore `downstream_live` and keep every
/// window-written register live.
/// Shared base `SearchConfig` for the AArch64 stochastic/enumerative/hybrid/
/// symbolic/LLM builders. Sets the fields every AArch64 algorithm configures
/// identically — cost metric, overall and SMT solver timeouts, verbosity, and
/// the register + immediate pools — so each builder only layers on its
/// algorithm-specific pieces. Mirrors `build_x86_base_search_config`.
///
/// Issue #243 was exactly the failure this base prevents: a per-algorithm
/// config that hand-rolls these fields inline can silently drop one (the CLI
/// once forgot to propagate `options.timeout` into the hybrid config, leaving
/// workers on the default 60 s timeout). Routing every builder through one
/// base means no algorithm arm can omit a shared field.
fn build_aarch64_base_search_config(
    options: &OptimizationOptions,
    available_registers: Vec<Register>,
    available_immediates: Vec<i64>,
) -> SearchConfig {
    SearchConfig::default()
        .with_cost_metric(options.cost_metric)
        .with_solver_timeout(options.solver_timeout)
        .with_timeout_option(options.timeout)
        .with_verbose(options.verbose)
        .with_registers(available_registers)
        .with_immediates(available_immediates)
}

fn build_stochastic_search_config(
    options: &OptimizationOptions,
    available_registers: Vec<Register>,
    available_immediates: Vec<i64>,
) -> SearchConfig {
    let stochastic_config = StochasticConfig::default()
        .with_beta(options.beta)
        .with_iterations(options.iterations)
        .with_seed_option(options.seed);

    build_aarch64_base_search_config(options, available_registers, available_immediates)
        .with_stochastic(stochastic_config)
}

fn build_enumerative_search_config(
    options: &OptimizationOptions,
    available_registers: Vec<Register>,
    available_immediates: Vec<i64>,
) -> SearchConfig {
    build_aarch64_base_search_config(options, available_registers, available_immediates)
        .with_cores(options.cores)
}

/// Build the per-worker `SearchConfig` consumed by the hybrid parallel
/// coordinator.
///
/// Issue #243: the CLI used to forget to propagate `options.timeout` into the
/// `SearchConfig`, which left workers running with the default 60 s timeout
/// even when the user passed a smaller `--timeout`. The coordinator-level
/// `ParallelConfig::timeout` still acts as the primary deadline (now wired
/// through `SharedBest::should_stop`); the search-config timeout is a
/// per-worker backstop in case the coordinator itself stalls. The `--timeout`
/// propagation is now inherited from `build_aarch64_base_search_config`.
fn build_hybrid_search_config(
    options: &OptimizationOptions,
    available_registers: Vec<Register>,
    available_immediates: Vec<i64>,
) -> SearchConfig {
    let stochastic_config = StochasticConfig::default()
        .with_beta(options.beta)
        .with_iterations(options.iterations);

    let symbolic_config = SymbolicConfig::default().with_search_mode(options.search_mode);

    build_aarch64_base_search_config(options, available_registers, available_immediates)
        .with_stochastic(stochastic_config)
        .with_symbolic(symbolic_config)
}

/// Build the `SearchConfig` for AArch64 symbolic (SMT) search: the shared base
/// plus the symbolic search mode.
fn build_symbolic_search_config(
    options: &OptimizationOptions,
    available_registers: Vec<Register>,
    available_immediates: Vec<i64>,
) -> SearchConfig {
    let symbolic_config = SymbolicConfig::default().with_search_mode(options.search_mode);

    build_aarch64_base_search_config(options, available_registers, available_immediates)
        .with_symbolic(symbolic_config)
}

/// Build the `SearchConfig` for AArch64 LLM-assisted (Codex) search: the shared
/// base plus the Codex model and call budget.
fn build_llm_search_config(
    options: &OptimizationOptions,
    available_registers: Vec<Register>,
    available_immediates: Vec<i64>,
) -> SearchConfig {
    let llm = LlmConfig::default()
        .with_max_codex_calls(options.llm_max_calls)
        .with_model(options.llm_model.clone());

    build_aarch64_base_search_config(options, available_registers, available_immediates)
        .with_llm(llm)
}

/// Shared base `SearchConfig` for the x86 stochastic/symbolic/enumerative
/// builders. Sets the fields they configure identically — cost metric, overall
/// and SMT solver timeouts, verbosity, the target-derived register pool, and the
/// default immediate pool — so each builder only layers on its
/// algorithm-specific pieces. Operand width is architectural (owned by the ISA
/// marker), not a config field.
fn build_x86_base_search_config(
    target: &[isa::x86::X86Instruction],
    options: &OptimizationOptions,
) -> SearchConfig {
    SearchConfig::default()
        .with_cost_metric(options.cost_metric)
        .with_solver_timeout(options.solver_timeout)
        .with_timeout_option(options.timeout)
        .with_verbose(options.verbose)
        .with_x86_registers(x86_search_inputs::registers_from_target(target))
        .with_immediates(isa::x86::default_x86_immediates())
}

fn build_x86_stochastic_search_config(
    target: &[isa::x86::X86Instruction],
    options: &OptimizationOptions,
) -> SearchConfig {
    let stochastic_config = StochasticConfig::default()
        .with_beta(options.beta)
        .with_iterations(options.iterations)
        .with_seed_option(options.seed);

    build_x86_base_search_config(target, options).with_stochastic(stochastic_config)
}

fn build_x86_symbolic_search_config(
    target: &[isa::x86::X86Instruction],
    options: &OptimizationOptions,
    // Kept as a search-policy input for callers that intentionally disable
    // same-count rewrites. The ELF frontend passes true because register views
    // are represented precisely throughout the x86 pipeline.
    same_count_code_size_allowed: bool,
) -> SearchConfig {
    let symbolic_config = SymbolicConfig::default().with_search_mode(options.search_mode);

    build_x86_base_search_config(target, options)
        .with_symbolic(symbolic_config)
        .with_x86_same_count_code_size_allowed(same_count_code_size_allowed)
}

/// Run optimization using the selected algorithm.
///
/// Issue #69: if `target` ends in a terminator (branch / control-flow
/// instruction), the search rewrites only the straight-line prefix and the
/// terminator is reattached bit-identical to the returned sequence.
fn run_optimization(
    target: &[Instruction],
    options: &OptimizationOptions,
    downstream_flags_live: bool,
    downstream_live: Option<semantics::live_out::RegisterSet<Register>>,
) -> Result<Option<Vec<Instruction>>, Box<dyn std::error::Error>> {
    if target.is_empty() {
        return Ok(None);
    }

    // Split off the terminator before search. The prefix is what gets
    // optimized; the terminator is part of the live-out contract and is
    // preserved bit-identical. A terminator-only sequence has no rewritable
    // prefix and skips search entirely.
    let (prefix, terminator) = split_terminator(target);
    if prefix.is_empty() {
        return Ok(None);
    }

    // Keep the historical scalar pool and add the target's vector registers
    // so every search backend can generate NEON candidates for NEON windows.
    let available_registers = aarch64_search_inputs::registers_from_target(prefix);
    let available_immediates = aarch64_search_inputs::default_immediates();

    // Create live-out contract over the prefix (assume all modified registers
    // are live-out), plus any registers the fixed terminator reads after the
    // optimized prefix runs. NZCV liveness comes from the fixed terminator or
    // the known downstream fall-through context.
    let live_out = aarch64_search_inputs::live_out_for_optimization_prefix(
        prefix,
        terminator,
        downstream_flags_live,
        downstream_live.as_ref(),
    );

    // Reattach the terminator (if any) to a successfully optimized prefix.
    let reattach = |opt: Option<Vec<Instruction>>| -> Option<Vec<Instruction>> {
        opt.map(|mut seq| {
            if let Some(t) = terminator {
                seq.push(*t);
            }
            seq
        })
    };

    match options.algorithm {
        Algorithm::Enumerative => {
            println!("\nRunning enumerative search...");
            if let Some(n) = options.cores {
                println!("  Cores: {}", n);
            }

            let config =
                build_enumerative_search_config(options, available_registers, available_immediates);

            let mut search = EnumerativeSearch::<isa::AArch64>::new();
            let result = search.search(prefix, &live_out, &config);

            print_search_statistics(&result.statistics);

            if result.found_optimization {
                Ok(reattach(result.optimized_sequence))
            } else {
                Ok(None)
            }
        }
        Algorithm::Stochastic => {
            println!("\nRunning stochastic (MCMC) search...");
            println!("  Beta: {}", options.beta);
            println!("  Iterations: {}", options.iterations);
            if let Some(seed) = options.seed {
                println!("  Seed: {}", seed);
            }

            let config =
                build_stochastic_search_config(options, available_registers, available_immediates);

            let mut search: StochasticSearch<isa::AArch64> = StochasticSearch::new();
            let result: search::result::SearchResult =
                search.search(prefix, &live_out, &config).into();

            print_search_statistics(&result.statistics);

            if result.found_optimization {
                Ok(reattach(result.optimized_sequence))
            } else {
                Ok(None)
            }
        }
        Algorithm::Symbolic => {
            println!("\nRunning symbolic (SMT) search...");
            println!("  Search mode: {:?}", options.search_mode);
            println!("  Solver timeout: {:?}", options.solver_timeout);

            let config =
                build_symbolic_search_config(options, available_registers, available_immediates);

            let mut search: SymbolicSearch<isa::AArch64> = SymbolicSearch::new();
            let result: search::result::SearchResult =
                search.search(prefix, &live_out, &config).into();

            print_search_statistics(&result.statistics);

            if result.found_optimization {
                Ok(reattach(result.optimized_sequence))
            } else {
                Ok(None)
            }
        }
        Algorithm::Llm => {
            println!("\nRunning LLM-assisted (Codex) search...");
            println!("  Model: {}", options.llm_model);
            println!("  Max codex calls: {}", options.llm_max_calls);

            let config =
                build_llm_search_config(options, available_registers, available_immediates);

            let mut search = search::llm::LlmSearch::new();
            let result = search.search(prefix, &live_out, &config);

            print_search_statistics(&result.statistics);
            print_llm_timings(search.timings(), result.statistics.elapsed_time);
            print_unsupported_mnemonic_ledger(search.ledger());

            if result.found_optimization {
                Ok(reattach(result.optimized_sequence))
            } else {
                Ok(None)
            }
        }
        Algorithm::Hybrid => {
            let num_cores = options.cores.unwrap_or_else(num_cpus::get);
            println!("\nRunning hybrid parallel search...");
            println!("  Workers: {}", num_cores);
            println!("  Symbolic worker: {}", !options.no_symbolic);
            if let Some(seed) = options.seed {
                println!("  Base seed: {}", seed);
            }

            let config =
                build_hybrid_search_config(options, available_registers, available_immediates);

            let parallel_config = ParallelConfig::default()
                .with_workers(num_cores)
                .with_symbolic(!options.no_symbolic)
                .with_seed_option(options.seed)
                .with_timeout_option(options.timeout);

            let result = run_parallel_search(prefix, &live_out, &config, &parallel_config);

            print_search_statistics(&result.total_statistics);

            if result.best_result.found_optimization {
                Ok(reattach(result.best_result.optimized_sequence))
            } else {
                Ok(None)
            }
        }
    }
}

/// Format a byte count with a unit chosen to keep ~3 significant digits visible.
/// Print the per-phase timing breakdown from an LLM-assisted run.
pub fn print_llm_timings(timings: &search::llm::LlmTimings, total: Duration) {
    for line in report::format_llm_timings(timings, total) {
        println!("{}", line);
    }
}

/// Print the unsupported-mnemonic ledger from an LLM-assisted run.
pub fn print_unsupported_mnemonic_ledger(ledger: &search::llm::ledger::UnsupportedMnemonicLedger) {
    for line in report::format_unsupported_mnemonic_ledger(ledger) {
        println!("{}", line);
    }
}

/// Print search statistics
pub fn print_search_statistics(stats: &search::result::SearchStatistics) {
    for line in report::format_search_statistics(stats) {
        println!("{}", line);
    }
}

#[cfg(test)]
fn ensure_window_fully_decoded(
    decoded_bytes: usize,
    window_bytes: usize,
    start_addr: u64,
    end_addr: u64,
) -> Result<(), String> {
    ensure_window_fully_decoded_for_arch(
        "AArch64",
        decoded_bytes,
        window_bytes,
        start_addr,
        end_addr,
    )
}

fn ensure_window_fully_decoded_for_arch(
    arch_label: &str,
    decoded_bytes: usize,
    window_bytes: usize,
    start_addr: u64,
    end_addr: u64,
) -> Result<(), String> {
    use std::cmp::Ordering;
    match decoded_bytes.cmp(&window_bytes) {
        Ordering::Equal => Ok(()),
        Ordering::Less => {
            let first_undecoded = start_addr
                .saturating_add(decoded_bytes as u64)
                .min(end_addr);
            Err(format!(
                "{} window 0x{:x}-0x{:x} ({} bytes) was not fully decoded by Capstone; \
                 decoded only {} bytes, first undecoded byte at 0x{:x}",
                arch_label, start_addr, end_addr, window_bytes, decoded_bytes, first_undecoded
            ))
        }
        // Defensive: cs.disasm_all only emits bytes it was given, so this
        // branch is an internal-invariant guard, not a user-facing condition.
        Ordering::Greater => Err(format!(
            "{} window 0x{:x}-0x{:x} ({} bytes) decoded {} bytes by Capstone — more than the window holds",
            arch_label, start_addr, end_addr, window_bytes, decoded_bytes
        )),
    }
}

fn convert_capstone_op_for_optimization(
    mnemonic: &str,
    op_str: &str,
    address: u64,
) -> Result<Option<Instruction>, String> {
    match convert_capstone_op(mnemonic, op_str) {
        ConvertOutcome::Instruction(instr) => Ok(Some(instr)),
        ConvertOutcome::Skip => {
            // `Skip` is intentionally narrower than `Unsupported`: today it is
            // only used for NOP-equivalent instructions, which the patcher can
            // re-pad after rewriting the whole byte window. Unsupported
            // instructions must still abort so side effects are never dropped.
            Ok(None)
        }
        ConvertOutcome::Unsupported(line) => Err(format!(
            "AArch64 window contains unsupported instruction '{}' at 0x{:x}; \
             narrow the --start-addr/--end-addr range to \
             exclude it, or add the mnemonic to the supported set.",
            line, address
        )),
    }
}

fn convert_to_ir(instructions: &capstone::Instructions) -> Result<Vec<Instruction>, String> {
    let mut ir_instructions = Vec::new();

    for instruction in instructions.iter() {
        let mnemonic = instruction.mnemonic().unwrap_or("");
        let op_str = instruction.op_str().unwrap_or("");

        if let Some(instr) =
            convert_capstone_op_for_optimization(mnemonic, op_str, instruction.address())?
        {
            ir_instructions.push(instr);
        }
    }

    Ok(ir_instructions)
}

/// Flags-only context derivation, used as the trait default and by callers
/// that do not have the window IR available to derive register liveness. The
/// register-liveness narrowing (#621) needs the window's written set, so it is
/// computed in the per-backend `optimization_context` overrides; here
/// `downstream_live_regs` stays `Unknown` (every written register live).
fn optimization_context_for_backend(
    arch: DetectedArch,
    patcher: &ElfPatcher,
    section: &TextSection,
    end_addr: u64,
    cs: &Capstone,
) -> OptimizationContext {
    if arch == DetectedArch::Aarch64 {
        return OptimizationContext {
            downstream_flags_live: validation::downstream::aarch64_downstream_flags_live(
                patcher, section, end_addr, cs,
            ),
            downstream_live_regs: DownstreamLiveRegs::Unknown,
        };
    }

    if matches!(arch, DetectedArch::X86_64 | DetectedArch::X86_32) {
        return OptimizationContext {
            downstream_flags_live: validation::downstream::x86_downstream_flags_live(
                arch, patcher, section, end_addr, cs,
            ),
            downstream_live_regs: DownstreamLiveRegs::Unknown,
        };
    }

    OptimizationContext::default()
}

// ============================================================================
// x86 parser + enumerative pipeline
// ============================================================================
//
// Text parsing helpers (`parse_x86_register`, `parse_x86_operand`,
// `parse_x86_immediate`, `x86_ir_from_mnemonic`, `parse_x86_assembly_string`)
// live in `parser::x86`. The Capstone bridge (`convert_to_x86_ir`,
// `convert_x86_capstone_op_for_optimization`) lives in `capstone_bridge_x86`.
// This file keeps only the length-1 enumerator used by the enumerative x86
// pipeline. The per-window search inputs — candidate register/immediate pools,
// the live-out contract, and the terminator-placement admissibility gate — live
// in `x86_search_inputs`.

/// Build the search config for the x86 *enumerative* path. Like stochastic and
/// symbolic search, enumerative search draws candidates from the target's own
/// registers via the shared x86 base; it additionally derives immediates from
/// the target and honours --cores now that the trait-backed search is
/// rayon-parallel. It reuses the stochastic builder so it inherits the same
/// solver timeout (`--solver-timeout`) wiring.
fn build_x86_enumerative_search_config(
    target: &[isa::x86::X86Instruction],
    options: &OptimizationOptions,
) -> SearchConfig {
    build_x86_stochastic_search_config(target, options)
        .with_immediates(x86_search_inputs::enumerative_immediates_from_target(
            target,
        ))
        .with_cores(options.cores)
}

/// Run x86 enumerative search and return the optimized sequence if any.
fn run_x86_enumerative(
    target: &[isa::x86::X86Instruction],
    width: u32,
    options: &OptimizationOptions,
    downstream_flags_live: bool,
    downstream_live: Option<&semantics::live_out::RegisterSet<isa::x86::X86Register>>,
) -> Option<Vec<isa::x86::X86Instruction>> {
    use search::SearchAlgorithm;

    let config = build_x86_enumerative_search_config(target, options);
    let live_out = x86_search_inputs::live_out_for_optimization(
        target,
        downstream_flags_live,
        downstream_live,
    );

    let (optimized, statistics) = if width == 32 {
        let mut search: EnumerativeSearch<isa::X86_32> = EnumerativeSearch::new();
        let result = search.search(target, &live_out, &config);
        (
            result
                .found_optimization
                .then_some(result.optimized_sequence)
                .flatten(),
            result.statistics,
        )
    } else {
        let mut search: EnumerativeSearch<isa::X86_64> = EnumerativeSearch::new();
        let result = search.search(target, &live_out, &config);
        (
            result
                .found_optimization
                .then_some(result.optimized_sequence)
                .flatten(),
            result.statistics,
        )
    };
    print_search_statistics(&statistics);
    optimized
}

/// Run x86 stochastic search and return the optimized sequence if any.
/// Width selects between `X86_64` and `X86_32` backends. Read live-out
/// from the target via `validation::live_out::x86_live_out_from_target`
/// (issue #73 Phase 1) so EFLAGS liveness is honoured when the target
/// contains a flag-writer.
fn run_x86_stochastic(
    target: &[isa::x86::X86Instruction],
    width: u32,
    options: &OptimizationOptions,
    downstream_flags_live: bool,
    downstream_live: Option<&semantics::live_out::RegisterSet<isa::x86::X86Register>>,
) -> Option<Vec<isa::x86::X86Instruction>> {
    use search::SearchAlgorithm;
    use search::stochastic::StochasticSearch;

    let config = build_x86_stochastic_search_config(target, options);
    if config.x86_available_registers.is_empty() {
        return None;
    }
    let live_out = x86_search_inputs::live_out_for_optimization(
        target,
        downstream_flags_live,
        downstream_live,
    );

    // Extract (optimized, statistics) in each width branch separately:
    // the two `SearchResultFor<X86_64>` / `SearchResultFor<X86_32>`
    // types are not the same, so the `if/else` must produce a
    // width-agnostic tuple.
    let (optimized, statistics) = if width == 32 {
        let mut search: StochasticSearch<isa::X86_32> = StochasticSearch::new();
        let result = search.search(target, &live_out, &config);
        (
            result
                .found_optimization
                .then_some(result.optimized_sequence)
                .flatten(),
            result.statistics,
        )
    } else {
        let mut search: StochasticSearch<isa::X86_64> = StochasticSearch::new();
        let result = search.search(target, &live_out, &config);
        (
            result
                .found_optimization
                .then_some(result.optimized_sequence)
                .flatten(),
            result.statistics,
        )
    };
    print_search_statistics(&statistics);
    optimized
}

/// Run x86 symbolic (SMT) search and return the optimized sequence if
/// any. Same width / live-out handling as `run_x86_stochastic`.
fn run_x86_symbolic(
    target: &[isa::x86::X86Instruction],
    width: u32,
    options: &OptimizationOptions,
    downstream_flags_live: bool,
    downstream_live: Option<&semantics::live_out::RegisterSet<isa::x86::X86Register>>,
    same_count_code_size_allowed: bool,
) -> Option<Vec<isa::x86::X86Instruction>> {
    use search::SearchAlgorithm;
    use search::symbolic::SymbolicSearch;

    let config = build_x86_symbolic_search_config(target, options, same_count_code_size_allowed);
    let live_out = x86_search_inputs::live_out_for_optimization(
        target,
        downstream_flags_live,
        downstream_live,
    );

    let (optimized, statistics) = if width == 32 {
        let mut search: SymbolicSearch<isa::X86_32> = SymbolicSearch::new();
        let result = search.search(target, &live_out, &config);
        (
            result
                .found_optimization
                .then_some(result.optimized_sequence)
                .flatten(),
            result.statistics,
        )
    } else {
        let mut search: SymbolicSearch<isa::X86_64> = SymbolicSearch::new();
        let result = search.search(target, &live_out, &config);
        (
            result
                .found_optimization
                .then_some(result.optimized_sequence)
                .flatten(),
            result.statistics,
        )
    };
    print_search_statistics(&statistics);
    optimized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Operand;
    use crate::isa::x86::{X86Instruction, X86Register};
    use crate::parser::x86::{parse_x86_operand, x86_ir_from_mnemonic};
    use crate::search::llm::LlmTimings;
    use crate::search::llm::ledger::UnsupportedMnemonicLedger;
    use crate::search::result::SearchStatistics;
    use crate::test_utils::TempFile;

    fn options_for(algorithm: Algorithm) -> OptimizationOptions {
        OptimizationOptions {
            algorithm,
            timeout: Some(Duration::from_millis(1)),
            cost_metric: CostMetric::InstructionCount,
            verbose: false,
            beta: 1.0,
            iterations: 0,
            seed: Some(1),
            search_mode: SearchMode::Linear,
            solver_timeout: Duration::from_millis(1),
            cores: Some(1),
            no_symbolic: true,
            llm_max_calls: 0,
            llm_model: "test-model".to_string(),
        }
    }

    fn assert_stochastic_config_matches_options(
        config: &SearchConfig,
        options: &OptimizationOptions,
    ) {
        assert_eq!(config.solver_timeout, Some(options.solver_timeout));
        assert_eq!(config.stochastic.beta, options.beta);
        assert_eq!(config.stochastic.iterations, options.iterations);
        assert_eq!(config.stochastic.seed, options.seed);
        assert_eq!(config.cost_metric, options.cost_metric);
        assert_eq!(config.timeout, options.timeout);
        assert_eq!(config.verbose, options.verbose);
    }

    fn r10_zeroing_target() -> [X86Instruction; 2] {
        let zero_r10 = X86Instruction::XorReg {
            rd: X86Register::R10,
            rs: X86Register::R10,
        };
        [zero_r10, zero_r10]
    }

    fn assert_single_r10_rewrite(optimized: &[X86Instruction]) {
        assert_eq!(optimized.len(), 1);
        assert_eq!(optimized[0].destination(), Some(X86Register::R10));
    }

    fn build_elf64_with_sections(sections: &[(&str, &[u8], u64, u64)], machine: u16) -> Vec<u8> {
        let elf_header_size = 64usize;
        let shentsize = 64usize;
        let shnum = sections.len() + 2;

        let mut shstrtab = vec![0u8];
        let section_name_offsets: Vec<usize> = sections
            .iter()
            .map(|(name, _, _, _)| {
                let offset = shstrtab.len();
                shstrtab.extend_from_slice(name.as_bytes());
                shstrtab.push(0);
                offset
            })
            .collect();
        let shstrtab_name_offset = shstrtab.len();
        shstrtab.extend_from_slice(b".shstrtab\0");

        let mut next_offset = elf_header_size;
        let section_file_offsets: Vec<usize> = sections
            .iter()
            .map(|(_, bytes, _, _)| {
                let offset = next_offset;
                next_offset += bytes.len();
                offset
            })
            .collect();
        let shstrtab_offset = next_offset;
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
        buf[60..62].copy_from_slice(
            &u16::try_from(shnum)
                .expect("test section count should fit ELF64 header")
                .to_le_bytes(),
        );
        buf[62..64].copy_from_slice(
            &u16::try_from(sections.len() + 1)
                .expect("test string-table index should fit ELF64 header")
                .to_le_bytes(),
        );

        for ((_, bytes, _, _), offset) in sections.iter().zip(&section_file_offsets) {
            buf[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        buf[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(&shstrtab);

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

        for (index, (((_, bytes, virtual_addr, flags), name_offset), file_offset)) in sections
            .iter()
            .zip(&section_name_offsets)
            .zip(&section_file_offsets)
            .enumerate()
        {
            write_shdr(
                index + 1,
                [
                    *name_offset as u64,
                    elf::abi::SHT_PROGBITS as u64,
                    *flags,
                    *virtual_addr,
                    *file_offset as u64,
                    bytes.len() as u64,
                    0,
                    0,
                    1,
                    0,
                ],
            );
        }
        write_shdr(
            sections.len() + 1,
            [
                shstrtab_name_offset as u64,
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

    fn build_elf64_with_executable_sections(
        sections: &[(&str, &[u8], u64)],
        machine: u16,
    ) -> Vec<u8> {
        let sections = sections
            .iter()
            .map(|(name, bytes, virtual_addr)| {
                (
                    *name,
                    *bytes,
                    *virtual_addr,
                    (elf::abi::SHF_ALLOC | elf::abi::SHF_EXECINSTR) as u64,
                )
            })
            .collect::<Vec<_>>();
        build_elf64_with_sections(&sections, machine)
    }

    fn build_minimal_elf64(text_bytes: &[u8], text_vaddr: u64, machine: u16) -> Vec<u8> {
        build_elf64_with_executable_sections(&[(".text", text_bytes, text_vaddr)], machine)
    }

    #[test]
    fn candidate_windows_find_maximal_supported_runs_in_each_executable_section() {
        // push rax; mov rax, rbx; add rax, 1; pop rax
        let text = [0x50, 0x48, 0x89, 0xd8, 0x48, 0x83, 0xc0, 0x01, 0x58];
        // A non-empty executable section containing only unsupported separators.
        let init = [0x50, 0x58];
        let elf_bytes = build_elf64_with_executable_sections(
            &[(".text", &text, 0x1000), (".init", &init, 0x2000)],
            elf::abi::EM_X86_64,
        );
        let input = TempFile::new_bytes("s11-candidate-runs", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].section.name, ".text");
        assert_eq!(sections[0].candidates.len(), 1);
        assert_eq!(sections[0].candidates[0].start, 0x1001);
        assert_eq!(sections[0].candidates[0].end, 0x1008);
        assert_eq!(sections[1].section.name, ".init");
        assert!(
            sections[1].candidates.is_empty(),
            "separator-only sections must retain an empty result record"
        );
    }

    #[test]
    fn candidate_windows_split_run_at_unsupported_instruction() {
        // add rax, 1; push rax; sub rbx, 1
        // The unsupported `push rax` sits between two supported runs and must
        // split them into two windows through the `Err(_)` flush branch,
        // pinning the "split at unsupported instructions" claim directly.
        let text = [0x48, 0x83, 0xc0, 0x01, 0x50, 0x48, 0x83, 0xeb, 0x01];
        let elf_bytes =
            build_elf64_with_executable_sections(&[(".text", &text, 0x1000)], elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-candidate-split", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].section.name, ".text");
        assert_eq!(sections[0].candidates.len(), 2);
        assert_eq!(sections[0].candidates[0].start, 0x1000);
        assert_eq!(sections[0].candidates[0].end, 0x1004);
        assert_eq!(sections[0].candidates[1].start, 0x1005);
        assert_eq!(sections[0].candidates[1].end, 0x1009);
    }

    #[test]
    fn candidate_window_straddling_switch_table_target_is_refused() {
        // Three supported instructions form one candidate; the trailing
        // register-indirect jump models switch dispatch and closes that run.
        // The table's 0x1004 entry names the second instruction, so the whole
        // [0x1000,0x100c) candidate must be refused rather than rewritten
        // across an entry point that linear direct-branch scanning cannot see.
        let text = [
            0x48, 0x83, 0xc0, 0x01, // add rax, 1 @0x1000
            0x48, 0x83, 0xc0, 0x01, // add rax, 1 @0x1004 <- table target
            0x48, 0x83, 0xc0, 0x01, // add rax, 1 @0x1008
            0xff, 0xe0, // jmp rax (indirect dispatch; excluded separator)
        ];
        let rodata = 0x1004u64.to_le_bytes();
        let elf_bytes = build_elf64_with_sections(
            &[
                (
                    ".text",
                    &text,
                    0x1000,
                    (elf::abi::SHF_ALLOC | elf::abi::SHF_EXECINSTR) as u64,
                ),
                (".rodata", &rodata, 0x2000, elf::abi::SHF_ALLOC as u64),
            ],
            elf::abi::EM_X86_64,
        );
        let input = TempFile::new_bytes("s11-candidate-switch-table", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 1);
        assert!(sections[0].candidates.is_empty());
        assert_eq!(sections[0].indirect_target_refusals, 1);
    }

    #[test]
    fn indirect_target_refusal_log_reports_suppressed_window_count() {
        assert_eq!(
            indirect_target_refusal_log(7),
            "Auto candidate discovery: refused 7 window(s) because indirect targets from relocations or .rodata/.data.rel.ro pointers fell inside them."
        );
    }

    #[test]
    fn auto_run_summary_log_reports_budget_and_qualified_fixpoint() {
        // `tests/integration/opt_test.rs` asserts on these substrings, so pin
        // the wording here where a reword fails fast and locally.
        let bounded = auto_run_summary_log(
            &AutoRunSummary {
                searches: 4,
                accepted_rewrites: 2,
                cache_hits: 1,
                termination: AutoTermination::BudgetExhausted { skipped: 2 },
            },
            0,
            0,
        );
        assert_eq!(
            bounded,
            "Auto summary: 4 searched, 1 cache hits, 2 rewrites accepted.\n\
             Auto window budget exhausted; skipped 2 candidate window(s) due to budget."
        );

        let fixpoint = auto_run_summary_log(
            &AutoRunSummary {
                searches: 3,
                accepted_rewrites: 0,
                cache_hits: 3,
                termination: AutoTermination::Fixpoint,
            },
            0,
            0,
        );
        assert!(
            fixpoint.ends_with(
                "Auto optimization reached a fixpoint (zero rewrites in the final pass)."
            ),
            "unqualified fixpoint should not claim a scope: {fixpoint}"
        );

        // Refused coverage qualifies the fixpoint rather than hiding it.
        let partial = auto_run_summary_log(&AutoRunSummary::default(), 5, 0);
        assert!(
            partial.contains(
                "Auto coverage is incomplete: refused 5 candidate window(s) whose interior contained an indirect target."
            ) && partial.contains(
                "reached a fixpoint over admitted windows (zero rewrites in the final pass)."
            ),
            "a fixpoint over incomplete coverage must say so: {partial}"
        );

        // A window whose rewrite the driver declined is suppressed coverage
        // too, so it qualifies the fixpoint the same way.
        let refused = auto_run_summary_log(&AutoRunSummary::default(), 0, 3);
        assert!(
            refused.contains(
                "Auto coverage is incomplete: refused 3 rewrite(s) that search or reassembly could not apply to their window."
            ) && refused.contains(
                "reached a fixpoint over admitted windows (zero rewrites in the final pass)."
            ),
            "a refused rewrite must qualify the fixpoint: {refused}"
        );
    }

    #[test]
    fn incomplete_executable_section_tail_log_reports_ignored_range() {
        assert_eq!(
            incomplete_executable_section_tail_log(".text", 0x1000, 0x100b, 0x1008, 4, 3),
            "Auto candidate discovery: executable section '.text' has raw range 0x1000-0x100b; scanning complete 4-byte-aligned instruction prefix 0x1000-0x1008 and ignoring 3 trailing byte(s)."
        );
    }

    #[test]
    fn auto_mode_skips_reassembling_a_search_miss() {
        // AArch64 `assemble_window` re-encodes the original IR even on a miss.
        // Auto mode discards those bytes, so asking for them is pure work and
        // an extra encoder-failure surface that would abort a whole-binary run
        // over a window nothing was going to patch.
        let text = 0x8b02_0020u32.to_le_bytes(); // add x0, x1, x2
        let elf_bytes = build_minimal_elf64(&text, 0x1000, elf::abi::EM_AARCH64);
        let input = TempFile::new_bytes("s11-auto-miss-reassembly", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("synthetic ELF should parse");
        let options = options_for(Algorithm::Enumerative);

        let skipped = optimize_elf_window_with_backend(
            &AArch64OptimizationBackend,
            &patcher,
            0x1000,
            0x1004,
            &options,
            false,
        )
        .expect("single-instruction window should search cleanly");
        assert!(
            matches!(
                skipped,
                ElfWindowOptimization::NoImprovement { reassembled: None }
            ),
            "auto mode must not pay for reassembly it discards"
        );

        let reassembled = optimize_elf_window_with_backend(
            &AArch64OptimizationBackend,
            &patcher,
            0x1000,
            0x1004,
            &options,
            true,
        )
        .expect("single-instruction window should search cleanly");
        assert!(
            matches!(
                reassembled,
                ElfWindowOptimization::NoImprovement {
                    reassembled: Some(ref bytes),
                } if bytes.as_slice() == text
            ),
            "single-window mode still materializes the reassembled miss"
        );
    }

    #[test]
    fn auto_adapter_accounts_for_indirect_target_refusals() {
        // Same switch-table shape as
        // `candidate_window_straddling_switch_table_target_is_refused`: the
        // .rodata entry names 0x1004, inside the only candidate. The adapter
        // must surface that suppressed coverage rather than hand the driver an
        // empty worklist that reads as "nothing left to optimize".
        let text = [
            0x48, 0x83, 0xc0, 0x01, // add rax, 1 @0x1000
            0x48, 0x83, 0xc0, 0x01, // add rax, 1 @0x1004 <- table target
            0x48, 0x83, 0xc0, 0x01, // add rax, 1 @0x1008
            0xff, 0xe0, // jmp rax (indirect dispatch; excluded separator)
        ];
        let rodata = 0x1004u64.to_le_bytes();
        let elf_bytes = build_elf64_with_sections(
            &[
                (
                    ".text",
                    &text,
                    0x1000,
                    (elf::abi::SHF_ALLOC | elf::abi::SHF_EXECINSTR) as u64,
                ),
                (".rodata", &rodata, 0x2000, elf::abi::SHF_ALLOC as u64),
            ],
            elf::abi::EM_X86_64,
        );
        let input = TempFile::new_bytes("s11-auto-indirect-gate", "elf", &elf_bytes);
        let mut patcher = ElfPatcher::new(input.path()).expect("synthetic ELF should parse");
        let options = options_for(Algorithm::Enumerative);
        let mut adapter = ElfAutoOptimizationAdapter {
            backend: X86OptimizationBackend::new(X86Arch::X86_64),
            patcher: &mut patcher,
            options: &options,
            refused_windows: 0,
            refused_rewrites: 0,
        };

        let candidates = adapter
            .discover_windows()
            .expect("indirect-target refusal should be non-fatal");

        assert!(
            candidates.is_empty(),
            "the only candidate straddles an indirect target and must be refused"
        );
        assert_eq!(
            adapter.refused_windows, 1,
            "refused coverage must be accounted for, not silently dropped"
        );
    }

    #[test]
    fn auto_adapter_contains_a_window_search_failure_instead_of_aborting_the_run() {
        // Nothing reaches disk until the driver's final `write_to`, so
        // propagating one window's search/reassembly failure would discard
        // every rewrite already accepted in memory. x86 window reassembly
        // really does error (rather than return oversized bytes) when an
        // optimized prefix would displace a pinned `Jcc`, so this seam must
        // hold for errors and not just for the `fits_window` gate.
        let elf_bytes = build_minimal_elf64(&[0x90], 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-auto-window-error", "elf", &elf_bytes);
        let mut patcher = ElfPatcher::new(input.path()).expect("synthetic ELF should parse");
        let options = options_for(Algorithm::Enumerative);
        let mut adapter = ElfAutoOptimizationAdapter {
            backend: X86OptimizationBackend::new(X86Arch::X86_64),
            patcher: &mut patcher,
            options: &options,
            refused_windows: 0,
            refused_rewrites: 0,
        };

        // An address window outside every executable section makes
        // `optimize_elf_window_with_backend` fail before any search runs.
        let outcome = adapter
            .optimize_window(&AutoWindow {
                window: AddressWindow {
                    start: 0x9000,
                    end: 0x9004,
                },
                instruction_bytes: vec![0x90; 4],
                instruction_count: 4,
                redundancy_score: 3,
            })
            .expect("a single window's failure must not fail the run");

        assert_eq!(outcome, WindowSearchResult::NoImprovement);
        assert_eq!(
            adapter.refused_rewrites, 1,
            "a contained failure must still be accounted for in the run summary"
        );
    }

    #[test]
    fn optimization_context_for_x86_64_backend_uses_conservative_default() {
        let elf_bytes = build_minimal_elf64(&[0xc3], 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-opt-context-x86-64", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");
        let section = patcher
            .get_text_sections()
            .expect("x86-64 ELF should expose executable section")
            .into_iter()
            .next()
            .expect("minimal ELF should contain .text");
        let backend = X86OptimizationBackend::new(X86Arch::X86_64);
        let cs = backend
            .disassembler()
            .expect("x86-64 disassembler should build");

        let context =
            optimization_context_for_backend(backend.arch(), &patcher, &section, 0x1001, &cs);

        assert!(
            context.downstream_flags_live,
            "non-AArch64 optimization context should stay conservative"
        );
    }

    #[test]
    fn run_auto_optimization_with_zero_budget_writes_unchanged_image() {
        let elf = build_minimal_elf64(&[0x90], 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-auto-zero-budget-in", "elf", &elf);
        let output = TempFile::new_bytes("s11-auto-zero-budget-out", "elf", &[]);
        let patcher = ElfPatcher::new(input.path()).expect("synthetic ELF should parse");
        let opts = options_for(Algorithm::Enumerative);

        run_auto_optimization(patcher, input.path(), Some(output.path()), true, &opts, 0)
            .expect("zero-budget auto run should succeed");

        assert_eq!(
            std::fs::read(output.path()).expect("read auto output"),
            elf,
            "zero search budget must materialize an unchanged image",
        );
    }

    #[test]
    fn run_auto_optimization_rejects_relocatable_elf_before_writing_output() {
        let mut elf = build_minimal_elf64(&[0x90], 0, elf::abi::EM_X86_64);
        elf[16..18].copy_from_slice(&elf::abi::ET_REL.to_le_bytes());
        let input = TempFile::new_bytes("s11-auto-relocatable-in", "o", &elf);
        let output = TempFile::new_bytes("s11-auto-relocatable-out", "elf", &[]);
        let patcher = ElfPatcher::new(input.path()).expect("relocatable ELF should parse");
        let opts = options_for(Algorithm::Enumerative);

        let error =
            run_auto_optimization(patcher, input.path(), Some(output.path()), false, &opts, 0)
                .expect_err("auto mode must reject address-ambiguous relocatable objects");

        assert!(
            error.to_string().contains("relocatable ELF"),
            "unexpected error: {error}"
        );
        assert_eq!(
            std::fs::read(output.path()).expect("read untouched output placeholder"),
            Vec::<u8>::new(),
            "rejection must happen before the auto driver writes an output image",
        );
    }

    #[test]
    fn convert_to_ir_returns_empty_for_pure_nop_window() {
        let cs = aarch64_test_capstone();
        let bytes = [
            0x1f, 0x20, 0x03, 0xd5, // nop
            0x1f, 0x20, 0x03, 0xd5, // nop
        ];
        let instructions = cs
            .disasm_all(&bytes, 0x1000)
            .expect("test NOP bytes should disassemble");

        let ir = convert_to_ir(&instructions).expect("pure-NOP window should convert");

        assert!(ir.is_empty(), "pure-NOP windows should produce empty IR");
    }

    #[test]
    fn convert_to_ir_treats_nop_add_nop_as_add() {
        let cs = aarch64_test_capstone();
        let mut bytes = vec![0x1f, 0x20, 0x03, 0xd5]; // nop
        bytes.extend(assemble_aarch64_test_bytes(&[Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }]));
        bytes.extend([0x1f, 0x20, 0x03, 0xd5]); // nop
        let instructions = cs
            .disasm_all(&bytes, 0x1000)
            .expect("test NOP/ADD bytes should disassemble");

        let ir = convert_to_ir(&instructions).expect("NOP/ADD/NOP window should convert");

        assert_eq!(
            ir,
            vec![Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            }]
        );
    }

    #[test]
    fn first_neon_slice_round_trips_through_assembler_capstone_and_parser() {
        let original = vec![
            Instruction::Movi {
                vd: ir::VectorRegister::V31,
                arrangement: ir::VectorArrangement::FourS,
                imm: 0,
            },
            Instruction::VectorAdd {
                vd: ir::VectorRegister::V0,
                vn: ir::VectorRegister::V1,
                vm: ir::VectorRegister::V2,
                arrangement: ir::VectorArrangement::TwoD,
            },
            Instruction::MovFromVectorLane {
                rd: Register::X0,
                vn: ir::VectorRegister::V0,
                lane: 1,
            },
        ];
        let bytes = assemble_aarch64_test_bytes(&original);
        let cs = aarch64_test_capstone();
        let instructions = cs
            .disasm_all(&bytes, 0x1000)
            .expect("first NEON slice should disassemble");

        let recovered = convert_to_ir(&instructions).expect("Capstone spellings should parse");

        assert_eq!(recovered, original);
    }

    fn assemble_aarch64_test_bytes(instructions: &[Instruction]) -> Vec<u8> {
        AArch64Assembler::new()
            .assemble_instructions(instructions, 0x1000)
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

    #[test]
    fn candidate_instruction_classification_uses_aarch64_conversion_outcome() {
        let backend = AArch64OptimizationBackend;
        let cs = aarch64_test_capstone();

        let nop = cs
            .disasm_all(&[0x1f, 0x20, 0x03, 0xd5], 0x1000)
            .expect("NOP should disassemble");
        assert_eq!(
            backend
                .classify_candidate_instruction(nop.iter().next().expect("one NOP"))
                .expect("NOP is a supported skip"),
            CandidateInstructionDisposition::StraightLine
        );

        let branch_bytes = assemble_aarch64_test_bytes(&[Instruction::B {
            target: crate::ir::LabelId(0x1000),
        }]);
        let branch = cs
            .disasm_all(&branch_bytes, 0x1000)
            .expect("branch should disassemble");
        assert_eq!(
            backend
                .classify_candidate_instruction(branch.iter().next().expect("one branch"))
                .expect("B is a supported terminator"),
            CandidateInstructionDisposition::Terminator
        );
    }

    #[test]
    fn candidate_instruction_classification_matches_x86_window_conversion() {
        let backend = X86OptimizationBackend::new(X86Arch::X86_64);
        let cs = x86_64_test_capstone();
        let supported = cs
            .disasm_all(&[0x48, 0x83, 0xc0, 0x01], 0x2000)
            .expect("add rax, 1 should disassemble");
        let instruction = supported.iter().next().expect("one add");

        assert_eq!(
            backend
                .classify_candidate_instruction(instruction)
                .expect("add rax, 1 is supported"),
            CandidateInstructionDisposition::StraightLine
        );
        assert_eq!(
            convert_x86_capstone_op_for_optimization(
                instruction.mnemonic().unwrap_or(""),
                instruction.op_str().unwrap_or(""),
                instruction.address(),
                parser::x86::X86ParseMode::Mode64,
            )
            .expect("single-instruction conversion should succeed"),
            convert_to_x86_ir(&supported, parser::x86::X86ParseMode::Mode64)
                .expect("whole-window conversion should succeed")
                .into_iter()
                .next()
                .expect("one IR instruction")
        );

        let unsupported = cs
            .disasm_all(&[0x50], 0x3000)
            .expect("push rax should disassemble");
        let instruction = unsupported.iter().next().expect("one push");
        let classifier_error = backend
            .classify_candidate_instruction(instruction)
            .expect_err("push rax is unsupported");
        let window_error = convert_to_x86_ir(&unsupported, parser::x86::X86ParseMode::Mode64)
            .expect_err("whole-window conversion must also reject push rax");
        assert_eq!(classifier_error, window_error);
    }

    #[test]
    fn candidate_windows_exclude_calls_and_split_both_sides() {
        let bytes = assemble_aarch64_test_bytes(&[
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
            Instruction::Bl {
                target: crate::ir::LabelId(0x1000),
            },
            Instruction::Sub {
                rd: Register::X1,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
        ]);
        let elf_bytes = build_minimal_elf64(&bytes, 0x1000, elf::abi::EM_AARCH64);
        let input = TempFile::new_bytes("s11-candidate-calls", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("AArch64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].candidates.len(), 2);
        assert_eq!(sections[0].candidates[0].start, 0x1000);
        assert_eq!(sections[0].candidates[0].end, 0x1004);
        assert_eq!(sections[0].candidates[1].start, 0x1008);
        assert_eq!(sections[0].candidates[1].end, 0x100c);
    }

    #[test]
    fn candidate_windows_scan_complete_aarch64_prefix_before_short_tail() {
        let complete_prefix = assemble_aarch64_test_bytes(&[
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
            Instruction::Sub {
                rd: Register::X1,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
        ]);

        for tail_len in 1..=3 {
            let mut section_bytes = complete_prefix.clone();
            section_bytes.extend(std::iter::repeat_n(0xff, tail_len));
            let elf_bytes = build_minimal_elf64(&section_bytes, 0x1000, elf::abi::EM_AARCH64);
            let input = TempFile::new_bytes("s11-candidate-a64-short-tail", "elf", &elf_bytes);
            let patcher = ElfPatcher::new(input.path()).expect("AArch64 ELF should parse");

            let sections = find_candidate_windows(&patcher).unwrap_or_else(|error| {
                panic!("candidate discovery should ignore a {tail_len}-byte tail: {error}")
            });

            assert_eq!(sections.len(), 1);
            assert_eq!(sections[0].section.size, 8 + tail_len as u64);
            assert_eq!(sections[0].candidates.len(), 1);
            assert_eq!(sections[0].candidates[0].start, 0x1000);
            assert_eq!(
                sections[0].candidates[0].end, 0x1008,
                "an incomplete {tail_len}-byte tail must not enter a candidate"
            );
        }
    }

    #[test]
    fn candidate_windows_keep_tail_only_aarch64_sections_as_empty_results() {
        for tail_len in 1..=3 {
            let section_bytes = vec![0xff; tail_len];
            let elf_bytes = build_minimal_elf64(&section_bytes, 0x1000, elf::abi::EM_AARCH64);
            let input = TempFile::new_bytes("s11-candidate-a64-tail-only", "elf", &elf_bytes);
            let patcher = ElfPatcher::new(input.path()).expect("AArch64 ELF should parse");

            let sections = find_candidate_windows(&patcher).unwrap_or_else(|error| {
                panic!("a {tail_len}-byte tail-only section should be empty: {error}")
            });

            assert_eq!(sections.len(), 1);
            assert_eq!(sections[0].section.name, ".text");
            assert_eq!(sections[0].section.size, tail_len as u64);
            assert!(sections[0].candidates.is_empty());
            assert_eq!(sections[0].indirect_target_refusals, 0);
        }
    }

    #[test]
    fn candidate_windows_reject_misaligned_aarch64_section_starts() {
        let full_instruction = assemble_aarch64_test_bytes(&[Instruction::Add {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Immediate(1),
        }]);
        let tail_only = [0xff];

        for (description, section_bytes) in [
            ("full-instruction", full_instruction.as_slice()),
            ("tail-only", tail_only.as_slice()),
        ] {
            let elf_bytes = build_minimal_elf64(section_bytes, 0x1002, elf::abi::EM_AARCH64);
            let input =
                TempFile::new_bytes("s11-candidate-a64-misaligned-start", "elf", &elf_bytes);
            let patcher = ElfPatcher::new(input.path()).expect("AArch64 ELF should parse");

            let error = find_candidate_windows(&patcher)
                .expect_err(&format!(
                    "a misaligned {description} section must fail closed"
                ))
                .to_string();

            assert!(error.contains("executable section '.text'"), "{error}");
            assert!(error.contains("4-byte aligned"), "{error}");
        }
    }

    #[test]
    fn candidate_windows_hold_supported_terminator_only_at_end() {
        // add rax, 1; je +0; sub rbx, 1
        let text = [0x48, 0x83, 0xc0, 0x01, 0x74, 0x00, 0x48, 0x83, 0xeb, 0x01];
        let terminator_only = [0x74, 0x00]; // je +0
        let elf_bytes = build_elf64_with_executable_sections(
            &[
                (".text", &text, 0x1000),
                (".terminator", &terminator_only, 0x2000),
            ],
            elf::abi::EM_X86_64,
        );
        let input = TempFile::new_bytes("s11-candidate-terminators", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].candidates.len(), 2);
        assert_eq!(sections[0].candidates[0].start, 0x1000);
        assert_eq!(
            sections[0].candidates[0].end, 0x1006,
            "the Jcc may appear only as the first run's held-fixed final instruction"
        );
        assert_eq!(sections[0].candidates[1].start, 0x1006);
        assert_eq!(sections[0].candidates[1].end, 0x100a);
        assert!(
            sections[1].candidates.is_empty(),
            "a terminator without a straight-line prefix is not a useful candidate"
        );
    }

    #[test]
    fn candidate_windows_exclude_x86_64_rip_relative_memory_operands() {
        // add rax, 1; lea rax, [rip]; sub rbx, 1
        let bytes = [
            0x48, 0x83, 0xc0, 0x01, 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xeb,
            0x01,
        ];
        let elf_bytes = build_minimal_elf64(&bytes, 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-candidate-rip-relative", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].candidates.len(), 2);
        assert_eq!(sections[0].candidates[0].start, 0x1000);
        assert_eq!(sections[0].candidates[0].end, 0x1004);
        assert_eq!(sections[0].candidates[1].start, 0x100b);
        assert_eq!(sections[0].candidates[1].end, 0x100f);
    }

    #[test]
    fn candidate_windows_inspect_detail_once_per_decoded_instruction() {
        // add rax, 1; call next; lea rax, [rip]; sub rbx, 1
        let bytes = [
            0x48, 0x83, 0xc0, 0x01, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x05, 0x00, 0x00,
            0x00, 0x00, 0x48, 0x83, 0xeb, 0x01,
        ];
        let elf_bytes = build_minimal_elf64(&bytes, 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-candidate-detail-cache", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");
        let mut detail_inspections = 0usize;

        let sections = find_candidate_windows_with_detail_provider(
            &X86OptimizationBackend::new(X86Arch::X86_64),
            &patcher,
            |cs, instruction, section_name| {
                detail_inspections += 1;
                inspect_capstone_instruction_detail(cs, instruction, section_name)
            },
        )
        .expect("candidate discovery should succeed");

        assert_eq!(
            detail_inspections, 4,
            "detail extraction should run once for each of the four decoded instructions"
        );
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].candidates.len(), 2);
        assert_eq!(sections[0].candidates[0].start, 0x1000);
        assert_eq!(sections[0].candidates[0].end, 0x1004);
        assert_eq!(sections[0].candidates[1].start, 0x1010);
        assert_eq!(sections[0].candidates[1].end, 0x1014);
    }

    #[test]
    fn candidate_windows_split_at_interior_direct_branch_target() {
        // add rax,1 (0x1000); add rax,1 (0x1004); add rax,1 (0x1008);
        // jne 0x1004 (0x100c). Without the target split this is one window
        // [0x1000,0x100e) whose interior contains the branch target 0x1004;
        // the reorder-safe rule must split it at that boundary.
        let text = [
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1000
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1004  <- jne target
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1008
            0x75, 0xf6, // jne 0x1004               @0x100c
        ];
        let elf_bytes = build_minimal_elf64(&text, 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-candidate-interior-target", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].candidates.len(), 2);
        assert_eq!(sections[0].candidates[0].start, 0x1000);
        assert_eq!(
            sections[0].candidates[0].end, 0x1004,
            "the run must end where the interior branch target begins"
        );
        assert_eq!(
            sections[0].candidates[1].start, 0x1004,
            "the branch target begins the second window, never its interior"
        );
        assert_eq!(sections[0].candidates[1].end, 0x100e);
    }

    #[test]
    fn candidate_windows_split_at_every_interior_direct_branch_target() {
        // Two interior targets in one straight-line run must produce three
        // windows, each beginning at a target and none holding one in its
        // interior — the split composes across every collected target.
        let text = [
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1000
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1004  <- jne target
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1008  <- jne target
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x100c
            0x75, 0xf2, // jne 0x1004               @0x1010
            0x75, 0xf4, // jne 0x1008               @0x1012
        ];
        let elf_bytes = build_minimal_elf64(&text, 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-candidate-two-targets", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].candidates.len(), 3);
        assert_eq!(sections[0].candidates[0].start, 0x1000);
        assert_eq!(sections[0].candidates[0].end, 0x1004);
        assert_eq!(sections[0].candidates[1].start, 0x1004);
        assert_eq!(sections[0].candidates[1].end, 0x1008);
        assert_eq!(sections[0].candidates[2].start, 0x1008);
        assert_eq!(sections[0].candidates[2].end, 0x1012);
    }

    #[test]
    fn candidate_windows_admit_window_that_begins_at_direct_branch_target() {
        // jmp 0x1002 (0x1000); add rax,1 (0x1002); add rax,1 (0x1006). The jump
        // target 0x1002 is fixed under rewrite, so a window may *begin* there —
        // the run must be admitted whole, not split or refused at its start.
        let text = [
            0xeb, 0x00, // jmp 0x1002               @0x1000  (target 0x1002)
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1002  <- window start == target
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1006
        ];
        let elf_bytes = build_minimal_elf64(&text, 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-candidate-start-target", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].candidates.len(), 1);
        assert_eq!(
            sections[0].candidates[0].start, 0x1002,
            "a window may begin exactly at a direct branch target"
        );
        assert_eq!(sections[0].candidates[0].end, 0x100a);
    }

    #[test]
    fn candidate_windows_split_at_interior_direct_branch_target_aarch64() {
        // Cross-arch coverage of the arm64 target-extraction path: a backward
        // cbz whose target lands inside a straight-line run must split it.
        let bytes = assemble_aarch64_test_bytes(&[
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            }, // 0x1000
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            }, // 0x1004  <- cbz target
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            }, // 0x1008
            Instruction::Cbz {
                rn: Register::X0,
                target: crate::ir::LabelId(0x1004),
            }, // 0x100c
        ]);
        let elf_bytes = build_minimal_elf64(&bytes, 0x1000, elf::abi::EM_AARCH64);
        let input = TempFile::new_bytes("s11-candidate-interior-target-a64", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("AArch64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].candidates.len(), 2);
        assert_eq!(sections[0].candidates[0].start, 0x1000);
        assert_eq!(sections[0].candidates[0].end, 0x1004);
        assert_eq!(
            sections[0].candidates[1].start, 0x1004,
            "the cbz target begins the second window"
        );
    }

    #[test]
    fn candidate_windows_split_at_cross_section_direct_branch_target() {
        // The global phase-1 target collection exists precisely so a branch in
        // one executable section can split a run in another. Here `.other` at
        // 0x2000 holds `jmp 0x1004`, which targets the interior of `.text`'s
        // straight-line run at 0x1000 — the run must split at 0x1004 even though
        // no branch lives in `.text` itself.
        let text = [
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1000
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1004  <- cross-section target
            0x48, 0x83, 0xc0, 0x01, // add rax, 1   @0x1008
        ];
        // jmp 0x1004 @0x2000: e9 <rel32>, next IP 0x2005, rel32 = 0x1004-0x2005
        // = -0x1001 = 0xffffefff (little-endian ff ef ff ff).
        let other = [0xe9, 0xff, 0xef, 0xff, 0xff];
        let elf_bytes = build_elf64_with_executable_sections(
            &[(".text", &text, 0x1000), (".other", &other, 0x2000)],
            elf::abi::EM_X86_64,
        );
        let input = TempFile::new_bytes("s11-candidate-cross-section", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        let text_section = sections
            .iter()
            .find(|s| s.section.name == ".text")
            .expect("the .text section must be present");
        assert_eq!(
            text_section.candidates.len(),
            2,
            "the cross-section jmp target must split .text's run"
        );
        assert_eq!(text_section.candidates[0].start, 0x1000);
        assert_eq!(text_section.candidates[0].end, 0x1004);
        assert_eq!(
            text_section.candidates[1].start, 0x1004,
            "the cross-section target begins the second window"
        );
        assert_eq!(text_section.candidates[1].end, 0x100c);
    }

    #[test]
    fn candidate_windows_flush_supported_run_at_section_end() {
        let bytes = [0x48, 0x89, 0xd8]; // mov rax, rbx
        let elf_bytes = build_minimal_elf64(&bytes, 0x4000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-candidate-section-end", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let sections =
            find_candidate_windows(&patcher).expect("candidate discovery should succeed");

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].candidates.len(), 1);
        assert_eq!(sections[0].candidates[0].start, 0x4000);
        assert_eq!(
            sections[0].candidates[0].end, 0x4003,
            "the exclusive end must come from the final decoded instruction"
        );
    }

    #[test]
    fn candidate_windows_fail_closed_when_section_is_only_partially_decoded() {
        let elf_bytes = build_minimal_elf64(&[0x48], 0x5000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-candidate-partial-decode", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("x86-64 ELF should parse");

        let error = find_candidate_windows(&patcher)
            .expect_err("an incomplete x86 prefix must not publish partial candidates")
            .to_string();

        assert!(error.contains("executable section '.text'"), "{error}");
        assert!(error.contains("x86-64 window 0x5000-0x5001"), "{error}");
        assert!(error.contains("decoded only 0 bytes"), "{error}");
        assert!(error.contains("first undecoded byte at 0x5000"), "{error}");
    }

    #[test]
    fn convert_capstone_op_for_optimization_rejects_unsupported_instruction() {
        let err = convert_capstone_op_for_optimization("fadd", "v0.4s, v1.4s, v2.4s", 0x1234)
            .expect_err("optimization conversion must reject unsupported non-NOP instructions");

        assert!(err.contains("fadd v0.4s, v1.4s, v2.4s"));
        assert!(err.contains("0x1234"));
        assert!(err.contains("--start-addr/--end-addr"));
        assert!(!err.contains("cannot optimize"));
    }

    #[test]
    fn convert_capstone_op_for_optimization_rejects_unnormalizable_mov_alias() {
        let err = convert_capstone_op_for_optimization("mov", "x0, #0x12345678", 0x4444)
            .expect_err("optimization conversion must reject multi-instruction mov aliases");

        assert!(err.contains("mov x0, #0x12345678"));
        assert!(err.contains("0x4444"));
        assert!(err.contains("--start-addr/--end-addr"));
        assert!(!err.contains("cannot optimize"));
    }

    #[test]
    fn ensure_window_fully_decoded_accepts_exact_match() {
        ensure_window_fully_decoded(8, 8, 0x1000, 0x1008)
            .expect("equal decoded and window byte counts must pass");
    }

    #[test]
    fn ensure_window_fully_decoded_rejects_partial_decode() {
        let err = ensure_window_fully_decoded(4, 8, 0x1000, 0x1008)
            .expect_err("a window Capstone only partially decoded must be rejected");

        assert!(err.contains("0x1000"));
        assert!(err.contains("0x1008"));
        assert!(err.contains("first undecoded byte at 0x1004"));
        assert!(err.contains("8 bytes"));
        assert!(err.contains("decoded only 4 bytes"));
    }

    #[test]
    fn ensure_window_fully_decoded_rejects_over_count() {
        let err = ensure_window_fully_decoded(12, 8, 0x1000, 0x1008)
            .expect_err("a window Capstone reported more bytes than holds must be rejected");

        assert!(err.contains("0x1000"));
        assert!(err.contains("0x1008"));
        assert!(err.contains("decoded 12 bytes"));
        assert!(err.contains("more than the window holds"));
    }

    #[test]
    fn x86_64_optimizer_accepts_narrow_register_aliases() {
        let elf_bytes = build_minimal_elf64(
            // Use the five-byte accumulator form so the two-instruction
            // window has room for any cheaper one-instruction dword-immediate
            // encoding that dynasm may choose.
            &[0x05, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00],
            0x1000,
            elf::abi::EM_X86_64,
        );
        let input = TempFile::new_bytes("s11-x86-64-eax-alias", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("read synthetic ELF");
        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_secs(5));
        opts.cost_metric = CostMetric::CodeSize;

        let output = resolve_output_path(input.path(), None, false).unwrap();
        optimize_elf_binary(&patcher, input.path(), 0x1000, 0x100a, &output, &opts)
            .expect("narrow register aliases should reach search");
    }

    #[test]
    fn x86_64_optimizer_rejects_architectural_setcc_before_search() {
        let elf_bytes = build_minimal_elf64(
            &[0x0f, 0x95, 0xc0, 0x0f, 0x95, 0xc0],
            0x1000,
            elf::abi::EM_X86_64,
        );
        let input = TempFile::new_bytes("s11-x86-64-setcc-byte", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("read synthetic ELF");
        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_secs(5));
        opts.cost_metric = CostMetric::CodeSize;

        let output = resolve_output_path(input.path(), None, false).unwrap();
        let err = optimize_elf_binary(&patcher, input.path(), 0x1000, 0x1006, &output, &opts)
            .expect_err("architectural byte SETcc should be rejected before search");
        let msg = err.to_string();
        assert!(
            msg.contains("failed to parse x86 instruction 'setne al'"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("cannot be represented until #75"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn x86_helpers_cover_error_and_optimization_paths() {
        assert!(parse_x86_operand("not-an-operand").is_err());
        assert!(x86_ir_from_mnemonic("add", "rax").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("add", "rax, nope").is_err());
        assert_eq!(
            x86_ir_from_mnemonic("mov", "ah, 0").unwrap(),
            Some(X86Instruction::MovImm {
                rd: X86Register::AH,
                imm: 0,
            })
        );

        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_secs(5));
        opts.solver_timeout = Duration::from_secs(5);
        opts.cost_metric = CostMetric::CodeSize;
        assert!(run_x86_enumerative(&[], 64, &opts, false, None).is_none());
        assert!(
            run_x86_enumerative(
                &[X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 1,
                }],
                64,
                &opts,
                false,
                None,
            )
            .is_none()
        );
        let optimized = run_x86_enumerative(
            &[
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
            ],
            64,
            &opts,
            false,
            None,
        )
        .expect("two identical writes can be shortened");
        assert_eq!(optimized.len(), 1);
    }

    #[test]
    fn x86_symbolic_code_size_preserves_downstream_flags_live() {
        let mut opts = options_for(Algorithm::Symbolic);
        opts.timeout = Some(Duration::from_secs(5));
        opts.solver_timeout = Duration::from_secs(5);
        opts.cost_metric = CostMetric::CodeSize;
        let target = [X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];

        let flags_dead = run_x86_symbolic(&target, 64, &opts, false, None, true)
            .expect("flags-dead one-instruction MOV can use an x86 code-size rewrite");
        assert_eq!(flags_dead.len(), 1);
        assert_ne!(flags_dead, target.to_vec());

        assert!(
            run_x86_symbolic(&target, 64, &opts, false, None, false).is_none(),
            "a caller can explicitly disable same-count symbolic code-size rewrites"
        );

        assert!(
            run_x86_symbolic(&target, 64, &opts, true, None, true).is_none(),
            "a same-count code-size rewrite must preserve EFLAGS when the following code reads them"
        );
    }

    #[test]
    fn x86_symbolic_backend_preserves_capstone_register_views() {
        let backend = X86OptimizationBackend::new(X86Arch::X86_64);
        let cs = backend.disassembler().unwrap();
        let mut opts = options_for(Algorithm::Symbolic);
        opts.timeout = Some(Duration::from_secs(5));
        opts.solver_timeout = Duration::from_secs(5);
        opts.cost_metric = CostMetric::CodeSize;
        let context = OptimizationContext {
            downstream_flags_live: false,
            downstream_live_regs: DownstreamLiveRegs::Unknown,
        };

        // 66 b8 00 00 = mov ax, 0. The register view survives conversion.
        let partial_instructions = cs.disasm_all(&[0x66, 0xb8, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!(
            backend.convert_ir(&partial_instructions).unwrap(),
            vec![X86Instruction::MovImm {
                rd: X86Register::AX,
                imm: 0,
            }]
        );

        // 66 83 e0 00 = and ax, 0; 74 00 = je +0. The partial-width AND in
        // the rewritable prefix also remains precise before a pinned Jcc.
        let partial_with_jcc_instructions = cs
            .disasm_all(&[0x66, 0x83, 0xe0, 0x00, 0x74, 0x00], 0x1000)
            .unwrap();
        assert_eq!(
            backend.convert_ir(&partial_with_jcc_instructions).unwrap(),
            vec![
                X86Instruction::AndImm {
                    rd: X86Register::AX,
                    imm: 0,
                },
                X86Instruction::Jcc {
                    cond: isa::x86::X86Condition::E,
                },
            ]
        );

        // b8 00 00 00 00 = mov eax, 0. A dword write zero-extends RAX, so
        // symbolic CodeSize search may safely replace it with a shorter
        // same-count dword zeroing instruction.
        let dword_instructions = cs
            .disasm_all(&[0xb8, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .unwrap();
        let dword_ir = backend.convert_ir(&dword_instructions).unwrap();
        assert_eq!(
            dword_ir,
            vec![X86Instruction::MovImm {
                rd: X86Register::EAX,
                imm: 0,
            }]
        );
        let dword_optimized = backend
            .run_search(&dword_ir, &dword_instructions, &opts, context.clone())
            .unwrap()
            .expect("x86-64 EAX should allow a same-count code-size rewrite");
        assert_eq!(dword_optimized.len(), dword_ir.len());
        assert_ne!(dword_optimized, dword_ir);
        assert_eq!(
            dword_optimized[0].destination_operand(),
            Some(X86Register::EAX),
            "the rewrite must retain the zero-extending dword destination view"
        );

        // 48 c7 c0 00 00 00 00 = mov rax, 0
        let full_instructions = cs
            .disasm_all(&[0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .unwrap();
        let full_ir = backend.convert_ir(&full_instructions).unwrap();
        assert!(
            backend
                .run_search(&full_ir, &full_instructions, &opts, context)
                .unwrap()
                .is_some(),
            "full-width x86-64 operands should keep the same-count code-size rewrite"
        );
    }

    /// Dispatch coverage: `run_search` with `Algorithm::Stochastic` must route
    /// to `run_x86_stochastic` and return `Ok`. Asserts only that the arm runs
    /// and yields a well-typed result; a stochastic search is non-deterministic
    /// in shape so we do not pin a specific optimization.
    #[test]
    fn x86_run_search_dispatches_stochastic_arm() {
        let backend = X86OptimizationBackend::new(X86Arch::X86_64);
        let cs = backend.disassembler().unwrap();
        let mut opts = options_for(Algorithm::Stochastic);
        opts.timeout = Some(Duration::from_millis(200));
        opts.solver_timeout = Duration::from_millis(200);
        opts.iterations = 50;
        opts.cost_metric = CostMetric::CodeSize;
        let context = OptimizationContext {
            downstream_flags_live: false,
            downstream_live_regs: DownstreamLiveRegs::Unknown,
        };

        // 48 c7 c0 00 00 00 00 = mov rax, 0 (full-width source operand).
        let instructions = cs
            .disasm_all(&[0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .unwrap();
        let ir = backend.convert_ir(&instructions).unwrap();
        let result = backend.run_search(&ir, &instructions, &opts, context);
        let optimized = result.expect("stochastic dispatch arm must return Ok");
        if let Some(seq) = optimized {
            assert!(
                !seq.is_empty(),
                "a returned stochastic rewrite must be non-empty"
            );
        }
    }

    /// Dispatch coverage: `run_search` with `Algorithm::Enumerative` must route
    /// to `run_x86_enumerative` and return `Ok`. A duplicate `mov rax, 0;
    /// mov rax, 0` window has a dead first write, so the code-size enumerative
    /// search deterministically collapses it to a single instruction.
    #[test]
    fn x86_run_search_dispatches_enumerative_arm() {
        let backend = X86OptimizationBackend::new(X86Arch::X86_64);
        let cs = backend.disassembler().unwrap();
        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_secs(5));
        opts.solver_timeout = Duration::from_secs(5);
        opts.cost_metric = CostMetric::CodeSize;
        let context = OptimizationContext {
            downstream_flags_live: false,
            downstream_live_regs: DownstreamLiveRegs::Unknown,
        };

        // 48 c7 c0 00 00 00 00 = mov rax, 0, written twice. The first write is
        // dead, so the two-instruction window collapses to one.
        let instructions = cs
            .disasm_all(
                &[
                    0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
                    0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
                ],
                0x1000,
            )
            .unwrap();
        let ir = backend.convert_ir(&instructions).unwrap();
        let optimized = backend
            .run_search(&ir, &instructions, &opts, context)
            .expect("enumerative dispatch arm must return Ok")
            .expect("enumerative arm should collapse the duplicate-write window");
        assert!(
            optimized.len() < ir.len(),
            "enumerative rewrite should be shorter than the duplicate window"
        );
    }

    /// Dispatch coverage: the `Hybrid` and `Llm` arms are AArch64-only and must
    /// be rejected by `run_search` even when a programmatic caller bypasses the
    /// CLI-layer gate.
    #[test]
    fn x86_run_search_rejects_hybrid_arm() {
        let backend = X86OptimizationBackend::new(X86Arch::X86_64);
        let cs = backend.disassembler().unwrap();
        let context = OptimizationContext {
            downstream_flags_live: false,
            downstream_live_regs: DownstreamLiveRegs::Unknown,
        };

        // 48 c7 c0 00 00 00 00 = mov rax, 0.
        let instructions = cs
            .disasm_all(&[0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .unwrap();
        let ir = backend.convert_ir(&instructions).unwrap();

        for algorithm in [Algorithm::Hybrid, Algorithm::Llm] {
            let opts = options_for(algorithm);
            let err = backend
                .run_search(&ir, &instructions, &opts, context.clone())
                .expect_err("hybrid/llm arms are AArch64-only and must be rejected");
            assert!(
                err.to_string().contains("AArch64-only"),
                "unexpected error for {:?}: {}",
                algorithm,
                err
            );
        }
    }

    /// Regression: x86 enumerative search must preserve a trailing Jcc while
    /// optimizing the straight-line prefix.
    #[test]
    fn x86_enumerative_can_optimize_jcc_terminated_window() {
        use isa::x86::X86Condition;
        // Two redundant MovImms followed by a Jcc terminator. Search
        // should collapse the prefix and re-attach the original Jcc.
        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_secs(5));
        opts.solver_timeout = Duration::from_secs(5);
        opts.cost_metric = CostMetric::CodeSize;
        let optimized = run_x86_enumerative(
            &[
                X86Instruction::MovImm {
                    rd: X86Register::RBX,
                    imm: 1,
                },
                X86Instruction::MovImm {
                    rd: X86Register::RBX,
                    imm: 1,
                },
                X86Instruction::Jcc {
                    cond: X86Condition::E,
                },
            ],
            64,
            &opts,
            false,
            None,
        )
        .expect("redundant prefix + Jcc must be optimizable");
        // Expect: [MovImm RBX, 1, Jcc E].
        assert_eq!(optimized.len(), 2);
        match optimized[0] {
            X86Instruction::MovImm { rd, imm } => {
                assert_eq!(rd, X86Register::RBX);
                assert_eq!(imm, 1);
            }
            ref other => panic!("expected MovImm RBX, 1, got {:?}", other),
        }
        assert!(matches!(
            optimized[1],
            X86Instruction::Jcc {
                cond: X86Condition::E
            }
        ));
    }

    #[test]
    fn x86_enumerative_collapses_without_rax_or_rdi_in_target() {
        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_secs(5));
        opts.solver_timeout = Duration::from_secs(5);
        opts.cost_metric = CostMetric::CodeSize;
        let target = vec![
            X86Instruction::MovImm {
                rd: X86Register::RBX,
                imm: 1,
            },
            X86Instruction::MovImm {
                rd: X86Register::RBX,
                imm: 1,
            },
        ];
        let config = build_x86_enumerative_search_config(&target, &opts);
        assert_eq!(config.x86_available_registers, vec![X86Register::RBX]);
        assert!(
            !config.x86_available_registers.contains(&X86Register::RAX),
            "RAX must not be injected into the duplicate-RBX search pool"
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::RDI),
            "RDI must not be injected into the duplicate-RBX search pool"
        );
        assert!(
            config.available_immediates.contains(&1),
            "immediate pool must preserve the fixture immediate"
        );

        let optimized = run_x86_enumerative(&target, 64, &opts, false, None)
            .expect("two identical RBX writes can be shortened");
        assert_eq!(optimized.len(), 1);
        match optimized[0] {
            X86Instruction::MovImm { rd, imm } => {
                assert_eq!(rd, X86Register::RBX);
                assert_eq!(imm, 1);
            }
            ref other => panic!("expected MovImm RBX, 1, got {:?}", other),
        }
    }

    /// Regression (PR #384): the trait-backed enumerative path must draw
    /// candidates from the target's own registers/immediates. R10 is outside
    /// `default_x86_registers()` and `-1` outside `default_x86_immediates()`,
    /// so the fixed-pool config could not express the obvious one-instruction
    /// rewrite and reported no optimization.
    #[test]
    fn x86_enumerative_finds_rewrite_for_nondefault_register_and_immediate() {
        let mut opts = options_for(Algorithm::Enumerative);
        // No wall-clock deadline: the bounded length-1 search terminates on
        // its own and a finite timeout flakes under coverage instrumentation.
        opts.timeout = None;
        opts.solver_timeout = Duration::from_secs(30);
        opts.cost_metric = CostMetric::CodeSize;
        let optimized = run_x86_enumerative(
            &[
                X86Instruction::MovImm {
                    rd: X86Register::R10,
                    imm: -1,
                },
                X86Instruction::MovImm {
                    rd: X86Register::R10,
                    imm: -1,
                },
            ],
            64,
            &opts,
            false,
            None,
        )
        .expect("two identical R10/-1 writes must collapse to one");
        assert_eq!(optimized.len(), 1);
        assert_eq!(optimized[0].destination(), Some(X86Register::R10));
    }

    /// Regression (issue #458): stochastic search must consume the
    /// target-derived x86 register pool end-to-end, not just expose it in the
    /// config. R10 is outside `default_x86_registers()`, so a successful
    /// rewrite proves the search backend can synthesize high-register
    /// candidates.
    #[test]
    fn x86_stochastic_finds_rewrite_for_r10_only_target() {
        let mut opts = options_for(Algorithm::Stochastic);
        opts.timeout = None;
        opts.solver_timeout = Duration::from_secs(30);
        opts.cost_metric = CostMetric::InstructionCount;
        opts.iterations = 50_000;
        opts.seed = Some(7);

        let target = r10_zeroing_target();
        let optimized = run_x86_stochastic(&target, 64, &opts, false, None)
            .expect("two identical R10 zeroing writes must collapse to one");

        assert_single_r10_rewrite(&optimized);
    }

    /// Regression (issue #458): symbolic search must also use the
    /// target-derived x86 register pool when synthesizing candidates. This
    /// closes the end-to-end gap left by config-only coverage for high x86-64
    /// registers.
    #[test]
    fn x86_symbolic_finds_rewrite_for_r10_only_target() {
        let mut opts = options_for(Algorithm::Symbolic);
        opts.timeout = None;
        opts.solver_timeout = Duration::from_secs(30);
        opts.search_mode = SearchMode::Linear;
        opts.cost_metric = CostMetric::InstructionCount;

        let target = r10_zeroing_target();
        let optimized = run_x86_symbolic(&target, 64, &opts, false, None, false)
            .expect("two identical R10 zeroing writes must collapse to one");

        assert_single_r10_rewrite(&optimized);
    }

    /// Regression (PR #384): the enumerative config must be target-derived and
    /// must thread `--cores` (the trait-backed search is rayon-parallel and
    /// honours `config.cores`, but the old builder left it `None`).
    #[test]
    fn build_x86_enumerative_search_config_is_target_derived_and_honors_cores() {
        let mut opts = options_for(Algorithm::Enumerative);
        opts.cores = Some(3);
        opts.solver_timeout = Duration::from_millis(37);
        let target = vec![
            X86Instruction::MovImm {
                rd: X86Register::R11,
                imm: -1,
            },
            X86Instruction::AddReg {
                rd: X86Register::R12,
                rs: X86Register::R11,
            },
            X86Instruction::CmpImm {
                rn: X86Register::R10,
                imm: 1,
            },
        ];
        let config = build_x86_enumerative_search_config(&target, &opts);
        assert_eq!(config.cores, Some(3), "--cores must be threaded through");
        assert_eq!(config.solver_timeout, Some(Duration::from_millis(37)));
        assert!(
            config.x86_available_registers.contains(&X86Register::R11)
                && config.x86_available_registers.contains(&X86Register::R12),
            "register pool must be derived from the target"
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::R10),
            "source-only registers must not become writable candidates"
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::RAX),
            "register pool must not fall back to the fixed default pool"
        );
        assert!(
            config.available_immediates.contains(&-1),
            "immediate pool must include -1"
        );
    }

    #[test]
    fn build_x86_enumerative_search_config_reuses_stochastic_base_and_overrides() {
        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_millis(31));
        opts.solver_timeout = Duration::from_millis(37);
        opts.beta = 7.25;
        opts.iterations = 987;
        opts.seed = Some(123);
        opts.cost_metric = CostMetric::Latency;
        opts.verbose = true;
        opts.cores = Some(4);

        let target = vec![
            X86Instruction::MovImm {
                rd: X86Register::R11,
                imm: -5,
            },
            X86Instruction::AddReg {
                rd: X86Register::R12,
                rs: X86Register::R11,
            },
            X86Instruction::CmpImm {
                rn: X86Register::R10,
                imm: 3,
            },
        ];
        let config = build_x86_enumerative_search_config(&target, &opts);

        assert_eq!(
            config.x86_available_registers,
            vec![X86Register::R11, X86Register::R12]
        );
        // The enumerative builder layers a target-derived immediate pool over the
        // stochastic base, so the operand immediates appear here.
        assert!(config.available_immediates.contains(&-5));
        assert!(config.available_immediates.contains(&3));
        assert_eq!(config.cores, Some(4));
        assert_eq!(config.cost_metric, CostMetric::Latency);
        assert_eq!(config.timeout, Some(Duration::from_millis(31)));
        assert!(config.verbose);

        // The enumerative builder reuses the stochastic builder, so the
        // stochastic fields are populated from the CLI options. They are inert
        // for enumerative search (it never reads `config.stochastic`), but the
        // shared base means the config still honors --solver-timeout for SMT
        // verification queries.
        assert_eq!(config.stochastic.beta, 7.25);
        assert_eq!(config.stochastic.iterations, 987);
        assert_eq!(config.stochastic.seed, Some(123));
        assert_eq!(config.solver_timeout, Some(Duration::from_millis(37)));
    }

    #[test]
    fn print_wrappers_delegate_to_report_without_panicking() {
        // The pure `report::format_*` seams are asserted in `crate::report`'s own
        // unit tests and the `report` integration test. Here we only exercise
        // the thin stdout wrappers that still live in the binary.
        let timings = LlmTimings {
            codex_calls: 1,
            codex_time: Duration::from_millis(2),
            verifications: 1,
            verify_time: Duration::from_millis(3),
            smt_calls: 2,
            smt_formula_bytes_total: 2_048,
            smt_formula_bytes_max: 1_536,
        };
        print_llm_timings(&timings, Duration::from_millis(10));

        let mut ledger = UnsupportedMnemonicLedger::new();
        print_unsupported_mnemonic_ledger(&ledger);
        ledger.record("ldr");
        print_unsupported_mnemonic_ledger(&ledger);

        let mut stats = SearchStatistics::new(Algorithm::Stochastic);
        stats.candidates_pruned_by_cost = 3;
        stats.iterations = 10;
        stats.accepted_proposals = 5;
        print_search_statistics(&stats);
    }

    /// Regression for issue #243: the hybrid `SearchConfig` must inherit
    /// `options.timeout` from the CLI, otherwise workers run with the
    /// default 60 s timeout and the per-worker search loop is unbounded
    /// (the coordinator-level deadline is now the primary cancel path, but
    /// this stays as a backstop).
    #[test]
    fn build_hybrid_search_config_propagates_timeout() {
        let mut opts = options_for(Algorithm::Hybrid);
        opts.timeout = Some(Duration::from_millis(7));
        opts.solver_timeout = Duration::from_millis(17);

        let regs = vec![Register::X0];
        let imms = vec![0, 1];
        let config = build_hybrid_search_config(&opts, regs, imms);

        assert_eq!(config.timeout, Some(Duration::from_millis(7)));
        assert_eq!(config.solver_timeout, Some(Duration::from_millis(17)));

        // None should propagate too.
        opts.timeout = None;
        let config = build_hybrid_search_config(&opts, vec![Register::X0], vec![0]);
        assert_eq!(config.timeout, None);
    }

    #[test]
    fn build_enumerative_search_config_propagates_solver_timeout() {
        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_millis(9));
        opts.solver_timeout = Duration::from_millis(13);
        opts.cost_metric = CostMetric::Latency;
        opts.verbose = true;
        opts.cores = Some(2);

        let regs = vec![Register::X0, Register::X1];
        let imms = vec![0, 7];
        let config = build_enumerative_search_config(&opts, regs.clone(), imms.clone());

        assert_eq!(config.solver_timeout, Some(Duration::from_millis(13)));
        assert_eq!(config.cost_metric, CostMetric::Latency);
        assert_eq!(config.timeout, Some(Duration::from_millis(9)));
        assert!(config.verbose);
        assert_eq!(config.available_registers, regs);
        assert_eq!(config.available_immediates, imms);
        assert_eq!(config.cores, Some(2));
    }

    #[test]
    fn build_stochastic_search_config_propagates_solver_timeout() {
        let mut opts = options_for(Algorithm::Stochastic);
        opts.timeout = Some(Duration::from_millis(11));
        opts.solver_timeout = Duration::from_millis(17);
        opts.beta = 2.5;
        opts.iterations = 123;
        opts.seed = Some(99);
        opts.cost_metric = CostMetric::Latency;
        opts.verbose = true;

        let regs = vec![Register::X0, Register::X1];
        let imms = vec![0, 7];
        let config = build_stochastic_search_config(&opts, regs.clone(), imms.clone());

        assert_stochastic_config_matches_options(&config, &opts);
        assert_eq!(config.available_registers, regs);
        assert_eq!(config.available_immediates, imms);
    }

    #[test]
    fn build_aarch64_base_search_config_sets_shared_fields_only() {
        // The base seam sets exactly the fields every AArch64 algorithm shares
        // — cost metric, overall + SMT solver timeouts, verbosity, and the
        // register/immediate pools — and applies no algorithm-specific layer,
        // so `cores` (the enumerative layer) stays at its default.
        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_millis(8));
        opts.solver_timeout = Duration::from_millis(12);
        opts.cost_metric = CostMetric::CodeSize;
        opts.verbose = true;

        let regs = vec![Register::X2, Register::X5];
        let imms = vec![3, 4, 9];
        let config = build_aarch64_base_search_config(&opts, regs.clone(), imms.clone());

        assert_eq!(config.timeout, Some(Duration::from_millis(8)));
        assert_eq!(config.solver_timeout, Some(Duration::from_millis(12)));
        assert_eq!(config.cost_metric, CostMetric::CodeSize);
        assert!(config.verbose);
        assert_eq!(config.available_registers, regs);
        assert_eq!(config.available_immediates, imms);
        // No algorithm layer applied: cores is left at the SearchConfig default.
        assert_eq!(config.cores, SearchConfig::default().cores);
    }

    /// Regression for issue #243, generalised: every AArch64 algorithm builder
    /// must propagate the shared base fields (`--timeout`, `--solver-timeout`,
    /// cost metric, verbosity, register/immediate pools) identically. They all
    /// route through `build_aarch64_base_search_config`, so a future arm cannot
    /// silently drop one the way the hybrid path once dropped `--timeout`.
    #[test]
    fn aarch64_algorithm_builders_share_one_base_config() {
        let mut opts = options_for(Algorithm::Hybrid);
        opts.timeout = Some(Duration::from_millis(21));
        opts.solver_timeout = Duration::from_millis(19);
        opts.cost_metric = CostMetric::Latency;
        opts.verbose = true;

        let regs = vec![Register::X0, Register::X3];
        let imms = vec![0, 5, 42];

        let assert_base = |config: &SearchConfig| {
            assert_eq!(config.timeout, Some(Duration::from_millis(21)));
            assert_eq!(config.solver_timeout, Some(Duration::from_millis(19)));
            assert_eq!(config.cost_metric, CostMetric::Latency);
            assert!(config.verbose);
            assert_eq!(config.available_registers, regs);
            assert_eq!(config.available_immediates, imms);
        };

        assert_base(&build_aarch64_base_search_config(
            &opts,
            regs.clone(),
            imms.clone(),
        ));
        assert_base(&build_stochastic_search_config(
            &opts,
            regs.clone(),
            imms.clone(),
        ));
        assert_base(&build_enumerative_search_config(
            &opts,
            regs.clone(),
            imms.clone(),
        ));
        assert_base(&build_hybrid_search_config(
            &opts,
            regs.clone(),
            imms.clone(),
        ));
        assert_base(&build_symbolic_search_config(
            &opts,
            regs.clone(),
            imms.clone(),
        ));
        assert_base(&build_llm_search_config(&opts, regs.clone(), imms.clone()));
    }

    #[test]
    fn build_x86_stochastic_search_config_propagates_solver_timeout() {
        let mut opts = options_for(Algorithm::Stochastic);
        opts.timeout = Some(Duration::from_millis(13));
        opts.solver_timeout = Duration::from_millis(19);
        opts.beta = 3.5;
        opts.iterations = 456;
        opts.seed = Some(101);
        opts.cost_metric = CostMetric::CodeSize;
        opts.verbose = true;

        let target = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RSP,
                rs: X86Register::R11,
            },
            X86Instruction::CmpReg {
                rn: X86Register::RBP,
                rs: X86Register::R12,
            },
            X86Instruction::CmpImm {
                rn: X86Register::R10,
                imm: 1,
            },
            X86Instruction::MovImm {
                rd: X86Register::R11,
                imm: -1,
            },
            X86Instruction::AddReg {
                rd: X86Register::R12,
                rs: X86Register::RSP,
            },
        ];
        let config = build_x86_stochastic_search_config(&target, &opts);

        assert_stochastic_config_matches_options(&config, &opts);
        assert_eq!(
            config.x86_available_registers,
            vec![X86Register::R11, X86Register::R12]
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::RSP),
            "stochastic register pool must not make RSP writable"
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::RBP),
            "stochastic register pool must not make RBP writable"
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::R10),
            "stochastic register pool must not make source-only registers writable"
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::RAX),
            "stochastic register pool must be derived from the target"
        );
        assert!(
            build_x86_stochastic_search_config(
                &[
                    X86Instruction::CmpImm {
                        rn: X86Register::RSP,
                        imm: 1,
                    },
                    X86Instruction::CmpReg {
                        rn: X86Register::RBP,
                        rs: X86Register::RBP,
                    },
                ],
                &opts,
            )
            .x86_available_registers
            .is_empty(),
            "all stack/frame targets must not fall back to writable defaults"
        );
        assert_eq!(
            config.available_immediates,
            isa::x86::default_x86_immediates()
        );
    }

    #[test]
    fn build_x86_symbolic_search_config_is_target_derived_and_preserves_symbolic_options() {
        let mut opts = options_for(Algorithm::Symbolic);
        opts.timeout = Some(Duration::from_millis(23));
        opts.solver_timeout = Duration::from_millis(29);
        opts.search_mode = SearchMode::Binary;
        opts.cost_metric = CostMetric::Latency;
        opts.verbose = true;

        let target = vec![
            X86Instruction::CmpImm {
                rn: X86Register::RSP,
                imm: 1,
            },
            X86Instruction::CmpReg {
                rn: X86Register::RBP,
                rs: X86Register::RBP,
            },
            X86Instruction::CmpImm {
                rn: X86Register::R10,
                imm: 1,
            },
            X86Instruction::CmpImm {
                rn: X86Register::R11,
                imm: -1,
            },
            X86Instruction::MovImm {
                rd: X86Register::R12,
                imm: 0,
            },
        ];
        let config = build_x86_symbolic_search_config(&target, &opts, true);

        assert_eq!(config.x86_available_registers, vec![X86Register::R12]);
        assert!(
            !config.x86_available_registers.contains(&X86Register::RSP),
            "symbolic register pool must not make RSP writable"
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::RBP),
            "symbolic register pool must not make RBP writable"
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::R10)
                && !config.x86_available_registers.contains(&X86Register::R11),
            "symbolic register pool must not make source-only registers writable"
        );
        assert!(
            !config.x86_available_registers.contains(&X86Register::RAX),
            "symbolic register pool must be derived from the target"
        );
        assert!(
            build_x86_symbolic_search_config(
                &[
                    X86Instruction::CmpImm {
                        rn: X86Register::RSP,
                        imm: 1,
                    },
                    X86Instruction::CmpReg {
                        rn: X86Register::RBP,
                        rs: X86Register::RBP,
                    },
                ],
                &opts,
                true,
            )
            .x86_available_registers
            .is_empty(),
            "all stack/frame targets must not fall back to writable defaults"
        );
        assert_eq!(config.symbolic.search_mode, SearchMode::Binary);
        assert_eq!(config.solver_timeout, Some(Duration::from_millis(29)));
        assert_eq!(config.cost_metric, CostMetric::Latency);
        assert_eq!(config.timeout, Some(Duration::from_millis(23)));
        assert!(config.verbose);
        assert_eq!(
            config.available_immediates,
            isa::x86::default_x86_immediates()
        );
        assert!(config.x86_same_count_code_size_allowed);
        assert!(
            !build_x86_symbolic_search_config(&target, &opts, false)
                .x86_same_count_code_size_allowed
        );
    }

    #[test]
    fn run_optimization_fast_modes_do_not_require_codex_or_long_searches() {
        let target = [Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }];

        for algorithm in [
            Algorithm::Stochastic,
            Algorithm::Symbolic,
            Algorithm::Hybrid,
            Algorithm::Llm,
        ] {
            let options = options_for(algorithm);
            let _ = run_optimization(&target, &options, true, None).unwrap();
        }
        assert!(
            run_optimization(&[], &options_for(Algorithm::Enumerative), true, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn run_optimization_uses_downstream_flags_dead_context() {
        let target = [
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 7,
            },
        ];
        let mut options = options_for(Algorithm::Symbolic);
        options.timeout = Some(Duration::from_secs(10));
        options.solver_timeout = Duration::from_secs(10);

        let flags_dead = run_optimization(&target, &options, false, None)
            .expect("symbolic search should run with flags dead")
            .expect("flags-dead window should drop redundant cmp");
        assert_eq!(flags_dead.len(), 1);
        assert!(
            !flags_dead.iter().any(Instruction::modifies_flags),
            "optimized sequence should not need to preserve NZCV when downstream flags are dead: {:?}",
            flags_dead
        );
    }

    #[test]
    fn issue_69_acceptance_find_shorter_preserves_terminator() {
        // Build a prefix with a redundant move that the search can shorten,
        // then a `ret` terminator. The result must keep `ret` bit-identical.
        //
        // This exercises the same code path as `run_optimization`:
        //   1. `split_terminator` peels off the trailing `ret`.
        //   2. The search runs on the prefix only.
        //   3. The terminator is re-attached to the optimized prefix.
        use crate::search::SearchAlgorithm;
        use crate::search::config::SearchConfig;

        let terminator = Instruction::Ret { rn: Register::X30 };
        let seq = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X0,
            },
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X0,
            },
            terminator,
        ];

        let (prefix, term) = split_terminator(&seq);
        assert_eq!(term, Some(&terminator), "split must recognize ret");

        let live_out =
            aarch64_search_inputs::live_out_for_optimization_prefix(prefix, term, true, None);
        let config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1]);
        let mut search = EnumerativeSearch::<isa::AArch64>::new();
        let result = search.search(prefix, &live_out, &config);

        if let Some(shorter_prefix) = result.optimized_sequence {
            // Re-attach the terminator and verify it survives bit-identical.
            let mut shorter = shorter_prefix;
            shorter.push(terminator);
            assert!(
                shorter.len() < seq.len(),
                "must return a strictly shorter sequence; got {:?}",
                shorter
            );
            assert_eq!(
                shorter.last(),
                Some(&terminator),
                "terminator must be preserved bit-identical; got {:?}",
                shorter
            );
        }
        // No shorter form found is acceptable; the assertion above fires
        // only when a shortening was actually achieved.
    }

    #[test]
    fn equivalence_rejects_prefix_candidate_that_clobbers_cbz_source() {
        // End-to-end regression for the live-out contract used by
        // `run_optimization`. Target: a prefix that writes only x2, followed
        // by `cbz x0, ...` as the fixed terminator. A candidate that also
        // writes x0 as scratch would be accepted under a naive live-out of
        // just prefix destinations ({x2}), but the reattached cbz reads x0
        // — so the optimizer must reject it. With the live-out built by
        // `live_out_for_optimization_prefix`, x0 is included and the
        // clobbering candidate is correctly rejected.
        use crate::semantics::EquivalenceConfig;
        use crate::semantics::equivalence::{EquivalenceResult, check_equivalence_with_config};

        let terminator = Instruction::Cbz {
            rn: Register::X0,
            target: crate::ir::LabelId(0x1000),
        };
        let target = vec![
            Instruction::MovImm {
                rd: Register::X2,
                imm: 5,
            },
            terminator,
        ];
        let candidate_clobbers_x0 = vec![
            Instruction::MovImm {
                rd: Register::X2,
                imm: 5,
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 99,
            },
            terminator,
        ];

        let (prefix, term) = split_terminator(&target);
        let live_out =
            aarch64_search_inputs::live_out_for_optimization_prefix(prefix, term, true, None);
        assert!(
            live_out.contains_register(Register::X0),
            "live_out_for_optimization_prefix must mark x0 live when the \
             terminator reads x0; got {:?}",
            live_out,
        );

        let config = EquivalenceConfig::default().live_out(live_out);
        let result = check_equivalence_with_config(&target, &candidate_clobbers_x0, &config);
        assert!(
            matches!(
                result,
                EquivalenceResult::NotEquivalent | EquivalenceResult::NotEquivalentFast(_),
            ),
            "candidate that clobbers x0 must be rejected because the \
             reattached cbz reads x0; got {:?}",
            result,
        );
    }

    #[test]
    fn x86arch_detectedarch_roundtrip() {
        assert_eq!(DetectedArch::from(X86Arch::X86_64), DetectedArch::X86_64);
        assert_eq!(DetectedArch::from(X86Arch::X86_32), DetectedArch::X86_32);
        assert_eq!(
            X86Arch::try_from(DetectedArch::X86_64).unwrap(),
            X86Arch::X86_64
        );
        assert_eq!(
            X86Arch::try_from(DetectedArch::X86_32).unwrap(),
            X86Arch::X86_32
        );
        assert!(X86Arch::try_from(DetectedArch::Aarch64).is_err());
        assert_eq!(X86Arch::X86_64.width(), 64);
        assert_eq!(X86Arch::X86_32.width(), 32);
    }
}
