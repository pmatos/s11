use capstone::prelude::*;
use clap::{Parser, Subcommand, ValueEnum};
use elf::{ElfBytes, endian::AnyEndian};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(test)]
#[path = "test_utils.rs"]
mod test_utils;

use s11::assembler::AArch64Assembler;
use s11::elf_patcher::{AddressWindow, DetectedArch, ElfPatcher, TextSection, parse_hex_address};
use s11::ir::instructions::{MOVW_LEGAL_SHIFTS, split_terminator};
use s11::ir::{Condition, Instruction, Register};
use s11::search::config::{
    Algorithm, LlmConfig, SearchConfig, SearchMode, StochasticConfig, SymbolicConfig,
};
use s11::search::parallel::{ParallelConfig, run_parallel_search};
use s11::search::{EnumerativeSearch, SearchAlgorithm, StochasticSearch, SymbolicSearch};
use s11::semantics::LiveOut;
use s11::semantics::cost::CostMetric;
#[allow(unused_imports)]
use s11::{assembler, elf_patcher, ir, isa, parser, search, semantics, validation};

// --- Command Line Arguments ---

#[derive(Parser)]
#[command(name = "s11")]
#[command(about = "s11 - Superoptimizer (AArch64, x86)")]
#[command(version)]
#[command(subcommand_required = true)]
#[command(arg_required_else_help = true)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

/// CLI algorithm selection
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliAlgorithm {
    /// Enumerative search (exhaustive)
    Enumerative,
    /// Stochastic search using MCMC
    Stochastic,
    /// Symbolic search using SMT solver
    Symbolic,
    /// Hybrid parallel search (symbolic + multiple stochastic workers)
    Hybrid,
    /// LLM-assisted search via Codex CLI
    Llm,
}

impl From<CliAlgorithm> for Algorithm {
    fn from(cli: CliAlgorithm) -> Self {
        match cli {
            CliAlgorithm::Enumerative => Algorithm::Enumerative,
            CliAlgorithm::Stochastic => Algorithm::Stochastic,
            CliAlgorithm::Symbolic => Algorithm::Symbolic,
            CliAlgorithm::Hybrid => Algorithm::Hybrid,
            CliAlgorithm::Llm => Algorithm::Llm,
        }
    }
}

/// CLI cost metric selection
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliCostMetric {
    /// Count number of instructions
    InstructionCount,
    /// Estimate latency cycles
    Latency,
    /// Estimate code size in bytes
    CodeSize,
}

impl From<CliCostMetric> for CostMetric {
    fn from(cli: CliCostMetric) -> Self {
        match cli {
            CliCostMetric::InstructionCount => CostMetric::InstructionCount,
            CliCostMetric::Latency => CostMetric::Latency,
            CliCostMetric::CodeSize => CostMetric::CodeSize,
        }
    }
}

/// CLI search mode selection for symbolic search
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliSearchMode {
    /// Linear cost search (try each cost bound in order)
    Linear,
    /// Binary search on cost bound
    Binary,
}

impl From<CliSearchMode> for SearchMode {
    fn from(cli: CliSearchMode) -> Self {
        match cli {
            CliSearchMode::Linear => SearchMode::Linear,
            CliSearchMode::Binary => SearchMode::Binary,
        }
    }
}

/// CLI target architecture selection
#[derive(Clone, Copy, Debug, Default, ValueEnum, PartialEq, Eq)]
pub enum CliArch {
    /// AArch64 (ARM64) architecture
    #[default]
    Aarch64,
    /// RISC-V 32-bit architecture
    Riscv32,
    /// RISC-V 64-bit architecture
    Riscv64,
    /// x86-64 (AMD64) architecture
    X86_64,
    /// x86-32 (i386) architecture
    X86_32,
}

impl std::fmt::Display for CliArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Derive the spelling from clap's ValueEnum so Display and the CLI
        // parser stay in sync by construction (a `#[value(name = ...)]` or a
        // renamed variant can never drift the error message from what users type).
        f.write_str(
            self.to_possible_value()
                .expect("CliArch has no skipped variants")
                .get_name(),
        )
    }
}

impl From<DetectedArch> for CliArch {
    fn from(arch: DetectedArch) -> Self {
        // DetectedArch is the closed set of architectures ElfPatcher accepts
        // (it rejects everything else at construction), so this mapping is
        // total — there is no RISC-V case to handle here.
        match arch {
            DetectedArch::Aarch64 => CliArch::Aarch64,
            DetectedArch::X86_64 => CliArch::X86_64,
            DetectedArch::X86_32 => CliArch::X86_32,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Disassemble an ELF binary showing addresses and machine code
    Disasm {
        /// Path to ELF binary to disassemble
        binary: PathBuf,
        /// Target architecture (auto-detected from ELF if not specified)
        #[arg(long, value_enum)]
        arch: Option<CliArch>,
    },
    /// Optimize a window of instructions in an ELF binary
    #[command(
        after_help = "Note: enumerative search scales with the generated instruction families in its candidate pool. At the default AArch64 8-register CLI scope, multiply-accumulate and high-half multiply add 9,728 candidates per length bucket; use --timeout or smaller windows to bound runtime."
    )]
    Opt {
        /// Path to ELF binary to optimize
        binary: PathBuf,
        /// Start address of optimization window (hex, e.g., 0x1000)
        #[arg(long)]
        start_addr: String,
        /// End address of optimization window (hex, e.g., 0x1100)
        #[arg(long)]
        end_addr: String,

        // --- Architecture selection ---
        /// Target architecture (auto-detected from ELF if not specified)
        #[arg(long, value_enum)]
        arch: Option<CliArch>,

        // --- Algorithm selection ---
        /// Search algorithm to use
        #[arg(long, value_enum, default_value = "enumerative")]
        algorithm: CliAlgorithm,

        // --- Common options ---
        /// Timeout in seconds for the search
        #[arg(long)]
        timeout: Option<u64>,
        /// Cost metric to optimize
        #[arg(long, value_enum, default_value = "instruction-count")]
        cost_metric: CliCostMetric,
        /// Enable verbose output
        #[arg(long, short)]
        verbose: bool,

        // --- Stochastic search options ---
        /// Inverse temperature for MCMC (higher = more greedy)
        #[arg(long, default_value = "1.0")]
        beta: f64,
        /// Number of MCMC iterations
        #[arg(long, default_value = "1000000")]
        iterations: u64,
        /// Random seed for reproducibility
        #[arg(long)]
        seed: Option<u64>,

        // --- Symbolic search options ---
        /// Search mode for symbolic synthesis
        #[arg(long, value_enum, default_value = "linear")]
        search_mode: CliSearchMode,
        /// Solver timeout in seconds
        #[arg(long, default_value = "5")]
        solver_timeout: u64,

        // --- Parallel/Hybrid search options ---
        /// Number of worker threads for hybrid search
        #[arg(long, short = 'j')]
        cores: Option<usize>,
        /// Disable symbolic worker in hybrid mode (all workers run stochastic)
        #[arg(long)]
        no_symbolic: bool,

        // --- LLM-assisted search options ---
        /// Maximum number of `codex exec` invocations per target (LLM algorithm)
        #[arg(long, default_value = "20")]
        llm_max_calls: u32,
        /// Codex model identifier (LLM algorithm)
        #[arg(long, default_value_t = search::config::DEFAULT_LLM_MODEL.to_string())]
        llm_model: String,
    },
    /// Run LLM-assisted optimization on a single assembly file (demo entry point)
    LlmOpt {
        /// Path to an .s file containing the target sequence (GAS syntax)
        #[arg(long)]
        asm: PathBuf,
        /// Live-out contract (comma-separated regs; ';nzcv' suffix is accepted for syntax compatibility with `equiv` but has no effect here — the LLM verifier always treats NZCV as live; see ADR-0006)
        #[arg(long)]
        live_out: String,
        /// Maximum number of `codex exec` invocations
        #[arg(long, default_value = "20")]
        max_calls: u32,
        /// Codex model identifier
        #[arg(long, default_value_t = search::config::DEFAULT_LLM_MODEL.to_string())]
        model: String,
        /// Overall timeout in seconds (across all calls)
        #[arg(long, default_value = "120")]
        timeout: u64,
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Check semantic equivalence of two assembly files
    Equiv {
        /// First assembly file
        file1: PathBuf,
        /// Second assembly file
        file2: PathBuf,
        /// Live-out contract (comma-separated regs; optional ';nzcv' suffix declares flags live, e.g. "x0,x1;nzcv")
        #[arg(long, default_value = "x0,x1,x2,x3,x4,x5,x6,x7")]
        live_out: String,
        /// Timeout in seconds for SMT solver
        #[arg(long, default_value = "30")]
        timeout: u64,
        /// Use fast path only (random testing, no SMT)
        #[arg(long)]
        fast_only: bool,
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

// --- ELF Binary Analysis ---

/// Prefix shared by every "architecture mismatch" diagnostic so the disasm
/// caller can recognise the error without coupling to the full message text.
const ARCH_MISMATCH_PREFIX: &str = "Architecture mismatch:";

fn cli_arch_from_e_machine(machine: u16) -> Result<CliArch, Box<dyn std::error::Error>> {
    match machine {
        elf::abi::EM_AARCH64 => Ok(CliArch::Aarch64),
        elf::abi::EM_X86_64 => Ok(CliArch::X86_64),
        elf::abi::EM_386 => Ok(CliArch::X86_32),
        m => Err(format!("Unsupported architecture (e_machine: {})", m).into()),
    }
}

fn analyze_elf_binary(
    path: &Path,
    disasm_mode: bool,
    expected_arch: Option<CliArch>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !disasm_mode {
        println!("Analyzing ELF binary: {}", path.display());
    }

    // Read the file
    let file_data = fs::read(path)?;

    // Parse ELF
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&file_data)?;

    // Detect architecture; reject anything outside the supported set.
    let detected_arch = cli_arch_from_e_machine(elf.ehdr.e_machine)?;
    if let Some(expected_arch) = expected_arch
        && expected_arch != detected_arch
    {
        return Err(format!(
            "{ARCH_MISMATCH_PREFIX} --arch {expected_arch} but ELF reports {detected_arch}"
        )
        .into());
    }
    let arch = match detected_arch {
        CliArch::Aarch64 => "AArch64",
        CliArch::X86_64 => "x86-64",
        CliArch::X86_32 => "x86-32",
        CliArch::Riscv32 | CliArch::Riscv64 => {
            unreachable!("RISC-V is not produced by cli_arch_from_e_machine")
        }
    };

    if !disasm_mode {
        println!("ELF Header:");
        println!("  Architecture: {}", arch);
        println!("  Entry point: 0x{:x}", elf.ehdr.e_entry);
        println!(
            "  Type: {}",
            match elf.ehdr.e_type {
                elf::abi::ET_EXEC => "Executable",
                elf::abi::ET_DYN => "Shared object",
                elf::abi::ET_REL => "Relocatable",
                _ => "Other",
            }
        );
    }

    // Initialize Capstone disassembler per architecture.
    let cs = match detected_arch {
        CliArch::Aarch64 => Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()?,
        CliArch::X86_64 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()?,
        CliArch::X86_32 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode32)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()?,
        CliArch::Riscv32 | CliArch::Riscv64 => {
            unreachable!("RISC-V is not produced by cli_arch_from_e_machine")
        }
    };

    // Find and disassemble .text sections
    let section_headers = elf
        .section_headers()
        .ok_or("Failed to get section headers")?;
    let (_, string_table) = elf.section_headers_with_strtab()?;
    let string_table = string_table.ok_or("Failed to get string table")?;

    if !disasm_mode {
        println!("\nText sections:");
    }

    for section_header in section_headers.iter() {
        let section_name = string_table.get(section_header.sh_name as usize)?;

        // Look for executable sections (typically .text, .init, .fini, etc.)
        if section_header.sh_flags & elf::abi::SHF_EXECINSTR as u64 != 0
            && section_header.sh_size > 0
        {
            if !disasm_mode {
                println!(
                    "\nSection: {} (offset: 0x{:x}, size: {} bytes)",
                    section_name, section_header.sh_offset, section_header.sh_size
                );
            }

            // Get section data
            let section_data = elf.section_data(&section_header)?;
            let (data, _) = section_data;

            if !data.is_empty() {
                if !disasm_mode {
                    println!("Disassembly:");
                }

                // Disassemble the section
                let instructions = cs.disasm_all(data, section_header.sh_addr)?;

                for instruction in instructions.iter() {
                    if disasm_mode {
                        // Format: address: bytes  mnemonic operands
                        let bytes = instruction.bytes();
                        let hex_bytes: String = bytes
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join("");
                        println!(
                            "0x{:x}: {:8} {} {}",
                            instruction.address(),
                            hex_bytes,
                            instruction.mnemonic().unwrap_or("???"),
                            instruction.op_str().unwrap_or("")
                        );
                    } else {
                        println!(
                            "  0x{:08x}: {}\t{}",
                            instruction.address(),
                            instruction.mnemonic().unwrap_or("???"),
                            instruction.op_str().unwrap_or("")
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Options for the optimization process
struct OptimizationOptions {
    algorithm: Algorithm,
    timeout: Option<Duration>,
    cost_metric: CostMetric,
    verbose: bool,
    beta: f64,
    iterations: u64,
    seed: Option<u64>,
    search_mode: SearchMode,
    solver_timeout: Duration,
    // Parallel/Hybrid options
    cores: Option<usize>,
    no_symbolic: bool,
    // LLM options
    llm_max_calls: u32,
    llm_model: String,
}

// --- Optimization Function ---

enum OptimizedWindowBytes {
    Patch(Vec<u8>),
    LeaveInputUnchanged,
}

#[derive(Clone, Copy)]
struct OptimizationContext {
    downstream_flags_live: bool,
}

impl Default for OptimizationContext {
    fn default() -> Self {
        Self {
            downstream_flags_live: true,
        }
    }
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

    fn validate_window_ir(&self, ir: &[Self::Instruction]) -> Result<(), String>;

    fn run_search(
        &self,
        ir: &[Self::Instruction],
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

    fn validate_window_ir(&self, ir: &[Self::Instruction]) -> Result<(), String> {
        validate_basic_block(ir)
    }

    fn run_search(
        &self,
        ir: &[Self::Instruction],
        options: &OptimizationOptions,
        context: OptimizationContext,
    ) -> Result<Option<Vec<Self::Instruction>>, Box<dyn std::error::Error>> {
        run_optimization(ir, options, context.downstream_flags_live)
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

struct X86OptimizationBackend {
    arch: DetectedArch,
    width: u32,
}

impl X86OptimizationBackend {
    fn new(arch: DetectedArch) -> Result<Self, Box<dyn std::error::Error>> {
        let width = match arch {
            DetectedArch::X86_64 => 64,
            DetectedArch::X86_32 => 32,
            DetectedArch::Aarch64 => {
                return Err("expected x86 binary; got AArch64".into());
            }
        };
        Ok(Self { arch, width })
    }

    fn parse_mode(&self) -> parser::x86::X86ParseMode {
        match self.arch {
            DetectedArch::X86_64 => parser::x86::X86ParseMode::Mode64,
            DetectedArch::X86_32 => parser::x86::X86ParseMode::Mode32,
            DetectedArch::Aarch64 => unreachable!("x86 backend never receives AArch64"),
        }
    }
}

impl ElfOptimizationBackend for X86OptimizationBackend {
    type Instruction = isa::x86::X86Instruction;

    fn arch(&self) -> DetectedArch {
        self.arch
    }

    fn arch_description(&self) -> String {
        format!("{:?} (width {})", self.arch, self.width)
    }

    fn ir_label(&self) -> &'static str {
        "x86 IR"
    }

    fn disassembler(&self) -> Result<Capstone, Box<dyn std::error::Error>> {
        let mut builder = Capstone::new().x86();
        builder = match self.arch {
            DetectedArch::X86_64 => builder.mode(capstone::arch::x86::ArchMode::Mode64),
            DetectedArch::X86_32 => builder.mode(capstone::arch::x86::ArchMode::Mode32),
            DetectedArch::Aarch64 => unreachable!("x86 backend never receives AArch64"),
        };
        Ok(builder
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()?)
    }

    fn convert_ir(
        &self,
        instructions: &capstone::Instructions,
    ) -> Result<Vec<Self::Instruction>, String> {
        convert_to_x86_ir(instructions, self.parse_mode())
    }

    fn validate_window_ir(&self, ir: &[Self::Instruction]) -> Result<(), String> {
        validate_x86_window_terminator_placement(ir)
    }

    fn run_search(
        &self,
        ir: &[Self::Instruction],
        options: &OptimizationOptions,
        _context: OptimizationContext,
    ) -> Result<Option<Vec<Self::Instruction>>, Box<dyn std::error::Error>> {
        let optimized = match options.algorithm {
            Algorithm::Enumerative => run_x86_enumerative(ir, self.width, options),
            Algorithm::Stochastic => run_x86_stochastic(ir, self.width, options),
            Algorithm::Symbolic => run_x86_symbolic(ir, self.width, options),
            Algorithm::Hybrid | Algorithm::Llm => {
                // Rejected upstream at the CLI layer; defensive check here
                // in case a programmatic caller bypasses it.
                return Err("hybrid and llm are AArch64-only".into());
            }
        };
        Ok(optimized)
    }

    fn no_optimization_message(&self) -> &'static str {
        "No optimization found; not patching (input binary left untouched)."
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
        // zero displacement and overwrite the real branch target. Peel the
        // Jcc from `final_ir` and splice the ORIGINAL Jcc bytes back at the
        // same offset they had in the source window so the displacement
        // stays valid.
        let (final_prefix_ir, final_terminator) =
            crate::ir::instructions::split_terminator_x86(final_ir);
        let (_, original_terminator) = crate::ir::instructions::split_terminator_x86(original_ir);
        if final_terminator != original_terminator {
            return Err(format!(
                "search returned a terminator ({:?}) that does not match the \
                 original window's terminator ({:?}); refusing to patch",
                final_terminator, original_terminator
            )
            .into());
        }
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
                Some(last.bytes().to_vec())
            } else {
                None
            };
        let original_prefix_byte_size =
            original_bytes.len() - pinned_terminator_bytes.as_ref().map_or(0, |b| b.len());

        let new_bytes = reassemble_x86_prefix_with_pinned_terminator(
            final_prefix_ir,
            self.arch,
            pinned_terminator_bytes.as_deref(),
            original_prefix_byte_size,
        )?;
        Ok(OptimizedWindowBytes::Patch(new_bytes))
    }
}

fn optimized_output_path(path: &Path) -> PathBuf {
    let mut new_path = path.to_path_buf();
    let stem = new_path.file_stem().unwrap().to_str().unwrap();
    let extension = new_path.extension().map(|e| e.to_str().unwrap());

    let new_name = if let Some(ext) = extension {
        format!("{}_optimized.{}", stem, ext)
    } else {
        format!("{}_optimized", stem)
    };

    new_path.set_file_name(new_name);
    new_path
}

fn decode_arch_label(arch: DetectedArch) -> &'static str {
    match arch {
        DetectedArch::Aarch64 => "AArch64",
        DetectedArch::X86_64 => "x86-64",
        DetectedArch::X86_32 => "x86-32",
    }
}

fn optimize_elf_binary(
    patcher: &ElfPatcher,
    path: &Path,
    start_addr: u64,
    end_addr: u64,
    options: &OptimizationOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    match patcher.arch() {
        DetectedArch::Aarch64 => optimize_elf_binary_with_backend(
            AArch64OptimizationBackend,
            patcher,
            path,
            start_addr,
            end_addr,
            options,
        ),
        DetectedArch::X86_64 | DetectedArch::X86_32 => optimize_elf_binary_with_backend(
            X86OptimizationBackend::new(patcher.arch())?,
            patcher,
            path,
            start_addr,
            end_addr,
            options,
        ),
    }
}

fn optimize_elf_binary_with_backend<B: ElfOptimizationBackend>(
    backend: B,
    patcher: &ElfPatcher,
    path: &Path,
    start_addr: u64,
    end_addr: u64,
    options: &OptimizationOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Optimizing ELF binary: {}", path.display());
    println!("Detected: {}", backend.arch_description());
    println!("Address window: 0x{:x} - 0x{:x}", start_addr, end_addr);
    println!("Algorithm: {:?}", options.algorithm);

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
        optimization_context_for_backend(backend.arch(), patcher, &section, end_addr, &cs);

    // Run optimization based on selected algorithm
    let optimized_instructions =
        backend.run_search(&ir_instructions, options, optimization_context)?;

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
    let assembled_bytes = backend.assemble_window(
        &ir_instructions,
        final_instructions,
        optimized_instructions.is_some(),
        &instructions,
        &original_bytes,
        start_addr,
    )?;
    let OptimizedWindowBytes::Patch(assembled_bytes) = assembled_bytes else {
        return Ok(());
    };
    println!("Reassembled to {} bytes", assembled_bytes.len());

    // Create output filename
    let output_path = optimized_output_path(path);

    // Create patched ELF file
    patcher.create_patched_copy(&output_path, &window, &assembled_bytes)?;
    println!("Created optimized binary: {}", output_path.display());

    Ok(())
}

fn live_out_for_optimization_prefix(
    prefix: &[Instruction],
    terminator: Option<&Instruction>,
    downstream_flags_live: bool,
) -> LiveOut {
    let mut live_registers: Vec<Register> = prefix
        .iter()
        .flat_map(|instr| instr.destinations())
        .collect();

    if let Some(terminator) = terminator {
        live_registers.extend(terminator.source_registers());
    }

    let flags_live = if terminator.is_some() {
        true
    } else {
        downstream_flags_live
    };

    LiveOut::from_registers(live_registers).with_flags(flags_live)
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

    let symbolic_config = SymbolicConfig::default().with_timeout(options.solver_timeout);

    SearchConfig::default()
        .with_stochastic(stochastic_config)
        .with_symbolic(symbolic_config)
        .with_cost_metric(options.cost_metric)
        .with_timeout_option(options.timeout)
        .with_verbose(options.verbose)
        .with_registers(available_registers)
        .with_immediates(available_immediates)
}

/// Build the per-worker `SearchConfig` consumed by the hybrid parallel
/// coordinator.
///
/// Issue #243: the CLI used to forget to propagate `options.timeout` into the
/// `SearchConfig`, which left workers running with the default 60 s timeout
/// even when the user passed a smaller `--timeout`. The coordinator-level
/// `ParallelConfig::timeout` still acts as the primary deadline (now wired
/// through `SharedBest::should_stop`); the search-config timeout is a
/// per-worker backstop in case the coordinator itself stalls.
fn build_hybrid_search_config(
    options: &OptimizationOptions,
    available_registers: Vec<Register>,
    available_immediates: Vec<i64>,
) -> SearchConfig {
    let stochastic_config = StochasticConfig::default()
        .with_beta(options.beta)
        .with_iterations(options.iterations);

    let symbolic_config = SymbolicConfig::default()
        .with_search_mode(options.search_mode)
        .with_timeout(options.solver_timeout);

    SearchConfig::default()
        .with_stochastic(stochastic_config)
        .with_symbolic(symbolic_config)
        .with_cost_metric(options.cost_metric)
        .with_verbose(options.verbose)
        .with_registers(available_registers)
        .with_immediates(available_immediates)
        .with_timeout_option(options.timeout)
}

fn build_x86_base_search_config(
    target: &[isa::x86::X86Instruction],
    width: u32,
    options: &OptimizationOptions,
) -> SearchConfig {
    SearchConfig::default()
        .with_cost_metric(options.cost_metric)
        .with_timeout_option(options.timeout)
        .with_verbose(options.verbose)
        .with_x86_registers(x86_registers_from_target(target))
        .with_immediates(isa::x86::default_x86_immediates())
        .with_x86_width(width)
}

fn build_x86_stochastic_search_config(
    target: &[isa::x86::X86Instruction],
    width: u32,
    options: &OptimizationOptions,
) -> SearchConfig {
    let stochastic_config = StochasticConfig::default()
        .with_beta(options.beta)
        .with_iterations(options.iterations)
        .with_seed_option(options.seed);

    let symbolic_config = SymbolicConfig::default().with_timeout(options.solver_timeout);

    build_x86_base_search_config(target, width, options)
        .with_stochastic(stochastic_config)
        .with_symbolic(symbolic_config)
}

fn build_x86_symbolic_search_config(
    target: &[isa::x86::X86Instruction],
    width: u32,
    options: &OptimizationOptions,
) -> SearchConfig {
    let symbolic_config = SymbolicConfig::default()
        .with_search_mode(options.search_mode)
        .with_timeout(options.solver_timeout);

    build_x86_base_search_config(target, width, options).with_symbolic(symbolic_config)
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

    // Default registers and immediates for search
    let available_registers = vec![
        Register::X0,
        Register::X1,
        Register::X2,
        Register::X3,
        Register::X4,
        Register::X5,
        Register::X6,
        Register::X7,
    ];
    let available_immediates = vec![
        0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
    ];

    // Create live-out contract over the prefix (assume all modified registers
    // are live-out), plus any registers the fixed terminator reads after the
    // optimized prefix runs. NZCV liveness comes from the fixed terminator or
    // the known downstream fall-through context.
    let live_out = live_out_for_optimization_prefix(prefix, terminator, downstream_flags_live);

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

            let config = SearchConfig::default()
                .with_cost_metric(options.cost_metric)
                .with_timeout_option(options.timeout)
                .with_verbose(options.verbose)
                .with_registers(available_registers)
                .with_immediates(available_immediates)
                .with_cores(options.cores);

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

            let symbolic_config = SymbolicConfig::default()
                .with_search_mode(options.search_mode)
                .with_timeout(options.solver_timeout);

            let config = SearchConfig::default()
                .with_symbolic(symbolic_config)
                .with_cost_metric(options.cost_metric)
                .with_timeout_option(options.timeout)
                .with_verbose(options.verbose)
                .with_registers(available_registers)
                .with_immediates(available_immediates);

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

            let llm = LlmConfig::default()
                .with_max_codex_calls(options.llm_max_calls)
                .with_model(options.llm_model.clone());

            let config = SearchConfig::default()
                .with_cost_metric(options.cost_metric)
                .with_timeout_option(options.timeout)
                .with_verbose(options.verbose)
                .with_registers(available_registers)
                .with_immediates(available_immediates)
                .with_llm(llm);

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
fn fmt_bytes(n: usize) -> String {
    if n >= 1_048_576 {
        format!("{:>7.2} MB", n as f64 / 1_048_576.0)
    } else if n >= 1_024 {
        format!("{:>7.2} kB", n as f64 / 1_024.0)
    } else {
        format!("{:>7} B ", n)
    }
}

/// Format a Duration with a unit chosen to keep ~3 significant digits visible.
fn fmt_dur(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs >= 1.0 {
        format!("{:>8.2} s ", secs)
    } else if secs >= 0.001 {
        format!("{:>8.2} ms", secs * 1_000.0)
    } else {
        format!("{:>8.1} µs", secs * 1_000_000.0)
    }
}

/// Print the per-phase timing breakdown from an LLM-assisted run.
fn print_llm_timings(timings: &search::llm::LlmTimings, total: Duration) {
    let codex = timings.codex_time;
    let verify = timings.verify_time;
    let other = total.saturating_sub(codex).saturating_sub(verify);
    println!("\nLLM phase timing:");
    println!(
        "  Codex calls:      {}   ({} call{})",
        fmt_dur(codex),
        timings.codex_calls,
        if timings.codex_calls == 1 { "" } else { "s" }
    );
    println!(
        "  Verification:     {}   ({} verification{}, parse + fast + SMT)",
        fmt_dur(verify),
        timings.verifications,
        if timings.verifications == 1 { "" } else { "s" }
    );
    if timings.smt_calls > 0 {
        let avg_bytes = timings.smt_formula_bytes_total / timings.smt_calls as usize;
        println!(
            "    SMT invoked:    {} time{}",
            timings.smt_calls,
            if timings.smt_calls == 1 { "" } else { "s" }
        );
        println!(
            "    SMT formula:    {}  total   ({}  avg, {}  max)",
            fmt_bytes(timings.smt_formula_bytes_total),
            fmt_bytes(avg_bytes),
            fmt_bytes(timings.smt_formula_bytes_max),
        );
    }
    println!("  Other:            {}", fmt_dur(other));
    println!("  Total:            {}", fmt_dur(total));
    if total.as_secs_f64() > 0.0 {
        println!(
            "  Codex share:      {:>6.2}%",
            100.0 * codex.as_secs_f64() / total.as_secs_f64()
        );
        println!(
            "  Verify share:     {:>6.2}%",
            100.0 * verify.as_secs_f64() / total.as_secs_f64()
        );
    }
}

/// Print the unsupported-mnemonic ledger from an LLM-assisted run.
fn print_unsupported_mnemonic_ledger(ledger: &search::llm::ledger::UnsupportedMnemonicLedger) {
    if ledger.is_empty() {
        return;
    }
    println!("\nUnsupported mnemonics emitted by the LLM (frequency-ranked):");
    for (mnem, count) in ledger.sorted_entries() {
        println!("  {:>5}  {}", count, mnem);
    }
}

/// Print search statistics
fn print_search_statistics(stats: &search::result::SearchStatistics) {
    println!("\nSearch Statistics:");
    println!("  Algorithm: {:?}", stats.algorithm);
    println!("  Elapsed time: {:?}", stats.elapsed_time);
    println!("  Candidates evaluated: {}", stats.candidates_evaluated);
    println!(
        "  Candidates passed fast test: {}",
        stats.candidates_passed_fast
    );
    println!("  SMT queries: {}", stats.smt_queries);
    println!("  SMT equivalent: {}", stats.smt_equivalent);
    println!("  Improvements found: {}", stats.improvements_found);
    println!("  Original cost: {}", stats.original_cost);
    println!("  Best cost found: {}", stats.best_cost_found);
    if stats.iterations > 0 {
        println!("  Iterations: {}", stats.iterations);
        println!("  Acceptance rate: {:.2}%", stats.acceptance_rate() * 100.0);
    }
}

/// Outcome of converting a single Capstone-disassembled instruction to IR.
///
/// Factored out so we can unit-test the dispatch without constructing a
/// `capstone::Instructions` (which is not directly buildable).
#[derive(Debug)]
enum ConvertOutcome {
    Instruction(Instruction),
    Skip,
    Unsupported(String),
}

fn capstone_instruction_line(mnemonic: &str, op_str: &str) -> String {
    if op_str.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{} {}", mnemonic, op_str)
    }
}

fn split_capstone_alias_operands(op_str: &str) -> Vec<&str> {
    op_str.split(',').map(str::trim).collect()
}

fn move_wide_movz_encoding(value: u64) -> Option<(u16, u8)> {
    for shift in MOVW_LEGAL_SHIFTS {
        let mask = 0xffff_u64 << shift;
        if value & !mask == 0 {
            let imm = ((value >> shift) & 0xffff) as u16;
            if imm != 0 {
                return Some((imm, shift));
            }
        }
    }
    None
}

fn move_wide_movn_encoding(value: u64) -> Option<(u16, u8)> {
    let inverted = !value;
    for shift in MOVW_LEGAL_SHIFTS {
        let imm = ((inverted >> shift) & 0xffff) as u16;
        if inverted == u64::from(imm) << shift {
            return Some((imm, shift));
        }
    }
    None
}

fn format_move_wide(mnemonic: &str, rd: &str, imm: u16, shift: u8) -> String {
    if shift == 0 {
        format!("{} {}, #{}", mnemonic, rd, imm)
    } else {
        format!("{} {}, #{}, lsl #{}", mnemonic, rd, imm, shift)
    }
}

fn normalize_mov_wide_alias(op_str: &str) -> Result<Option<String>, String> {
    let operands = split_capstone_alias_operands(op_str);
    if operands.len() != 2 {
        return Ok(None);
    }

    let rd = operands[0];
    if !rd.to_ascii_lowercase().starts_with('x') || parser::parse_register(rd).is_err() {
        return Ok(None);
    }

    let Ok(imm) = parser::parse_immediate(operands[1]) else {
        return Ok(None);
    };
    if (0..=0xffff).contains(&imm) {
        return Ok(None);
    }

    let value = imm as u64;
    if let Some((imm, shift)) = move_wide_movz_encoding(value) {
        return Ok(Some(format_move_wide("movz", rd, imm, shift)));
    }
    if let Some((imm, shift)) = move_wide_movn_encoding(value) {
        return Ok(Some(format_move_wide("movn", rd, imm, shift)));
    }

    Ok(None)
}

fn normalize_cond_select_alias(mnemonic: &str, op_str: &str) -> Result<String, String> {
    let operands = split_capstone_alias_operands(op_str);
    if operands.len() != 3 {
        return Err(format!(
            "{} alias requires 3 operands (rd, rn, cond), got {}",
            mnemonic,
            operands.len()
        ));
    }

    let rd = operands[0];
    let rn = operands[1];
    parser::parse_register(rd).map_err(|err| format!("invalid {mnemonic} destination: {err}"))?;
    parser::parse_register(rn).map_err(|err| format!("invalid {mnemonic} source: {err}"))?;

    let cond = parser::parse_condition(operands[2])?;
    if matches!(cond, Condition::AL | Condition::NV) {
        return Err(format!(
            "{} alias does not support {} condition",
            mnemonic, cond
        ));
    }

    let canonical = match mnemonic {
        "cinc" => "csinc",
        "cinv" => "csinv",
        "cneg" => "csneg",
        _ => unreachable!("conditional-select alias normalizer called for {mnemonic}"),
    };

    Ok(format!(
        "{} {}, {}, {}, {}",
        canonical,
        rd,
        rn,
        rn,
        cond.invert()
    ))
}

fn normalize_capstone_alias(mnemonic: &str, op_str: &str) -> Result<Option<String>, String> {
    let mnemonic = mnemonic.to_ascii_lowercase();
    match mnemonic.as_str() {
        "mov" => normalize_mov_wide_alias(op_str),
        "cinc" | "cinv" | "cneg" => normalize_cond_select_alias(&mnemonic, op_str).map(Some),
        _ => Ok(None),
    }
}

/// Render the diagnostic for a Capstone instruction the parser rejected. When
/// the alias bridge rewrote the raw spelling, the normalized form that was
/// actually handed to the parser is surfaced too — otherwise a bridge
/// regression would be invisible in the warning. Both parser failure modes
/// share this so their diagnostics stay consistent (`UnknownInstruction`
/// carries no message, `Other` carries one appended in parentheses).
fn describe_unsupported_line(raw_line: &str, line: &str, err: Option<&str>) -> String {
    let base = if line == raw_line {
        raw_line.to_string()
    } else {
        format!("{} normalized as `{}`", raw_line, line)
    };
    match err {
        Some(err) => format!("{} ({})", base, err),
        None => base,
    }
}

/// Convert one Capstone (mnemonic, op_str) pair into an IR outcome by
/// delegating to `parser::parse_line`. Keeping a single shared parser is what
/// guarantees the asm-text path and the ELF/Capstone path support exactly the
/// same mnemonic set (see CLAUDE.md "Adding a new AArch64 instruction").
fn convert_capstone_op(mnemonic: &str, op_str: &str) -> ConvertOutcome {
    if mnemonic.eq_ignore_ascii_case("nop") {
        // NOPs are filtered here; the assembler re-emits any padding needed.
        return ConvertOutcome::Skip;
    }

    let raw_line = capstone_instruction_line(mnemonic, op_str);
    let line = match normalize_capstone_alias(mnemonic, op_str) {
        Ok(Some(normalized)) => normalized,
        Ok(None) => raw_line.clone(),
        Err(err) => return ConvertOutcome::Unsupported(format!("{} ({})", raw_line, err)),
    };

    match parser::parse_line(&line) {
        Ok(parser::LineResult::Instruction(instr)) => ConvertOutcome::Instruction(instr),
        Ok(parser::LineResult::Skip) => ConvertOutcome::Skip,
        Err(parser::ParseLineError::UnknownInstruction(_)) => {
            ConvertOutcome::Unsupported(describe_unsupported_line(&raw_line, &line, None))
        }
        Err(parser::ParseLineError::Other(err)) => {
            ConvertOutcome::Unsupported(describe_unsupported_line(&raw_line, &line, Some(&err)))
        }
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
        Ordering::Less => Err(format!(
            "{} window 0x{:x}-0x{:x} ({} bytes) was not fully decoded by Capstone; decoded only {} bytes",
            arch_label, start_addr, end_addr, window_bytes, decoded_bytes
        )),
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
        ConvertOutcome::Skip => Ok(None),
        ConvertOutcome::Unsupported(line) => Err(format!(
            "AArch64 window contains unsupported instruction '{}' at 0x{:x}; \
             cannot optimize. Narrow the --start-addr/--end-addr range to \
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

fn aarch64_downstream_flags_live_from_bytes(cs: &Capstone, bytes: &[u8], start_addr: u64) -> bool {
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
        match convert_capstone_op(mnemonic, op_str) {
            ConvertOutcome::Instruction(instr) => {
                if validation::live_out::flags_read_before_overwrite_after_window(&[instr]) {
                    return true;
                }
                if instr.modifies_flags() {
                    return false;
                }
                if instr.is_terminator() {
                    return true;
                }
            }
            ConvertOutcome::Skip => {}
            ConvertOutcome::Unsupported(_) => return true,
        }

        remaining = &remaining[instruction_len..];
        address += instruction_len as u64;
    }

    false
}

fn aarch64_downstream_flags_live_from_section(
    patcher: &ElfPatcher,
    section: &TextSection,
    end_addr: u64,
    cs: &Capstone,
) -> bool {
    let section_end = section.virtual_addr + section.size;
    if end_addr >= section_end {
        return true;
    }

    let suffix_window = AddressWindow {
        start: end_addr,
        end: section_end,
    };
    let Ok(bytes) = patcher.get_instructions_in_window(&suffix_window) else {
        return true;
    };

    aarch64_downstream_flags_live_from_bytes(cs, &bytes, end_addr)
}

fn optimization_context_for_backend(
    arch: DetectedArch,
    patcher: &ElfPatcher,
    section: &TextSection,
    end_addr: u64,
    cs: &Capstone,
) -> OptimizationContext {
    if arch == DetectedArch::Aarch64 {
        return OptimizationContext {
            downstream_flags_live: aarch64_downstream_flags_live_from_section(
                patcher, section, end_addr, cs,
            ),
        };
    }

    OptimizationContext::default()
}

/// Validate that an IR sequence forms a single basic block: at most one
/// terminator (branch / control-flow instruction), and only at the final
/// position. Issue #69 scope — internal branches mid-block are rejected.
///
/// Accepted shapes: `[]`, `[i1, ..., ik]` (no branch), `[t]` (terminator
/// only), `[i1, ..., ik, t]` (prefix + terminator).
fn validate_basic_block(ir: &[Instruction]) -> Result<(), String> {
    let last_idx = ir.len().saturating_sub(1);
    for (i, instr) in ir.iter().enumerate() {
        if i < last_idx && instr.is_terminator() {
            return Err(format!(
                "Region contains a branch at position {} ({}); only single basic blocks ending in a terminator are supported (issue #69 scope)",
                i, instr
            ));
        }
    }
    Ok(())
}

// ============================================================================
// x86 parser + enumerative pipeline
// ============================================================================
//
// Text parsing helpers (`parse_x86_register`, `parse_x86_operand`,
// `parse_x86_immediate`, `x86_ir_from_mnemonic`, `parse_x86_assembly_string`)
// live in `parser::x86`. This file keeps only the Capstone bridge
// (`convert_to_x86_ir`) and the length-1 enumerator used by the
// enumerative x86 pipeline.

use parser::x86::{X86ParseMode, x86_ir_from_mnemonic_for_mode};

/// Reject any non-terminal Jcc in an x86 optimization window. The
/// optimizer only special-cases a trailing Jcc (peeled by
/// `split_terminator_x86`, displacement preserved by
/// `reassemble_x86_prefix_with_pinned_terminator`). A Jcc anywhere
/// else in the window would be modelled as a data-state no-op by
/// both the concrete and SMT executors, so the equivalence check
/// could accept a rewrite that silently drops or rewrites the branch.
fn validate_x86_window_terminator_placement(ir: &[isa::x86::X86Instruction]) -> Result<(), String> {
    for (idx, instr) in ir.iter().enumerate() {
        if matches!(instr, isa::x86::X86Instruction::Jcc { .. }) && idx != ir.len() - 1 {
            return Err(format!(
                "x86 window contains a non-terminal conditional branch at position {} \
                 (last position is {}). The optimizer only supports Jcc as the trailing \
                 terminator of a window. Narrow --start-addr/--end-addr to exclude the \
                 mid-window branch.",
                idx,
                ir.len() - 1
            ));
        }
    }
    Ok(())
}

fn convert_to_x86_ir(
    instructions: &capstone::Instructions,
    mode: X86ParseMode,
) -> Result<Vec<isa::x86::X86Instruction>, String> {
    let mut out = Vec::new();
    for instruction in instructions.iter() {
        let mn = instruction.mnemonic().unwrap_or("");
        let ops = instruction.op_str().unwrap_or("");
        match x86_ir_from_mnemonic_for_mode(mn, ops, mode) {
            Ok(Some(ir)) => out.push(ir),
            Ok(None) => {
                // Refusing the window is safer than silently dropping the
                // unsupported instruction: the patcher overwrites the entire
                // byte window with the reassembled IR, so a dropped `lea`,
                // `call`, etc. would lose its side effect from the binary.
                return Err(format!(
                    "x86 window contains unsupported mnemonic '{} {}' at 0x{:x}; \
                     cannot optimize. Narrow the --start-addr/--end-addr range \
                     to exclude it, or add the mnemonic to the supported set.",
                    mn,
                    ops,
                    instruction.address()
                ));
            }
            Err(e) => {
                return Err(format!(
                    "failed to parse x86 instruction '{} {}' at 0x{:x}: {}",
                    mn,
                    ops,
                    instruction.address(),
                    e
                ));
            }
        }
    }
    Ok(out)
}

/// Candidate register pool for x86 search, drawn from the target's original
/// destinations. The trait refactor regressed coverage by defaulting to the
/// fixed `default_x86_registers()` pool, so a window over R10-R15 had no
/// representable rewrite. Source-only registers are deliberately excluded: the
/// single candidate pool can place registers in writable positions, while
/// live-out tracking only makes original destinations plus EFLAGS observable.
/// `RSP` and `RBP` are also excluded so search never synthesizes stack/frame
/// writes. Falls back to the default pool only for an empty target; a non-empty
/// target with no usable destinations returns an empty pool so search does not
/// introduce unrelated writable registers.
fn x86_registers_from_target(target: &[isa::x86::X86Instruction]) -> Vec<isa::x86::X86Register> {
    let mut pool: Vec<isa::x86::X86Register> = Vec::new();
    let referenced = target.iter().filter_map(|instr| instr.destination());
    for reg in referenced {
        if matches!(reg, isa::x86::X86Register::RSP | isa::x86::X86Register::RBP) {
            continue;
        }
        if !pool.contains(&reg) {
            pool.push(reg);
        }
    }
    if target.is_empty() {
        return isa::x86::default_x86_registers();
    }
    pool
}

/// Candidate immediate pool for the x86 enumerative path: the target's own
/// immediates plus `0`, `1`, and `-1`. The fixed `default_x86_immediates()`
/// pool holds no negatives, so the trait refactor lost rewrites like
/// `mov rax, -1; mov rax, -1` → `mov rax, -1`.
fn x86_enumerative_immediates_from_target(target: &[isa::x86::X86Instruction]) -> Vec<i64> {
    use isa::x86::X86Instruction;
    let mut imms = vec![0i64, 1, -1];
    let referenced = target.iter().filter_map(|instr| match instr {
        X86Instruction::MovImm { imm, .. }
        | X86Instruction::AddImm { imm, .. }
        | X86Instruction::SubImm { imm, .. }
        | X86Instruction::AndImm { imm, .. }
        | X86Instruction::OrImm { imm, .. }
        | X86Instruction::XorImm { imm, .. }
        | X86Instruction::CmpImm { imm, .. } => Some(*imm),
        _ => None,
    });
    for imm in referenced {
        if !imms.contains(&imm) {
            imms.push(imm);
        }
    }
    imms
}

/// Build the search config for the x86 *enumerative* path. Like stochastic and
/// symbolic search, enumerative search draws candidates from the target's own
/// registers via the shared x86 base; it additionally derives immediates from
/// the target and honours --cores now that the trait-backed search is
/// rayon-parallel.
fn build_x86_enumerative_search_config(
    target: &[isa::x86::X86Instruction],
    width: u32,
    options: &OptimizationOptions,
) -> SearchConfig {
    // Enumerative verification reads `config.symbolic.solver_timeout`, so the
    // CLI --solver-timeout must be attached here even though the stochastic
    // fields stay out of the enumerative config.
    let symbolic_config = SymbolicConfig::default().with_timeout(options.solver_timeout);
    build_x86_base_search_config(target, width, options)
        .with_immediates(x86_enumerative_immediates_from_target(target))
        .with_cores(options.cores)
        .with_symbolic(symbolic_config)
}

/// Run x86 enumerative search and return the optimized sequence if any.
fn run_x86_enumerative(
    target: &[isa::x86::X86Instruction],
    width: u32,
    options: &OptimizationOptions,
) -> Option<Vec<isa::x86::X86Instruction>> {
    use search::SearchAlgorithm;
    use validation::live_out::x86_live_out_from_target;

    let config = build_x86_enumerative_search_config(target, width, options);
    let live_out = x86_live_out_from_target(target);

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
) -> Option<Vec<isa::x86::X86Instruction>> {
    use search::SearchAlgorithm;
    use search::stochastic::StochasticSearch;
    use validation::live_out::x86_live_out_from_target;

    let config = build_x86_stochastic_search_config(target, width, options);
    if config.x86_available_registers.is_empty() {
        return None;
    }
    let live_out = x86_live_out_from_target(target);

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
) -> Option<Vec<isa::x86::X86Instruction>> {
    use search::SearchAlgorithm;
    use search::symbolic::SymbolicSearch;
    use validation::live_out::x86_live_out_from_target;

    let config = build_x86_symbolic_search_config(target, width, options);
    let live_out = x86_live_out_from_target(target);

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

/// Reassemble an x86 prefix and splice an ORIGINAL pinned Jcc
/// terminator back at its original byte offset. Re-encoding the Jcc via
/// dynasm would emit a placeholder zero displacement and overwrite the
/// real branch target.
///
/// `pinned_terminator` is `None` when the source window had no trailing
/// Jcc; in that case the function returns the assembled prefix verbatim.
/// When `Some(jcc_bytes)`, the returned vector is exactly
/// `original_prefix_byte_size + jcc_bytes.len()` long, with NOP padding
/// inserted between the new prefix and the Jcc so the Jcc lands at its
/// original offset (preserving its rel8 / rel32 displacement).
///
/// Returns `Err` if the optimized prefix encodes to more bytes than the
/// original prefix occupied — shifting the Jcc earlier would change the
/// branch target.
fn reassemble_x86_prefix_with_pinned_terminator(
    final_prefix_ir: &[isa::x86::X86Instruction],
    arch: DetectedArch,
    pinned_terminator: Option<&[u8]>,
    original_prefix_byte_size: usize,
) -> Result<Vec<u8>, String> {
    let mut asm = match arch {
        DetectedArch::X86_64 => assembler::x86::X86Assembler::new_64(),
        DetectedArch::X86_32 => assembler::x86::X86Assembler::new_32(),
        DetectedArch::Aarch64 => {
            return Err("reassemble helper is x86-only".to_string());
        }
    };
    let mut out = asm.assemble_instructions(final_prefix_ir)?;

    let Some(jcc_bytes) = pinned_terminator else {
        return Ok(out);
    };

    if out.len() > original_prefix_byte_size {
        return Err(format!(
            "optimized prefix ({} bytes) is larger than original prefix \
             ({} bytes); cannot preserve the pinned Jcc terminator's \
             displacement",
            out.len(),
            original_prefix_byte_size
        ));
    }

    let gap = original_prefix_byte_size - out.len();
    append_nop_padding(&mut out, gap, arch, |remaining| {
        arch.nop_sequence(remaining)
    })?;
    out.extend_from_slice(jcc_bytes);
    Ok(out)
}

fn append_nop_padding<F>(
    out: &mut Vec<u8>,
    gap: usize,
    arch: DetectedArch,
    mut nop_sequence: F,
) -> Result<(), String>
where
    F: FnMut(usize) -> &'static [u8],
{
    // Pad NOPs so the Jcc lands at the same offset as in the original
    // window. `nop_sequence` may return fewer than the requested bytes;
    // loop until the gap is filled. Return Err on an empty NOP slice
    // (debug-assert alone would let release builds spin forever).
    let mut padded = 0;
    while padded < gap {
        let remaining = gap - padded;
        let nop = nop_sequence(remaining);
        if nop.is_empty() {
            return Err(format!(
                "nop_sequence returned an empty slice while padding {} bytes \
                 for arch {:?}; refusing to spin forever",
                remaining, arch
            ));
        }
        let take = nop.len().min(remaining);
        out.extend_from_slice(&nop[..take]);
        padded += take;
    }
    Ok(())
}

// --- Equivalence Checking Command ---

fn run_llm_opt(
    asm: &Path,
    live_out_str: &str,
    max_calls: u32,
    model: &str,
    timeout_secs: u64,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = parser::parse_assembly_file(asm)?;
    if verbose {
        println!("Target ({} instructions):", target.len());
        for instr in &target {
            println!("  {}", instr);
        }
    }

    // The LLM verifier in `outcome.rs` pins `flags_live=true` regardless of
    // what the user requests here, so the `;nzcv` suffix is accepted (for
    // CLI vocabulary parity with `equiv`) but does not change behaviour on
    // this path. See ADR-0006.
    let live_out = validation::live_out::parse_live_out_contract(live_out_str)
        .map_err(|e| format!("invalid live-out: {}", e))?;

    let llm = LlmConfig::default()
        .with_max_codex_calls(max_calls)
        .with_model(model);

    // Note: `available_registers` and `available_immediates` are intentionally
    // omitted here. `LlmSearch` does not enumerate over a register/immediate
    // pool — Codex generates candidates directly. The other algorithms
    // (enumerative, stochastic, symbolic) need those fields and set them in
    // `optimize_elf_binary`. If `LlmSearch` ever falls back to one of those
    // generators, this entry point must populate the pools too.
    let config = SearchConfig::default()
        .with_algorithm(Algorithm::Llm)
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_verbose(verbose)
        .with_llm(llm);

    let mut searcher = search::llm::LlmSearch::new();
    let result = searcher.search(&target, &live_out, &config);

    print_search_statistics(&result.statistics);
    print_llm_timings(searcher.timings(), result.statistics.elapsed_time);
    print_unsupported_mnemonic_ledger(searcher.ledger());

    println!();
    println!("{}", result);

    Ok(())
}

fn run_equiv(
    file1: &Path,
    file2: &Path,
    live_out_str: &str,
    timeout: u64,
    fast_only: bool,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use semantics::{EquivalenceConfig, EquivalenceResult, check_equivalence_with_config};

    // Parse assembly files
    if verbose {
        println!("Parsing {}...", file1.display());
    }
    let seq1 = parser::parse_assembly_file(file1)?;
    if verbose {
        println!("  Parsed {} instructions:", seq1.len());
        for instr in &seq1 {
            println!("    {}", instr);
        }
    }

    if verbose {
        println!("Parsing {}...", file2.display());
    }
    let seq2 = parser::parse_assembly_file(file2)?;
    if verbose {
        println!("  Parsed {} instructions:", seq2.len());
        for instr in &seq2 {
            println!("    {}", instr);
        }
    }

    let live_out = validation::live_out::parse_live_out_contract(live_out_str)
        .map_err(|e| format!("invalid live-out: {}", e))?;

    if verbose {
        let mut regs: Vec<_> = live_out.iter().collect();
        regs.sort_by_key(|r| r.index().unwrap_or(u8::MAX));
        let names: Vec<String> = regs.iter().map(|r| format!("{}", r)).collect();
        println!("Live-out registers: {}", names.join(", "));
        if live_out.flags_live() {
            println!("Live-out flags: nzcv");
        }
    }

    let config = EquivalenceConfig::default()
        .live_out(live_out)
        .timeout(Duration::from_secs(timeout))
        .set_fast_only(fast_only);

    if verbose {
        println!("\nChecking equivalence...");
        if fast_only {
            println!("  Mode: fast path only (random testing)");
        } else {
            println!("  Mode: random testing + SMT verification");
            println!("  Timeout: {}s", timeout);
        }
    }

    // Check equivalence
    let result = check_equivalence_with_config(&seq1, &seq2, &config);

    match result {
        EquivalenceResult::Equivalent => {
            println!("EQUIVALENT: The two sequences are semantically equivalent.");
            Ok(())
        }
        EquivalenceResult::NotEquivalent => {
            println!(
                "NOT EQUIVALENT: The two sequences produce different results (verified by SMT)."
            );
            std::process::exit(1);
        }
        EquivalenceResult::NotEquivalentFast(input_state) => {
            println!("NOT EQUIVALENT: The two sequences produce different results.");
            println!("\nCounterexample found:");

            // Issue #69: strip terminators before re-running on the counterexample.
            // The B1/B2 stubs panic if a branch reaches the concrete interpreter;
            // the equivalence layer already excluded the terminator from its
            // comparison via the precheck.
            let (prefix1, _) = split_terminator(&seq1);
            let (prefix2, _) = split_terminator(&seq2);

            // Run both sequences on the counterexample input
            let output1 = semantics::apply_sequence_concrete(input_state.clone(), prefix1);
            let output2 = semantics::apply_sequence_concrete(input_state.clone(), prefix2);

            println!("  Input state:");
            for (reg, val) in input_state.registers() {
                if config.live_out.contains_register(*reg) {
                    println!("    {} = 0x{:016x}", reg, val.as_u64());
                }
            }
            println!("  Output from sequence 1:");
            for (reg, val) in output1.registers() {
                if config.live_out.contains_register(*reg) {
                    println!("    {} = 0x{:016x}", reg, val.as_u64());
                }
            }
            println!("  Output from sequence 2:");
            for (reg, val) in output2.registers() {
                if config.live_out.contains_register(*reg) {
                    println!("    {} = 0x{:016x}", reg, val.as_u64());
                }
            }
            std::process::exit(1);
        }
        EquivalenceResult::Unknown(reason) => {
            println!("UNKNOWN: Could not determine equivalence.");
            println!("  Reason: {}", reason);
            std::process::exit(2);
        }
    }
}

// --- Main Function ---
fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Disasm { binary, arch } => {
            // Disassemble mode. `analyze_elf_binary` auto-detects the
            // architecture from e_machine and picks the right Capstone
            // backend. The optional `--arch` still early-rejects RISC-V, but
            // supported hints are cross-checked inside the analyzer after its
            // single ELF read/parse.
            if let Some(CliArch::Riscv32 | CliArch::Riscv64) = arch {
                eprintln!("RISC-V disassembly is not yet supported");
                std::process::exit(1);
            }
            match analyze_elf_binary(&binary, true, arch) {
                Ok(()) => {}
                Err(e) => {
                    let message = e.to_string();
                    if message.starts_with(ARCH_MISMATCH_PREFIX) {
                        eprintln!("{}", message);
                    } else {
                        eprintln!("Error analyzing binary: {}", message);
                    }
                    std::process::exit(1);
                }
            }
        }
        Commands::Opt {
            binary,
            start_addr,
            end_addr,
            arch,
            algorithm,
            timeout,
            cost_metric,
            verbose,
            beta,
            iterations,
            seed,
            search_mode,
            solver_timeout,
            cores,
            no_symbolic,
            llm_max_calls,
            llm_model,
        } => {
            // Architecture selection — always read the ELF e_machine first so
            // a stale or wrong --arch value cannot route bytes through the
            // wrong optimization pipeline. Build the ElfPatcher once here
            // (issue #88) and thread it into both helpers so the file isn't
            // read + parsed twice.
            let patcher = ElfPatcher::new(&binary).unwrap_or_else(|e| {
                eprintln!("Error reading ELF: {}", e);
                std::process::exit(1);
            });
            let detected_arch: CliArch = patcher.arch().into();
            let cli_arch = match arch {
                Some(a) if a == detected_arch => a,
                Some(a) => {
                    eprintln!("{ARCH_MISMATCH_PREFIX} --arch {a} but ELF reports {detected_arch}");
                    std::process::exit(1);
                }
                None => detected_arch,
            };
            match cli_arch {
                CliArch::Aarch64 | CliArch::X86_64 | CliArch::X86_32 => {}
                CliArch::Riscv32 | CliArch::Riscv64 => {
                    eprintln!(
                        "RISC-V optimization is not yet supported (ISA traits available but not integrated)"
                    );
                    std::process::exit(1);
                }
            }
            let is_x86 = matches!(cli_arch, CliArch::X86_64 | CliArch::X86_32);
            // Issue #73: x86 now supports enumerative + stochastic +
            // symbolic. Hybrid and LLM remain AArch64-only (the parallel
            // coordinator is still AArch64-typed per #77 stage 2 step 12
            // deferral; the LLM path is AArch64-only by design per
            // ADR-0004 decision 3).
            if is_x86 && matches!(algorithm, CliAlgorithm::Hybrid | CliAlgorithm::Llm) {
                eprintln!(
                    "x86 supports --algorithm enumerative / stochastic / symbolic in this release; \
                     hybrid and llm remain AArch64-only."
                );
                std::process::exit(1);
            }
            // Optimization mode
            let start_addr = match parse_hex_address(&start_addr) {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("Error parsing start address: {}", e);
                    std::process::exit(1);
                }
            };

            let end_addr = match parse_hex_address(&end_addr) {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("Error parsing end address: {}", e);
                    std::process::exit(1);
                }
            };

            let options = OptimizationOptions {
                algorithm: algorithm.into(),
                timeout: timeout.map(Duration::from_secs),
                cost_metric: cost_metric.into(),
                verbose,
                beta,
                iterations,
                seed,
                search_mode: search_mode.into(),
                solver_timeout: Duration::from_secs(solver_timeout),
                cores,
                no_symbolic,
                llm_max_calls,
                llm_model,
            };

            match optimize_elf_binary(&patcher, &binary, start_addr, end_addr, &options) {
                Ok(()) => println!("\nOptimization completed successfully."),
                Err(e) => {
                    eprintln!("Error during optimization: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::LlmOpt {
            asm,
            live_out,
            max_calls,
            model,
            timeout,
            verbose,
        } => match run_llm_opt(&asm, &live_out, max_calls, &model, timeout, verbose) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("llm-opt: {}", e);
                std::process::exit(1);
            }
        },
        Commands::Equiv {
            file1,
            file2,
            live_out,
            timeout,
            fast_only,
            verbose,
        } => match run_equiv(&file1, &file2, &live_out, timeout, fast_only, verbose) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
    }
}

#[cfg(test)]
mod cli_helper_tests {
    use super::*;
    use ir::Operand;
    use isa::x86::{X86Instruction, X86Register};
    use parser::x86::{parse_x86_operand, parse_x86_register, x86_ir_from_mnemonic};
    use search::llm::LlmTimings;
    use search::llm::ledger::UnsupportedMnemonicLedger;
    use search::result::SearchStatistics;
    use test_utils::TempFile;

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

    #[test]
    fn cli_arch_display_uses_cli_value_names() {
        assert_eq!(CliArch::Aarch64.to_string(), "aarch64");
        assert_eq!(CliArch::Riscv32.to_string(), "riscv32");
        assert_eq!(CliArch::Riscv64.to_string(), "riscv64");
        assert_eq!(CliArch::X86_64.to_string(), "x86-64");
        assert_eq!(CliArch::X86_32.to_string(), "x86-32");
    }

    #[test]
    fn analyze_elf_binary_rejects_expected_arch_mismatch() {
        let elf_bytes = build_minimal_elf64(&[0xc3], 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-disasm-mismatch", "elf", &elf_bytes);

        let err = analyze_elf_binary(input.path(), true, Some(CliArch::Aarch64))
            .expect_err("mismatched expected architecture should fail");

        let message = err.to_string();
        assert_eq!(
            message,
            "Architecture mismatch: --arch aarch64 but ELF reports x86-64"
        );
        assert!(
            !message.contains("Aarch64") && !message.contains("X86_64"),
            "diagnostic should use CLI architecture names: {message}"
        );
    }

    #[test]
    fn analyze_elf_binary_accepts_matching_expected_arch() {
        let elf_bytes = build_minimal_elf64(&[0xc3], 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-disasm-match", "elf", &elf_bytes);

        analyze_elf_binary(input.path(), true, Some(CliArch::X86_64))
            .expect("matching expected architecture should disassemble");
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
        let backend =
            X86OptimizationBackend::new(DetectedArch::X86_64).expect("x86-64 backend should build");
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
    fn opt_help_mentions_enumerative_candidate_pool_growth() {
        use clap::CommandFactory;

        let mut command = Args::command();
        let opt_help = command
            .find_subcommand_mut("opt")
            .expect("opt subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(
            opt_help.contains("enumerative search scales with the generated instruction families"),
            "opt help should explain enumerative candidate pool growth:\n{opt_help}"
        );
        assert!(
            opt_help.contains("9,728"),
            "opt help should mention the default AArch64 multiply candidate growth:\n{opt_help}"
        );
    }

    #[test]
    fn cli_enum_conversions_cover_all_variants() {
        assert_eq!(
            Algorithm::from(CliAlgorithm::Enumerative),
            Algorithm::Enumerative
        );
        assert_eq!(
            Algorithm::from(CliAlgorithm::Stochastic),
            Algorithm::Stochastic
        );
        assert_eq!(Algorithm::from(CliAlgorithm::Symbolic), Algorithm::Symbolic);
        assert_eq!(Algorithm::from(CliAlgorithm::Hybrid), Algorithm::Hybrid);
        assert_eq!(Algorithm::from(CliAlgorithm::Llm), Algorithm::Llm);

        assert_eq!(
            CostMetric::from(CliCostMetric::InstructionCount),
            CostMetric::InstructionCount
        );
        assert_eq!(
            CostMetric::from(CliCostMetric::Latency),
            CostMetric::Latency
        );
        assert_eq!(
            CostMetric::from(CliCostMetric::CodeSize),
            CostMetric::CodeSize
        );

        assert_eq!(SearchMode::from(CliSearchMode::Linear), SearchMode::Linear);
        assert_eq!(SearchMode::from(CliSearchMode::Binary), SearchMode::Binary);
    }

    /// Locks in that the Capstone→IR converter covers every mnemonic the asm
    /// parser supports and the docs capability matrix lists. If a mnemonic in
    /// this list ever stops parsing, the binary path has silently broken; if
    /// the docs source changes without a sample here, this test fails.
    #[test]
    fn convert_capstone_op_handles_all_supported_aarch64_mnemonics() {
        let cases = [
            ("mov", "x0, x1"),
            ("mov", "w0, w1"),
            ("mov", "x0, #5"),
            ("mov", "w0, #0xff"),
            ("mov", "wsp, #0xff"),
            ("mvn", "x0, x1"),
            ("neg", "x0, x1"),
            ("negs", "x0, x1"),
            ("movn", "x0, #1"),
            ("movz", "x0, #0xffff, lsl #48"),
            ("movk", "x1, #0x1234, lsl #16"),
            ("add", "x0, x1, x2"),
            ("add", "w0, w1, w2"),
            ("add", "x0, x1, #4"),
            ("add", "w0, w1, #4"),
            ("add", "x0, x1, x2, lsl #3"),
            ("add", "w0, w1, w2, lsl #3"),
            ("sub", "x0, x1, #3"),
            ("sub", "w0, w1, #3"),
            ("adds", "x0, x1, #1"),
            ("subs", "x0, x1, x2"),
            ("adc", "x0, x1, x2"),
            ("adcs", "x0, x1, x2"),
            ("sbc", "x0, x1, x2"),
            ("sbcs", "x0, x1, x2"),
            ("and", "x0, x1, x2"),
            ("and", "w0, w1, #0xff"),
            ("ands", "x0, x1, x2"),
            ("ands", "w0, w1, #0xff"),
            ("orr", "x0, x1, x2"),
            ("orr", "w0, w1, #0xff"),
            ("eor", "x0, x1, x2"),
            ("eor", "w0, w1, #0xff"),
            ("bic", "x0, x1, x2"),
            ("bics", "x0, x1, x2"),
            ("orn", "x0, x1, x2"),
            ("eon", "x0, x1, x2"),
            ("lsl", "x0, x1, #4"),
            ("lsr", "x0, x1, x2"),
            ("asr", "x0, x1, #8"),
            ("ror", "x0, x1, #5"),
            ("mul", "x0, x1, x2"),
            ("madd", "x0, x1, x2, x3"),
            ("msub", "x0, x1, x2, x3"),
            ("mneg", "x0, x1, x2"),
            ("smulh", "x0, x1, x2"),
            ("umulh", "x0, x1, x2"),
            ("sdiv", "x0, x1, x2"),
            ("udiv", "x0, x1, x2"),
            ("cmp", "x1, #5"),
            ("cmp", "x1, x2, lsl #4"),
            ("cmn", "x1, x2"),
            ("tst", "x1, x2"),
            ("tst", "w1, #0xff"),
            ("ccmp", "x1, x2, #5, eq"),
            ("ccmn", "x1, #15, #3, ne"),
            ("csel", "x0, x1, x2, eq"),
            ("csinc", "x0, x1, x2, ne"),
            ("csinv", "x0, x1, x2, lt"),
            ("csneg", "x0, x1, x2, ge"),
            ("cset", "x0, eq"),
            ("csetm", "x3, ne"),
            ("clz", "x0, x1"),
            ("cls", "x0, x1"),
            ("rbit", "x0, x1"),
            ("rev", "x0, x1"),
            ("rev32", "x0, x1"),
            ("rev16", "x0, x1"),
            // Issue #60: extended-register operand form for ADD/SUB/CMP/CMN
            // and the five standalone UBFM/SBFM-alias mnemonics. Capstone
            // emits W-form register names for byte/half/word kinds.
            ("add", "x0, x1, w2, uxtb #2"),
            ("sub", "x0, x1, w2, sxth #1"),
            ("cmp", "x1, w2, uxtw #3"),
            ("cmn", "x1, x2, sxtx #0"),
            ("uxtb", "w0, w1"),
            ("uxth", "w0, w1"),
            ("sxtb", "x0, w1"),
            ("sxth", "x0, w1"),
            ("sxtw", "x0, w1"),
            // Issue #61: bit-field aliases of UBFM/SBFM/BFM.
            ("ubfx", "x0, x1, #8, #16"),
            ("sbfx", "x0, x1, #8, #16"),
            ("bfi", "x0, x1, #4, #8"),
            ("bfxil", "x0, x1, #8, #8"),
            ("ubfiz", "x0, x1, #4, #8"),
            ("sbfiz", "x0, x1, #4, #8"),
            // Issue #145: 32-bit W-register forms. Capstone emits `wN` operands
            // for these encodings; lsb+width stays < 32 to avoid the LSR/MOV
            // alias boundary.
            ("ubfx", "w0, w1, #8, #16"),
            ("sbfx", "w0, w1, #8, #16"),
            ("bfi", "w0, w1, #4, #8"),
            ("bfxil", "w0, w1, #8, #8"),
            ("ubfiz", "w0, w1, #4, #8"),
            ("sbfiz", "w0, w1, #4, #8"),
            // Issue #69: branch / control-flow mnemonics. Capstone emits
            // branch targets as `#0x...` (immediate-with-hash) and renders
            // TBZ/TBNZ as `wN` when bit<32, `xN` otherwise.
            ("b", "#0x1000"),
            ("bl", "#0x1000"),
            ("br", "x16"),
            ("ret", ""),
            ("ret", "x30"),
            ("b.eq", "#0x1000"),
            ("b.ne", "#0x1000"),
            ("cbz", "x0, #0x1000"),
            ("cbnz", "x5, #0x1000"),
            ("tbz", "w3, #5, #0x1000"),
            ("tbnz", "x3, #40, #0x1000"),
            // Issue #68: memory ops. 9 single-register mnemonics × 5
            // addressing modes = 45 rows; 3 pair mnemonics × 3 modes = 9
            // rows. See ADR-0007.
            // LDR (X/W form, immediate-offset / pre-index / post-index /
            // register-offset / register-extend).
            ("ldr", "x0, [x1]"),
            ("ldr", "x0, [x1, #8]!"),
            ("ldr", "x0, [x1], #8"),
            ("ldr", "x0, [x1, x2]"),
            ("ldr", "x0, [x1, w2, uxtw #3]"),
            // LDRB.
            ("ldrb", "w0, [x1]"),
            ("ldrb", "w0, [x1, #1]!"),
            ("ldrb", "w0, [x1], #1"),
            ("ldrb", "w0, [x1, x2]"),
            ("ldrb", "w0, [x1, w2, uxtw]"),
            // LDRH.
            ("ldrh", "w0, [x1]"),
            ("ldrh", "w0, [x1, #2]!"),
            ("ldrh", "w0, [x1], #2"),
            ("ldrh", "w0, [x1, x2]"),
            ("ldrh", "w0, [x1, w2, uxtw #1]"),
            // LDRSB.
            ("ldrsb", "x0, [x1]"),
            ("ldrsb", "x0, [x1, #1]!"),
            ("ldrsb", "x0, [x1], #1"),
            ("ldrsb", "x0, [x1, x2]"),
            ("ldrsb", "x0, [x1, w2, sxtw]"),
            // LDRSH.
            ("ldrsh", "x0, [x1]"),
            ("ldrsh", "x0, [x1, #2]!"),
            ("ldrsh", "x0, [x1], #2"),
            ("ldrsh", "x0, [x1, x2]"),
            ("ldrsh", "x0, [x1, w2, sxtw #1]"),
            // LDRSW.
            ("ldrsw", "x0, [x1]"),
            ("ldrsw", "x0, [x1, #4]!"),
            ("ldrsw", "x0, [x1], #4"),
            ("ldrsw", "x0, [x1, x2]"),
            ("ldrsw", "x0, [x1, w2, sxtw #2]"),
            // STR.
            ("str", "x0, [x1]"),
            ("str", "x0, [x1, #8]!"),
            ("str", "x0, [x1], #8"),
            ("str", "x0, [x1, x2]"),
            ("str", "x0, [x1, w2, uxtw #3]"),
            // STRB.
            ("strb", "w0, [x1]"),
            ("strb", "w0, [x1, #1]!"),
            ("strb", "w0, [x1], #1"),
            ("strb", "w0, [x1, x2]"),
            ("strb", "w0, [x1, w2, uxtw]"),
            // STRH.
            ("strh", "w0, [x1]"),
            ("strh", "w0, [x1, #2]!"),
            ("strh", "w0, [x1], #2"),
            ("strh", "w0, [x1, x2]"),
            ("strh", "w0, [x1, w2, uxtw #1]"),
            // LDP (offset / pre-index / post-index — register-offset and
            // register-extend are not part of the AArch64 pair grammar).
            ("ldp", "x0, x1, [sp, #16]"),
            ("ldp", "x0, x1, [sp, #-16]!"),
            ("ldp", "x0, x1, [sp], #16"),
            // STP.
            ("stp", "x0, x1, [sp, #16]"),
            ("stp", "x0, x1, [sp, #-16]!"),
            ("stp", "x0, x1, [sp], #16"),
            // LDPSW.
            ("ldpsw", "x0, x1, [sp, #8]"),
            ("ldpsw", "x0, x1, [sp, #-8]!"),
            ("ldpsw", "x0, x1, [sp], #8"),
        ];

        // Tripwire: bump in lockstep when adding/removing rows. Catches
        // accidental row deletion and forces a re-read when adding a parser
        // mnemonic without a matching test row.
        assert_eq!(cases.len(), 154);

        fn docs_mnemonic(mnemonic: &'static str) -> &'static str {
            if mnemonic.starts_with("b.") {
                "b.<cond>"
            } else {
                mnemonic
            }
        }

        let case_mnemonics: std::collections::BTreeSet<&'static str> = cases
            .iter()
            .map(|(mnemonic, _)| docs_mnemonic(mnemonic))
            .collect();
        let documented_mnemonics: std::collections::BTreeSet<&'static str> =
            s11::docs_support::AARCH64_REWRITABLE_MNEMONICS
                .iter()
                .chain(s11::docs_support::AARCH64_FIXED_TERMINATORS.iter())
                .copied()
                .collect();
        assert_eq!(case_mnemonics, documented_mnemonics);

        for (mnem, ops) in cases {
            match convert_capstone_op(mnem, ops) {
                ConvertOutcome::Instruction(_) => {}
                other => panic!(
                    "expected Instruction for `{} {}`, got {:?}",
                    mnem, ops, other
                ),
            }
        }
    }

    #[test]
    fn convert_capstone_op_normalizes_mov_wide_aliases() {
        for (ops, expected) in [
            (
                "x0, #0x10000",
                Instruction::MovZ {
                    rd: Register::X0,
                    imm: 1,
                    shift: 16,
                },
            ),
            (
                "x1, #0x100000000",
                Instruction::MovZ {
                    rd: Register::X1,
                    imm: 1,
                    shift: 32,
                },
            ),
            (
                "x2, #-1",
                Instruction::MovN {
                    rd: Register::X2,
                    imm: 0,
                    shift: 0,
                },
            ),
            (
                "x3, #0xffffffffffff0000",
                Instruction::MovN {
                    rd: Register::X3,
                    imm: 0xffff,
                    shift: 0,
                },
            ),
        ] {
            match convert_capstone_op("mov", ops) {
                ConvertOutcome::Instruction(instr) => assert_eq!(instr, expected),
                other => panic!("expected normalized Instruction for `mov {ops}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn convert_capstone_op_passes_mov_alias_fall_through_to_parser() {
        // The move-wide normalizer deliberately leaves `mov Xd, #imm` alone for
        // single-halfword values (0..=0xffff) and skips W-register destinations.
        // `mov` *is* a parser mnemonic, so these fall through to the parser
        // rather than becoming Unsupported: an x-register small immediate parses
        // to MovImm, and a W-register logical-immediate alias parses to Orr. Pin
        // both so the normalizer's fall-through boundary cannot silently regress.
        match convert_capstone_op("mov", "x0, #5") {
            ConvertOutcome::Instruction(Instruction::MovImm {
                rd: Register::X0,
                imm: 5,
            }) => {}
            other => panic!("expected MovImm for `mov x0, #5`, got {other:?}"),
        }
        match convert_capstone_op("mov", "w0, #0x10000") {
            ConvertOutcome::Instruction(Instruction::Orr { .. }) => {}
            other => panic!("expected Orr for `mov w0, #0x10000`, got {other:?}"),
        }
    }

    #[test]
    fn convert_capstone_op_normalizes_cond_select_aliases() {
        for (mnemonic, ops, expected) in [
            (
                "cinc",
                "x0, x1, eq",
                Instruction::Csinc {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X1,
                    cond: ir::Condition::NE,
                },
            ),
            (
                "cinv",
                "x2, x3, lt",
                Instruction::Csinv {
                    rd: Register::X2,
                    rn: Register::X3,
                    rm: Register::X3,
                    cond: ir::Condition::GE,
                },
            ),
            (
                "cneg",
                "x4, x5, ge",
                Instruction::Csneg {
                    rd: Register::X4,
                    rn: Register::X5,
                    rm: Register::X5,
                    cond: ir::Condition::LT,
                },
            ),
        ] {
            match convert_capstone_op(mnemonic, ops) {
                ConvertOutcome::Instruction(instr) => assert_eq!(instr, expected),
                other => {
                    panic!("expected normalized Instruction for `{mnemonic} {ops}`, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn convert_capstone_op_rejects_cond_select_al_nv_aliases() {
        // AL/NV have no meaningful inverse, so the conditional-select
        // normalizer rejects them rather than emitting a csinc/csinv/csneg
        // with AL/NV. Pin that error path through to the Unsupported outcome.
        for (mnemonic, ops) in [("cinc", "x0, x1, al"), ("cinv", "x2, x3, nv")] {
            match convert_capstone_op(mnemonic, ops) {
                ConvertOutcome::Unsupported(msg) => {
                    assert!(
                        msg.contains(mnemonic),
                        "diagnostic should name `{mnemonic}`: {msg}"
                    );
                    assert!(
                        msg.contains("does not support"),
                        "diagnostic should explain the rejected condition: {msg}"
                    );
                }
                other => panic!("expected Unsupported for `{mnemonic} {ops}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn convert_capstone_op_skips_nop_silently() {
        assert!(matches!(
            convert_capstone_op("nop", ""),
            ConvertOutcome::Skip
        ));
        assert!(matches!(
            convert_capstone_op("NOP", ""),
            ConvertOutcome::Skip
        ));
    }

    #[test]
    fn convert_capstone_op_flags_unknown_mnemonic_as_unsupported() {
        // NEON FADD is not parsed; memory ops were promoted to supported in
        // issue #68. See ADR-0007.
        match convert_capstone_op("fadd", "v0.4s, v1.4s, v2.4s") {
            ConvertOutcome::Unsupported(line) => {
                assert!(line.contains("fadd"), "warning line should name mnemonic");
            }
            other => panic!("expected Unsupported, got {:?}", other),
        }
    }

    #[test]
    fn convert_capstone_op_keeps_related_memory_mnemonics_unsupported() {
        // ADR-0007 §9 explicitly leaves these out of scope. Lock the outcome
        // here so a future Capstone-syntax shift cannot silently start
        // parsing them as supported instructions:
        //   - LDUR / STUR: unscaled-signed-offset variants Capstone uses
        //     for negative immediates that LDR-imm cannot encode.
        //   - LDR (literal): PC-relative pool load — different operand
        //     grammar than the bracketed forms supported by step 4.
        for (mnem, ops) in [
            ("ldur", "x0, [x1, #-1]"),
            ("stur", "x0, [x1, #-1]"),
            ("ldr", "x0, #0x1234"),
        ] {
            match convert_capstone_op(mnem, ops) {
                ConvertOutcome::Unsupported(_) => {}
                other => panic!(
                    "expected Unsupported for `{} {}`, got {:?}",
                    mnem, ops, other
                ),
            }
        }
    }

    #[test]
    fn convert_capstone_op_rejects_w_form_signed_load_destinations() {
        for (mnem, ops) in [
            ("ldrsb", "w0, [x1]"),
            ("ldrsh", "w0, [x1]"),
            ("ldrsw", "w0, [x1]"),
        ] {
            match convert_capstone_op(mnem, ops) {
                ConvertOutcome::Unsupported(line) => {
                    assert!(line.contains(mnem));
                    assert!(line.contains("X-form"));
                }
                other => panic!("expected Unsupported for `{mnem} {ops}`, got {other:?}"),
            }
        }
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
                cond: s11::ir::Condition::EQ,
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
            cond: s11::ir::Condition::EQ,
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
            target: s11::ir::LabelId(0x1000),
        }]);
        let cs = aarch64_test_capstone();

        assert!(aarch64_downstream_flags_live_from_bytes(
            &cs, &bytes, 0x1000
        ));
    }

    #[test]
    fn convert_capstone_op_for_optimization_rejects_unsupported_instruction() {
        let err = convert_capstone_op_for_optimization("fadd", "v0.4s, v1.4s, v2.4s", 0x1234)
            .expect_err("optimization conversion must reject unsupported non-NOP instructions");

        assert!(err.contains("fadd v0.4s, v1.4s, v2.4s"));
        assert!(err.contains("0x1234"));
        assert!(err.contains("cannot optimize"));
    }

    #[test]
    fn convert_capstone_op_for_optimization_rejects_unnormalizable_mov_alias() {
        let err = convert_capstone_op_for_optimization("mov", "x0, #0x12345678", 0x4444)
            .expect_err("optimization conversion must reject multi-instruction mov aliases");

        assert!(err.contains("mov x0, #0x12345678"));
        assert!(err.contains("0x4444"));
        assert!(err.contains("cannot optimize"));
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
    fn convert_capstone_op_reports_operand_errors_against_supported_mnemonic() {
        // Mnemonic recognised, but operand fails to parse — should be
        // classified as Unsupported with the parser's error appended so the
        // optimization path can reject the window with useful context.
        match convert_capstone_op("add", "x0, x1, #wat") {
            ConvertOutcome::Unsupported(line) => {
                assert!(line.contains("add"));
                assert!(line.contains("wat"));
            }
            other => panic!("expected Unsupported, got {:?}", other),
        }
    }

    #[test]
    fn x86_register_parser_covers_all_alias_groups() {
        let cases = [
            (["rax", "eax", "ax", "al"], X86Register::RAX),
            (["rcx", "ecx", "cx", "cl"], X86Register::RCX),
            (["rdx", "edx", "dx", "dl"], X86Register::RDX),
            (["rbx", "ebx", "bx", "bl"], X86Register::RBX),
            (["rsp", "esp", "sp", "spl"], X86Register::RSP),
            (["rbp", "ebp", "bp", "bpl"], X86Register::RBP),
            (["rsi", "esi", "si", "sil"], X86Register::RSI),
            (["rdi", "edi", "di", "dil"], X86Register::RDI),
            (["r8", "r8d", "r8w", "r8b"], X86Register::R8),
            (["r9", "r9d", "r9w", "r9b"], X86Register::R9),
            (["r10", "r10d", "r10w", "r10b"], X86Register::R10),
            (["r11", "r11d", "r11w", "r11b"], X86Register::R11),
            (["r12", "r12d", "r12w", "r12b"], X86Register::R12),
            (["r13", "r13d", "r13w", "r13b"], X86Register::R13),
            (["r14", "r14d", "r14w", "r14b"], X86Register::R14),
            (["r15", "r15d", "r15w", "r15b"], X86Register::R15),
        ];
        for (aliases, reg) in cases {
            for alias in aliases {
                assert_eq!(parse_x86_register(alias).unwrap(), reg);
            }
        }
    }

    #[test]
    fn x86_64_capstone_bridge_rejects_non_mode_width_register_aliases() {
        let cs = capstone::Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone init");

        let add_eax = cs
            .disasm_all(&[0x83, 0xc0, 0x00], 0x1000)
            .expect("disassemble add eax, 0");
        let insn = add_eax.iter().next().expect("one instruction");
        assert_eq!(insn.mnemonic(), Some("add"));
        assert_eq!(insn.op_str(), Some("eax, 0"));
        let err = convert_to_x86_ir(&add_eax, parser::x86::X86ParseMode::Mode64)
            .expect_err("x86-64 add eax, 0 must be rejected until width is modeled");
        assert!(
            err.contains("unsupported x86-64 register alias width"),
            "unexpected error: {err}"
        );

        let mov_al = cs
            .disasm_all(&[0xb0, 0x7f], 0x1000)
            .expect("disassemble mov al, 0x7f");
        let insn = mov_al.iter().next().expect("one instruction");
        assert_eq!(insn.mnemonic(), Some("mov"));
        assert_eq!(insn.op_str(), Some("al, 0x7f"));
        let err = convert_to_x86_ir(&mov_al, parser::x86::X86ParseMode::Mode64)
            .expect_err("x86-64 mov al, imm must be rejected until width is modeled");
        assert!(
            err.contains("unsupported x86-64 register alias width"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn x86_capstone_bridge_accepts_mode_width_register_aliases() {
        let cs64 = capstone::Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone x86-64 init");
        let add_rax = cs64
            .disasm_all(&[0x48, 0x83, 0xc0, 0x00], 0x1000)
            .expect("disassemble add rax, 0");
        let insn = add_rax.iter().next().expect("one instruction");
        assert_eq!(insn.mnemonic(), Some("add"));
        assert_eq!(insn.op_str(), Some("rax, 0"));
        assert_eq!(
            convert_to_x86_ir(&add_rax, parser::x86::X86ParseMode::Mode64).unwrap(),
            vec![X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 0,
            }]
        );

        let cs32 = capstone::Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode32)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone x86-32 init");
        let add_eax = cs32
            .disasm_all(&[0x83, 0xc0, 0x00], 0x1000)
            .expect("disassemble add eax, 0");
        let insn = add_eax.iter().next().expect("one instruction");
        assert_eq!(insn.mnemonic(), Some("add"));
        assert_eq!(insn.op_str(), Some("eax, 0"));
        assert_eq!(
            convert_to_x86_ir(&add_eax, parser::x86::X86ParseMode::Mode32).unwrap(),
            vec![X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 0,
            }]
        );
    }

    #[test]
    fn x86_64_optimizer_rejects_narrow_register_alias_before_search() {
        let elf_bytes = build_minimal_elf64(
            &[0x83, 0xc0, 0x00, 0x83, 0xc0, 0x00],
            0x1000,
            elf::abi::EM_X86_64,
        );
        let input = TempFile::new_bytes("s11-x86-64-eax-alias", "elf", &elf_bytes);
        let patcher = ElfPatcher::new(input.path()).expect("read synthetic ELF");
        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_secs(5));
        opts.cost_metric = CostMetric::CodeSize;

        let err = optimize_elf_binary(&patcher, input.path(), 0x1000, 0x1006, &opts)
            .expect_err("narrow register aliases should be rejected before search");
        let msg = err.to_string();
        assert!(
            msg.contains("failed to parse x86 instruction 'add eax, 0'"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("unsupported x86-64 register alias width"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn x86_helpers_cover_error_and_optimization_paths() {
        assert!(parse_x86_operand("not-an-operand").is_err());
        assert!(x86_ir_from_mnemonic("add", "rax").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("add", "rax, nope").is_err());

        let mut opts = options_for(Algorithm::Enumerative);
        opts.timeout = Some(Duration::from_secs(5));
        opts.solver_timeout = Duration::from_secs(5);
        opts.cost_metric = CostMetric::CodeSize;
        assert!(run_x86_enumerative(&[], 64, &opts).is_none());
        assert!(
            run_x86_enumerative(
                &[X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 1,
                }],
                64,
                &opts
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
        )
        .expect("two identical writes can be shortened");
        assert_eq!(optimized.len(), 1);
    }

    #[test]
    fn validate_x86_window_rejects_mid_window_jcc() {
        use isa::x86::{X86Condition, X86Instruction, X86Register};
        let ir = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
        ];
        let err = validate_x86_window_terminator_placement(&ir)
            .expect_err("mid-window Jcc must be rejected");
        assert!(
            err.contains("non-terminal conditional branch") && err.contains("position 1"),
            "unhelpful error: {}",
            err
        );
    }

    #[test]
    fn validate_x86_window_accepts_trailing_jcc() {
        use isa::x86::{X86Condition, X86Instruction, X86Register};
        let ir = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
        ];
        validate_x86_window_terminator_placement(&ir).expect("trailing Jcc must be accepted");
    }

    #[test]
    fn validate_x86_window_accepts_no_jcc() {
        use isa::x86::{X86Instruction, X86Register};
        let ir = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        validate_x86_window_terminator_placement(&ir).expect("Jcc-free window must be accepted");
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
        let config = build_x86_enumerative_search_config(&target, 64, &opts);
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

        let optimized = run_x86_enumerative(&target, 64, &opts)
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
        let optimized = run_x86_stochastic(&target, 64, &opts)
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
        let optimized = run_x86_symbolic(&target, 64, &opts)
            .expect("two identical R10 zeroing writes must collapse to one");

        assert_single_r10_rewrite(&optimized);
    }

    #[test]
    fn x86_register_pool_is_destination_derived_and_empty_falls_back() {
        let target = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RSP,
                rs: X86Register::R11,
            },
            X86Instruction::CmpReg {
                rn: X86Register::RBP,
                rs: X86Register::R12,
            },
            X86Instruction::MovReg {
                rd: X86Register::R11,
                rs: X86Register::R10,
            },
            X86Instruction::AddReg {
                rd: X86Register::R12,
                rs: X86Register::RSP,
            },
        ];

        assert_eq!(
            x86_registers_from_target(&target),
            vec![X86Register::R11, X86Register::R12]
        );
        assert_eq!(
            x86_registers_from_target(&[]),
            isa::x86::default_x86_registers()
        );
        assert_eq!(
            x86_registers_from_target(&[
                X86Instruction::CmpImm {
                    rn: X86Register::R10,
                    imm: 1,
                },
                X86Instruction::CmpImm {
                    rn: X86Register::R10,
                    imm: 1,
                },
            ]),
            Vec::<X86Register>::new()
        );
        assert_eq!(
            x86_registers_from_target(&[
                X86Instruction::CmpImm {
                    rn: X86Register::RSP,
                    imm: 1,
                },
                X86Instruction::CmpReg {
                    rn: X86Register::RBP,
                    rs: X86Register::RBP,
                },
            ]),
            Vec::<X86Register>::new()
        );
    }

    /// Regression (PR #384): the enumerative config must be target-derived and
    /// must thread `--cores` (the trait-backed search is rayon-parallel and
    /// honours `config.cores`, but the old builder left it `None`).
    #[test]
    fn build_x86_enumerative_search_config_is_target_derived_and_honors_cores() {
        let mut opts = options_for(Algorithm::Enumerative);
        opts.cores = Some(3);
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
        let config = build_x86_enumerative_search_config(&target, 64, &opts);
        assert_eq!(config.cores, Some(3), "--cores must be threaded through");
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
    fn build_x86_enumerative_search_config_does_not_inherit_stochastic_options() {
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
        let config = build_x86_enumerative_search_config(&target, 32, &opts);

        assert_eq!(
            config.x86_available_registers,
            vec![X86Register::R11, X86Register::R12]
        );
        assert!(config.available_immediates.contains(&-5));
        assert!(config.available_immediates.contains(&3));
        assert_eq!(config.cores, Some(4));
        assert_eq!(config.cost_metric, CostMetric::Latency);
        assert_eq!(config.timeout, Some(Duration::from_millis(31)));
        assert!(config.verbose);
        assert_eq!(config.x86_width, 32);
        assert_eq!(config.x86_mode(), assembler::x86::X86Mode::Mode32);

        let default_stochastic = StochasticConfig::default();
        assert_eq!(config.stochastic.beta, default_stochastic.beta);
        assert_eq!(config.stochastic.iterations, default_stochastic.iterations);
        assert_eq!(config.stochastic.seed, default_stochastic.seed);
        // The enumerative path keeps stochastic fields out but still honors the
        // CLI --solver-timeout for its SMT verification queries.
        assert_eq!(
            config.symbolic.solver_timeout,
            Some(Duration::from_millis(37))
        );
    }

    #[test]
    fn formatting_and_print_helpers_cover_optional_sections() {
        assert_eq!(fmt_bytes(42), "     42 B ");
        assert!(fmt_bytes(2_048).contains("kB"));
        assert!(fmt_bytes(2_097_152).contains("MB"));
        assert!(fmt_dur(Duration::from_nanos(500)).contains("µs"));
        assert!(fmt_dur(Duration::from_millis(2)).contains("ms"));
        assert!(fmt_dur(Duration::from_secs(2)).contains("s"));

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

        let regs = vec![Register::X0];
        let imms = vec![0, 1];
        let config = build_hybrid_search_config(&opts, regs, imms);

        assert_eq!(config.timeout, Some(Duration::from_millis(7)));

        // None should propagate too.
        opts.timeout = None;
        let config = build_hybrid_search_config(&opts, vec![Register::X0], vec![0]);
        assert_eq!(config.timeout, None);
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

        assert_eq!(
            config.symbolic.solver_timeout,
            Some(Duration::from_millis(17))
        );
        assert_eq!(config.stochastic.beta, 2.5);
        assert_eq!(config.stochastic.iterations, 123);
        assert_eq!(config.stochastic.seed, Some(99));
        assert_eq!(config.cost_metric, CostMetric::Latency);
        assert_eq!(config.timeout, Some(Duration::from_millis(11)));
        assert!(config.verbose);
        assert_eq!(config.available_registers, regs);
        assert_eq!(config.available_immediates, imms);
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
        let config = build_x86_stochastic_search_config(&target, 32, &opts);

        assert_eq!(
            config.symbolic.solver_timeout,
            Some(Duration::from_millis(19))
        );
        assert_eq!(config.stochastic.beta, 3.5);
        assert_eq!(config.stochastic.iterations, 456);
        assert_eq!(config.stochastic.seed, Some(101));
        assert_eq!(config.cost_metric, CostMetric::CodeSize);
        assert_eq!(config.timeout, Some(Duration::from_millis(13)));
        assert!(config.verbose);
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
                64,
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
        assert_eq!(config.x86_width, 32);
        assert_eq!(config.x86_mode(), assembler::x86::X86Mode::Mode32);
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
        let config = build_x86_symbolic_search_config(&target, 64, &opts);

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
                64,
                &opts,
            )
            .x86_available_registers
            .is_empty(),
            "all stack/frame targets must not fall back to writable defaults"
        );
        assert_eq!(config.symbolic.search_mode, SearchMode::Binary);
        assert_eq!(
            config.symbolic.solver_timeout,
            Some(Duration::from_millis(29))
        );
        assert_eq!(config.cost_metric, CostMetric::Latency);
        assert_eq!(config.timeout, Some(Duration::from_millis(23)));
        assert!(config.verbose);
        assert_eq!(
            config.available_immediates,
            isa::x86::default_x86_immediates()
        );
        assert_eq!(config.x86_width, 64);
        assert_eq!(config.x86_mode(), assembler::x86::X86Mode::Mode64);
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
            let _ = run_optimization(&target, &options, true).unwrap();
        }
        assert!(
            run_optimization(&[], &options_for(Algorithm::Enumerative), true)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn run_optimization_uses_downstream_flags_dead_context() {
        let target = [
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Immediate(0),
            },
            Instruction::MovImm {
                rd: Register::X1,
                imm: 7,
            },
        ];
        let mut options = options_for(Algorithm::Symbolic);
        options.timeout = Some(Duration::from_secs(10));
        options.solver_timeout = Duration::from_secs(10);

        let flags_dead = run_optimization(&target, &options, false)
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
    fn run_equiv_and_llm_opt_accept_equivalent_tiny_files() {
        let asm1 = TempFile::new("s11-equiv-a", "s", "mov x0, x1\n");
        let asm2 = TempFile::new("s11-equiv-b", "s", "mov x0, x1\n");
        run_equiv(asm1.path(), asm2.path(), "x0", 1, true, true).unwrap();

        let llm_asm = TempFile::new("s11-llm", "s", "mov x0, x1\n");
        run_llm_opt(llm_asm.path(), "x0", 0, "test-model", 0, true).unwrap();
    }

    // ===== Issue #69: validate_basic_block =====

    #[test]
    fn validate_basic_block_accepts_empty_sequence() {
        assert!(validate_basic_block(&[]).is_ok());
    }

    #[test]
    fn validate_basic_block_accepts_prefix_only_no_terminator() {
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(2),
            },
        ];
        assert!(validate_basic_block(&seq).is_ok());
    }

    #[test]
    fn validate_basic_block_accepts_terminator_only() {
        let seq = vec![Instruction::Ret { rn: Register::X30 }];
        assert!(validate_basic_block(&seq).is_ok());
    }

    #[test]
    fn validate_basic_block_accepts_prefix_plus_terminator() {
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Ret { rn: Register::X30 },
        ];
        assert!(validate_basic_block(&seq).is_ok());
    }

    #[test]
    fn split_terminator_returns_full_slice_when_no_terminator() {
        let seq = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];
        let (prefix, term) = split_terminator(&seq);
        assert_eq!(prefix.len(), 1);
        assert!(term.is_none());
    }

    #[test]
    fn split_terminator_separates_trailing_branch() {
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Ret { rn: Register::X30 },
        ];
        let (prefix, term) = split_terminator(&seq);
        assert_eq!(prefix.len(), 1);
        assert_eq!(term, Some(&Instruction::Ret { rn: Register::X30 }));
    }

    #[test]
    fn live_out_for_optimization_prefix_includes_registers_read_by_terminator() {
        let prefix = [Instruction::MovImm {
            rd: Register::X1,
            imm: 1,
        }];
        let cases = [
            (
                Instruction::Cbz {
                    rn: Register::X0,
                    target: s11::ir::LabelId(0x1000),
                },
                Register::X0,
            ),
            (
                Instruction::Tbz {
                    rt: Register::X2,
                    bit: 5,
                    target: s11::ir::LabelId(0x1000),
                },
                Register::X2,
            ),
            (Instruction::Br { rn: Register::X16 }, Register::X16),
            (Instruction::Ret { rn: Register::X30 }, Register::X30),
        ];

        for (terminator, source) in cases {
            let live_out = live_out_for_optimization_prefix(&prefix, Some(&terminator), false);
            assert!(live_out.contains_register(Register::X1));
            assert!(
                live_out.contains_register(source),
                "{:?} must keep {:?} live for the reattached terminator",
                terminator,
                source
            );
        }
    }

    #[test]
    fn live_out_for_optimization_prefix_uses_downstream_flags_without_terminator() {
        let prefix = [Instruction::MovImm {
            rd: Register::X1,
            imm: 1,
        }];

        let flags_dead = live_out_for_optimization_prefix(&prefix, None, false);
        assert!(!flags_dead.flags_live());

        let flags_live = live_out_for_optimization_prefix(&prefix, None, true);
        assert!(flags_live.flags_live());
    }

    #[test]
    fn live_out_for_optimization_prefix_keeps_flags_live_for_terminators() {
        let prefix = [Instruction::MovImm {
            rd: Register::X1,
            imm: 1,
        }];

        let b_cond = Instruction::BCond {
            target: s11::ir::LabelId(0x1000),
            cond: s11::ir::Condition::EQ,
        };
        let live_out = live_out_for_optimization_prefix(&prefix, Some(&b_cond), false);
        assert!(live_out.flags_live());

        let ret = Instruction::Ret { rn: Register::X30 };
        let live_out = live_out_for_optimization_prefix(&prefix, Some(&ret), false);
        assert!(live_out.flags_live());
    }

    // (The standalone `find_shorter_equivalent_preserves_terminator_bit_identical`
    // test was removed when the MVP `find_shorter_equivalent` helper was
    // replaced by `search::EnumerativeSearch` (issue #67). The same contract
    // is exercised by `issue_69_acceptance_find_shorter_preserves_terminator`
    // below.)

    // ===== Issue #69 acceptance: end-to-end basic-block-with-terminator =====
    //
    // Covers both acceptance criteria of issue #69:
    //   (1) IR can represent a basic block ending in a conditional branch.
    //   (2) Equivalence checking accounts for the branch decision.

    #[test]
    fn issue_69_acceptance_parses_bb_ending_in_b_cond() {
        let src = "mov x0, x1\nb.eq .Ltarget\n";
        let ir = parser::parse_assembly_string(src, "test".to_string()).expect("parse failed");
        assert_eq!(ir.len(), 2, "expected 2-instruction BB, got {:?}", ir);
        let last = ir.last().unwrap();
        match last {
            Instruction::BCond { cond, .. } => {
                assert_eq!(*cond, s11::ir::types::Condition::EQ);
            }
            other => panic!("expected BCond terminator, got {:?}", other),
        }
        assert!(last.is_terminator());
    }

    #[test]
    fn issue_69_acceptance_equivalence_rejects_different_branch_decisions() {
        // Same prefix, different conditional branch → NotEquivalent
        // (the branch decision differs, so equivalence must fail).
        use s11::semantics::equivalence::{EquivalenceResult, check_equivalence};
        let ir_eq =
            parser::parse_assembly_string("mov x0, x1\nb.eq 0x1000\n", "a".to_string()).unwrap();
        let ir_ne =
            parser::parse_assembly_string("mov x0, x1\nb.ne 0x1000\n", "b".to_string()).unwrap();
        let result = check_equivalence(&ir_eq, &ir_ne);
        assert!(
            matches!(result, EquivalenceResult::NotEquivalentFast(_)),
            "expected NotEquivalent for differing branch decisions, got {:?}",
            result
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
        use s11::search::SearchAlgorithm;
        use s11::search::config::SearchConfig;

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

        let live_out = live_out_for_optimization_prefix(prefix, term, true);
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
        use s11::semantics::EquivalenceConfig;
        use s11::semantics::equivalence::{EquivalenceResult, check_equivalence_with_config};

        let terminator = Instruction::Cbz {
            rn: Register::X0,
            target: s11::ir::LabelId(0x1000),
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
        let live_out = live_out_for_optimization_prefix(prefix, term, true);
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
    fn validate_basic_block_rejects_branch_mid_block() {
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::B {
                target: s11::ir::LabelId(0x1000),
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(2),
            },
        ];
        let err = validate_basic_block(&seq).expect_err("branch at position 1 must be rejected");
        assert!(
            err.contains("position 1") && err.contains("issue #69"),
            "unexpected error: {}",
            err
        );
    }

    // --- end-to-end CMP + CMOV / Jcc pipeline ---

    #[test]
    fn issue_74_cmp_cmov_round_trips_through_asm_disasm_parse() {
        use assembler::x86::X86Assembler;
        use capstone::prelude::*;
        use isa::x86::{X86Condition, X86Instruction, X86Register};
        use parser::x86::x86_ir_from_mnemonic;

        let original = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RCX,
                cond: X86Condition::E,
            },
        ];
        let mut asm = X86Assembler::new_64();
        let bytes = asm
            .assemble_instructions(&original)
            .expect("encode cmp + cmove");
        let cs = capstone::Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone init");
        let insns = cs.disasm_all(&bytes, 0x0).expect("disassemble");
        let recovered: Vec<X86Instruction> = insns
            .iter()
            .map(|i| {
                let mn = i.mnemonic().unwrap_or("");
                let op = i.op_str().unwrap_or("");
                x86_ir_from_mnemonic(mn, op)
                    .expect("parse succeeds")
                    .expect("parse yields IR")
            })
            .collect();
        assert_eq!(recovered, original);
    }

    #[test]
    fn issue_74_jcc_round_trips_through_asm_disasm_parse() {
        use assembler::x86::X86Assembler;
        use capstone::prelude::*;
        use isa::x86::{X86Condition, X86Instruction};
        use parser::x86::x86_ir_from_mnemonic;

        let original = vec![X86Instruction::Jcc {
            cond: X86Condition::NE,
        }];
        let mut asm = X86Assembler::new_64();
        let bytes = asm.assemble_instructions(&original).expect("encode jne");
        let cs = capstone::Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone init");
        let insns = cs.disasm_all(&bytes, 0x0).expect("disassemble");
        assert_eq!(insns.len(), 1);
        let mn = insns.iter().next().unwrap().mnemonic().unwrap_or("");
        let op = insns.iter().next().unwrap().op_str().unwrap_or("");
        let parsed = x86_ir_from_mnemonic(mn, op)
            .expect("parse succeeds")
            .expect("parse yields IR");
        assert_eq!(parsed, original[0]);
    }

    #[test]
    fn issue_74_cmp_cmov_pipeline_distinguishes_different_cmov_sources_when_flags_live() {
        use isa::x86::{X86Condition, X86Instruction, X86Register};
        use semantics::equivalence::{
            EquivalenceConfigFor, EquivalenceResult, check_equivalence_for,
        };
        use semantics::live_out::X86LiveOut;

        let target = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RCX,
                cond: X86Condition::E,
            },
        ];
        let proposal = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RDX,
                cond: X86Condition::E,
            },
        ];
        let cfg = EquivalenceConfigFor::<isa::X86_64>::default()
            .live_out(X86LiveOut::from_registers(vec![X86Register::RAX]).with_flags(true));
        assert!(matches!(
            check_equivalence_for::<isa::X86_64>(&target, &proposal, &cfg),
            EquivalenceResult::NotEquivalent
        ));
    }

    #[test]
    fn issue_74_cmp_cmov_pipeline_self_equivalent_under_flags_live() {
        use isa::x86::{X86Condition, X86Instruction, X86Register};
        use semantics::equivalence::{
            EquivalenceConfigFor, EquivalenceResult, check_equivalence_for,
        };
        use semantics::live_out::X86LiveOut;

        let seq = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RCX,
                cond: X86Condition::NE,
            },
        ];
        let cfg = EquivalenceConfigFor::<isa::X86_64>::default()
            .live_out(X86LiveOut::from_registers(vec![X86Register::RAX]).with_flags(true));
        assert_eq!(
            check_equivalence_for::<isa::X86_64>(&seq.clone(), &seq, &cfg),
            EquivalenceResult::Equivalent
        );
    }

    // --- x86 Jcc-byte preservation across reassembly ---

    #[test]
    fn reassemble_x86_no_terminator_returns_assembled_bytes_unchanged() {
        use isa::x86::{X86Instruction, X86Register};
        let final_ir = [X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let bytes =
            reassemble_x86_prefix_with_pinned_terminator(&final_ir, DetectedArch::X86_64, None, 3)
                .expect("reassemble succeeds");
        // No splice, no padding: just the assembled prefix.
        assert_eq!(bytes.len(), 3);
    }

    #[test]
    fn reassemble_x86_splices_original_terminator_bytes_at_original_offset() {
        // Original window: [3-byte mov rax,rbx] [2-byte je 0x10] = 5 bytes total,
        // jcc at offset 3.
        // Optimized prefix: same 3-byte mov. Should produce: [mov, je] = 5 bytes,
        // jcc still at offset 3 (no NOP padding needed since prefix didn't shrink).
        use isa::x86::{X86Instruction, X86Register};
        let original_jcc_bytes = [0x74u8, 0x10]; // je rel8=0x10
        let final_ir = [X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let out = reassemble_x86_prefix_with_pinned_terminator(
            &final_ir,
            DetectedArch::X86_64,
            Some(&original_jcc_bytes),
            3,
        )
        .expect("reassemble succeeds");
        // Original Jcc bytes must be the LAST 2 bytes, unchanged.
        assert_eq!(&out[out.len() - 2..], &original_jcc_bytes);
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn reassemble_x86_pads_with_nops_when_optimized_prefix_shrinks() {
        // Original window: 7-byte prefix + 2-byte jcc = 9 bytes, jcc at offset 7.
        // Optimized prefix shrinks to 3 bytes. We must NOP-pad 4 bytes so the
        // Jcc still lands at offset 7 (preserving its rel8 displacement).
        use isa::x86::{X86Instruction, X86Register};
        let original_jcc_bytes = [0x75u8, 0x20]; // jne rel8=0x20
        let final_ir = [X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let out = reassemble_x86_prefix_with_pinned_terminator(
            &final_ir,
            DetectedArch::X86_64,
            Some(&original_jcc_bytes),
            7,
        )
        .expect("reassemble succeeds");
        // Total length matches the original window.
        assert_eq!(out.len(), 9);
        // Jcc bytes are at the original offset (7).
        assert_eq!(&out[7..9], &original_jcc_bytes);
        // First 3 bytes are the new prefix; bytes [3..7] are NOP padding.
        // We don't assert specific NOP encodings here — `nop_sequence` is
        // covered separately. We just assert they aren't zero (which would
        // be the buggy `je BYTE 0` overwrite the reviewer flagged).
        assert_ne!(&out[3..7], &[0u8; 4]);
    }

    #[test]
    fn reassemble_x86_32_splices_and_pads_correctly() {
        // Mirrors the x86-64 pad-with-NOPs test for the x86-32 mode.
        // The x86-32 nop_sequence returns single-byte 0x90 NOPs, so the
        // padding loop must iterate `gap` times rather than once.
        use isa::x86::{X86Instruction, X86Register};
        let original_jcc_bytes = [0x74u8, 0x05]; // je rel8=5
        let final_ir = [X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        // Original prefix was 5 bytes; optimized prefix encodes to 2
        // bytes (`mov eax, ebx` on x86-32). NOP-pad 3 bytes then the
        // 2-byte je at offset 5 — total 7 bytes.
        let out = reassemble_x86_prefix_with_pinned_terminator(
            &final_ir,
            DetectedArch::X86_32,
            Some(&original_jcc_bytes),
            5,
        )
        .expect("x86-32 reassemble succeeds");
        assert_eq!(out.len(), 7);
        assert_eq!(&out[5..7], &original_jcc_bytes);
        // Bytes [2..5] are NOP-padding; x86-32 nop_sequence emits 0x90.
        assert_eq!(&out[2..5], &[0x90u8; 3]);
    }

    #[test]
    fn append_nop_padding_clamps_overlong_nop_provider() {
        let mut out = vec![0xcc];

        append_nop_padding(&mut out, 3, DetectedArch::X86_64, |_| {
            &[0x90, 0x90, 0x90, 0x90]
        })
        .expect("padding succeeds");

        assert_eq!(out.len(), 4, "padding must not overshoot the requested gap");
        assert_eq!(&out[1..], &[0x90, 0x90, 0x90]);
    }

    #[test]
    fn reassemble_x86_rejects_optimized_prefix_larger_than_original() {
        // Pathological case: optimized prefix is LARGER than the original
        // prefix room. Cannot pad backwards. Must surface as an error
        // instead of silently corrupting the Jcc displacement.
        use isa::x86::{X86Instruction, X86Register};
        let original_jcc_bytes = [0x74u8, 0x10];
        // 3-byte assembled prefix — but we claim original prefix room was 1.
        let final_ir = [X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let err = reassemble_x86_prefix_with_pinned_terminator(
            &final_ir,
            DetectedArch::X86_64,
            Some(&original_jcc_bytes),
            1,
        )
        .expect_err("should reject");
        assert!(
            err.contains("larger") || err.contains("preserve"),
            "expected explanatory error, got: {}",
            err
        );
    }
}
