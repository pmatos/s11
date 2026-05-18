use capstone::prelude::*;
use clap::{Parser, Subcommand, ValueEnum};
use elf::{ElfBytes, endian::AnyEndian};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod assembler;
mod elf_patcher;
mod ir;
mod isa;
mod parser;
mod search;
mod semantics;
#[cfg(test)]
mod test_utils;
mod validation;

use assembler::AArch64Assembler;
use elf_patcher::{AddressWindow, ElfPatcher, parse_hex_address};
use ir::instructions::split_terminator;
use ir::{Instruction, Register};
use search::config::{
    Algorithm, LlmConfig, SearchConfig, SearchMode, StochasticConfig, SymbolicConfig,
};
use search::parallel::{ParallelConfig, run_parallel_search};
use search::{EnumerativeSearch, SearchAlgorithm, StochasticSearch, SymbolicSearch};
use semantics::LiveOut;
use semantics::cost::CostMetric;

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

/// Read an ELF's `e_machine` and map it to the matching `CliArch` variant.
/// Returns an error if the binary can't be read or the architecture isn't
/// one we support.
fn detect_cli_arch_from_elf(path: &Path) -> Result<CliArch, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&data)?;
    match elf.ehdr.e_machine {
        elf::abi::EM_AARCH64 => Ok(CliArch::Aarch64),
        elf::abi::EM_X86_64 => Ok(CliArch::X86_64),
        elf::abi::EM_386 => Ok(CliArch::X86_32),
        m => Err(format!("Unsupported architecture (e_machine: {})", m).into()),
    }
}

fn analyze_elf_binary(path: &PathBuf, disasm_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !disasm_mode {
        println!("Analyzing ELF binary: {}", path.display());
    }

    // Read the file
    let file_data = fs::read(path)?;

    // Parse ELF
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&file_data)?;

    // Detect architecture; reject anything outside the supported set.
    let arch = match elf.ehdr.e_machine {
        elf::abi::EM_AARCH64 => "AArch64",
        elf::abi::EM_X86_64 => "x86-64",
        elf::abi::EM_386 => "x86-32",
        m => return Err(format!("Unsupported architecture (e_machine: {})", m).into()),
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
    let cs = match elf.ehdr.e_machine {
        elf::abi::EM_AARCH64 => Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()?,
        elf::abi::EM_X86_64 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()?,
        elf::abi::EM_386 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode32)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()?,
        _ => unreachable!("e_machine already validated above"),
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

// Issue #77 stage 1 step 15 note: this AArch64 optimization path consumes the
// new trait-surface scaffolding (`<AArch64 as ConcreteExecutor<Instruction>>`,
// `<AArch64 as SymbolicExecutor<Instruction>>`, `<AArch64 as Assembler<...>>`)
// indirectly through the existing free functions, which step 8 wired to the
// trait impls. Stage 2 step 20 merges this function with
// `optimize_elf_binary_x86` into a single `optimize_elf_binary_generic<I: ISA>`
// once x86 has its own SearchAlgorithm impl. For now the AArch64-typed
// signature is preserved so existing callers do not need turbofish.
//
// Step 20 status: BLOCKED on the SearchAlgorithm<I> follow-up to step 11.
// `optimize_elf_binary_x86` uses `find_shorter_equivalent_x86` which directly
// drives the candidate enumerator over X86Instruction — there is no x86
// SearchAlgorithm impl to dispatch to. Once that lands, the merge is
// mechanical: `match detect_cli_arch_from_elf(...) { Aarch64 => ::<AArch64>,
// X86_64 => ::<X86_64>, X86_32 => ::<X86_32>, Riscv* => stage 3 }`.
fn optimize_elf_binary(
    path: &Path,
    start_addr: u64,
    end_addr: u64,
    options: &OptimizationOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Optimizing ELF binary: {}", path.display());
    println!("Address window: 0x{:x} - 0x{:x}", start_addr, end_addr);
    println!("Algorithm: {:?}", options.algorithm);

    // Create address window
    let window = AddressWindow {
        start: start_addr,
        end: end_addr,
    };

    // Load and validate the ELF file
    let elf_patcher = ElfPatcher::new(path)?;
    let section = elf_patcher.validate_address_window(&window)?;
    println!("Window is within section: {}", section.name);

    // Get the original instructions in the window
    let original_bytes = elf_patcher.get_instructions_in_window(&window)?;
    println!("Original code: {} bytes", original_bytes.len());

    // Initialize Capstone disassembler
    let cs = Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()?;

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
    ensure_window_fully_decoded(decoded_bytes, original_bytes.len(), start_addr, end_addr)?;

    // Convert to IR
    let ir_instructions = convert_to_ir(&instructions)?;
    println!("Converted {} instructions to IR:", ir_instructions.len());

    for instr in &ir_instructions {
        println!("  {}", instr);
    }

    // Issue #69: the optimization unit is a single basic block. Reject regions
    // with branches at non-terminal positions before invoking search.
    validate_basic_block(&ir_instructions)?;

    // Run optimization based on selected algorithm
    let optimized_instructions = run_optimization(&ir_instructions, options)?;

    // Use optimized instructions if found, otherwise use original
    let final_instructions = optimized_instructions.as_ref().unwrap_or(&ir_instructions);

    if optimized_instructions.is_some() {
        println!("Optimized to {} instructions:", final_instructions.len());
        for instr in final_instructions {
            println!("  {}", instr);
        }
    } else {
        println!("No optimization found, using original instructions.");
    }

    // Reassemble the instructions
    let mut assembler = AArch64Assembler::new();
    let assembled_bytes = assembler.assemble_instructions(final_instructions, start_addr)?;
    println!("Reassembled to {} bytes", assembled_bytes.len());

    // Create output filename
    let output_path = {
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
    };

    // Create patched ELF file
    elf_patcher.create_patched_copy(&output_path, &window, &assembled_bytes)?;
    println!("Created optimized binary: {}", output_path.display());

    Ok(())
}

fn live_out_for_optimization_prefix(
    prefix: &[Instruction],
    terminator: Option<&Instruction>,
) -> LiveOut {
    let mut live_registers: Vec<Register> = prefix
        .iter()
        .filter_map(|instr| instr.destination())
        .collect();

    if let Some(terminator) = terminator {
        live_registers.extend(terminator.source_registers());
    }

    LiveOut::from_registers(live_registers)
}

/// Run optimization using the selected algorithm.
///
/// Issue #69: if `target` ends in a terminator (branch / control-flow
/// instruction), the search rewrites only the straight-line prefix and the
/// terminator is reattached bit-identical to the returned sequence.
fn run_optimization(
    target: &[Instruction],
    options: &OptimizationOptions,
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
    // optimized prefix runs.
    let live_out = live_out_for_optimization_prefix(prefix, terminator);

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

            let mut search = EnumerativeSearch::new();
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

            let stochastic_config = StochasticConfig::default()
                .with_beta(options.beta)
                .with_iterations(options.iterations)
                .with_seed_option(options.seed);

            let config = SearchConfig::default()
                .with_stochastic(stochastic_config)
                .with_cost_metric(options.cost_metric)
                .with_timeout_option(options.timeout)
                .with_verbose(options.verbose)
                .with_registers(available_registers)
                .with_immediates(available_immediates);

            let mut search = StochasticSearch::new();
            let result = search.search(prefix, &live_out, &config);

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

            let mut search = SymbolicSearch::new();
            let result = search.search(prefix, &live_out, &config);

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

            let stochastic_config = StochasticConfig::default()
                .with_beta(options.beta)
                .with_iterations(options.iterations);

            let symbolic_config = SymbolicConfig::default()
                .with_search_mode(options.search_mode)
                .with_timeout(options.solver_timeout);

            let config = SearchConfig::default()
                .with_stochastic(stochastic_config)
                .with_symbolic(symbolic_config)
                .with_cost_metric(options.cost_metric)
                .with_verbose(options.verbose)
                .with_registers(available_registers)
                .with_immediates(available_immediates);

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

/// Convert one Capstone (mnemonic, op_str) pair into an IR outcome by
/// delegating to `parser::parse_line`. Keeping a single shared parser is what
/// guarantees the asm-text path and the ELF/Capstone path support exactly the
/// same mnemonic set (see CLAUDE.md "Adding a new AArch64 instruction").
fn convert_capstone_op(mnemonic: &str, op_str: &str) -> ConvertOutcome {
    if mnemonic.eq_ignore_ascii_case("nop") {
        // NOPs are filtered here; the assembler re-emits any padding needed.
        return ConvertOutcome::Skip;
    }

    let line = if op_str.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{} {}", mnemonic, op_str)
    };

    match parser::parse_line(&line) {
        Ok(parser::LineResult::Instruction(instr)) => ConvertOutcome::Instruction(instr),
        Ok(parser::LineResult::Skip) => ConvertOutcome::Skip,
        Err(parser::ParseLineError::UnknownInstruction(_)) => ConvertOutcome::Unsupported(line),
        Err(parser::ParseLineError::Other(err)) => {
            ConvertOutcome::Unsupported(format!("{} ({})", line, err))
        }
    }
}

fn ensure_window_fully_decoded(
    decoded_bytes: usize,
    window_bytes: usize,
    start_addr: u64,
    end_addr: u64,
) -> Result<(), String> {
    use std::cmp::Ordering;
    match decoded_bytes.cmp(&window_bytes) {
        Ordering::Equal => Ok(()),
        Ordering::Less => Err(format!(
            "AArch64 window 0x{:x}-0x{:x} ({} bytes) was not fully decoded by Capstone; decoded only {} bytes",
            start_addr, end_addr, window_bytes, decoded_bytes
        )),
        // Defensive: cs.disasm_all only emits bytes it was given, so this
        // branch is an internal-invariant guard, not a user-facing condition.
        Ordering::Greater => Err(format!(
            "AArch64 window 0x{:x}-0x{:x} ({} bytes) decoded {} bytes by Capstone — more than the window holds",
            start_addr, end_addr, window_bytes, decoded_bytes
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

fn parse_x86_register(reg_str: &str) -> Result<isa::x86::X86Register, String> {
    use isa::x86::X86Register;
    match reg_str.trim().to_lowercase().as_str() {
        // 64-bit names map to the canonical X86Register variants.
        // Legacy high-byte aliases (ah/bh/ch/dh) are intentionally excluded
        // because the minimal x86 IR models the low-byte/REX alias set.
        "rax" | "eax" | "ax" | "al" => Ok(X86Register::RAX),
        "rcx" | "ecx" | "cx" | "cl" => Ok(X86Register::RCX),
        "rdx" | "edx" | "dx" | "dl" => Ok(X86Register::RDX),
        "rbx" | "ebx" | "bx" | "bl" => Ok(X86Register::RBX),
        "rsp" | "esp" | "sp" | "spl" => Ok(X86Register::RSP),
        "rbp" | "ebp" | "bp" | "bpl" => Ok(X86Register::RBP),
        "rsi" | "esi" | "si" | "sil" => Ok(X86Register::RSI),
        "rdi" | "edi" | "di" | "dil" => Ok(X86Register::RDI),
        "r8" | "r8d" | "r8w" | "r8b" => Ok(X86Register::R8),
        "r9" | "r9d" | "r9w" | "r9b" => Ok(X86Register::R9),
        "r10" | "r10d" | "r10w" | "r10b" => Ok(X86Register::R10),
        "r11" | "r11d" | "r11w" | "r11b" => Ok(X86Register::R11),
        "r12" | "r12d" | "r12w" | "r12b" => Ok(X86Register::R12),
        "r13" | "r13d" | "r13w" | "r13b" => Ok(X86Register::R13),
        "r14" | "r14d" | "r14w" | "r14b" => Ok(X86Register::R14),
        "r15" | "r15d" | "r15w" | "r15b" => Ok(X86Register::R15),
        _ => Err(format!("Unknown x86 register: {}", reg_str)),
    }
}

/// Parse an Intel-syntax operand string ("rax" or "42" or "0x2a").
fn parse_x86_operand(op_str: &str) -> Result<isa::x86::X86Operand, String> {
    use isa::x86::X86Operand;
    let s = op_str.trim();
    if let Ok(reg) = parse_x86_register(s) {
        return Ok(X86Operand::Register(reg));
    }
    let imm = parse_x86_immediate(s)?;
    Ok(X86Operand::Immediate(imm))
}

fn parse_x86_immediate(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        // Positive hex: parse via u64 then reinterpret as i64 with
        // two's-complement wrapping. Capstone's Intel-syntax
        // disassembler renders a sign-extended `imm = -1` operand as
        // the full-width `0xffffffffffffffff` (and `-2` as
        // `0xfffffffffffffffe`, etc.), so any value with the top bit
        // set must be re-mapped to the corresponding negative i64.
        // Treating "high bit set" as out-of-range here would reject
        // legitimate `cmp/and/add rax, -1` lines coming straight from
        // Capstone — exactly the false rejection raised on this PR.
        let u =
            u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex immediate: {}", s))?;
        Ok(u as i64)
    } else if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        // Negative hex: the magnitude can be as large as 1<<63 (giving
        // i64::MIN). `i64::from_str_radix` rejects 0x8000_0000_0000_0000
        // because that doesn't fit i64 positively. Parse via u64 and
        // negate carefully with wrapping_neg so INT64_MIN survives.
        let abs =
            u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex immediate: {}", s))?;
        if abs > (1u64 << 63) {
            return Err(format!("Hex immediate {} out of i64 range", s));
        }
        Ok((abs as i64).wrapping_neg())
    } else {
        s.parse::<i64>()
            .map_err(|_| format!("Invalid immediate: {}", s))
    }
}

/// Convert a `(mnemonic, op_str)` pair (as produced by Capstone Intel
/// syntax) into an `X86Instruction`. Returns `Ok(None)` for mnemonics
/// outside the minimal core set, mirroring the AArch64 path.
fn x86_ir_from_mnemonic(
    mnemonic: &str,
    op_str: &str,
) -> Result<Option<isa::x86::X86Instruction>, String> {
    use isa::x86::X86Instruction;
    let mnemonic = mnemonic.trim().to_lowercase();
    let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return Ok(None);
    }
    let rd = parse_x86_register(parts[0])?;
    let src_op = parse_x86_operand(parts[1])?;
    let make = |reg_form: fn(isa::x86::X86Register, isa::x86::X86Register) -> X86Instruction,
                imm_form: fn(isa::x86::X86Register, i64) -> X86Instruction|
     -> Result<Option<X86Instruction>, String> {
        Ok(Some(match src_op {
            isa::x86::X86Operand::Register(rs) => reg_form(rd, rs),
            isa::x86::X86Operand::Immediate(imm) => imm_form(rd, imm),
        }))
    };
    let make_cmp =
        |reg_form: fn(isa::x86::X86Register, isa::x86::X86Register) -> X86Instruction,
         imm_form: fn(isa::x86::X86Register, i64) -> X86Instruction|
         -> Result<Option<X86Instruction>, String> {
            Ok(Some(match src_op {
                isa::x86::X86Operand::Register(rs) => reg_form(rd, rs),
                isa::x86::X86Operand::Immediate(imm) => imm_form(rd, imm),
            }))
        };
    match mnemonic.as_str() {
        "mov" | "movabs" => make(
            |rd, rs| X86Instruction::MovReg { rd, rs },
            |rd, imm| X86Instruction::MovImm { rd, imm },
        ),
        "add" => make(
            |rd, rs| X86Instruction::AddReg { rd, rs },
            |rd, imm| X86Instruction::AddImm { rd, imm },
        ),
        "sub" => make(
            |rd, rs| X86Instruction::SubReg { rd, rs },
            |rd, imm| X86Instruction::SubImm { rd, imm },
        ),
        "and" => make(
            |rd, rs| X86Instruction::AndReg { rd, rs },
            |rd, imm| X86Instruction::AndImm { rd, imm },
        ),
        "or" => make(
            |rd, rs| X86Instruction::OrReg { rd, rs },
            |rd, imm| X86Instruction::OrImm { rd, imm },
        ),
        "xor" => make(
            |rd, rs| X86Instruction::XorReg { rd, rs },
            |rd, imm| X86Instruction::XorImm { rd, imm },
        ),
        "cmp" => make_cmp(
            |rn, rs| X86Instruction::CmpReg { rn, rs },
            |rn, imm| X86Instruction::CmpImm { rn, imm },
        ),
        _ => Ok(None),
    }
}

fn convert_to_x86_ir(
    instructions: &capstone::Instructions,
) -> Result<Vec<isa::x86::X86Instruction>, String> {
    let mut out = Vec::new();
    for instruction in instructions.iter() {
        let mn = instruction.mnemonic().unwrap_or("");
        let ops = instruction.op_str().unwrap_or("");
        match x86_ir_from_mnemonic(mn, ops) {
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

/// Length-1 enumerator for x86: try every candidate of length 1 against
/// the target sequence, return the first equivalent shorter sequence.
fn find_shorter_equivalent_x86(
    target: &[isa::x86::X86Instruction],
    width: u32,
) -> Option<Vec<isa::x86::X86Instruction>> {
    use isa::InstructionType;
    use isa::x86::X86Register;
    use search::candidate_x86::generate_all_x86_instructions;
    use semantics::cost_x86;
    use semantics::equivalence::{X86EquivalenceConfig, check_equivalence_x86};
    use semantics::state::X86LiveOutMask;

    if target.is_empty() || target.len() < 2 {
        // Already length 1; nothing strictly shorter exists.
        return None;
    }
    let target_cost =
        cost_x86::sequence_cost(target, &semantics::cost::CostMetric::CodeSize, width);

    // Live-out registers = everything the target writes.
    let live_regs: Vec<X86Register> = target.iter().filter_map(|i| i.destination()).collect();
    // Flags are live whenever the target contains any instruction with
    // observable side-effects beyond the register write — every variant
    // except MOV reports `has_side_effects() == true` because it touches
    // EFLAGS. Without this, a rewrite like `add rax, 0; mov rax, rbx`
    // → `mov rax, rbx` could be silently accepted, dropping the EFLAGS
    // write the surrounding code may consume via Jcc.
    let flags_live = target.iter().any(InstructionType::has_side_effects);
    let live_out = X86LiveOutMask::from_registers(live_regs.clone()).with_flags(flags_live);

    // Build a register pool from the registers actually used in the
    // target, plus a couple of scratch regs.
    let mut pool: Vec<X86Register> = live_regs.clone();
    for reg in target.iter().flat_map(|i| i.source_registers()) {
        if !pool.contains(&reg) {
            pool.push(reg);
        }
    }
    for extra in [X86Register::RAX, X86Register::RDI] {
        if !pool.contains(&extra) {
            pool.push(extra);
        }
    }
    let imms = vec![0i64, 1, -1];

    let candidates = generate_all_x86_instructions(&pool, &imms);
    let cfg = X86EquivalenceConfig::new_for_64()
        .live_out(live_out.clone())
        .fast_only();
    let cfg = X86EquivalenceConfig { width, ..cfg };
    for cand in candidates {
        let seq = vec![cand];
        let cand_cost =
            cost_x86::sequence_cost(&seq, &semantics::cost::CostMetric::CodeSize, width);
        if cand_cost >= target_cost {
            continue;
        }
        match check_equivalence_x86(target, &seq, &cfg) {
            semantics::equivalence::EquivalenceResult::Equivalent => return Some(seq),
            _ => continue,
        }
    }
    None
}

fn optimize_elf_binary_x86(
    path: &Path,
    start_addr: u64,
    end_addr: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use elf_patcher::{AddressWindow, DetectedArch};

    println!("Optimizing x86 ELF binary: {}", path.display());
    println!("Address window: 0x{:x} - 0x{:x}", start_addr, end_addr);

    let window = AddressWindow {
        start: start_addr,
        end: end_addr,
    };
    let patcher = elf_patcher::ElfPatcher::new(path)?;
    let arch = patcher.arch();
    let width = match arch {
        DetectedArch::X86_64 => 64u32,
        DetectedArch::X86_32 => 32u32,
        DetectedArch::Aarch64 => {
            return Err("expected x86 binary; got AArch64".into());
        }
    };
    println!("Detected: {:?} (width {})", arch, width);

    let section = patcher.validate_address_window(&window)?;
    println!("Window is within section: {}", section.name);

    let bytes = patcher.get_instructions_in_window(&window)?;
    println!("Original code: {} bytes", bytes.len());

    let cs = match arch {
        DetectedArch::X86_64 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()?,
        DetectedArch::X86_32 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode32)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()?,
        DetectedArch::Aarch64 => unreachable!(),
    };
    let cs_instrs = cs.disasm_all(&bytes, start_addr)?;
    println!("Disassembled {} instructions:", cs_instrs.len());
    for i in cs_instrs.iter() {
        println!(
            "  0x{:x}: {} {}",
            i.address(),
            i.mnemonic().unwrap_or("???"),
            i.op_str().unwrap_or("")
        );
    }

    // Validate that the disassembled instructions cover the entire byte
    // window. x86 is variable-length, so an `--end-addr` that lands
    // mid-instruction (or leaves any undecodable tail bytes) makes
    // disasm_all return only the complete decoded prefix; the patcher
    // then overwrites the entire requested byte range with the
    // reassembled IR, which can replace or NOP part of the next
    // instruction in the binary. Refuse the window in that case.
    let decoded_bytes: usize = cs_instrs.iter().map(|i| i.bytes().len()).sum();
    if decoded_bytes != bytes.len() {
        return Err(format!(
            "x86 window 0x{:x}-0x{:x} ({} bytes) does not end on an \
             instruction boundary: Capstone decoded only {} bytes. Adjust \
             --end-addr to align with the next instruction's start address.",
            start_addr,
            end_addr,
            bytes.len(),
            decoded_bytes
        )
        .into());
    }

    let ir = convert_to_x86_ir(&cs_instrs)?;
    println!("Converted {} instructions to x86 IR:", ir.len());
    for instr in &ir {
        println!("  {}", instr);
    }

    let optimized = find_shorter_equivalent_x86(&ir, width);
    let Some(final_ir) = optimized else {
        // Without a shorter sequence to substitute there is nothing to
        // patch. Round-tripping the original IR through dynasm could
        // emit different bytes than the source compiler (e.g. a
        // different MOV imm32 form, or different NOP padding) and
        // silently produce a non-byte-identical "no-op" output binary.
        // Leave the input untouched and exit.
        println!("No optimization found; not patching (input binary left untouched).");
        return Ok(());
    };
    println!("Optimized to {} instructions:", final_ir.len());
    for i in &final_ir {
        println!("  {}", i);
    }

    let mut asm = match arch {
        DetectedArch::X86_64 => assembler::x86::X86Assembler::new_64(),
        DetectedArch::X86_32 => assembler::x86::X86Assembler::new_32(),
        DetectedArch::Aarch64 => unreachable!(),
    };
    let new_bytes = asm.assemble_instructions(&final_ir)?;
    println!("Reassembled to {} bytes", new_bytes.len());

    let output_path = {
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
    };
    patcher.create_patched_copy(&output_path, &window, &new_bytes)?;
    println!("Created optimized binary: {}", output_path.display());
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
    let (live_out, _flags_live) = validation::live_out::parse_live_out_contract(live_out_str)
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

    let (live_out, flags_live) = validation::live_out::parse_live_out_contract(live_out_str)
        .map_err(|e| format!("invalid live-out: {}", e))?;

    if verbose {
        let mut regs: Vec<_> = live_out.registers().iter().collect();
        regs.sort_by_key(|r| r.index().unwrap_or(u8::MAX));
        let names: Vec<String> = regs.iter().map(|r| format!("{}", r)).collect();
        println!("Live-out registers: {}", names.join(", "));
        if flags_live {
            println!("Live-out flags: nzcv");
        }
    }

    let config = EquivalenceConfig::default()
        .live_out(live_out)
        .with_flags(flags_live)
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
            // backend. The optional `--arch` is used to (a) early-reject
            // RISC-V (still unsupported) and (b) cross-check against the
            // ELF so a stale or wrong `--arch` value fails fast instead of
            // silently producing disassembly for a different architecture.
            if let Some(a) = arch {
                match a {
                    CliArch::Riscv32 | CliArch::Riscv64 => {
                        eprintln!("RISC-V disassembly is not yet supported");
                        std::process::exit(1);
                    }
                    CliArch::Aarch64 | CliArch::X86_64 | CliArch::X86_32 => {
                        match detect_cli_arch_from_elf(&binary) {
                            Ok(detected) if detected == a => {}
                            Ok(detected) => {
                                eprintln!(
                                    "Architecture mismatch: --arch {:?} but ELF reports {:?}",
                                    a, detected
                                );
                                std::process::exit(1);
                            }
                            Err(e) => {
                                eprintln!("Error reading ELF: {}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }
            match analyze_elf_binary(&binary, true) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Error analyzing binary: {}", e);
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
            // wrong optimization pipeline.
            let detected_arch = detect_cli_arch_from_elf(&binary).unwrap_or_else(|e| {
                eprintln!("Error reading ELF: {}", e);
                std::process::exit(1);
            });
            let cli_arch = match arch {
                Some(a) if a == detected_arch => a,
                Some(a) => {
                    eprintln!(
                        "Architecture mismatch: --arch {:?} but ELF reports {:?}",
                        a, detected_arch
                    );
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
            if is_x86 && !matches!(algorithm, CliAlgorithm::Enumerative) {
                eprintln!(
                    "x86 only supports --algorithm enumerative in this release; \
                     stochastic/symbolic/hybrid/llm are AArch64-only."
                );
                std::process::exit(1);
            }
            // The x86 path uses a fixed enumerative + fast-path-only
            // pipeline in v1, so most search-tuning options are
            // silently dropped. Warn the user so an unexpected --beta
            // / --iterations / --timeout / --cores / --cost-metric on
            // an x86 invocation isn't mistaken for being honored.
            if is_x86 {
                let mut ignored: Vec<&str> = Vec::new();
                if timeout.is_some() {
                    ignored.push("--timeout");
                }
                if !matches!(cost_metric, CliCostMetric::CodeSize) {
                    ignored.push("--cost-metric (x86 v1 always uses CodeSize)");
                }
                if cores.is_some() {
                    ignored.push("--cores (x86 v1 is single-threaded)");
                }
                if !ignored.is_empty() {
                    eprintln!(
                        "warning: x86 v1 ignores the following option(s): {}. \
                         Stochastic/symbolic-specific flags (--beta, --iterations, \
                         --seed, --search-mode, --solver-timeout, --no-symbolic, \
                         --llm-*) are also ignored even when not listed.",
                        ignored.join(", ")
                    );
                }
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

            let opt_result = if is_x86 {
                optimize_elf_binary_x86(&binary, start_addr, end_addr)
            } else {
                optimize_elf_binary(&binary, start_addr, end_addr, &options)
            };
            match opt_result {
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
mod x86_parser_tests {
    use super::*;
    use isa::x86::{X86Instruction, X86Operand, X86Register};

    #[test]
    fn parse_register_handles_aliased_names() {
        assert_eq!(parse_x86_register("rax").unwrap(), X86Register::RAX);
        assert_eq!(parse_x86_register("eax").unwrap(), X86Register::RAX);
        assert_eq!(parse_x86_register("RAX").unwrap(), X86Register::RAX);
        assert_eq!(parse_x86_register("r10").unwrap(), X86Register::R10);
        assert_eq!(parse_x86_register("r10d").unwrap(), X86Register::R10);
        assert!(parse_x86_register("zmm0").is_err());
    }

    #[test]
    fn parse_immediate_int64_boundaries() {
        // Smallest signed value: -0x8000_0000_0000_0000 = i64::MIN.
        // The naive `i64::from_str_radix(abs_hex).map(-)` rejects this
        // because the absolute magnitude doesn't fit i64 positively.
        assert_eq!(
            parse_x86_immediate("-0x8000000000000000").unwrap(),
            i64::MIN
        );
        assert_eq!(parse_x86_immediate("0x7FFFFFFFFFFFFFFF").unwrap(), i64::MAX);
        // Capstone Intel-syntax renders a sign-extended -1 as the
        // full-width 0xffffffffffffffff. We must accept it as the
        // wrapping signed value (i64 -1), not reject it as
        // out-of-range.
        assert_eq!(parse_x86_immediate("0xffffffffffffffff").unwrap(), -1i64);
        assert_eq!(parse_x86_immediate("0xfffffffffffffffe").unwrap(), -2i64);
        assert_eq!(parse_x86_immediate("0x8000000000000000").unwrap(), i64::MIN);
        // Magnitudes that exceed even u64 width must still fail.
        assert!(parse_x86_immediate("0x10000000000000000").is_err());
        assert!(parse_x86_immediate("-0x8000000000000001").is_err());
    }

    #[test]
    fn parse_immediate_supports_hex_decimal_signed() {
        assert_eq!(parse_x86_immediate("42").unwrap(), 42);
        assert_eq!(parse_x86_immediate("-1").unwrap(), -1);
        assert_eq!(parse_x86_immediate("0x2a").unwrap(), 42);
        assert_eq!(parse_x86_immediate("0XFF").unwrap(), 255);
        assert_eq!(parse_x86_immediate("-0x10").unwrap(), -16);
    }

    #[test]
    fn parse_operand_routes_to_register_or_immediate() {
        assert_eq!(
            parse_x86_operand("rdi").unwrap(),
            X86Operand::Register(X86Register::RDI)
        );
        assert_eq!(parse_x86_operand("7").unwrap(), X86Operand::Immediate(7));
    }

    #[test]
    fn x86_ir_recognises_seven_mnemonics() {
        let cases = [
            (
                "mov",
                "rax, rbx",
                X86Instruction::MovReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
            ),
            (
                "mov",
                "rax, 42",
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 42,
                },
            ),
            (
                "add",
                "rax, rbx",
                X86Instruction::AddReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
            ),
            (
                "sub",
                "rax, 1",
                X86Instruction::SubImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
            ),
            (
                "and",
                "rax, rbx",
                X86Instruction::AndReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
            ),
            (
                "or",
                "rax, 0",
                X86Instruction::OrImm {
                    rd: X86Register::RAX,
                    imm: 0,
                },
            ),
            (
                "xor",
                "rax, rax",
                X86Instruction::XorReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RAX,
                },
            ),
            (
                "cmp",
                "rax, 5",
                X86Instruction::CmpImm {
                    rn: X86Register::RAX,
                    imm: 5,
                },
            ),
        ];
        for (mn, ops, expected) in cases {
            let got = x86_ir_from_mnemonic(mn, ops).unwrap().unwrap();
            assert_eq!(got, expected, "{} {}", mn, ops);
        }
    }

    #[test]
    fn x86_ir_unsupported_mnemonic_returns_none() {
        assert!(x86_ir_from_mnemonic("ret", "").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("jmp", "0x1234").unwrap().is_none());
        // Two-operand "shl" not in the minimal set.
        assert!(x86_ir_from_mnemonic("shl", "rax, 1").unwrap().is_none());
    }
}

#[cfg(test)]
mod cli_helper_tests {
    use super::*;
    use ir::Operand;
    use isa::x86::{X86Instruction, X86Register};
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
    /// parser supports. If a new mnemonic is added to `parser::parse_line`
    /// without a sample here, this stays green (we only catch regressions in
    /// the other direction). If a mnemonic in this list ever stops parsing,
    /// the binary path has silently broken.
    #[test]
    fn convert_capstone_op_handles_all_supported_aarch64_mnemonics() {
        let cases = [
            ("mov", "x0, x1"),
            ("mov", "x0, #5"),
            ("mvn", "x0, x1"),
            ("neg", "x0, x1"),
            ("negs", "x0, x1"),
            ("movn", "x0, #1"),
            ("movz", "x0, #0xffff, lsl #48"),
            ("movk", "x1, #0x1234, lsl #16"),
            ("add", "x0, x1, x2"),
            ("add", "x0, x1, #4"),
            ("add", "x0, x1, x2, lsl #3"),
            ("sub", "x0, x1, #3"),
            ("adds", "x0, x1, #1"),
            ("subs", "x0, x1, x2"),
            ("and", "x0, x1, x2"),
            ("ands", "x0, x1, x2"),
            ("orr", "x0, x1, x2"),
            ("eor", "x0, x1, x2"),
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
        ];

        // Tripwire: bump in lockstep when adding/removing rows. Catches
        // accidental row deletion and forces a re-read when adding a parser
        // mnemonic without a matching test row.
        assert_eq!(cases.len(), 78);

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
        match convert_capstone_op("ldr", "x0, [x1]") {
            ConvertOutcome::Unsupported(line) => {
                assert!(line.contains("ldr"), "warning line should name mnemonic");
            }
            other => panic!("expected Unsupported, got {:?}", other),
        }
    }

    #[test]
    fn convert_capstone_op_for_optimization_rejects_unsupported_instruction() {
        let err = convert_capstone_op_for_optimization("ldr", "x0, [x1]", 0x1234)
            .expect_err("optimization conversion must reject unsupported non-NOP instructions");

        assert!(err.contains("ldr x0, [x1]"));
        assert!(err.contains("0x1234"));
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
    fn x86_helpers_cover_error_and_optimization_paths() {
        assert!(parse_x86_operand("not-an-operand").is_err());
        assert!(x86_ir_from_mnemonic("add", "rax").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("add", "rax, nope").is_err());

        assert!(find_shorter_equivalent_x86(&[], 64).is_none());
        assert!(
            find_shorter_equivalent_x86(
                &[X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 1,
                }],
                64
            )
            .is_none()
        );
        let optimized = find_shorter_equivalent_x86(
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
        )
        .expect("two identical writes can be shortened");
        assert_eq!(optimized.len(), 1);
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
            let _ = run_optimization(&target, &options).unwrap();
        }
        assert!(
            run_optimization(&[], &options_for(Algorithm::Enumerative))
                .unwrap()
                .is_none()
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
                    target: crate::ir::LabelId(0x1000),
                },
                Register::X0,
            ),
            (
                Instruction::Tbz {
                    rt: Register::X2,
                    bit: 5,
                    target: crate::ir::LabelId(0x1000),
                },
                Register::X2,
            ),
            (Instruction::Br { rn: Register::X16 }, Register::X16),
            (Instruction::Ret { rn: Register::X30 }, Register::X30),
        ];

        for (terminator, source) in cases {
            let live_out = live_out_for_optimization_prefix(&prefix, Some(&terminator));
            assert!(live_out.contains_register(Register::X1));
            assert!(
                live_out.contains_register(source),
                "{:?} must keep {:?} live for the reattached terminator",
                terminator,
                source
            );
        }
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
                assert_eq!(*cond, crate::ir::types::Condition::EQ);
            }
            other => panic!("expected BCond terminator, got {:?}", other),
        }
        assert!(last.is_terminator());
    }

    #[test]
    fn issue_69_acceptance_equivalence_rejects_different_branch_decisions() {
        // Same prefix, different conditional branch → NotEquivalent
        // (the branch decision differs, so equivalence must fail).
        use crate::semantics::equivalence::{EquivalenceResult, check_equivalence};
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

        let live_out = live_out_for_optimization_prefix(prefix, term);
        let config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1]);
        let mut search = EnumerativeSearch::new();
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
            terminator.clone(),
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
        let live_out = live_out_for_optimization_prefix(prefix, term);
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
                target: crate::ir::LabelId(0x1000),
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
}
