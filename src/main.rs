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
mod search;
mod semantics;
mod validation;

use assembler::AArch64Assembler;
use elf_patcher::{AddressWindow, ElfPatcher, parse_hex_address};
use ir::{Instruction, Operand, Register};
use search::config::{Algorithm, SearchConfig, SearchMode, StochasticConfig, SymbolicConfig};
use search::parallel::{ParallelConfig, run_parallel_search};
use search::{SearchAlgorithm, StochasticSearch, SymbolicSearch};
use semantics::cost::CostMetric;
use semantics::state::LiveOutMask;
use semantics::{EquivalenceResult, check_equivalence};

// --- Command Line Arguments ---

#[derive(Parser)]
#[command(name = "s11")]
#[command(about = "s11 - AArch64 Optimizer")]
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
}

impl From<CliAlgorithm> for Algorithm {
    fn from(cli: CliAlgorithm) -> Self {
        match cli {
            CliAlgorithm::Enumerative => Algorithm::Enumerative,
            CliAlgorithm::Stochastic => Algorithm::Stochastic,
            CliAlgorithm::Symbolic => Algorithm::Symbolic,
            CliAlgorithm::Hybrid => Algorithm::Hybrid,
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
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum CliArch {
    /// AArch64 (ARM64) architecture
    #[default]
    Aarch64,
    /// RISC-V 32-bit architecture
    Riscv32,
    /// RISC-V 64-bit architecture
    Riscv64,
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
    },
}

// --- ELF Binary Analysis ---

fn analyze_elf_binary(path: &PathBuf, disasm_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !disasm_mode {
        println!("Analyzing ELF binary: {}", path.display());
    }

    // Read the file
    let file_data = fs::read(path)?;

    // Parse ELF
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&file_data)?;

    // Check if it's AArch64
    if elf.ehdr.e_machine != elf::abi::EM_AARCH64 {
        return Err(format!(
            "Not an AArch64 binary (machine type: {})",
            elf.ehdr.e_machine
        )
        .into());
    }

    if !disasm_mode {
        println!("ELF Header:");
        println!("  Architecture: AArch64");
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

    // Initialize Capstone disassembler for AArch64
    let cs = Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()?;

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
}

// --- Optimization Function ---

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

    // Convert to IR
    let ir_instructions = convert_to_ir(&instructions)?;
    println!("Converted {} instructions to IR:", ir_instructions.len());

    for instr in &ir_instructions {
        println!("  {}", instr);
    }

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
    let assembled_bytes = assembler.assemble_instructions(final_instructions)?;
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

/// Run optimization using the selected algorithm
fn run_optimization(
    target: &[Instruction],
    options: &OptimizationOptions,
) -> Result<Option<Vec<Instruction>>, Box<dyn std::error::Error>> {
    if target.is_empty() {
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
    let available_immediates = vec![-1, 0, 1, 2, 4, 8];

    // Create live-out mask (assume all modified registers are live-out for now)
    let live_out = LiveOutMask::from_registers(
        target
            .iter()
            .filter_map(|instr| instr.destination())
            .collect(),
    );

    match options.algorithm {
        Algorithm::Enumerative => {
            // Use existing enumerative search
            println!("\nRunning enumerative search...");
            Ok(find_shorter_equivalent(target))
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
            let result = search.search(target, &live_out, &config);

            print_search_statistics(&result.statistics);

            if result.found_optimization {
                Ok(result.optimized_sequence)
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
            let result = search.search(target, &live_out, &config);

            print_search_statistics(&result.statistics);

            if result.found_optimization {
                Ok(result.optimized_sequence)
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

            let result = run_parallel_search(target, &live_out, &config, &parallel_config);

            print_search_statistics(&result.total_statistics);

            if result.best_result.found_optimization {
                Ok(result.best_result.optimized_sequence)
            } else {
                Ok(None)
            }
        }
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

fn convert_to_ir(instructions: &capstone::Instructions) -> Result<Vec<Instruction>, String> {
    let mut ir_instructions = Vec::new();

    for instruction in instructions.iter() {
        let mnemonic = instruction.mnemonic().unwrap_or("");
        let op_str = instruction.op_str().unwrap_or("");

        // For MVP, only convert basic instructions we can handle
        match mnemonic {
            "mov" => {
                if let Some(ir_instr) = parse_mov_instruction(op_str)? {
                    ir_instructions.push(ir_instr);
                }
            }
            "add" => {
                if let Some(ir_instr) = parse_add_instruction(op_str)? {
                    ir_instructions.push(ir_instr);
                }
            }
            "nop" => {
                // Skip NOPs for now, they'll be added back if needed during assembly
            }
            _ => {
                println!(
                    "Warning: Skipping unsupported instruction: {} {}",
                    mnemonic, op_str
                );
            }
        }
    }

    Ok(ir_instructions)
}

fn parse_mov_instruction(op_str: &str) -> Result<Option<Instruction>, String> {
    let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return Ok(None); // Skip complex MOV instructions for MVP
    }

    let dst = parse_register(parts[0])?;

    // Check if source is register or immediate
    if parts[1].starts_with('#') {
        // Immediate
        let imm_str = &parts[1][1..]; // Remove '#'
        let imm = if let Some(hex_str) = imm_str.strip_prefix("0x") {
            i64::from_str_radix(hex_str, 16)
        } else {
            imm_str.parse::<i64>()
        }
        .map_err(|_| format!("Invalid immediate: {}", imm_str))?;

        Ok(Some(Instruction::MovImm { rd: dst, imm }))
    } else {
        // Register
        let src = parse_register(parts[1])?;
        Ok(Some(Instruction::MovReg { rd: dst, rn: src }))
    }
}

fn parse_add_instruction(op_str: &str) -> Result<Option<Instruction>, String> {
    let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
    if parts.len() != 3 {
        return Ok(None); // Skip complex ADD instructions for MVP
    }

    let dst = parse_register(parts[0])?;
    let src1 = parse_register(parts[1])?;

    // Check if third operand is register or immediate
    let src2 = if parts[2].starts_with('#') {
        // Immediate
        let imm_str = &parts[2][1..]; // Remove '#'
        let imm = if let Some(hex_str) = imm_str.strip_prefix("0x") {
            i64::from_str_radix(hex_str, 16)
        } else {
            imm_str.parse::<i64>()
        }
        .map_err(|_| format!("Invalid immediate: {}", imm_str))?;

        Operand::Immediate(imm)
    } else {
        // Register
        let reg = parse_register(parts[2])?;
        Operand::Register(reg)
    };

    Ok(Some(Instruction::Add {
        rd: dst,
        rn: src1,
        rm: src2,
    }))
}

fn parse_register(reg_str: &str) -> Result<Register, String> {
    match reg_str.to_lowercase().as_str() {
        "x0" => Ok(Register::X0),
        "x1" => Ok(Register::X1),
        "x2" => Ok(Register::X2),
        "x3" => Ok(Register::X3),
        "x4" => Ok(Register::X4),
        "x5" => Ok(Register::X5),
        "x6" => Ok(Register::X6),
        "x7" => Ok(Register::X7),
        "x8" => Ok(Register::X8),
        "x9" => Ok(Register::X9),
        "x10" => Ok(Register::X10),
        "x11" => Ok(Register::X11),
        "x12" => Ok(Register::X12),
        "x13" => Ok(Register::X13),
        "x14" => Ok(Register::X14),
        "x15" => Ok(Register::X15),
        "x16" => Ok(Register::X16),
        "x17" => Ok(Register::X17),
        "x18" => Ok(Register::X18),
        "x19" => Ok(Register::X19),
        "x20" => Ok(Register::X20),
        "x21" => Ok(Register::X21),
        "x22" => Ok(Register::X22),
        "x23" => Ok(Register::X23),
        "x24" => Ok(Register::X24),
        "x25" => Ok(Register::X25),
        "x26" => Ok(Register::X26),
        "x27" => Ok(Register::X27),
        "x28" => Ok(Register::X28),
        "x29" => Ok(Register::X29),
        "x30" => Ok(Register::X30),
        "xzr" => Ok(Register::XZR),
        "sp" => Ok(Register::SP),
        _ => Err(format!("Unknown register: {}", reg_str)),
    }
}

// For simplicity in MVP, immediate is fixed for generation, but can be varied in input.
const IMM_VALUE_FOR_GENERATION: i64 = 1;

// --- Equivalence Checker ---

fn are_sequences_equivalent(seq1: &[Instruction], seq2: &[Instruction]) -> Result<bool, String> {
    match check_equivalence(seq1, seq2) {
        EquivalenceResult::Equivalent => Ok(true),
        EquivalenceResult::NotEquivalent | EquivalenceResult::NotEquivalentFast(_) => Ok(false),
        EquivalenceResult::Unknown(msg) => Err(msg),
    }
}

// --- Enumerative Search ---

fn generate_all_instructions() -> Vec<Instruction> {
    let mut instrs = Vec::new();
    // Use only first few registers for MVP
    let regs = [Register::X0, Register::X1, Register::X2];

    // Add (register)
    for rd in regs {
        for rn in regs {
            for rm in regs {
                instrs.push(Instruction::Add {
                    rd,
                    rn,
                    rm: Operand::Register(rm),
                });
            }
        }
    }

    // Add (immediate)
    for rd in regs {
        for rn in regs {
            instrs.push(Instruction::Add {
                rd,
                rn,
                rm: Operand::Immediate(IMM_VALUE_FOR_GENERATION),
            });
        }
    }

    // MovReg
    for rd in regs {
        for rn in regs {
            instrs.push(Instruction::MovReg { rd, rn });
        }
    }

    // MovImm
    for rd in regs {
        instrs.push(Instruction::MovImm {
            rd,
            imm: IMM_VALUE_FOR_GENERATION,
        });
        instrs.push(Instruction::MovImm { rd, imm: 0 });
    }

    // Eor (for zeroing)
    for rd in regs {
        instrs.push(Instruction::Eor {
            rd,
            rn: rd,
            rm: Operand::Register(rd),
        });
    }

    instrs
}

fn find_shorter_equivalent(original_seq: &[Instruction]) -> Option<Vec<Instruction>> {
    if original_seq.is_empty() {
        return None;
    }

    let all_possible_single_instrs = generate_all_instructions();

    // Search for sequences of length 1 up to original_seq.len() - 1
    for len in 1..original_seq.len() {
        println!("Searching for equivalent sequences of length {}...", len);
        // This MVP only implements search for length 1 for simplicity.
        // A full enumerator would generate sequences of `len`.
        if len == 1 {
            for instr_candidate in &all_possible_single_instrs {
                let candidate_seq = vec![*instr_candidate];
                print!("  Testing candidate: ");
                for i in &candidate_seq {
                    print!("{}; ", i);
                }

                match are_sequences_equivalent(original_seq, &candidate_seq) {
                    Ok(true) => {
                        println!("Found equivalent!");
                        return Some(candidate_seq);
                    }
                    Ok(false) => {
                        println!("Not equivalent.");
                    }
                    Err(e) => {
                        eprintln!("SMT Error for candidate: {}", e);
                    }
                }
            }
        } else {
            // Placeholder for generating sequences of length > 1
            // This would involve iterating `len` times over `all_possible_single_instrs`
            // and forming all combinations.
            println!("  (Skipping length {} for MVP simplicity)", len);
        }
    }
    None
}

// --- Main Function ---
fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Disasm { binary, arch } => {
            // Disassemble mode
            if let Some(a) = arch {
                // For now, only AArch64 is fully supported for disassembly
                match a {
                    CliArch::Aarch64 => {}
                    CliArch::Riscv32 | CliArch::Riscv64 => {
                        eprintln!("RISC-V disassembly is not yet supported");
                        std::process::exit(1);
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
        } => {
            // Architecture selection
            if let Some(a) = arch {
                // For now, only AArch64 is fully supported for optimization
                match a {
                    CliArch::Aarch64 => {}
                    CliArch::Riscv32 | CliArch::Riscv64 => {
                        eprintln!(
                            "RISC-V optimization is not yet supported (ISA traits available but not integrated)"
                        );
                        std::process::exit(1);
                    }
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
            };

            match optimize_elf_binary(&binary, start_addr, end_addr, &options) {
                Ok(()) => println!("\nOptimization completed successfully."),
                Err(e) => {
                    eprintln!("Error during optimization: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
