use capstone::prelude::*;
use clap::{Parser, Subcommand, ValueEnum};
use elf::{ElfBytes, endian::AnyEndian};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(test)]
#[path = "test_utils.rs"]
mod test_utils;

use s11::disassembly::{self, DisassembledInstruction};
use s11::elf_optimizer::{
    OptimizationOptions, optimize_elf_binary, print_llm_timings, print_search_statistics,
    print_unsupported_mnemonic_ledger, run_auto_optimization,
};
use s11::elf_patcher::{DetectedArch, ElfPatcher, parse_hex_address};
use s11::output_path::resolve_output_path;
use s11::report;
use s11::search::SearchAlgorithm;
use s11::search::config::{Algorithm, LlmConfig, SearchConfig, SearchMode};
use s11::semantics::cost::CostMetric;
#[allow(unused_imports)]
use s11::{
    aarch64_search_inputs, assembler, elf_patcher, ir, isa, parser, search, semantics, validation,
    x86_search_inputs, x86_window_reassembly,
};

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
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SupportedArch {
    Aarch64,
    X86_64,
    X86_32,
}

impl SupportedArch {
    fn from_e_machine(machine: u16) -> Result<Self, Box<dyn std::error::Error>> {
        match machine {
            elf::abi::EM_AARCH64 => Ok(Self::Aarch64),
            elf::abi::EM_X86_64 => Ok(Self::X86_64),
            elf::abi::EM_386 => Ok(Self::X86_32),
            m => Err(format!("Unsupported architecture (e_machine: {})", m).into()),
        }
    }

    fn build_capstone(self) -> capstone::CsResult<Capstone> {
        match self {
            Self::Aarch64 => Capstone::new()
                .arm64()
                .mode(capstone::arch::arm64::ArchMode::Arm)
                .detail(true)
                .build(),
            Self::X86_64 => Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode64)
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build(),
            Self::X86_32 => Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode32)
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build(),
        }
    }
}

impl TryFrom<CliArch> for SupportedArch {
    type Error = &'static str;

    fn try_from(arch: CliArch) -> Result<Self, Self::Error> {
        match arch {
            CliArch::Aarch64 => Ok(Self::Aarch64),
            CliArch::X86_64 => Ok(Self::X86_64),
            CliArch::X86_32 => Ok(Self::X86_32),
            CliArch::Riscv32 | CliArch::Riscv64 => Err("RISC-V disassembly is not yet supported"),
        }
    }
}

impl From<SupportedArch> for CliArch {
    fn from(arch: SupportedArch) -> Self {
        // SupportedArch is the closed set of architectures the disassembler
        // accepts, so this mapping is total — there is no RISC-V case to handle.
        match arch {
            SupportedArch::Aarch64 => CliArch::Aarch64,
            SupportedArch::X86_64 => CliArch::X86_64,
            SupportedArch::X86_32 => CliArch::X86_32,
        }
    }
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
        after_help = concat!(
            "Auto mode: `--auto` superoptimizes the whole binary and is mutually ",
            "exclusive with --start-addr/--end-addr. Use -o/--output to name the ",
            "result file; when omitted the result is written next to the input as ",
            "<stem>_optimized.<ext>.\n\n",
            "Output policy: Existing output files are refused unless --force is passed; ",
            "--force never permits replacing the input itself. Any non-regular filesystem entry ",
            "(including a symlink or directory) at the output path is always refused. ",
            "A successful run always writes the ",
            "result file; when no improvement is found the result is a byte copy of the ",
            "input on x86, and a re-encoding of the searched window on AArch64.\n\n",
            "Note: enumerative search scales with the generated instruction families ",
            "in its candidate pool. At the default AArch64 8-register CLI scope, ",
            "multiply-accumulate and high-half multiply add 9,728 candidates per ",
            "length bucket; use --timeout or smaller windows to bound runtime."
        )
    )]
    Opt {
        /// Path to ELF binary to optimize
        binary: PathBuf,
        /// Start address of optimization window (hex, e.g., 0x1000). Required unless --auto is set.
        #[arg(long, required_unless_present = "auto")]
        start_addr: Option<String>,
        /// End address of optimization window (hex, e.g., 0x1100). Required unless --auto is set.
        #[arg(long, required_unless_present = "auto")]
        end_addr: Option<String>,

        /// Superoptimize the whole binary (mutually exclusive with --start-addr/--end-addr)
        #[arg(long, conflicts_with_all = ["start_addr", "end_addr"])]
        auto: bool,
        /// Write the optimized binary to PATH (defaults to <stem>_optimized.<ext>)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
        /// Maximum window searches across all auto-mode passes
        #[arg(
            long,
            conflicts_with_all = ["start_addr", "end_addr"],
            default_value_t = s11::auto_driver::DEFAULT_MAX_WINDOWS
        )]
        max_windows: usize,
        /// Replace an existing output file (never permits optimizing the input in place)
        #[arg(long)]
        force: bool,

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
        /// Solver timeout in seconds; 0 disables SMT queries and does not request an unbounded solver query
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

/// Why an `s11 opt` invocation cannot proceed once the ELF's architecture is
/// known. Each variant is one pre-dispatch policy rule the CLI enforces, and
/// its `Display` is the exact diagnostic printed to stderr before exiting.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OptTargetError {
    /// `--arch requested` was given but the ELF's e_machine decodes to
    /// `detected`. Reported with CLI value names so it matches what the user
    /// typed for `--arch`.
    ArchMismatch {
        requested: CliArch,
        detected: CliArch,
    },
    /// The resolved architecture is RISC-V, which has no supported opt path
    /// yet (ADR-0005 — machine-code emission is not implemented).
    RiscvUnsupported,
    /// The resolved architecture is x86 but the algorithm is AArch64-only
    /// (ADR-0004 decision 3 — hybrid and LLM remain AArch64-only).
    AlgorithmNotForArch {
        arch: CliArch,
        algorithm: CliAlgorithm,
    },
}

impl std::fmt::Display for OptTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptTargetError::ArchMismatch {
                requested,
                detected,
            } => write!(
                f,
                "{ARCH_MISMATCH_PREFIX} --arch {requested} but ELF reports {detected}"
            ),
            OptTargetError::RiscvUnsupported => f.write_str(
                "RISC-V optimization is not yet supported (ISA traits available but not integrated)",
            ),
            OptTargetError::AlgorithmNotForArch { .. } => f.write_str(
                "x86 supports --algorithm enumerative / stochastic / symbolic in this release; \
                 hybrid and llm remain AArch64-only.",
            ),
        }
    }
}

impl std::error::Error for OptTargetError {}

/// Resolve which architecture `s11 opt` should optimize for, enforcing every
/// pre-dispatch policy rule in one testable place.
///
/// `detected` is the architecture decoded from the ELF e_machine (always read
/// first so a stale or wrong `--arch` cannot route bytes through the wrong
/// pipeline); `requested` is the optional `--arch` override; `algorithm` is
/// the chosen search algorithm. The rules are applied in the same order the
/// CLI has always used: reject an `--arch` that disagrees with the ELF, then
/// reject RISC-V, then reject x86 paired with an AArch64-only algorithm.
fn resolve_opt_target(
    requested: Option<CliArch>,
    detected: CliArch,
    algorithm: CliAlgorithm,
) -> Result<SupportedArch, OptTargetError> {
    let arch = match requested {
        Some(a) if a != detected => {
            return Err(OptTargetError::ArchMismatch {
                requested: a,
                detected,
            });
        }
        Some(a) => a,
        None => detected,
    };

    let supported = match arch {
        CliArch::Aarch64 => SupportedArch::Aarch64,
        CliArch::X86_64 => SupportedArch::X86_64,
        CliArch::X86_32 => SupportedArch::X86_32,
        CliArch::Riscv32 | CliArch::Riscv64 => return Err(OptTargetError::RiscvUnsupported),
    };

    let is_x86 = matches!(supported, SupportedArch::X86_64 | SupportedArch::X86_32);
    if is_x86 && matches!(algorithm, CliAlgorithm::Hybrid | CliAlgorithm::Llm) {
        return Err(OptTargetError::AlgorithmNotForArch { arch, algorithm });
    }

    Ok(supported)
}

/// Disassemble every executable section of an ELF and print the `disasm`
/// listing (one `0x{addr}: {bytes} {mnemonic} {operands}` line per instruction).
///
/// Architecture is auto-detected from `e_machine`; an explicit `expected_arch`
/// (from `--arch`) is cross-checked and a mismatch is rejected before any
/// disassembly. This is a thin adapter: ELF parsing and Capstone decoding stay
/// here, while the executable-section rule and the listing format live behind
/// the pure [`disassembly`](s11::disassembly) seam, so both are unit-testable
/// without driving the command or scraping stdout. Sections are printed as they
/// decode, so a decode failure in a later section still surfaces the listings
/// already produced for earlier ones.
fn disassemble_elf_binary(
    path: &Path,
    expected_arch: Option<SupportedArch>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_data = fs::read(path)?;
    let elf = ElfBytes::<AnyEndian>::minimal_parse(&file_data)?;

    // Detect architecture; reject anything outside the supported set.
    let detected_arch = SupportedArch::from_e_machine(elf.ehdr.e_machine)?;
    if let Some(expected_arch) = expected_arch
        && expected_arch != detected_arch
    {
        // Report the mismatch using CLI architecture names (via Display for
        // CliArch) so the diagnostic matches what users typed for --arch.
        let expected_cli = CliArch::from(expected_arch);
        let detected_cli = CliArch::from(detected_arch);
        return Err(format!(
            "{ARCH_MISMATCH_PREFIX} --arch {expected_cli} but ELF reports {detected_cli}"
        )
        .into());
    }

    // Initialize Capstone disassembler per architecture.
    let cs = detected_arch.build_capstone()?;

    let section_headers = elf
        .section_headers()
        .ok_or("Failed to get section headers")?;

    for section_header in section_headers.iter() {
        if !disassembly::section_is_executable(section_header.sh_flags, section_header.sh_size) {
            continue;
        }

        let (data, _) = elf.section_data(&section_header)?;
        if data.is_empty() {
            continue;
        }

        let instructions = cs.disasm_all(data, section_header.sh_addr)?;
        let decoded: Vec<DisassembledInstruction> = instructions
            .iter()
            .map(|instruction| DisassembledInstruction {
                address: instruction.address(),
                bytes: instruction.bytes().to_vec(),
                mnemonic: instruction.mnemonic().unwrap_or("???").to_string(),
                operands: instruction.op_str().unwrap_or("").to_string(),
            })
            .collect();

        for line in disassembly::format_disassembly(&decoded) {
            println!("{line}");
        }
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
) -> Result<i32, Box<dyn std::error::Error>> {
    use semantics::{EquivalenceConfig, check_equivalence_with_config};

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
        regs.sort_by_key(|r| r.sort_key());
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

    // Check equivalence, then let the pure report builder decide what to print
    // and which exit code to surface. `main` performs the actual `process::exit`.
    let result = check_equivalence_with_config(&seq1, &seq2, &config);
    let report = report::build_equiv_report(&result, &seq1, &seq2, &config.live_out);
    for line in &report.lines {
        println!("{}", line);
    }
    Ok(report.exit_code)
}

// --- Main Function ---
fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Disasm { binary, arch } => {
            // Disassemble mode. `disassemble_elf_binary` auto-detects the
            // architecture from e_machine and picks the right Capstone
            // backend. The optional `--arch` still early-rejects RISC-V, but
            // supported hints are cross-checked inside the disassembler after
            // its single ELF read/parse.
            let arch = match arch.map(SupportedArch::try_from).transpose() {
                Ok(arch) => arch,
                Err(message) => {
                    eprintln!("{message}");
                    std::process::exit(1);
                }
            };
            match disassemble_elf_binary(&binary, arch) {
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
            auto,
            output,
            max_windows,
            force,
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
            // RISC-V has no optimization pipeline, so reject an explicit
            // RISC-V target before asking the supported-architecture patcher
            // to open the ELF (constructing it fails hard on a RISC-V e_machine,
            // which is bug #207). Peek at the header first — rather than exit
            // unconditionally — so an unreadable file or a genuine arch
            // mismatch still gets its own diagnostic ahead of the RISC-V one.
            if let Some(requested) = arch
                && matches!(requested, CliArch::Riscv32 | CliArch::Riscv64)
            {
                match fs::read(&binary)
                    .map_err(|e| e.to_string())
                    .and_then(|data| {
                        ElfBytes::<AnyEndian>::minimal_parse(&data)
                            .map(|elf| elf.ehdr.e_machine)
                            .map_err(|e| e.to_string())
                    }) {
                    Ok(machine) => match SupportedArch::from_e_machine(machine) {
                        Ok(detected) => {
                            let detected: CliArch = detected.into();
                            eprintln!(
                                "{ARCH_MISMATCH_PREFIX} --arch {requested} but ELF reports {detected}"
                            );
                            std::process::exit(1);
                        }
                        Err(_) => {
                            eprintln!("{}", OptTargetError::RiscvUnsupported);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("Error reading ELF: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            // Build the ElfPatcher once here (issue #88) and thread it into
            // both helpers so the file isn't read + parsed twice.
            let patcher = ElfPatcher::new(&binary).unwrap_or_else(|e| {
                eprintln!("Error reading ELF: {}", e);
                std::process::exit(1);
            });
            let detected_arch: CliArch = patcher.arch().into();
            // Every pre-dispatch policy rule (arch cross-check, RISC-V refusal,
            // x86-only-algorithm refusal) lives behind resolve_opt_target so it
            // is exercised by table tests rather than only through this CLI arm.
            if let Err(e) = resolve_opt_target(arch, detected_arch, algorithm) {
                eprintln!("{e}");
                std::process::exit(1);
            }

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

            let result = if auto {
                // Whole-binary driver. clap already guaranteed --start-addr /
                // --end-addr are absent (conflicts_with_all).
                run_auto_optimization(
                    patcher,
                    &binary,
                    output.as_deref(),
                    force,
                    &options,
                    max_windows,
                )
            } else {
                // Single-window path. clap's required_unless_present guarantees
                // both addresses are present here; guard defensively rather than
                // unwrap so a future clap change fails loudly, not with a panic.
                let (Some(start_addr), Some(end_addr)) = (start_addr, end_addr) else {
                    eprintln!(
                        "Error: --start-addr and --end-addr are required unless --auto is set"
                    );
                    std::process::exit(1);
                };
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
                let output_path = match resolve_output_path(&binary, output.as_deref(), force) {
                    Ok(path) => path,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                };
                optimize_elf_binary(
                    &patcher,
                    &binary,
                    start_addr,
                    end_addr,
                    &output_path,
                    &options,
                )
            };

            match result {
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
            Ok(code) => {
                if code != 0 {
                    std::process::exit(code);
                }
            }
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
    use ir::instructions::split_terminator;
    use ir::{Instruction, Register};
    use isa::x86::{X86Instruction, X86Register};
    use parser::x86::parse_x86_register;
    use s11::capstone_bridge_x86::convert_to_x86_ir;
    use test_utils::TempFile;
    use test_utils::build_minimal_elf64;

    #[test]
    fn supported_arch_from_e_machine_rejects_riscv() {
        assert_eq!(
            SupportedArch::from_e_machine(elf::abi::EM_AARCH64).unwrap(),
            SupportedArch::Aarch64
        );
        assert_eq!(
            SupportedArch::from_e_machine(elf::abi::EM_X86_64).unwrap(),
            SupportedArch::X86_64
        );
        assert_eq!(
            SupportedArch::from_e_machine(elf::abi::EM_386).unwrap(),
            SupportedArch::X86_32
        );

        let err = SupportedArch::from_e_machine(elf::abi::EM_RISCV)
            .expect_err("RISC-V ELF disassembly should not be supported yet");

        assert_eq!(
            err.to_string(),
            format!(
                "Unsupported architecture (e_machine: {})",
                elf::abi::EM_RISCV
            )
        );
    }

    #[test]
    fn supported_arch_try_from_cli_arch_rejects_riscv() {
        assert_eq!(
            SupportedArch::try_from(CliArch::Aarch64).unwrap(),
            SupportedArch::Aarch64
        );
        assert_eq!(
            SupportedArch::try_from(CliArch::X86_64).unwrap(),
            SupportedArch::X86_64
        );
        assert_eq!(
            SupportedArch::try_from(CliArch::X86_32).unwrap(),
            SupportedArch::X86_32
        );

        for cli_arch in [CliArch::Riscv32, CliArch::Riscv64] {
            assert_eq!(
                SupportedArch::try_from(cli_arch),
                Err("RISC-V disassembly is not yet supported")
            );
        }
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
    fn resolve_opt_target_defaults_to_detected_arch_when_arch_unset() {
        // No --arch: every supported detected architecture resolves to itself.
        assert_eq!(
            resolve_opt_target(None, CliArch::Aarch64, CliAlgorithm::Enumerative),
            Ok(SupportedArch::Aarch64)
        );
        assert_eq!(
            resolve_opt_target(None, CliArch::X86_64, CliAlgorithm::Stochastic),
            Ok(SupportedArch::X86_64)
        );
        assert_eq!(
            resolve_opt_target(None, CliArch::X86_32, CliAlgorithm::Symbolic),
            Ok(SupportedArch::X86_32)
        );
    }

    #[test]
    fn resolve_opt_target_accepts_matching_arch_override() {
        // --arch that agrees with the detected e_machine is accepted.
        assert_eq!(
            resolve_opt_target(
                Some(CliArch::Aarch64),
                CliArch::Aarch64,
                CliAlgorithm::Hybrid
            ),
            Ok(SupportedArch::Aarch64)
        );
        assert_eq!(
            resolve_opt_target(
                Some(CliArch::X86_64),
                CliArch::X86_64,
                CliAlgorithm::Enumerative
            ),
            Ok(SupportedArch::X86_64)
        );
    }

    #[test]
    fn resolve_opt_target_rejects_arch_mismatch() {
        // --arch that contradicts the detected e_machine is rejected before
        // any bytes reach an optimization pipeline.
        assert_eq!(
            resolve_opt_target(
                Some(CliArch::Aarch64),
                CliArch::X86_64,
                CliAlgorithm::Enumerative
            ),
            Err(OptTargetError::ArchMismatch {
                requested: CliArch::Aarch64,
                detected: CliArch::X86_64,
            })
        );
    }

    #[test]
    fn resolve_opt_target_mismatch_message_uses_cli_names() {
        // The diagnostic must match what users typed for --arch (CLI value
        // names via CliArch Display), not Rust variant names — the exact
        // contract tests/integration/opt_test.rs pins end-to-end.
        let err = resolve_opt_target(
            Some(CliArch::Aarch64),
            CliArch::X86_64,
            CliAlgorithm::Enumerative,
        )
        .expect_err("mismatched --arch should be rejected");
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
    fn resolve_opt_target_rejects_riscv() {
        // RISC-V has no supported opt path (ADR-0005) — reject it regardless
        // of the requested algorithm.
        for arch in [CliArch::Riscv32, CliArch::Riscv64] {
            assert_eq!(
                resolve_opt_target(Some(arch), arch, CliAlgorithm::Enumerative),
                Err(OptTargetError::RiscvUnsupported)
            );
        }
        assert_eq!(
            resolve_opt_target(
                Some(CliArch::Riscv64),
                CliArch::Riscv64,
                CliAlgorithm::Symbolic
            )
            .unwrap_err()
            .to_string(),
            "RISC-V optimization is not yet supported (ISA traits available but not integrated)"
        );
    }

    #[test]
    fn resolve_opt_target_rejects_x86_with_aarch64_only_algorithms() {
        // Hybrid and LLM remain AArch64-only (ADR-0004 decision 3).
        for algorithm in [CliAlgorithm::Hybrid, CliAlgorithm::Llm] {
            assert_eq!(
                resolve_opt_target(None, CliArch::X86_64, algorithm),
                Err(OptTargetError::AlgorithmNotForArch {
                    arch: CliArch::X86_64,
                    algorithm,
                })
            );
            assert_eq!(
                resolve_opt_target(None, CliArch::X86_32, algorithm),
                Err(OptTargetError::AlgorithmNotForArch {
                    arch: CliArch::X86_32,
                    algorithm,
                })
            );
        }
        let err = resolve_opt_target(None, CliArch::X86_64, CliAlgorithm::Hybrid)
            .expect_err("x86 + hybrid should be rejected");
        assert_eq!(
            err.to_string(),
            "x86 supports --algorithm enumerative / stochastic / symbolic in this release; \
             hybrid and llm remain AArch64-only."
        );
    }

    #[test]
    fn resolve_opt_target_allows_x86_with_shared_algorithms() {
        // Enumerative / stochastic / symbolic run on x86.
        for algorithm in [
            CliAlgorithm::Enumerative,
            CliAlgorithm::Stochastic,
            CliAlgorithm::Symbolic,
        ] {
            assert_eq!(
                resolve_opt_target(None, CliArch::X86_64, algorithm),
                Ok(SupportedArch::X86_64)
            );
        }
    }

    #[test]
    fn resolve_opt_target_allows_aarch64_with_every_algorithm() {
        // AArch64 supports the full algorithm set, including hybrid and LLM.
        for algorithm in [
            CliAlgorithm::Enumerative,
            CliAlgorithm::Stochastic,
            CliAlgorithm::Symbolic,
            CliAlgorithm::Hybrid,
            CliAlgorithm::Llm,
        ] {
            assert_eq!(
                resolve_opt_target(None, CliArch::Aarch64, algorithm),
                Ok(SupportedArch::Aarch64)
            );
        }
    }

    #[test]
    fn disassemble_elf_binary_rejects_expected_arch_mismatch() {
        let elf_bytes = build_minimal_elf64(&[0xc3], 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-disasm-mismatch", "elf", &elf_bytes);

        let err = disassemble_elf_binary(input.path(), Some(SupportedArch::Aarch64))
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
    fn disassemble_elf_binary_accepts_matching_expected_arch() {
        let elf_bytes = build_minimal_elf64(&[0xc3], 0x1000, elf::abi::EM_X86_64);
        let input = TempFile::new_bytes("s11-disasm-match", "elf", &elf_bytes);

        disassemble_elf_binary(input.path(), Some(SupportedArch::X86_64))
            .expect("matching expected architecture should disassemble");
    }

    #[test]
    fn disassemble_elf_binary_rejects_riscv_machine() {
        let elf_bytes = build_minimal_elf64(&[0x13, 0x00, 0x00, 0x00], 0x1000, elf::abi::EM_RISCV);
        let input = TempFile::new_bytes("s11-disasm-riscv", "elf", &elf_bytes);

        let err = disassemble_elf_binary(input.path(), None)
            .expect_err("RISC-V ELF disassembly should not be supported yet");

        assert_eq!(
            err.to_string(),
            format!(
                "Unsupported architecture (e_machine: {})",
                elf::abi::EM_RISCV
            )
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
    fn opt_help_defines_zero_solver_timeout_as_disabling_smt() {
        use clap::CommandFactory;

        let mut command = Args::command();
        let opt_help = command
            .find_subcommand_mut("opt")
            .expect("opt subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(
            opt_help.contains("0 disables SMT queries")
                && opt_help.contains("does not request an unbounded solver query"),
            "opt help should define the zero solver-timeout policy:\n{opt_help}"
        );
    }

    /// Parse an `s11` invocation and return the `Opt` subcommand it selected,
    /// panicking if parsing fails or another subcommand was chosen. Keeps the
    /// `--auto`/`-o` parse tests terse.
    fn parse_opt(args: &[&str]) -> Commands {
        Args::try_parse_from(args)
            .unwrap_or_else(|e| panic!("expected `{args:?}` to parse: {e}"))
            .command
    }

    /// Parse an invocation expected to fail and return the clap error. Written
    /// by hand rather than `Result::expect_err` so it need not require
    /// `Args: Debug`.
    fn parse_opt_err(args: &[&str]) -> clap::Error {
        match Args::try_parse_from(args) {
            Ok(_) => panic!("expected `{args:?}` to fail parsing"),
            Err(e) => e,
        }
    }

    #[test]
    fn opt_auto_with_output_parses() {
        let Commands::Opt {
            auto,
            output,
            start_addr,
            end_addr,
            ..
        } = parse_opt(&["s11", "opt", "prog.elf", "--auto", "-o", "out.elf"])
        else {
            panic!("expected the opt subcommand");
        };
        assert!(auto);
        assert_eq!(output, Some(PathBuf::from("out.elf")));
        assert_eq!(start_addr, None);
        assert_eq!(end_addr, None);
    }

    #[test]
    fn opt_auto_without_output_parses() {
        // The driver falls back to the derived path when -o is omitted, so
        // --auto must be legal on its own — guards against a future change that
        // makes -o mandatory.
        let Commands::Opt {
            auto,
            output,
            max_windows,
            ..
        } = parse_opt(&["s11", "opt", "prog.elf", "--auto"])
        else {
            panic!("expected the opt subcommand");
        };
        assert!(auto);
        assert_eq!(output, None);
        assert_eq!(max_windows, s11::auto_driver::DEFAULT_MAX_WINDOWS);
    }

    #[test]
    fn opt_auto_parses_global_window_budget() {
        let Commands::Opt {
            auto, max_windows, ..
        } = parse_opt(&["s11", "opt", "prog.elf", "--auto", "--max-windows", "0"])
        else {
            panic!("expected the opt subcommand");
        };
        assert!(auto);
        assert_eq!(max_windows, 0);
    }

    #[test]
    fn opt_auto_conflicts_with_start_addr() {
        let err = parse_opt_err(&["s11", "opt", "prog.elf", "--auto", "--start-addr", "0x1000"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn opt_max_windows_requires_auto_mode() {
        let err = parse_opt_err(&[
            "s11",
            "opt",
            "prog.elf",
            "--start-addr",
            "0x1000",
            "--end-addr",
            "0x1100",
            "--max-windows",
            "1",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn opt_auto_conflicts_with_end_addr() {
        let err = parse_opt_err(&["s11", "opt", "prog.elf", "--auto", "--end-addr", "0x1100"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn opt_single_window_requires_addresses_without_auto() {
        let err = parse_opt_err(&["s11", "opt", "prog.elf"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn opt_single_window_is_unaffected() {
        let Commands::Opt {
            auto,
            output,
            start_addr,
            end_addr,
            ..
        } = parse_opt(&[
            "s11",
            "opt",
            "prog.elf",
            "--start-addr",
            "0x1000",
            "--end-addr",
            "0x1100",
        ])
        else {
            panic!("expected the opt subcommand");
        };
        assert!(!auto);
        assert_eq!(output, None);
        assert_eq!(start_addr.as_deref(), Some("0x1000"));
        assert_eq!(end_addr.as_deref(), Some("0x1100"));
    }

    #[test]
    fn opt_single_window_honors_output() {
        let Commands::Opt { output, .. } = parse_opt(&[
            "s11",
            "opt",
            "prog.elf",
            "--start-addr",
            "0x1000",
            "--end-addr",
            "0x1100",
            "-o",
            "out.elf",
        ]) else {
            panic!("expected the opt subcommand");
        };
        assert_eq!(output, Some(PathBuf::from("out.elf")));
    }

    #[test]
    fn opt_accepts_zero_solver_timeout_as_the_disable_sentinel() {
        let Commands::Opt { solver_timeout, .. } = parse_opt(&[
            "s11",
            "opt",
            "prog.elf",
            "--start-addr",
            "0x1000",
            "--end-addr",
            "0x1100",
            "--solver-timeout",
            "0",
        ]) else {
            panic!("expected the opt subcommand");
        };

        assert_eq!(solver_timeout, 0);
    }

    #[test]
    fn opt_help_mentions_auto_and_output() {
        use clap::CommandFactory;

        let mut command = Args::command();
        let opt_help = command
            .find_subcommand_mut("opt")
            .expect("opt subcommand should be registered")
            .render_long_help()
            .to_string();

        assert!(
            opt_help.contains("--auto"),
            "opt help should document --auto:\n{opt_help}"
        );
        assert!(
            opt_help.contains("--output"),
            "opt help should document -o/--output:\n{opt_help}"
        );
        assert!(
            opt_help.contains("--max-windows"),
            "opt help should document the global auto budget:\n{opt_help}"
        );
        assert!(
            opt_help.contains("Existing output files are refused unless --force is passed"),
            "opt help should document the overwrite policy:\n{opt_help}"
        );
        assert!(
            opt_help.contains("Any non-regular filesystem entry"),
            "opt help should document rejection of special output files:\n{opt_help}"
        );
        assert!(
            opt_help.contains("A successful run always writes the result file"),
            "opt help should document no-improvement copy-through:\n{opt_help}"
        );
        assert!(
            opt_help.contains("a re-encoding of the searched window on AArch64"),
            "opt help must not promise a byte copy on AArch64, whose no-improvement \
             path re-assembles the window:\n{opt_help}"
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
                assert_eq!(parse_x86_register(alias).unwrap().canonical(), reg);
            }
        }
        for (alias, expected) in [
            ("ah", X86Register::AH),
            ("ch", X86Register::CH),
            ("dh", X86Register::DH),
            ("bh", X86Register::BH),
        ] {
            assert_eq!(parse_x86_register(alias).unwrap(), expected);
        }
    }

    #[test]
    fn x86_64_capstone_bridge_retains_sub_register_aliases() {
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
        assert_eq!(
            convert_to_x86_ir(&add_eax, parser::x86::X86ParseMode::Mode64).unwrap(),
            vec![X86Instruction::AddImm {
                rd: X86Register::EAX,
                imm: 0,
            }]
        );

        let mov_al = cs
            .disasm_all(&[0xb0, 0x7f], 0x1000)
            .expect("disassemble mov al, 0x7f");
        let insn = mov_al.iter().next().expect("one instruction");
        assert_eq!(insn.mnemonic(), Some("mov"));
        assert_eq!(insn.op_str(), Some("al, 0x7f"));
        assert_eq!(
            convert_to_x86_ir(&mov_al, parser::x86::X86ParseMode::Mode64).unwrap(),
            vec![X86Instruction::MovImm {
                rd: X86Register::AL,
                imm: 0x7f,
            }]
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
                rd: X86Register::EAX,
                imm: 0,
            }]
        );
    }

    #[test]
    fn x86_capstone_bridge_accepts_extension_move_source_widths() {
        let cs64 = capstone::Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone x86-64 init");
        let movzx = cs64
            .disasm_all(&[0x48, 0x0f, 0xb6, 0xc3], 0x1000)
            .expect("disassemble movzx rax, bl");
        assert_eq!(
            convert_to_x86_ir(&movzx, parser::x86::X86ParseMode::Mode64).unwrap(),
            vec![X86Instruction::Movzx {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                src_width: 8,
            }]
        );
        let movzx_eax = cs64
            .disasm_all(&[0x0f, 0xb6, 0xc3], 0x1000)
            .expect("disassemble movzx eax, bl");
        assert_eq!(
            convert_to_x86_ir(&movzx_eax, parser::x86::X86ParseMode::Mode64).unwrap(),
            vec![X86Instruction::Movzx {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                src_width: 8,
            }]
        );
        let movsx_eax = cs64
            .disasm_all(&[0x0f, 0xbe, 0xc3], 0x1000)
            .expect("disassemble movsx eax, bl");
        assert!(
            convert_to_x86_ir(&movsx_eax, parser::x86::X86ParseMode::Mode64).is_err(),
            "MOVSX through EAX is not representable by the native-width extension IR"
        );

        let cs32 = capstone::Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode32)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone x86-32 init");
        let movsx = cs32
            .disasm_all(&[0x0f, 0xbf, 0xc2], 0x1000)
            .expect("disassemble movsx eax, dx");
        assert_eq!(
            convert_to_x86_ir(&movsx, parser::x86::X86ParseMode::Mode32).unwrap(),
            vec![X86Instruction::Movsx {
                rd: X86Register::RAX,
                rs: X86Register::RDX,
                src_width: 16,
            }]
        );
    }

    #[test]
    fn x86_capstone_bridge_rejects_architectural_setcc_byte_destinations() {
        for (mode, parse_mode) in [
            (
                capstone::arch::x86::ArchMode::Mode64,
                parser::x86::X86ParseMode::Mode64,
            ),
            (
                capstone::arch::x86::ArchMode::Mode32,
                parser::x86::X86ParseMode::Mode32,
            ),
        ] {
            let cs = capstone::Capstone::new()
                .x86()
                .mode(mode)
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .build()
                .expect("capstone init");
            let setne_al = cs
                .disasm_all(&[0x0f, 0x95, 0xc0], 0x1000)
                .expect("disassemble setne al");
            let instruction = setne_al.iter().next().expect("one instruction");
            assert_eq!(instruction.mnemonic(), Some("setne"));
            assert_eq!(instruction.op_str(), Some("al"));
            let err = convert_to_x86_ir(&setne_al, parse_mode)
                .expect_err("architectural byte SETcc must not enter the full-width pseudo-IR");
            assert!(
                err.contains("cannot be represented until #75"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn run_equiv_and_llm_opt_accept_equivalent_tiny_files() {
        let asm1 = TempFile::new("s11-equiv-a", "s", "mov x0, x1\n");
        let asm2 = TempFile::new("s11-equiv-b", "s", "mov x0, x1\n");
        assert_eq!(
            run_equiv(asm1.path(), asm2.path(), "x0", 1, true, true).unwrap(),
            0,
            "equivalent sequences must map to exit code 0"
        );

        let llm_asm = TempFile::new("s11-llm", "s", "mov x0, x1\n");
        run_llm_opt(llm_asm.path(), "x0", 0, "test-model", 0, true).unwrap();
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
}
