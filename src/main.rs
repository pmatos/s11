use capstone::prelude::*;
use clap::Parser;
use elf::{ElfBytes, endian::AnyEndian};
use std::fs;
use std::path::PathBuf;

mod assembler;
mod elf_patcher;
mod ir;
mod semantics;

use assembler::AArch64Assembler;
use elf_patcher::{AddressWindow, ElfPatcher, parse_hex_address};
use ir::{Instruction, Operand, Register};
use semantics::{EquivalenceResult, check_equivalence};

// --- Command Line Arguments ---

#[derive(Parser)]
#[command(name = "s11")]
#[command(about = "s11 - AArch64 Optimizer")]
#[command(version)]
struct Args {
    /// Path to AArch64 ELF binary to analyze
    #[arg(short, long)]
    binary: Option<PathBuf>,

    /// Run demo optimization (default if no binary provided)
    #[arg(short, long, conflicts_with_all = ["disasm", "opt"])]
    demo: bool,

    /// Disassemble the binary showing addresses and machine code
    #[arg(long, conflicts_with_all = ["demo", "opt"])]
    disasm: bool,

    /// Optimize a window of instructions from start to end address
    #[arg(long, conflicts_with_all = ["demo", "disasm"])]
    opt: bool,

    /// Start address of optimization window (hex, e.g., 0x1000)
    #[arg(long, requires = "opt")]
    start_addr: Option<String>,

    /// End address of optimization window (hex, e.g., 0x1100)
    #[arg(long, requires = "opt")]
    end_addr: Option<String>,
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

// --- Optimization Function ---

fn optimize_elf_binary(
    path: &PathBuf,
    start_addr: u64,
    end_addr: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Optimizing ELF binary: {}", path.display());
    println!("Address window: 0x{:x} - 0x{:x}", start_addr, end_addr);

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

    // For MVP: Just reassemble the same instructions (no actual optimization yet)
    // This demonstrates the full pipeline: disasm -> IR -> assembly -> patch

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

    // Convert to IR (for MVP, we'll create simple IR for demonstrable instructions)
    let ir_instructions = convert_to_ir(&instructions)?;
    println!("Converted {} instructions to IR:", ir_instructions.len());

    for instr in &ir_instructions {
        println!("  {}", instr);
    }

    // Reassemble the IR instructions
    let mut assembler = AArch64Assembler::new();
    let assembled_bytes = assembler.assemble_instructions(&ir_instructions)?;
    println!("Reassembled to {} bytes", assembled_bytes.len());

    // Create output filename
    let output_path = {
        let mut new_path = path.clone();
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
        let imm = if imm_str.starts_with("0x") {
            i64::from_str_radix(&imm_str[2..], 16)
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
        let imm = if imm_str.starts_with("0x") {
            i64::from_str_radix(&imm_str[2..], 16)
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
        EquivalenceResult::NotEquivalent => Ok(false),
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

fn run_demo() {
    println!("=== Running Optimization Demo ===");

    // Example: Original Sequence
    // Let's try to optimize:
    // MOV X0, X1
    // ADD X0, X0, #1
    // This is equivalent to: ADD X0, X1, #1 (if X1 is not X0 initially, which our SMT model handles)
    let original_sequence = vec![
        Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        },
        Instruction::Add {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Immediate(1),
        },
    ];

    print!("Original sequence: ");
    for instr in &original_sequence {
        print!("{}; ", instr);
    }
    println!();

    println!("\nSearching for optimizations...");

    match find_shorter_equivalent(&original_sequence) {
        Some(optimized_seq) => {
            print!("Found shorter equivalent sequence: ");
            for instr in &optimized_seq {
                print!("{}; ", instr);
            }
            println!();
        }
        None => {
            println!(
                "No shorter equivalent sequence found with the current MVP search capabilities."
            );
        }
    }

    // Test equivalence directly for a known case
    println!("\nDirectly testing equivalence of known sequences:");
    let seq_a = vec![
        Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        },
        Instruction::Add {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Immediate(1),
        },
    ];
    let seq_b = vec![Instruction::Add {
        rd: Register::X0,
        rn: Register::X1,
        rm: Operand::Immediate(1),
    }];
    print!("Seq A: ");
    seq_a.iter().for_each(|i| print!("{}; ", i));
    println!();
    print!("Seq B: ");
    seq_b.iter().for_each(|i| print!("{}; ", i));
    println!();

    match are_sequences_equivalent(&seq_a, &seq_b) {
        Ok(true) => println!("Direct Test: Seq A and Seq B ARE equivalent."),
        Ok(false) => println!("Direct Test: Seq A and Seq B are NOT equivalent."),
        Err(e) => eprintln!("Direct Test SMT Error: {}", e),
    }
    // Test non-equivalent
    let seq_c = vec![Instruction::MovImm {
        rd: Register::X0,
        imm: 5,
    }];
    print!("Seq C: ");
    seq_c.iter().for_each(|i| print!("{}; ", i));
    println!();
    match are_sequences_equivalent(&seq_a, &seq_c) {
        Ok(true) => println!("Direct Test: Seq A and Seq C ARE equivalent."),
        Ok(false) => println!("Direct Test: Seq A and Seq C are NOT equivalent."),
        Err(e) => eprintln!("Direct Test SMT Error: {}", e),
    }

    // Test MOV #0 vs EOR equivalence
    println!("\nTesting MOV #0 vs EOR equivalence:");
    let mov_zero = vec![Instruction::MovImm {
        rd: Register::X0,
        imm: 0,
    }];
    let eor_self = vec![Instruction::Eor {
        rd: Register::X0,
        rn: Register::X0,
        rm: Operand::Register(Register::X0),
    }];
    print!("MOV X0, #0: ");
    mov_zero.iter().for_each(|i| print!("{}; ", i));
    println!();
    print!("EOR X0, X0, X0: ");
    eor_self.iter().for_each(|i| print!("{}; ", i));
    println!();
    match are_sequences_equivalent(&mov_zero, &eor_self) {
        Ok(true) => {
            println!("Direct Test: MOV #0 and EOR self ARE equivalent (register clearing).")
        }
        Ok(false) => println!("Direct Test: MOV #0 and EOR self are NOT equivalent."),
        Err(e) => eprintln!("Direct Test SMT Error: {}", e),
    }
}

// --- Main Function ---
fn main() {
    let args = Args::parse();

    if !args.disasm && !args.opt {
        println!("s11 - AArch64 Optimizer");
    }

    if let Some(binary_path) = args.binary {
        if args.opt {
            // Optimization mode
            let start_addr = match args.start_addr {
                Some(s) => match parse_hex_address(&s) {
                    Ok(addr) => addr,
                    Err(e) => {
                        eprintln!("Error parsing start address: {}", e);
                        std::process::exit(1);
                    }
                },
                None => {
                    eprintln!("Error: --opt requires --start-addr");
                    std::process::exit(1);
                }
            };

            let end_addr = match args.end_addr {
                Some(s) => match parse_hex_address(&s) {
                    Ok(addr) => addr,
                    Err(e) => {
                        eprintln!("Error parsing end address: {}", e);
                        std::process::exit(1);
                    }
                },
                None => {
                    eprintln!("Error: --opt requires --end-addr");
                    std::process::exit(1);
                }
            };

            match optimize_elf_binary(&binary_path, start_addr, end_addr) {
                Ok(()) => println!("\nOptimization completed successfully."),
                Err(e) => {
                    eprintln!("Error during optimization: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            // Analyze ELF binary
            match analyze_elf_binary(&binary_path, args.disasm) {
                Ok(()) => {
                    if !args.disasm {
                        println!("\nBinary analysis completed successfully.");
                    }
                }
                Err(e) => {
                    eprintln!("Error analyzing binary: {}", e);
                    std::process::exit(1);
                }
            }
        }
    } else if args.demo {
        // Run demo
        run_demo();
    } else if args.disasm {
        eprintln!("Error: --disasm requires --binary <path>");
        std::process::exit(1);
    } else if args.opt {
        eprintln!("Error: --opt requires --binary <path>");
        std::process::exit(1);
    } else {
        // Default: run demo if no binary specified
        println!("No binary specified. Running demo mode.\n");
        run_demo();
        println!("\nTo analyze a binary, use: --binary <path>");
    }
}
