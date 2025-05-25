use capstone::prelude::*;
use clap::Parser;
use elf::{ElfBytes, endian::AnyEndian};
use std::fs;
use std::path::PathBuf;

mod ir;
mod semantics;

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
    #[arg(short, long, conflicts_with = "disasm")]
    demo: bool,

    /// Disassemble the binary showing addresses and machine code
    #[arg(long, conflicts_with = "demo")]
    disasm: bool,
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

    if !args.disasm {
        println!("s11 - AArch64 Optimizer");
    }

    if let Some(binary_path) = args.binary {
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
    } else if args.demo {
        // Run demo
        run_demo();
    } else if args.disasm {
        eprintln!("Error: --disasm requires --binary <path>");
        std::process::exit(1);
    } else {
        // Default: run demo if no binary specified
        println!("No binary specified. Running demo mode.\n");
        run_demo();
        println!("\nTo analyze a binary, use: --binary <path>");
    }
}
