pub mod aarch64_search_inputs;
pub mod assembler;
pub mod bench_support;
pub mod candidate_windows;
pub mod capstone_bridge;
pub mod capstone_bridge_x86;
pub mod disassembly;
pub mod docs_support;
pub mod elf_patcher;
pub mod ir;
pub mod isa;
pub mod parser;
pub mod report;
pub mod search;
pub mod semantics;
pub mod validation;
pub mod x86_search_inputs;
pub mod x86_window_reassembly;

#[cfg(test)]
#[path = "test_utils.rs"]
mod test_utils;
