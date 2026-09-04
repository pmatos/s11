//! Pins the public interface of the extracted `elf_optimizer` module.
//!
//! Before the engine was relocated out of `main.rs`, this whole optimization
//! pipeline was inlined in the binary crate and had no interface at all — it
//! was reachable only as private siblings of `fn main`. This test exists to
//! pin the module's 6-item public surface as *the* test surface: the `use`
//! below fails to compile if any public item is renamed or removed, and the
//! body pins the reporter signatures. The two entry-point signatures are held
//! fixed by `main.rs`'s own call sites.

use std::time::Duration;

use s11::elf_optimizer::{
    OptimizationOptions, optimize_elf_binary, print_llm_timings, print_search_statistics,
    print_unsupported_mnemonic_ledger, run_auto_optimization,
};
use s11::search::llm::LlmTimings;
use s11::search::llm::ledger::UnsupportedMnemonicLedger;
use s11::search::result::SearchStatistics;

#[test]
fn elf_optimizer_exposes_the_engine_entry_points() {
    // The three reporters have simple signatures — pin them exactly.
    let _stats: fn(&SearchStatistics) = print_search_statistics;
    let _timings: fn(&LlmTimings, Duration) = print_llm_timings;
    let _ledger: fn(&UnsupportedMnemonicLedger) = print_unsupported_mnemonic_ledger;

    // The two window/auto entry points exist behind the facade; their exact
    // signatures are exercised by `main.rs`, so here we only pin addressability.
    let _single = optimize_elf_binary;
    let _auto = run_auto_optimization;

    // `OptimizationOptions` is nameable and sized through the facade.
    assert!(std::mem::size_of::<OptimizationOptions>() > 0);
}
