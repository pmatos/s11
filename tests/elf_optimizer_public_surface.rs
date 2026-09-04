//! Pins the public interface of the extracted `elf_optimizer` module.
//!
//! Before the engine was relocated out of `main.rs`, this whole optimization
//! pipeline was inlined in the binary crate and had no interface at all — it
//! was reachable only as private siblings of `fn main`. This test pins the
//! module's 6-item public surface as *the* test surface: the `use` below
//! fails to compile if any public item is renamed or removed, and each
//! function is coerced to its exact signature (via a `type` alias so the
//! signature is named rather than triggering `clippy::type_complexity`), so a
//! regression that narrows a signature also fails to compile here.

use std::path::Path;
use std::time::Duration;

use s11::elf_optimizer::{
    OptimizationOptions, optimize_elf_binary, print_llm_timings, print_search_statistics,
    print_unsupported_mnemonic_ledger, run_auto_optimization,
};
use s11::elf_patcher::ElfPatcher;
use s11::output_path::ResolvedOutput;
use s11::search::llm::LlmTimings;
use s11::search::llm::ledger::UnsupportedMnemonicLedger;
use s11::search::result::SearchStatistics;

type OptResult = Result<(), Box<dyn std::error::Error>>;
type SingleWindowEntry =
    fn(&ElfPatcher, &Path, u64, u64, &ResolvedOutput, &OptimizationOptions) -> OptResult;
type AutoEntry =
    fn(ElfPatcher, &Path, Option<&Path>, bool, &OptimizationOptions, usize) -> OptResult;

#[test]
fn elf_optimizer_exposes_the_engine_entry_points() {
    // Coerce each public function to its exact signature. This pins the whole
    // public surface without running any side-effecting optimization work.
    let _single: SingleWindowEntry = optimize_elf_binary;
    let _auto: AutoEntry = run_auto_optimization;
    let _stats: fn(&SearchStatistics) = print_search_statistics;
    let _timings: fn(&LlmTimings, Duration) = print_llm_timings;
    let _ledger: fn(&UnsupportedMnemonicLedger) = print_unsupported_mnemonic_ledger;

    // `OptimizationOptions` is nameable and sized through the facade.
    assert!(std::mem::size_of::<OptimizationOptions>() > 0);
}
