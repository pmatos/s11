# Architecture deepening backlog

Persisted candidate memory for the `pm-deepen` refactor-audit routine. Statuses:
`proposed` (surfaced, scored, eligible), `in-flight` (branch + PR exist),
`landed` (PR merged), `dropped` (a hard filter excluded it — reversible),
`rejected` (a human declined it — only a human re-proposes). Score axes:
`score = leverage×2 + locality + heat + (6 − blast_radius)`, range 5–25.

> **Backlog provenance (2026-09-02).** This file was recovered from the unmerged
> branch `pm-deepen/run-2026-09-01-0107` because `.architecture/` was absent from
> `origin/main`. As of the 2026-09-03 firing it now rides on `origin/main` (PR
> #812 merged), so subsequent firings reconcile against a stable copy. Pre-#800
> `main.rs` line references have been corrected against the current tree during
> the 2026-09-03 firing.

## opt-window-report-seam

- **Status**: landed
- **Score**: 22/25 (leverage 4, locality 4, blast radius 1, heat 5)
- **Files**: 2–3 estimated (`src/report.rs` edited, new lib-visible outcome type, `src/main.rs` edited)
- **Modules**: `report::build_window_write_plan` (`src/report.rs:290`), `WindowWritePlan`/`WindowWriteAction` (`src/report.rs:273`/`:260`), `ElfWindowOptimization` (relocated to `src/auto_driver.rs:38`)
- **Summary**: Give the `opt` single-window path a pure `report::build_window_write_plan` seam mirroring the `equiv` path's `build_equiv_report`, so the untested miss/improve/leave-unchanged classification and its "Created optimized/unchanged binary" messages become unit-pinnable instead of reachable only through the `opt` binary. Relocated the bin-local `ElfWindowOptimization` outcome type into the lib (`src/auto_driver.rs`) so `report.rs` (lib) can consume it.
- **First seen**: 2026-09-01
- **PR**: #818 (merged 2026-09-03)
- **Reason**: Landed — `gh pr view 818` reports state MERGED (mergedAt 2026-09-03T08:18:00Z). Reconciled from `in-flight` to `landed` this firing (2026-09-04).

## elf-optimizer-engine-extraction

- **Status**: in-flight
- **Score**: 22/25 (leverage 5, locality 5, blast radius 4, heat 5)
- **PR**: #823 (opened 2026-09-04)
- **Files**: 3 estimated (`src/main.rs`, `src/lib.rs`, new `src/elf_optimizer/`)
- **Modules**: engine block `src/main.rs:543`–`:2417` (trait `ElfOptimizationBackend` `:606`, both backend impls `:678`/`:847`, `find_candidate_windows*` `:1111`/`:1125`/`:1136`, `run_auto_optimization*` `:1459`/`:1495`, `optimize_elf_binary*` `:1579`/`:1610`/`:1736`, `run_optimization` `:1947`, `run_x86_*` `:2279`/`:2325`/`:2376`, `build_*_search_config` `:1805`–`:2278`, `print_*` `:2110`–`:2131`); `src/lib.rs`; new `src/elf_optimizer/`
- **Summary**: Relocate the ~1,875-line ELF optimization engine out of `main.rs` into `src/elf_optimizer/` as a deep lib module behind a 6-item interface (`OptimizationOptions`, `run_auto_optimization`, `optimize_elf_binary`, three `print_*`), carrying its 66 engine-only tests into the module. Verified this firing: the engine references **zero** CLI-layer types, all 66 engine tests classify cleanly (0 "both" tests), so the move is clean. A follow-on narrows the two leaky trait methods that still take raw Capstone (`optimization_context(…, cs: &Capstone)` `:643`, `assemble_window(…, capstone_instructions: &Instructions, …)` `:667`).
- **First seen**: 2026-09-01
- **Reason**: — (pick, run 2026-09-04; `opt-window-report-seam` PR #818 now landed so the one-architecture-PR-at-a-time block is cleared. Runner-up candidate `opt-target-arch-mismatch-classifier` at 19/25, three points below.)

## x86-width-dispatch-runner

- **Status**: proposed
- **Score**: 19/25 (leverage 3, locality 4, blast radius 1, heat 4)
- **Files**: ~1 estimated
- **Modules**: `src/main.rs:2279` (`run_x86_enumerative`), `src/main.rs:2325` (`run_x86_stochastic`), `src/main.rs:2376` (`run_x86_symbolic`)
- **Summary**: Collapse the triplicated width-dispatch spine of `run_x86_enumerative/stochastic/symbolic` into one generic `run_x86_width_dispatched<A: SearchAlgorithm>` helper.
- **First seen**: 2026-09-01
- **Reason**: — (Note, line refs refreshed 2026-09-04: the triplication is **already drifting** — `run_x86_stochastic` has an early `if config.x86_available_registers.is_empty() { return None; }` guard at `src/main.rs:2336`–2338 that the enumerative and symbolic siblings lack. Either a latent bug in the other two or an undocumented asymmetry; a shared seam would have prevented the divergence.)

## search-config-builder-module

- **Status**: proposed
- **Score**: 19/25 (leverage 4, locality 4, blast radius 2, heat 3)
- **Files**: ~2–3 estimated
- **Modules**: `src/main.rs:542` (`OptimizationOptions`), `src/main.rs:1852`–1992 + `:2314` (builder family), `src/search/config.rs`
- **Summary**: Move `OptimizationOptions` and the 12-strong search-config builder family into `search/config.rs` as `SearchConfig::for_aarch64`/`for_x86` constructors, unifying the two near-identical base builders. No longer coupling-blocked — every field is already a `search::config` type.
- **First seen**: 2026-09-01
- **Reason**: —

## search-result-optimized-accessor

- **Status**: proposed
- **Score**: 19/25 (leverage 4, locality 4, blast radius 2, heat 3)
- **Files**: ~2 estimated (`src/search/result.rs`, `src/main.rs`)
- **Modules**: `src/search/result.rs:13` (`SearchResult`), `src/search/result.rs:67` (`SearchResultFor<I>`), 8 call sites in `src/main.rs`
- **Summary**: Both result structs store `optimized_sequence: Option<..>` **and** a redundant `found_optimization: bool` that is always exactly `optimized_sequence.is_some()`; every consumer then re-derives "optimized if found" — the five `run_optimization` arms (`src/main.rs:2054`–2149) and the three x86 runners' `.found_optimization.then_some(result.optimized_sequence).flatten()` (`src/main.rs:2346`–2459). Collapse the redundant bool into a derived accessor `optimized_if_found(self) -> Option<Vec<..>>`, removing an invariant that can silently drift and unifying 8 call sites.
- **First seen**: 2026-09-03
- **Reason**: — (leans type-design/simplification: it tidies the result data model rather than deepening a module interface, which is why leverage is 4 not 5)

## opt-target-arch-mismatch-classifier

- **Status**: proposed
- **Score**: 19/25 (leverage 3, locality 3, blast radius 1, heat 5)
- **Files**: ~1 estimated (`src/main.rs`)
- **Modules**: `src/main.rs:418` (`OptTargetError::Display`), `src/main.rs:501` (`disassemble_elf_binary`), `src/main.rs:2613` (`message.starts_with(ARCH_MISMATCH_PREFIX)` re-dispatch), `src/main.rs:2651`–2679 (inline RISC-V pre-dispatch peek)
- **Summary**: The arch-mismatch message string is built at three independent sites and `main` re-classifies errors by matching on its wording; separately, the RISC-V pre-dispatch peek re-reads the ELF header and formats its own mismatch/refusal decision inline (~28 lines with `std::process::exit`), directly contradicting the comment at `:2688` that "every pre-dispatch policy rule lives behind `resolve_opt_target`". Unify behind one pure `classify_opt_target(requested, e_machine) -> Result<SupportedArch, OptTargetError>` so the message has one owner and the RISC-V/mismatch decision is table-testable like `resolve_opt_target` already is.
- **First seen**: 2026-09-03
- **Reason**: — (leverage diluted by overlap with `arch-name-rendering` (labels) and adjacency to the dropped `resolve-opt-target-relocation`; distinct in that it concerns the cross-check decision + message, not the label strings or the already-clean pure seam)

## aarch64-parser-arity-combinators

- **Status**: proposed
- **Score**: 19/25 (leverage 2, locality 5, blast radius 1, heat 5)
- **Files**: ~1 estimated (`src/parser/mod.rs`)
- **Modules**: `src/parser/mod.rs` (arity prologue repeated ~49×; sibling parsers `:584`–759; dispatch `:2089+`)
- **Summary**: The arity-check prologue `if operands.len() != N { return Err(...) }` is copy-pasted ~49 times, and ~12 sibling parsers are byte-for-byte identical bar the emitted variant in four clean families (`neg`/`negs`; `adc`/`adcs`/`sbc`/`sbcs`; `bic`/`bics`/`orn`/`eon`; `cset`/`csetm`). One `expect_arity(mnem, ops, n)` helper covers the 49 prologues and ~3 combinators collapse the 12 siblings, extending the file's existing combinator idiom (`parse_unary_rd_rn`, `parse_unary_extend`). Exclude `parse_ands`/`parse_adds`/`parse_subs` (variable arity/width).
- **First seen**: 2026-09-03
- **Reason**: — (leverage 2: `parse_line`'s public interface is unchanged, callers gain nothing, and behaviour is already pinned end-to-end so the test surface barely improves — this is implementation-internal DRY inside an already-deep module, weighted low despite high raw duplication. Heat is 5, not "cold": `src/parser/mod.rs` was last touched 2026-09-01 (#810) and appears in ~108 of the last 120 commits — the Explore agent's "1 change in 40 commits" note was wrong.)

## arch-name-rendering

- **Status**: proposed
- **Score**: 14/25 (leverage 2, locality 2, blast radius 1, heat 3)
- **Files**: ~1–2 estimated
- **Modules**: `src/main.rs:1615` (`decode_arch_label`), `src/main.rs:660` + `:917` (`arch_description` impls), `src/main.rs:202` (`CliArch: Display`); natural home `src/elf_patcher/mod.rs:48` (`DetectedArch` already hosts `instruction_alignment`/`nop_sequence`)
- **Summary**: Collapse the three parallel arch-to-string paths into a single `DetectedArch::label()`. Low priority.
- **First seen**: 2026-09-01
- **Reason**: —

## cli-error-exit-seam

- **Status**: proposed
- **Score**: 20/25 (leverage 3, locality 4, blast radius 1, heat 5)
- **Files**: ~1 estimated (`src/main.rs`)
- **Modules**: `src/main.rs:2545`–`:2758` (`fn main`: 15 `std::process::exit` + 15 `eprintln!` paired inline across every command arm)
- **Summary**: The error→exit-code/message policy has no owner: it is scattered across ~15 inline `eprintln!("Error …: {e}"); std::process::exit(1);` sites and is reachable only by running the `s11` binary. Frame command handlers as `Commands::run(self) -> Result<(), CliError>` with a single exit-mapping site in `main`, deepening the dispatch and making the exit/message table pinnable via the repo's integration-test binaries.
- **First seen**: 2026-09-04
- **Reason**: — (fresh this firing; strongest new candidate, 2 points below the pick. Partially subsumes `opt-target-arch-mismatch-classifier`'s exit paths at `:2620/:2624/:2629`. Pinnable: current exit-code behaviour is observable through the CI-built integration test binaries, so it survives the "cannot be pinned" filter.)

## x86-parser-mnemonic-dispatch-decomposition

- **Status**: proposed
- **Score**: 17/25 (leverage 2, locality 4, blast radius 1, heat 4)
- **Files**: ~1 estimated (`src/parser/x86.rs`)
- **Modules**: `src/parser/x86.rs:361`–`:731` (`x86_ir_from_mnemonic_impl`, one ~370-line sequential `if mnemonic == …` dispatch)
- **Summary**: The x86 twin of `aarch64-parser-arity-combinators`, concentrated in one ~370-line mega-function that re-implements arity + register-width checks inline per family (SETcc, CMOVcc, Jcc, NEG/NOT/INC/DEC, IMUL, two-operand families). Extract per-family `parse_x86_*` combinators mirroring the AArch64 `parse_unary_*` idiom so each family is a named, testable unit. Public parse interface unchanged (leverage 2).
- **First seen**: 2026-09-04
- **Reason**: — (fresh this firing; internal DRY inside an already-deep module, weighted low despite high raw size because `parse_x86_assembly_string`'s interface is unchanged and behaviour is already pinned end-to-end)

## resolve-opt-target-relocation

- **Status**: dropped
- **Score**: not scored (hard-filtered)
- **Files**: ~2 estimated
- **Modules**: `src/main.rs:442` (`resolve_opt_target`)
- **Summary**: Relocate `resolve_opt_target` out of the driver.
- **First seen**: 2026-09-01
- **Reason**: Leverage ~1 — already a clean, fully-pinned pure seam (8 table tests); its only coupling is to CLI-layer enums that legitimately live beside the clap definitions, so moving it is near-zero leverage. Re-check the filter if those enums move. (2026-09-04 re-check: still dropped; the enums have not moved.)

## llm-search-stats-accumulator

- **Status**: landed
- **Score**: 22/25 (leverage 4, locality 4, blast radius 1, heat 5)
- **Files**: 2 (`src/search/llm/accounting.rs` new, `src/search/llm/mod.rs` edited)
- **Modules**: `src/search/llm/accounting.rs` (new seam), `src/search/llm/mod.rs` (`LlmSearch::search`)
- **Summary**: Pulled the LLM search-run accounting (stats/timings/ledger updates) out of the `LlmSearch::search` loop into a tested `RunAccounting` seam fed one `RunEvent` per loop event.
- **First seen**: 2026-09-01
- **PR**: #812 (merged 2026-09-02)
- **Reason**: Landed — `gh pr view 812` reports state MERGED (mergedAt 2026-09-02T07:51:15Z); on `origin/main` as `0238e4f refactor(llm): extract search-run accounting into a tested seam (#812)`. Reconciled to `landed` this firing.

## auto-capstone-detail-seam

- **Status**: landed
- **Score**: n/a (prior firing)
- **Files**: n/a
- **Modules**: `src/capstone_detail.rs` (new), `src/main.rs` auto driver (`find_candidate_windows_with_detail_provider`)
- **Summary**: Extract Capstone detail inspection in the auto driver into a pure tested seam.
- **First seen**: 2026-08-26
- **PR**: #800 (merged 2026-09-01/02)
- **Reason**: Landed — `gh pr view 800` reports state MERGED.

## Run log

### Run 2026-09-01 — bailed (one-architecture-PR-at-a-time)

- **Outcome**: bailed-preflight-clean / blocked-open-PR (candidates surfaced and scored; implementation not started)
- **Stopped at**: step 2 — reconciliation found an open in-flight architecture PR (#800); skill rule is one architecture PR at a time.
- **Branch**: `pm-deepen/run-2026-09-01-0107` — created from `origin/main` (adoption of the firing branch refused: condition 3 failed — upstream set to `origin/main`). Kept run-stamped.
- **Committed**: report + backlog, pushed to the run branch.
- **Next**: A human merges (or closes) PR #800; the next firing reconciles and implements the top surviving candidate.

### Run 2026-09-02 — complete (llm-search-stats-accumulator)

- **Outcome**: complete
- **Stopped at**: n/a — full default run through PR
- **Branch**: `pm-deepen/llm-search-stats-accumulator` — created from `origin/main` (adoption refused: condition 3 failed — upstream set to `origin/main`), renamed from `pm-deepen/run-2026-09-02-0102` at step 2.
- **Committed**: report + recovered backlog, design adjudication, accounting seam + CONTEXT.md term, in-flight backlog. PR #812.
- **Next**: a human reviews and merges PR #812; the next firing reconciles this entry to `landed` and picks the runner-up `opt-window-report-seam` (tied 22/25).

### Run 2026-09-03 — complete (opt-window-report-seam)

- **Outcome**: complete
- **Stopped at**: n/a — full default run through PR
- **Branch**: `pm-deepen/opt-window-report-seam` — created from `origin/main` (adoption of the firing branch `sym/s11/routine/refactor-audit/01M1J5Q8CD` refused: condition 3 failed — it had an upstream set to `origin/main`), renamed from `pm-deepen/run-2026-09-03-0103` at step 2.
- **Committed**: this report (`.architecture/reviews/2026-09-03-opt-window-report-seam.md`) + reconciled backlog; design adjudication; the `build_window_write_plan` seam (PR #818); in-flight backlog + PR link.
- **Evidence**: PR #812 reconciled to `landed` (merged); no open architecture PRs at start, so the one-at-a-time block was clear. Three fresh candidates added (`search-result-optimized-accessor`, `opt-target-arch-mismatch-classifier`, `aarch64-parser-arity-combinators`).
- **Next**: a human reviews and merges the PR; the next firing reconciles this entry to `landed` and picks the runner-up `elf-optimizer-engine-extraction` (tied 22/25, blast radius 4).

### Run 2026-09-04 — complete (elf-optimizer-engine-extraction)

- **Outcome**: complete
- **Stopped at**: n/a — full default run through PR
- **Branch**: `pm-deepen/elf-optimizer-engine-extraction` — created from `origin/main` (adoption of the firing branch `sym/s11/routine/refactor-audit/01M1MR2N0C` refused: condition 3 failed — it had an upstream set to `origin/main`), renamed from `pm-deepen/run-2026-09-04-0102` at step 2.
- **Committed**: this report (`.architecture/reviews/2026-09-04-elf-optimizer-engine-extraction.md`) + reconciled backlog; design-it-twice adjudication (winner: faithful single-module move); the `src/elf_optimizer/` extraction + `tests/elf_optimizer_public_surface.rs` pin test + `CLAUDE.md` path fix (PR #823); in-flight backlog + PR link.
- **Evidence**: PR #818 reconciled to `landed` (merged 2026-09-03); no open architecture PRs at start, so the one-at-a-time block was clear. Gate green: fmt, clippy `-D warnings`, 1832 lib + 42 bin + 76 integration + 1 pin test. Two fresh candidates added: `cli-error-exit-seam` (20/25), `x86-parser-mnemonic-dispatch-decomposition` (17/25). The scored candidate's trait-method narrowing was evaluated and **declined** (Capstone params are load-bearing).
- **Next**: a human reviews and merges PR #823; the next firing reconciles this entry to `landed` and picks the top surviving candidate — `cli-error-exit-seam` (20/25) leads the `proposed` set.
