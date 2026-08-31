# Architecture deepening backlog

Persisted candidate memory for the `pm-deepen` refactor-audit routine. Statuses:
`proposed` (surfaced, scored, eligible), `in-flight` (branch + PR exist),
`landed` (PR merged), `dropped` (a hard filter excluded it — reversible),
`rejected` (a human declined it — only a human re-proposes). Score axes:
`score = leverage×2 + locality + heat + (6 − blast_radius)`, range 5–25.

## llm-search-stats-accumulator

- **Status**: proposed
- **Score**: 22/25 (leverage 4, locality 4, blast radius 1, heat 5)
- **Files**: ~2 estimated
- **Modules**: `src/search/llm/mod.rs:95`, `src/search/llm/outcome.rs:37`
- **Summary**: Pull the LLM search-run accounting (stats/timings/ledger updates) out of the `LlmSearch::search` loop into a tested `LlmRunAccounting` seam, so the subtle counting rules are unit-pinnable instead of reachable only through `FakeCodex` end-to-end runs.
- **First seen**: 2026-09-01
- **Reason**: — (pick; blocked this firing by in-flight PR #800, not by a hard filter)

## opt-window-report-seam

- **Status**: proposed
- **Score**: 22/25 (leverage 4, locality 4, blast radius 1, heat 5)
- **Files**: ~2 estimated
- **Modules**: `src/main.rs:1762`, `src/report.rs:200`
- **Summary**: Give the `opt` window path a pure `report::build_window_report` seam mirroring the `equiv` path's `build_equiv_report`, so the currently-untested 125-line window orchestrator's miss/improve/leave-unchanged branching and ~11 inline prints become unit-testable.
- **First seen**: 2026-09-01
- **Reason**: — (runner-up candidate; tied with the pick within 0 points on tie-break)

## elf-optimizer-engine-extraction

- **Status**: proposed
- **Score**: 22/25 (leverage 5, locality 5, blast radius 4, heat 5)
- **Files**: 3–5 estimated
- **Modules**: `src/main.rs:654` (trait + impls + orchestrators), `src/lib.rs`, new `src/elf_optimizer/`
- **Summary**: Relocate the ~2,000-line ELF optimization engine (backend trait, both impls, window orchestrator, `run_optimization`, `run_x86_*`) out of `main.rs` into `src/elf_optimizer/` and narrow the leaky `optimization_context`/`assemble_window` trait methods to pass a decoded slice rather than raw Capstone. Best sequenced after the two internal seams above.
- **First seen**: 2026-09-01
- **Reason**: — (loses the blast-radius tie-break; follow-on to the smaller seams)

## x86-width-dispatch-runner

- **Status**: proposed
- **Score**: 19/25 (leverage 3, locality 4, blast radius 1, heat 4)
- **Files**: ~1 estimated
- **Modules**: `src/main.rs:2434`, `src/main.rs:2480`, `src/main.rs:2531`
- **Summary**: Collapse the triplicated width-dispatch spine of `run_x86_enumerative/stochastic/symbolic` into one generic `run_x86_width_dispatched<A: SearchAlgorithm>` helper.
- **First seen**: 2026-09-01
- **Reason**: —

## search-config-builder-module

- **Status**: proposed
- **Score**: 19/25 (leverage 4, locality 4, blast radius 2, heat 3)
- **Files**: ~2–3 estimated
- **Modules**: `src/main.rs:542` (`OptimizationOptions`), `src/main.rs:1960`–`2100`, `src/search/config.rs`
- **Summary**: Move `OptimizationOptions` and the 12-strong search-config builder family into `search/config.rs` as `SearchConfig::for_aarch64`/`for_x86` constructors, unifying the two near-identical base builders. Re-evaluated: no longer coupling-blocked — every field is already a `search::config` type.
- **First seen**: 2026-09-01
- **Reason**: —

## arch-name-rendering

- **Status**: proposed
- **Score**: 14/25 (leverage 2, locality 2, blast radius 1, heat 3)
- **Files**: ~1–2 estimated
- **Modules**: `src/main.rs:1723`, `src/main.rs:659`, `src/main.rs:916`
- **Summary**: Collapse the three parallel arch-to-string paths (`decode_arch_label`, two `arch_description` impls, `CliArch: Display`) into a single `DetectedArch::label()`. Low priority.
- **First seen**: 2026-09-01
- **Reason**: —

## resolve-opt-target-relocation

- **Status**: dropped
- **Score**: not scored (hard-filtered)
- **Files**: ~2 estimated
- **Modules**: `src/main.rs:441` (`resolve_opt_target`)
- **Summary**: Relocate `resolve_opt_target` out of the driver.
- **First seen**: 2026-09-01
- **Reason**: Leverage ~1 — already a clean, fully-pinned pure seam (8 table tests); its only coupling is to CLI-layer enums that legitimately live beside the clap definitions, so moving it is near-zero leverage. Re-check the filter if those enums move.

## auto-capstone-detail-seam

- **Status**: in-flight
- **Score**: n/a (prior firing)
- **Files**: n/a
- **Modules**: `src/main.rs` auto driver (`find_candidate_windows_with_detail_provider`)
- **Summary**: Extract Capstone detail inspection in the auto driver into a pure tested seam. Implemented by the previous firing of this routine.
- **First seen**: 2026-08-26
- **PR**: #800 (open, unmerged as of 2026-09-01)
- **Reason**: In-flight architecture PR — its open state blocked implementation this firing (one architecture PR at a time).

## Run log

### Run 2026-09-01 — bailed (one-architecture-PR-at-a-time)

- **Outcome**: bailed-preflight-clean / blocked-open-PR (candidates surfaced and scored; implementation not started)
- **Stopped at**: step 2 — reconciliation found an open in-flight architecture PR (#800); skill rule is one architecture PR at a time.
- **Branch**: `pm-deepen/run-2026-09-01-0107` — created from `origin/main` (adoption of the firing branch `sym/s11/routine/refactor-audit/01M1D161D7` was refused: condition 3 failed — it had an upstream set to `origin/main`). Kept run-stamped (not renamed to `pm-deepen/<slug>`), since no implementation ran.
- **Committed**: this report (`.architecture/reviews/2026-09-01-llm-search-stats-accumulator.md`) and this backlog, pushed to the run branch.
- **Evidence**: `gh pr view 800` → state OPEN, mergedAt null, isDraft false, mergeable MERGEABLE, created 2026-08-26; branch `sym/s11/routine/refactor-audit/01M104XQDM`, title "refactor(auto): extract Capstone detail inspection into a pure tested seam".
- **Next**: A human merges (or closes) PR #800. The next firing then reconciles this backlog against `origin/main`, moves `auto-capstone-detail-seam` to `landed` (or `rejected`), and implements the top surviving candidate — currently `llm-search-stats-accumulator` (runner-up `opt-window-report-seam`, tied).
