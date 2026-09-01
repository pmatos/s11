# Architecture deepening backlog

Persisted candidate memory for the `pm-deepen` refactor-audit routine. Statuses:
`proposed` (surfaced, scored, eligible), `in-flight` (branch + PR exist),
`landed` (PR merged), `dropped` (a hard filter excluded it — reversible),
`rejected` (a human declined it — only a human re-proposes). Score axes:
`score = leverage×2 + locality + heat + (6 − blast_radius)`, range 5–25.

> **Backlog provenance (2026-09-02).** This file was recovered from the unmerged
> branch `pm-deepen/run-2026-09-01-0107` because `.architecture/` is absent from
> `origin/main`: PR #800 merged without carrying it, and every prior firing kept
> its backlog only on a run-stamped branch. The `main.rs` line references in the
> `main.rs`-hosted entries below predate #800 (which removed ~296 lines from
> `main.rs`) and are therefore **approximate**; the picked candidate's
> `src/search/llm/*` references were re-verified against the current tree.

## llm-search-stats-accumulator

- **Status**: proposed
- **Score**: 22/25 (leverage 4, locality 4, blast radius 1, heat 5)
- **Files**: ~2 estimated
- **Modules**: `src/search/llm/mod.rs:95` (`LlmSearch::search`), `src/search/llm/outcome.rs:37` (`classify`)
- **Summary**: Pull the LLM search-run accounting (stats/timings/ledger updates) out of the `LlmSearch::search` loop into a tested `LlmRunAccounting` seam, so the subtle counting rules are unit-pinnable instead of reachable only through `FakeCodex` end-to-end runs.
- **First seen**: 2026-09-01
- **Reason**: — (pick, run 2026-09-02; PR #800 now landed so the one-architecture-PR-at-a-time block from the prior firing is cleared)

## opt-window-report-seam

- **Status**: proposed
- **Score**: 22/25 (leverage 4, locality 4, blast radius 1, heat 5)
- **Files**: ~2 estimated
- **Modules**: `src/main.rs:1762` (approx, pre-#800), `src/report.rs:200`
- **Summary**: Give the `opt` window path a pure `report::build_window_report` seam mirroring the `equiv` path's `build_equiv_report`, so the currently-untested 125-line window orchestrator's miss/improve/leave-unchanged branching and ~11 inline prints become unit-testable.
- **First seen**: 2026-09-01
- **Reason**: — (runner-up candidate; tied with the pick within 0 points, lost the tie-break because the LLM files were touched more recently — #797/#798 vs report.rs #743)

## elf-optimizer-engine-extraction

- **Status**: proposed
- **Score**: 22/25 (leverage 5, locality 5, blast radius 4, heat 5)
- **Files**: 3–5 estimated
- **Modules**: `src/main.rs:654` (approx, pre-#800; trait + impls + orchestrators), `src/lib.rs`, new `src/elf_optimizer/`
- **Summary**: Relocate the ~2,000-line ELF optimization engine (backend trait, both impls, window orchestrator, `run_optimization`, `run_x86_*`) out of `main.rs` into `src/elf_optimizer/` and narrow the leaky `optimization_context`/`assemble_window` trait methods to pass a decoded slice rather than raw Capstone. Best sequenced after the two internal seams above.
- **First seen**: 2026-09-01
- **Reason**: — (loses the blast-radius tie-break; follow-on to the smaller seams)

## x86-width-dispatch-runner

- **Status**: proposed
- **Score**: 19/25 (leverage 3, locality 4, blast radius 1, heat 4)
- **Files**: ~1 estimated
- **Modules**: `src/main.rs:2434`, `src/main.rs:2480`, `src/main.rs:2531` (all approx, pre-#800)
- **Summary**: Collapse the triplicated width-dispatch spine of `run_x86_enumerative/stochastic/symbolic` into one generic `run_x86_width_dispatched<A: SearchAlgorithm>` helper.
- **First seen**: 2026-09-01
- **Reason**: —

## search-config-builder-module

- **Status**: proposed
- **Score**: 19/25 (leverage 4, locality 4, blast radius 2, heat 3)
- **Files**: ~2–3 estimated
- **Modules**: `src/main.rs:542` (`OptimizationOptions`, approx pre-#800), `src/main.rs:1960`–`2100` (approx), `src/search/config.rs`
- **Summary**: Move `OptimizationOptions` and the 12-strong search-config builder family into `search/config.rs` as `SearchConfig::for_aarch64`/`for_x86` constructors, unifying the two near-identical base builders. Re-evaluated: no longer coupling-blocked — every field is already a `search::config` type.
- **First seen**: 2026-09-01
- **Reason**: —

## arch-name-rendering

- **Status**: proposed
- **Score**: 14/25 (leverage 2, locality 2, blast radius 1, heat 3)
- **Files**: ~1–2 estimated
- **Modules**: `src/main.rs:1723`, `src/main.rs:659`, `src/main.rs:916` (all approx, pre-#800)
- **Summary**: Collapse the three parallel arch-to-string paths (`decode_arch_label`, two `arch_description` impls, `CliArch: Display`) into a single `DetectedArch::label()`. Low priority.
- **First seen**: 2026-09-01
- **Reason**: —

## resolve-opt-target-relocation

- **Status**: dropped
- **Score**: not scored (hard-filtered)
- **Files**: ~2 estimated
- **Modules**: `src/main.rs:441` (`resolve_opt_target`, approx pre-#800)
- **Summary**: Relocate `resolve_opt_target` out of the driver.
- **First seen**: 2026-09-01
- **Reason**: Leverage ~1 — already a clean, fully-pinned pure seam (8 table tests); its only coupling is to CLI-layer enums that legitimately live beside the clap definitions, so moving it is near-zero leverage. Re-check the filter if those enums move.

## auto-capstone-detail-seam

- **Status**: landed
- **Score**: n/a (prior firing)
- **Files**: n/a
- **Modules**: `src/capstone_detail.rs` (new), `src/main.rs` auto driver (`find_candidate_windows_with_detail_provider`)
- **Summary**: Extract Capstone detail inspection in the auto driver into a pure tested seam. Implemented by an earlier firing of this routine.
- **First seen**: 2026-08-26
- **PR**: #800 (merged 2026-09-01/02; reconciled to `landed` this firing)
- **Reason**: Landed — `gh pr view 800` reports state MERGED. The merge added `src/capstone_detail.rs` (+420) and trimmed `src/main.rs` by ~296 lines.

## Run log

### Run 2026-09-01 — bailed (one-architecture-PR-at-a-time)

- **Outcome**: bailed-preflight-clean / blocked-open-PR (candidates surfaced and scored; implementation not started)
- **Stopped at**: step 2 — reconciliation found an open in-flight architecture PR (#800); skill rule is one architecture PR at a time.
- **Branch**: `pm-deepen/run-2026-09-01-0107` — created from `origin/main` (adoption of the firing branch `sym/s11/routine/refactor-audit/01M1D161D7` was refused: condition 3 failed — it had an upstream set to `origin/main`). Kept run-stamped (not renamed to `pm-deepen/<slug>`), since no implementation ran.
- **Committed**: this report (`.architecture/reviews/2026-09-01-llm-search-stats-accumulator.md`) and this backlog, pushed to the run branch.
- **Evidence**: `gh pr view 800` → state OPEN, mergedAt null, isDraft false, mergeable MERGEABLE, created 2026-08-26; branch `sym/s11/routine/refactor-audit/01M104XQDM`, title "refactor(auto): extract Capstone detail inspection into a pure tested seam".
- **Next**: A human merges (or closes) PR #800. The next firing then reconciles this backlog against `origin/main`, moves `auto-capstone-detail-seam` to `landed` (or `rejected`), and implements the top surviving candidate — currently `llm-search-stats-accumulator` (runner-up `opt-window-report-seam`, tied).

### Run 2026-09-02 — implementing llm-search-stats-accumulator

- **Outcome**: in-progress → see PR (below) once opened
- **Stopped at**: n/a — full default run
- **Branch**: `pm-deepen/llm-search-stats-accumulator` — created from `origin/main` (adoption of the firing branch `sym/s11/routine/refactor-audit/01M1FK9QZX` refused: condition 3 failed — it had an upstream set to `origin/main`), then renamed from `pm-deepen/run-2026-09-02-0102` to the slug at step 2.
- **Committed**: this backlog and `.architecture/reviews/2026-09-02-llm-search-stats-accumulator.md`; the accounting-seam implementation follows.
- **Evidence**: PR #800 reconciled to `landed`; no open architecture PRs, so the one-at-a-time block is clear. Backlog recovered from unmerged branch `pm-deepen/run-2026-09-01-0107`.
- **Next**: implement the `LlmRunAccounting` seam test-first, open the PR, flip this entry to `in-flight` with the PR number.
