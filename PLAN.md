# Plan — issue #242: Parallel statistics mislabel symbolic workers and drop most worker metrics

## 1. Problem restated

`WorkerMessage::Finished` (src/search/parallel/channel.rs:29-33) only ships `candidates_evaluated`, and the coordinator's `Finished` arm (src/search/parallel/coordinator.rs:150-158) unconditionally synthesises a fresh `SearchStatistics::new(Algorithm::Stochastic)` for every worker, copying only that single field. The symbolic worker — which is always `worker_id == 0` in hybrid mode (src/search/parallel/coordinator.rs:219, src/search/parallel/coordinator.rs:251-272) — therefore appears as `Algorithm::Stochastic` in `worker_statistics`, and `total_statistics` is the sum of one field across workers. Every other stat (`smt_queries`, `smt_equivalent`, `candidates_passed_fast`, `smt_elapsed`, `iterations`, `accepted_proposals`, `improvements_found`, `original_cost`, `best_cost_found`) is silently zero. Because the hybrid CLI path prints `result.total_statistics` (src/main.rs:746), user-visible hybrid reports show 0 SMT/improvement/cost metrics even when a worker has provably found and verified an optimization.

Fix scope: make `Finished` carry the full per-worker `SearchStatistics` (including its `algorithm` field), and have `run_coordinator` aggregate fields field-by-field rather than synthesising stats from scratch. Also: when an improvement wins, `best_result.statistics` should reflect the actual winning worker's stats, not a hollow `SearchStatistics::new(algorithm)`.

## 2. Files to touch

Production:
- `src/search/parallel/channel.rs` — extend `WorkerMessage::Finished` payload (add `algorithm: Algorithm`, `statistics: SearchStatistics`); drop the now-redundant standalone `candidates_evaluated` field (the value is `statistics.candidates_evaluated`).
- `src/search/parallel/coordinator.rs` — three call sites:
  - `run_symbolic_worker` (lines ~244-276): send `result.statistics` (already carries `Algorithm::Symbolic`) instead of just `candidates_evaluated`.
  - `run_stochastic_worker` (lines ~279-315): same — send `result.statistics`.
  - `run_coordinator` (lines ~91-208): change the `Finished` arm to push the received `(worker_id, stats.algorithm, stats)` directly; track the winning worker_id when an `Improvement` wins so `best_result.statistics` can be filled with that worker's final stats; rewrite the aggregate `total_stats` to sum/min relevant fields instead of synthesising. Update the `Improvement` arm so `best_result` is populated *only* with sequence + worker_id + cost — defer assigning `statistics` until all workers have reported.

Tests:
- `src/search/parallel/coordinator.rs` `#[cfg(test)] mod tests` — add the new hybrid regression test the issue asks for (see slice 1) and update the existing tests that assert the dropped-Finished invariant.
- `src/search/parallel/channel.rs` `#[cfg(test)] mod tests` — `test_create_channels` constructs a `WorkerMessage::Finished` literally and pattern-matches on its fields; update both the construction and the destructure to the new shape.

No `docs/spec/*.md` updates required — `docs/spec/` is not a thing in this repo (the s11 architecture lives in `CLAUDE.md` and `docs/` is benchmark/ADR-style content). The `ParallelResult` doc comment is the API contract; update it inline.

## 3. TDD slices

### Slice 1 — Red: hybrid statistics regression test

Add to `src/search/parallel/coordinator.rs::tests`:

```rust
#[test]
fn test_parallel_search_symbolic_worker_statistics_are_propagated() { … }
```

Behavior under test:
- Run `run_parallel_search` with `include_symbolic = true`, `num_workers = 2`, on `mov_add_sequence()` with `LiveOut::from_registers(vec![Register::X0])`, registers `[X0, X1, X2]`, immediates `[-1, 0, 1, 2]`, symbolic config with a 10s solver timeout, stochastic iterations small enough to finish promptly, overall timeout ≥ 30s. (Mirror `test_symbolic_finds_mov_add_fusion` in src/search/symbolic/synthesis.rs:419 for hyperparameters known to land the optimization.)
- Assert: exactly one entry in `result.worker_statistics` has `algorithm == Algorithm::Symbolic` and `worker_id == 0`; remaining entries have `algorithm == Algorithm::Stochastic`.
- Assert: `result.total_statistics.smt_queries > 0` (proves symbolic stats are aggregated, not dropped).
- Assert: `result.total_statistics.improvements_found > 0` (symbolic worker increments this when it finds the mov→add fusion — see src/search/symbolic/synthesis.rs:137,169,231).
- Assert: `result.total_statistics.original_cost > 0` and `result.total_statistics.best_cost_found > 0` (proves cost fields are propagated).
- Assert: `result.best_result.found_optimization == true` and `result.best_result.statistics.algorithm == Algorithm::Symbolic` (proves `best_result.statistics` is the winner's stats, not a stochastic placeholder).

This will fail today because of the four bugs the issue calls out. It will pass after slices 2–6.

### Slice 2 — Green: extend `WorkerMessage::Finished` payload

Edit `src/search/parallel/channel.rs:29-33`:

```rust
Finished {
    worker_id: usize,
    algorithm: Algorithm,
    statistics: SearchStatistics,
},
```

(Drop the standalone `candidates_evaluated` field — `statistics.candidates_evaluated` carries the same value.)

Add the `use crate::search::result::SearchStatistics;` import at the top of the file. Update the existing `test_create_channels` test (src/search/parallel/channel.rs:198-214) to construct the new shape:

```rust
let mut stats = SearchStatistics::new(Algorithm::Stochastic);
stats.candidates_evaluated = 100;
let msg = WorkerMessage::Finished {
    worker_id: 0,
    algorithm: Algorithm::Stochastic,
    statistics: stats,
};
```

…and destructure into `{ worker_id, algorithm, statistics }` in the assertion arm. Verify `worker_id == 0`, `algorithm == Algorithm::Stochastic`, `statistics.candidates_evaluated == 100`.

At this point the project no longer compiles because the worker send sites are still using the old shape. Slice 3 fixes that.

### Slice 3 — Green: worker send sites ship full stats

In `src/search/parallel/coordinator.rs::run_symbolic_worker` and `::run_stochastic_worker`, replace:

```rust
let _ = channels.to_coordinator.send(WorkerMessage::Finished {
    worker_id,
    candidates_evaluated,
});
```

with (per algorithm):

```rust
let _ = channels.to_coordinator.send(WorkerMessage::Finished {
    worker_id,
    algorithm: Algorithm::Symbolic, // or Algorithm::Stochastic
    statistics: result.statistics.clone(),
});
```

Note: `result.statistics.algorithm` is already set correctly by the search drivers (src/search/stochastic/mcmc.rs:81 and src/search/symbolic/synthesis.rs:35 both call `SearchStatistics::new(Algorithm::…)`). The explicit `algorithm:` on the message is for the coordinator's bookkeeping and to make the worker label invariant the test asserts; both fields agree by construction.

The unused `candidates_evaluated` locals can be dropped (they are now only read in the `Improvement` send sites and may not even be needed there). Inspect: in the stochastic worker, `candidates_evaluated` is computed but only used in `Finished`; safe to remove. In the symbolic worker, same. Confirm during the edit.

### Slice 4 — Green: rewrite the coordinator `Finished` arm and track the winning worker

In `run_coordinator`:

```rust
let mut winning_worker_id: Option<usize> = None;
```

In the `Improvement` arm (after `if channels.shared.try_update(cost)` succeeds), remember the winner:

```rust
winning_worker_id = Some(worker_id);
let result = SearchResult {
    found_optimization: true,
    original_sequence: target.to_vec(),
    optimized_sequence: Some(sequence),
    statistics: SearchStatistics::new(algorithm), // placeholder; filled in post-loop
};
best_result = Some(result);
```

(Keep the placeholder for now — the final value is set after the loop, slice 6.)

Rewrite the `Finished` arm to:

```rust
WorkerMessage::Finished {
    worker_id,
    algorithm,
    statistics,
} => {
    finished_count += 1;
    let mut stats = statistics;
    stats.elapsed_time = start_time.elapsed(); // wall-clock for this run, not the per-worker subtime
    worker_stats.push((worker_id, algorithm, stats));
    if finished_count >= total_workers {
        break;
    }
}
```

Decision: we overwrite `stats.elapsed_time` with the coordinator's wall-clock-to-this-point. Rationale: per-worker `elapsed_time` from the search driver is the worker's *own* search wall-clock, which is consistent with what callers expect when comparing workers (they all started at `start_time`). Document this in the `ParallelResult` doc comment. (Alternative: keep the per-worker driver-reported value. We pick coordinator-clock to match today's behavior at src/search/parallel/coordinator.rs:157, minimising behavioral surprise for the existing dropped-Finished test.)

### Slice 5 — Green: field-by-field aggregate

Replace the post-loop block (src/search/parallel/coordinator.rs:186-194):

```rust
let elapsed = start_time.elapsed();
let mut total_stats = SearchStatistics::new(Algorithm::Hybrid);
total_stats.elapsed_time = elapsed;
for (_, _, s) in &worker_stats {
    total_stats.candidates_evaluated += s.candidates_evaluated;
    total_stats.candidates_passed_fast += s.candidates_passed_fast;
    total_stats.smt_queries += s.smt_queries;
    total_stats.smt_elapsed += s.smt_elapsed;
    total_stats.smt_equivalent += s.smt_equivalent;
    total_stats.iterations += s.iterations;
    total_stats.accepted_proposals += s.accepted_proposals;
    total_stats.improvements_found += s.improvements_found;
}
// original_cost: workers see the same target, so any nonzero value works.
// Take max to be defensive against zero-init workers (e.g. a worker that
// failed before `search()` set the field).
total_stats.original_cost = worker_stats
    .iter()
    .map(|(_, _, s)| s.original_cost)
    .max()
    .unwrap_or(0);
// best_cost_found: minimum nonzero across workers, falling back to original_cost.
total_stats.best_cost_found = worker_stats
    .iter()
    .map(|(_, _, s)| s.best_cost_found)
    .filter(|&c| c > 0)
    .min()
    .unwrap_or(total_stats.original_cost);
```

`total_stats.algorithm` stays `Algorithm::Hybrid`.

### Slice 6 — Green: best_result.statistics = winning worker's stats (or aggregate)

After building `total_stats`, finalise `best_result.statistics`:

```rust
if let Some(ref mut br) = best_result {
    if let Some(winner) = winning_worker_id
        && let Some((_, _, ref winner_stats)) =
            worker_stats.iter().find(|(id, _, _)| *id == winner)
    {
        br.statistics = winner_stats.clone();
    } else {
        // Workers finished after their Improvement message but their Finished
        // never arrived (shouldn't happen given the loop exits on
        // finished_count >= total_workers). Fall back to the aggregate so the
        // CLI doesn't show zeroes.
        br.statistics = total_stats.clone();
    }
}

let final_result = best_result.unwrap_or_else(|| SearchResult {
    found_optimization: false,
    original_sequence: target.to_vec(),
    optimized_sequence: None,
    statistics: total_stats.clone(),
});
```

Update the doc comment on `ParallelResult` (src/search/parallel/coordinator.rs:21-29):

```rust
/// Result from parallel search execution.
///
/// `best_result.statistics` is the *winning worker's* statistics when an
/// optimization was found, and the cross-worker aggregate when none was.
/// `total_statistics` is always the cross-worker aggregate (algorithm is
/// `Algorithm::Hybrid`; `elapsed_time` is coordinator wall-clock; counter
/// fields are sums; `original_cost` is max across workers; `best_cost_found`
/// is min nonzero across workers, falling back to `original_cost`).
/// `worker_statistics` carries the per-worker, per-algorithm breakdown.
```

### Slice 7 — Refactor: clean up existing tests

- `test_create_channels` (src/search/parallel/channel.rs): updated in slice 2.
- `test_parallel_search_no_dropped_finished_messages` (src/search/parallel/coordinator.rs:388-431): the assertion `total_statistics.candidates_evaluated > 0` continues to hold under the new aggregator. No edits expected unless cargo flags a compile error. Verify.
- `test_parallel_search_single_worker` and `test_parallel_search_multiple_workers`: no statistical assertions broken; they should keep passing.

### Slice 8 — `cargo fmt` and `./ci_check.sh`

Run `cargo fmt --all`. Then `./ci_check.sh` (which the project's CLAUDE.md mandates pre-push). Address any clippy hits in the touched code only — do not bundle unrelated clippy fixes.

## 4. Verification surface

- **No ESBMC/contract verification**: this is a Rust-only API-contract bug. No `tests/run/` or `examples/` fixtures grow.
- **Unit + integration**: `cargo test --workspace`. The slice-1 regression test exercises the new aggregation against a real hybrid run. The existing `test_parallel_search_no_dropped_finished_messages` continues to gate that every worker reports.
- **Manual smoke (optional)**: `cargo run --release -- opt …` on an AArch64 ELF with `--algorithm hybrid` and watch `print_search_statistics(&result.total_statistics)` produce nonzero SMT and improvement numbers when the symbolic worker wins. Not required for the PR — the regression test is the authoritative check.

## 5. Risk areas

- **Hybrid CLI output (src/main.rs:746)**: now shows real SMT/improvement metrics. Numbers will be larger than they were yesterday for the same run — that's a fix, not a regression, but it's the most user-visible behavioural change in the PR. Mention in the PR body.
- **`elapsed_time` semantics for per-worker stats**: I'm preserving today's behaviour (coordinator-clock at the moment each `Finished` arrives) rather than the worker's own reported `elapsed_time`. This keeps the existing dropped-Finished test working unchanged. Alternative discussed inline.
- **Compile fan-out**: `WorkerMessage` is part of `crate::search::parallel::channel`. A quick grep for direct constructors outside `coordinator.rs` and `channel.rs` tests showed none. Worth one final pass during implementation:
  ```bash
  rg "WorkerMessage::Finished" src tests
  ```
- **`SearchStatistics` is `Clone` but not cheap**: it's a small struct of primitives + one `Duration` + an `Algorithm` enum — clone cost is negligible. No `Arc` wrapping needed.
- **`Algorithm::Hybrid` as the top-level label**: unchanged; the existing CLI path expects this.
- **Symbolic worker timing race**: with `num_workers == 2` the symbolic worker may not finish before the stochastic one in CI under load. The slice-1 test uses a 30s outer timeout and the same setup `test_symbolic_finds_mov_add_fusion` proved adequate, so this should be stable. If CI flakes, raise the outer timeout to 60s before raising any other flag.
- **No SearchStatistics field additions**: keeping the payload to existing fields means no `BTreeMap`/`HashMap` ordering risk and no codegen-layout concerns. This is purely a Rust runtime change.

## 6. Out of scope

- Adding `winning_worker_id: Option<usize>` to `ParallelResult` as a first-class field. (Would help testability further but expands the public-ish API beyond the minimum fix.)
- Refactoring `WorkerMessage` to be generic over `<I: ISA>` — explicitly deferred to issue #77 stage 1 step 12 per the file-level comment at src/search/parallel/channel.rs:1-9.
- Changing `print_search_statistics` formatting in src/main.rs:838-856.
- Improving the timeout-driven shutdown path so stochastic workers honour `CoordinatorMessage::Stop` mid-search (called out as out-of-scope in src/search/parallel/coordinator.rs:380-387).
- Renaming/restructuring `Algorithm::Hybrid` or introducing a `Algorithm::Parallel`.
- Touching x86 / RISC-V parallel coordination (today AArch64-only).
- Splitting `SearchStatistics` into algorithm-specific subtypes.
- Reworking `SearchResult` vs `SearchResultFor<I>` (issue #77).
- Any `cargo clippy` cleanups outside `src/search/parallel/channel.rs` and `src/search/parallel/coordinator.rs`.
