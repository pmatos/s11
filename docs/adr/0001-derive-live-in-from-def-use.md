# ADR-0001 — Derive live-in from intra-sequence def-use rather than threading through the search trait

Status: Accepted
Date: 2026-05-07

## Context

The LLM-assisted search algorithm (`LlmSearch`, see `src/search/llm/`) needs to tell the model which registers (and flags) the target reads before writing — i.e., the target's live-in set. The existing `SearchAlgorithm::search` trait at `src/search/mod.rs:39` exposes only `live_out` and the target itself. No live-in is plumbed through.

Three options were considered:

1. **Extend the trait** with a `live_in: &LiveInMask` argument. Forces every existing impl (enumerative, stochastic, symbolic) to accept and ignore a parameter only one consumer uses.
2. **Derive live-in from the target via def-use analysis** inside `LlmSearch`, reusing the `target` argument the trait already provides. Add a `compute_live_in_registers(&[Instruction])` helper alongside the existing `compute_written_registers` in `src/validation/live_out.rs`.
3. **Configure live-in on the `LlmSearch` struct** via a builder method, requiring the caller to compute and pass live-in explicitly.

## Decision

Option 2: derive live-in from the target via intra-sequence def-use analysis.

A new helper `compute_live_in_registers(&[Instruction]) -> LiveOutMask` is added in `src/validation/live_out.rs` (the type is reused — it's structurally a set-of-registers, despite the name). Flag-livein is tracked by a separate boolean predicate `reads_flags_before_writing(&[Instruction]) -> bool` because flags don't fit `LiveOutMask`'s bitset.

## Consequences

**Positive:**
- The `SearchAlgorithm` trait stays unchanged; existing impls untouched.
- The derived live-in is **the semantically correct one** for an isolated sequence — a register the target reads before defining is, definitionally, live-in. Over-approximation ("all registers are live-in") would tell the LLM nothing; under-approximation (caller-supplied) risks the LLM thinking it can clobber a value the target reads.
- The helper has wider value: symbolic synthesis can constrain free variables tighter, stochastic search can pick scratch registers from the non-live-in set.

**Negative / scope:**
- This is **intra-sequence only**. It tells us what the sequence *itself* reads, not what the caller's downstream code expects to be untouched. For the MVP — single `s11 opt` regions of short asm — that's exactly right. For whole-function optimization with values that live across the region, this approach would need to be revisited (and at that point the trait extension becomes the right answer because the information has nowhere to come from but the caller).

**Reversibility:** moderate. If we later need caller-supplied live-in, we'd add an optional builder method on `LlmSearch` and prefer it over the derived value when present. The helper itself stays useful as a default. We are not painting ourselves into a corner.
