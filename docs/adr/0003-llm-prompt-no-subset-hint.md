# ADR-0003 — LLM prompt does not constrain the model to the s11 mnemonic subset; rejected outputs become a research signal

Status: Accepted
Date: 2026-05-07

## Context

`parse_assembly_string` in `src/parser/mod.rs` accepts the maintained AArch64 subset documented in [`docs/capability.md`](../capability.md). The LLM-assisted search algorithm could either:

1. **Tell the model about the subset** (a ~40-token instruction in the system prompt), reducing parse-rejection rate but biasing the model toward its training distribution within that subset.
2. **Say nothing about the subset**, allowing the model to use any AArch64 mnemonic it knows. Many completions will be rejected at the parse stage. The rejected mnemonics are themselves informative: the model is implicitly voting for which instructions s11 should support next.
3. **Tell the model and also log** when it ignores the constraint (impossible to distinguish from confused output).

## Decision

Option 2: do not constrain the model in the prompt. Treat parse-rejection as a first-class output, not lossage.

Concretely:
- The prompt contains the live-in registers, live-out registers, and the target asm. No mnemonic list, no flags discussion, no SMT mention.
- Each Codex call's response is run through `parse_assembly_string`. On parse failure, the offending mnemonics (extracted from the parse error or by simple pre-tokenisation) are recorded in an **unsupported-mnemonic ledger** carried in `SearchStatistics` (or a sibling `LlmStatistics`).
- The loop continues to the next call (subject to the calls + time budget) — parse-rejection is a non-fatal outcome of an iteration, on equal footing with "rejected by fast equivalence" and "not strictly shorter."

## Consequences

**Positive:**
- The MVP gets a free side-output: a frequency-ranked list of "instructions s11 doesn't support that the LLM wants to use." That directly informs the next phase of s11's instruction-set growth, with empirical demand data.
- The prompt stays minimal — no hand-curated subset list to maintain as s11 adds opcodes.
- The model is not biased into a smaller search space; it can suggest any rewrite it knows, and we filter post-hoc.

**Negative:**
- A meaningful fraction of Codex calls per run will return parse-rejected output. With the user's subscription, marginal call cost is ~zero, but wall-clock budget and `max_codex_calls` budget are both consumed by these rejections. The MVP defaults (60s timeout, 20 calls) need to be set with this in mind.
- Two failure modes look superficially similar in logs ("LLM didn't help") — parse-rejection vs equivalence-rejection — and must be reported separately for the ledger to be useful.

**Reversibility:** trivial. If parse-rejection rate proves catastrophic in practice, append the subset list to the system prompt — one-line change, ledger keeps working.
