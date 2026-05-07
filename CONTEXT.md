# s11 — Domain Context

A glossary of domain terms used in this superoptimizer. Update inline as terms get sharpened.

## Glossary

### Target
The original instruction sequence we are trying to optimize. Always a `Vec<Instruction>` from the s11 IR, drawn from the 20-opcode AArch64 subset. "The target" is fixed input; "candidates" are what search algorithms produce as potential replacements.

### Candidate
A `Vec<Instruction>` produced by a search algorithm as a potential replacement for the target. A candidate is not yet accepted as an optimization — it must be (a) cheaper than the target by some metric and (b) semantically equivalent on live-out state.

### Optimization (the noun)
A candidate that is both **strictly cheaper** than the target and **proven equivalent** on the live-out contract. The metric of "cheaper" is search-config dependent (cost model in `src/semantics/cost.rs`, or byte count for the LLM-assisted flow).

### Live-out
The set of architectural registers (and, implicitly, flags read by the target's downstream context) whose values must agree between target and candidate after execution. Carried as `LiveOutMask` in `src/semantics/state.rs`. Fed into `EquivalenceConfig` and `SearchAlgorithm::search`.

### Live-in
The set of architectural registers whose initial values the target reads. Currently *not* surfaced in `SearchAlgorithm::search`. The LLM-assisted flow needs this in the prompt; computed by def-use analysis on the target rather than added to the trait (see ADR-0001).

### Equivalence (fast vs SMT)
Two notions, layered:
- **Fast equivalence**: target and candidate produce the same live-out state for a fixed corpus of random + edge-case inputs (`src/validation/random.rs`). Cheap, refutation-only.
- **SMT equivalence**: Z3 proves the live-out state is bit-identical for *all* inputs (`src/semantics/equivalence.rs`). Expensive, gives a proof.
A candidate is "an optimization" only after passing both, in that order.

### LLM-assisted search (Codex Spark flow)
A `SearchAlgorithm` impl that delegates candidate generation to the OpenAI Codex CLI running model `gpt-5.3-codex-spark`. The LLM is the candidate generator; the existing fast-then-SMT equivalence pipeline is the verifier. The metric is **instruction count** (equivalently, byte count, since AArch64 is fixed-width 4-byte) — not the cost model. Chosen for the MVP because "smaller program" is the LLM's most natural objective and the most legible success criterion to a human reader.

**Operational shape (MVP):**
- One `codex exec` invocation per loop iteration. `-m gpt-5.3-codex-spark`, `--output-schema <single-string-asm.json>`, `-o <answer.json>`, `-s read-only`, `--ephemeral`, `--skip-git-repo-check`. Subscription auth is implicit (already done via `codex login`).
- Each call is **fresh** — no feedback from prior iterations. Diversity comes from default temperature.
- Calls are **sequential** within one search.
- Loop terminates when **either** an optimization is found, **or** `max_codex_calls` is reached, **or** `SearchConfig.timeout` elapses.
- Per-iteration outcomes: parse-fail → log unsupported mnemonics, continue. Equivalence-fail → log, continue. Not-shorter → log, continue. Equivalent and shorter → **success**, return.
- Verification reuses `EquivalenceConfig::default().with_live_out(live_out)`: 10 random tests (fast path), then Z3 with 30s timeout.

**Deliverable:** local-only. A bash/`just` target that runs the search across a fixed corpus of 5–10 small asm targets known to be optimizable (drawn from existing equivalence tests). No CI, no mocked Codex backend, no `CandidateGenerator` trait abstraction.

### Flags-live-out (MVP exclusion)
For the LLM-assisted search MVP only, targets whose final architectural state includes a meaningful NZCV value (i.e., flags are live-out) are **refused** rather than processed. `LiveOutMask` does not currently encode flags, and adding flags to the live-out contract would require co-ordinated changes to `EquivalenceConfig` and all four search algorithms — out of scope for the MVP. The LLM flow detects flags-live-out by static inspection of the target and bails with an explicit message. See ADR-0002.

### Subset hint (intentionally absent)
The LLM prompt does **not** enumerate the 20-opcode subset s11's parser accepts. The model is invited to use any AArch64 mnemonic it knows. Outputs that use unsupported instructions are recorded as a research signal (which mnemonics the model "wanted" to reach for), not treated as wasted calls. See ADR-0003.

### Unsupported-mnemonic ledger
A first-class output of an LLM-assisted search run, alongside the (optional) optimization. A multiset of mnemonics the model emitted that `parse_assembly_string` rejected — interpretable as "which instructions should s11 add support for next, sorted by frequency of LLM demand on real targets." Surfaced in the `SearchStatistics` (or a sibling `LlmStatistics`) returned from `SearchAlgorithm::search`.
