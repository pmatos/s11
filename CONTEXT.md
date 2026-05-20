# s11 — Domain Context

A glossary of domain terms used in this superoptimizer. Update inline as terms get sharpened.

See [docs/capability.md](docs/capability.md) for the canonical instruction and
ISA support matrix.

## Glossary

### Target
The original instruction sequence we are trying to optimize. In the AArch64 path this is a `Vec<Instruction>` from the s11 IR, drawn from the supported AArch64 subset in [docs/capability.md](docs/capability.md). "The target" is fixed input; "candidates" are what search algorithms produce as potential replacements.

### Candidate
A `Vec<Instruction>` produced by a search algorithm as a potential replacement for the target. A candidate is not yet accepted as an optimization — it must be (a) cheaper than the target by some metric and (b) semantically equivalent on live-out state.

### Optimization (the noun)
A candidate that is both **strictly cheaper** than the target and **proven equivalent** on the live-out contract. The metric of "cheaper" is search-config dependent (cost model in `src/semantics/cost.rs`, or byte count for the LLM-assisted flow).

### Live-out
The observable architectural state whose values must agree between target and candidate after execution. Today this is represented by `LiveOut` in `src/semantics/live_out.rs`; it populates two slices — a register set (`RegisterSet<R>` per ADR-0004 §5) and the AArch64 NZCV `flags_live` bit (ADR-0006). The intended concept is still broader: memory and PC can also be live-out when downstream code observes them, and they remain unmodeled.

### Live-out registers
The register slice of the live-out contract. Represented by `LiveOutRegisters`, a set of architectural registers whose values must agree between target and candidate after execution. This is not the whole live-out concept.

### Observable state
Any architectural state a downstream context can observe after the target executes. Registers and AArch64 condition state (NZCV) are modeled today (the latter via `LiveOut.flags_live`, ADR-0006). Memory and PC are intentionally reserved in the term so the live-out contract can grow without being renamed.

### Condition state
Architecture-specific predicate or flag state that later instructions can read. On AArch64 this is NZCV. On a RISC-V integer subset there may be no condition state. Future architectures can map this term to their own flag or predicate state without changing the shared live-out vocabulary.

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
- Verification reuses `EquivalenceConfig` with the caller's `LiveOut` contract: 10 random tests (fast path), then Z3 with 30s timeout.

**Deliverable:** local-only. A bash/`just` target that runs the search across a fixed corpus of 5–10 small asm targets known to be optimizable (drawn from existing equivalence tests). No CI, no mocked Codex backend, no `CandidateGenerator` trait abstraction.

### Flags-live-out (LLM-flow exclusion)
AArch64 condition state (NZCV) is part of the equivalence contract via `LiveOut.flags_live` (set from the `;nzcv` suffix to `equiv --live-out` per ADR-0006). The fast and SMT equivalence paths both consume the bit. *Separately*, the LLM-assisted search flow statically refuses targets whose final state includes flag liveness (any flag-writing instruction in the sequence — see `flags_live_out` in `src/validation/live_out.rs`) and bails before invoking Codex. This is a conservative policy choice, not a soundness workaround, and is the only remaining surface on which ADR-0002 is authoritative. See ADR-0002 (as amended) and ADR-0006.

### Subset hint (intentionally absent)
The LLM prompt does **not** enumerate the maintained AArch64 subset s11's parser accepts (see [docs/capability.md](docs/capability.md)). The model is invited to use any AArch64 mnemonic it knows. Outputs that use unsupported instructions are recorded as a research signal (which mnemonics the model "wanted" to reach for), not treated as wasted calls. See ADR-0003.

### Unsupported-mnemonic ledger
A first-class output of an LLM-assisted search run, alongside the (optional) optimization. A multiset of mnemonics the model emitted that `parse_assembly_string` rejected — interpretable as "which instructions should s11 add support for next, sorted by frequency of LLM demand on real targets." Surfaced in the `SearchStatistics` (or a sibling `LlmStatistics`) returned from `SearchAlgorithm::search`.
