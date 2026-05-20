# ADR-0002 — LLM-assisted search MVP refuses targets with flags live-out

Status: Accepted
Date: 2026-05-07

## Amendment (2026-05-19)

Superseded in part by [ADR-0006](0006-live-out-cli-grammar.md). The Context
paragraph below originally claimed NZCV was not modeled by the equivalence
pipeline (a "pre-existing soundness gap"). That claim no longer holds:
`LiveOut` carries a `flags_live` bit (`src/semantics/live_out.rs`), and both
the fast-path and SMT equivalence paths consume it
(`src/semantics/equivalence.rs`); `equiv --live-out '...;nzcv'` is the
user-facing knob (ADR-0006). What remains authoritative in this ADR is the
LLM-specific *static refusal* of flag-live-out targets in
`src/search/llm/mod.rs`; that policy is unchanged and is independent of how
the equivalence pipeline handles NZCV.

## Context

At the time this ADR was accepted, `LiveOut` (`src/semantics/live_out.rs`) named the broad live-out contract, but its only populated slice was the register-only `LiveOutRegisters`. It did not encode whether AArch64 condition state (NZCV) was part of the broader live-out contract. The AArch64 subset includes flag writers (`CMP`, `CMN`, `TST`) and flag readers (`CSEL`, `CSINC`, `CSINV`, `CSNEG`); a target whose final instruction is `CMP` (for example) has condition state as a real downstream output even though no register value reflects it. (See the Amendment above for the present state of this part of the contract.)

`EquivalenceConfig` and all four search algorithms threaded `LiveOut` through, but equivalence at that time checked only its `LiveOutRegisters` slice; none of them checked NZCV equivalence. That was a pre-existing soundness gap with respect to condition-state live-out, but only mattered for the LLM flow because the LLM is the only generator that might *legitimately* drop a final flag-setting instruction (the others enumerate from a pool that includes it).

Two options:

1. **Restrict the MVP corpus**: refuse LLM-flow execution on targets where flags are live-out (statically detectable: any flag writer with no later flag-using or flag-overwriting instruction before the end). Sound. Narrower applicable input class than other search algorithms.
2. **Extend live-out contract to include condition state**: add an architecture-aware condition-state slice beside `LiveOutRegisters`, update the concrete/SMT equivalence internals, and constrain NZCV for AArch64. Wider impact, deserves its own ADR, slows down the MVP.

## Decision

Option 1. The LLM flow refuses to run on targets where static analysis says flags are live-out, with a clear diagnostic message.

## Consequences

**Positive:**
- The MVP's verifier (`check_equivalence_with_config`) is **sound** for the corpus the LLM flow accepts. No risk of declaring a candidate equivalent when it has dropped a needed flag-setter.
- The refusal behavior remains local to `src/search/llm/` plus a static-analysis helper. The broader `LiveOut` plumbing can exist without modeling condition state yet.

**Negative:**
- The LLM flow has a **narrower applicable input class than the rest of the optimizer**. A user who feeds it a region ending in `CMP` for a downstream branch sees a refusal, not an attempt.
- The static refusal in the LLM flow is conservative: it bails *before* invoking Codex, even on targets whose equivalence the pipeline could now verify under ADR-0006. This is a deliberate cost/safety trade-off, not a soundness workaround.

**Reversibility:** high. If the LLM flow is later judged to be sound on flag-live-out targets, the static refusal in `src/search/llm/mod.rs` (the `if flags_live_out(target)` guard inside `Llm::search`) becomes a one-line deletion and the inputs pass through to Codex like any other target.
