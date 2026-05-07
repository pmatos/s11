# ADR-0002 — LLM-assisted search MVP refuses targets with flags live-out

Status: Accepted
Date: 2026-05-07

## Context

`LiveOutMask` (`src/semantics/state.rs`) is a register-only bitset. It does not encode whether NZCV is part of the live-out contract. The 20-opcode subset includes flag writers (`CMP`, `CMN`, `TST`) and flag readers (`CSEL`, `CSINC`, `CSINV`, `CSNEG`); a target whose final instruction is `CMP` (for example) has flags as a real downstream output even though no register value reflects it.

`EquivalenceConfig` and all four search algorithms thread `LiveOutMask` through; none of them check NZCV equivalence. This is a pre-existing soundness gap with respect to flags-live-out, but only matters for the LLM flow because the LLM is the only generator that might *legitimately* drop a final flag-setting instruction (the others enumerate from a pool that includes it).

Two options:

1. **Restrict the MVP corpus**: refuse LLM-flow execution on targets where flags are live-out (statically detectable: any flag writer with no later flag-using or flag-overwriting instruction before the end). Sound. Narrower applicable input class than other search algorithms.
2. **Extend live-out contract to include flags**: thread a `flags_live_out: bool` through `LiveOutMask` and `EquivalenceConfig`, update all four algorithms, update the SMT encoding to constrain NZCV. Wider impact, deserves its own ADR, slows down the MVP.

## Decision

Option 1. The LLM flow refuses to run on targets where static analysis says flags are live-out, with a clear diagnostic message.

## Consequences

**Positive:**
- The MVP's verifier (`check_equivalence_with_config`) is **sound** for the corpus the LLM flow accepts. No risk of declaring a candidate equivalent when it has dropped a needed flag-setter.
- The change scope is local to `src/search/llm/` plus a static-analysis helper. No edits to existing search algorithms, the SMT module, or `LiveOutMask`.

**Negative:**
- The LLM flow has a **narrower applicable input class than the rest of the optimizer**. A user who feeds it a region ending in `CMP` for a downstream branch sees a refusal, not an attempt.
- We are explicitly accepting a known pre-existing soundness gap (flags-live-out is unmodelled by `EquivalenceConfig` for *all* algorithms) rather than fixing it. Fix is deferred.

**Reversibility:** high. When flags-live-out becomes a supported part of the live-out contract (its own ADR), the static refusal in the LLM flow is replaced by passing the flag-live-out bit through to the prompt and the equivalence check.
