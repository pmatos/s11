# ADR-0006 — `--live-out` CLI grammar extends with `;nzcv` flag-liveness suffix

Status: Accepted
Date: 2026-05-18

## Context

Before this ADR, the `--live-out` CLI argument on the `equiv` and `llm-opt` subcommands accepted only a comma-separated register list (e.g. `x0,x1,sp`). NZCV flag-liveness was already a first-class property of the AArch64 equivalence pipeline — `EquivalenceConfig.flags_live` plus `EquivalenceConfig::with_flags(bool)` exist on `src/semantics/equivalence.rs:106,171`, and both the fast-path concrete comparison and the SMT path consume the bit. The search algorithms (enumerative, stochastic, symbolic, LLM) all internally pin `flags_live=true` when verifying candidates (e.g. `src/search/enumerative/search.rs:89`, `src/search/stochastic/mcmc.rs:211`, `src/search/symbolic/synthesis.rs:241`, `src/search/llm/outcome.rs:67`). What was missing was a way for the `equiv` user to opt in.

PR #78 deferred this as issue #81 with the note that once the live-out contract grew beyond registers, the CLI parser would need broadening. The deferral was contingent on a syntax decision and on the absence of a flag bit on the contract object; that absence is no longer load-bearing because the bit lives on `EquivalenceConfig`, not on `LiveOut`.

ADR-0004 §5 commits to eventually replacing `LiveOut` and `X86LiveOutMask` with the generic `LiveOutMask<R>` (already scaffolded at `src/semantics/live_out.rs:25-87` with its own `flags_live`/`set_flags_live` API). When that migration lands, the CLI parser introduced here will simply produce a `LiveOutMask<Register>` directly; the grammar does not need to change.

## Decision

1. Add a free function `validation::live_out::parse_live_out_contract(s: &str) -> Result<(LiveOut, bool), ParseLiveOutRegistersError>` implementing the grammar `<regs>` or `<regs>;<flags>`:
   - Register half follows the existing `LiveOutRegisters::from_str` rules (comma- or space-separated, case-insensitive, accepts `x0..x30`, `sp`, `xzr`).
   - Flag half accepts only the group token `nzcv` (case-insensitive). The per-flag tokens `n`, `z`, `c`, `v` are **explicitly reserved** so a future per-flag liveness rev can add them without a second grammar break. They are rejected today with a "reserved" diagnostic.
   - Bareword `nzcv` (no leading `;`) is rejected so the bareword reservation is unambiguous.
   - At most one `;` is permitted.

2. Route both `run_equiv` (`src/main.rs`) and `run_llm_opt` through `parse_live_out_contract`, using a uniform `"invalid live-out: ..."` error prefix.

3. In `run_equiv`, plug the returned `flags_live` bit into `EquivalenceConfig::with_flags(flags_live)`. The verbose printout gains `Live-out flags: nzcv` when the bit is set.

4. In `run_llm_opt`, accept the same grammar but discard the bit. The LLM verification path pins `flags_live=true` internally at `src/search/llm/outcome.rs:67`, so the CLI bit is informational only on that subcommand. Keeping the parser consistent across both subcommands avoids a CLI-vocabulary fork.

5. Do **not** add a `flags_live` field to `LiveOut` or a `with_flags` builder. The bit lives on `EquivalenceConfig` today and on `LiveOutMask<R>` in the future (ADR-0004 §5); adding a third home would create exactly the kind of state-duplication the ISA-trait-collapse ADR cautions against.

6. Do **not** drop `impl FromStr for LiveOutRegisters`. Existing callers (and the existing `from_str` test suite) keep working.

## Consequences

**Positive:**
- The `equiv` subcommand can finally express "match registers and NZCV after execution" — a real user-facing capability gap closed without semantic churn.
- The CLI grammar reserves the per-flag tokens up front, so a per-flag rev (when one is needed) lands without breaking in-flight scripts.
- The two divergent CLI parse paths (`run_llm_opt` via `LiveOutRegisters::from_str`, `run_equiv` via hand-rolled `parser::parse_register` splitting) now share a single helper. Error messages match.

**Negative / scope:**
- `run_llm_opt --live-out "x0;nzcv"` and `run_llm_opt --live-out "x0"` are observationally identical on the LLM path today because `outcome.rs:67` pins `flags_live=true`. Users may be surprised that the suffix is "accepted but ignored" on this subcommand. Documented in the help text and in the `run_llm_opt` source comment.
- `opt` (ELF optimization) does not accept `--live-out` and is unchanged. The search algorithms it dispatches still pin `flags_live=true` internally, so the conservative semantics there are preserved.
- The bit lives on `EquivalenceConfig` and (in scaffolding) on `LiveOutMask<R>`. When the mask migration of ADR-0004 §5 lands, this ADR's CLI grammar should remain stable but the parser will return `(LiveOutMask<Register>, ())` — a single-return shape — and the explicit `bool` plumbing in `run_equiv` will collapse.

**Reversibility:** high for the per-flag rev — the `n`/`z`/`c`/`v` tokens are rejected with a "reserved" message today, so adding their semantics later is a strict superset of the current grammar. Reversibility low for the parser function itself: it becomes load-bearing for both CLI subcommands.
