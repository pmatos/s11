# ADR-0006 — `--live-out` CLI grammar extends with `;nzcv` flag-liveness suffix

Status: Accepted
Date: 2026-05-18

## Context

Before this ADR, the `--live-out` CLI argument on the `equiv` and `llm-opt` subcommands accepted only a comma-separated register list (e.g. `x0,x1,sp`). NZCV flag-liveness was already a first-class property of the AArch64 equivalence pipeline — `EquivalenceConfig.flags_live` plus `EquivalenceConfig::with_flags(bool)` exist on `src/semantics/equivalence.rs:106,171`, and both the fast-path concrete comparison and the SMT path consume the bit. The search algorithms (enumerative, stochastic, symbolic, LLM) all internally pin `flags_live=true` when verifying candidates (e.g. `src/search/enumerative/search.rs:89`, `src/search/stochastic/mcmc.rs:211`, `src/search/symbolic/synthesis.rs:241`, `src/search/llm/outcome.rs:67`). What was missing was a way for the `equiv` user to opt in.

PR #78 deferred this as issue #81 with the note that once the live-out contract grew beyond registers, the CLI parser would need broadening. The deferral was contingent on a syntax decision and on the absence of a flag bit on the contract object; that absence is no longer load-bearing because the bit lives on `EquivalenceConfig`, not on `LiveOut`.

ADR-0004 §5 commits to replacing `LiveOut` and `X86LiveOutMask` with the generic `RegisterSet<R>` (`src/semantics/live_out.rs`). That migration has since landed: the CLI parser now produces a `LiveOut` (= `RegisterSet<Register>`) directly with `flags_live` set on the mask, and the `bool` was dropped from `parse_live_out_contract`'s return type. The grammar itself is unchanged.

This ADR also supersedes the equivalence-semantics portion of [ADR-0002](0002-mvp-restricts-flags-live-out.md) (the paragraph that described NZCV as unmodeled by the equivalence pipeline); see the Amendment block on that ADR for the delta. ADR-0002 remains the authority for the LLM-flow refusal of flag-live-out targets.

## Decision

1. Add a free function `validation::live_out::parse_live_out_contract(s: &str) -> Result<LiveOut, ParseLiveOutError>` implementing the grammar `<regs>` or `<regs>;<flags>`:
   - Register half follows the existing `RegisterSet::<Register>::from_str` rules (comma- or space-separated, case-insensitive, accepts `x0..x30`, `sp`, `xzr`).
   - Flag half accepts only the group token `nzcv` (case-insensitive). The per-flag tokens `n`, `z`, `c`, `v` are **explicitly reserved** so a future per-flag liveness rev can add them without a second grammar break. They are rejected today with a "reserved" diagnostic.
   - Bareword `nzcv` (no leading `;`) is rejected so the bareword reservation is unambiguous.
   - At most one `;` is permitted.

2. Route both `run_equiv` (`src/main.rs`) and `run_llm_opt` through `parse_live_out_contract`, using a uniform `"invalid live-out: ..."` error prefix.

3. In `run_equiv`, pass the parsed `LiveOut` (with its `flags_live` bit already set) into the `EquivalenceConfig` builder via `.live_out(...)`. The verbose printout gains `Live-out flags: nzcv` when `live_out.flags_live()` is true.

4. In `run_llm_opt`, accept the same grammar but discard the bit. The LLM verification path pins `flags_live=true` internally at `src/search/llm/outcome.rs:67`, so the CLI bit is informational only on that subcommand. Keeping the parser consistent across both subcommands avoids a CLI-vocabulary fork.

5. `flags_live` lives on `LiveOut` (= `RegisterSet<Register>`) per ADR-0004 §5; `EquivalenceConfig::with_flags` is preserved as a thin builder that writes through to `self.live_out.with_flags(...)` so existing callers keep working.

6. The `FromStr` impl that used to live on `LiveOutRegisters` is now `impl FromStr for RegisterSet<Register>`. Existing callers (and the existing `from_str` test suite) keep working through the `LiveOut` alias.

## Consequences

**Positive:**
- The `equiv` subcommand can finally express "match registers and NZCV after execution" — a real user-facing capability gap closed without semantic churn.
- The CLI grammar reserves the per-flag tokens up front, so a per-flag rev (when one is needed) lands without breaking in-flight scripts.
- The two divergent CLI parse paths (`run_llm_opt` via `RegisterSet::<Register>::from_str`, `run_equiv` via hand-rolled `parser::parse_register` splitting) now share a single helper. Error messages match.

**Negative / scope:**
- `run_llm_opt --live-out "x0;nzcv"` and `run_llm_opt --live-out "x0"` are observationally identical on the LLM path today because `outcome.rs:67` pins `flags_live=true`. Users may be surprised that the suffix is "accepted but ignored" on this subcommand. Documented in the help text and in the `run_llm_opt` source comment.
- `opt` (ELF optimization) does not accept `--live-out` and is unchanged. The search algorithms it dispatches still pin `flags_live=true` internally, so the conservative semantics there are preserved.
- The mask migration of ADR-0004 §5 has landed in lockstep with this ADR's update. The parser now returns a single `LiveOut`, with `flags_live` set on the mask itself; the explicit `bool` plumbing in `run_equiv` has collapsed.

**Reversibility:** high for the per-flag rev — the `n`/`z`/`c`/`v` tokens are rejected with a "reserved" message today, so adding their semantics later is a strict superset of the current grammar. Reversibility low for the parser function itself: it becomes load-bearing for both CLI subcommands.

**Resolution note (issue #80, 2026-05-18; issue #180, 2026-06-16):** `ParseLiveOutError`'s `Display` impl writes only the message body. It is a contract-facing alias over the shared `ParseRegisterSetError` wrapper used by `RegisterSet<Register>::from_str`. The `"invalid live-out: "` prefix from `run_equiv`/`run_llm_opt` (§2) is the sole documented user-visible prefix; pinned by `validation::live_out::tests::display_renders_message_without_type_prefix`.
