# ADR-0011: Zero solver timeout disables SMT queries

## Status

Accepted for issue #670 on 2026-07-21.

## Context

Z3 interprets a zero timeout parameter as no timeout. s11 also exposes the
per-query timeout as the CLI flag `--solver-timeout SECS` and the programmatic
builder `SearchConfig::with_solver_timeout(Duration)`. Before PR #669, passing
zero through those surfaces had inconsistent results: symbolic and stochastic
search passed zero to Z3 and therefore allowed an unbounded query, while
enumerative and LLM search skipped the query because they required at least one
millisecond of usable budget.

PR #669 routed the SMT-driven search paths through budget guards so a solver
query cannot overrun the overall `--timeout`. That made zero uniformly skip SMT
queries, but left the behavior undocumented. It also left the LLM path with a
separate millisecond gate, creating a place where the policy could drift again.

The ambiguity matters because `--solver-timeout 0` is accepted by clap, and a
raw zero reaching Z3 changes a bounded search into a potentially unbounded one.
Conversely, skipping SMT does not create a fast-only optimizer: s11 accepts a
candidate only after a formal equivalence proof.

## Decision

A configured solver timeout of zero means **disable SMT queries**. It never
means an unbounded Z3 query.

This applies to both public configuration surfaces:

- `s11 opt ... --solver-timeout 0` remains valid and selects the disable
  sentinel.
- `SearchConfig::with_solver_timeout(Duration::ZERO)` selects the same
  sentinel, whether or not an overall search timeout is configured.

`SearchConfig::solver_timeout_within_budget` is the canonical policy seam. It
returns `None` when the configured solver timeout is zero, when the overall
search budget is exhausted, or when the usable timeout is positive but below
Z3's whole-millisecond granularity. No backend may pass those values to Z3.
The LLM path, which computes its remaining budget around an external Codex
call, delegates its equivalent remaining-budget calculation to the same seam.

`solver_timeout: None` has a distinct existing meaning: use the shared
five-second fallback. It does not disable SMT.

The query-level contract is uniform across the four SMT-driven search paths:

- enumerative search stops before verifying the candidate;
- stochastic search stops when a cheaper proposal would require proof;
- symbolic search treats the candidate as unproven;
- LLM search does not run its candidate verifier.

In every case the candidate is not accepted, no SMT query is counted, and no
zero timeout reaches Z3. Hybrid search inherits the symbolic and stochastic
behavior of its workers. Because all accepted optimizations require an SMT
proof, a zero solver timeout means that the search cannot report an
optimization.

## Alternatives considered

### Reject zero at the CLI

A positive-only clap parser would remove the ambiguous CLI input, but it would
not define the behavior of the public programmatic builder. Rejecting or
panicking in the builder would also be a breaking API change. This option was
rejected because zero already has one safe, consistent meaning across both
surfaces.

### Preserve Z3's zero-means-unbounded behavior

Passing zero through would allow a single solver query to exceed the overall
search deadline, reversing the budget guarantee established by PR #669. A
special case that clamps zero only when an overall timeout exists would make
the same input mean two different things depending on another option. This was
rejected.

### Add an explicit unbounded-solver flag

A separate flag or typed configuration variant could represent an unbounded
solver request without overloading `Duration::ZERO`. It would still need to be
clamped whenever an overall search timeout is present. There is no current use
case that justifies the extra CLI and API surface, so this remains an additive
future option rather than part of this decision.

## Consequences

The CLI, builder, and all SMT-driven backends now have one documented zero
policy, and future call sites can use the shared budget seam without knowing
Z3's sentinel semantics. Existing positive timeouts and the unset five-second
fallback are unchanged.

Users who previously relied on symbolic or stochastic search passing zero to
Z3 must choose a sufficiently large positive timeout instead. This qualifies
PR #669's original “no public CLI behavior changes” statement for the reachable
zero-timeout edge case.

**Reversibility:** high. A future explicit unbounded option can be added without
changing the meaning of zero. Reinterpreting zero itself would be a breaking
semantic change and would require revisiting this ADR.
