# ADR-0011: Fixed-width packed state for the first NEON slice

## Status

Accepted.

## Context

The AArch64 IR previously represented only general-purpose registers. Adding
Advanced SIMD support requires register aliases, lane arrangements, mixed
SIMD/GPR instructions, concrete and symbolic state, and liveness contracts.
The broader issue also anticipates SVE, SVE2, and other vector ISAs, but those
architectures add scalable lengths and predicate state that do not fit NEON's
fixed 128-bit register file.

## Decision

The first vertical slice uses a NEON-specific `VectorRegister` type for
`V0..V31`. `Register::Vector` embeds that class in the existing generic
`RegisterSet<Register>` carrier, so vector live-in/live-out contracts use the
same data flow as scalar contracts without pretending vector values are 64-bit
GPRs.

Each architectural V register is one packed 128-bit value. `.2d` and `.4s` are
instruction metadata and alias the same bits; they are not distinct register
identities. Concrete execution uses `u128`. SMT execution uses 128-bit bit
vectors, with lane extraction, independent wrapping arithmetic per lane, and
concatenation back into packed state. Mixed `mov Xd, Vn.d[i]` semantics extract
the selected 64-bit slice into the GPR file.

The initial instruction set is intentionally narrow:

- `movi Vd.2d|4s, #0`;
- `add Vd.2d|4s, Vn.2d|4s, Vm.2d|4s`;
- `mov Xd, Vn.d[0|1]`.

Only immediate zero is accepted for `movi`; AArch64's broader modified-
immediate grammar is deferred. Candidate generation keeps scalar and vector
register pools separate so a V register cannot leak into an X-register slot.

## Consequences

The equivalence checker can now prove windows that mix scalar and vector state,
and `--live-out vN` observes all 128 bits. Arrangement changes preserve normal
architectural aliasing automatically. The representation is deliberately not
a generic scalable-vector abstraction; SVE/SVE2 and RVV will need a design that
includes vector length and predicate/mask state.

Vector loads, reductions, pairwise operations, shuffles, additional
arrangements, scalar `q`/`d`/`s` views, and non-zero modified immediates remain
follow-up slices.
