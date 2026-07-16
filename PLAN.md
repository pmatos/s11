# Issue #632 review-follow-up plan

## 1. Problem restated

PR #674 already implements MOVZX/MOVSX, but its mode-neutral
`X86InstructionGenerator::generate_all` emits every 8/16-bit extension form for
the supplied register pool. The x86-32 enumerative and symbolic backends only
remove R8-R15, so their normal pool still admits unencodable 8-bit sources from
RSP/RBP/RSI/RDI (including the default RSI/RDI); an SMT-equivalent candidate can
therefore survive search and fail later in the 32-bit assembler. Filter each
x86-32 backend's generated pool through the existing `X86_32::can_assemble`
contract while preserving valid full-width instructions and 16-bit extension
sources from those registers.

## 2. Files to touch

- `src/search/enumerative/search.rs` — add an x86-32 candidate-pool regression
  and make `EnumerativeBackend<X86_32>::enumerate_all` retain only instructions
  accepted by `Assembler::can_assemble`.
- `src/search/symbolic/backend.rs` — add the matching symbolic-backend
  regression and apply the same x86-32 encodability filter.
- `PLAN.md` — planning artifact only; no implementation-stage behavior depends
  on it.

There are no `crates/`, `compiler/`, `docs/spec/`, `tests/run/`, or `examples/`
trees in this Rust repository. `docs/capability.md` already documents that only
AL/CL/DL/BL are valid x86-32 8-bit extension sources, so this correction needs
no specification or capability-matrix edit.

## 3. TDD slices

1. **Red: pin the x86-32 enumerative candidate contract.**
   - Test location: the existing `#[cfg(test)]` module in
     `src/search/enumerative/search.rs`, beside
     `x86_32_enumerative_finds_single_instruction_rewrite`.
   - Call
     `<X86_32 as EnumerativeBackend<X86_32>>::enumerate_all` with a pool
     containing RAX, RSI, and RDI.
   - Assert every returned instruction passes `X86_32::can_assemble`; explicitly
     assert that MOVZX/MOVSX with 8-bit RSI/RDI sources are absent while their
     16-bit forms remain present. The current implementation must fail on the
     8-bit assertions.
   - Green production change: import the `Assembler` trait and filter only the
     x86-32 `enumerate_all` result through `X86_32::can_assemble`. Keep register
     ordering and candidate ordering stable by using an order-preserving
     iterator filter.

2. **Red: pin the independent x86-32 symbolic candidate contract.**
   - Test location: the existing `#[cfg(test)]` module in
     `src/search/symbolic/backend.rs`, beside `symbolic_width_is_architectural`.
   - Exercise
     `<X86_32 as SymbolicBackend<X86_32>>::enumerate_all` with the same
     RAX/RSI/RDI pool and the same all-encodable, 8-bit-absent, 16-bit-present
     assertions. This test must fail before the symbolic backend is changed,
     even after slice 1 has fixed the enumerative backend.
   - Green production change: import `Assembler` and apply the same
     order-preserving `X86_32::can_assemble` filter in the symbolic x86-32
     `enumerate_all` implementation.

3. **Refactor and integration check.**
   - Keep `X86InstructionGenerator::generate_all` mode-neutral: its
     `InstructionGenerator` trait method receives no mode, and changing its
     global output would incorrectly remove valid x86-64 forms.
   - Do not add a new helper unless the two backend filters require more than
     the same small iterator expression; the ISA-specific backend duplication
     is preferable to widening the generator API for this targeted fix.
   - Run each new unit test separately, then the complete enumerative and
     symbolic module test surfaces to catch candidate-count or ordering
     assumptions.

## 4. Verification surface

- This follow-up changes candidate admission only; it does not change MOVZX or
  MOVSX concrete semantics, SMT lowering, parser behavior, assembly encoding,
  effects, or contracts.
- No ESBMC proof, C model, Vow contract, `tests/run/` fixture, or example needs
  to grow. The property established by Rust tests is:
  `<X86_32 as EnumerativeBackend<X86_32>>::enumerate_all` and
  `<X86_32 as SymbolicBackend<X86_32>>::enumerate_all` return only instructions
  for which `X86_32::can_assemble` is true, without discarding valid 16-bit
  RSI/RDI extension forms.
- Verification commands, in order:
  1. Targeted new enumerative test.
  2. Targeted new symbolic-backend test.
  3. `cargo fmt --all -- --check`.
  4. `cargo clippy --all -- -D warnings`.
  5. `cargo test --all`.
  6. `./ci_check.sh`.
- After all gates pass, commit and push the existing issue branch, then reply to
  PR #674 review thread `PRRT_kwDOOuU3Hc6RYfhW` with the fix summary and test
  evidence. Do not create another pull request.

## 5. Risk areas

- **Over-filtering:** filtering the register pool itself to indices below four
  would wrongly remove ESI/EDI from ordinary 32-bit operations and from valid
  16-bit MOVZX/MOVSX sources. Filter generated instructions through
  `can_assemble` instead.
- **Backend drift:** enumerative and symbolic have separate backend impls; each
  needs its own regression so fixing one cannot leave the other vulnerable.
- **Deterministic search behavior:** filtering must preserve relative candidate
  order; do not sort, deduplicate, or replace the generator's `Vec`.
- **x86-64 regression:** do not filter the shared generator or x86-64 backend,
  where SIL/DIL and the other low-byte aliases are encodable.
- **Parse/print idempotency and binary fixed point:** neither surface is touched.
  There is no self-hosted `compiler/`, codegen-ordering map, `vow-clif-shim`, or
  stack-slot layout in this repository.
- **Clippy:** bring `Assembler` into scope only where its method is used and
  avoid redundant closures or needless borrows under the
  `cargo clippy --all -- -D warnings` gate.

## 6. Out of scope

- Refactoring `X86InstructionGenerator` to become mode-aware or changing the
  `InstructionGenerator` trait.
- General consolidation of candidate encodability helpers across ISAs.
- The review's non-blocking stochastic generation efficiency observation;
  stochastic search already rejects unencodable proposals before acceptance.
- Deduplicating parser and assembler extension-source validation.
- Additional MOVZX/MOVSX widths, MOVSXD, high-byte AH/BH/CH/DH sources, or
  general sub-register modeling.
- Coverage-driven tests, unrelated formatting, candidate-pool cleanup, and
  documentation rewrites.
