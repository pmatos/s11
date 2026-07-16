# Issue #632 implementation plan

## Representation and scope

- Add `Movzx { rd, rs, src_width }` and `Movsx { rd, rs, src_width }` to
  `X86Instruction`.
- Keep the destination width implicit in the selected x86 executor/assembler
  mode, consistent with the issue's requested IR shape and the existing shared
  x86-64/x86-32 IR.
- Support the encodable low-source forms with `src_width` 8 or 16. In 64-bit
  mode this means a 64-bit destination; in 32-bit mode it means a 32-bit
  destination. Continue rejecting legacy high-byte sources and reject the
  unavailable x86-32 low-byte aliases `spl`, `bpl`, `sil`, and `dil`.
- Defer 32-to-64 sign extension to a future `movsxd` family. There is no
  `movzx r64, r32` encoding; a 32-bit write provides that architectural zero
  extension.

## TDD slices

1. Parser/IR seam
   - Test `movzx rax, bl` and `movsx rax, bx` parsing, display round trips,
     mode-aware parsing, instruction metadata, and invalid-width rejection.
   - Add enum variants, register-alias rendering, parser dispatch, traits, and
     flag-effect metadata.
2. Concrete-execution seam
   - Pin zero extension, positive/negative sign extension in 64- and 32-bit
     states, source preservation, and unchanged EFLAGS.
   - Add low-width extraction plus zero/sign extension.
3. Symbolic-equivalence seam
   - Prove `movzx rax, bl` equivalent to a full-register copy followed by
     `and rax, 0xff` when flags are dead.
   - Prove sign behavior and concrete/SMT parity; lower with Extract followed
     by ZeroExt/SignExt.
4. Assembly seam
   - Round-trip 8- and 16-bit MOVZX/MOVSX forms through dynasm and Capstone in
     x86-64 and x86-32.
   - Add mode-specific encoders and encodability guards.
5. Search/cost/documentation seam
   - Enumerate and mutate both extension families and source widths, keep the
     shared random dispatch tables synchronized, and add conservative code-size
     costs.
   - Update `docs/capability.md` with supported widths and deferrals.

## Verification

- Run targeted tests after every red/green slice.
- Run `cargo fmt --all`, `cargo clippy --all -- -D warnings`,
  `cargo test --all`, and `./ci_check.sh` before pushing. The prompt's
  Vow-specific `scripts/full_test.sh` does not exist in this Rust repository;
  `./ci_check.sh` is the repository-defined full local gate.
