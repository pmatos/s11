# x86 assembly fixtures

Hand-written x86 assembly fixtures for end-to-end `s11 opt` integration
tests. Unlike the `tests/*.c` sources (which gcc compiles to memory-operand
heavy code the x86 opt path does not model), these fixtures are restricted to
the register-only / register-immediate instruction subset the x86 optimizer
supports, and they encode a *known* deterministic shortening.

`build_tests.sh` assembles each `.s` here into `binaries/x86_64/<name>` with
host gcc (`-no-pie -nostdlib`), giving a fixed-address ELF whose window
addresses are stable across rebuilds. It also copies each assembled binary
into `tests/e2e/fixtures/x86_64/<name>` for the e2e outcome-case harness
(`tests/e2e/cases/outcome_x86_64.rs`).

Both fixtures end with an explicit `exit` syscall (rather than trailing NOP
padding) so they can actually be run, not just disassembled — consumed by the
e2e harness's behavioral tier (#837), which natively executes input vs.
patched output and diffs exit code + stdout. The exit code is derived from
live-out register state, itself a compile-time constant, so no run depends on
unseeded RNG (issue #409).

- `dup_mov_imm.s` — two identical `mov rax, 5` instructions. The enumerative
  search collapses the redundant pair to a single `mov rax, 5` (a one
  instruction shortening), exercised by `test_opt_x86_64_known_shortening` and
  the e2e case `outcome-x86-64-dup-mov-imm`, which also runs it through the
  behavioral tier (`execution: Some(ExecutionExpectation { expected_exit_code:
  5 })`). Exits with RAX's value (5).
- `auto_two_dup_mov.s` — two duplicate-MOV pairs separated by an unsupported
  `push`, giving `--auto` two deterministic windows for loop, padding, budget,
  and fixpoint coverage. The exit sequence uses only `push`/`pop` (outside the
  liftable x86 mnemonic subset, like the `push rbx` separator) so it cannot
  perturb candidate-window discovery. Exits with RCX's value (7).
- `x86_32/dup_mov_imm.s` — the x86-32 mirror of `dup_mov_imm.s`: two identical
  `mov eax, 5` instructions collapse to one, followed by an explicit
  `int 0x80` exit syscall (exit code 5, the live-out EAX value), exercised by
  the e2e case `outcome-x86-32-dup-mov-collapse`'s behavioral-tier
  `execution` expectation. `build_tests.sh`'s `gcc -m32` block assembles it
  into `tests/e2e/fixtures/x86_32/dup_mov_imm`, consumed by the e2e harness
  (`tests/e2e/cases/outcome_x86_32.rs`), not `binaries/x86_32/`.
