# x86 assembly fixtures

Hand-written x86 assembly fixtures for end-to-end `s11 opt` integration
tests. Unlike the `tests/*.c` sources (which gcc compiles to memory-operand
heavy code the x86 opt path does not model), these fixtures are restricted to
the register-only / register-immediate instruction subset the x86 optimizer
supports, and they encode a *known* deterministic shortening.

`build_tests.sh` assembles each `.s` here into `binaries/x86_64/<name>` with
host gcc (`-no-pie -nostdlib`), giving a fixed-address ELF whose window
addresses are stable across rebuilds.

- `dup_mov_imm.s` — two identical `mov rax, 5` instructions. The enumerative
  search collapses the redundant pair to a single `mov rax, 5` (a one
  instruction shortening), exercised by `test_opt_x86_64_known_shortening`.
