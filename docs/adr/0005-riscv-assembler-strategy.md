# ADR-0005 — RISC-V backend ships without machine-code emission in its first iteration

Status: Accepted
Date: 2026-05-16

## Context

ADR-0004 deferred the RISC-V assembler decision to its own ADR. Issue #77 stage 3 step 23 onwards requires that `<RiscV32 as ISA>::Assembler` and `<RiscV64 as ISA>::Assembler` either return real machine code, or be explicitly stubbed as "unavailable".

The constraint is external: `dynasm`/`dynasmrt` 5.0.0 (`Cargo.toml:18-19`) — the assembler s11 uses for AArch64 (`src/assembler/mod.rs`) and both x86 variants (`src/assembler/x86.rs`) — has no RISC-V backend upstream. There is no dynasm RISC-V crate published and no in-progress upstream patch as of the writing of this ADR.

Three options:

1. **Bring in an alternative encoder.** Either a crate (`riscv-encoding`, `riscv-isa`, etc.) or a hand-rolled RV32I/RV64I encoder. Adds a new dependency or maintenance burden; lets `s11 opt <riscv.elf>` produce verified ELF patches.
2. **Ship RISC-V without ELF patching.** `s11 opt <riscv.elf>` returns an error (or printable-asm-only output) telling the user "RISC-V optimization is disabled in this build (no assembler backend)". `s11 disasm <riscv.elf>` and `s11 equiv` for RISC-V assembly text remain functional. The trait impl returns `Err("RISC-V assembler not yet implemented")`.
3. **Subprocess to host `riscv64-linux-gnu-as`.** Reuses GNU AS; lets the build run on systems that have the cross-toolchain installed. Adds runtime dependency on a toolchain and a fork/exec per assemble call.

## Decision

Option 2. The first RISC-V PR ships with `<RiscV32 as ISA>::Assembler::assemble` and `<RiscV64 as ISA>::Assembler::assemble` returning `Err`, and the CLI route through `optimize_elf_binary_generic` surfaces a clear "RISC-V optimization disabled" error when the user asks for an opt pass on a RISC-V ELF. `s11 disasm` works unchanged because it does not call the assembler.

Concretely:

- `src/isa/riscv.rs` adds `impl Assembler<RiscVInstruction> for RiscV32` / `for RiscV64`; `assemble` returns `Err("RISC-V machine-code emission is not yet implemented; pass --algorithm enumerative for assembly-text output only".into())`; `can_assemble` returns `false` for every instruction so the search pipeline filters them out before reaching the assembler. (Returning `false` from `can_assemble` is consistent with how the trait was designed in step 8 — an assembler that cannot encode the instruction reports it cannot, regardless of why.)
- A follow-up RISC-V issue tracks "Add real assembler backend (option 1 or 3)".
- A `--features riscv-encoder` Cargo feature is **not** added in the first PR — it would imply that the path is supported, only requiring opt-in. We prefer the honest "not implemented" state until someone owns option 1 or 3.

## Consequences

**Positive:**
- The first RISC-V PR is small. It wires Capstone, `DetectedArch`, the concrete and SMT executors, the parser, and the test fixtures — the assembler is a one-line `Err`.
- Users get useful coverage immediately: disassembly, equivalence checking on assembly-text RISC-V sequences, and the trait surface is fully populated so future assembler work doesn't need to retrofit the CLI.
- The decision is contained to one trait method. If option 1 lands later, the only file that changes is `src/isa/riscv.rs`'s `Assembler` impl body; no consumer migration is needed.

**Negative:**
- `s11 opt <riscv.elf>` is not functional. Users who try it see an error message. This is the user-visible price of shipping the broader trait collapse without waiting for a working RISC-V encoder.
- Test coverage for the RISC-V SMT + concrete executors is asm-text-only; no round-trip-from-ELF integration test is possible until the assembler exists.

**Reversibility:** trivial. The decision is one trait method's body. Switching to option 1 (alternative encoder) or option 3 (subprocess) is a single PR that swaps the `Err(...)` for real encoding, with no cross-cutting consequences.
