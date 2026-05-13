# Plan: x86 Backend (x86-64 primary + x86-32 secondary), Minimal Core ISA

## Goal
Land an x86 backend in s11 with a full vertical slice (IR → concrete + SMT semantics → cost → enumerative search → dynasm assembler → ELF patcher → CLI) for the minimal core opcodes **MOV / ADD / SUB / AND / OR / XOR / CMP**. Both **x86-64 (primary)** and **x86-32 (secondary)** as two ISA marker structs sharing one register/operand/instruction enum family — mirroring the existing `RiscV64`/`RiscV32` pattern in `src/isa/riscv.rs`.

## Critical context from exploration

1. **RISC-V is scaffold-only, not wired through.** The CLI rejects it at `src/main.rs:1172-1178` and `src/main.rs:1212-1217`. Mirroring `src/isa/riscv.rs` gives the trait scaffolding *but does nothing end-to-end*. To make x86 actually optimize binaries, the semantics/search/assembler/elf_patcher/CLI layers — currently AArch64-only — must each gain an x86 dispatch.
2. **The `ISA` / `ConcreteExecutor` / `SymbolicExecutor` / `CostModel` / `Assembler` traits in `src/isa/traits.rs` are aspirational** — implementations exist for no backend. AArch64 bypasses them and works against concrete `crate::ir::Instruction` directly. **This plan does NOT attempt to retrofit the codebase onto the traits.** It introduces x86 via **parallel ISA-tagged code paths** (the same shape RISC-V was meant to follow but didn't reach).
3. **Z3 BV width is hardcoded to 64** at `src/semantics/smt.rs:69-86`. x86-32 needs a parameterised width path.
4. **Two-operand destructive x86 form (`add rax, rbx` clobbers rax)** fits the existing `destination() -> Option<Register>` model — `rd` is both source and dest. The IR variant must list it once in `source_registers()`.
5. **EFLAGS ≠ NZCV.** `ConditionFlags` (`src/semantics/state.rs:11-100`) is AArch64-specific. For the **CMP-only** initial scope, we only need ZF/SF/CF/OF/PF/AF set by CMP and *unused thereafter* (no CMOVcc, no Jcc). Plan therefore models EFLAGS as a separate struct on the x86 machine state but **does not yet feed it into search**.
6. **dynasmrt 4.0.1 (`Cargo.toml:18-19`) supports both `dynasmrt::x64` and `dynasmrt::x86`** modules; both ship in the default feature set — verified in Phase 0.
7. **capstone 0.14 (`Cargo.toml:15`)** ships x86 disassembly by default.

## Architectural decision (baked into this plan)

> **Decision:** Add x86 as a **parallel pipeline** dispatched on `CliArch` in `main.rs`. Do NOT generalise the existing AArch64 pipeline to be ISA-generic. The AArch64 path stays exactly as-is; an x86 sibling path is added next to it. This keeps the PR reviewable and avoids touching working AArch64 code.
>
> **Tradeoff:** Some code is duplicated (semantics matchers, cost match arms, candidate enumeration). Future work can collapse them onto the existing trait surface. Mitigation: x86-side helpers live behind a single `x86` module so cross-cutting refactors later are local.

## Key files

| File | Role | Status |
|---|---|---|
| `src/isa/x86.rs` | x86 register/operand/instruction enums + `ISA` trait impls + generator + tests | **NEW** |
| `src/isa/mod.rs:6-21` | Add `pub mod x86;` + re-exports | MOD |
| `src/semantics/state.rs:11-100` | Add x86 `Eflags` struct alongside `ConditionFlags` | MOD |
| `src/semantics/state.rs:131-196` | Add `X86ConcreteMachineState` (separate from AArch64 state) | MOD (additive) |
| `src/semantics/concrete_x86.rs` | x86 concrete interpreter (mirrors `concrete.rs:15-174` shape) | **NEW** |
| `src/semantics/smt_x86.rs` | x86 SMT lowering with parameterised BV width (32 or 64) | **NEW** |
| `src/semantics/cost_x86.rs` | x86 cost model (CodeSize uses variable lengths) | **NEW** |
| `src/semantics/equivalence.rs:109-255` | Add `check_equivalence_x86` sibling | MOD |
| `src/semantics/mod.rs` | Re-export new x86 sub-modules | MOD |
| `src/assembler/x86.rs` | `X86Assembler` using `dynasmrt::x64::Assembler` and `dynasmrt::x86::Assembler` | **NEW** |
| `src/assembler/mod.rs` | `pub mod x86;` declaration | MOD |
| `src/elf_patcher/mod.rs:5-7,29-35,84-89,155-165` | Tag `ElfPatcher` with `DetectedArch`; ISA-conditional alignment + NOP | MOD |
| `src/search/candidate_x86.rs` | x86 enumerative candidate generation | **NEW** |
| `src/search/mod.rs` | Wire `candidate_x86` module | MOD |
| `src/main.rs:108-118` | Add `X86_64` and `X86_32` to `CliArch` | MOD |
| `src/main.rs:1168-1260` | `Disasm` and `Opt` match arms — add x86 branches | MOD |
| `src/main.rs:241-274` | Make `analyze_elf_binary` arch-aware (Capstone init + `e_machine` whitelist) | MOD |
| `src/main.rs:373-467` | New `optimize_elf_binary_x86` sibling function | MOD (additive) |
| `Cargo.toml:13-26` | Verify (and pin if needed) `dynasmrt` features and capstone features | MOD-maybe |
| `tests/integration/disasm_test.rs` + `tests/integration/opt_test.rs` | Add x86 integration cases | MOD |
| `build_tests.sh` | Add host-`gcc` (x86_64) and `gcc -m32` (i386) cross paths | MOD |
| `test_all.sh:30-56,59` | Add x86 binary loop | MOD |
| `CLAUDE.md:7,10,15,33-98` | Broaden ISA & opcode-count language | MOD |

---

## Phase 0 — Validate external dependencies (no source changes outside `.ultraplan/`)

### Step 0.1. Confirm `dynasmrt 4.0.1` exposes `x64` and `x86` modules and ships in default features
- **Action**: `cargo doc --no-deps -p dynasmrt 2>&1 | head -50` or `cargo tree -e features -p dynasmrt`. Inspect `~/.cargo/registry/src/.../dynasmrt-4.0.1/Cargo.toml` for default features.
- **Acceptance**: both `dynasmrt::x64::Assembler` and `dynasmrt::x86::Assembler` resolve in a scratch `cargo check` (write a one-line scratch test, do NOT commit).
- **Fallback**: if x86 backends are gated behind a Cargo feature, update `Cargo.toml:18-19` to `dynasmrt = { version = "4.0.1", features = ["x64", "x86"] }` and `dynasm = { version = "4.0.1", features = ["x64", "x86"] }`.

### Step 0.2. Confirm `capstone 0.14` ships x86 by default
- **Action**: `grep -n 'x86' ~/.cargo/registry/src/.../capstone-0.14*/Cargo.toml` or trial-build `Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build()` in a scratch.
- **Acceptance**: builds without changing `Cargo.toml`.

---

## Phase 1 — x86 ISA layer (`src/isa/x86.rs`)

This phase produces a self-contained module that compiles + tests pass, but does not affect any other code paths.

### Step 1.1. Create `src/isa/x86.rs` [new] mirroring `src/isa/riscv.rs:1-1006`
- **Module preamble** (mirrors `riscv.rs:1-11`): `use crate::isa::traits::{ISA, InstructionGenerator, InstructionType, OperandType, RegisterType};` plus `rand::Rng` for the generator.
- **`enum X86Register`**: 16 general-purpose 64-bit GPRs `RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8..R15` with `#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]`. Mirrors `riscv.rs:14-48`.
  - Note: x86-32 callers will use only `RAX..RDI` (the low 8); we expose all 16 from the enum and let the `ISA::register_count` / `general_registers` methods filter per variant.
- **`impl X86Register`** (mirrors `riscv.rs:50-163`): `index() -> Option<u8>` (RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7, R8..R15=8..15 — Intel encoding order), `from_index`, optional `abi_name` helper.
- **`impl fmt::Display for X86Register`** (mirrors `riscv.rs:165-169`): lowercase Intel-syntax mnemonics (`rax`, `rbx`, ...).
- **`impl RegisterType for X86Register`** (mirrors `riscv.rs:171-187`):
  - `is_zero_register() = false` (x86 has none).
  - `is_special()`: `true` for `RSP` only (see policy note below the ISA struct impls).
- **`enum X86Operand { Register(X86Register), Immediate(i64) }`** mirrors `riscv.rs:191-194`.
- **`impl fmt::Display for X86Operand`** (mirrors `riscv.rs:196-203`): `imm` prefix per Intel syntax (raw integer, no `#`).
- **`impl OperandType for X86Operand`** (mirrors `riscv.rs:205-229`).
- **`enum X86Instruction`** (seven variants, all in **two-operand destructive form** — `rd` is both first source and destination):
  ```
  MovReg { rd: X86Register, rs: X86Register }
  MovImm { rd: X86Register, imm: i64 }
  AddReg { rd: X86Register, rs: X86Register }       // rd = rd + rs ; sets EFLAGS
  AddImm { rd: X86Register, imm: i64 }              // rd = rd + imm ; sets EFLAGS
  SubReg { rd: X86Register, rs: X86Register }       // rd = rd - rs ; sets EFLAGS
  SubImm { rd: X86Register, imm: i64 }
  AndReg / AndImm / OrReg / OrImm / XorReg / XorImm // each clobbers CF/OF, sets SF/ZF/PF, AF undefined
  CmpReg { rn: X86Register, rs: X86Register }       // rn - rs ; sets EFLAGS, no register write
  CmpImm { rn: X86Register, imm: i64 }
  ```
  Total: 13 variants (each opcode except CMP has reg and imm forms; CMP has reg and imm; MOV has reg and imm). Pattern mirrors `riscv.rs:232-318` (where Add/Addi etc. are split per-operand-shape).
- **`impl X86Instruction`** inherent helpers (`destination`, `source_registers`) mirror `riscv.rs:320-364`:
  - `destination()`: `Some(rd)` for MOV/ADD/SUB/AND/OR/XOR variants; `None` for `CmpReg`/`CmpImm`.
  - `source_registers()`: **intentional divergence from AArch64/RISC-V documented convention** — both existing ISAs treat the destination as *not* a source (`src/ir/instructions.rs:230-273`, `src/isa/riscv.rs:343-363`). x86's two-operand destructive form requires `rd` to *also* appear in sources for liveness analysis to work correctly (`src/validation/live_out.rs:122-138` reads `source_registers()` to compute live-in). Therefore:
    - `MovReg { rd, rs }` → `[rs]` (MOV is non-destructive: rd is fully overwritten).
    - `MovImm { rd, imm }` → `[]`.
    - `AddReg / SubReg / AndReg / OrReg / XorReg { rd, rs }` → `[rd, rs]` (rd is read AND written).
    - `AddImm / SubImm / AndImm / OrImm / XorImm { rd, imm }` → `[rd]`.
    - `CmpReg { rn, rs }` → `[rn, rs]`; `CmpImm { rn, imm }` → `[rn]`.
  - **Doc-comment at top of `enum X86Instruction`** must explicitly state this divergence and the reason, otherwise a future refactor that "normalises" with AArch64 will silently regress liveness.
- **`impl fmt::Display for X86Instruction`** (mirrors `riscv.rs:366-393`): Intel syntax (`add rax, rbx`).
- **`impl InstructionType for X86Instruction`** (mirrors `riscv.rs:395-452`):
  - `opcode_id` numbers the 13 variants 0..12. **Must equal `opcode_count`** (cross-reference the `aarch64.rs:268`/`aarch64.rs:525` mismatch flagged in exploration; do not repeat the bug).
  - `has_side_effects()`: `true` for every variant except `MovReg`/`MovImm` (EFLAGS changes are observable side-effects). **This diverges from AArch64/RV behaviour and is the only place `has_side_effects` is currently `true` in the codebase** — flag for reviewer.
- **`struct X86_64;` + `impl ISA for X86_64`** (mirrors `riscv.rs:454-486`):
  - `name() = "x86-64"`, `register_count() = 16`, `register_width() = 64`, `instruction_size() = None` (variable-length).
  - `general_registers()`: return all 16 GPRs via `(0..16).filter_map(X86Register::from_index).collect()` — mirror the RISC-V convention (`riscv.rs:479-481`) which returns *all* registers including the special ones. Callers (CLI `optimize_elf_binary_x86`) are responsible for filtering RSP out of the search-available pool, the same way `main.rs:479-488` builds the AArch64 available-register list (it excludes XZR/SP by listing only X0..X7).
  - `zero_register() = None`.
- **`struct X86_32;` + `impl ISA for X86_32`** (mirrors `riscv.rs:488-520`):
  - `name() = "x86-32"`, `register_count() = 8`, `register_width() = 32`, `instruction_size() = None`.
  - `general_registers()`: return the low 8 GPRs via `(0..8).filter_map(X86Register::from_index).collect()`. CLI filters ESP at call sites.
- **`is_special()` policy**: only `RSP` is special. **RBP is *not* special** — modern x86-64 SysV ABI does not require a frame pointer (`-fomit-frame-pointer` is GCC's default since 4.6) and excluding RBP would bias the search against valid optimisations that use RBP as a scratch register.
- **`struct X86InstructionGenerator;` + `impl InstructionGenerator<X86Instruction>`** (mirrors `riscv.rs:522-809`): three strategies in `mutate` (full re-gen / change-dest / change-source). `opcode_count() = 13`.
- **`#[cfg(test)] mod tests`** (mirrors `riscv.rs:811-1006`):
  - Trait conformance: every `RegisterType`/`OperandType`/`InstructionType` method invariant.
  - Display round-trip.
  - Generator: `generate_all` returns expected count given N registers and M immediates.
  - Generator: `generate_random` only produces opcode IDs in `0..opcode_count`.
  - Generator: `mutate` invariants (mutated instruction is reachable from neighbourhood).
  - `X86_32` vs `X86_64` metadata correctness.

### Step 1.2. Wire `src/isa/x86.rs` into the ISA namespace
- **File**: `src/isa/mod.rs:6-21`
- **Change**:
  - After `pub mod riscv;` add `pub mod x86;`.
  - Extend the `pub use aarch64::AArch64;` / `pub use riscv::{...};` block at lines 17-21 with `pub use x86::{X86_32, X86_64, X86Instruction, X86InstructionGenerator, X86Operand, X86Register};`.
  - Update the doc comment at line 4: append "x86" to the example list.

### Step 1.3. Verify Phase 1 compiles in isolation
- `cargo check` and `cargo test --lib isa::x86 -- --nocapture`. No other code paths touched yet.

---

## Phase 2 — x86 machine state and concrete interpreter

### Step 2.1. Add `Eflags` struct in `src/semantics/state.rs`
- **File**: `src/semantics/state.rs` (after the `ConditionFlags` block at lines 11-100, additive)
- **Change**: Add `pub struct Eflags { cf: bool, pf: bool, af: bool, zf: bool, sf: bool, of: bool }` with `from_sub`/`from_logical`/`from_add` constructors mirroring the existing `ConditionFlags::from_*` patterns. AF can be left as `false` (undefined per x86 ABI) — comment it.
- **Reuses**: `from_sub` / `from_logical` / `from_add` shape from `state.rs:25-64`.
- **Why kept separate from `ConditionFlags`**: AArch64 NZCV semantics for `from_add`/`from_sub` differ slightly (e.g. C-flag polarity on SUB). Reusing would be wrong.

### Step 2.2. Add `X86ConcreteMachineState` in `src/semantics/state.rs`
- **File**: `src/semantics/state.rs` (after `ConcreteMachineState` at lines 131-196, additive)
- **Change**: Mirror `ConcreteMachineState` but:
  - `HashMap<X86Register, ConcreteValue>` keyed by `X86Register`.
  - Carries `Eflags` instead of `ConditionFlags`.
  - `new_zeroed()` enumerates the 16 GPRs (use `X86Register::from_index` for 0..16).
  - Width-aware: `X86_64` writes 64-bit values; `X86_32` writes 32-bit values zero-extended to 64. Carry a `width: u32` field on the state to control mask-on-write.
- **Reuses**: `ConcreteValue` from `state.rs`.

### Step 2.3. Create `src/semantics/concrete_x86.rs` [new]
- **Path**: `src/semantics/concrete_x86.rs` (parent dir `src/semantics/` exists).
- **Content**: `apply_instruction_concrete_x86(state, instr) -> X86ConcreteMachineState` — a `match instr` over the 13 x86 variants. For each arithmetic/logic variant, also compute `Eflags::from_*` and stash it in `state.flags`. Width-mask results to 32 or 64 bits per `state.width`.
- **Reuses**:
  - Shape and signature pattern from `src/semantics/concrete.rs:15-174`.
  - `wrapping_add` / `wrapping_sub` / bitwise ops (Rust stdlib).
- **Tests** at end of file: per-opcode functional check for each of the 13 variants in both x86-64 (64-bit width) and x86-32 (32-bit width) modes.

### Step 2.4. Wire module
- **File**: `src/semantics/mod.rs:1-20`
- **Change**: Add `pub mod concrete_x86;` and re-export `apply_instruction_concrete_x86`. Update the doc comment at `:1` to drop "for AArch64 instructions" or broaden.

---

## Phase 3 — x86 SMT lowering

### Step 3.1. Create `src/semantics/smt_x86.rs` [new]
- **Path**: `src/semantics/smt_x86.rs`.
- **Content**: Parameterise the Z3 BV width. Mirror `src/semantics/smt.rs:60-220` shape but:
  - `MachineStateX86 { regs: HashMap<X86Register, BV>, width: u32 }`.
  - `new_symbolic(ctx, prefix, width)`: create 16 fresh `BV::new_const(name, width)`.
  - `apply_instruction(state, instr) -> MachineStateX86`: bitvector ops per opcode, both register and immediate forms. **CMP is a no-op for now (no symbolic flag plumbing)** — exactly like AArch64 at `smt.rs:201-204`.
- **Reuses**: `BV` import + Z3 context plumbing from `src/semantics/smt.rs:1-30`.
- **Tests**: bitvector identity invariants (e.g. `xor rax, rax` produces a BV equal to `BV::from_i64(0, width)`); width round-trip.

### Step 3.2. Add `check_equivalence_x86` in `src/semantics/equivalence.rs`
- **File**: `src/semantics/equivalence.rs:109-255`
- **Change**: Add sibling `check_equivalence_x86(seq1: &[X86Instruction], seq2: &[X86Instruction], config: &X86EquivConfig)` that orchestrates the x86 concrete fast path (Step 2.3) and x86 SMT verification (Step 3.1).
- **`X86EquivConfig` must carry `width: u32`** — `optimize_elf_binary_x86` (Step 7.4) sets it to 64 for `CliArch::X86_64` and 32 for `CliArch::X86_32`. Z3 will panic on mixed-width BV ops, so `MachineStateX86::new_symbolic` and every `BV::from_i64(*imm, width)` in `apply_instruction` must read from `config.width`. Both `seq1` and `seq2` must be validated as belonging to the same width before lowering.
- **Reuses**: orchestration shape from `equivalence.rs:143-255`. Live-out logic must be x86-register-keyed — define `X86LiveOutMask` alongside the existing `LiveOutMask` (`state.rs:218-282`).
- **EFLAGS soundness — critical, see also Risks section**: x86's CMP / AddReg / etc. mutate EFLAGS. The concrete interpreter (Step 2.3) computes EFLAGS; the SMT path leaves CMP as a no-op (mirroring AArch64). Without further care, the optimiser could drop a target's trailing CMP and incorrectly call the shorter sequence equivalent. **Mitigation (in this step)**: extend the fast-path equivalence comparator `states_equal_for_live_out` (currently at `concrete.rs:211-222`) with an x86 sibling `states_equal_for_live_out_x86` that **also compares `Eflags`** when CMP is present anywhere in either sequence. Concretely: if `seq1.iter().any(|i| matches!(i, X86Instruction::CmpReg{..} | X86Instruction::CmpImm{..}))` OR same for `seq2`, require `state1.flags == state2.flags` after applying each random-input test. The SMT path stays a no-op for CMP, but the fast path's coverage of EFLAGS catches the regression empirically. Document this as an MVP soundness compromise.

### Step 3.3. Wire module
- **File**: `src/semantics/mod.rs` — add `pub mod smt_x86;` (gated under `#[cfg(feature = "z3")]` to match the existing `smt` module gating convention if any; check `mod.rs` to confirm).

---

## Phase 4 — x86 cost model

### Step 4.1. Create `src/semantics/cost_x86.rs` [new]
- **Path**: `src/semantics/cost_x86.rs`.
- **Content**: Mirror `src/semantics/cost.rs:5-47`:
  - `InstructionCount`: 1 per instruction.
  - `Latency`: 1 for ALU (every opcode in the initial set).
  - `CodeSize`: variable per x86 — implement a per-variant byte-length lookup table for the minimal set. Initial-set sizes:
    - `MovImm` reg=RAX/imm fits 32 bits → 5 bytes (opcode + 4); imm doesn't fit → 10 bytes (REX.W + opcode + 8). Use a conservative upper bound of 10 to start; refine later.
    - `MovReg` → 3 bytes (REX + opcode + ModRM).
    - `AddReg`/`SubReg`/`AndReg`/`OrReg`/`XorReg`/`CmpReg` → 3 bytes.
    - `AddImm`/`SubImm`/... → 6 bytes (REX + opcode + ModRM + imm8) if imm fits int8 ; 7 bytes otherwise. Approximate as 7.
  - For x86-32: subtract REX prefix (one byte less than the x86-64 sizes above).
- **Tests**: cost ordering invariant (e.g. `MovImm` of small constant ≤ `MovImm` of large constant).

### Step 4.2. Wire module
- **File**: `src/semantics/mod.rs` — add `pub mod cost_x86;`.

---

## Phase 5 — `X86Assembler` (dynasm-based)

### Step 5.1. Create `src/assembler/x86.rs` [new]
- **Path**: `src/assembler/x86.rs` (parent dir `src/assembler/` exists).
- **Content**:
  - `pub struct X86Assembler { mode: X86Mode }` where `X86Mode = { Mode64, Mode32 }`.
  - `pub fn new_64() -> Self` / `pub fn new_32() -> Self`.
  - `pub fn assemble_instructions(&mut self, instructions: &[X86Instruction]) -> Result<Vec<u8>, String>`.
  - Two encoder bodies: `encode_64(ops: &mut dynasmrt::x64::Assembler, instr) -> Result<(), String>` and `encode_32(ops: &mut dynasmrt::x86::Assembler, instr) -> Result<(), String>`.
  - Each encoder body is a match over the 13 variants using `dynasm!(ops; .arch x64; mov Rq(rd), Rq(rs))` and `; .arch x86; mov Rd(rd), Rd(rs)` respectively.
- **Reuses**: encoding pattern, error shape, and the Capstone round-trip test idiom from `src/assembler/mod.rs:30-364, 400-731`.
- **dynasm Intel-syntax operand sizes**: `Rq(...)` for 64-bit, `Rd(...)` for 32-bit register operands per dynasm-rs docs.
- **Tests** at end of file: round-trip each opcode through Capstone in both modes — copy the `disassemble_and_verify` helper pattern from `src/assembler/mod.rs:502-537`, adapted for x86 mnemonics.

### Step 5.2. Wire module
- **File**: `src/assembler/mod.rs:1-3`
- **Change**: Add `pub mod x86;` before the existing `use` statements. Keep `AArch64Assembler` exactly as-is.

---

## Phase 6 — ELF patcher ISA-awareness

The patcher needs to accept three architectures with different alignment and NOP semantics.

### Step 6.1. Introduce a `DetectedArch` tag and store it on `ElfPatcher`
- **File**: `src/elf_patcher/mod.rs:5-7`
- **Change**: Add `pub enum DetectedArch { Aarch64, X86_64, X86_32 }`. Extend `ElfPatcher` to carry `arch: DetectedArch` alongside `file_data`.

### Step 6.2. Detect arch from `e_machine`
- **File**: `src/elf_patcher/mod.rs:28-35`
- **Change**: Replace the `EM_AARCH64`-only guard with a match:
  ```
  let arch = match elf.ehdr.e_machine {
      elf::abi::EM_AARCH64 => DetectedArch::Aarch64,
      elf::abi::EM_X86_64  => DetectedArch::X86_64,
      elf::abi::EM_386     => DetectedArch::X86_32,
      m => return Err(format!("Unsupported architecture (e_machine={})", m).into()),
  };
  ```
  Pass `arch` into the new constructor field.
- **Acceptance**: existing AArch64 tests still pass; new test asserts an x86-64 ELF parses without error.

### Step 6.3. Alignment check is per-arch
- **File**: `src/elf_patcher/mod.rs:84-89`
- **Change**: Only enforce 4-byte alignment when `self.arch == Aarch64`. For x86, accept byte-aligned windows. Update the error string.

### Step 6.4. NOP padding is per-arch
- **File**: `src/elf_patcher/mod.rs:155-165`
- **Change**: Three things change inside this block (not just the loop bound):
  1. The `nop_bytes` slice (`:157`): per-arch — `vec![0x1f, 0x20, 0x03, 0xd5]` for `Aarch64`; `vec![0x90]` for `X86_64`/`X86_32`.
  2. The for-loop iteration count (`:158`): `remaining / nop_bytes.len()`.
  3. The buffer-write step inside the loop (`:160`): `nop_start + nop_bytes.len()` instead of `nop_start + 4`; `copy_from_slice(&nop_bytes)` works with any slice length.
  4. The bounds check (`:161`): same — `nop_start + nop_bytes.len() <= file_offset + window_size`.
- After the loop, any sub-`nop_bytes.len()` remainder (for x86 it's always 0 because the slice is 1 byte; for AArch64 it's always 0 because the window is 4-aligned per Step 6.3) — so no remainder handling needed.
- **Note for reviewer**: multi-byte NOP (`0x66 0x90`, ... `0x0f 0x1f 0x84 0x00 0x00 0x00 0x00 0x00`) is a perf optimisation; deferred.

### Step 6.5. Extend `src/elf_patcher/mod.rs:184-213` tests
- Add tests for the three branches: AArch64 4-byte alignment failure stays; x86_64 byte-aligned window accepted; x86 NOP padding produces `0x90` bytes.
- **Test data approach**: build a minimal in-memory ELF byte buffer (mirroring the `proptest` dev-dep at `Cargo.toml:32-33` if needed) rather than requiring real on-disk fixtures from Phase 9.2. Reuse the existing unit-test pattern at `elf_patcher/mod.rs:184-213` which currently tests pure helpers — extend with `ElfPatcher::from_bytes(&[u8])` if it exists (check `:5-23`), otherwise add a `#[cfg(test)] fn new_for_test(bytes: Vec<u8>, arch: DetectedArch)` constructor that bypasses ELF parsing.

### Step 6.6. Reflect arch detection in `src/main.rs:241-274` (`analyze_elf_binary`)
- **File**: `src/main.rs:253-263`
- **Change**: Replace the `EM_AARCH64` check with the same `e_machine` match; print the detected arch name in the human output.

---

## Phase 7 — CLI dispatch

### Step 7.1. Extend `CliArch`
- **File**: `src/main.rs:108-118`
- **Change**: Add `X86_64` and `X86_32` variants to the enum with doc comments mirroring the existing entries.

### Step 7.2. `Disasm` arm — wire x86 Capstone init
- **File**: `src/main.rs:1168-1186`
- **Change**: Replace the AArch64-only acceptance with a per-arch dispatch. For x86 branches, call a new `analyze_elf_binary_with_arch(path, true, arch)` that selects `Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build()` for x86-64 and `.Mode32` for x86-32, mirroring the existing `arm64().mode(arch::arm64::ArchMode::Arm)` at `:277-281, :399-403`.

### Step 7.3. `Opt` arm — wire x86 optimization pipeline
- **File**: `src/main.rs:1188-1260`
- **Change**: For `CliArch::X86_64` and `CliArch::X86_32`, dispatch to a **new** `optimize_elf_binary_x86(path, window, options, mode)`. Leave the AArch64 path through `optimize_elf_binary` untouched.

### Step 7.4. Create `optimize_elf_binary_x86`
- **File**: `src/main.rs` (additive — same file, append after the existing `optimize_elf_binary` at `:373-467`)
- **Change**: Mirror the existing pipeline:
  1. `ElfPatcher::new(path)` (already arch-aware after Phase 6).
  2. `ElfPatcher::validate_address_window` — alignment now correct per arch.
  3. Read bytes via `ElfPatcher::get_instructions_in_window`.
  4. Disassemble with Capstone `.x86()` (mode per `CliArch`).
  5. **Convert to x86 IR**: new helper `convert_to_x86_ir(&capstone_instructions, mode) -> Vec<X86Instruction>`. Mirrors `main.rs:742-774` but recognises the 7 mnemonics (mov, add, sub, and, or, xor, cmp) with Intel-syntax operands. Unrecognised mnemonics print a warning and are dropped (same policy as the AArch64 path).
  6. Run the **enumerative** search (see Phase 8). Skip stochastic / symbolic / hybrid / LLM for the initial PR; emit a friendly error if the user passes `--algorithm` with anything else.
  7. Verify equivalence with `check_equivalence_x86` (Phase 3.2).
  8. Assemble with `X86Assembler::new_64()` or `new_32()` (Phase 5).
  9. Write the patched ELF.
- **Reuses**: orchestration shape from `main.rs:373-467` (esp. window handling, equiv-fail messaging).

### Step 7.5. Help text
- **File**: `src/main.rs:33`
- **Change**: Broaden `#[command(about = "s11 - AArch64 Optimizer")]` to "s11 - Superoptimizer (AArch64, x86)".
- **Note on live-out**: `optimize_elf_binary` infers live-out from `instr.destination()` (`main.rs:493-499`), not from CLI. The new `optimize_elf_binary_x86` (Step 7.4) will mirror that pattern using `X86Instruction::destination()` to build an `X86LiveOutMask`. No CLI default change needed for the `opt` subcommand. The `equiv` subcommand (`main.rs:226`) keeps its AArch64 default; running `equiv` on x86 assembly is out of scope for v1.

---

## Phase 8 — x86 enumerative search (the only search backend for v1)

### Step 8.1. Create `src/search/candidate_x86.rs` [new]
- **Path**: `src/search/candidate_x86.rs`.
- **Content**: Mirror the shape of `src/search/candidate.rs:14-22, 25-100`:
  - `generate_all_x86_instructions(registers: &[X86Register], immediates: &[i64]) -> Vec<X86Instruction>`: nested loops over (rd, rs) producing the 13 variants.
  - No encoding-gate equivalent of `is_encodable_aarch64` — x86 immediate ranges are wide and our cost model already prices large immediates; defer encodability filtering to the assembler (which returns `Err` for unsupported encodings).
- **Tests**: count invariant — for N registers and M immediates, the generator returns exactly `2*N + 6*(N*N + N*M) + 2*(N + N*M) = ...` (work out exact formula in implementation and assert).

### Step 8.2. Wire module
- **File**: `src/search/mod.rs:1-30`
- **Change**: Add `pub mod candidate_x86;`. Do NOT add x86 to the `SearchAlgorithm` trait — the v1 x86 path bypasses the trait and calls the enumerator + equivalence checker directly inside `optimize_elf_binary_x86`.

### Step 8.3. Enumerative loop in `optimize_elf_binary_x86`
- **File**: `src/main.rs` (in the new function from Step 7.4)
- **Change**: Replicate the length-1 enumerative shape from `main.rs:948-989` (`find_shorter_equivalent`) and the AArch64 candidate generator at `main.rs:891-946` (`generate_all_instructions`) over `X86Instruction`. Call `candidate_x86::generate_all_x86_instructions` for candidate generation. **Use `cost_x86::sequence_cost` with `CodeSize` as a tie-breaker** among candidates of the same length: this gives `cost_x86` (Phase 4) a real consumer in v1 and matches a user-visible expectation that "shorter" should mean *bytes*, not just instruction count. Length still dominates (a 2-instruction sequence wins over a 1-instruction sequence only if cost says so, which on x86 can happen — but for v1 we keep the "must be strictly shorter in instruction count" rule and tie-break by bytes).

### Step 8.4. Explicit error for unsupported algorithms
- In `optimize_elf_binary_x86`, when the user passes `--algorithm` ≠ `enumerative`, print `"x86 only supports --algorithm enumerative in this release; stochastic/symbolic/hybrid/llm are AArch64-only"` and exit 1. This is intentional MVP scope — flag in the PR description.

---

## Phase 9 — Tests

### Step 9.1. Unit-test parity
- `cargo test --lib isa::x86` — Phase 1 tests.
- `cargo test --lib semantics::concrete_x86` — Phase 2.3 tests.
- `cargo test --lib semantics::smt_x86` — Phase 3.1 tests (gated on `--features z3`).
- `cargo test --lib semantics::cost_x86` — Phase 4.1 tests.
- `cargo test --lib assembler::x86` — Phase 5.1 Capstone round-trip tests.
- `cargo test --lib elf_patcher` — extended Phase 6.5 tests.

### Step 9.2. Build test ELFs for x86
- **File**: `build_tests.sh`
- **Change**: Add a second pass that compiles each `tests/*.c` with host `gcc` for x86-64 into `binaries/x86_64/` and with `gcc -m32` for i386 into `binaries/x86_32/`. Keep the existing `aarch64-linux-gnu-gcc` path intact.
- **Acceptance**: `./build_tests.sh` produces both AArch64 and x86 binaries on a host with `gcc-multilib` installed. Document the dep in `BUILD.md`.

### Step 9.3. Integration tests
- **File**: `tests/integration/disasm_test.rs`
- **Change**: Add a new test `test_disasm_x86_64` that invokes the compiled `s11` with `disasm --binary binaries/x86_64/simple --arch x86-64` and asserts non-zero output.
- **File**: `tests/integration/opt_test.rs`
- **Change**: Add `test_opt_x86_64_minimal` exercising `opt --binary binaries/x86_64/optimizable --arch x86-64 --start-addr ... --end-addr ...` with a known-shortening fixture. Pick an addr range that contains only the 7 supported mnemonics — generate from a hand-written tiny .c snippet specifically for this.

### Step 9.4. `test_all.sh` smoke-loop
- **File**: `test_all.sh:30-56,59`
- **Change**: Add a parallel loop over `binaries/x86_64/*` (and `binaries/x86_32/*` if cross-compilation is reliable on the CI host) that invokes `s11 disasm --arch x86-64 <bin>` and asserts exit 0.

### Step 9.5. `ci_check.sh`
- **File**: `ci_check.sh:1-65`
- **Change**: No source change required — the script invokes `cargo test` and `test_all.sh`, both of which gain the x86 cases above.

---

## Phase 10 — Documentation

### Step 10.1. CLAUDE.md
- **File**: `CLAUDE.md`
- **Lines & changes**:
  - `:7` "s11 is an AArch64 superoptimizer" → "s11 is a superoptimizer (AArch64 primary, x86 and RISC-V backends)".
  - `:10` "20 AArch64 instructions" → "20 AArch64 / 13 x86 instructions" (or restructure).
  - `:15` "ISA abstraction supporting AArch64 (primary) and RISC-V (secondary)" → "AArch64 (primary), x86-64/x86-32 (initial vertical slice), RISC-V (trait scaffolding)".
  - `:74-98` add `src/isa/x86.rs`, `src/semantics/{concrete,smt,cost}_x86.rs`, `src/assembler/x86.rs`, `src/search/candidate_x86.rs` to the module map.

### Step 10.2. README.md (if it mentions ISAs)
- Grep first; broaden as needed. Out of scope if unchanged.

### Step 10.3. BUILD.md
- Document the `gcc -m32` / `gcc-multilib` requirement added by Step 9.2.

---

## Testing checklist (verification commands)

In order:

1. `cargo fmt -- --check`
2. `cargo build --verbose`
3. `cargo test --lib` — all unit tests including new x86 modules.
4. `./build_tests.sh` (after Phase 9.2 changes) — produces all three arch binaries.
5. `./test_all.sh` — smoke tests pass for all three arches.
6. `./ci_check.sh` — full pre-push gate.
7. Manual: `./target/debug/s11 disasm --binary binaries/x86_64/simple --arch x86-64`.
8. Manual: `./target/debug/s11 opt --binary binaries/x86_64/optimizable --arch x86-64 --start-addr <X> --end-addr <Y> --algorithm enumerative`.

*Removed `--no-default-features`*: the existing AArch64 `smt.rs` is NOT feature-gated despite `z3` being marked `optional = true` in `Cargo.toml`. Adding `--no-default-features` to the verification gate would fail on `main` today, before any x86 code lands. Fixing that gating is a separate ADR-level cleanup.

## Risks (carried over from exploration; mitigations in-plan)

| Risk | Mitigation |
|---|---|
| dynasm `x64`/`x86` modules not in default features | Phase 0.1 fallback: explicit `features = ["x64","x86"]` in `Cargo.toml`. |
| capstone x86 mode requires explicit feature | Phase 0.2 trial-build. |
| Z3 BV width hardcoded to 64 in `smt.rs` | Phase 3.1 isolates x86 SMT into a new file with a `width: u32` parameter; AArch64 path stays at 64. Step 3.2's `X86EquivConfig` threads width from `CliArch`. |
| `has_side_effects()` is `false` everywhere today; x86 EFLAGS forces it to `true` | Step 1.1 flags this for reviewer. No downstream caller of `has_side_effects()` exists in search code today (verified by grep), so it's a passive marker for now. |
| `LiveOutMask` is AArch64-keyed (`state.rs:218-282`) | Add `X86LiveOutMask` sibling (Step 3.2). No retrofit. |
| Two enumeration paths (`candidate.rs` vs `aarch64.rs`) disagree on opcode subset — risk of repeating for x86 | Single x86 generator lives in `candidate_x86.rs`. The trait generator in `isa/x86.rs` is for trait-conformance tests only; not wired into search. Document in `src/isa/x86.rs` module doc. |
| **EFLAGS soundness gap for CMP-shortening (x86-specific)** | Step 3.2 extends the *fast path* equivalence to compare `Eflags` when any CMP appears in either sequence. SMT path stays a no-op (mirrors AArch64). MVP compromise; documented inline. |
| `source_registers()` convention divergence | Step 1.1 documents the intentional divergence at the top of `enum X86Instruction`. Liveness analysis at `src/validation/live_out.rs:122-138` remains correct. |
| `--algorithm` other than enumerative will fail confusingly for x86 | Step 8.4: explicit early error. PR description calls out the v1 scope. |
| Integration tests require `gcc-multilib` | Step 9.2 documents the dep; CI gate documents the optional skip if the toolchain is absent. |
| `cargo-mutants` config (`.cargo/mutants.toml`) gains a large new surface, lengthening local mutation runs | Out of scope for this PR. Note in PR description that `just mutants -- --diff` is the recommended invocation while iterating. |

## Out of scope for v1 (called out explicitly)

- Stochastic / Symbolic / Hybrid / LLM search for x86. Explicit error in Step 8.4.
- CMOVcc / Jcc and the symbolic EFLAGS plumbing they would need.
- Sub-register aliasing (AL/AH/AX/EAX/RAX).
- Multi-byte NOPs in ELF patcher.
- RISC-V activation (still scaffolded only — explicitly out of scope; reuse the CliArch rejection branches as-is).
- Generalising AArch64/RISC-V/x86 onto the trait surface in `src/isa/traits.rs`. A follow-up issue should propose this refactor independently.
