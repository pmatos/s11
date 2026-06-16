# ADR-0004 — Collapse parallel AArch64 / x86 / RISC-V pipelines onto the `ISA` trait surface

Status: Accepted
Date: 2026-05-16

## Context

Issue #77 called for collapsing the parallel AArch64, x86 and RISC-V pipelines onto the existing trait surface in `src/isa/traits.rs`. At planning time the `ISA` / `InstructionType` / `OperandType` / `RegisterType` / `InstructionGenerator` traits had impls on every backend, but four others — `ConcreteExecutor`, `SymbolicExecutor`, `CostModel`, `Assembler` — had **no implementations** and were bypassed by free functions in `src/semantics/{concrete,smt,cost,equivalence}.rs` and their `_x86` siblings, plus `src/assembler/{mod,x86}.rs`. The search layer (`src/search/`), the validation layer (`src/validation/`), and the CLI in `src/main.rs` referenced `crate::ir::Instruction` directly, with a duplicated x86 pipeline (`optimize_elf_binary_x86`, `convert_to_x86_ir`, etc.) sitting beside the AArch64 path. RISC-V was rejected even though `src/isa/riscv.rs` implemented the existing trait surface.

The refactor was planned in three stages — (1) lift AArch64 onto the four trait gaps as a no-functional-change refactor, (2) port x86 onto the same surface and remove consumer-facing x86 bypasses, (3) wire RISC-V through end-to-end. Several cross-cutting design choices were needed before stage 1 code began, and once chosen they thread through every consumer. This ADR records those choices.

Implementation status as of 2026-06-16: stages 1 and 2 have landed for AArch64 and x86. Generic equivalence/search live on the trait surface, x86 live-out uses `RegisterSet<X86Register>`, x86 candidates/costs flow through ISA trait impls, and `s11 opt` uses one shared ELF optimization driver with per-architecture hooks. The x86 concrete/SMT/cost modules remain as backend implementation details behind the trait impls. RISC-V remains scaffold-only with no supported opt path because machine-code emission is not yet implemented.

The decisions below are not a menu of alternatives. They are commitments made in the plan at `.ultraplan/unify-isa-traits.md` after parallel codebase exploration and adversarial review.

## Decisions

### 1. Width as an associated type `type Width: BVWidth` on `ISA`

Width threads as an associated type, not a const generic. A new `BVWidth` trait with `const BITS: u32;` and `type Value: Copy + Debug + Eq + Hash;` is added beside `ISA` in `src/isa/traits.rs`. Marker types `U32` and `U64` implement `BVWidth`. `ISA::register_width()` (`src/isa/traits.rs:111`) keeps its current signature but returns `Self::Width::BITS` by default.

Rationale: bounds explosion is worse with const generics in current Rust (each generic function picks up an `<const W: u32>` parameter that has to be repeated and constrained at every callsite); const generics also cannot be lifted into trait associated types without `feature(generic_const_exprs)`. The associated-type variant mirrors how `X86_64` and `X86_32` already share one instruction enum while differing in metadata (`src/isa/x86.rs:321-388`).

### 2. Stochastic `Mutator` as `type Mutator` on `ISA`

The free `Mutator` type (`src/search/stochastic/mutation.rs:71-100`) becomes accessible via `<I as ISA>::Mutator`. A new helper trait `ISAMutator<I: InstructionType>` defines the surface (`new`, `mutate`, `default_weights`). The AArch64 mutator body — including the `Operand::ExtendedRegister` handling at `mutation.rs:45,247` added by PR #144 — stays in `src/search/stochastic/mutation.rs`; only a newtype wrapper `AArch64Mutator(Mutator)` is added at the bottom of the file with the `ISAMutator<Instruction>` impl.

Rationale: `InstructionGenerator::mutate` (`src/isa/traits.rs:204-210`) already exists but no consumer routes through it; stochastic search uses its own free `Mutator`. Promoting the free type to `<I as ISA>::Mutator` keeps the existing AArch64 behaviour byte-identical (no file move means the cyclic dep on `crate::search::candidate::generate_random_instruction` at `mutation.rs:14,778` is contained). `InstructionGenerator::mutate` survives as the single-instruction mutate primitive; `ISAMutator` carries the multi-strategy machinery.

### 3. Parser stays AArch64-only until stage 3

A `<I as ISA>::Parser` associated type with an `ISAParser<I>` helper trait is introduced in stage 3 step 25. Until then, `parser::parse_line` (`src/parser/mod.rs:1063-1186`) stays AArch64-only. When the associated type lands, `AArch64Parser` is a thin newtype that delegates to the existing `parse_line` body — the project CLAUDE.md `convert_to_ir → parse_line` delegation contract is preserved byte-for-byte; x86 keeps its own `convert_to_x86_ir` (`src/main.rs:969-1004`) without a corresponding `parse_line`, and RISC-V gets `convert_to_riscv_ir`.

Rationale: text-input flows (`s11 equiv`, `--algorithm llm`) are AArch64-only for the foreseeable future; the binary-path Capstone → IR conversion is already per-ISA (`convert_to_ir`, `convert_to_x86_ir`). A premature generic parser would force x86 and RISC-V to ship asm-text parsers they don't currently need.

### 4. `OperandType` is **not** extended to carry `ExtendedRegister`

`Operand::ExtendedRegister` (introduced by PR #144) carries an `ExtendKind` and shift amount. The current `OperandType` trait surface (`src/isa/traits.rs:34-63`) — `as_register / as_immediate / from_register / from_immediate` — cannot represent this losslessly. Rather than extend the trait to admit it, the mutator (decision 2) stays per-ISA and so does any code that needs to round-trip the full operand grammar. `OperandType` keeps its current scope: a small lowest-common-denominator surface used by code that doesn't need full operand structure.

Rationale: the only consumer that round-trips full operand structure is the stochastic mutator, and mutators are already per-ISA. Generalising `OperandType` to cover every ISA's operand grammar (extended registers for AArch64, ModR/M-shaped operands for x86, future RISC-V operand encodings) would balloon the trait and provide no real abstraction win.

### 5. `RegisterSet<R>` replaces `LiveOut` and `X86LiveOutMask`; `flags_live` lives on the mask

A generic `pub struct RegisterSet<R: RegisterType> { regs: HashSet<R>, flags_live: bool }` lives in `src/semantics/live_out.rs`. AArch64's `LiveOut` is the type alias `pub type LiveOut = RegisterSet<crate::ir::Register>;`. Stage 2 deleted `X86LiveOutMask` and moved x86 callers to `RegisterSet<X86Register>`. RISC-V uses `RegisterSet<RiscVRegister>` with `flags_live` always `false`.

The neutral name `RegisterSet` (closes #85) acknowledges that the same shape carries both live-in (`compute_live_in_registers`) and live-out sets — previously the AArch64 path used `LiveOutRegisters` for both, which surprised readers. The earlier working name `LiveOutMask<R>` from the original ADR draft was renamed during stage 1 step 9 to land both renames in a single PR.

Today's asymmetry — x86 puts `flags_live` on the mask, AArch64 puts it on `EquivalenceConfig.flags_live` — resolves in x86's favour. The AArch64 `EquivalenceConfig.flags_live` field is removed in stage 1 step 9; consumers consult `live_out.flags_live()` instead.

Rationale: `flags_live` is a property of the live-out contract, not of the equivalence configuration. The x86 location is the principled one. ADR-0002 ("LLM-assisted search MVP refuses targets with flags live-out") remains the authoritative statement about how `flags_live` is propagated for the LLM flow; this ADR only changes *where* the bit is stored.

### 6. `ConcreteValue` keeps `u64` storage and masks on **write**

`ConcreteValue` (`src/semantics/state.rs:224`) keeps its `pub u64` field. A new `ConcreteValue::new(width: u32, raw: u64)` constructor applies `mask_to_width(raw, width)` (`src/semantics/state.rs:189-197`) before storing. All write paths route through this constructor or through `ConcreteMachineState::set_register`, which already masks on write for x86 at `src/semantics/state.rs:374-378`. Reads return the stored `u64` unchanged.

Rationale: mask-on-read is the trap. The same `u64` field, written by two callers under different widths, would compare differently under `Hash`/`Eq` (and silently diverge in `find_counterexample` diff loops at `src/semantics/equivalence.rs:342-431`) even though both values mask to the same canonical form. Mask-on-write commits the canonical form to memory and matches the existing x86 invariant.

### 7. `type Flags` bounds; `FlagsAnalysis` helper trait introduced in stage 1 step 5

`ISA` gains `type Flags: Clone + Debug + Default + PartialEq + Eq + Hash;`. AArch64 sets `type Flags = ConditionFlags`, x86 sets `type Flags = Eflags`, RISC-V sets `type Flags = ();`. A new helper trait

```
pub trait FlagsAnalysis<I: InstructionType> {
    fn modifies_flags(instr: &I) -> bool;
    fn reads_flags(instr: &I) -> bool;
}
```

is added in stage 1 step 5 with one impl per ISA marker. `equivalence::flag_writers_diverge` (`src/semantics/equivalence.rs:32-72`) and `validation::live_out::flags_live_out` (`src/validation/live_out.rs:96`) both consume `FlagsAnalysis::modifies_flags`, NOT `InstructionType::has_side_effects`. The x86 `has_side_effects` impl (`src/isa/x86.rs:283-291`) returns `true` for everything except `MOV`, which is much broader than flag-writing and would over-trigger; the principled hook is `modifies_flags`.

Rationale: keeping flag analysis as a separate trait (not a method on `InstructionType`) avoids a "default impl returns false, easy to forget to override" trap. The `FlagsAnalysis<I> for AArch64` impl delegates to the existing inherent `Instruction::modifies_flags()` / `Instruction::reads_flags()` (defined in `src/ir/instructions.rs`).

### 8. RISC-V assembler strategy is deferred to ADR-0005

`dynasm-rs` 5.0.0 (`Cargo.toml:18-19`) has no RISC-V backend. The choice between (a) an alternative encoder crate (e.g. `riscv-encoding`), (b) shipping `s11` for RISC-V without ELF patching, or (c) subprocessing to `riscv64-linux-gnu-as` is non-trivial enough to warrant its own ADR. ADR-0005 will be written at stage 3 step 22, immediately before the assembler impl is added to `src/isa/riscv.rs`.

Rationale: stage 1 and stage 2 are unaffected by this decision; deferring it does not block anything. Forcing it now would either prematurely commit a dependency choice or stall the refactor on an irrelevant question.

## Consequences

**Positive:**
- The four trait gaps (`ConcreteExecutor`, `SymbolicExecutor`, `CostModel`, `Assembler`) get their first implementations and start carrying real weight. The trait surface stops being aspirational.
- Consumer-facing x86 bypasses have disappeared by stage 2: `src/search/candidate_x86.rs`, `X86LiveOutMask`, `X86EquivalenceConfig`, `check_equivalence_x86`, and `optimize_elf_binary_x86` are removed. The remaining x86 concrete/SMT/cost files stay as backend implementation details behind trait impls.
- A single principled width abstraction (`type Width: BVWidth`) replaces today's scattered hardcoded `64` literals in `src/semantics/smt.rs` and `src/semantics/concrete.rs` (~91 sites per the exploration audit).
- The `flag_writers_diverge` substitution moves from "AArch64 inherent method" to "trait dispatch", which means x86 stops being silently mishandled by any future consumer that reaches for `has_side_effects`.
- RISC-V's existing 1185 lines of trait scaffolding in `src/isa/riscv.rs` actually get exercised once the consumer layer is generic.

**Negative / scope:**
- Stage 1 is a no-functional-change refactor for AArch64. It moves a lot of code without adding any new capability. Reviewer attention has to come from the safety-net tests (stage 1 step 2: per-opcode SMT-vs-concrete parity, parallel clean-shutdown, mutation encodability invariant), not from new behaviour.
- Bounds get verbose at use sites. A worker that needs concrete + symbolic + cost + generator + assembler picks up four trait bounds plus `I::Instruction: 'static + Send + Sync`. If the noise becomes painful, the plan permits introducing an umbrella `trait SuperoptimizerISA: ISA where ...` — but that's a stage-1-late call, not a stage-0 commitment.
- The LLM-assisted search stays AArch64-only by explicit constraint (`impl SearchAlgorithm<AArch64> for LlmSearch` in stage 1 step 13). ADR-0003 already documented the AArch64-only prompt and parse path; this ADR does not change that.
- Operand grammar stays per-ISA (decision 4). Anyone who later wants a generic optimizer pass that walks operand structure will need to either add a per-ISA visitor or extend `OperandType`.

**Reversibility:**
- Decision 1 (width as associated type vs const generic) is the hardest to reverse — every generic function in the refactored consumer layer depends on it. Switching to const generics later means re-touching every `<I: ISA>` bound. Picked deliberately as the safer choice given today's Rust.
- Decision 2 (`type Mutator` on `ISA` vs on `InstructionGenerator`) is moderately reversible. Moving the associated type later means updating every ISA impl block, but no consumer signature changes (consumers reach through the trait either way).
- Decision 5 (`RegisterSet<R>` with `flags_live` on the mask) is reversible by promoting `flags_live` back to `EquivalenceConfig` or to a third location; every consumer of `flags_live` is contained in `src/semantics/equivalence.rs` and `src/validation/live_out.rs`.
- Decisions 3, 4, 6, 7, 8 are all individually reversible without disturbing the rest of the plan. Decision 8 in particular is deliberately deferred.
