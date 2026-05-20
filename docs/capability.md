# s11 capability matrix

This page is the canonical summary of instruction and ISA support in the
current tree. Public docs should link here instead of maintaining separate
mnemonic inventories.

## AArch64

Status: primary target. Assembly text and ELF/Capstone input share the same
parser path for accepted mnemonics. Search rewrites the straight-line prefix of
a region; supported control-flow terminators are parsed and then held fixed.

Algorithms:
- Enumerative, stochastic, symbolic, hybrid, and LLM-assisted search are
  available for AArch64.
- Hybrid and LLM remain AArch64-only.

Rewritable straight-line mnemonics accepted by the parser and Capstone bridge:

- Data movement and aliases: `mov`, `mvn`, `neg`, `negs`, `movn`, `movz`,
  `movk`
- Arithmetic and flag-setting arithmetic: `add`, `sub`, `adds`, `subs`
- Logical and inverted-logical forms: `and`, `ands`, `orr`, `eor`, `bic`,
  `bics`, `orn`, `eon`
- Shifts and rotate: `lsl`, `lsr`, `asr`, `ror`
- Multiply/divide and multiply-accumulate: `mul`, `madd`, `msub`, `mneg`,
  `smulh`, `umulh`, `sdiv`, `udiv`
- Comparison and conditional compare: `cmp`, `cmn`, `tst`, `ccmp`, `ccmn`
- Conditional select/set: `csel`, `csinc`, `csinv`, `csneg`, `cset`, `csetm`
- Single-source bit manipulation: `clz`, `cls`, `rbit`, `rev`, `rev32`,
  `rev16`
- Standalone extend aliases: `uxtb`, `uxth`, `sxtb`, `sxth`, `sxtw`
- Bit-field aliases: `ubfx`, `sbfx`, `bfi`, `bfxil`, `ubfiz`, `sbfiz`
- Memory loads and stores (issue #68, [ADR-0007](adr/0007-memory-model.md);
  byte-addressed Z3-array memory model with sound full aliasing, whole-memory
  live-out auto-derived): `ldr`, `ldrb`, `ldrh`, `ldrsb`, `ldrsh`, `ldrsw`,
  `str`, `strb`, `strh`, `ldp`, `stp`, `ldpsw` — accepted in immediate-offset,
  pre-index, post-index, register-offset, and register-extend addressing
  forms, in both `W` and `X` widths

Fixed control-flow terminators:

- `b`, `b.<cond>`, `bl`, `br`, `ret`, `cbz`, `cbnz`, `tbz`, `tbnz`

Known gaps:

- `LDUR`, `STUR`, and `LDR (literal)` are out of scope (see ADR-0007 §9) and
  remain unsupported.
- The optimizer does not rewrite across control-flow boundaries; terminators
  are part of the parsed sequence but not produced by search.

## x86-64 / x86-32

Status: supported through a parallel x86 pipeline for ELF optimization and
width-parameterised SMT equivalence.

Supported mnemonic families:

- `mov`, `add`, `sub`, `and`, `or`, `xor`, `cmp`

Each family has register and immediate forms where the x86 IR models them.
x86-64 and x86-32 support enumerative, stochastic, and symbolic search. Hybrid
and LLM remain AArch64-only.

## RISC-V

Status: scaffold-only.

The current tree has RISC-V ISA trait scaffolding, but there is no supported RISC-V opt path. User-facing RISC-V ELF optimization is rejected before a real
pipeline runs, and RISC-V machine-code emission is not yet implemented.

See [ADR-0005](adr/0005-riscv-assembler-strategy.md) for the accepted assembler
strategy: the RISC-V assembler remains unavailable until a future encoder lands.
