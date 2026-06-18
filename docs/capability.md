# s11 capability matrix

This page is the canonical summary of instruction and ISA support in the
current tree. Public docs should link here instead of maintaining separate
mnemonic inventories.

## AArch64

Status: primary target. Assembly text and ELF/Capstone input share the same
parser path for accepted mnemonics. Search rewrites the straight-line prefix of
a region; supported control-flow terminators are parsed and then held fixed.
The ELF/Capstone bridge first normalizes a small set of Capstone-only aliases
that map to one existing IR instruction: Capstone `mov Xd, #imm` move-wide
aliases are normalized to single-instruction `movz`/`movn` forms when the
immediate is representable by one move-wide instruction, and Capstone
`cinc`/`cinv`/`cneg` aliases are normalized to `csinc`/`csinv`/`csneg`.
Aliases that require multiple instructions remain unsupported and make
optimization reject the selected window.

Numbered `W` registers are accepted only by width-aware parser rules (such as
logical-immediate and memory forms) or scoped W/X register slots (such as
extended-register operands and TBZ/TBNZ). Generic widthless data-processing and
CBZ/CBNZ forms still reject `w0`-`w30` because the current IR would otherwise
model 32-bit instructions with existing 64-bit semantics.

Algorithms:
- Enumerative, stochastic, symbolic, hybrid, and LLM-assisted search are
  available for AArch64.
- Enumerative search scales with the generated instruction families in its
  candidate pool. At the default AArch64 8-register CLI scope, `madd`/`msub`
  contribute `2 * 8^4` and `mneg`/`smulh`/`umulh` contribute `3 * 8^3`, or
  9,728 extra candidates per length bucket; use `--timeout` or smaller
  optimization windows to bound runtime.
- Hybrid and LLM remain AArch64-only.

Rewritable straight-line mnemonics accepted by the parser and Capstone bridge:

- Data movement and aliases: `mov`, `mvn`, `neg`, `negs`, `movn`, `movz`,
  `movk`
  - Register `mov` supports both 64-bit `X` and 32-bit `W` forms.
- Arithmetic and flag-setting arithmetic: `add`, `sub`, `adds`, `subs`
- Add/subtract with carry (X-only, register form): `adc`, `adcs`
  - Non-flag-setting `add` and `sub` support both 64-bit `X` and 32-bit `W`
    register/immediate/shifted-register forms. W extended-register arithmetic
    remains out of scope for now.
- Logical and inverted-logical forms: `and`, `ands`, `orr`, `eor`, `bic`,
  `bics`, `orn`, `eon`
  - Logical-immediate forms for `and`, `ands`, `orr`, `eor`, and `tst`
    support both 64-bit `X` registers and 32-bit `W` registers.
    Capstone `mov Wd|WSP, #imm` bitmask aliases are accepted for the
    `orr Wd|WSP, wzr, #imm` form.
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

Status: supported through the shared ISA trait-backed ELF optimization path,
with width-parameterised SMT equivalence.

Rewritable straight-line mnemonic families:

- `mov`, `add`, `sub`, `and`, `or`, `xor`, `cmp`
- Conditional moves: `cmov<cond>`

The data-movement/arithmetic/logical/comparison families have register and
immediate forms where the x86 IR models them. `cmov<cond>` has register
operands and reads EFLAGS without modifying them.

Fixed control-flow terminators:

- `j<cond>` — parsed as an opaque trailing terminator and held fixed. Search
  does not synthesize Jcc, and binary patching preserves the original branch
  bytes.

x86-64 and x86-32 support enumerative, stochastic, and symbolic search. Hybrid
and LLM remain AArch64-only.

## RISC-V

Status: scaffold-only.

The current tree has RISC-V ISA trait scaffolding, but there is no supported RISC-V opt path. User-facing RISC-V ELF optimization is rejected before a real
pipeline runs, and RISC-V machine-code emission is not yet implemented.

See [ADR-0005](adr/0005-riscv-assembler-strategy.md) for the accepted assembler
strategy: the RISC-V assembler remains unavailable until a future encoder lands.
