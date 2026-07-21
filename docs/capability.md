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
  candidate pool. The source entry point is
  [`generate_all_instructions`](../src/search/candidate.rs). At the default
  AArch64 8-register CLI scope, `madd`/`msub` contribute `2 * 8^4` and
  `mneg`/`smulh`/`umulh` contribute `3 * 8^3`, adding 9,728 additional
  instructions to the candidate pool. The sequence space in each length bucket
  therefore grows as `pool_size^L`; use `--timeout` or smaller optimization
  windows to bound runtime.
- Hybrid and LLM remain AArch64-only.

Rewritable straight-line mnemonics accepted by the parser and Capstone bridge:

- Data movement and aliases: `mov`, `mvn`, `neg`, `negs`, `movn`, `movz`,
  `movk`
  - Register `mov` supports both 64-bit `X` and 32-bit `W` forms.
- First NEON/SIMD vertical slice: `movi` with `Vn.2d|4s, #0`, lane-wise
  wrapping `add Vd.2d|4s, Vn.2d|4s, Vm.2d|4s`, and
  `mov Xd, Vn.d[0|1]`.
  `V0..V31` are modelled as aliased 128-bit registers across arrangement
  views and may be named in `--live-out`. Concrete and SMT equivalence compare
  the full 128 bits. Other arrangements, modified immediates, vector loads,
  reductions, shuffles, and scalar `q`/`d`/`s` spellings remain out of scope.
- Arithmetic and flag-setting arithmetic: `add`, `sub`, `adds`, `subs`
- Add/subtract with carry (X-only, register form): `adc`, `adcs`, `sbc`, `sbcs`
  - Non-flag-setting `add` and `sub` support both 64-bit `X` and 32-bit `W`
    register/immediate/shifted-register forms. W extended-register arithmetic
    remains out of scope for now.
  - X-form `adds` and `subs` support register, immediate, and non-ROR
    shifted-register forms.
- Logical and inverted-logical forms: `and`, `ands`, `orr`, `eor`, `bic`,
  `bics`, `orn`, `eon`
  - Logical-immediate forms for `and`, `ands`, `orr`, `eor`, and `tst`
    support both 64-bit `X` registers and 32-bit `W` registers.
    Non-flag-setting `and`, `orr`, and `eor` also support 32-bit `W`
    register and shifted-register forms.
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
- Bit-field aliases: `ubfx`, `sbfx`, `bfi`, `bfxil`, `ubfiz`, `sbfiz` — each
  supports both 64-bit `X` and 32-bit `W` register forms (the W form zeroes the
  destination's upper 32 bits per the ARM ARM).
- Memory loads and stores (issue #68, [ADR-0007](adr/0007-memory-model.md);
  byte-addressed Z3-array memory model with sound full aliasing, whole-memory
  live-out auto-derived): `ldr`, `ldrb`, `ldrh`, `ldrsb`, `ldrsh`, `ldrsw`,
  `str`, `strb`, `strh`, `ldp`, `stp`, `ldpsw`. Single-register memory
  instructions accept immediate-offset, pre-index, post-index, register-offset,
  and register-extend addressing in supported `W`/`X`-sized forms. Pair memory
  instructions accept immediate-offset, pre-index, and post-index addressing
  only; `ldp`/`stp` cover `W` and `X` pairs, and `ldpsw` loads sign-extended
  word pairs.
  Unsized `ldr` / `str` infer `W` vs `X` width from the data register spelling.
  Zero-extending `ldrb` / `ldrh` loads and `strb` / `strh` stores use scoped
  `W`/`X` register slots.
  `ldrsb` / `ldrsh` / `ldrsw` signed loads currently accept only X-form
  destinations because the current `Ldrs` IR models X-form sign-extension.

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

- `mov`, `movzx`, `movsx`, `add`, `sub`, `and`, `or`, `xor`, `cmp`, `test`
- Single-operand: `neg`, `not`, `inc`, `dec`
- Immediate-count shifts: `shl`/`sal`, `shr`, `sar`
- Immediate-count rotates: `rol`, `ror`
- Signed multiply: `imul` (2-operand `imul rd, rs` and 3-operand `imul rd, rs, imm`)
- Load effective address: `lea` (register-base + displacement only)
- Conditional moves: `cmov<cond>`

Synthesizable-only pseudo-instruction families:

- Conditional full-width sets: `set<cond>`

The data-movement/arithmetic/logical/comparison families have register and
immediate forms where the x86 IR models them. `movzx` and `movsx` are
register-only width-changing moves: they extract the low 8 or 16 bits named by
the source alias and zero- or sign-extend them into the native-width destination
(64 bits in x86-64, 32 bits in x86-32), without changing EFLAGS. Legacy
high-byte sources (`ah`/`bh`/`ch`/`dh`) are not modelled. The 32-to-64 signed
form is the distinct `movsxd` family and remains unsupported; x86 has no
`movzx r64, r32` encoding because a 32-bit GPR write already provides that zero
extension. For the same reason, the x86-64 parser normalizes a 32-bit
destination spelling such as `movzx eax, bl` to the native-width zero-extension
IR. It rejects `movsx eax, bl`, whose sign extension into EAX followed by
architectural zero-extension is not equivalent to native-width sign extension.
`cmp` and `test` are
flag-setting: each discards its result and writes only EFLAGS (`cmp` from a
subtraction, `test` from a bitwise AND that clears CF/OF). `neg` and `not`
are single-operand: `neg` computes `rd = -rd` and sets EFLAGS as if from
`0 - rd` (CF = rd != 0), whereas `not` computes `rd = !rd` and leaves EFLAGS
unchanged (like `mov`). `inc` (`rd = rd + 1`) and `dec` (`rd = rd - 1`) are
also single-operand and set OF/SF/ZF/PF as the corresponding `add`/`sub` by 1
would, but — unlike `add`/`sub` — they preserve CF (the incoming carry flows
through unchanged). `shl`/`sal`, `shr`, and `sar` are immediate-count shifts:
the count is a compile-time constant masked to `width-1` (the CL-register-count
form is not yet modelled). A masked count of 0 leaves the register and ALL
flags unchanged; for a nonzero count SF/ZF/PF come from the result and CF is the
last bit shifted out. OF is architecturally defined only for a count of 1 and
is UNDEFINED for larger counts; the model uses the count-1 OF formula for every
nonzero count as a deterministic, internally-consistent value, so downstream
code must not rely on OF after a count > 1 shift. `sal` assembles identically to
`shl` and parses to the same IR. `rol` and `ror` are immediate-count rotates
(the CL-register-count form is not yet modelled) and differ from the shifts in
their flag effect: a rotate touches ONLY CF (plus OF for a count of 1) and
PRESERVES SF/ZF/PF/AF. A masked count of 0 leaves the register and ALL flags
unchanged. For a nonzero count, `rol` sets CF to bit 0 of the result (the bit
rotated out of the MSB) and `ror` sets CF to the result's MSB; OF is defined only
for a count of 1 (`rol`: `MSB(result) XOR CF`; `ror`: XOR of the result's two
most-significant bits) and, like the shifts, is preserved (left at its incoming
value) for count > 1. `imul` is signed multiply in two single-destination forms:
the two-operand `imul rd, rs` computes `rd = rd * rs` (low `width` bits, `rd`
read and written) and the three-operand `imul rd, rs, imm` computes
`rd = rs * imm` (`rd` written only). For both, only CF and OF are
architecturally defined: they are set iff the FULL signed product does not fit
the truncated `width`-bit destination (signed overflow), and cleared otherwise.
SF/ZF/PF are Intel-UNDEFINED; the model derives them deterministically from the
truncated result (SF = MSB, ZF = result == 0, PF = low-byte parity) so the
shared concrete/SMT lowering stays internally consistent (target and candidate
agree), and AF follows the existing convention. The one-operand widening form
(`imul rs`, writing RDX:RAX) is deferred. `lea` is modelled only in its minimal
register-base + displacement form, `lea rd, [base + disp]`, computing
`rd = base + disp` (wrapping at width). It is non-destructive (`base` is read,
`rd` is purely written, like `mov`) and affects NO flags. The index*scale
(`[base + index*scale + disp]`) and RIP/EIP-relative addressing forms are
deferred and rejected as unsupported shapes. `cmov<cond>` reads EFLAGS without
modifying them and has two register operands. The synthesizable-only
`set<cond>` pseudo-family also reads EFLAGS without modifying them and uses the
interim native-width abstraction `rd = zext(condition)`: the IR, concrete
interpreter, and SMT lowering fully overwrite `rd` with 0 or 1. Candidate
assembly emits architectural byte `SETcc` followed by same-register `MOVZX`
into the 32-bit destination; that destination write also clears bits 63:32 in
x86-64, so the emitted pair matches the full-width IR semantics.

The x86 IR retains each GPR operand's native, dword, word, low-byte, or
legacy high-byte view. Reads select the corresponding slice of the canonical
architectural register. Native writes replace the mode-width register, dword
writes zero-extend into the full GPR on x86-64, and word/byte writes preserve
the surrounding bits. Thus `rax`/`eax`/`ax`/`al`/`ah` (and their corresponding
GPR aliases) are distinct operands throughout parsing, search, concrete and
SMT execution, liveness, costing, and assembly. Legacy high-byte operands are
limited to `ah`/`bh`/`ch`/`dh` and cannot be combined with an encoding that
requires a REX prefix. x86-32 continues to reject the x86-64-only extended
register family (`r8` through `r15` and their aliases).

MOVZX/MOVSX carry an explicit 8- or 16-bit source width while keeping a
native-width destination. This preserves the width-changing operation even
though the source is stored as its canonical architectural register; display
and assembly recover the corresponding byte or word spelling. Mode-aware
x86-32 parsing accepts its 32-bit destination, while width-agnostic parsing
keeps the canonical x86-64 destination spelling.

The synthesis-only `set<cond>` pseudo-family is the exception to this
precise-width model and keeps the interim full-width abstraction described
above. Architectural byte SETcc from ELF input is rejected until #75 rather
than lifted into the full-width pseudo-IR, and its width-agnostic text spelling
is the pseudo-family's canonical full register (`setne rax`, not a
byte/word/dword alias). In x86-32, synthesized SETcc remains limited to
destinations backed by `al`/`cl`/`dl`/`bl`, because byte-register encoding
slots 4–7 name the legacy high-byte registers without a REX prefix.

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
