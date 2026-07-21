# ADR-0010: Represent x86 sub-register operands as register views

## Status

Accepted for issue #75.

## Context

The x86 IR historically stored only a canonical GPR such as `RAX`. Parsing
`rax`, `eax`, `ax`, and `al` therefore produced the same value, even though the
operands select different architectural bits and have different write
semantics. Legacy high-byte operands such as `ah` were rejected entirely.

Operand width affects every correctness boundary: concrete and SMT execution,
flag computation, liveness, code size, assembly, and search. A 32-bit write in
x86-64 clears bits 63:32, while 8/16-bit writes preserve all bits outside their
selected slice. High-byte writes select bits 15:8 rather than bits 7:0.

## Decision

`X86Register` represents an operand view consisting of:

- a canonical architectural GPR identity;
- one of native, dword, word, low-byte, or high-byte access.

The existing native constants (`RAX` through `R15`) remain the default for
programmatically constructed IR. Alias constants and parser results retain
explicit narrower views.

Architectural machine state, live-in sets, and live-out sets are always keyed
by the canonical GPR. Instruction operands retain their views until execution
or encoding. Reads extract the selected slice. Writes:

- replace the whole mode-width value for native operands;
- zero-extend dword results to the whole GPR in x86-64 and replace the whole
  GPR in x86-32;
- preserve surrounding bits for word and byte results;
- replace bits 15:8 for a high-byte result.

Instructions validate operand-view compatibility at the parser and assembler
boundaries. The legacy high-byte views are restricted to AX/BX/CX/DX and to
encodings that do not require a REX prefix.

Search carries views in its operand register pool but canonicalizes them for
state generation and liveness. Candidate generation and mutation are filtered
through the architecture's encodability check, which rejects incompatible
views before equivalence checking.

## Alternatives considered

### Separate instruction variants for every width

Variants such as `MovReg32`, `MovReg16`, `MovReg8L`, and `MovReg8H` make width
explicit but multiply every supported opcode family and every match site.
Mixed-width operations would require a combinatorial set of additional
variants. This was rejected as disproportionate and difficult to extend.

### One width field on every instruction

An instruction-wide field avoids variant multiplication for current
same-width operations. It does not naturally represent instructions whose
source and destination widths differ, notably MOVZX/MOVSX, and it still needs
an extra high-byte lane marker. This was rejected in favor of a composable
per-operand view.

### Independent architectural registers for each alias

Treating `RAX`, `EAX`, `AX`, `AL`, and `AH` as independent state keys makes
ordinary maps simple but loses architectural aliasing and would require
cross-register synchronization after every write. This was rejected as
error-prone in both concrete and SMT state.

## Consequences

The IR can round-trip sub-register spellings and model their semantics without
new opcode variants. Future mixed-width instructions can reuse the same
operand representation.

Every state and liveness boundary must canonicalize register views. Missing
that step would split one architectural GPR into several independent values,
so canonicalization and partial-store behavior require dedicated regressions.
