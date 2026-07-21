// Known one-instruction shortening fixture for the x86-64 opt path.
//
// Two identical `mov rax, 5` instructions are semantically equivalent to a
// single `mov rax, 5` (only RAX is live-out; neither MOV touches EFLAGS), so
// the enumerative search deterministically rewrites the 2-instruction window
// to 1 instruction. The trailing NOPs pad the function so the window never
// abuts the section end. Register/immediate only — the x86 IR models no
// memory operands.
.intel_syntax noprefix
.text
.globl _start
_start:
    mov rax, 5
    mov rax, 5
    nop
    nop
    nop
    nop
