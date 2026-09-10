// Dynamically-linked PIE counterpart to dup_mov_imm.s (issue #838):
// same "redundant mov elimination" identity, but built as a normal
// gcc-linked `main`/`bl exit` executable (not a raw `_start`/`svc`
// syscall), so it links against the cross sysroot's real glibc and
// exercises qemu's `-L <sysroot>` dynamic-linker-resolution path —
// representative of a real target binary like binaries/arrays_opt,
// unlike the other hand-written -no-pie -nostdlib fixtures.
//
// Two identical `mov x0, #5` instructions are semantically equivalent to a
// single `mov x0, #5` (only X0 is live-out; MOVZ does not touch NZCV), so
// the enumerative search deterministically rewrites the 2-instruction
// window to 1 instruction. The optimizer's window sits entirely before
// `bl exit`, so the patch never touches the call.
.text
.global main
main:
    mov x0, #5
    mov x0, #5
    bl exit
