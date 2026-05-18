// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-1 (isolate lowest set bit: x & -x)
// AArch64 has no NEG mnemonic in s11's pool; build via SUB from XZR-substitute.
mov x1, #0
sub x1, x1, x0
and x0, x0, x1
