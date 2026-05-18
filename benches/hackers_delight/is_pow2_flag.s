// Live-in: x0
// Live-out: ;nzcv
// Reference: Hacker's Delight §2-1 (x is power-of-two iff x & (x-1) == 0)
// Output via NZCV: Z=1 means x was a power of two (or zero).
sub x1, x0, #1
and x0, x0, x1
cmp x0, #0
