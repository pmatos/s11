// Live-in: x0, x1
// Live-out: x0
// Reference: Hacker's Delight §2-4 (conditional negate: if x1<0 return -x0 else x0)
// CSNEG-based form should be discoverable.
mov x2, #0
sub x2, x2, x0
cmp x1, #0
csel x0, x2, x0, lt
