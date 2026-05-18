// Live-in: x0, x1
// Live-out: x0
// Reference: Hacker's Delight §2-10 (difference or zero: max(a-b, 0))
sub x2, x0, x1
mov x3, #0
cmp x0, x1
csel x0, x2, x3, gt
