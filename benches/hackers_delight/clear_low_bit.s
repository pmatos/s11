// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-1 (turn off lowest set bit: x & (x-1))
sub x1, x0, #1
and x0, x0, x1
