// Live-in: x0, x1
// Live-out: x0
// Reference: Hacker's Delight §2-5 (overflow-free unsigned average)
// Pattern: (a & b) + ((a ^ b) >> 1).
and x2, x0, x1
eor x3, x0, x1
lsr x3, x3, #1
add x0, x2, x3
