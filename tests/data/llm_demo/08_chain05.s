// Live-in:  x1
// Live-out: x0
// Length:   5 instructions
// Computes: x0 = x1 + 4   (chain of +1 increments — collapses to a single add)
mov x0, x1
add x0, x0, #1
add x0, x0, #1
add x0, x0, #1
add x0, x0, #1
