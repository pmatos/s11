// Live-in: x1
// Live-out: x0
// Expected reduction: x0 = x1 + x1 -> lsl x0, x1, #1 (or single add) (2 -> 1)
mov x0, x1
add x0, x0, x1
