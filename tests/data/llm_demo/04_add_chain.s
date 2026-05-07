// Live-in: x1
// Live-out: x0
// Expected reduction: x0 = x1 + 1 + 2 -> x0 = x1 + 3 (3 -> 1)
mov x0, x1
add x0, x0, #1
add x0, x0, #2
