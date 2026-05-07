// Live-in: x1
// Live-out: x0
// Expected reduction: mov + add (2) -> add (1)
mov x0, x1
add x0, x0, #1
