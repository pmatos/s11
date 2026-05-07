// Live-in: x1
// Live-out: x0
// Expected reduction: x0 = x1 - 1 directly (2 -> 1)
mov x0, x1
sub x0, x0, #1
