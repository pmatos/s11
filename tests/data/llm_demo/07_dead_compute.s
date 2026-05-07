// Live-in: x1
// Live-out: x0
// Expected reduction: dead computation in x2 can be removed (3 -> 2 or fewer)
mov x0, x1
add x2, x1, #100
add x0, x0, #5
