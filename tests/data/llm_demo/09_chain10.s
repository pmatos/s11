// Live-in:  x1, x3
// Live-out: x0
// Length:   10 instructions
// Computes: x0 = 2 * (x1 + x3)
//   with redundant moves and identity adds that should be eliminable.
mov x0, x1
mov x2, x3
add x4, x0, x2
mov x5, x4
add x6, x4, x4
sub x7, x6, x0
mov x0, x6
add x0, x0, #2
sub x0, x0, #2
add x0, x0, #0
