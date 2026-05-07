// Live-in:  x1, x3
// Live-out: x0
// Length:   20 instructions
// Computes: x0 = (x1 + 5) * (x3 - 1)   (same expression as 10_chain15.s,
//   padded with more dead writes and zero-net-effect arithmetic on x0).
mov x0, x1
add x0, x0, #5
mov x2, x3
sub x2, x2, #1
mul x4, x0, x2
mov x5, x4
mov x6, x5
add x7, x6, x5
mov x0, x4
add x0, x0, x0
sub x0, x0, x4
add x0, x0, #0
sub x0, x0, #0
add x8, x0, #1
mov x9, x8
mov x10, x4
add x10, x10, x10
sub x11, x0, x4
add x0, x0, x11
mov x12, x0
