// Live-in: x1, x2, x3
// Live-out: x0
// Identity: SUB after MUL fuses into MSUB (x0 = x3 - x1*x2).
mul x0, x1, x2
sub x0, x3, x0
