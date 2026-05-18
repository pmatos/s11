// Live-in: x1, x2, x3
// Live-out: x0
// Identity: MUL+ADD fuses into MADD.
mul x0, x1, x2
add x0, x0, x3
