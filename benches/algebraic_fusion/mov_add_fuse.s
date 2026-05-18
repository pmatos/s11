// Live-in: x1
// Live-out: x0
// Identity: MOV+ADD imm fuses into a single ADD imm.
mov x0, x1
add x0, x0, #1
