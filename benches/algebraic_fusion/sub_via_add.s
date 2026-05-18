// Live-in: x1
// Live-out: x0
// Identity: MOV+SUB imm collapses into a single SUB imm.
mov x0, x1
sub x0, x0, #1
