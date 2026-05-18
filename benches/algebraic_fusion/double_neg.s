// Live-in: x1
// Live-out: x0
// Identity: -(-x) ≡ x — two SUB-from-zero ops cancel back to MOV.
mov x0, #0
sub x0, x0, x1
mov x2, #0
sub x0, x2, x0
