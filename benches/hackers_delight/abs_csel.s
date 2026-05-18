// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-4 (alt. |x| via CSEL/CSNEG path)
// Companion to abs.s — same semantics, longer 4-instruction encoding.
mov x1, #0
sub x1, x1, x0
cmp x0, #0
csel x0, x1, x0, lt
