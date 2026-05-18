// Live-in:
// Live-out: x0
// Identity: MOV #0 ≡ EOR x0,x0,x0 (zeroing idiom). Each form is one
// instruction; the bench measures whether the optimizer recognises
// the equivalence rather than shortening.
mov x0, #0
