//! x86 stochastic-search candidate-space policy.
//!
//! This is the single home for *which* x86 candidates the stochastic and
//! enumerative searches may propose and how a candidate is mutated: the
//! rewritable-opcode pool, the CMOVcc distinct-register rule, the default
//! register / immediate pools, the opcode -> variant dispatch table, and the
//! operand-rewrite tables. The generator ([`X86InstructionGenerator`]) and the
//! MCMC mutator ([`X86Mutator`]) are kept in the same module because they are
//! deliberately RNG-lock-stepped: both route opcode selection through
//! [`build_x86_instruction_by_opcode`] and both gate the extra distinct-source
//! CMOV draw on the same opcode id, so their streams must not drift.
//!
//! Encodability lives one seam over in [`super::encoding`]; this module only
//! decides candidate *shape*, never machine-code legality.

use super::encoding::{
    x86_extension_source_ok, x86_mov_imm_ok, x86_mov_operand_immediate_ok, x86_non_mov_imm_ok,
    x86_operand_immediate_ok, x86_register_ok, x86_register_pair_ok, x86_shift_count_imm8_ok,
};
use super::{X86Condition, X86Instruction, X86Register, X86RegisterView};
use crate::isa::traits::InstructionGenerator;
use rand::{Rng, RngExt};

/// x86 mutator for stochastic search. Carries filtered register and
/// immediate pools (Mode32 excludes R8-R15 once at construction, and
/// immediates are split by MOV vs non-MOV encodability) plus the four
/// operator weights borrowed from the AArch64 `Mutator`.
///
/// **Destructive-form invariant** (`src/isa/x86.rs:150-158`): every
/// non-MOV variant has `rd` in `source_registers()`. Mutating any
/// single operand slot preserves this — there is no path that
/// "splits" rd and rs into a shape that drops a source.
///
/// `Default` yields the x86-64 / 8-register baseline so
/// `<X86_64 as ISA>::Mutator = X86Mutator` produces a usable instance
/// from `X86Mutator::default()` if a caller has nothing better.
#[derive(Debug, Clone)]
pub struct X86Mutator {
    registers: Vec<X86Register>,
    mov_immediates: Vec<i64>,
    non_mov_immediates: Vec<i64>,
    // Shift counts encode as imm8 (`0..=255`), a stricter range than the
    // arithmetic/logical immediates, so they are filtered into their own pool
    // at construction. See `x86_shift_count_imm8_ok`.
    shift_counts: Vec<i64>,
    mode: crate::assembler::x86::X86Mode,
    weights: crate::search::config::MutationWeights,
}

impl X86Mutator {
    /// Construct a mutator. `mode` filters extended registers (Mode32
    /// excludes R8-R15) and immediate pools once at construction, then
    /// remains available for opcode-bridge immediate validation.
    /// Downstream mutation therefore cannot reintroduce extended
    /// registers or immediates that the target opcode class cannot encode.
    pub fn new(
        registers: Vec<X86Register>,
        immediates: Vec<i64>,
        weights: crate::search::config::MutationWeights,
        mode: crate::assembler::x86::X86Mode,
    ) -> Self {
        let registers = registers
            .into_iter()
            .filter(|r| r.is_available_in(mode))
            .collect();
        let mov_immediates = immediates
            .iter()
            .copied()
            .filter(|&imm| x86_mov_imm_ok(mode, imm))
            .collect();
        let shift_counts = immediates
            .iter()
            .copied()
            .filter(|&imm| x86_shift_count_imm8_ok(imm))
            .collect();
        let non_mov_immediates = immediates
            .into_iter()
            .filter(|&imm| x86_non_mov_imm_ok(mode, imm))
            .collect();
        Self {
            registers,
            mov_immediates,
            non_mov_immediates,
            shift_counts,
            mode,
            weights,
        }
    }

    fn pick_register<R: rand::RngExt>(&self, rng: &mut R) -> Option<X86Register> {
        if self.registers.is_empty() {
            None
        } else {
            Some(self.registers[rng.random_range(0..self.registers.len())])
        }
    }

    fn pick_mov_immediate<R: rand::RngExt>(&self, rng: &mut R) -> i64 {
        if self.mov_immediates.is_empty() {
            0
        } else {
            self.mov_immediates[rng.random_range(0..self.mov_immediates.len())]
        }
    }

    fn pick_non_mov_immediate<R: rand::RngExt>(&self, rng: &mut R) -> i64 {
        if self.non_mov_immediates.is_empty() {
            0
        } else {
            self.non_mov_immediates[rng.random_range(0..self.non_mov_immediates.len())]
        }
    }

    fn keep_or_pick_mov_immediate<R: rand::RngExt>(&self, rng: &mut R, imm: i64) -> i64 {
        if x86_mov_imm_ok(self.mode, imm) {
            imm
        } else {
            self.pick_mov_immediate(rng)
        }
    }

    fn keep_or_pick_non_mov_immediate<R: rand::RngExt>(&self, rng: &mut R, imm: i64) -> i64 {
        if x86_non_mov_imm_ok(self.mode, imm) {
            imm
        } else {
            self.pick_non_mov_immediate(rng)
        }
    }

    /// Draw a shift count from the imm8-encodable pool. Falls back to 1 (the
    /// canonical single-bit shift) when the pool holds no encodable count, so
    /// a drawn shift is always assemblable.
    fn pick_shift_count<R: rand::RngExt>(&self, rng: &mut R) -> i64 {
        if self.shift_counts.is_empty() {
            1
        } else {
            self.shift_counts[rng.random_range(0..self.shift_counts.len())]
        }
    }

    fn keep_or_pick_shift_count<R: rand::RngExt>(&self, rng: &mut R, imm: i64) -> i64 {
        if x86_shift_count_imm8_ok(imm) {
            imm
        } else {
            self.pick_shift_count(rng)
        }
    }

    fn pick_condition<R: rand::RngExt>(&self, rng: &mut R) -> X86Condition {
        X86Condition::ALL[rng.random_range(0..X86Condition::ALL.len())]
    }

    fn pick_extension_width<R: rand::RngExt>(&self, rng: &mut R) -> u32 {
        if rng.random_bool(0.5) { 8 } else { 16 }
    }

    fn pick_extension_source<R: rand::RngExt>(
        &self,
        rng: &mut R,
        src_width: u32,
    ) -> Option<X86Register> {
        let available = self
            .registers
            .iter()
            .copied()
            .filter(|&reg| x86_extension_source_ok(self.mode, reg, src_width))
            .collect::<Vec<_>>();
        if available.is_empty() {
            None
        } else {
            Some(available[rng.random_range(0..available.len())])
        }
    }

    fn random_instruction<R: rand::RngExt>(&self, rng: &mut R) -> Option<X86Instruction> {
        if self.registers.is_empty() {
            return None;
        }
        // Rewritable variants only, including CMOVcc, SETcc, and the two
        // width-changing move families (MOVZX/MOVSX). Source width is drawn
        // unconditionally to keep the shared generator's RNG stream in
        // lock-step.
        // The RNG draw order/count MUST stay in lock-step with the shared
        // free helper `generate_random_rewritable_x86_instruction`
        // (opcode → rd → rs → imm → cond → src_width, all six drawn
        // unconditionally)
        // so callers that interleave the two stay deterministic. Two
        // helper behaviours must be mirrored exactly: (1) the
        // CMOV opcode slot is skipped unless the pool holds a distinct
        // register pair (a self-CMOV is a no-op), and (2) CMOV draws its
        // source via an extra `pick_register_except` so `rs != rd`. The
        // #593 behaviour change is *which* prefiltered pool the single imm
        // draw indexes: opcode 1 (MOV) uses the MOVABS-capable `mov`
        // pool, every other imm form uses the non-MOV pool.
        // CMOV with rd == rs is a no-op, so its opcode slot is only offered
        // when the pool holds a distinct pair. This MUST mirror
        // `generate_random_rewritable_x86_instruction` so the two stay in
        // lock-step (stream parity) while both filter self-CMOV.
        let opcode =
            pick_random_rewritable_opcode(rng, has_distinct_register_pair(&self.registers));
        let rd = self.pick_register(rng)?;
        let rs = self.pick_register(rng)?;
        let imm = if opcode == 1 {
            self.pick_mov_immediate(rng)
        } else {
            self.pick_non_mov_immediate(rng)
        };
        let cond = X86Condition::ALL[rng.random_range(0..X86Condition::ALL.len())];
        let mut src_width = self.pick_extension_width(rng);
        // The CMOV slot resolves a distinct source register via an extra
        // `pick_register_except` draw; every other opcode reuses the `rs`
        // drawn above. This extra draw MUST stay conditional on the CMOV
        // opcode to preserve the RNG stream that the parity test
        // `x86_mutator_random_instruction_matches_shared_generator_stream`
        // pins against `generate_random_rewritable_x86_instruction`.
        let mut final_rs = if opcode == X86_CMOV_OPCODE {
            pick_register_except(rng, &self.registers, rd)
                .expect("CMOV opcode requires a distinct register pair")
        } else {
            rs
        };
        if matches!(opcode, 28 | 29) && !x86_extension_source_ok(self.mode, final_rs, src_width) {
            if let Some(encodable) = self.pick_extension_source(rng, src_width) {
                final_rs = encodable;
            } else {
                src_width = 16;
                final_rs = self.pick_extension_source(rng, src_width)?;
            }
        }
        Some(build_x86_instruction_by_opcode(
            opcode, rd, final_rs, imm, cond, src_width,
        ))
    }

    fn mutate_operand<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.is_empty() {
            return;
        }
        let idx = rng.random_range(0..sequence.len());
        if self.registers.is_empty() {
            match &mut sequence[idx] {
                X86Instruction::MovImm { imm, .. } => *imm = self.pick_mov_immediate(rng),
                X86Instruction::AddImm { imm, .. }
                | X86Instruction::SubImm { imm, .. }
                | X86Instruction::AndImm { imm, .. }
                | X86Instruction::OrImm { imm, .. }
                | X86Instruction::XorImm { imm, .. }
                | X86Instruction::CmpImm { imm, .. }
                // The 3-operand IMUL immediate draws from the imm32 pool too.
                | X86Instruction::ImulRegImm { imm, .. }
                | X86Instruction::TestImm { imm, .. } => *imm = self.pick_non_mov_immediate(rng),
                // LEA's displacement is a signed disp32; mutate it from the
                // non-MOV (imm32) pool even with no register pool.
                X86Instruction::Lea { disp, .. } => *disp = self.pick_non_mov_immediate(rng),
                // SHL / SHR / SAR / ROL / ROR carry an imm8 count; mutate it
                // from the imm8-encodable pool even with no register pool.
                X86Instruction::Shl { imm, .. }
                | X86Instruction::Shr { imm, .. }
                | X86Instruction::Sar { imm, .. }
                | X86Instruction::Rol { imm, .. }
                | X86Instruction::Ror { imm, .. } => *imm = self.pick_shift_count(rng),
                X86Instruction::MovReg { .. }
                | X86Instruction::Movzx { .. }
                | X86Instruction::Movsx { .. }
                | X86Instruction::AddReg { .. }
                | X86Instruction::SubReg { .. }
                | X86Instruction::AndReg { .. }
                | X86Instruction::OrReg { .. }
                | X86Instruction::XorReg { .. }
                | X86Instruction::CmpReg { .. }
                | X86Instruction::TestReg { .. }
                | X86Instruction::Neg { .. }
                | X86Instruction::Not { .. }
                | X86Instruction::Inc { .. }
                | X86Instruction::Dec { .. }
                // IMUL rd, rs has no immediate, so it is a no-op with no pool.
                | X86Instruction::ImulReg { .. }
                | X86Instruction::Jcc { .. } => {}
                X86Instruction::Cmov { cond, .. }
                | X86Instruction::Setcc { cond, .. } => *cond = self.pick_condition(rng),
            }
            return;
        }
        match &mut sequence[idx] {
            X86Instruction::MovReg { rd, rs } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *rs = self.pick_register(rng).expect("register pool is non-empty");
                }
            }
            X86Instruction::Movzx {
                rd,
                rs,
                src_width,
            }
            | X86Instruction::Movsx {
                rd,
                rs,
                src_width,
            } => match rng.random_range(0..3u32) {
                0 => *rd = self.pick_register(rng).expect("register pool is non-empty"),
                1 => {
                    if let Some(new_rs) = self.pick_extension_source(rng, *src_width) {
                        *rs = new_rs;
                    }
                }
                _ => {
                    let new_width = self.pick_extension_width(rng);
                    if x86_extension_source_ok(self.mode, *rs, new_width) {
                        *src_width = new_width;
                    } else if let Some(new_rs) = self.pick_extension_source(rng, new_width) {
                        *src_width = new_width;
                        *rs = new_rs;
                    }
                }
            },
            X86Instruction::MovImm { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *imm = self.pick_mov_immediate(rng);
                }
            }
            X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            // IMUL rd, rs mutates either register slot, like the other reg-reg
            // forms.
            | X86Instruction::ImulReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *rs = self.pick_register(rng).expect("register pool is non-empty");
                }
            }
            // IMUL rd, rs, imm mutates one of the three operand slots.
            X86Instruction::ImulRegImm { rd, rs, imm } => match rng.random_range(0..3u32) {
                0 => *rd = self.pick_register(rng).expect("register pool is non-empty"),
                1 => *rs = self.pick_register(rng).expect("register pool is non-empty"),
                _ => *imm = self.pick_non_mov_immediate(rng),
            },
            // LEA rd, [base + disp] mutates one of the three operand slots: the
            // destination register, the base register, or the disp32.
            X86Instruction::Lea { rd, base, disp } => match rng.random_range(0..3u32) {
                0 => *rd = self.pick_register(rng).expect("register pool is non-empty"),
                1 => *base = self.pick_register(rng).expect("register pool is non-empty"),
                _ => *disp = self.pick_non_mov_immediate(rng),
            },
            X86Instruction::AddImm { rd, imm }
            | X86Instruction::SubImm { rd, imm }
            | X86Instruction::AndImm { rd, imm }
            | X86Instruction::OrImm { rd, imm }
            | X86Instruction::XorImm { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *imm = self.pick_non_mov_immediate(rng);
                }
            }
            X86Instruction::CmpReg { rn, rs } | X86Instruction::TestReg { rn, rs } => {
                if rng.random_bool(0.5) {
                    *rn = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *rs = self.pick_register(rng).expect("register pool is non-empty");
                }
            }
            X86Instruction::CmpImm { rn, imm } | X86Instruction::TestImm { rn, imm } => {
                if rng.random_bool(0.5) {
                    *rn = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *imm = self.pick_non_mov_immediate(rng);
                }
            }
            // SHL / SHR / SAR / ROL / ROR mutate either the destination register
            // or the imm8 count.
            X86Instruction::Shl { rd, imm }
            | X86Instruction::Shr { rd, imm }
            | X86Instruction::Sar { rd, imm }
            | X86Instruction::Rol { rd, imm }
            | X86Instruction::Ror { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *imm = self.pick_shift_count(rng);
                }
            }
            // NEG / NOT / INC / DEC have a single register operand; mutate it.
            X86Instruction::Neg { rd }
            | X86Instruction::Not { rd }
            | X86Instruction::Inc { rd }
            | X86Instruction::Dec { rd } => {
                *rd = self.pick_register(rng).expect("register pool is non-empty");
            }
            X86Instruction::Cmov { rd, rs, cond } => {
                // Treat the condition code as a mutable operand alongside
                // the destination and source registers. CMOVcc with rd == rs
                // is a no-op, so register mutation samples from the pool minus
                // the other operand to avoid collapsing into a self-CMOV.
                match rng.random_range(0..3u32) {
                    0 => *rd = pick_register_except(rng, &self.registers, *rs).unwrap_or(*rd),
                    1 => *rs = pick_register_except(rng, &self.registers, *rd).unwrap_or(*rs),
                    _ => *cond = self.pick_condition(rng),
                }
            }
            X86Instruction::Setcc { rd, cond } => {
                if rng.random_bool(0.5) {
                    *rd = self.pick_register(rng).expect("register pool is non-empty");
                } else {
                    *cond = self.pick_condition(rng);
                }
            }
            // Jcc is a terminator; mutation never reaches it because the
            // search pool excludes terminators. Keep the arm as a no-op
            // so an accidental call doesn't panic.
            X86Instruction::Jcc { .. } => {}
        }
    }

    /// Swap the variant of a randomly-chosen instruction while keeping
    /// its operand shape (reg-reg → reg-reg, reg-imm → reg-imm). CMP
    /// has no rd, so it only swaps between register and immediate CMP
    /// forms.
    ///
    /// Note the deliberate asymmetry: the reg-reg and reg-imm groups
    /// sample from a range that includes the current variant, so they may
    /// produce an identity mutation. CMP, by contrast, always bridges
    /// `CmpReg` ↔ `CmpImm`, so a CMP opcode mutation is guaranteed to
    /// change the form. This is intentional, not an oversight.
    fn mutate_opcode<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.is_empty() {
            return;
        }
        let idx = rng.random_range(0..sequence.len());
        let current = sequence[idx];
        sequence[idx] = match current {
            X86Instruction::MovReg { rd, rs }
            | X86Instruction::AddReg { rd, rs }
            | X86Instruction::SubReg { rd, rs }
            | X86Instruction::AndReg { rd, rs }
            | X86Instruction::OrReg { rd, rs }
            | X86Instruction::XorReg { rd, rs } => match rng.random_range(0..6u32) {
                0 => X86Instruction::MovReg { rd, rs },
                1 => X86Instruction::AddReg { rd, rs },
                2 => X86Instruction::SubReg { rd, rs },
                3 => X86Instruction::AndReg { rd, rs },
                4 => X86Instruction::OrReg { rd, rs },
                _ => X86Instruction::XorReg { rd, rs },
            },
            X86Instruction::MovImm { rd, imm }
            | X86Instruction::AddImm { rd, imm }
            | X86Instruction::SubImm { rd, imm }
            | X86Instruction::AndImm { rd, imm }
            | X86Instruction::OrImm { rd, imm }
            | X86Instruction::XorImm { rd, imm } => match rng.random_range(0..6u32) {
                0 => X86Instruction::MovImm {
                    rd,
                    imm: self.keep_or_pick_mov_immediate(rng, imm),
                },
                1 => X86Instruction::AddImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
                2 => X86Instruction::SubImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
                3 => X86Instruction::AndImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
                4 => X86Instruction::OrImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
                _ => X86Instruction::XorImm {
                    rd,
                    imm: self.keep_or_pick_non_mov_immediate(rng, imm),
                },
            },
            X86Instruction::CmpReg { rn, .. } => X86Instruction::CmpImm {
                rn,
                imm: self.pick_non_mov_immediate(rng),
            },
            X86Instruction::CmpImm { rn, .. } => match self.pick_register(rng) {
                Some(rs) => X86Instruction::CmpReg { rn, rs },
                None => current,
            },
            // TEST mirrors CMP: the opcode-bridge mutation always flips
            // between its register and immediate forms.
            X86Instruction::TestReg { rn, .. } => X86Instruction::TestImm {
                rn,
                imm: self.pick_non_mov_immediate(rng),
            },
            X86Instruction::TestImm { rn, .. } => match self.pick_register(rng) {
                Some(rs) => X86Instruction::TestReg { rn, rs },
                None => current,
            },
            X86Instruction::Movzx { rd, rs, src_width }
            | X86Instruction::Movsx { rd, rs, src_width } => {
                if rng.random_bool(0.5) {
                    X86Instruction::Movzx { rd, rs, src_width }
                } else {
                    X86Instruction::Movsx { rd, rs, src_width }
                }
            }
            // NEG / NOT / INC / DEC share the single-operand (rd-only) shape,
            // so the opcode-bridge mutation swaps among the four. Like the
            // reg-reg / reg-imm groups (and unlike the guaranteed-change
            // CMP↔TEST pair), the draw range includes the current variant, so
            // it may produce an identity mutation.
            X86Instruction::Neg { rd }
            | X86Instruction::Not { rd }
            | X86Instruction::Inc { rd }
            | X86Instruction::Dec { rd } => match rng.random_range(0..4u32) {
                0 => X86Instruction::Neg { rd },
                1 => X86Instruction::Not { rd },
                2 => X86Instruction::Inc { rd },
                _ => X86Instruction::Dec { rd },
            },
            // SHL / SHR / SAR share the reg-plus-count shape, so the
            // opcode-bridge mutation swaps among the three, carrying the
            // current count through (re-drawing it only if it became
            // unencodable). Like the reg-reg / reg-imm groups, the draw range
            // includes the current variant, so it may be an identity mutation.
            X86Instruction::Shl { rd, imm }
            | X86Instruction::Shr { rd, imm }
            | X86Instruction::Sar { rd, imm } => {
                let imm = self.keep_or_pick_shift_count(rng, imm);
                match rng.random_range(0..3u32) {
                    0 => X86Instruction::Shl { rd, imm },
                    1 => X86Instruction::Shr { rd, imm },
                    _ => X86Instruction::Sar { rd, imm },
                }
            }
            // ROL / ROR share the reg-plus-count shape but a distinct
            // (CF/OF-only) flag model, so they bridge only to each other —
            // never to a shift, whose SF/ZF/PF semantics differ. Carry the
            // current count through, re-drawing only if it became unencodable.
            // The draw range includes the current variant, so it may be an
            // identity mutation.
            X86Instruction::Rol { rd, imm } | X86Instruction::Ror { rd, imm } => {
                let imm = self.keep_or_pick_shift_count(rng, imm);
                if rng.random_bool(0.5) {
                    X86Instruction::Rol { rd, imm }
                } else {
                    X86Instruction::Ror { rd, imm }
                }
            }
            // IMUL has a distinct (CF/OF-only-defined) flag model that no other
            // family shares, so — like Cmov — it has no opcode-shape sibling to
            // bridge to. Keep both IMUL forms unchanged here; operand mutation
            // and whole-instruction replacement still explore them.
            X86Instruction::ImulReg { .. } | X86Instruction::ImulRegImm { .. } => current,
            // LEA has a unique (rd, base, disp) shape and a flag-free model that
            // no other family shares, so — like IMUL and Cmov — it has no
            // opcode-shape sibling to bridge to. Keep it unchanged; operand
            // mutation and whole-instruction replacement still explore it.
            X86Instruction::Lea { .. } => current,
            // Cmov has a unique shape (rd, rs, cond) with no opcode-shape
            // siblings; keep it unchanged in the opcode-bridge mutator.
            X86Instruction::Cmov { .. } => current,
            // Setcc has a unique (rd, cond) shape.
            X86Instruction::Setcc { .. } => current,
            // Jcc is a terminator and should never reach mutation; preserve it.
            X86Instruction::Jcc { .. } => current,
        };
    }

    fn mutate_swap<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.len() < 2 {
            return;
        }
        let n = sequence.len();
        let a = rng.random_range(0..n);
        let offset = rng.random_range(0..(n - 1));
        let b = (a + 1 + offset) % n;
        sequence.swap(a, b);
    }

    fn mutate_instruction<R: rand::RngExt>(&self, rng: &mut R, sequence: &mut [X86Instruction]) {
        if sequence.is_empty() {
            return;
        }
        let idx = rng.random_range(0..sequence.len());
        if let Some(instr) = self.random_instruction(rng) {
            sequence[idx] = instr;
        }
    }
}

impl Default for X86Mutator {
    fn default() -> Self {
        Self::new(
            (0..8u8).filter_map(X86Register::from_index).collect(),
            vec![
                0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
            ],
            crate::search::config::MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        )
    }
}

impl crate::isa::traits::ISAMutator<X86Instruction> for X86Mutator {
    fn mutate<R: rand::RngExt>(
        &self,
        rng: &mut R,
        sequence: &[X86Instruction],
    ) -> Vec<X86Instruction> {
        if sequence.is_empty() {
            return sequence.to_vec();
        }
        let mut out = sequence.to_vec();
        let r: f64 = rng.random();
        match self.weights.select_index(r) {
            0 => self.mutate_operand(rng, &mut out),
            1 => self.mutate_opcode(rng, &mut out),
            2 => self.mutate_swap(rng, &mut out),
            _ => self.mutate_instruction(rng, &mut out),
        }
        out
    }
}

/// Stateless generator producing every rewritable x86 variant for a
/// given register and immediate pool. Jcc is intentionally excluded:
/// it is a fixed terminator, not a search candidate.
#[derive(Clone, Copy, Debug, Default)]
pub struct X86InstructionGenerator;

// One entry per rewritable opcode family: 6 reg-reg + 6 reg-imm + CMP + TEST
// (each reg/imm) + NEG + NOT + INC + DEC + SHL + SHR + SAR + ROL + ROR +
// IMUL (2-op) + IMUL (3-op) + LEA + MOVZX + MOVSX + CMOVcc + SETcc. MOVZX/MOVSX
// each expand across their 8- and 16-bit source widths; the conditional
// families (CMOVcc, SETcc) each count as one opcode here even though
// `generate_all` expands all 16 `X86Condition::ALL` variants.
//
// The extra distinct-source CMOV draw at both `X86Mutator::random_instruction`
// and `generate_random_rewritable_x86_instruction` is gated on
// `opcode == X86_CMOV_OPCODE`, so CMOV is position-independent and need not be
// the last opcode; SETcc follows it as the final rewritable opcode.
const X86_REWRITABLE_OPCODE_COUNT: u8 = 32;
const X86_CMOV_OPCODE: u8 = 30;

fn has_distinct_register_pair(registers: &[X86Register]) -> bool {
    let Some(first) = registers.first() else {
        return false;
    };
    registers.iter().any(|reg| reg != first)
}

/// Draw a rewritable opcode, omitting CMOV when no distinct register pair can
/// represent its non-no-op shape. SETcc follows CMOV in the opcode table, so a
/// degenerate pool skips the CMOV hole rather than dropping the final opcode.
fn pick_random_rewritable_opcode<R: Rng + ?Sized>(rng: &mut R, cmov_available: bool) -> u8 {
    if cmov_available {
        return rng.random_range(0..X86_REWRITABLE_OPCODE_COUNT);
    }
    let mut opcode = rng.random_range(0..(X86_REWRITABLE_OPCODE_COUNT - 1));
    if opcode >= X86_CMOV_OPCODE {
        opcode += 1;
    }
    opcode
}

/// Maps a rewritable opcode index in `0..X86_REWRITABLE_OPCODE_COUNT` to the
/// `X86Instruction` variant it denotes, using operands the caller has already
/// drawn. This is the single source of truth for the opcode → variant table;
/// `X86Mutator::random_instruction` and
/// `generate_random_rewritable_x86_instruction` both delegate here so the two
/// dispatch tables cannot drift (see issue #348). Operand drawing and RNG draw
/// order stay at the call sites; the CMOV slot consumes the `rs` the caller
/// resolved via `pick_register_except` so `rs != rd`.
///
/// Keep this in lock-step with `X86_REWRITABLE_OPCODE_COUNT` and the
/// `opcode_dispatch_is_consistent` test, which pins the full mapping.
pub(crate) fn build_x86_instruction_by_opcode(
    opcode: u8,
    rd: X86Register,
    rs: X86Register,
    imm: i64,
    cond: X86Condition,
    src_width: u32,
) -> X86Instruction {
    match opcode {
        0 => X86Instruction::MovReg { rd, rs },
        1 => X86Instruction::MovImm { rd, imm },
        2 => X86Instruction::AddReg { rd, rs },
        3 => X86Instruction::AddImm { rd, imm },
        4 => X86Instruction::SubReg { rd, rs },
        5 => X86Instruction::SubImm { rd, imm },
        6 => X86Instruction::AndReg { rd, rs },
        7 => X86Instruction::AndImm { rd, imm },
        8 => X86Instruction::OrReg { rd, rs },
        9 => X86Instruction::OrImm { rd, imm },
        10 => X86Instruction::XorReg { rd, rs },
        11 => X86Instruction::XorImm { rd, imm },
        12 => X86Instruction::CmpReg { rn: rd, rs },
        13 => X86Instruction::CmpImm { rn: rd, imm },
        14 => X86Instruction::TestReg { rn: rd, rs },
        15 => X86Instruction::TestImm { rn: rd, imm },
        // NEG / NOT / INC / DEC are single-operand: they consume only `rd`
        // (rs/imm/cond are ignored).
        16 => X86Instruction::Neg { rd },
        17 => X86Instruction::Not { rd },
        18 => X86Instruction::Inc { rd },
        19 => X86Instruction::Dec { rd },
        // SHL / SHR / SAR consume `rd` plus the shared `imm` shift count. The
        // count is only checked for imm8-encodability at `can_assemble` time,
        // so no extra RNG draw is introduced here — the two dispatch sites stay
        // in lock-step on the shared `imm`.
        20 => X86Instruction::Shl { rd, imm },
        21 => X86Instruction::Shr { rd, imm },
        22 => X86Instruction::Sar { rd, imm },
        // ROL / ROR consume `rd` plus the shared `imm` rotate count, exactly
        // like the shifts — no extra RNG draw, so the two dispatch sites stay
        // in lock-step on the shared `imm`.
        23 => X86Instruction::Rol { rd, imm },
        24 => X86Instruction::Ror { rd, imm },
        // IMUL (2-op) consumes rd + rs; IMUL (3-op) consumes rd + rs + the
        // shared `imm`. No extra RNG draw, so the two dispatch sites stay in
        // lock-step on the shared operands.
        25 => X86Instruction::ImulReg { rd, rs },
        26 => X86Instruction::ImulRegImm { rd, rs, imm },
        // LEA consumes rd as the destination, rs as the base register, and the
        // shared `imm` as the displacement. No extra RNG draw, so the two
        // dispatch sites stay in lock-step on the shared operands.
        27 => X86Instruction::Lea {
            rd,
            base: rs,
            disp: imm,
        },
        28 => X86Instruction::Movzx { rd, rs, src_width },
        29 => X86Instruction::Movsx { rd, rs, src_width },
        // CMOV consumes the distinct `rs` the caller resolved via
        // `pick_register_except` (gated on `opcode == X86_CMOV_OPCODE`).
        30 => X86Instruction::Cmov { rd, rs, cond },
        31 => X86Instruction::Setcc { rd, cond },
        _ => unreachable!("opcode out of range"),
    }
}

fn pick_register_except<R: Rng + ?Sized>(
    rng: &mut R,
    registers: &[X86Register],
    excluded: X86Register,
) -> Option<X86Register> {
    let available = registers.iter().filter(|&&reg| reg != excluded).count();
    if available == 0 {
        return None;
    }
    let target = rng.random_range(0..available);
    registers
        .iter()
        .copied()
        .filter(|&reg| reg != excluded)
        .nth(target)
}

fn generate_random_rewritable_x86_instruction<R: Rng + ?Sized>(
    rng: &mut R,
    registers: &[X86Register],
    immediates: &[i64],
) -> X86Instruction {
    assert!(
        !registers.is_empty(),
        "x86 random instruction generation requires a register pool"
    );
    assert!(
        !immediates.is_empty(),
        "x86 random instruction generation requires an immediate pool"
    );

    // CMOVcc with rd == rs is a no-op, so its opcode is only a candidate when
    // the register pool holds two distinct registers.
    let opcode = pick_random_rewritable_opcode(rng, has_distinct_register_pair(registers));
    let rd = registers[rng.random_range(0..registers.len())];
    let rs = registers[rng.random_range(0..registers.len())];
    let imm = immediates[rng.random_range(0..immediates.len())];
    let cond = X86Condition::ALL[rng.random_range(0..X86Condition::ALL.len())];
    let src_width = if rng.random_bool(0.5) { 8 } else { 16 };
    // Mirror `X86Mutator::random_instruction`: the CMOV slot draws a distinct
    // source register; every other opcode reuses `rs`. Keep this draw
    // conditional on the CMOV opcode so both paths share one RNG stream.
    let final_rs = if opcode == X86_CMOV_OPCODE {
        pick_register_except(rng, registers, rd)
            .expect("CMOV opcode requires a distinct register pair")
    } else {
        rs
    };
    build_x86_instruction_by_opcode(opcode, rd, final_rs, imm, cond, src_width)
}

/// Default register pool for x86 stochastic / symbolic search.
///
/// Mirrors the AArch64 baseline of a small GPR subset. RSP and RBP are
/// deliberately excluded so search never touches the stack frame.
pub fn default_x86_registers() -> Vec<X86Register> {
    vec![
        X86Register::RAX,
        X86Register::RCX,
        X86Register::RDX,
        X86Register::RBX,
        X86Register::RSI,
        X86Register::RDI,
        X86Register::R8,
        X86Register::R9,
    ]
}

/// Default immediate pool for x86 search. Same constants as the AArch64
/// search baseline so the two backends use comparable candidate spaces.
pub fn default_x86_immediates() -> Vec<i64> {
    vec![
        0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
    ]
}

impl InstructionGenerator<X86Instruction> for X86InstructionGenerator {
    fn generate_all(&self, registers: &[X86Register], immediates: &[i64]) -> Vec<X86Instruction> {
        let mut out = Vec::new();
        // Register-register variants (8 data mnemonics).
        for &rd in registers {
            for &rs in registers {
                if !x86_register_pair_ok(rd, rs, 64) {
                    continue;
                }
                out.push(X86Instruction::MovReg { rd, rs });
                out.push(X86Instruction::AddReg { rd, rs });
                out.push(X86Instruction::SubReg { rd, rs });
                out.push(X86Instruction::AndReg { rd, rs });
                out.push(X86Instruction::OrReg { rd, rs });
                out.push(X86Instruction::XorReg { rd, rs });
                out.push(X86Instruction::CmpReg { rn: rd, rs });
                out.push(X86Instruction::TestReg { rn: rd, rs });
                for src_width in [8, 16] {
                    out.push(X86Instruction::Movzx { rd, rs, src_width });
                    out.push(X86Instruction::Movsx { rd, rs, src_width });
                }
            }
        }
        // Register-immediate variants (8 data mnemonics).
        for &rd in registers {
            for &imm in immediates {
                if x86_mov_operand_immediate_ok(rd, imm, 64) {
                    out.push(X86Instruction::MovImm { rd, imm });
                }
                if x86_operand_immediate_ok(rd, imm, 64) {
                    out.push(X86Instruction::AddImm { rd, imm });
                    out.push(X86Instruction::SubImm { rd, imm });
                    out.push(X86Instruction::AndImm { rd, imm });
                    out.push(X86Instruction::OrImm { rd, imm });
                    out.push(X86Instruction::XorImm { rd, imm });
                    out.push(X86Instruction::CmpImm { rn: rd, imm });
                    out.push(X86Instruction::TestImm { rn: rd, imm });
                }
            }
        }
        // Single-operand variants (NEG, NOT, INC, DEC): one per register.
        for &rd in registers {
            out.push(X86Instruction::Neg { rd });
            out.push(X86Instruction::Not { rd });
            out.push(X86Instruction::Inc { rd });
            out.push(X86Instruction::Dec { rd });
        }
        // Immediate-count shifts (SHL, SHR, SAR): one per (register, count).
        // The count encodes as imm8, so only imm8-encodable immediates yield a
        // candidate; larger pool entries are skipped here rather than emitted
        // and later rejected by `can_assemble`.
        for &rd in registers {
            for &imm in immediates {
                if !x86_shift_count_imm8_ok(imm) {
                    continue;
                }
                out.push(X86Instruction::Shl { rd, imm });
                out.push(X86Instruction::Shr { rd, imm });
                out.push(X86Instruction::Sar { rd, imm });
            }
        }
        // Immediate-count rotates (ROL, ROR): same imm8-count shape as the
        // shifts, so only imm8-encodable counts yield a candidate.
        for &rd in registers {
            for &imm in immediates {
                if !x86_shift_count_imm8_ok(imm) {
                    continue;
                }
                out.push(X86Instruction::Rol { rd, imm });
                out.push(X86Instruction::Ror { rd, imm });
            }
        }
        // IMUL (2-operand): `imul rd, rs` for every (register, register) pair,
        // including rd == rs (self-multiply is meaningful, unlike self-CMOV).
        for &rd in registers {
            for &rs in registers {
                if !x86_register_pair_ok(rd, rs, 64) || rd.is_byte() {
                    continue;
                }
                out.push(X86Instruction::ImulReg { rd, rs });
            }
        }
        // IMUL (3-operand): `imul rd, rs, imm` for every (rd, rs, imm) triple.
        // The immediate encodes as imm32, so non-imm32 pool entries are skipped
        // here rather than emitted and later rejected by `can_assemble`.
        for &rd in registers {
            for &rs in registers {
                if !x86_register_pair_ok(rd, rs, 64) || rd.is_byte() {
                    continue;
                }
                for &imm in immediates {
                    if !x86_operand_immediate_ok(rd, imm, 64) {
                        continue;
                    }
                    out.push(X86Instruction::ImulRegImm { rd, rs, imm });
                }
            }
        }
        // LEA: `lea rd, [base + disp]` for every (rd, base, disp) triple,
        // including rd == base (self-base is meaningful: it adds disp to rd).
        // The displacement encodes as a signed disp32, so non-imm32 pool
        // entries are skipped here rather than emitted and later rejected by
        // `can_assemble`.
        for &rd in registers {
            for &base in registers {
                if rd.is_byte()
                    || !matches!(
                        base.view(),
                        X86RegisterView::Native | X86RegisterView::Dword
                    )
                    || !x86_register_ok(rd, 64)
                {
                    continue;
                }
                for &disp in immediates {
                    if i32::try_from(disp).is_err() {
                        continue;
                    }
                    out.push(X86Instruction::Lea { rd, base, disp });
                }
            }
        }
        // SETcc is rewritable and reads flags, so enumerate every condition
        // for every destination register.
        for &rd in registers {
            for &cond in &X86Condition::ALL {
                out.push(X86Instruction::Setcc { rd, cond });
            }
        }
        // CMOVcc is rewritable and reads flags, so enumerate every condition
        // for each non-identical register pair. Jcc remains excluded.
        for &rd in registers {
            for &rs in registers {
                if rd == rs || !x86_register_pair_ok(rd, rs, 64) || rd.is_byte() {
                    continue;
                }
                for &cond in &X86Condition::ALL {
                    out.push(X86Instruction::Cmov { rd, rs, cond });
                }
            }
        }
        out
    }

    fn generate_random<R: Rng>(
        &self,
        rng: &mut R,
        registers: &[X86Register],
        immediates: &[i64],
    ) -> X86Instruction {
        generate_random_rewritable_x86_instruction(rng, registers, immediates)
    }

    fn mutate<R: Rng>(
        &self,
        rng: &mut R,
        instruction: &X86Instruction,
        registers: &[X86Register],
        immediates: &[i64],
    ) -> X86Instruction {
        // Three strategies, matching the RISC-V mutator:
        //   0: completely fresh instruction (opcode change)
        //   1: keep opcode + sources, change destination
        //   2: keep opcode + destination, change sources/immediate
        match rng.random_range(0..3) {
            0 => self.generate_random(rng, registers, immediates),
            1 => match *instruction {
                X86Instruction::Cmov { rd, rs, cond } => X86Instruction::Cmov {
                    rd: pick_register_except(rng, registers, rs).unwrap_or(rd),
                    rs,
                    cond,
                },
                _ => {
                    let new_rd = registers[rng.random_range(0..registers.len())];
                    with_destination(*instruction, new_rd)
                }
            },
            2 => match *instruction {
                X86Instruction::Cmov { rd, rs, cond } => X86Instruction::Cmov {
                    rd,
                    rs: pick_register_except(rng, registers, rd).unwrap_or(rs),
                    cond,
                },
                _ => {
                    let new_rs = registers[rng.random_range(0..registers.len())];
                    let new_imm = immediates[rng.random_range(0..immediates.len())];
                    with_sources(*instruction, new_rs, new_imm)
                }
            },
            _ => unreachable!(),
        }
    }

    fn opcode_count(&self) -> u8 {
        X86_REWRITABLE_OPCODE_COUNT
    }
}

fn with_destination(instr: X86Instruction, new_rd: X86Register) -> X86Instruction {
    match instr {
        X86Instruction::MovReg { rs, .. } => X86Instruction::MovReg { rd: new_rd, rs },
        X86Instruction::MovImm { imm, .. } => X86Instruction::MovImm { rd: new_rd, imm },
        X86Instruction::Movzx { rs, src_width, .. } => X86Instruction::Movzx {
            rd: new_rd,
            rs,
            src_width,
        },
        X86Instruction::Movsx { rs, src_width, .. } => X86Instruction::Movsx {
            rd: new_rd,
            rs,
            src_width,
        },
        X86Instruction::AddReg { rs, .. } => X86Instruction::AddReg { rd: new_rd, rs },
        X86Instruction::AddImm { imm, .. } => X86Instruction::AddImm { rd: new_rd, imm },
        X86Instruction::SubReg { rs, .. } => X86Instruction::SubReg { rd: new_rd, rs },
        X86Instruction::SubImm { imm, .. } => X86Instruction::SubImm { rd: new_rd, imm },
        X86Instruction::AndReg { rs, .. } => X86Instruction::AndReg { rd: new_rd, rs },
        X86Instruction::AndImm { imm, .. } => X86Instruction::AndImm { rd: new_rd, imm },
        X86Instruction::OrReg { rs, .. } => X86Instruction::OrReg { rd: new_rd, rs },
        X86Instruction::OrImm { imm, .. } => X86Instruction::OrImm { rd: new_rd, imm },
        X86Instruction::XorReg { rs, .. } => X86Instruction::XorReg { rd: new_rd, rs },
        X86Instruction::XorImm { imm, .. } => X86Instruction::XorImm { rd: new_rd, imm },
        // CMP / TEST variants have rn instead of rd; mutate rn for symmetry.
        X86Instruction::CmpReg { rs, .. } => X86Instruction::CmpReg { rn: new_rd, rs },
        X86Instruction::CmpImm { imm, .. } => X86Instruction::CmpImm { rn: new_rd, imm },
        X86Instruction::TestReg { rs, .. } => X86Instruction::TestReg { rn: new_rd, rs },
        X86Instruction::TestImm { imm, .. } => X86Instruction::TestImm { rn: new_rd, imm },
        // NEG / NOT / INC / DEC have only a destination register; redirect it.
        X86Instruction::Neg { .. } => X86Instruction::Neg { rd: new_rd },
        X86Instruction::Not { .. } => X86Instruction::Not { rd: new_rd },
        X86Instruction::Inc { .. } => X86Instruction::Inc { rd: new_rd },
        X86Instruction::Dec { .. } => X86Instruction::Dec { rd: new_rd },
        // SHL / SHR / SAR redirect the destination, carrying the count.
        X86Instruction::Shl { imm, .. } => X86Instruction::Shl { rd: new_rd, imm },
        X86Instruction::Shr { imm, .. } => X86Instruction::Shr { rd: new_rd, imm },
        X86Instruction::Sar { imm, .. } => X86Instruction::Sar { rd: new_rd, imm },
        // ROL / ROR likewise redirect the destination, carrying the count.
        X86Instruction::Rol { imm, .. } => X86Instruction::Rol { rd: new_rd, imm },
        X86Instruction::Ror { imm, .. } => X86Instruction::Ror { rd: new_rd, imm },
        // IMUL redirects the destination, carrying the source (and imm).
        X86Instruction::ImulReg { rs, .. } => X86Instruction::ImulReg { rd: new_rd, rs },
        X86Instruction::ImulRegImm { rs, imm, .. } => X86Instruction::ImulRegImm {
            rd: new_rd,
            rs,
            imm,
        },
        // LEA redirects the destination, carrying the base and displacement.
        X86Instruction::Lea { base, disp, .. } => X86Instruction::Lea {
            rd: new_rd,
            base,
            disp,
        },
        X86Instruction::Cmov { rd, rs, cond } => X86Instruction::Cmov {
            rd: if new_rd == rs { rd } else { new_rd },
            rs,
            cond,
        },
        X86Instruction::Setcc { cond, .. } => X86Instruction::Setcc { rd: new_rd, cond },
        // Jcc has no register operand; ignore the requested rd swap.
        X86Instruction::Jcc { cond } => X86Instruction::Jcc { cond },
    }
}

fn with_sources(instr: X86Instruction, new_rs: X86Register, new_imm: i64) -> X86Instruction {
    match instr {
        X86Instruction::MovReg { rd, .. } => X86Instruction::MovReg { rd, rs: new_rs },
        X86Instruction::MovImm { rd, .. } => X86Instruction::MovImm { rd, imm: new_imm },
        X86Instruction::Movzx { rd, src_width, .. } => X86Instruction::Movzx {
            rd,
            rs: new_rs,
            src_width,
        },
        X86Instruction::Movsx { rd, src_width, .. } => X86Instruction::Movsx {
            rd,
            rs: new_rs,
            src_width,
        },
        X86Instruction::AddReg { rd, .. } => X86Instruction::AddReg { rd, rs: new_rs },
        X86Instruction::AddImm { rd, .. } => X86Instruction::AddImm { rd, imm: new_imm },
        X86Instruction::SubReg { rd, .. } => X86Instruction::SubReg { rd, rs: new_rs },
        X86Instruction::SubImm { rd, .. } => X86Instruction::SubImm { rd, imm: new_imm },
        X86Instruction::AndReg { rd, .. } => X86Instruction::AndReg { rd, rs: new_rs },
        X86Instruction::AndImm { rd, .. } => X86Instruction::AndImm { rd, imm: new_imm },
        X86Instruction::OrReg { rd, .. } => X86Instruction::OrReg { rd, rs: new_rs },
        X86Instruction::OrImm { rd, .. } => X86Instruction::OrImm { rd, imm: new_imm },
        X86Instruction::XorReg { rd, .. } => X86Instruction::XorReg { rd, rs: new_rs },
        X86Instruction::XorImm { rd, .. } => X86Instruction::XorImm { rd, imm: new_imm },
        X86Instruction::CmpReg { rn, .. } => X86Instruction::CmpReg { rn, rs: new_rs },
        X86Instruction::CmpImm { rn, .. } => X86Instruction::CmpImm { rn, imm: new_imm },
        X86Instruction::TestReg { rn, .. } => X86Instruction::TestReg { rn, rs: new_rs },
        X86Instruction::TestImm { rn, .. } => X86Instruction::TestImm { rn, imm: new_imm },
        // NEG / NOT / INC / DEC have no source operand to vary; carry through
        // unchanged.
        X86Instruction::Neg { rd } => X86Instruction::Neg { rd },
        X86Instruction::Not { rd } => X86Instruction::Not { rd },
        X86Instruction::Inc { rd } => X86Instruction::Inc { rd },
        X86Instruction::Dec { rd } => X86Instruction::Dec { rd },
        // SHL / SHR / SAR vary the shift count via `new_imm`, but only when it
        // is imm8-encodable; otherwise keep the existing count so the result
        // stays assemblable.
        X86Instruction::Shl { rd, imm } => X86Instruction::Shl {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        X86Instruction::Shr { rd, imm } => X86Instruction::Shr {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        X86Instruction::Sar { rd, imm } => X86Instruction::Sar {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        // ROL / ROR vary the rotate count via `new_imm` when it is imm8-encodable;
        // otherwise keep the existing count so the result stays assemblable.
        X86Instruction::Rol { rd, imm } => X86Instruction::Rol {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        X86Instruction::Ror { rd, imm } => X86Instruction::Ror {
            rd,
            imm: if x86_shift_count_imm8_ok(new_imm) {
                new_imm
            } else {
                imm
            },
        },
        // IMUL (2-op) varies its source register; (3-op) varies both source
        // register and immediate.
        X86Instruction::ImulReg { rd, .. } => X86Instruction::ImulReg { rd, rs: new_rs },
        X86Instruction::ImulRegImm { rd, .. } => X86Instruction::ImulRegImm {
            rd,
            rs: new_rs,
            imm: new_imm,
        },
        // LEA varies both its base register and the displacement.
        X86Instruction::Lea { rd, .. } => X86Instruction::Lea {
            rd,
            base: new_rs,
            disp: new_imm,
        },
        // Cmov's `rs` is mutated; `cond` and `rd` carry through unchanged.
        X86Instruction::Cmov { rd, rs, cond } => X86Instruction::Cmov {
            rd,
            rs: if new_rs == rd { rs } else { new_rs },
            cond,
        },
        X86Instruction::Setcc { rd, cond } => X86Instruction::Setcc { rd, cond },
        X86Instruction::Jcc { cond } => X86Instruction::Jcc { cond },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::x86::{X86_32, X86_64};

    type ImmForm = (&'static str, fn(i64) -> X86Instruction);

    #[test]
    fn x86_generator_generate_all_covers_every_opcode() {
        use crate::isa::traits::{InstructionGenerator, InstructionType};
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1, -1];
        let all = X86InstructionGenerator.generate_all(&regs, &imms);

        let n = regs.len();
        let m = imms.len();
        // Shifts only enumerate over imm8-encodable counts (e.g. -1 is dropped).
        let shift_m = imms
            .iter()
            .filter(|&&imm| u8::try_from(imm).is_ok())
            .count();
        // The 3-operand IMUL only enumerates over imm32-encodable immediates;
        // LEA enumerates over imm32-encodable displacements with the same filter.
        let imul_m = imms
            .iter()
            .filter(|&&imm| i32::try_from(imm).is_ok())
            .count();
        let lea_m = imul_m;
        // 8 reg-reg families + 4 extension forms (MOVZX/MOVSX × 8/16-bit
        // source) + 8 reg-imm families + 4 single-operand families
        // (NEG, NOT, INC, DEC) + 3 shift families (SHL, SHR, SAR over imm8
        // counts) + 2 rotate families (ROL, ROR over imm8 counts) + IMUL 2-op
        // (every register pair) + IMUL 3-op (every (rd, rs, imm32) triple) +
        // LEA (every (rd, base, disp32) triple) + SETcc per register and
        // condition + CMOVcc over distinct pairs.
        let expected_len = 8 * n * n
            + 4 * n * n
            + 8 * n * m
            + 4 * n
            + 3 * n * shift_m
            + 2 * n * shift_m
            + n * n
            + n * n * imul_m
            + n * n * lea_m
            + n * X86Condition::ALL.len()
            + n * (n - 1) * X86Condition::ALL.len();
        assert_eq!(
            all.len(),
            expected_len,
            "generate_all should only prune CMOV self-pairs and non-imm8 shift/rotate / non-imm32 imul/lea counts from the full pool"
        );

        // For each opcode_id, at least one variant must appear.
        let opcode_count = X86InstructionGenerator.opcode_count();
        let mut seen = vec![false; opcode_count as usize];
        for instr in &all {
            seen[instr.opcode_id() as usize] = true;
        }
        for (id, present) in seen.iter().enumerate() {
            assert!(*present, "opcode_id {} never generated", id);
        }

        // Sanity: every generated instruction's destination (if any) is
        // drawn from the supplied register pool, and source registers too.
        for instr in &all {
            if let Some(dst) = instr.destination() {
                assert!(regs.contains(&dst));
            }
            for src in instr.source_registers() {
                assert!(regs.contains(&src));
            }
        }
    }

    #[test]
    fn x86_generator_enumerates_setcc_for_each_register_and_condition() {
        use crate::isa::traits::InstructionGenerator;

        let regs = [X86Register::RAX, X86Register::RBX];
        let all = X86InstructionGenerator.generate_all(&regs, &[0]);
        for rd in regs {
            for cond in X86Condition::ALL {
                assert!(
                    all.contains(&X86Instruction::Setcc { rd, cond }),
                    "generator omitted SET{} {}",
                    cond.suffix(),
                    rd
                );
            }
        }
    }

    #[test]
    fn x86_generator_includes_cmov_but_excludes_jcc() {
        use crate::isa::traits::InstructionGenerator;
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64];
        let all = X86InstructionGenerator.generate_all(&regs, &imms);

        assert!(
            all.contains(&X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            }),
            "trait generator must enumerate CMOVcc candidates"
        );
        assert!(
            all.iter()
                .all(|instr| !matches!(instr, X86Instruction::Jcc { .. })),
            "trait generator must not enumerate fixed Jcc terminators"
        );
    }

    #[test]
    fn x86_generator_filters_self_cmov_candidates() {
        use crate::isa::traits::InstructionGenerator;
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64];
        let all = X86InstructionGenerator.generate_all(&regs, &imms);

        for &cond in &X86Condition::ALL {
            assert!(
                all.contains(&X86Instruction::Cmov {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    cond,
                }),
                "generator must keep cross-register cmov{} rax, rbx",
                cond
            );
            assert!(
                all.contains(&X86Instruction::Cmov {
                    rd: X86Register::RBX,
                    rs: X86Register::RAX,
                    cond,
                }),
                "generator must keep cross-register cmov{} rbx, rax",
                cond
            );
        }

        assert!(
            !all.iter()
                .any(|instr| matches!(instr, X86Instruction::Cmov { rd, rs, .. } if rd == rs)),
            "generate_all must skip no-op CMOV candidates where rd == rs"
        );
    }

    /// Safety invariant (restored from the deleted `candidate_x86.rs`): the
    /// default search register pool must never include the stack or frame
    /// pointer, and must contain no duplicates. A regression here would let
    /// search clobber RSP/RBP in a patched binary.
    #[test]
    fn default_register_pool_excludes_stack_pointer_and_base_pointer() {
        use std::collections::HashSet;
        let pool = default_x86_registers();
        assert!(
            !pool.contains(&X86Register::RSP),
            "RSP must not be in the default search pool"
        );
        assert!(
            !pool.contains(&X86Register::RBP),
            "RBP must not be in the default search pool"
        );
        let unique: HashSet<_> = pool.iter().collect();
        assert_eq!(
            unique.len(),
            pool.len(),
            "default register pool must not contain duplicates"
        );
    }

    #[test]
    fn x86_generator_random_can_emit_cmov_without_emitting_jcc() {
        use crate::isa::traits::InstructionGenerator;
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(74);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1];
        let mut saw_cmov = false;

        for _ in 0..2000 {
            let instr = X86InstructionGenerator.generate_random(&mut rng, &regs, &imms);
            saw_cmov |= matches!(instr, X86Instruction::Cmov { .. });
            assert!(
                !matches!(instr, X86Instruction::Jcc { .. }),
                "random trait generator must not emit fixed Jcc terminators"
            );
        }

        assert!(saw_cmov, "random trait generator never emitted CMOVcc");
    }

    #[test]
    fn x86_generator_random_filters_self_cmov_candidates() {
        use crate::isa::traits::InstructionGenerator;
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(453);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1];
        let mut saw_cmov = false;

        for _ in 0..2000 {
            let instr = X86InstructionGenerator.generate_random(&mut rng, &regs, &imms);
            if let X86Instruction::Cmov { rd, rs, .. } = instr {
                saw_cmov = true;
                assert_ne!(rd, rs, "random generator emitted self-CMOV {instr:?}");
            }
        }

        assert!(saw_cmov, "random trait generator never emitted CMOVcc");
    }

    #[test]
    fn shared_x86_random_generator_uses_rewritable_pool() {
        use crate::isa::traits::InstructionType;
        use rand::SeedableRng;

        fn assert_from_pools(instr: X86Instruction, regs: &[X86Register], imms: &[i64]) {
            if let Some(dst) = instr.destination() {
                assert!(regs.contains(&dst), "destination {:?} outside pool", dst);
            }
            for src in instr.source_registers() {
                assert!(regs.contains(&src), "source {:?} outside pool", src);
            }
            match instr {
                X86Instruction::MovImm { imm, .. }
                | X86Instruction::AddImm { imm, .. }
                | X86Instruction::SubImm { imm, .. }
                | X86Instruction::AndImm { imm, .. }
                | X86Instruction::OrImm { imm, .. }
                | X86Instruction::XorImm { imm, .. }
                | X86Instruction::CmpImm { imm, .. }
                | X86Instruction::TestImm { imm, .. }
                // Shifts and rotates draw their count from the same shared
                // `imm` slot in `generate_random_rewritable_x86_instruction`,
                // so it is in the pool too.
                | X86Instruction::Shl { imm, .. }
                | X86Instruction::Shr { imm, .. }
                | X86Instruction::Sar { imm, .. }
                | X86Instruction::Rol { imm, .. }
                | X86Instruction::Ror { imm, .. }
                // The 3-operand IMUL draws its immediate from the shared pool.
                | X86Instruction::ImulRegImm { imm, .. }
                // LEA draws its displacement from the same shared `imm` slot.
                | X86Instruction::Lea { disp: imm, .. } => {
                    assert!(imms.contains(&imm), "immediate {} outside pool", imm);
                }
                X86Instruction::MovReg { .. }
                | X86Instruction::Movzx { .. }
                | X86Instruction::Movsx { .. }
                | X86Instruction::AddReg { .. }
                | X86Instruction::SubReg { .. }
                | X86Instruction::AndReg { .. }
                | X86Instruction::OrReg { .. }
                | X86Instruction::XorReg { .. }
                | X86Instruction::CmpReg { .. }
                | X86Instruction::TestReg { .. }
                | X86Instruction::Neg { .. }
                | X86Instruction::Not { .. }
                | X86Instruction::Inc { .. }
                | X86Instruction::Dec { .. }
                | X86Instruction::ImulReg { .. }
                | X86Instruction::Cmov { .. }
                | X86Instruction::Setcc { .. }
                | X86Instruction::Jcc { .. } => {}
            }
        }

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(252);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1];
        let count = X86InstructionGenerator.opcode_count();
        let mut saw_cmov = false;

        for _ in 0..2000 {
            let instr = generate_random_rewritable_x86_instruction(&mut rng, &regs, &imms);
            saw_cmov |= matches!(instr, X86Instruction::Cmov { .. });
            assert!(instr.opcode_id() < count);
            assert!(!matches!(instr, X86Instruction::Jcc { .. }));
            assert_from_pools(instr, &regs, &imms);
        }

        assert!(saw_cmov, "shared generator never emitted CMOVcc");
    }

    #[test]
    fn x86_generator_random_within_opcode_range() {
        use crate::isa::traits::{InstructionGenerator, InstructionType};
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let regs = [X86Register::RAX, X86Register::RBX, X86Register::RCX];
        let imms = [0i64, 1];
        let count = X86InstructionGenerator.opcode_count();
        for _ in 0..200 {
            let instr = X86InstructionGenerator.generate_random(&mut rng, &regs, &imms);
            assert!(
                instr.opcode_id() < count,
                "{} out of range",
                instr.opcode_id()
            );
        }
    }

    #[test]
    fn x86_generator_mutate_changes_instruction() {
        use crate::isa::traits::{InstructionGenerator, InstructionType};
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1, 2, 3];
        // Mutator can mutate any starting variant without panicking,
        // and the result is always a valid opcode.
        let start = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let count = X86InstructionGenerator.opcode_count();
        for _ in 0..50 {
            let mutated = X86InstructionGenerator.mutate(&mut rng, &start, &regs, &imms);
            assert!(mutated.opcode_id() < count);
        }
    }

    #[test]
    fn x86_generator_mutate_filters_self_cmov_candidates() {
        use crate::isa::traits::InstructionGenerator;
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(453);
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64, 1];
        let mut saw_cmov = false;

        for start in [
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            },
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RAX,
                cond: X86Condition::E,
            },
        ] {
            for _ in 0..2000 {
                let mutated = X86InstructionGenerator.mutate(&mut rng, &start, &regs, &imms);
                if let X86Instruction::Cmov { rd, rs, .. } = mutated {
                    saw_cmov = true;
                    assert_ne!(rd, rs, "generator mutate emitted self-CMOV {mutated:?}");
                }
            }
        }

        assert!(saw_cmov, "generator mutate never returned CMOVcc");
    }

    #[test]
    fn x86_generator_enumerates_both_extension_families_and_source_widths() {
        use crate::isa::traits::InstructionGenerator;

        let generated =
            X86InstructionGenerator.generate_all(&[X86Register::RAX, X86Register::RBX], &[0]);
        for src_width in [8, 16] {
            assert!(generated.contains(&X86Instruction::Movzx {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                src_width,
            }));
            assert!(generated.contains(&X86Instruction::Movsx {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                src_width,
            }));
        }
    }

    // ---- X86Mutator (issue #73 Phase B) ----

    struct BudgetedRng {
        words: Vec<u32>,
        next_word: usize,
    }

    impl BudgetedRng {
        fn new(words: Vec<u32>) -> Self {
            Self {
                words,
                next_word: 0,
            }
        }

        fn draw_word(&mut self) -> u32 {
            let word = self
                .words
                .get(self.next_word)
                .copied()
                .expect("random generator exceeded its draw budget");
            self.next_word += 1;
            word
        }
    }

    impl rand::TryRng for BudgetedRng {
        type Error = std::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.draw_word())
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let low = u64::from(self.draw_word());
            let high = u64::from(self.draw_word());
            Ok(low | (high << 32))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(4) {
                let bytes = self.draw_word().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn word_for_range(range: u32, value: u32) -> u32 {
        assert!(range > 0);
        assert!(value < range);
        let numerator = (u128::from(value)) << 32;
        let word = numerator.div_ceil(u128::from(range)) as u32;
        debug_assert_eq!(((u64::from(word) * u64::from(range)) >> 32) as u32, value);
        word
    }

    #[test]
    fn x86_mutator_swap_uses_two_draws_with_modular_second_index() {
        let mutator = X86Mutator::default();
        let mut sequence = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddReg {
                rd: X86Register::RBX,
                rs: X86Register::RCX,
            },
            X86Instruction::SubImm {
                rd: X86Register::RDX,
                imm: 1,
            },
        ];
        let mut rng = BudgetedRng::new(vec![word_for_range(3, 1), word_for_range(2, 1)]);

        mutator.mutate_swap(&mut rng, &mut sequence);

        assert_eq!(
            sequence,
            vec![
                X86Instruction::AddReg {
                    rd: X86Register::RBX,
                    rs: X86Register::RCX,
                },
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 0,
                },
                X86Instruction::SubImm {
                    rd: X86Register::RDX,
                    imm: 1,
                },
            ]
        );
    }

    #[test]
    fn x86_mutator_eventually_changes_the_sequence() {
        use super::{default_x86_immediates, default_x86_registers};
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            default_x86_registers(),
            default_x86_immediates(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut changed = false;
        for _ in 0..200 {
            let mutated = mutator.mutate(&mut rng, &target);
            if mutated != target {
                changed = true;
                break;
            }
        }
        assert!(
            changed,
            "200 mutations produced no change \u{2014} stub still wired?"
        );
    }

    #[test]
    fn x86_mutator_opcode_mutates_cmp_reg_to_cmp_imm() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RBX],
            vec![7],
            MutationWeights {
                operand: 0.0,
                opcode: 1.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);

        let mutated = mutator.mutate(&mut rng, &target);

        // rn (RAX) must survive the form change; only the right operand is replaced.
        assert_eq!(
            mutated,
            vec![X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 7,
            }]
        );
    }

    #[test]
    fn x86_mutator_opcode_mutates_cmp_imm_to_cmp_reg() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RBX],
            // Unused by CmpImm → CmpReg (which calls pick_register, not
            // an immediate picker); a value absent from the target makes that clear.
            vec![0],
            MutationWeights {
                operand: 0.0,
                opcode: 1.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        // rn is a non-RAX register so the "rn is preserved" assertion can't be
        // satisfied coincidentally by the pick_register RAX fallback default.
        let target = vec![X86Instruction::CmpImm {
            rn: X86Register::RCX,
            imm: 5,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);

        let mutated = mutator.mutate(&mut rng, &target);

        assert_eq!(
            mutated,
            vec![X86Instruction::CmpReg {
                rn: X86Register::RCX,
                rs: X86Register::RBX,
            }]
        );
    }

    #[test]
    fn x86_mutator_opcode_mutates_cmp_at_selected_nonzero_index() {
        use crate::search::config::MutationWeights;

        let mutator = X86Mutator::new(
            Vec::new(),
            vec![7],
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );
        let mut sequence = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::CmpReg {
                rn: X86Register::RCX,
                rs: X86Register::RBX,
            },
            X86Instruction::SubImm {
                rd: X86Register::RDX,
                imm: 1,
            },
        ];
        let mut rng = BudgetedRng::new(vec![word_for_range(3, 1), word_for_range(1, 0)]);

        mutator.mutate_opcode(&mut rng, &mut sequence);

        assert_eq!(
            sequence,
            vec![
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 0,
                },
                X86Instruction::CmpImm {
                    rn: X86Register::RCX,
                    imm: 7,
                },
                X86Instruction::SubImm {
                    rd: X86Register::RDX,
                    imm: 1,
                },
            ]
        );
    }

    #[test]
    fn x86_mutator_empty_register_pool_does_not_invent_writable_registers() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            Vec::new(),
            vec![0],
            MutationWeights {
                operand: 0.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 1.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::CmpImm {
            rn: X86Register::R10,
            imm: 1,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);

        assert_eq!(mutator.mutate(&mut rng, &target), target);
    }

    #[test]
    fn x86_mutator_cmov_operand_mutates_condition_with_empty_register_pool() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            Vec::new(),
            vec![0],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut changed = None;

        for _ in 0..200 {
            let mutated = mutator.mutate(&mut rng, &target);
            match mutated.as_slice() {
                [X86Instruction::Cmov { rd, rs, cond }]
                    if *rd == X86Register::RAX && *rs == X86Register::RBX =>
                {
                    if *cond != X86Condition::E {
                        changed = Some(*cond);
                        break;
                    }
                }
                other => panic!("unexpected CMOV mutation with empty register pool: {other:?}"),
            }
        }

        assert!(
            changed.is_some(),
            "CMOV condition did not change after repeated operand mutations"
        );
    }

    #[test]
    fn x86_mutator_cmov_operand_reaches_all_conditions() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::collections::HashSet;

        let pool = vec![X86Register::RAX, X86Register::RBX, X86Register::RCX];
        let mutator = X86Mutator::new(
            pool.clone(),
            vec![0],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let mut seq = vec![X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let mut observed = HashSet::from([X86Condition::E]);

        for _ in 0..2_000 {
            seq = mutator.mutate(&mut rng, &seq);
            match seq.as_slice() {
                [X86Instruction::Cmov { rd, rs, cond }] => {
                    assert!(pool.contains(rd), "CMOV rd left mutator pool: {rd:?}");
                    assert!(pool.contains(rs), "CMOV rs left mutator pool: {rs:?}");
                    observed.insert(*cond);
                }
                other => panic!("CMOV operand mutation changed instruction shape: {other:?}"),
            }
            if observed.len() == X86Condition::ALL.len() {
                break;
            }
        }

        assert_eq!(
            observed.len(),
            X86Condition::ALL.len(),
            "CMOV operand mutation reached only {observed:?}"
        );
    }

    #[test]
    fn x86_mutator_random_instruction_uses_zero_for_empty_immediate_pool() {
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX, X86Register::RBX],
            Vec::new(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(252);
        let mut saw_immediate_form = false;

        for _ in 0..2000 {
            match mutator
                .random_instruction(&mut rng)
                .expect("non-empty register pool should generate an instruction")
            {
                X86Instruction::MovImm { imm, .. }
                | X86Instruction::AddImm { imm, .. }
                | X86Instruction::SubImm { imm, .. }
                | X86Instruction::AndImm { imm, .. }
                | X86Instruction::OrImm { imm, .. }
                | X86Instruction::XorImm { imm, .. }
                | X86Instruction::CmpImm { imm, .. }
                | X86Instruction::TestImm { imm, .. }
                // Shifts and rotates carry the same shared `imm` draw (0 for an
                // empty pool).
                | X86Instruction::Shl { imm, .. }
                | X86Instruction::Shr { imm, .. }
                | X86Instruction::Sar { imm, .. }
                | X86Instruction::Rol { imm, .. }
                | X86Instruction::Ror { imm, .. }
                // The 3-operand IMUL draws its immediate from the same shared
                // slot, so the empty pool yields 0 here too.
                | X86Instruction::ImulRegImm { imm, .. }
                // LEA's displacement comes from the same shared slot (0 here).
                | X86Instruction::Lea { disp: imm, .. } => {
                    saw_immediate_form = true;
                    assert_eq!(imm, 0);
                }
                X86Instruction::MovReg { .. }
                | X86Instruction::Movzx { .. }
                | X86Instruction::Movsx { .. }
                | X86Instruction::AddReg { .. }
                | X86Instruction::SubReg { .. }
                | X86Instruction::AndReg { .. }
                | X86Instruction::OrReg { .. }
                | X86Instruction::XorReg { .. }
                | X86Instruction::CmpReg { .. }
                | X86Instruction::TestReg { .. }
                | X86Instruction::Neg { .. }
                | X86Instruction::Not { .. }
                | X86Instruction::Inc { .. }
                | X86Instruction::Dec { .. }
                | X86Instruction::ImulReg { .. }
                | X86Instruction::Cmov { .. }
                | X86Instruction::Setcc { .. }
                | X86Instruction::Jcc { .. } => {}
            }
        }

        assert!(
            saw_immediate_form,
            "mutator did not exercise the empty-immediate fallback"
        );
    }

    #[test]
    fn x86_mutator_random_instruction_matches_shared_generator_stream() {
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let regs = [X86Register::RAX, X86Register::RBX, X86Register::RCX];
        let imms = [0i64, 1, -1];
        let mutator = X86Mutator::new(
            regs.to_vec(),
            imms.to_vec(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );

        for seed in 0..32u64 {
            let mut mutator_rng = ChaCha8Rng::seed_from_u64(seed);
            let mut helper_rng = ChaCha8Rng::seed_from_u64(seed);

            for _ in 0..32 {
                assert_eq!(
                    mutator.random_instruction(&mut mutator_rng),
                    Some(generate_random_rewritable_x86_instruction(
                        &mut helper_rng,
                        &regs,
                        &imms,
                    )),
                    "seed {seed} diverged from shared generator"
                );
            }
        }
    }

    #[test]
    fn opcode_dispatch_is_consistent() {
        // Pin the full opcode → instruction-family mapping that the shared
        // `build_x86_instruction_by_opcode` constructor produces. Both
        // `X86Mutator::random_instruction` and
        // `generate_random_rewritable_x86_instruction` delegate here, so this
        // guards the consolidated table against future drift (issue #348).
        let rd = X86Register::RAX;
        let rs = X86Register::RBX;
        let imm = 7i64;
        let cond = X86Condition::E;

        let expected: [(u8, X86Instruction); X86_REWRITABLE_OPCODE_COUNT as usize] = [
            (0, X86Instruction::MovReg { rd, rs }),
            (1, X86Instruction::MovImm { rd, imm }),
            (2, X86Instruction::AddReg { rd, rs }),
            (3, X86Instruction::AddImm { rd, imm }),
            (4, X86Instruction::SubReg { rd, rs }),
            (5, X86Instruction::SubImm { rd, imm }),
            (6, X86Instruction::AndReg { rd, rs }),
            (7, X86Instruction::AndImm { rd, imm }),
            (8, X86Instruction::OrReg { rd, rs }),
            (9, X86Instruction::OrImm { rd, imm }),
            (10, X86Instruction::XorReg { rd, rs }),
            (11, X86Instruction::XorImm { rd, imm }),
            (12, X86Instruction::CmpReg { rn: rd, rs }),
            (13, X86Instruction::CmpImm { rn: rd, imm }),
            (14, X86Instruction::TestReg { rn: rd, rs }),
            (15, X86Instruction::TestImm { rn: rd, imm }),
            (16, X86Instruction::Neg { rd }),
            (17, X86Instruction::Not { rd }),
            (18, X86Instruction::Inc { rd }),
            (19, X86Instruction::Dec { rd }),
            (20, X86Instruction::Shl { rd, imm }),
            (21, X86Instruction::Shr { rd, imm }),
            (22, X86Instruction::Sar { rd, imm }),
            (23, X86Instruction::Rol { rd, imm }),
            (24, X86Instruction::Ror { rd, imm }),
            (25, X86Instruction::ImulReg { rd, rs }),
            (26, X86Instruction::ImulRegImm { rd, rs, imm }),
            (
                27,
                X86Instruction::Lea {
                    rd,
                    base: rs,
                    disp: imm,
                },
            ),
            (
                28,
                X86Instruction::Movzx {
                    rd,
                    rs,
                    src_width: 8,
                },
            ),
            (
                29,
                X86Instruction::Movsx {
                    rd,
                    rs,
                    src_width: 8,
                },
            ),
            (30, X86Instruction::Cmov { rd, rs, cond }),
            (31, X86Instruction::Setcc { rd, cond }),
        ];

        for (opcode, want) in expected {
            assert_eq!(
                build_x86_instruction_by_opcode(opcode, rd, rs, imm, cond, 8),
                want,
                "opcode {opcode} built the wrong instruction"
            );
        }

        // Sanity-check the mnemonic family for each opcode too, so a future
        // variant swap that preserves struct shape still trips the guard.
        let mnemonics: [(u8, &str); X86_REWRITABLE_OPCODE_COUNT as usize] = [
            (0, "mov"),
            (1, "mov"),
            (2, "add"),
            (3, "add"),
            (4, "sub"),
            (5, "sub"),
            (6, "and"),
            (7, "and"),
            (8, "or"),
            (9, "or"),
            (10, "xor"),
            (11, "xor"),
            (12, "cmp"),
            (13, "cmp"),
            (14, "test"),
            (15, "test"),
            (16, "neg"),
            (17, "not"),
            (18, "inc"),
            (19, "dec"),
            (20, "shl"),
            (21, "shr"),
            (22, "sar"),
            (23, "rol"),
            (24, "ror"),
            (25, "imul"),
            (26, "imul"),
            (27, "lea"),
            (28, "movzx"),
            (29, "movsx"),
            (30, "cmove"),
            (31, "sete"),
        ];
        for (opcode, mnem) in mnemonics {
            assert_eq!(
                build_x86_instruction_by_opcode(opcode, rd, rs, imm, cond, 8).mnemonic(),
                mnem,
                "opcode {opcode} mnemonic drifted"
            );
        }
    }

    #[test]
    fn x86_mutator_preserves_sequence_length() {
        use super::{default_x86_immediates, default_x86_registers};
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            default_x86_registers(),
            default_x86_immediates(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 5,
            },
        ];
        for seed in 0..50u64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let mutated = mutator.mutate(&mut rng, &target);
            assert_eq!(
                mutated.len(),
                target.len(),
                "seed {} changed sequence length",
                seed
            );
        }
    }

    #[test]
    fn x86_mutator_instruction_replacement_filters_self_cmov_candidates() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX, X86Register::RBX],
            vec![0i64, 1],
            MutationWeights {
                operand: 0.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 1.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(453);
        let mut saw_cmov = false;

        for _ in 0..2000 {
            let mutated = mutator.mutate(&mut rng, &target);
            if let X86Instruction::Cmov { rd, rs, .. } = mutated[0] {
                saw_cmov = true;
                assert_ne!(rd, rs, "replacement mutator emitted self-CMOV {mutated:?}");
            }
        }

        assert!(saw_cmov, "replacement mutator never emitted CMOVcc");
    }

    #[test]
    fn x86_mutator_operand_keeps_cmov_registers_distinct() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX, X86Register::RBX],
            vec![0i64, 1],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(453);

        for _ in 0..2000 {
            let mutated = mutator.mutate(&mut rng, &target);
            let X86Instruction::Cmov { rd, rs, .. } = mutated[0] else {
                panic!("operand mutator changed CMOV opcode: {mutated:?}");
            };
            assert_ne!(rd, rs, "operand mutator emitted self-CMOV {mutated:?}");
        }
    }

    #[test]
    fn x86_stochastic_cmov_filters_handle_degenerate_register_pools() {
        use crate::isa::traits::{ISAMutator, InstructionGenerator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        for regs in [
            vec![X86Register::RAX],
            vec![X86Register::RAX, X86Register::RAX],
        ] {
            let imms = [0i64, 1];
            let mut generator_rng = ChaCha8Rng::seed_from_u64(453);
            for _ in 0..500 {
                let instr =
                    X86InstructionGenerator.generate_random(&mut generator_rng, &regs, &imms);
                assert!(
                    !matches!(instr, X86Instruction::Cmov { .. }),
                    "random generator emitted CMOV from degenerate pool {regs:?}: {instr:?}"
                );
            }

            let replacement_mutator = X86Mutator::new(
                regs.clone(),
                imms.to_vec(),
                MutationWeights {
                    operand: 0.0,
                    opcode: 0.0,
                    swap: 0.0,
                    instruction: 1.0,
                },
                crate::assembler::x86::X86Mode::Mode64,
            );
            let target = vec![X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            }];
            let mut replacement_rng = ChaCha8Rng::seed_from_u64(453);
            for _ in 0..500 {
                let mutated = replacement_mutator.mutate(&mut replacement_rng, &target);
                assert!(
                    !matches!(mutated[0], X86Instruction::Cmov { .. }),
                    "replacement mutator emitted CMOV from degenerate pool {regs:?}: {mutated:?}"
                );
            }

            let operand_mutator = X86Mutator::new(
                regs,
                imms.to_vec(),
                MutationWeights {
                    operand: 1.0,
                    opcode: 0.0,
                    swap: 0.0,
                    instruction: 0.0,
                },
                crate::assembler::x86::X86Mode::Mode64,
            );
            let cmov_target = vec![X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            }];
            let mut operand_rng = ChaCha8Rng::seed_from_u64(453);
            for _ in 0..100 {
                let mutated = operand_mutator.mutate(&mut operand_rng, &cmov_target);
                let X86Instruction::Cmov { rd, rs, .. } = mutated[0] else {
                    panic!("operand mutator changed CMOV opcode: {mutated:?}");
                };
                assert_ne!(
                    rd, rs,
                    "operand mutator collapsed CMOV with degenerate pool: {mutated:?}"
                );
            }
        }
    }

    #[test]
    fn x86_mutator_mode32_never_emits_extended_registers() {
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        // Pool deliberately includes R8-R15 to verify Mode32 filters
        // them out at construction time.
        let pool = vec![
            X86Register::RAX,
            X86Register::RCX,
            X86Register::R8,
            X86Register::R9,
            X86Register::R15,
        ];
        let mutator = X86Mutator::new(
            pool,
            vec![0i64, 1],
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode32,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut seq = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        for _ in 0..500 {
            seq = mutator.mutate(&mut rng, &seq);
            for instr in &seq {
                if let Some(rd) = instr.destination() {
                    assert!(
                        matches!(rd.index(), Some(i) if i < 8),
                        "Mode32 produced extended rd {:?}",
                        rd
                    );
                }
                for rs in instr.source_registers() {
                    assert!(
                        matches!(rs.index(), Some(i) if i < 8),
                        "Mode32 produced extended rs {:?}",
                        rs
                    );
                }
            }
        }
    }

    #[test]
    fn x86_mutator_mode32_filters_immediate_pool_to_encodable_bitpatterns() {
        use crate::isa::traits::{Assembler, ISAMutator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::collections::BTreeSet;

        let mutator = X86Mutator::new(
            Vec::new(),
            vec![
                i64::from(i32::MIN) - 1,
                i64::from(i32::MIN),
                i64::from(i32::MAX),
                i64::from(u32::MAX),
                i64::from(u32::MAX) + 1,
                i64::MAX,
            ],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode32,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(500);
        let mut seq = vec![X86Instruction::AddImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mut seen = BTreeSet::new();

        for _ in 0..1000 {
            seq = mutator.mutate(&mut rng, &seq);
            let [X86Instruction::AddImm { rd, imm }] = seq.as_slice() else {
                panic!("operand-only mutation changed instruction shape: {seq:?}");
            };
            let instr = X86Instruction::AddImm { rd: *rd, imm: *imm };
            assert!(
                <X86_32 as Assembler<X86Instruction>>::can_assemble(&X86_32, &instr),
                "Mode32 mutator emitted unencodable immediate {imm}"
            );
            seen.insert(*imm);
        }

        assert!(seen.contains(&i64::from(i32::MIN)));
        assert!(seen.contains(&i64::from(i32::MAX)));
        assert!(seen.contains(&i64::from(u32::MAX)));
    }

    #[test]
    fn x86_mutator_mode64_splits_movabs_from_non_mov_immediate_pool() {
        use crate::isa::traits::{Assembler, ISAMutator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;
        use std::collections::BTreeSet;

        let mutator = X86Mutator::new(
            Vec::new(),
            vec![
                i64::MAX,
                i64::from(i32::MIN),
                i64::from(i32::MAX),
                i64::from(i32::MAX) + 1,
            ],
            MutationWeights {
                operand: 1.0,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );

        let mut mov_rng = ChaCha8Rng::seed_from_u64(501);
        let mut mov_seq = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mut saw_movabs = false;
        for _ in 0..1000 {
            mov_seq = mutator.mutate(&mut mov_rng, &mov_seq);
            let [X86Instruction::MovImm { imm, .. }] = mov_seq.as_slice() else {
                panic!("operand-only mutation changed MOV shape: {mov_seq:?}");
            };
            saw_movabs |= *imm == i64::MAX;
        }
        assert!(saw_movabs, "Mode64 MOV immediate pool lost MOVABS values");

        let non_mov_forms: [ImmForm; 6] = [
            ("add", |imm| X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("sub", |imm| X86Instruction::SubImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("and", |imm| X86Instruction::AndImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("or", |imm| X86Instruction::OrImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("xor", |imm| X86Instruction::XorImm {
                rd: X86Register::RAX,
                imm,
            }),
            ("cmp", |imm| X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm,
            }),
        ];

        for (name, form) in non_mov_forms {
            let mut rng = ChaCha8Rng::seed_from_u64(502);
            let mut seq = vec![form(0)];
            let mut seen = BTreeSet::new();
            for _ in 0..1000 {
                seq = mutator.mutate(&mut rng, &seq);
                let [instr] = seq.as_slice() else {
                    panic!("operand-only mutation changed {name} sequence length: {seq:?}");
                };
                assert!(
                    <X86_64 as Assembler<X86Instruction>>::can_assemble(&X86_64, instr),
                    "Mode64 mutator emitted unencodable {name} immediate: {instr:?}"
                );
                let imm = match instr {
                    X86Instruction::AddImm { imm, .. }
                    | X86Instruction::SubImm { imm, .. }
                    | X86Instruction::AndImm { imm, .. }
                    | X86Instruction::OrImm { imm, .. }
                    | X86Instruction::XorImm { imm, .. }
                    | X86Instruction::CmpImm { imm, .. } => *imm,
                    other => panic!("operand-only mutation changed {name} shape: {other:?}"),
                };
                seen.insert(imm);
            }
            assert!(seen.contains(&i64::from(i32::MIN)), "{name} lost i32::MIN");
            assert!(seen.contains(&i64::from(i32::MAX)), "{name} lost i32::MAX");
        }
    }

    #[test]
    fn x86_mutator_mode64_operand_and_instruction_mutations_keep_non_mov_immediates_encodable() {
        use crate::isa::traits::{Assembler, ISAMutator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX, X86Register::RBX],
            vec![i64::MAX, 17, i64::from(i32::MAX) + 1],
            MutationWeights {
                operand: 0.5,
                opcode: 0.0,
                swap: 0.0,
                instruction: 0.5,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(503);
        let mut seq = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 0,
            },
        ];
        let mut saw_movabs = false;
        let mut saw_non_mov_immediate = false;

        for _ in 0..5000 {
            seq = mutator.mutate(&mut rng, &seq);
            for instr in &seq {
                match instr {
                    X86Instruction::MovImm { imm, .. } => {
                        saw_movabs |= *imm == i64::MAX;
                    }
                    X86Instruction::AddImm { .. }
                    | X86Instruction::SubImm { .. }
                    | X86Instruction::AndImm { .. }
                    | X86Instruction::OrImm { .. }
                    | X86Instruction::XorImm { .. }
                    | X86Instruction::CmpImm { .. }
                    | X86Instruction::TestImm { .. }
                    // Shifts and rotates carry an imm8 count; the same
                    // encodability invariant applies — `can_assemble` must
                    // accept them.
                    | X86Instruction::Shl { .. }
                    | X86Instruction::Shr { .. }
                    | X86Instruction::Sar { .. }
                    | X86Instruction::Rol { .. }
                    | X86Instruction::Ror { .. }
                    // The 3-operand IMUL immediate is imm32; same encodability
                    // invariant. LEA's displacement is also a disp32 with the
                    // same encodability requirement.
                    | X86Instruction::ImulRegImm { .. }
                    | X86Instruction::Lea { .. } => {
                        saw_non_mov_immediate = true;
                        assert!(
                            <X86_64 as Assembler<X86Instruction>>::can_assemble(&X86_64, instr),
                            "Mode64 mutation emitted unencodable non-MOV immediate: {instr:?}"
                        );
                    }
                    X86Instruction::MovReg { .. }
                    | X86Instruction::Movzx { .. }
                    | X86Instruction::Movsx { .. }
                    | X86Instruction::AddReg { .. }
                    | X86Instruction::SubReg { .. }
                    | X86Instruction::AndReg { .. }
                    | X86Instruction::OrReg { .. }
                    | X86Instruction::XorReg { .. }
                    | X86Instruction::CmpReg { .. }
                    | X86Instruction::TestReg { .. }
                    | X86Instruction::Neg { .. }
                    | X86Instruction::Not { .. }
                    | X86Instruction::Inc { .. }
                    | X86Instruction::Dec { .. }
                    | X86Instruction::ImulReg { .. }
                    | X86Instruction::Cmov { .. }
                    | X86Instruction::Setcc { .. }
                    | X86Instruction::Jcc { .. } => {}
                }
            }
        }

        assert!(saw_movabs, "Mode64 MOV mutation never drew i64::MAX");
        assert!(
            saw_non_mov_immediate,
            "test never observed a non-MOV immediate mutation"
        );
    }

    #[test]
    fn x86_mutator_mode64_opcode_mutation_replaces_movabs_immediate_for_non_mov_forms() {
        use crate::isa::traits::{Assembler, ISAMutator};
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            vec![X86Register::RAX],
            vec![7],
            MutationWeights {
                operand: 0.0,
                opcode: 1.0,
                swap: 0.0,
                instruction: 0.0,
            },
            crate::assembler::x86::X86Mode::Mode64,
        );
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: i64::MAX,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(504);
        let mut saw_non_mov_bridge = false;

        for _ in 0..100 {
            let mutated = mutator.mutate(&mut rng, &target);
            let [instr] = mutated.as_slice() else {
                panic!("opcode-only mutation changed sequence length: {mutated:?}");
            };
            match instr {
                X86Instruction::MovImm { imm, .. } => {
                    assert_eq!(*imm, i64::MAX, "MOVABS immediate should stay valid for MOV");
                }
                X86Instruction::AddImm { .. }
                | X86Instruction::SubImm { .. }
                | X86Instruction::AndImm { .. }
                | X86Instruction::OrImm { .. }
                | X86Instruction::XorImm { .. } => {
                    saw_non_mov_bridge = true;
                    assert!(
                        <X86_64 as Assembler<X86Instruction>>::can_assemble(&X86_64, instr),
                        "opcode mutation carried a MOVABS immediate into {instr:?}"
                    );
                }
                other => panic!("unexpected opcode mutation from MOV immediate: {other:?}"),
            }
        }

        assert!(
            saw_non_mov_bridge,
            "test never observed MOV immediate bridge to a non-MOV form"
        );
    }

    #[test]
    fn x86_mutator_destructive_form_invariant() {
        // For every destructive variant (non-MOV, non-CMP that writes
        // rd), `rd` must appear in `source_registers()` per
        // src/isa/x86.rs:228-245. The mutator must preserve that.
        use super::{default_x86_immediates, default_x86_registers};
        use crate::isa::traits::ISAMutator;
        use crate::search::config::MutationWeights;
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mutator = X86Mutator::new(
            default_x86_registers(),
            default_x86_immediates(),
            MutationWeights::default(),
            crate::assembler::x86::X86Mode::Mode64,
        );
        let seed_target = vec![X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        let mut seq = seed_target;
        for _ in 0..300 {
            seq = mutator.mutate(&mut rng, &seq);
            for instr in &seq {
                let destructive = matches!(
                    instr,
                    X86Instruction::AddReg { .. }
                        | X86Instruction::SubReg { .. }
                        | X86Instruction::AndReg { .. }
                        | X86Instruction::OrReg { .. }
                        | X86Instruction::XorReg { .. }
                        | X86Instruction::AddImm { .. }
                        | X86Instruction::SubImm { .. }
                        | X86Instruction::AndImm { .. }
                        | X86Instruction::OrImm { .. }
                        | X86Instruction::XorImm { .. }
                );
                if destructive && let Some(rd) = instr.destination() {
                    assert!(
                        instr.source_registers().contains(&rd),
                        "destructive {:?} dropped rd from sources",
                        instr
                    );
                }
            }
        }
    }
}
