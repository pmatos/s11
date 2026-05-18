//! Concrete (non-symbolic) interpreter for the x86 backend.
//!
//! Mirrors `semantics::concrete::apply_instruction_concrete` but over
//! ## Deletion gate
//!
//! Issue #77 stage 2 step 18 plans to delete this file once
//! `optimize_elf_binary_x86` (src/main.rs) and the x86 unit tests below
//! route through `<X86_64 as ConcreteExecutor<X86Instruction>>::execute_instruction`
//! (added in step 17). That migration is blocked on the
//! SearchAlgorithm<I> follow-up to step 11. Until then this file is the
//! authoritative x86 concrete interpreter and the trait impl delegates here.
//!
//! `X86Instruction` and `X86ConcreteMachineState`. Operand widths follow
//! `state.width()` — writes to registers are already masked by the
//! state, and flag computation receives the correct width.

#![allow(dead_code)]

use crate::isa::x86::{X86Instruction, X86Operand};
use crate::semantics::state::{ConcreteValue, Eflags, X86ConcreteMachineState};

/// Apply a single x86 instruction to a concrete machine state.
pub fn apply_instruction_concrete_x86(
    mut state: X86ConcreteMachineState,
    instruction: &X86Instruction,
) -> X86ConcreteMachineState {
    match instruction {
        X86Instruction::MovReg { rd, rs } => {
            let value = state.get_register(*rs);
            state.set_register(*rd, value);
        }
        X86Instruction::MovImm { rd, imm } => {
            state.set_register(*rd, ConcreteValue::from_i64(*imm));
        }
        X86Instruction::AddReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::Add),
        X86Instruction::AddImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::Add),
        X86Instruction::SubReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::Sub),
        X86Instruction::SubImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::Sub),
        X86Instruction::AndReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::And),
        X86Instruction::AndImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::And),
        X86Instruction::OrReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::Or),
        X86Instruction::OrImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::Or),
        X86Instruction::XorReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::Xor),
        X86Instruction::XorImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::Xor),
        X86Instruction::CmpReg { rn, rs } => apply_cmp_reg(&mut state, *rn, *rs),
        X86Instruction::CmpImm { rn, imm } => apply_cmp_imm(&mut state, *rn, *imm),
    }
    state
}

fn apply_cmp_reg(
    state: &mut X86ConcreteMachineState,
    rn: crate::isa::x86::X86Register,
    rs: crate::isa::x86::X86Register,
) {
    let lhs = state.get_register(rn).as_u64();
    let rhs = state.get_register(rs).as_u64();
    let result = lhs.wrapping_sub(rhs);
    state.set_flags(Eflags::from_sub(lhs, rhs, result, state.width()));
}

fn apply_cmp_imm(state: &mut X86ConcreteMachineState, rn: crate::isa::x86::X86Register, imm: i64) {
    let lhs = state.get_register(rn).as_u64();
    let rhs = imm as u64;
    let result = lhs.wrapping_sub(rhs);
    state.set_flags(Eflags::from_sub(lhs, rhs, result, state.width()));
}

#[derive(Clone, Copy)]
enum Binop {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

fn apply_binop_reg(
    state: &mut X86ConcreteMachineState,
    rd: crate::isa::x86::X86Register,
    rs: crate::isa::x86::X86Register,
    op: Binop,
) {
    let lhs = state.get_register(rd).as_u64();
    let rhs = state.get_register(rs).as_u64();
    apply_binop(state, rd, lhs, rhs, op);
}

fn apply_binop_imm(
    state: &mut X86ConcreteMachineState,
    rd: crate::isa::x86::X86Register,
    imm: i64,
    op: Binop,
) {
    let lhs = state.get_register(rd).as_u64();
    let rhs = imm as u64;
    apply_binop(state, rd, lhs, rhs, op);
}

fn apply_binop(
    state: &mut X86ConcreteMachineState,
    rd: crate::isa::x86::X86Register,
    lhs: u64,
    rhs: u64,
    op: Binop,
) {
    let width = state.width();
    let (result, flags) = match op {
        Binop::Add => {
            let r = lhs.wrapping_add(rhs);
            (r, Eflags::from_add(lhs, rhs, r, width))
        }
        Binop::Sub => {
            let r = lhs.wrapping_sub(rhs);
            (r, Eflags::from_sub(lhs, rhs, r, width))
        }
        Binop::And => {
            let r = lhs & rhs;
            (r, Eflags::from_logical(r, width))
        }
        Binop::Or => {
            let r = lhs | rhs;
            (r, Eflags::from_logical(r, width))
        }
        Binop::Xor => {
            let r = lhs ^ rhs;
            (r, Eflags::from_logical(r, width))
        }
    };
    state.set_register(rd, ConcreteValue::new(result));
    state.set_flags(flags);
}

/// Convenience for tests / callers that don't have an operand wrapper.
fn _operand_unused(_op: X86Operand) {}

/// Apply a sequence of x86 instructions to a concrete machine state.
/// Mirrors `apply_sequence_concrete` for AArch64; used by
/// stochastic/symbolic search to evaluate a candidate against a test
/// input.
pub fn apply_sequence_concrete_x86(
    state: crate::semantics::state::X86ConcreteMachineState,
    sequence: &[X86Instruction],
) -> crate::semantics::state::X86ConcreteMachineState {
    let mut s = state;
    for instr in sequence {
        s = apply_instruction_concrete_x86(s, instr);
    }
    s
}

/// Compare two x86 concrete states over the registers (and, when
/// `mask.flags_live()`, the EFLAGS) declared live-out by `mask`.
pub fn states_equal_for_live_out_x86(
    state1: &crate::semantics::state::X86ConcreteMachineState,
    state2: &crate::semantics::state::X86ConcreteMachineState,
    mask: &crate::semantics::state::X86LiveOutMask,
) -> bool {
    for reg in mask.iter() {
        if state1.get_register(*reg) != state2.get_register(*reg) {
            return false;
        }
    }
    if mask.flags_live() && state1.get_flags() != state2.get_flags() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::x86::X86Register;

    #[test]
    fn cmpreg_sets_eflags_without_writing_register() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(5));
        state.set_register(X86Register::RBX, ConcreteValue::new(5));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        // Equal operands -> ZF set, no borrow.
        let flags = after.get_flags();
        assert!(flags.zf);
        assert!(!flags.cf);
        // Operand registers must be unchanged.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 5);
        assert_eq!(after.get_register(X86Register::RBX).as_u64(), 5);
    }

    #[test]
    fn cmpimm_less_than_sets_cf_and_sf() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(3));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 5,
            },
        );
        assert!(after.get_flags().cf, "3 < 5 -> borrow");
        assert!(after.get_flags().sf);
        // rn must be untouched.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 3);
    }

    #[test]
    fn xorreg_self_clears_register_and_sets_zf() {
        // The canonical x86 zeroing idiom: `xor rax, rax`.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0x42));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::XorReg {
                rd: X86Register::RAX,
                rs: X86Register::RAX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0);
        let flags = after.get_flags();
        assert!(flags.zf, "zero flag set");
        assert!(!flags.cf, "CF cleared by logical");
        assert!(!flags.of, "OF cleared by logical");
        assert!(!flags.sf);
        assert!(flags.pf, "zero has even parity");
    }

    #[test]
    fn andimm_masks_register() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xff_ff));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::AndImm {
                rd: X86Register::RAX,
                imm: 0xff,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xff);
        assert!(!after.get_flags().cf);
        assert!(!after.get_flags().of);
    }

    #[test]
    fn orreg_combines_bits() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xf0));
        state.set_register(X86Register::RBX, ConcreteValue::new(0x0f));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::OrReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xff);
        assert!(!after.get_flags().zf);
    }

    #[test]
    fn addreg_writes_sum_and_sets_eflags() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(3));
        state.set_register(X86Register::RBX, ConcreteValue::new(4));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 7);
        let flags = after.get_flags();
        assert!(!flags.cf);
        assert!(!flags.zf);
        assert!(!flags.sf);
        assert!(!flags.of);
    }

    #[test]
    fn addimm_carries_set_cf() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(u64::MAX));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0);
        assert!(after.get_flags().cf, "carry expected");
        assert!(after.get_flags().zf, "result is zero");
    }

    #[test]
    fn subreg_writes_difference_and_sets_eflags() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(10));
        state.set_register(X86Register::RBX, ConcreteValue::new(3));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::SubReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 7);
        assert!(!after.get_flags().cf, "no borrow");
        assert!(!after.get_flags().zf);
    }

    #[test]
    fn subimm_borrow_sets_cf_and_sf() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(3));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::SubImm {
                rd: X86Register::RAX,
                imm: 5,
            },
        );
        // 3 - 5 = -2 → 0xff..fe.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), u64::MAX - 1);
        assert!(after.get_flags().cf, "borrow");
        assert!(after.get_flags().sf, "negative");
    }

    #[test]
    fn movreg_copies_source_to_destination() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RBX, ConcreteValue::new(0xcafebabe));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xcafebabe);
        // Source unchanged.
        assert_eq!(after.get_register(X86Register::RBX).as_u64(), 0xcafebabe);
        // MOV does not change EFLAGS.
        assert_eq!(after.get_flags(), Eflags::default());
    }

    #[test]
    fn movimm_loads_immediate() {
        let state = X86ConcreteMachineState::new_zeroed(64);
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 42,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 42);
        assert_eq!(after.get_flags(), Eflags::default());
    }

    #[test]
    fn movimm_in_32bit_state_truncates_to_low_32() {
        let state = X86ConcreteMachineState::new_zeroed(32);
        // i64 with high bits set; the 32-bit state must truncate.
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0x1_0000_0042i64,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0x0000_0042);
    }

    // ---- apply_sequence_concrete_x86 + states_equal_for_live_out_x86 ----

    #[test]
    fn apply_sequence_concrete_x86_threads_state_left_to_right() {
        use crate::semantics::state::{ConcreteValue, X86ConcreteMachineState};

        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RBX, ConcreteValue::new(7));
        let seq = vec![
            X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 3,
            },
        ];
        let after = apply_sequence_concrete_x86(state, &seq);
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 10);
    }

    #[test]
    fn states_equal_for_live_out_x86_ignores_non_live_registers() {
        use crate::semantics::state::{ConcreteValue, X86ConcreteMachineState, X86LiveOutMask};

        let mut a = X86ConcreteMachineState::new_zeroed(64);
        let mut b = X86ConcreteMachineState::new_zeroed(64);
        a.set_register(X86Register::RAX, ConcreteValue::new(42));
        b.set_register(X86Register::RAX, ConcreteValue::new(42));
        a.set_register(X86Register::RCX, ConcreteValue::new(1));
        b.set_register(X86Register::RCX, ConcreteValue::new(99)); // differs

        // Only RAX live-out: equal.
        let mask = X86LiveOutMask::from_registers(vec![X86Register::RAX]);
        assert!(states_equal_for_live_out_x86(&a, &b, &mask));

        // RCX live-out too: unequal.
        let mask = X86LiveOutMask::from_registers(vec![X86Register::RAX, X86Register::RCX]);
        assert!(!states_equal_for_live_out_x86(&a, &b, &mask));
    }

    #[test]
    fn states_equal_for_live_out_x86_honours_flags_live() {
        use crate::semantics::state::{
            ConcreteValue, Eflags, X86ConcreteMachineState, X86LiveOutMask,
        };

        let mut a = X86ConcreteMachineState::new_zeroed(64);
        let mut b = X86ConcreteMachineState::new_zeroed(64);
        a.set_register(X86Register::RAX, ConcreteValue::new(0));
        b.set_register(X86Register::RAX, ConcreteValue::new(0));
        let mut flags_set = Eflags::new();
        flags_set.zf = true;
        a.set_flags(flags_set);
        // b keeps default (zf = false).

        let no_flags = X86LiveOutMask::from_registers(vec![X86Register::RAX]);
        assert!(states_equal_for_live_out_x86(&a, &b, &no_flags));

        let with_flags = no_flags.with_flags(true);
        assert!(!states_equal_for_live_out_x86(&a, &b, &with_flags));
    }
}
