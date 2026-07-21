//! End-to-end coverage for carry-aware arithmetic (issue #205): parse
//! ADC/ADCS-bearing assembly through the public parser, then exercise it via
//! the concrete interpreter and the equivalence checker. Deterministic — no
//! timed search.

use s11::ir::{Instruction, Register};
use s11::parser::{LineResult, parse_line};
use s11::semantics::concrete::apply_instruction_concrete;
use s11::semantics::equivalence::{EquivalenceResult, check_equivalence};
use s11::semantics::state::ConcreteMachineState;
use std::collections::HashMap;

fn parse_seq(lines: &[&str]) -> Vec<Instruction> {
    lines
        .iter()
        .map(|line| match parse_line(line).expect("parse") {
            LineResult::Instruction(instr) => instr,
            other => panic!("expected an instruction for {line:?}, got {other:?}"),
        })
        .collect()
}

/// A two-word (128-bit) add `(x3:x2) += (x5:x4)` expressed as the canonical
/// `adds`/`adc` pair must thread the carry across the word boundary.
#[test]
fn adds_adc_compute_128bit_add_across_carry() {
    let seq = parse_seq(&["adds x2, x2, x4", "adc x3, x3, x5"]);

    // A = 2^64 - 1 (low = u64::MAX, high = 0), B = 1 (low = 1, high = 0).
    // The low add overflows, so the carry must propagate into the high word.
    let mut values = HashMap::new();
    values.insert(Register::X2, u64::MAX);
    values.insert(Register::X3, 0);
    values.insert(Register::X4, 1);
    values.insert(Register::X5, 0);

    let mut state = ConcreteMachineState::from_values(values);
    for instr in &seq {
        state = apply_instruction_concrete(state, instr);
    }

    // A + B = 2^64  ->  (x3:x2) = (1, 0).
    assert_eq!(state.get_register(Register::X2).as_u64(), 0);
    assert_eq!(state.get_register(Register::X3).as_u64(), 1);
}

/// Replacing the carry-absorbing `adc` tail with a plain `add` drops the
/// carry-out of the first `adds`, changing the high word. The equivalence
/// checker must reject the rewrite, while the chain is equivalent to itself.
#[test]
fn dropping_the_adc_carry_tail_is_not_equivalent() {
    let full = parse_seq(&["adds x2, x2, x4", "adc x3, x3, x5"]);
    let dropped = parse_seq(&["adds x2, x2, x4", "add x3, x3, x5"]);

    let result = check_equivalence(&full, &dropped);
    assert!(
        matches!(
            result,
            EquivalenceResult::NotEquivalent | EquivalenceResult::NotEquivalentFast(_)
        ),
        "ignoring the carry tail changes the high word; got {result:?}"
    );

    assert_eq!(
        check_equivalence(&full, &full),
        EquivalenceResult::Equivalent,
        "the carry chain is equivalent to itself"
    );
}
