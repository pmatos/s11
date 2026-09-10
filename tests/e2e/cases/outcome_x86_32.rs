use crate::e2e::harness::{Case, Window, fixture_exists, run};

#[test]
fn dup_mov_collapses_to_one_x86_32() {
    if !fixture_exists("x86_32/dup_mov_imm") {
        eprintln!(
            "Skipping dup_mov_collapses_to_one_x86_32: x86_32/dup_mov_imm \
             fixture not present. Run ./build_tests.sh; it skips x86-32 \
             when gcc -m32 / gcc-multilib is unavailable."
        );
        return;
    }
    run(&Case {
        name: "outcome-x86-32-dup-mov-collapse",
        subcommand: Some("opt"),
        fixture: Some("x86_32/dup_mov_imm"),
        arch: Some("x86-32"),
        window: Some(Window {
            start_addr: "0x8049000",
            end_addr: "0x804900a",
        }),
        args: &["--algorithm", "enumerative", "--timeout", "30", "--force"],
        expected_exit_code: 0,
        expected_instructions: Some((2, 1)),
        ..Default::default()
    });
}
