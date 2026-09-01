//! Capstone instruction-detail reduction for the whole-binary `--auto` driver
//! (ADR-0009).
//!
//! Candidate-window discovery has two soundness-critical questions to ask of
//! every decoded instruction — *is it a call?*, *does it touch RIP-relative
//! memory?*, *which direct branch targets does it name?* — and Capstone answers
//! all three only through a borrowed [`capstone::InsnDetail`] whose lifetime is
//! tied to the disassembly buffer. Those predicates used to sit inline in the
//! binary's `find_candidate_windows` adapter, interleaved with ELF I/O and the
//! run-splitting state machine, so the only way to exercise a group-filter or
//! operand-typing rule was to build a whole ELF fixture in memory.
//!
//! This module lifts the detail inspection into a **pure seam**:
//! [`inspect_capstone_instruction_detail`] reduces one borrowed detail into the
//! owned [`CapstoneInstructionFacts`] the planner needs (so the borrow never
//! extends across section processing), and the three predicates behind it are
//! each independently testable against a single disassembled instruction. The
//! adapter in `src/main.rs` keeps only the ELF plumbing; every Capstone
//! group/operand rule is a fixture-free unit test here.
//!
//! The pure run-splitting algorithm these facts feed lives in
//! [`crate::candidate_windows`]; this module is its Capstone-facing counterpart.

use capstone::prelude::*;

/// Owned facts reduced from one borrowed Capstone detail inspection.
///
/// Keeping only planning inputs lets the two candidate-finder phases share the
/// result without extending `InsnDetail`'s borrow across section processing.
#[derive(Debug)]
pub struct CapstoneInstructionFacts {
    /// Absolute addresses named by a direct branch/call (see
    /// [`capstone_detail_direct_branch_targets`]); empty for everything else.
    pub direct_branch_targets: Vec<u64>,
    /// Whether the instruction is a call (Capstone's semantic call group).
    pub is_call: bool,
    /// Whether an x86-64 operand reads or writes RIP-relative memory.
    pub has_rip_relative_memory: bool,
}

/// Reduce one instruction's borrowed Capstone detail to the owned planning
/// facts candidate-window discovery needs.
///
/// Failure to obtain the detail is reported against the section name and
/// instruction address so a mid-section decode fault fails closed with a
/// locatable message rather than silently dropping the instruction.
pub fn inspect_capstone_instruction_detail(
    cs: &Capstone,
    instruction: &capstone::Insn<'_>,
    section_name: &str,
) -> Result<CapstoneInstructionFacts, Box<dyn std::error::Error>> {
    let detail = cs
        .insn_detail(instruction)
        .map_err(|error| instruction_detail_error(section_name, instruction.address(), error))?;
    Ok(CapstoneInstructionFacts {
        direct_branch_targets: capstone_detail_direct_branch_targets(&detail),
        is_call: capstone_detail_is_call(&detail),
        has_rip_relative_memory: capstone_detail_has_rip_relative_memory(&detail),
    })
}

fn instruction_detail_error(
    section_name: &str,
    instruction_address: u64,
    error: capstone::Error,
) -> String {
    format!(
        "failed to inspect instruction detail in executable section '{}' at 0x{:x}: {}",
        section_name, instruction_address, error
    )
}

/// Whether the instruction belongs to Capstone's semantic call group.
pub fn capstone_detail_is_call(detail: &capstone::InsnDetail<'_>) -> bool {
    let call_group =
        capstone::InsnGroupId(capstone::InsnGroupType::CS_GRP_CALL as capstone::InsnGroupIdInt);
    detail.groups().contains(&call_group)
}

/// Whether any x86-64 operand names RIP-relative memory.
pub fn capstone_detail_has_rip_relative_memory(detail: &capstone::InsnDetail<'_>) -> bool {
    let arch_detail = detail.arch_detail();
    let Some(x86_detail) = arch_detail.x86() else {
        return false;
    };
    let rip = capstone::RegId(capstone::arch::x86::X86Reg::X86_REG_RIP as capstone::RegIdInt);
    x86_detail.operands().any(|operand| {
        matches!(
            operand.op_type,
            capstone::arch::x86::X86OperandType::Mem(memory) if memory.base() == rip
        )
    })
}

/// Absolute target addresses named by a *direct* branch or call instruction, or
/// an empty vector for non-branch instructions and indirect control transfers.
///
/// Capstone resolves a direct (PC-relative or absolute-immediate) branch/call
/// target to an absolute address in an immediate operand, so the driver
/// recovers the whole in-binary direct-target set by a linear scan
/// (ADR-0009 Decision 4/5). Indirect control flow — register/memory jumps,
/// jump tables, PLT stubs, computed gotos — carries no immediate here and is
/// deliberately invisible; it is the separate soundness gate in issue #619.
///
/// The group filter accepts jumps, calls, and relative branches
/// (`CS_GRP_BRANCH_RELATIVE`). The relative-branch group is load-bearing: x86
/// `loop`/`loope`/`loopne` tag *only* as relative branches — Capstone never
/// adds `CS_GRP_JUMP` to them (their instruction descriptor's `branch` flag is
/// unset) — so filtering on jump/call alone would silently drop their targets
/// and admit an unsound interior. Every immediate on such an instruction is
/// collected. On x86 the sole immediate is the target; on AArch64 `tbz`/`tbnz`
/// also expose a small bit-position immediate, which is harmlessly
/// over-collected: an extra target can only cause an extra window split, never
/// an unsound admit, and a 0..=63 bit index never coincides with a real
/// in-section code address.
pub fn capstone_detail_direct_branch_targets(detail: &capstone::InsnDetail<'_>) -> Vec<u64> {
    let jump =
        capstone::InsnGroupId(capstone::InsnGroupType::CS_GRP_JUMP as capstone::InsnGroupIdInt);
    let branch_relative = capstone::InsnGroupId(
        capstone::InsnGroupType::CS_GRP_BRANCH_RELATIVE as capstone::InsnGroupIdInt,
    );
    let groups = detail.groups();
    if !groups.contains(&jump)
        && !groups.contains(&branch_relative)
        && !capstone_detail_is_call(detail)
    {
        return Vec::new();
    }
    detail
        .arch_detail()
        .operands()
        .into_iter()
        .filter_map(|operand| match operand {
            capstone::arch::ArchOperand::X86Operand(op) => match op.op_type {
                capstone::arch::x86::X86OperandType::Imm(value) => Some(value as u64),
                _ => None,
            },
            capstone::arch::ArchOperand::Arm64Operand(op) => match op.op_type {
                capstone::arch::arm64::Arm64OperandType::Imm(value) => Some(value as u64),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::AArch64Assembler;
    use crate::ir::{Instruction, LabelId, Operand, Register};

    fn assemble_aarch64_test_bytes(instructions: &[Instruction]) -> Vec<u8> {
        AArch64Assembler::new()
            .assemble_instructions(instructions, 0x1000)
            .expect("test instruction should assemble")
    }

    fn aarch64_test_capstone() -> Capstone {
        Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("test capstone should build")
    }

    fn x86_64_test_capstone() -> Capstone {
        Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .syntax(capstone::arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("test capstone should build")
    }

    #[test]
    fn is_call_uses_capstone_semantic_call_group() {
        let cs = x86_64_test_capstone();
        // call 0x1005: e8 00 00 00 00 at 0x1000.
        let call = cs
            .disasm_all(&[0xe8, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .expect("call should disassemble");
        let detail = cs
            .insn_detail(call.iter().next().expect("one call"))
            .expect("call detail should be available");
        assert!(capstone_detail_is_call(&detail));

        // add rax, 1 is not a call.
        let add = cs
            .disasm_all(&[0x48, 0x83, 0xc0, 0x01], 0x1000)
            .expect("add should disassemble");
        let detail = cs
            .insn_detail(add.iter().next().expect("one add"))
            .expect("add detail should be available");
        assert!(!capstone_detail_is_call(&detail));
    }

    #[test]
    fn has_rip_relative_memory_inspects_typed_memory_base() {
        let cs = x86_64_test_capstone();
        // lea rax, [rip + 0]: 48 8d 05 00 00 00 00.
        let rip_relative = cs
            .disasm_all(&[0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00], 0x1004)
            .expect("RIP-relative LEA should disassemble");
        let detail = cs
            .insn_detail(rip_relative.iter().next().expect("one LEA"))
            .expect("LEA detail should be available");
        assert!(
            capstone_detail_has_rip_relative_memory(&detail),
            "RIP-relative exclusion must inspect the typed memory-base operand"
        );

        // add rax, 1 has no memory operand at all.
        let add = cs
            .disasm_all(&[0x48, 0x83, 0xc0, 0x01], 0x1000)
            .expect("add should disassemble");
        let detail = cs
            .insn_detail(add.iter().next().expect("one add"))
            .expect("add detail should be available");
        assert!(!capstone_detail_has_rip_relative_memory(&detail));
    }

    #[test]
    fn direct_branch_targets_extract_absolute_x86_targets_and_skip_indirect() {
        let cs = x86_64_test_capstone();

        // je 0x1006: 74 04 at 0x1000 (next_ip 0x1002 + rel8 0x04). Capstone must
        // hand back the *absolute* target, not the relative displacement.
        let je = cs
            .disasm_all(&[0x74, 0x04], 0x1000)
            .expect("je should disassemble");
        let detail = cs
            .insn_detail(je.iter().next().expect("one je"))
            .expect("je detail should be available");
        assert_eq!(capstone_detail_direct_branch_targets(&detail), vec![0x1006]);

        // call 0x1005: e8 00 00 00 00 at 0x1000 (next_ip 0x1005 + rel32 0).
        let call = cs
            .disasm_all(&[0xe8, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .expect("call should disassemble");
        let detail = cs
            .insn_detail(call.iter().next().expect("one call"))
            .expect("call detail should be available");
        assert_eq!(capstone_detail_direct_branch_targets(&detail), vec![0x1005]);

        // jmp rax: ff e0 — an indirect branch carries no immediate target here
        // (that is issue #619's territory, not this slice's).
        let indirect = cs
            .disasm_all(&[0xff, 0xe0], 0x1000)
            .expect("jmp rax should disassemble");
        let detail = cs
            .insn_detail(indirect.iter().next().expect("one jmp rax"))
            .expect("jmp rax detail should be available");
        assert!(
            capstone_detail_direct_branch_targets(&detail).is_empty(),
            "indirect branches expose no direct target"
        );

        // add rax, 1: 48 83 c0 01 — the group filter must reject a plain
        // arithmetic immediate so ordinary constants never become targets.
        let add = cs
            .disasm_all(&[0x48, 0x83, 0xc0, 0x01], 0x1000)
            .expect("add should disassemble");
        let detail = cs
            .insn_detail(add.iter().next().expect("one add"))
            .expect("add detail should be available");
        assert!(
            capstone_detail_direct_branch_targets(&detail).is_empty(),
            "non-branch immediate operands must not be collected as targets"
        );
    }

    #[test]
    fn direct_branch_targets_include_relative_only_loop_family() {
        // x86 `loop`/`loope`/`loopne` are tagged ONLY with CS_GRP_BRANCH_RELATIVE
        // — Capstone never adds CS_GRP_JUMP to them — so a jump/call-only filter
        // would drop their targets and admit an unsound interior. Each encodes a
        // rel8 of 0xfe (-2): at 0x1000 the next IP is 0x1002, so the target is
        // 0x1000. `jecxz` (0xe3), by contrast, does get CS_GRP_JUMP and is
        // covered by the general path — pinned here so the two stay distinct.
        let cs = x86_64_test_capstone();
        for (label, opcode) in [("loop", 0xe2u8), ("loope", 0xe1), ("loopne", 0xe0)] {
            let disasm = cs
                .disasm_all(&[opcode, 0xfe], 0x1000)
                .unwrap_or_else(|_| panic!("{label} should disassemble"));
            let detail = cs
                .insn_detail(
                    disasm
                        .iter()
                        .next()
                        .unwrap_or_else(|| panic!("one {label}")),
                )
                .unwrap_or_else(|_| panic!("{label} detail should be available"));
            assert_eq!(
                capstone_detail_direct_branch_targets(&detail),
                vec![0x1000],
                "{label} is a relative-only branch whose target must be collected"
            );
        }

        // jecxz: 67 e3 fb — assert only that it is caught (it carries
        // CS_GRP_JUMP), not its exact target; the point is the general jump path
        // already covers it, unlike the loop family above.
        let jecxz = cs
            .disasm_all(&[0x67, 0xe3, 0xfb], 0x1000)
            .expect("jecxz should disassemble");
        let detail = cs
            .insn_detail(jecxz.iter().next().expect("one jecxz"))
            .expect("jecxz detail should be available");
        assert!(
            !capstone_detail_direct_branch_targets(&detail).is_empty(),
            "jecxz carries CS_GRP_JUMP and its target must still be collected"
        );
    }

    #[test]
    fn direct_branch_targets_extract_absolute_aarch64_targets() {
        let cs = aarch64_test_capstone();
        // cbz x0, 0x1000 assembled at 0x1004 resolves to the absolute 0x1000.
        let bytes = assemble_aarch64_test_bytes(&[
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
            Instruction::Cbz {
                rn: Register::X0,
                target: LabelId(0x1000),
            },
        ]);
        let disassembly = cs
            .disasm_all(&bytes, 0x1000)
            .expect("fixture should disassemble");
        let cbz = disassembly.get(1).expect("fixture should contain CBZ");
        let detail = cs.insn_detail(cbz).expect("CBZ detail should be available");
        assert_eq!(
            capstone_detail_direct_branch_targets(&detail),
            vec![0x1000],
            "the register operand is skipped and the branch target resolves absolute"
        );
    }

    #[test]
    fn direct_branch_targets_overcollect_aarch64_tbz_tbnz_bit_positions() {
        let cs = aarch64_test_capstone();
        for (mnemonic, instruction, bit) in [
            (
                "tbz",
                Instruction::Tbz {
                    rt: Register::X0,
                    bit: 5,
                    target: LabelId(0x1100),
                },
                5,
            ),
            (
                "tbnz",
                Instruction::Tbnz {
                    rt: Register::X0,
                    bit: 40,
                    target: LabelId(0x1100),
                },
                40,
            ),
        ] {
            let bytes = assemble_aarch64_test_bytes(&[instruction]);
            let disassembly = cs
                .disasm_all(&bytes, 0x1000)
                .unwrap_or_else(|_| panic!("{mnemonic} fixture should disassemble"));
            let instruction = disassembly
                .iter()
                .next()
                .unwrap_or_else(|| panic!("fixture should contain {mnemonic}"));
            let detail = cs
                .insn_detail(instruction)
                .unwrap_or_else(|_| panic!("{mnemonic} detail should be available"));

            assert_eq!(
                capstone_detail_direct_branch_targets(&detail),
                vec![bit, 0x1100],
                "{mnemonic} bit position and absolute branch target must both be collected"
            );
        }
    }

    #[test]
    fn inspect_reduces_all_three_facts_for_a_call() {
        let cs = x86_64_test_capstone();
        // call 0x1005: e8 00 00 00 00 at 0x1000.
        let call = cs
            .disasm_all(&[0xe8, 0x00, 0x00, 0x00, 0x00], 0x1000)
            .expect("call should disassemble");
        let facts = inspect_capstone_instruction_detail(
            &cs,
            call.iter().next().expect("one call"),
            ".text",
        )
        .expect("detail inspection should succeed");
        assert_eq!(facts.direct_branch_targets, vec![0x1005]);
        assert!(facts.is_call);
        assert!(!facts.has_rip_relative_memory);
    }

    #[test]
    fn inspect_flags_rip_relative_memory_without_a_branch() {
        let cs = x86_64_test_capstone();
        // lea rax, [rip + 0]: 48 8d 05 00 00 00 00.
        let lea = cs
            .disasm_all(&[0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00], 0x1004)
            .expect("RIP-relative LEA should disassemble");
        let facts =
            inspect_capstone_instruction_detail(&cs, lea.iter().next().expect("one LEA"), ".text")
                .expect("detail inspection should succeed");
        assert!(facts.direct_branch_targets.is_empty());
        assert!(!facts.is_call);
        assert!(facts.has_rip_relative_memory);
    }
}
