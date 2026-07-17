//! Cost model for the x86 backend.
//!
//! x86 is variable-length, so `CodeSize` is an approximation per variant.
//! `InstructionCount` counts emitted machine instructions; the full-width
//! SETcc pseudo-instruction counts as its SETcc + MOVZX lowering.
//! Width-aware: x86-32 encodings save one byte per REX prefix.
//!
//! # Latency model (issue #622)
//!
//! `Latency` is NOT a flat per-instruction sum. It is a **critical-path**
//! (dependency-aware) sequence cost so that a serial dependency chain costs
//! more than the same number of independent instructions — which is the whole
//! point of the metric as a "faster sequence" discriminator for `--auto` (see
//! `docs/adr/0009-auto-whole-binary-driver.md`).
//!
//! Two layers:
//!
//! 1. **Per-opcode latency table** ([`instruction_latency`]). Latencies are
//!    sourced from Agner Fog's "Instruction Tables" (<https://agner.org/optimize/>,
//!    accessed 2026-06) for the Intel **Skylake** microarchitecture, cross-checked
//!    against <https://uops.info/>. On Skylake the simple integer ALU ops
//!    (MOV/ADD/SUB/AND/OR/XOR/INC/DEC/NEG/NOT/CMP/TEST/shift-by-imm/rotate-by-imm
//!    including MOVZX/MOVSX and CMOV) have **1-cycle** latency, SETcc's
//!    two-operation lowering has **2-cycle** dependent latency, and
//!    two-operand/three-operand integer multiply
//!    (`IMUL r,r` / `IMUL r,r,imm`) has **3-cycle** latency. A
//!    register-to-register MOV is special-cased to **0** because Skylake (and all
//!    Sandy-Bridge-and-later cores) eliminate it at rename — it never sits on a
//!    dependency chain. `MovImm` is a real 1-cycle op (it is not move-elimination
//!    eligible).
//!
//! 2. **Critical-path sequence latency** ([`critical_path_latency`]). The
//!    sequence cost for `Latency` walks the def-use chains: for each instruction
//!    its issue time is the max completion time over the last writer of every
//!    register it reads (plus EFLAGS when it reads flags); its completion time is
//!    that issue time plus its per-opcode latency. The sequence cost is the
//!    maximum completion time over all instructions, i.e. the length of the
//!    longest dependency chain. This is a pure critical path (no port-pressure /
//!    reciprocal-throughput term) so that the per-instruction lower bound used by
//!    the enumerative pruner stays provably valid — see "Pruning soundness"
//!    below. A throughput term is a possible future refinement but is *not* free:
//!    it would force the pruner's per-instruction lower bound to drop the
//!    throughput contribution (a single instruction's throughput cost can exceed
//!    a long independent sequence's marginal throughput), so it is deferred.
//!
//! ## Pruning soundness (the critical invariant)
//!
//! The enumerative search prunes whole *lengths* using
//! `length_cost_lower_bound`, which must be a VALID LOWER BOUND on the real cost
//! of any sequence of that length — a bound that ever *exceeded* the real cost
//! would prune valid candidates and make the search unsound. Under the
//! critical-path cost a length-`L` sequence can have a critical path as small as
//! the latency of its single cheapest independent instruction (e.g. `L`
//! independent 1-cycle ops cost ~1 on the critical path, NOT `L`). The flat
//! `min_per_instr_cost * L` bound used for the additive metrics is therefore
//! INVALID for `Latency`. The search switches to a trivially-valid constant
//! lower bound for `Latency` — the minimum single-instruction latency in the
//! candidate pool (which is `<=` every non-empty sequence's critical path). See
//! `length_cost_lower_bound` in `src/search/enumerative/search.rs`. The symbolic
//! search prunes per fully-formed candidate against the exact `sequence_cost`, so
//! it stays sound under any cost function with no change.

#![allow(dead_code)]

use crate::isa::x86::{X86Instruction, X86Register, x86_reads_flags};
use crate::semantics::cost::CostMetric;

/// Cost of a single x86 instruction at the given operand width.
///
/// For `Latency` this returns the instruction's *isolated* latency (its
/// per-opcode table value). The sequence-level critical-path combination lives
/// in [`sequence_cost`] / [`critical_path_latency`]; a single instruction's
/// critical path equals its own latency, so the two agree on length-1 inputs.
pub fn instruction_cost(instr: &X86Instruction, metric: &CostMetric, width: u32) -> u64 {
    match metric {
        CostMetric::InstructionCount => match instr {
            X86Instruction::Setcc { .. } => 2,
            _ => 1,
        },
        CostMetric::Latency => instruction_latency(instr),
        CostMetric::CodeSize => instruction_code_size(instr, width),
    }
}

/// Isolated per-opcode latency in cycles, sourced from Agner Fog's Skylake
/// instruction tables (see the module doc-comment).
///
/// - Register-to-register `mov` is **0**: Skylake eliminates it at rename, so it
///   never extends a dependency chain.
/// - Simple integer ALU ops (everything except multiply) are **1** cycle.
/// - `IMUL` (two- and three-operand) is **3** cycles on Skylake.
fn instruction_latency(instr: &X86Instruction) -> u64 {
    match instr {
        // Register-rename move elimination: zero-latency on the critical path.
        X86Instruction::MovReg { .. } => 0,
        // Full-width SETcc lowers to a byte SETcc followed by a dependent MOVZX.
        X86Instruction::Setcc { .. } => 2,
        // Two-/three-operand signed multiply: 3-cycle latency on Skylake.
        X86Instruction::ImulReg { .. } | X86Instruction::ImulRegImm { .. } => 3,
        // Everything else in the supported set is a 1-cycle integer ALU op:
        // MovImm, MOVZX/MOVSX, ADD/SUB/AND/OR/XOR (reg and imm), CMP/TEST,
        // NEG/NOT/INC/DEC, SHL/SHR/SAR/ROL/ROR by immediate, CMOV, and the Jcc
        // terminator (taken-branch latency; misprediction is not modelled).
        _ => 1,
    }
}

/// Approximate encoded length in bytes. Conservative upper bounds.
///
/// - REX prefix adds 1 byte to every x86-64 register op except one naming a
///   legacy high-byte register (dynasm emits REX.W for native operands and a
///   bare 0x40 for dword/word/low-byte operands via its dynamic-register path).
/// - Register-register: opcode + ModR/M = 2 bytes, plus REX for x86-64
///   = 3 bytes.
/// - Register-immediate (32-bit imm): opcode + ModR/M + 4-byte imm
///   = 6 bytes plus REX for x86-64 = 7 bytes.
/// - MOV reg, imm is immediate-dependent (see `MovImm` arm): x86-32 uses the
///   5-byte `B8+rd id`; x86-64 uses the 7-byte `REX.W C7 /0 id` when the
///   immediate fits in i32, else the 10-byte `REX.W B8+rd io` movabs. These
///   match the assembler exactly (a flat cost previously underestimated
///   movabs, which is unsound for length-based pruning).
fn encoding_prefix_bytes(registers: &[X86Register], machine_width: u32) -> u64 {
    let Some(first) = registers.first() else {
        return 0;
    };
    let operand_width = first.effective_width(machine_width);
    let operand_size_prefix = u64::from(operand_width == 16);
    // In 64-bit mode the assembler encodes register operands through dynasm's
    // dynamic-register path, which always emits a REX byte — REX.W for a native
    // operand, otherwise a bare 0x40 for a dword/word/low-byte operand (with the
    // REX.R/REX.B extension bits added for r8..r15 / spl..dil). The sole
    // exception is a legacy high-byte register (AH/BH/CH/DH), which is
    // REX-incompatible and forces a REX-free legacy encoding. So an x86-64
    // instruction carries a REX byte unless it names a high-byte register.
    let rex = u64::from(machine_width == 64 && !registers.iter().any(|reg| reg.is_high_byte()));
    operand_size_prefix + rex
}

fn instruction_code_size(instr: &X86Instruction, width: u32) -> u64 {
    let operand = instr.destination_operand().or(match instr {
        X86Instruction::CmpReg { rn, .. }
        | X86Instruction::CmpImm { rn, .. }
        | X86Instruction::TestReg { rn, .. }
        | X86Instruction::TestImm { rn, .. } => Some(*rn),
        _ => None,
    });
    let operands: Vec<X86Register> = match instr {
        X86Instruction::MovReg { rd, rs }
        | X86Instruction::AddReg { rd, rs }
        | X86Instruction::SubReg { rd, rs }
        | X86Instruction::AndReg { rd, rs }
        | X86Instruction::OrReg { rd, rs }
        | X86Instruction::XorReg { rd, rs }
        | X86Instruction::ImulReg { rd, rs }
        | X86Instruction::Cmov { rd, rs, .. } => vec![*rd, *rs],
        X86Instruction::CmpReg { rn, rs } | X86Instruction::TestReg { rn, rs } => {
            vec![*rn, *rs]
        }
        X86Instruction::ImulRegImm { rd, rs, .. } => vec![*rd, *rs],
        X86Instruction::Lea { rd, base, .. } => vec![*rd, *base],
        _ => operand.into_iter().collect(),
    };
    let prefixes = encoding_prefix_bytes(&operands, width);
    let operand_width = operand.map_or(width, |reg| reg.effective_width(width));
    match instr {
        X86Instruction::MovReg { .. } => 2 + prefixes,
        // `0F B6/B7 /r` or `0F BE/BF /r`: two-byte opcode plus ModR/M,
        // with REX.W in native-width x86-64 mode.
        X86Instruction::Movzx { .. } | X86Instruction::Movsx { .. } => 3 + prefixes,
        // See the module doc-comment: immediate-dependent to stay a valid
        // upper bound on the assembler's MovImm encoding (issue #225).
        X86Instruction::MovImm { imm, .. } => {
            if operand_width == 64 {
                if i32::try_from(*imm).is_ok() { 7 } else { 10 }
            } else {
                match operand_width {
                    32 => 5 + prefixes,
                    16 => 3 + prefixes,
                    8 => 2 + prefixes,
                    _ => unreachable!("unsupported x86 operand width"),
                }
            }
        }
        X86Instruction::AddReg { .. }
        | X86Instruction::SubReg { .. }
        | X86Instruction::AndReg { .. }
        | X86Instruction::OrReg { .. }
        | X86Instruction::XorReg { .. }
        | X86Instruction::CmpReg { .. }
        | X86Instruction::TestReg { .. }
        // NEG / NOT are single-operand `F7 /3` / `F7 /2` = 2 bytes (+REX.W).
        | X86Instruction::Neg { .. }
        | X86Instruction::Not { .. }
        // INC / DEC are single-operand `FF /0` / `FF /1` = 2 bytes (+REX.W).
        | X86Instruction::Inc { .. }
        | X86Instruction::Dec { .. } => 2 + prefixes,
        // SHL / SHR / SAR / ROL / ROR by imm8 are `C1 /n ib` = opcode + ModR/M
        // + imm8 = 3 bytes (+REX.W).
        X86Instruction::Shl { .. }
        | X86Instruction::Shr { .. }
        | X86Instruction::Sar { .. }
        | X86Instruction::Rol { .. }
        // IMUL rd, rs is `0F AF /r` = opcode (2) + ModR/M = 3 bytes (+REX.W).
        | X86Instruction::ImulReg { .. }
        | X86Instruction::Ror { .. } => 3 + prefixes,
        // IMUL rd, rs, imm is `69 /r id` = opcode + ModR/M + 4-byte imm
        // = 6 bytes (+REX.W), mirroring the reg-imm arithmetic sizing.
        X86Instruction::ImulRegImm { .. } => {
            if operand_width == 16 {
                4 + prefixes
            } else {
                6 + prefixes
            }
        }
        // LEA rd, [base + disp] is `8D /r` = opcode + ModR/M, plus a possible
        // SIB byte (when base is RSP/R12) and a 4-byte disp32 = up to 7 bytes
        // (+REX.W). A conservative upper bound for length-based pruning.
        X86Instruction::Lea { .. } => 7 + prefixes,
        X86Instruction::AddImm { .. }
        | X86Instruction::SubImm { .. }
        | X86Instruction::AndImm { .. }
        | X86Instruction::OrImm { .. }
        | X86Instruction::XorImm { .. }
        | X86Instruction::CmpImm { .. }
        | X86Instruction::TestImm { .. } => match operand_width {
            64 | 32 => 6 + prefixes,
            16 => 4 + prefixes,
            8 => 3 + prefixes,
            _ => unreachable!("unsupported x86 operand width"),
        },
        // CMOV is `0F 4x ModR/M` = 3 bytes plus REX.W on 64-bit.
        X86Instruction::Cmov { .. } => 3 + prefixes,
        // Full-width SETcc lowers to `0F 9x ModR/M` plus
        // `0F B6 ModR/M` (MOVZX), 6 bytes total. In x86-64, SPL..DIL and
        // R8B..R15B (indices 4..15) need a REX prefix on both instructions.
        // x86-32 only admits indices 0..3 for this family.
        X86Instruction::Setcc { rd, .. } => {
            6 + 2 * u64::from(width == 64 && rd.index().is_some_and(|index| index >= 4))
        }
        // Short-form Jcc is `7x rel8` = 2 bytes (no REX). Long-form
        // `0F 8x rel32` = 6 bytes is used when the displacement doesn't
        // fit. The optimizer never emits Jcc bytes (terminators stay
        // pinned in the binary), so this is only the IR accounting
        // baseline; patching splices the original branch bytes back.
        X86Instruction::Jcc { .. } => 2,
    }
}

/// Total cost of a sequence at the given width.
///
/// `InstructionCount` and `CodeSize` are flat per-instruction sums.
/// `Latency` is the sequence's **critical path** (see [`critical_path_latency`]),
/// which is NOT a sum: a serial dependency chain costs more than the same number
/// of independent instructions. The two agree only on the empty and single-
/// instruction cases (a single instruction's critical path equals its latency).
pub fn sequence_cost(seq: &[X86Instruction], metric: &CostMetric, width: u32) -> u64 {
    match metric {
        CostMetric::Latency => critical_path_latency(seq),
        CostMetric::InstructionCount | CostMetric::CodeSize => {
            seq.iter().map(|i| instruction_cost(i, metric, width)).sum()
        }
    }
}

/// EFLAGS is tracked as a synthetic "register" slot beyond the 16 GPRs so that
/// flag def-use edges (e.g. `cmp` → `cmovCC`, `add` → `jcc`) land on the
/// dependency graph alongside register edges.
const FLAGS_SLOT: usize = 16;
const DEP_SLOTS: usize = 17; // 16 GPRs + EFLAGS.

/// Critical-path latency of a sequence, in cycles (issue #622).
///
/// Models an idealized out-of-order core with unbounded execution resources:
/// the only thing that serializes two instructions is a true data dependency
/// (a later instruction reading a register or EFLAGS written by an earlier one).
/// Independent instructions issue in the same cycle, so their latencies overlap
/// rather than add.
///
/// Algorithm (single forward pass, O(n · operands)):
/// - `ready[slot]` holds the completion cycle of the last writer of each
///   register slot (and EFLAGS). All slots start ready at cycle 0.
/// - For instruction `i`: `issue = max(ready[s])` over every source register
///   `s` it reads, plus `ready[FLAGS_SLOT]` when it reads flags. With no tracked
///   inputs `issue = 0`.
/// - `complete = issue + latency(i)`.
/// - Update `ready[d] = complete` for every register `d` it writes, and
///   `ready[FLAGS_SLOT] = complete` when it modifies flags.
/// - The sequence cost is `max(complete)` over all instructions (0 for empty).
///
/// This is a valid lower-bound-friendly cost: the critical path of any non-empty
/// sequence is `>= max_i latency(i) >= min_i latency(i)`, which is what keeps the
/// enumerative pruner's per-instruction lower bound sound (module doc-comment).
pub fn critical_path_latency(seq: &[X86Instruction]) -> u64 {
    let mut ready = [0u64; DEP_SLOTS];
    let mut max_complete = 0u64;

    for instr in seq {
        let mut issue = 0u64;
        for src in instr.source_registers() {
            if let Some(idx) = reg_slot(src) {
                issue = issue.max(ready[idx]);
            }
        }
        if x86_reads_flags(instr) {
            issue = issue.max(ready[FLAGS_SLOT]);
        }

        let complete = issue.saturating_add(instruction_latency(instr));
        max_complete = max_complete.max(complete);

        if let Some(dst) = instr.destination()
            && let Some(idx) = reg_slot(dst)
        {
            ready[idx] = complete;
        }
        if crate::isa::x86::x86_modifies_flags(instr) {
            ready[FLAGS_SLOT] = complete;
        }
    }

    max_complete
}

/// Map a register to its dependency-graph slot (0..=15). Returns `None` only if
/// the register has no architectural index (none do today), defensively keeping
/// the indexer total.
fn reg_slot(reg: X86Register) -> Option<usize> {
    reg.index().map(usize::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::x86::X86Register;

    #[test]
    fn instruction_count_is_always_one() {
        let i = X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        assert_eq!(instruction_cost(&i, &CostMetric::InstructionCount, 64), 1);
        assert_eq!(instruction_cost(&i, &CostMetric::InstructionCount, 32), 1);
    }

    // --- Layer 1: per-opcode latency table (Agner Fog, Skylake) ---

    /// IMUL has strictly higher isolated latency than ADD on Skylake (3 vs 1),
    /// per Agner Fog's instruction tables (module doc-comment). This pins the
    /// documented per-opcode reference value the search relies on.
    #[test]
    fn imul_latency_exceeds_add_latency() {
        let add = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let imul = X86Instruction::ImulReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let imul3 = X86Instruction::ImulRegImm {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            imm: 7,
        };
        assert_eq!(instruction_latency(&add), 1);
        assert_eq!(instruction_latency(&imul), 3);
        assert_eq!(instruction_latency(&imul3), 3);
        assert!(instruction_latency(&imul) > instruction_latency(&add));
        // Register-to-register MOV is move-eliminated (0 cycles); MovImm is a
        // real 1-cycle op.
        let mov_reg = X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let mov_imm = X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 7,
        };
        assert_eq!(instruction_latency(&mov_reg), 0);
        assert_eq!(instruction_latency(&mov_imm), 1);
    }

    // --- Layer 2: critical-path sequence latency rewards parallelism ---

    /// A serial dependency chain (each op reads the result of the previous one)
    /// must cost MORE than the same number of fully independent ops, even though
    /// they have identical length and identical per-instruction latencies. This
    /// is the whole point of the critical-path model: with the old flat-sum stub
    /// both sequences cost 3 and this test failed.
    #[test]
    fn sequence_latency_rewards_parallelism() {
        // Serial: rax = rax+rbx; rax = rax+rcx; rax = rax+rdx.
        // Each instruction reads rax written by the previous one -> chain of 3.
        let serial = [
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RCX,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RDX,
            },
        ];
        // Independent: three distinct destinations, no def-use edge between them.
        let independent = [
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RSI,
            },
            X86Instruction::AddReg {
                rd: X86Register::RBX,
                rs: X86Register::RSI,
            },
            X86Instruction::AddReg {
                rd: X86Register::RCX,
                rs: X86Register::RSI,
            },
        ];

        let serial_cost = sequence_cost(&serial, &CostMetric::Latency, 64);
        let independent_cost = sequence_cost(&independent, &CostMetric::Latency, 64);

        // Serial chain: 1 + 1 + 1 = 3 cycles on the critical path.
        assert_eq!(serial_cost, 3);
        // Independent ops all issue at cycle 0, complete at cycle 1.
        assert_eq!(independent_cost, 1);
        assert!(
            serial_cost > independent_cost,
            "critical-path latency must penalize the serial dependency chain: \
             serial={serial_cost} independent={independent_cost}"
        );
    }

    /// Flag def-use edges serialize too: `cmp` writes EFLAGS, `cmovCC` reads
    /// them, so the pair forms a 2-cycle chain even though they touch different
    /// registers.
    #[test]
    fn critical_path_tracks_flag_dependencies() {
        use crate::isa::x86::X86Condition;
        let seq = [
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Cmov {
                rd: X86Register::RCX,
                rs: X86Register::RDX,
                cond: X86Condition::E,
            },
        ];
        assert_eq!(sequence_cost(&seq, &CostMetric::Latency, 64), 2);
    }

    /// SETcc's two-instruction lowering contributes its internal dependency:
    /// CMP (1) -> SETcc+MOVZX (2) -> consumer (1) is a 4-cycle chain.
    #[test]
    fn critical_path_accounts_for_setcc_macro_lowering() {
        use crate::isa::x86::X86Condition;
        let seq = [
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Setcc {
                rd: X86Register::RCX,
                cond: X86Condition::NE,
            },
            X86Instruction::AddReg {
                rd: X86Register::RDX,
                rs: X86Register::RCX,
            },
        ];
        assert_eq!(sequence_cost(&seq, &CostMetric::Latency, 64), 4);
    }

    /// A register-to-register MOV is eliminated at rename, so it adds 0 to the
    /// critical path: `mov rax, rbx; add rax, rcx` costs the same as the lone
    /// `add` (1 cycle), not 2.
    #[test]
    fn move_elimination_does_not_extend_critical_path() {
        let seq = [
            X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RCX,
            },
        ];
        assert_eq!(sequence_cost(&seq, &CostMetric::Latency, 64), 1);
    }

    #[test]
    fn partial_write_keeps_old_destination_on_the_critical_path() {
        let producer = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RCX,
        };
        let consumer = X86Instruction::AddReg {
            rd: X86Register::RDX,
            rs: X86Register::RAX,
        };
        let partial = [
            producer,
            X86Instruction::MovImm {
                rd: X86Register::AL,
                imm: 1,
            },
            consumer,
        ];
        let dword = [
            producer,
            X86Instruction::MovImm {
                rd: X86Register::EAX,
                imm: 1,
            },
            consumer,
        ];

        assert_eq!(sequence_cost(&partial, &CostMetric::Latency, 64), 3);
        assert_eq!(
            sequence_cost(&dword, &CostMetric::Latency, 64),
            2,
            "an EAX write replaces the old RAX value and breaks its dependency"
        );
    }

    /// IMUL's 3-cycle latency shows up on the critical path: a single IMUL costs
    /// 3, and chaining it after an ADD that produces its input costs 1 + 3 = 4.
    #[test]
    fn imul_latency_lengthens_critical_path() {
        let single = [X86Instruction::ImulReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        assert_eq!(sequence_cost(&single, &CostMetric::Latency, 64), 3);

        let chain = [
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            // Reads rax produced by the ADD above -> 1 (add) + 3 (imul) = 4.
            X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RCX,
            },
        ];
        assert_eq!(sequence_cost(&chain, &CostMetric::Latency, 64), 4);
    }

    #[test]
    fn code_size_x86_64_includes_rex_prefix() {
        let rr = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let ri = X86Instruction::AddImm {
            rd: X86Register::RAX,
            imm: 5,
        };
        assert_eq!(instruction_cost(&rr, &CostMetric::CodeSize, 64), 3);
        assert_eq!(instruction_cost(&ri, &CostMetric::CodeSize, 64), 7);
    }

    #[test]
    fn code_size_x86_32_drops_rex_prefix() {
        let rr = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let ri = X86Instruction::AddImm {
            rd: X86Register::RAX,
            imm: 5,
        };
        assert_eq!(instruction_cost(&rr, &CostMetric::CodeSize, 32), 2);
        assert_eq!(instruction_cost(&ri, &CostMetric::CodeSize, 32), 6);
    }

    #[test]
    fn code_size_tracks_sub_register_prefixes_and_immediates() {
        let cases = [
            (
                X86Instruction::MovImm {
                    rd: X86Register::EAX,
                    imm: 1,
                },
                6,
            ),
            (
                X86Instruction::MovImm {
                    rd: X86Register::AX,
                    imm: 1,
                },
                5,
            ),
            (
                X86Instruction::MovImm {
                    rd: X86Register::AL,
                    imm: 1,
                },
                3,
            ),
            (
                X86Instruction::MovImm {
                    rd: X86Register::AH,
                    imm: 1,
                },
                2,
            ),
            (
                X86Instruction::XorReg {
                    rd: X86Register::EAX,
                    rs: X86Register::EAX,
                },
                3,
            ),
            (
                X86Instruction::XorReg {
                    rd: X86Register::AX,
                    rs: X86Register::AX,
                },
                4,
            ),
        ];

        for (instruction, expected) in cases {
            assert_eq!(
                instruction_cost(&instruction, &CostMetric::CodeSize, 64),
                expected,
                "{instruction}"
            );
        }
    }

    #[test]
    fn test_code_size_and_latency_mirror_cmp() {
        let reg = X86Instruction::TestReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let imm = X86Instruction::TestImm {
            rn: X86Register::RAX,
            imm: 5,
        };
        // Same sizes as CMP: reg-reg 2(+rex), reg-imm 6(+rex); latency 1.
        assert_eq!(instruction_cost(&reg, &CostMetric::CodeSize, 64), 3);
        assert_eq!(instruction_cost(&reg, &CostMetric::CodeSize, 32), 2);
        assert_eq!(instruction_cost(&imm, &CostMetric::CodeSize, 64), 7);
        assert_eq!(instruction_cost(&imm, &CostMetric::CodeSize, 32), 6);
        assert_eq!(instruction_cost(&reg, &CostMetric::Latency, 64), 1);
        assert_eq!(instruction_cost(&imm, &CostMetric::Latency, 64), 1);
    }

    #[test]
    fn sequence_cost_sums_individual_costs() {
        let seq = [
            X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RCX,
            },
        ];
        // 3 + 3 = 6 bytes on x86-64.
        assert_eq!(sequence_cost(&seq, &CostMetric::CodeSize, 64), 6);
        // 2 + 2 = 4 bytes on x86-32.
        assert_eq!(sequence_cost(&seq, &CostMetric::CodeSize, 32), 4);
    }

    #[test]
    fn mov_imm_code_size_is_immediate_dependent() {
        let zero = X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        };
        let small = X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: i32::MAX as i64,
        };
        let big = X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: i64::MAX,
        };
        // x86-64: imm fitting i32 -> 7-byte `REX.W C7 /0 id`; full 64-bit imm
        // -> 10-byte `REX.W B8+rd io` movabs. (The old flat `5 + rex` = 6
        // underestimated both, breaking length-pruning soundness.)
        assert_eq!(instruction_cost(&zero, &CostMetric::CodeSize, 64), 7);
        assert_eq!(instruction_cost(&small, &CostMetric::CodeSize, 64), 7);
        assert_eq!(instruction_cost(&big, &CostMetric::CodeSize, 64), 10);
        // x86-32: `B8+rd id` is 5 bytes (no REX; the assembler rejects
        // immediates that do not fit imm32 rather than emitting movabs).
        assert_eq!(instruction_cost(&zero, &CostMetric::CodeSize, 32), 5);
        assert_eq!(instruction_cost(&small, &CostMetric::CodeSize, 32), 5);
    }

    // --- SETcc / CMOV / Jcc cost ---

    #[test]
    fn setcc_cost_accounts_for_two_instruction_lowering() {
        use crate::isa::x86::X86Condition;

        let setne_rax = X86Instruction::Setcc {
            rd: X86Register::RAX,
            cond: X86Condition::NE,
        };
        let setne_rsp = X86Instruction::Setcc {
            rd: X86Register::RSP,
            cond: X86Condition::NE,
        };
        let setne_r8 = X86Instruction::Setcc {
            rd: X86Register::R8,
            cond: X86Condition::NE,
        };
        assert_eq!(instruction_cost(&setne_rax, &CostMetric::CodeSize, 64), 6);
        assert_eq!(instruction_cost(&setne_rsp, &CostMetric::CodeSize, 64), 8);
        assert_eq!(instruction_cost(&setne_r8, &CostMetric::CodeSize, 64), 8);
        assert_eq!(instruction_cost(&setne_rax, &CostMetric::CodeSize, 32), 6);
        assert_eq!(
            instruction_cost(&setne_rax, &CostMetric::InstructionCount, 64),
            2
        );
        assert_eq!(instruction_cost(&setne_rax, &CostMetric::Latency, 64), 2);
    }

    #[test]
    fn cmov_code_size_includes_rex_on_64_bit() {
        use crate::isa::x86::X86Condition;
        let cmov = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::E,
        };
        // CMOV is `0F 4x ModR/M` = 3 bytes, +1 for REX.W on x86-64.
        assert_eq!(instruction_cost(&cmov, &CostMetric::CodeSize, 64), 4);
        assert_eq!(instruction_cost(&cmov, &CostMetric::CodeSize, 32), 3);
    }

    #[test]
    fn extension_moves_have_two_byte_opcode_plus_modrm_and_optional_rex() {
        for instruction in [
            X86Instruction::Movzx {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                src_width: 8,
            },
            X86Instruction::Movsx {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                src_width: 16,
            },
        ] {
            assert_eq!(instruction_cost(&instruction, &CostMetric::CodeSize, 64), 4);
            assert_eq!(instruction_cost(&instruction, &CostMetric::CodeSize, 32), 3);
            assert_eq!(instruction_cost(&instruction, &CostMetric::Latency, 64), 1);
        }
    }

    #[test]
    fn rotate_code_size_and_latency_mirror_shifts() {
        // ROL / ROR by imm8 are `C1 /n ib` = 3 bytes (+REX.W on x86-64 -> 4),
        // identical to the shifts; latency 1.
        for instr in [
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 3,
            },
            X86Instruction::Ror {
                rd: X86Register::RBX,
                imm: 5,
            },
        ] {
            // Mirror the shift cost exactly.
            let shift = X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 3,
            };
            assert_eq!(
                instruction_cost(&instr, &CostMetric::CodeSize, 64),
                instruction_cost(&shift, &CostMetric::CodeSize, 64),
            );
            assert_eq!(instruction_cost(&instr, &CostMetric::CodeSize, 64), 4);
            assert_eq!(instruction_cost(&instr, &CostMetric::CodeSize, 32), 3);
            assert_eq!(instruction_cost(&instr, &CostMetric::Latency, 64), 1);
        }
    }

    #[test]
    fn jcc_short_form_costs_two_bytes() {
        use crate::isa::x86::X86Condition;
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::NE,
        };
        // 0x7x + rel8 = 2 bytes regardless of mode.
        assert_eq!(instruction_cost(&jcc, &CostMetric::CodeSize, 64), 2);
        assert_eq!(instruction_cost(&jcc, &CostMetric::CodeSize, 32), 2);
    }
}
