//! AArch64 ISA implementation
//!
//! This module provides the AArch64-specific implementation of the ISA traits.

#![allow(dead_code)]

use crate::ir::instructions::{AARCH64_RANDOM_SHIFT_IMMEDIATES, MOVW_LEGAL_SHIFTS};
use crate::ir::types::Condition;
use crate::ir::{Instruction, Operand, Register, RegisterWidth};
use crate::isa::traits::{ISA, InstructionGenerator, InstructionType, OperandType, RegisterType};

use rand::RngExt;

/// AArch64 ISA marker type
#[derive(Clone, Debug)]
pub struct AArch64;

impl ISA for AArch64 {
    type Register = Register;
    type Operand = Operand;
    type Instruction = Instruction;
    type Width = crate::isa::traits::U64;
    type Flags = crate::semantics::state::ConditionFlags;
    type Mutator = crate::search::stochastic::mutation::AArch64Mutator;

    fn name(&self) -> &'static str {
        "AArch64"
    }

    fn register_count(&self) -> usize {
        31 // X0-X30, plus XZR
    }

    fn instruction_size(&self) -> Option<usize> {
        Some(4) // All AArch64 instructions are 4 bytes
    }

    fn general_registers(&self) -> Vec<Self::Register> {
        (0..31).filter_map(Register::from_index).collect()
    }

    fn zero_register(&self) -> Option<Self::Register> {
        Some(Register::XZR)
    }
}

impl crate::isa::traits::FlagsAnalysis<Instruction> for AArch64 {
    fn modifies_flags(instr: &Instruction) -> bool {
        instr.modifies_flags()
    }

    fn reads_flags(instr: &Instruction) -> bool {
        instr.reads_flags()
    }
}

impl crate::isa::traits::ConcreteExecutor<Instruction> for AArch64 {
    type Value = u64;
    type State = crate::semantics::state::ConcreteMachineState;

    fn execute_instruction(&self, state: Self::State, instruction: &Instruction) -> Self::State {
        crate::semantics::concrete::apply_instruction_concrete(state, instruction)
    }

    fn new_zeroed_state(&self) -> Self::State {
        crate::semantics::state::ConcreteMachineState::new_zeroed()
    }

    fn state_from_values(&self, values: std::collections::HashMap<Register, u64>) -> Self::State {
        crate::semantics::state::ConcreteMachineState::from_values(values)
    }

    fn get_register(&self, state: &Self::State, reg: Register) -> u64 {
        state.get_register(reg).as_u64()
    }

    fn set_register(&self, state: &mut Self::State, reg: Register, value: u64) {
        state.set_register(reg, crate::semantics::state::ConcreteValue::new(value));
    }
}

impl crate::isa::traits::SymbolicExecutor<Instruction> for AArch64 {
    type State = crate::semantics::smt::MachineState;

    fn execute_instruction(&self, state: Self::State, instruction: &Instruction) -> Self::State {
        crate::semantics::smt::apply_instruction(state, instruction)
    }

    fn new_symbolic_state(&self, prefix: &str) -> Self::State {
        crate::semantics::smt::MachineState::new_symbolic(prefix)
    }
}

impl crate::isa::traits::CostModel<Instruction> for AArch64 {
    fn instruction_cost(
        &self,
        instruction: &Instruction,
        metric: &crate::semantics::cost::CostMetric,
    ) -> u64 {
        crate::semantics::cost::instruction_cost(instruction, metric)
    }
}

impl crate::isa::traits::Assembler<Instruction> for AArch64 {
    fn assemble(&mut self, instructions: &[Instruction]) -> Result<Vec<u8>, String> {
        // base_address=0 is correct for unbranching sequences (no PC-relative
        // encoding involved). Trait callers that need real branch targets
        // should reach for `AArch64Assembler` directly with their base_address.
        crate::assembler::AArch64Assembler::new().assemble_instructions(instructions, 0)
    }

    /// Bridges the inherent `Instruction::is_encodable_aarch64()` so step 11
    /// can swap `is_sequence_encodable` for trait dispatch without losing
    /// behaviour.
    fn can_assemble(&self, instruction: &Instruction) -> bool {
        instruction.is_encodable_aarch64()
    }
}

impl RegisterType for Register {
    fn index(&self) -> Option<u8> {
        Register::index(self)
    }

    fn from_index(idx: u8) -> Option<Self> {
        Register::from_index(idx)
    }

    fn is_zero_register(&self) -> bool {
        matches!(self, Register::XZR)
    }

    fn is_special(&self) -> bool {
        matches!(self, Register::SP | Register::XZR)
    }
}

impl OperandType for Operand {
    type Register = Register;

    fn as_register(&self) -> Option<Register> {
        match self {
            Operand::Register(r) => Some(*r),
            Operand::Immediate(_) => None,
            // ShiftedRegister/ExtendedRegister carry a register but are not
            // plain register operands; callers asking "is this a register?"
            // should treat them as distinct shapes.
            Operand::ShiftedRegister { .. } => None,
            Operand::ExtendedRegister { .. } => None,
        }
    }

    fn as_immediate(&self) -> Option<i64> {
        match self {
            Operand::Register(_) => None,
            Operand::Immediate(i) => Some(*i),
            Operand::ShiftedRegister { .. } => None,
            Operand::ExtendedRegister { .. } => None,
        }
    }

    fn from_register(reg: Register) -> Self {
        Operand::Register(reg)
    }

    fn from_immediate(imm: i64) -> Self {
        Operand::Immediate(imm)
    }
}

impl InstructionType for Instruction {
    type Register = Register;
    type Operand = Operand;

    fn destination(&self) -> Option<Register> {
        Instruction::destination(self)
    }

    fn source_registers(&self) -> Vec<Register> {
        Instruction::source_registers(self)
    }

    // Canonical AArch64 opcode-id table. Candidate generation calls this through
    // `InstructionType::opcode_id`; drift is guarded by this module's
    // `all_instruction_families_cover_trait_methods` test and
    // `test_generate_all_instructions_covers_opcode_count` in
    // `src/search/candidate.rs`.
    fn opcode_id(&self) -> u8 {
        match self {
            Instruction::MovReg { .. } | Instruction::MovRegW { .. } => 0,
            Instruction::MovImm { .. } => 1,
            Instruction::Add { .. } | Instruction::AddW { .. } => 2,
            Instruction::Sub { .. } | Instruction::SubW { .. } => 3,
            Instruction::And { .. } => 4,
            Instruction::Orr { .. } => 5,
            Instruction::Eor { .. } => 6,
            Instruction::Lsl { .. } => 7,
            Instruction::Lsr { .. } => 8,
            Instruction::Asr { .. } => 9,
            Instruction::Mul { .. } => 10,
            Instruction::Sdiv { .. } => 11,
            Instruction::Udiv { .. } => 12,
            Instruction::Cmp { .. } => 13,
            Instruction::Cmn { .. } => 14,
            Instruction::Tst { .. } => 15,
            Instruction::Csel { .. } => 16,
            Instruction::Csinc { .. } => 17,
            Instruction::Csinv { .. } => 18,
            Instruction::Csneg { .. } => 19,
            Instruction::Mvn { .. } => 20,
            Instruction::Neg { .. } => 21,
            Instruction::Negs { .. } => 22,
            Instruction::MovN { .. } => 23,
            Instruction::Bic { .. } => 24,
            Instruction::Bics { .. } => 25,
            Instruction::Orn { .. } => 26,
            Instruction::Eon { .. } => 27,
            Instruction::Adds { .. } => 28,
            Instruction::Subs { .. } => 29,
            Instruction::Ands { .. } => 30,
            Instruction::Cset { .. } => 31,
            Instruction::Csetm { .. } => 32,
            Instruction::Ror { .. } => 33,
            Instruction::MovZ { .. } => 34,
            Instruction::MovK { .. } => 35,
            Instruction::Clz { .. } => 36,
            Instruction::Cls { .. } => 37,
            Instruction::Rbit { .. } => 38,
            Instruction::Rev { .. } => 39,
            Instruction::Rev32 { .. } => 40,
            Instruction::Rev16 { .. } => 41,
            Instruction::Madd { .. } => 42,
            Instruction::Msub { .. } => 43,
            Instruction::Mneg { .. } => 44,
            Instruction::Smulh { .. } => 45,
            Instruction::Umulh { .. } => 46,
            Instruction::Ccmp { .. } => 47,
            Instruction::Ccmn { .. } => 48,
            Instruction::Sxtb { .. } => 49,
            Instruction::Sxth { .. } => 50,
            Instruction::Sxtw { .. } => 51,
            Instruction::Uxtb { .. } => 52,
            Instruction::Uxth { .. } => 53,
            Instruction::Ubfx { .. } => 54,
            Instruction::Sbfx { .. } => 55,
            Instruction::Bfi { .. } => 56,
            Instruction::Bfxil { .. } => 57,
            Instruction::Ubfiz { .. } => 58,
            Instruction::Sbfiz { .. } => 59,
            // Branches / terminators (issue #69). Branches are not in the
            // random-generation pool, so these IDs fall above `opcode_count`;
            // the `id < opcode_count` invariant only applies to enumerated
            // families.
            Instruction::B { .. } => 60,
            Instruction::BCond { .. } => 61,
            Instruction::Ret { .. } => 62,
            Instruction::Cbz { .. } => 63,
            Instruction::Cbnz { .. } => 64,
            Instruction::Tbz { .. } => 65,
            Instruction::Tbnz { .. } => 66,
            Instruction::Bl { .. } => 67,
            Instruction::Br { .. } => 68,

            // Memory ops (issue #68). LDR/LDRB/LDRH share id 69 — the
            // mnemonic table differentiates by `AccessWidth`; this id
            // bucket is used only for coarse equality checks.
            Instruction::Ldr { .. } => 69,
            // Sign-extending loads (LDRSB / LDRSH / LDRSW).
            Instruction::Ldrs { .. } => 70,
            // Stores (STR / STRB / STRH).
            Instruction::Str { .. } => 71,
            // Pair loads (LDP, LDPSW).
            Instruction::Ldp { .. } => 72,
            // Pair store (STP).
            Instruction::Stp { .. } => 73,
            // Add/subtract with carry (issue #205). Not in the random-
            // generation pool, so these ids fall above `opcode_count`
            // (same as branches/memory).
            Instruction::Adc { .. } => 74,
            Instruction::Adcs { .. } => 75,
            Instruction::Sbc { .. } => 76,
            Instruction::Sbcs { .. } => 77,
        }
    }

    fn mnemonic(&self) -> &'static str {
        match self {
            Instruction::MovReg { .. }
            | Instruction::MovRegW { .. }
            | Instruction::MovImm { .. } => "mov",
            Instruction::Add { .. } | Instruction::AddW { .. } => "add",
            Instruction::Sub { .. } | Instruction::SubW { .. } => "sub",
            Instruction::And { .. } => "and",
            Instruction::Orr { .. } => "orr",
            Instruction::Eor { .. } => "eor",
            Instruction::Lsl { .. } => "lsl",
            Instruction::Lsr { .. } => "lsr",
            Instruction::Asr { .. } => "asr",
            Instruction::Mul { .. } => "mul",
            Instruction::Sdiv { .. } => "sdiv",
            Instruction::Udiv { .. } => "udiv",
            Instruction::Cmp { .. } => "cmp",
            Instruction::Cmn { .. } => "cmn",
            Instruction::Tst { .. } => "tst",
            Instruction::Csel { .. } => "csel",
            Instruction::Csinc { .. } => "csinc",
            Instruction::Csinv { .. } => "csinv",
            Instruction::Csneg { .. } => "csneg",
            Instruction::Mvn { .. } => "mvn",
            Instruction::Neg { .. } => "neg",
            Instruction::Negs { .. } => "negs",
            Instruction::MovN { .. } => "movn",
            Instruction::Bic { .. } => "bic",
            Instruction::Bics { .. } => "bics",
            Instruction::Orn { .. } => "orn",
            Instruction::Eon { .. } => "eon",
            Instruction::Adds { .. } => "adds",
            Instruction::Subs { .. } => "subs",
            Instruction::Adc { .. } => "adc",
            Instruction::Adcs { .. } => "adcs",
            Instruction::Sbc { .. } => "sbc",
            Instruction::Sbcs { .. } => "sbcs",
            Instruction::Ands { .. } => "ands",
            Instruction::Cset { .. } => "cset",
            Instruction::Csetm { .. } => "csetm",
            Instruction::Ror { .. } => "ror",
            Instruction::MovZ { .. } => "movz",
            Instruction::MovK { .. } => "movk",
            Instruction::Clz { .. } => "clz",
            Instruction::Cls { .. } => "cls",
            Instruction::Rbit { .. } => "rbit",
            Instruction::Rev { .. } => "rev",
            Instruction::Rev32 { .. } => "rev32",
            Instruction::Rev16 { .. } => "rev16",
            Instruction::Madd { .. } => "madd",
            Instruction::Msub { .. } => "msub",
            Instruction::Mneg { .. } => "mneg",
            Instruction::Smulh { .. } => "smulh",
            Instruction::Umulh { .. } => "umulh",
            Instruction::Ccmp { .. } => "ccmp",
            Instruction::Ccmn { .. } => "ccmn",
            Instruction::Sxtb { .. } => "sxtb",
            Instruction::Sxth { .. } => "sxth",
            Instruction::Sxtw { .. } => "sxtw",
            Instruction::Uxtb { .. } => "uxtb",
            Instruction::Uxth { .. } => "uxth",
            Instruction::Ubfx { .. } => "ubfx",
            Instruction::Sbfx { .. } => "sbfx",
            Instruction::Bfi { .. } => "bfi",
            Instruction::Bfxil { .. } => "bfxil",
            Instruction::Ubfiz { .. } => "ubfiz",
            Instruction::Sbfiz { .. } => "sbfiz",
            // Branches / terminators (issue #69)
            Instruction::B { .. } => "b",
            Instruction::BCond { .. } => "b.cond",
            Instruction::Ret { .. } => "ret",
            Instruction::Cbz { .. } => "cbz",
            Instruction::Cbnz { .. } => "cbnz",
            Instruction::Tbz { .. } => "tbz",
            Instruction::Tbnz { .. } => "tbnz",
            Instruction::Bl { .. } => "bl",
            Instruction::Br { .. } => "br",

            // Memory ops (issue #68). LDR / LDRB / LDRH differ only by
            // access width.
            Instruction::Ldr { width, .. } => match width {
                crate::ir::types::AccessWidth::Byte => "ldrb",
                crate::ir::types::AccessWidth::Half => "ldrh",
                crate::ir::types::AccessWidth::Word | crate::ir::types::AccessWidth::Extended => {
                    "ldr"
                }
            },
            // Sign-extending loads. `Extended` width is rejected by
            // `is_encodable_aarch64`; fall through to "ldrsw" if it ever
            // reaches here.
            Instruction::Ldrs { width, .. } => match width {
                crate::ir::types::AccessWidth::Byte => "ldrsb",
                crate::ir::types::AccessWidth::Half => "ldrsh",
                crate::ir::types::AccessWidth::Word | crate::ir::types::AccessWidth::Extended => {
                    "ldrsw"
                }
            },
            // Stores. STR / STRB / STRH; the X/W distinction is hidden in
            // the AccessWidth (Extended vs Word).
            Instruction::Str { width, .. } => match width {
                crate::ir::types::AccessWidth::Byte => "strb",
                crate::ir::types::AccessWidth::Half => "strh",
                crate::ir::types::AccessWidth::Word | crate::ir::types::AccessWidth::Extended => {
                    "str"
                }
            },
            // LDP / LDPSW.
            Instruction::Ldp { signed: true, .. } => "ldpsw",
            Instruction::Ldp { signed: false, .. } => "ldp",
            // STP.
            Instruction::Stp { .. } => "stp",
        }
    }

    fn has_side_effects(&self) -> bool {
        // Memory ops have observable side effects beyond NZCV: stores write
        // memory, writeback modes mutate the base register, loads read from
        // potentially-aliased memory. See ADR-0007.
        self.modifies_flags()
            || matches!(
                self,
                Instruction::Ldr { .. }
                    | Instruction::Ldrs { .. }
                    | Instruction::Str { .. }
                    | Instruction::Ldp { .. }
                    | Instruction::Stp { .. }
            )
    }
}

/// AArch64 instruction generator
#[derive(Clone, Debug, Default)]
pub struct AArch64InstructionGenerator;

impl InstructionGenerator<Instruction> for AArch64InstructionGenerator {
    fn generate_all(&self, registers: &[Register], immediates: &[i64]) -> Vec<Instruction> {
        let mut instructions = Vec::new();

        // MovReg: rd <- rn
        for &rd in registers {
            for &rn in registers {
                instructions.push(Instruction::MovReg { rd, rn });
                instructions.push(Instruction::MovRegW { rd, rn });
            }
        }

        // MovImm: rd <- imm
        for &rd in registers {
            for &imm in immediates {
                instructions.push(Instruction::MovImm { rd, imm });
            }
        }

        // Binary register-register operations: Add, Sub, And, Orr, Eor
        for &rd in registers {
            for &rn in registers {
                for &rm in registers {
                    let rm_op = Operand::Register(rm);
                    instructions.push(Instruction::Add { rd, rn, rm: rm_op });
                    instructions.push(Instruction::AddW { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Sub { rd, rn, rm: rm_op });
                    instructions.push(Instruction::SubW { rd, rn, rm: rm_op });
                    instructions.push(Instruction::And {
                        rd,
                        rn,
                        rm: rm_op,
                        width: RegisterWidth::X64,
                    });
                    instructions.push(Instruction::Orr {
                        rd,
                        rn,
                        rm: rm_op,
                        width: RegisterWidth::X64,
                    });
                    instructions.push(Instruction::Eor {
                        rd,
                        rn,
                        rm: rm_op,
                        width: RegisterWidth::X64,
                    });
                }
            }
        }

        // Binary register-immediate operations: Add, Sub
        for &rd in registers {
            for &rn in registers {
                for &imm in immediates {
                    let imm_op = Operand::Immediate(imm);
                    instructions.push(Instruction::Add { rd, rn, rm: imm_op });
                    instructions.push(Instruction::AddW { rd, rn, rm: imm_op });
                    instructions.push(Instruction::Sub { rd, rn, rm: imm_op });
                    instructions.push(Instruction::SubW { rd, rn, rm: imm_op });
                }
            }
        }

        // Shift operations
        let shift_amounts: Vec<i64> = vec![0, 1, 2, 4, 8, 16, 32];
        for &rd in registers {
            for &rn in registers {
                // Register shifts
                for &rm in registers {
                    let rm_op = Operand::Register(rm);
                    instructions.push(Instruction::Lsl {
                        rd,
                        rn,
                        shift: rm_op,
                    });
                    instructions.push(Instruction::Lsr {
                        rd,
                        rn,
                        shift: rm_op,
                    });
                    instructions.push(Instruction::Asr {
                        rd,
                        rn,
                        shift: rm_op,
                    });
                }
                // Immediate shifts
                for &shift in &shift_amounts {
                    let shift_op = Operand::Immediate(shift);
                    instructions.push(Instruction::Lsl {
                        rd,
                        rn,
                        shift: shift_op,
                    });
                    instructions.push(Instruction::Lsr {
                        rd,
                        rn,
                        shift: shift_op,
                    });
                    instructions.push(Instruction::Asr {
                        rd,
                        rn,
                        shift: shift_op,
                    });
                }
            }
        }

        // Multiplication and division (register-register only)
        for &rd in registers {
            for &rn in registers {
                for &rm in registers {
                    instructions.push(Instruction::Mul { rd, rn, rm });
                    instructions.push(Instruction::Sdiv { rd, rn, rm });
                    instructions.push(Instruction::Udiv { rd, rn, rm });
                }
            }
        }

        // Multiply-accumulate family. MADD/MSUB add a 4th register slot,
        // so candidate count grows by |registers|^4 per variant
        // (e.g. 8^4 = 4096 per arm). MNEG/SMULH/UMULH are 3-operand like MUL.
        for &rd in registers {
            for &rn in registers {
                for &rm in registers {
                    instructions.push(Instruction::Mneg { rd, rn, rm });
                    instructions.push(Instruction::Smulh { rd, rn, rm });
                    instructions.push(Instruction::Umulh { rd, rn, rm });
                    for &ra in registers {
                        instructions.push(Instruction::Madd { rd, rn, rm, ra });
                        instructions.push(Instruction::Msub { rd, rn, rm, ra });
                    }
                }
            }
        }

        // Conditional-compare family (CCMP/CCMN). Sample a small product of
        // nzcv × cond × imm5 so the enumeration footprint stays bounded
        // (mirrors candidate.rs::generate_all_instructions); is_encodable_aarch64
        // filters SP at the encoder boundary, so we emit unconstrained `rn`
        // and `rm`-register entries here.
        const CCMP_NZCV_SAMPLES: [u8; 5] = [0, 1, 7, 8, 15];
        const CCMP_IMM5_SAMPLES: [i64; 4] = [0, 1, 16, 31];
        for &rn in registers {
            for &rm_reg in registers {
                for cond in crate::ir::types::NORMAL_CONDITIONS {
                    for &nzcv in &CCMP_NZCV_SAMPLES {
                        instructions.push(Instruction::Ccmp {
                            rn,
                            rm: Operand::Register(rm_reg),
                            nzcv,
                            cond,
                        });
                        instructions.push(Instruction::Ccmn {
                            rn,
                            rm: Operand::Register(rm_reg),
                            nzcv,
                            cond,
                        });
                    }
                }
            }
            for &imm in &CCMP_IMM5_SAMPLES {
                for cond in crate::ir::types::NORMAL_CONDITIONS {
                    for &nzcv in &CCMP_NZCV_SAMPLES {
                        instructions.push(Instruction::Ccmp {
                            rn,
                            rm: Operand::Immediate(imm),
                            nzcv,
                            cond,
                        });
                        instructions.push(Instruction::Ccmn {
                            rn,
                            rm: Operand::Immediate(imm),
                            nzcv,
                            cond,
                        });
                    }
                }
            }
        }

        // Tier 1 inverted-logical / flag-setting binary ops (register form).
        for &rd in registers {
            for &rn in registers {
                for &rm in registers {
                    let rm_op = Operand::Register(rm);
                    instructions.push(Instruction::Bic { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Bics { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Orn { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Eon { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Adds { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Subs { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Ands {
                        rd,
                        rn,
                        rm: rm_op,
                        width: RegisterWidth::X64,
                    });
                }
                // ADDS / SUBS immediate forms (ANDS is register-only).
                for &imm in immediates {
                    let imm_op = Operand::Immediate(imm);
                    instructions.push(Instruction::Adds { rd, rn, rm: imm_op });
                    instructions.push(Instruction::Subs { rd, rn, rm: imm_op });
                }
                // ROR with register and immediate shift.
                for &rm in registers {
                    instructions.push(Instruction::Ror {
                        rd,
                        rn,
                        shift: Operand::Register(rm),
                    });
                }
                for &shift in &shift_amounts {
                    instructions.push(Instruction::Ror {
                        rd,
                        rn,
                        shift: Operand::Immediate(shift),
                    });
                }
            }

            // Tier 1 unary: MVN / NEG / NEGS.
            for &rm in registers {
                instructions.push(Instruction::Mvn { rd, rm });
                instructions.push(Instruction::Neg { rd, rm });
                instructions.push(Instruction::Negs { rd, rm });
            }

            // Single-source bit-manipulation and standalone extends.
            for &rn in registers {
                instructions.push(Instruction::Clz { rd, rn });
                instructions.push(Instruction::Cls { rd, rn });
                instructions.push(Instruction::Rbit { rd, rn });
                instructions.push(Instruction::Rev { rd, rn });
                instructions.push(Instruction::Rev32 { rd, rn });
                instructions.push(Instruction::Rev16 { rd, rn });
                instructions.push(Instruction::Sxtb { rd, rn });
                instructions.push(Instruction::Sxth { rd, rn });
                instructions.push(Instruction::Sxtw { rd, rn });
                instructions.push(Instruction::Uxtb { rd, rn });
                instructions.push(Instruction::Uxth { rd, rn });
            }

            // MOVN / MOVZ / MOVK: small representative imm × {0,16,32,48}
            // shift table. The same parsimony rationale as MOVN applies for
            // MOVZ/MOVK — the full u16 × 4-shift space would balloon
            // candidate counts.
            for imm in [0u16, 1, 0xFF, 0xFFFF] {
                for shift in MOVW_LEGAL_SHIFTS {
                    instructions.push(Instruction::MovN { rd, imm, shift });
                    instructions.push(Instruction::MovZ { rd, imm, shift });
                    instructions.push(Instruction::MovK { rd, imm, shift });
                }
            }

            // CSET / CSETM: 14 non-AL/NV conditions from ir::types.
            for cond in crate::ir::types::NORMAL_CONDITIONS {
                instructions.push(Instruction::Cset { rd, cond });
                instructions.push(Instruction::Csetm { rd, cond });
            }
        }

        // Bit-field aliases (issue #61: UBFX/SBFX/BFI/BFXIL/UBFIZ/SBFIZ) in both
        // X (64-bit) and W (32-bit) forms (issue #145). Sparse (lsb, width)
        // sampling to keep the enumerative budget bounded; SP filtered from rd
        // and rn (matches is_encodable_aarch64). The shared sample tables are
        // filtered per width against the bound (lsb < bound, lsb+width <= bound).
        // Mirrors `src/search/candidate.rs::generate_all_instructions`.
        const BITFIELD_LSB_SAMPLES: [u8; 5] = [0, 1, 16, 32, 63];
        const BITFIELD_WIDTH_SAMPLES: [u8; 6] = [1, 4, 8, 16, 32, 64];
        for &rd in registers {
            if rd == Register::SP {
                continue;
            }
            for &rn in registers {
                if rn == Register::SP {
                    continue;
                }
                for reg_width in [RegisterWidth::X64, RegisterWidth::W32] {
                    let bound = reg_width.bit_width() as u16;
                    for &lsb in &BITFIELD_LSB_SAMPLES {
                        if lsb as u16 >= bound {
                            continue;
                        }
                        for &width in &BITFIELD_WIDTH_SAMPLES {
                            if width as u16 > bound || (lsb as u16 + width as u16) > bound {
                                continue;
                            }
                            instructions.push(Instruction::Ubfx {
                                rd,
                                rn,
                                lsb,
                                width,
                                reg_width,
                            });
                            instructions.push(Instruction::Sbfx {
                                rd,
                                rn,
                                lsb,
                                width,
                                reg_width,
                            });
                            instructions.push(Instruction::Bfi {
                                rd,
                                rn,
                                lsb,
                                width,
                                reg_width,
                            });
                            instructions.push(Instruction::Bfxil {
                                rd,
                                rn,
                                lsb,
                                width,
                                reg_width,
                            });
                            instructions.push(Instruction::Ubfiz {
                                rd,
                                rn,
                                lsb,
                                width,
                                reg_width,
                            });
                            instructions.push(Instruction::Sbfiz {
                                rd,
                                rn,
                                lsb,
                                width,
                                reg_width,
                            });
                        }
                    }
                }
            }
        }

        instructions
    }

    fn generate_random<R: RngExt>(
        &self,
        rng: &mut R,
        registers: &[Register],
        immediates: &[i64],
    ) -> Instruction {
        // 38 random-generation slots: 0..=12 original, 13..=23 Tier 1,
        // 24 = MOVZ, 25 = MOVK, 26..=31 = CLZ/CLS/RBIT/REV/REV32/REV16 as
        // separate top-level slots, 32 = multiply-accumulate family (issue
        // #56: 5-way sub-multiplexer for MADD/MSUB/MNEG/SMULH/UMULH), 33 =
        // conditional-compare family (issue #57: 2-way sub-multiplexer for
        // CCMP/CCMN), 34 = bit-field aliases (issue #61: 6-way sub-multiplexer
        // for UBFX/SBFX/BFI/BFXIL/UBFIZ/SBFIZ), 35 = CSET, 36 = CSETM,
        // 37 = ROR.
        // These sampler slots are independent from `opcode_id()` values; for
        // example, CSET/CSETM/ROR are slots 35/36/37 here but opcode IDs
        // 31/32/33.
        // See also `src/search/candidate.rs::generate_random_instruction`:
        // it is a parallel 38-slot sampler, but its slot numbers differ
        // (notably, ROR is slot 23 there and slot 37 here).
        let opcode = rng.random_range(0..38);
        let rd = registers[rng.random_range(0..registers.len())];
        let rn = registers[rng.random_range(0..registers.len())];
        let pick_reg = |rng: &mut R| registers[rng.random_range(0..registers.len())];
        let pick_imm = |rng: &mut R| immediates[rng.random_range(0..immediates.len())];

        match opcode {
            0 => Instruction::MovReg { rd, rn },
            1 => Instruction::MovImm {
                rd,
                imm: pick_imm(rng),
            },
            2..=6 => {
                let use_imm = rng.random_bool(0.5);
                let rm = if use_imm && (opcode == 2 || opcode == 3) {
                    Operand::Immediate(pick_imm(rng))
                } else {
                    Operand::Register(pick_reg(rng))
                };
                match opcode {
                    2 => Instruction::Add { rd, rn, rm },
                    3 => Instruction::Sub { rd, rn, rm },
                    4 => Instruction::And {
                        rd,
                        rn,
                        rm,
                        width: RegisterWidth::X64,
                    },
                    5 => Instruction::Orr {
                        rd,
                        rn,
                        rm,
                        width: RegisterWidth::X64,
                    },
                    6 => Instruction::Eor {
                        rd,
                        rn,
                        rm,
                        width: RegisterWidth::X64,
                    },
                    _ => unreachable!(),
                }
            }
            7..=9 => {
                let use_imm = rng.random_bool(0.5);
                let shift = if use_imm {
                    let amounts = AARCH64_RANDOM_SHIFT_IMMEDIATES;
                    Operand::Immediate(amounts[rng.random_range(0..amounts.len())])
                } else {
                    Operand::Register(pick_reg(rng))
                };
                match opcode {
                    7 => Instruction::Lsl { rd, rn, shift },
                    8 => Instruction::Lsr { rd, rn, shift },
                    9 => Instruction::Asr { rd, rn, shift },
                    _ => unreachable!(),
                }
            }
            10..=12 => {
                let rm = pick_reg(rng);
                match opcode {
                    10 => Instruction::Mul { rd, rn, rm },
                    11 => Instruction::Sdiv { rd, rn, rm },
                    12 => Instruction::Udiv { rd, rn, rm },
                    _ => unreachable!(),
                }
            }
            // Tier 1: unary
            13 => Instruction::Mvn {
                rd,
                rm: pick_reg(rng),
            },
            14 => Instruction::Neg {
                rd,
                rm: pick_reg(rng),
            },
            15 => Instruction::Negs {
                rd,
                rm: pick_reg(rng),
            },
            16 => {
                let imm = (rng.random::<u32>() & 0xFFFF) as u16;
                let shifts = MOVW_LEGAL_SHIFTS;
                Instruction::MovN {
                    rd,
                    imm,
                    shift: shifts[rng.random_range(0..shifts.len())],
                }
            }
            // Tier 1: inverted-logical (register-only)
            17 => Instruction::Bic {
                rd,
                rn,
                rm: Operand::Register(pick_reg(rng)),
            },
            18 => Instruction::Bics {
                rd,
                rn,
                rm: Operand::Register(pick_reg(rng)),
            },
            19 => Instruction::Orn {
                rd,
                rn,
                rm: Operand::Register(pick_reg(rng)),
            },
            20 => Instruction::Eon {
                rd,
                rn,
                rm: Operand::Register(pick_reg(rng)),
            },
            // Tier 1: flag-setting arith (ADDS/SUBS imm, ANDS reg-only)
            21 => {
                let rm = if rng.random_bool(0.5) {
                    Operand::Immediate(pick_imm(rng))
                } else {
                    Operand::Register(pick_reg(rng))
                };
                Instruction::Adds { rd, rn, rm }
            }
            22 => {
                let rm = if rng.random_bool(0.5) {
                    Operand::Immediate(pick_imm(rng))
                } else {
                    Operand::Register(pick_reg(rng))
                };
                Instruction::Subs { rd, rn, rm }
            }
            23 => Instruction::Ands {
                rd,
                rn,
                rm: Operand::Register(pick_reg(rng)),
                width: RegisterWidth::X64,
            },
            24 => {
                let imm = (rng.random::<u32>() & 0xFFFF) as u16;
                let shifts = MOVW_LEGAL_SHIFTS;
                Instruction::MovZ {
                    rd,
                    imm,
                    shift: shifts[rng.random_range(0..shifts.len())],
                }
            }
            25 => {
                let imm = (rng.random::<u32>() & 0xFFFF) as u16;
                let shifts = MOVW_LEGAL_SHIFTS;
                Instruction::MovK {
                    rd,
                    imm,
                    shift: shifts[rng.random_range(0..shifts.len())],
                }
            }
            // Single-source bit-manipulation opcodes each keep a top-level slot
            // so stochastic search does not starve CLZ/RBIT/REV-shaped targets.
            26 => Instruction::Clz {
                rd,
                rn: pick_reg(rng),
            },
            27 => Instruction::Cls {
                rd,
                rn: pick_reg(rng),
            },
            28 => Instruction::Rbit {
                rd,
                rn: pick_reg(rng),
            },
            29 => Instruction::Rev {
                rd,
                rn: pick_reg(rng),
            },
            30 => Instruction::Rev32 {
                rd,
                rn: pick_reg(rng),
            },
            31 => Instruction::Rev16 {
                rd,
                rn: pick_reg(rng),
            },
            // Multiply-accumulate family.
            32 => {
                let rm = pick_reg(rng);
                match rng.random_range(0..5) {
                    0 => {
                        let ra = pick_reg(rng);
                        Instruction::Madd { rd, rn, rm, ra }
                    }
                    1 => {
                        let ra = pick_reg(rng);
                        Instruction::Msub { rd, rn, rm, ra }
                    }
                    2 => Instruction::Mneg { rd, rn, rm },
                    3 => Instruction::Smulh { rd, rn, rm },
                    _ => Instruction::Umulh { rd, rn, rm },
                }
            }
            // Conditional-compare family (CCMP/CCMN). `is_encodable_aarch64`
            // forbids SP in `rn` and forbids AL/NV; mirror those in the
            // sampler to keep the emitted candidates encodable. Build a
            // SP-filtered slice up front so the picker is a single
            // bounded sample (no retry loop, no infinite-spin risk in
            // release builds on a degenerate `[SP]`-only pool — that
            // case falls back to the next opcode).
            33 => {
                let non_sp: Vec<Register> = registers
                    .iter()
                    .copied()
                    .filter(|r| *r != Register::SP)
                    .collect();
                if non_sp.is_empty() {
                    // No encodable CCMP/CCMN candidates with this pool —
                    // fall back to the multiply-accumulate family which
                    // tolerates any register.
                    let rm = pick_reg(rng);
                    return Instruction::Mneg { rd, rn, rm };
                }
                let pick_non_sp = |rng: &mut R| non_sp[rng.random_range(0..non_sp.len())];
                let ccmp_rn = pick_non_sp(rng);
                let rm = if rng.random_bool(0.5) {
                    Operand::Register(pick_non_sp(rng))
                } else {
                    Operand::Immediate(pick_imm(rng).rem_euclid(32))
                };
                let nzcv = (rng.random::<u32>() & 0x0F) as u8;
                let cond = Condition::random_normal(rng);
                if rng.random_bool(0.5) {
                    Instruction::Ccmp {
                        rn: ccmp_rn,
                        rm,
                        nzcv,
                        cond,
                    }
                } else {
                    Instruction::Ccmn {
                        rn: ccmp_rn,
                        rm,
                        nzcv,
                        cond,
                    }
                }
            }
            // Bit-field aliases (issue #61: UBFX/SBFX/BFI/BFXIL/UBFIZ/SBFIZ).
            // SP is illegal in both rd and rn; we pre-filter rather than retry
            // so the release build has no infinite-spin path on a degenerate
            // `[SP]`-only pool — that case falls back to the multiply-accumulate
            // family (which tolerates any register). The 2D constraint
            // `lsb + width <= 64` is enforced by sampling width AFTER lsb so
            // width is bounded by `64 - lsb`.
            34 => {
                let non_sp: Vec<Register> = registers
                    .iter()
                    .copied()
                    .filter(|r| *r != Register::SP)
                    .collect();
                if non_sp.is_empty() {
                    let rm = pick_reg(rng);
                    return Instruction::Mneg { rd, rn, rm };
                }
                let pick_non_sp = |rng: &mut R| non_sp[rng.random_range(0..non_sp.len())];
                let bf_rd = pick_non_sp(rng);
                let bf_rn = pick_non_sp(rng);
                let reg_width = if rng.random_bool(0.5) {
                    RegisterWidth::W32
                } else {
                    RegisterWidth::X64
                };
                let bound = reg_width.bit_width() as u32;
                let lsb = (rng.random::<u32>() % bound) as u8;
                let max_w = bound - lsb as u32;
                let width = ((rng.random::<u32>() % max_w) + 1) as u8;
                match rng.random_range(0..6) {
                    0 => Instruction::Ubfx {
                        rd: bf_rd,
                        rn: bf_rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    1 => Instruction::Sbfx {
                        rd: bf_rd,
                        rn: bf_rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    2 => Instruction::Bfi {
                        rd: bf_rd,
                        rn: bf_rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    3 => Instruction::Bfxil {
                        rd: bf_rd,
                        rn: bf_rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    4 => Instruction::Ubfiz {
                        rd: bf_rd,
                        rn: bf_rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    _ => Instruction::Sbfiz {
                        rd: bf_rd,
                        rn: bf_rn,
                        lsb,
                        width,
                        reg_width,
                    },
                }
            }
            35 => Instruction::Cset {
                rd,
                cond: Condition::random_normal(rng),
            },
            36 => Instruction::Csetm {
                rd,
                cond: Condition::random_normal(rng),
            },
            37 => {
                let shift = if rng.random_bool(0.5) {
                    let amounts = AARCH64_RANDOM_SHIFT_IMMEDIATES;
                    Operand::Immediate(amounts[rng.random_range(0..amounts.len())])
                } else {
                    Operand::Register(pick_reg(rng))
                };
                Instruction::Ror { rd, rn, shift }
            }
            _ => unreachable!(),
        }
    }

    fn mutate<R: RngExt>(
        &self,
        rng: &mut R,
        instruction: &Instruction,
        registers: &[Register],
        immediates: &[i64],
    ) -> Instruction {
        // Random mutation strategy: change opcode, change operand, or change register
        let strategy = rng.random_range(0..3);

        match strategy {
            0 => {
                // Change opcode - generate a completely new instruction
                self.generate_random(rng, registers, immediates)
            }
            1 => {
                // Change destination register
                let new_rd = registers[rng.random_range(0..registers.len())];
                match *instruction {
                    Instruction::MovReg { rn, .. } => Instruction::MovReg { rd: new_rd, rn },
                    Instruction::MovRegW { rn, .. } => Instruction::MovRegW { rd: new_rd, rn },
                    Instruction::MovImm { imm, .. } => Instruction::MovImm { rd: new_rd, imm },
                    Instruction::Add { rn, rm, .. } => Instruction::Add { rd: new_rd, rn, rm },
                    Instruction::AddW { rn, rm, .. } => Instruction::AddW { rd: new_rd, rn, rm },
                    Instruction::Sub { rn, rm, .. } => Instruction::Sub { rd: new_rd, rn, rm },
                    Instruction::SubW { rn, rm, .. } => Instruction::SubW { rd: new_rd, rn, rm },
                    Instruction::And { rn, rm, width, .. } => Instruction::And {
                        rd: new_rd,
                        rn,
                        rm,
                        width,
                    },
                    Instruction::Orr { rn, rm, width, .. } => Instruction::Orr {
                        rd: new_rd,
                        rn,
                        rm,
                        width,
                    },
                    Instruction::Eor { rn, rm, width, .. } => Instruction::Eor {
                        rd: new_rd,
                        rn,
                        rm,
                        width,
                    },
                    Instruction::Lsl { rn, shift, .. } => Instruction::Lsl {
                        rd: new_rd,
                        rn,
                        shift,
                    },
                    Instruction::Lsr { rn, shift, .. } => Instruction::Lsr {
                        rd: new_rd,
                        rn,
                        shift,
                    },
                    Instruction::Asr { rn, shift, .. } => Instruction::Asr {
                        rd: new_rd,
                        rn,
                        shift,
                    },
                    Instruction::Mul { rn, rm, .. } => Instruction::Mul { rd: new_rd, rn, rm },
                    Instruction::Sdiv { rn, rm, .. } => Instruction::Sdiv { rd: new_rd, rn, rm },
                    Instruction::Udiv { rn, rm, .. } => Instruction::Udiv { rd: new_rd, rn, rm },
                    Instruction::Madd { rn, rm, ra, .. } => Instruction::Madd {
                        rd: new_rd,
                        rn,
                        rm,
                        ra,
                    },
                    Instruction::Msub { rn, rm, ra, .. } => Instruction::Msub {
                        rd: new_rd,
                        rn,
                        rm,
                        ra,
                    },
                    Instruction::Mneg { rn, rm, .. } => Instruction::Mneg { rd: new_rd, rn, rm },
                    Instruction::Smulh { rn, rm, .. } => Instruction::Smulh { rd: new_rd, rn, rm },
                    Instruction::Umulh { rn, rm, .. } => Instruction::Umulh { rd: new_rd, rn, rm },
                    // Comparison instructions have no destination - generate random instead
                    Instruction::Cmp { .. }
                    | Instruction::Cmn { .. }
                    | Instruction::Tst { .. }
                    | Instruction::Ccmp { .. }
                    | Instruction::Ccmn { .. } => self.generate_random(rng, registers, immediates),
                    // Conditional select instructions
                    Instruction::Csel { rn, rm, cond, .. } => Instruction::Csel {
                        rd: new_rd,
                        rn,
                        rm,
                        cond,
                    },
                    Instruction::Csinc { rn, rm, cond, .. } => Instruction::Csinc {
                        rd: new_rd,
                        rn,
                        rm,
                        cond,
                    },
                    Instruction::Csinv { rn, rm, cond, .. } => Instruction::Csinv {
                        rd: new_rd,
                        rn,
                        rm,
                        cond,
                    },
                    Instruction::Csneg { rn, rm, cond, .. } => Instruction::Csneg {
                        rd: new_rd,
                        rn,
                        rm,
                        cond,
                    },
                    Instruction::Mvn { rm, .. } => Instruction::Mvn { rd: new_rd, rm },
                    Instruction::Neg { rm, .. } => Instruction::Neg { rd: new_rd, rm },
                    Instruction::Negs { rm, .. } => Instruction::Negs { rd: new_rd, rm },
                    Instruction::MovN { imm, shift, .. } => Instruction::MovN {
                        rd: new_rd,
                        imm,
                        shift,
                    },
                    Instruction::MovZ { imm, shift, .. } => Instruction::MovZ {
                        rd: new_rd,
                        imm,
                        shift,
                    },
                    Instruction::MovK { imm, shift, .. } => Instruction::MovK {
                        rd: new_rd,
                        imm,
                        shift,
                    },
                    Instruction::Bic { rn, rm, .. } => Instruction::Bic { rd: new_rd, rn, rm },
                    Instruction::Bics { rn, rm, .. } => Instruction::Bics { rd: new_rd, rn, rm },
                    Instruction::Orn { rn, rm, .. } => Instruction::Orn { rd: new_rd, rn, rm },
                    Instruction::Eon { rn, rm, .. } => Instruction::Eon { rd: new_rd, rn, rm },
                    Instruction::Adds { rn, rm, .. } => Instruction::Adds { rd: new_rd, rn, rm },
                    Instruction::Subs { rn, rm, .. } => Instruction::Subs { rd: new_rd, rn, rm },
                    Instruction::Adc { rn, rm, .. } => Instruction::Adc { rd: new_rd, rn, rm },
                    Instruction::Adcs { rn, rm, .. } => Instruction::Adcs { rd: new_rd, rn, rm },
                    Instruction::Sbc { rn, rm, .. } => Instruction::Sbc { rd: new_rd, rn, rm },
                    Instruction::Sbcs { rn, rm, .. } => Instruction::Sbcs { rd: new_rd, rn, rm },
                    Instruction::Ands { rn, rm, width, .. } => Instruction::Ands {
                        rd: new_rd,
                        rn,
                        rm,
                        width,
                    },
                    Instruction::Cset { cond, .. } => Instruction::Cset { rd: new_rd, cond },
                    Instruction::Csetm { cond, .. } => Instruction::Csetm { rd: new_rd, cond },
                    Instruction::Ror { rn, shift, .. } => Instruction::Ror {
                        rd: new_rd,
                        rn,
                        shift,
                    },
                    Instruction::Clz { rn, .. } => Instruction::Clz { rd: new_rd, rn },
                    Instruction::Cls { rn, .. } => Instruction::Cls { rd: new_rd, rn },
                    Instruction::Rbit { rn, .. } => Instruction::Rbit { rd: new_rd, rn },
                    Instruction::Rev { rn, .. } => Instruction::Rev { rd: new_rd, rn },
                    Instruction::Rev32 { rn, .. } => Instruction::Rev32 { rd: new_rd, rn },
                    Instruction::Rev16 { rn, .. } => Instruction::Rev16 { rd: new_rd, rn },
                    Instruction::Sxtb { rn, .. } => Instruction::Sxtb { rd: new_rd, rn },
                    Instruction::Sxth { rn, .. } => Instruction::Sxth { rd: new_rd, rn },
                    Instruction::Sxtw { rn, .. } => Instruction::Sxtw { rd: new_rd, rn },
                    Instruction::Uxtb { rn, .. } => Instruction::Uxtb { rd: new_rd, rn },
                    Instruction::Uxth { rn, .. } => Instruction::Uxth { rd: new_rd, rn },
                    Instruction::Ubfx {
                        rn,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Ubfx {
                        rd: new_rd,
                        rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Sbfx {
                        rn,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Sbfx {
                        rd: new_rd,
                        rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Bfi {
                        rn,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Bfi {
                        rd: new_rd,
                        rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Bfxil {
                        rn,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Bfxil {
                        rd: new_rd,
                        rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Ubfiz {
                        rn,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Ubfiz {
                        rd: new_rd,
                        rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Sbfiz {
                        rn,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Sbfiz {
                        rd: new_rd,
                        rn,
                        lsb,
                        width,
                        reg_width,
                    },
                    // Branches have no rd; identity-mutate.
                    Instruction::B { target } => Instruction::B { target },
                    Instruction::BCond { target, cond } => Instruction::BCond { target, cond },
                    Instruction::Ret { rn } => Instruction::Ret { rn },
                    Instruction::Cbz { rn, target } => Instruction::Cbz { rn, target },
                    Instruction::Cbnz { rn, target } => Instruction::Cbnz { rn, target },
                    Instruction::Tbz { rt, bit, target } => Instruction::Tbz { rt, bit, target },
                    Instruction::Tbnz { rt, bit, target } => Instruction::Tbnz { rt, bit, target },
                    Instruction::Bl { target } => Instruction::Bl { target },
                    Instruction::Br { rn } => Instruction::Br { rn },
                    // Memory ops: identity-mutate for now. Step 16 wires
                    // dedicated rt/base/idx/offset rotation slots in
                    // `mutate_operand` / `mutate_opcode`.
                    Instruction::Ldr { .. }
                    | Instruction::Ldrs { .. }
                    | Instruction::Str { .. }
                    | Instruction::Ldp { .. }
                    | Instruction::Stp { .. } => *instruction,
                }
            }
            2 => {
                // Change source operand
                match *instruction {
                    Instruction::MovReg { rd, .. } => {
                        let new_rn = registers[rng.random_range(0..registers.len())];
                        Instruction::MovReg { rd, rn: new_rn }
                    }
                    Instruction::MovRegW { rd, .. } => {
                        let new_rn = registers[rng.random_range(0..registers.len())];
                        Instruction::MovRegW { rd, rn: new_rn }
                    }
                    Instruction::MovImm { rd, .. } => {
                        let new_imm = immediates[rng.random_range(0..immediates.len())];
                        Instruction::MovImm { rd, imm: new_imm }
                    }
                    Instruction::Add { rd, rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 0xFFF);
                        Instruction::Add { rd, rn, rm: new_rm }
                    }
                    Instruction::AddW { rd, rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 0xFFF);
                        Instruction::AddW { rd, rn, rm: new_rm }
                    }
                    Instruction::Sub { rd, rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 0xFFF);
                        Instruction::Sub { rd, rn, rm: new_rm }
                    }
                    Instruction::SubW { rd, rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 0xFFF);
                        Instruction::SubW { rd, rn, rm: new_rm }
                    }
                    Instruction::And {
                        rd,
                        rn,
                        rm: _,
                        width,
                    } => {
                        // AND doesn't support immediates, so only change register
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::And {
                            rd,
                            rn,
                            rm: new_rm,
                            width,
                        }
                    }
                    Instruction::Orr {
                        rd,
                        rn,
                        rm: _,
                        width,
                    } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Orr {
                            rd,
                            rn,
                            rm: new_rm,
                            width,
                        }
                    }
                    Instruction::Eor {
                        rd,
                        rn,
                        rm: _,
                        width,
                    } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Eor {
                            rd,
                            rn,
                            rm: new_rm,
                            width,
                        }
                    }
                    Instruction::Lsl { rd, rn, shift } => {
                        let new_shift = mutate_shift_operand(rng, shift, registers);
                        Instruction::Lsl {
                            rd,
                            rn,
                            shift: new_shift,
                        }
                    }
                    Instruction::Lsr { rd, rn, shift } => {
                        let new_shift = mutate_shift_operand(rng, shift, registers);
                        Instruction::Lsr {
                            rd,
                            rn,
                            shift: new_shift,
                        }
                    }
                    Instruction::Asr { rd, rn, shift } => {
                        let new_shift = mutate_shift_operand(rng, shift, registers);
                        Instruction::Asr {
                            rd,
                            rn,
                            shift: new_shift,
                        }
                    }
                    Instruction::Mul { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Mul { rd, rn, rm: new_rm }
                    }
                    Instruction::Sdiv { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Sdiv { rd, rn, rm: new_rm }
                    }
                    Instruction::Udiv { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Udiv { rd, rn, rm: new_rm }
                    }
                    Instruction::Madd { rd, rn, rm, ra } => {
                        // Pick one of {rm, ra} to substitute (rd handled by
                        // strategy 1; rn by the broader source-mutation path).
                        if rng.random_bool(0.5) {
                            let new_rm = registers[rng.random_range(0..registers.len())];
                            Instruction::Madd {
                                rd,
                                rn,
                                rm: new_rm,
                                ra,
                            }
                        } else {
                            let new_ra = registers[rng.random_range(0..registers.len())];
                            Instruction::Madd {
                                rd,
                                rn,
                                rm,
                                ra: new_ra,
                            }
                        }
                    }
                    Instruction::Msub { rd, rn, rm, ra } => {
                        if rng.random_bool(0.5) {
                            let new_rm = registers[rng.random_range(0..registers.len())];
                            Instruction::Msub {
                                rd,
                                rn,
                                rm: new_rm,
                                ra,
                            }
                        } else {
                            let new_ra = registers[rng.random_range(0..registers.len())];
                            Instruction::Msub {
                                rd,
                                rn,
                                rm,
                                ra: new_ra,
                            }
                        }
                    }
                    Instruction::Mneg { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Mneg { rd, rn, rm: new_rm }
                    }
                    Instruction::Smulh { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Smulh { rd, rn, rm: new_rm }
                    }
                    Instruction::Umulh { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Umulh { rd, rn, rm: new_rm }
                    }
                    // Comparison instructions - change operand
                    Instruction::Cmp { rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 0xFFF);
                        Instruction::Cmp { rn, rm: new_rm }
                    }
                    Instruction::Cmn { rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 0xFFF);
                        Instruction::Cmn { rn, rm: new_rm }
                    }
                    Instruction::Tst { rn, rm: _, width } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Tst {
                            rn,
                            rm: new_rm,
                            width,
                        }
                    }
                    // CCMP / CCMN: pick a new rm (register or imm5). The
                    // dedicated mutate_operand path in
                    // `search/stochastic/mutation.rs` covers nzcv and cond.
                    Instruction::Ccmp { rn, rm, nzcv, cond } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 31);
                        Instruction::Ccmp {
                            rn,
                            rm: new_rm,
                            nzcv,
                            cond,
                        }
                    }
                    Instruction::Ccmn { rn, rm, nzcv, cond } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 31);
                        Instruction::Ccmn {
                            rn,
                            rm: new_rm,
                            nzcv,
                            cond,
                        }
                    }
                    // Conditional select - change operands
                    Instruction::Csel { rd, rn, cond, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Csel {
                            rd,
                            rn,
                            rm: new_rm,
                            cond,
                        }
                    }
                    Instruction::Csinc { rd, rn, cond, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Csinc {
                            rd,
                            rn,
                            rm: new_rm,
                            cond,
                        }
                    }
                    Instruction::Csinv { rd, rn, cond, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Csinv {
                            rd,
                            rn,
                            rm: new_rm,
                            cond,
                        }
                    }
                    Instruction::Csneg { rd, rn, cond, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Csneg {
                            rd,
                            rn,
                            rm: new_rm,
                            cond,
                        }
                    }
                    Instruction::Mvn { rd, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Mvn { rd, rm: new_rm }
                    }
                    Instruction::Neg { rd, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Neg { rd, rm: new_rm }
                    }
                    Instruction::Negs { rd, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Negs { rd, rm: new_rm }
                    }
                    Instruction::MovN { rd, shift, .. } => {
                        // "Change source operand" strategy: for MOVN the only
                        // source operand is `imm`. The `shift` field is part
                        // of the encoding form, not the source-operand set,
                        // so we leave it alone here.
                        //
                        // The more granular per-field mutator in
                        // `search/stochastic/mutation.rs` (mutate_operand)
                        // also covers `shift` because it picks among rd,
                        // imm, and shift uniformly. Both paths are
                        // intentionally distinct.
                        let new_imm = (rng.random::<u32>() & 0xFFFF) as u16;
                        Instruction::MovN {
                            rd,
                            imm: new_imm,
                            shift,
                        }
                    }
                    // MOVZ / MOVK: same rationale as MOVN — `imm` is the only
                    // source operand; `shift` is left alone here. MOVK also
                    // reads `rd`, but `rd` is the destination, not a source
                    // operand we mutate in this strategy (the "change
                    // destination register" branch above already handles it).
                    Instruction::MovZ { rd, shift, .. } => {
                        let new_imm = (rng.random::<u32>() & 0xFFFF) as u16;
                        Instruction::MovZ {
                            rd,
                            imm: new_imm,
                            shift,
                        }
                    }
                    Instruction::MovK { rd, shift, .. } => {
                        let new_imm = (rng.random::<u32>() & 0xFFFF) as u16;
                        Instruction::MovK {
                            rd,
                            imm: new_imm,
                            shift,
                        }
                    }
                    Instruction::Bic { rd, rn, rm: _ } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Bic { rd, rn, rm: new_rm }
                    }
                    Instruction::Bics { rd, rn, rm: _ } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Bics { rd, rn, rm: new_rm }
                    }
                    Instruction::Orn { rd, rn, rm: _ } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Orn { rd, rn, rm: new_rm }
                    }
                    Instruction::Eon { rd, rn, rm: _ } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Eon { rd, rn, rm: new_rm }
                    }
                    Instruction::Adds { rd, rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 0xFFF);
                        Instruction::Adds { rd, rn, rm: new_rm }
                    }
                    Instruction::Subs { rd, rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates, 0xFFF);
                        Instruction::Subs { rd, rn, rm: new_rm }
                    }
                    Instruction::Adc { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Adc { rd, rn, rm: new_rm }
                    }
                    Instruction::Adcs { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Adcs { rd, rn, rm: new_rm }
                    }
                    Instruction::Sbc { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Sbc { rd, rn, rm: new_rm }
                    }
                    Instruction::Sbcs { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Sbcs { rd, rn, rm: new_rm }
                    }
                    Instruction::Ands {
                        rd,
                        rn,
                        rm: _,
                        width,
                    } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Ands {
                            rd,
                            rn,
                            rm: new_rm,
                            width,
                        }
                    }
                    // CSET / CSETM: only thing to "change as operand" is the cond.
                    // Pick from the 14 sensible conditions (skip AL/NV).
                    Instruction::Cset { rd, .. } => Instruction::Cset {
                        rd,
                        cond: Condition::random_normal(rng),
                    },
                    Instruction::Csetm { rd, .. } => Instruction::Csetm {
                        rd,
                        cond: Condition::random_normal(rng),
                    },
                    Instruction::Ror { rd, rn, shift } => {
                        let new_shift = mutate_shift_operand(rng, shift, registers);
                        Instruction::Ror {
                            rd,
                            rn,
                            shift: new_shift,
                        }
                    }
                    Instruction::Clz { rd, .. } => Instruction::Clz {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Cls { rd, .. } => Instruction::Cls {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Rbit { rd, .. } => Instruction::Rbit {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Rev { rd, .. } => Instruction::Rev {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Rev32 { rd, .. } => Instruction::Rev32 {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Rev16 { rd, .. } => Instruction::Rev16 {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Sxtb { rd, .. } => Instruction::Sxtb {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Sxth { rd, .. } => Instruction::Sxth {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Sxtw { rd, .. } => Instruction::Sxtw {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Uxtb { rd, .. } => Instruction::Uxtb {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Uxth { rd, .. } => Instruction::Uxth {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                    },
                    Instruction::Ubfx {
                        rd,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Ubfx {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Sbfx {
                        rd,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Sbfx {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Bfi {
                        rd,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Bfi {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Bfxil {
                        rd,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Bfxil {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Ubfiz {
                        rd,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Ubfiz {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                        lsb,
                        width,
                        reg_width,
                    },
                    Instruction::Sbfiz {
                        rd,
                        lsb,
                        width,
                        reg_width,
                        ..
                    } => Instruction::Sbfiz {
                        rd,
                        rn: registers[rng.random_range(0..registers.len())],
                        lsb,
                        width,
                        reg_width,
                    },
                    // Branches: no source operand mutation; identity.
                    Instruction::B { target } => Instruction::B { target },
                    Instruction::BCond { target, cond } => Instruction::BCond { target, cond },
                    Instruction::Ret { rn } => Instruction::Ret { rn },
                    Instruction::Cbz { rn, target } => Instruction::Cbz { rn, target },
                    Instruction::Cbnz { rn, target } => Instruction::Cbnz { rn, target },
                    Instruction::Tbz { rt, bit, target } => Instruction::Tbz { rt, bit, target },
                    Instruction::Tbnz { rt, bit, target } => Instruction::Tbnz { rt, bit, target },
                    Instruction::Bl { target } => Instruction::Bl { target },
                    Instruction::Br { rn } => Instruction::Br { rn },
                    // Memory ops: identity-mutate for now. Step 16 wires
                    // dedicated source-operand rotation slots.
                    Instruction::Ldr { .. }
                    | Instruction::Ldrs { .. }
                    | Instruction::Str { .. }
                    | Instruction::Ldp { .. }
                    | Instruction::Stp { .. } => *instruction,
                }
            }
            _ => unreachable!(),
        }
    }

    /// Total number of distinct opcode *families* (the upper bound on
    /// `opcode_id()`). Not the same as `generate_random`'s slot count —
    /// `generate_random` samples 38 top-level slots and still folds several
    /// families into sub-multiplexers (e.g. the five multiply-accumulate ops,
    /// the two conditional-compare ops, the five standalone extend aliases,
    /// and the six bit-field aliases). So `opcode_id < opcode_count` always
    /// holds for generated arithmetic/logical families, but the
    /// random-generation distribution is not uniform across all 60 IDs.
    fn opcode_count(&self) -> u8 {
        60 // 20 original + 14 Tier 1 (MVN, NEG, NEGS, MovN, BIC, BICS, ORN,
        //  EON, ADDS, SUBS, ANDS, CSET, CSETM, ROR) + 2 MOVK/MOVZ (issue
        //  #55) + 6 single-source bit-manipulation (CLZ, CLS, RBIT, REV,
        //  REV32, REV16) + 5 multiply-accumulate family (issue #56:
        //  MADD, MSUB, MNEG, SMULH, UMULH) + 2 conditional-compare family
        //  (issue #57: CCMP, CCMN) + 5 standalone extend aliases
        //  (SXTB, SXTH, SXTW, UXTB, UXTH) + 6 bit-field aliases (UBFX, SBFX,
        //  BFI, BFXIL, UBFIZ, SBFIZ, issue #61).
    }
}

fn mutate_operand<R: RngExt>(
    rng: &mut R,
    operand: Operand,
    registers: &[Register],
    immediates: &[i64],
    imm_max: i64,
) -> Operand {
    debug_assert!(imm_max >= 0, "imm_max must be non-negative");
    let pick_imm = |rng: &mut R| {
        let v = immediates[rng.random_range(0..immediates.len())];
        // Issue #87: clamp to the caller's encodable upper bound. Mirrors
        // the CCMP/CCMN clamp in `src/search/stochastic/mutation.rs` and
        // matches `Instruction::is_encodable_aarch64`'s per-variant ranges
        // (ADD/SUB/ADDS/SUBS/CMP/CMN: 0..=0xFFF; CCMP/CCMN: 0..=31).
        Operand::Immediate(v.rem_euclid(imm_max + 1))
    };
    match operand {
        Operand::Register(_)
        | Operand::ShiftedRegister { .. }
        | Operand::ExtendedRegister { .. } => {
            if rng.random_bool(0.7) {
                Operand::Register(registers[rng.random_range(0..registers.len())])
            } else {
                pick_imm(rng)
            }
        }
        Operand::Immediate(_) => {
            if rng.random_bool(0.7) {
                pick_imm(rng)
            } else {
                Operand::Register(registers[rng.random_range(0..registers.len())])
            }
        }
    }
}

fn mutate_shift_operand<R: RngExt>(
    rng: &mut R,
    operand: Operand,
    registers: &[Register],
) -> Operand {
    let shift_amounts = AARCH64_RANDOM_SHIFT_IMMEDIATES;
    match operand {
        Operand::Register(_)
        | Operand::ShiftedRegister { .. }
        | Operand::ExtendedRegister { .. } => {
            if rng.random_bool(0.5) {
                Operand::Register(registers[rng.random_range(0..registers.len())])
            } else {
                Operand::Immediate(shift_amounts[rng.random_range(0..shift_amounts.len())])
            }
        }
        Operand::Immediate(_) => {
            if rng.random_bool(0.5) {
                Operand::Immediate(shift_amounts[rng.random_range(0..shift_amounts.len())])
            } else {
                Operand::Register(registers[rng.random_range(0..registers.len())])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::collections::BTreeSet;

    fn all_instruction_families() -> Vec<Instruction> {
        vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 7,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(3),
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(4),
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Mul {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Sdiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Udiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Immediate(9),
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Csel {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::EQ,
            },
            Instruction::Csinc {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::NE,
            },
            Instruction::Csinv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::LT,
            },
            Instruction::Csneg {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::GT,
            },
            Instruction::Mvn {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Neg {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Negs {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 0x55aa,
                shift: 16,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0x55aa,
                shift: 32,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0x55aa,
                shift: 48,
            },
            Instruction::Bic {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Bics {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Orn {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Eon {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::GE,
            },
            Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::LE,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(8),
            },
            Instruction::Clz {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Cls {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Rbit {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Rev {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Rev32 {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Rev16 {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Madd {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Msub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                ra: Register::X3,
            },
            Instruction::Mneg {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Smulh {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Umulh {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Ccmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                nzcv: 0,
                cond: Condition::EQ,
            },
            Instruction::Ccmn {
                rn: Register::X1,
                rm: Operand::Immediate(5),
                nzcv: 0,
                cond: Condition::EQ,
            },
            Instruction::Sxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sxth {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sxtw {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Uxth {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Ubfx {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 8,
                width: 16,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Sbfx {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 8,
                width: 16,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Bfi {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 4,
                width: 8,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Bfxil {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 4,
                width: 8,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Ubfiz {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 4,
                width: 8,
                reg_width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Sbfiz {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 4,
                width: 8,
                reg_width: crate::ir::RegisterWidth::X64,
            },
        ]
    }

    #[test]
    fn test_aarch64_isa_metadata() {
        let isa = AArch64;
        assert_eq!(isa.name(), "AArch64");
        assert_eq!(isa.register_count(), 31);
        assert_eq!(isa.register_width(), 64);
        assert_eq!(isa.instruction_size(), Some(4));
        assert_eq!(isa.zero_register(), Some(Register::XZR));
        assert_eq!(isa.general_registers().len(), 31);
    }

    #[test]
    fn test_register_traits() {
        assert!(Register::XZR.is_zero_register());
        assert!(!Register::X0.is_zero_register());

        assert!(Register::SP.is_special());
        assert!(Register::XZR.is_special());
        assert!(!Register::X0.is_special());

        assert_eq!(
            <Register as RegisterType>::from_index(0),
            Some(Register::X0)
        );
        assert_eq!(
            <Register as RegisterType>::from_index(30),
            Some(Register::X30)
        );
        assert_eq!(
            <Register as RegisterType>::from_index(31),
            Some(Register::XZR)
        );
        assert_eq!(<Register as RegisterType>::from_index(32), None);
    }

    #[test]
    fn test_operand_traits() {
        let reg_op = <Operand as OperandType>::from_register(Register::X5);
        assert_eq!(reg_op.as_register(), Some(Register::X5));
        assert_eq!(reg_op.as_immediate(), None);
        assert!(reg_op.is_register());
        assert!(!reg_op.is_immediate());

        let imm_op = <Operand as OperandType>::from_immediate(42);
        assert_eq!(imm_op.as_register(), None);
        assert_eq!(imm_op.as_immediate(), Some(42));
        assert!(!imm_op.is_register());
        assert!(imm_op.is_immediate());

        let shifted_op = Operand::ShiftedRegister {
            reg: Register::X3,
            kind: crate::ir::ShiftKind::Lsl,
            amount: 4,
        };
        assert_eq!(shifted_op.as_register(), None);
        assert_eq!(shifted_op.as_immediate(), None);
        assert!(!shifted_op.is_register());
        assert!(!shifted_op.is_immediate());

        let extended_op = Operand::ExtendedRegister {
            reg: Register::X3,
            kind: crate::ir::ExtendKind::Uxtx,
            shift: 0,
        };
        assert_eq!(extended_op.as_register(), None);
        assert_eq!(extended_op.as_immediate(), None);
        assert!(!extended_op.is_register());
        assert!(!extended_op.is_immediate());
    }

    #[test]
    fn test_instruction_traits() {
        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };

        assert_eq!(add.destination(), Some(Register::X0));
        assert_eq!(add.source_registers(), vec![Register::X1, Register::X2]);
        assert_eq!(add.opcode_id(), 2);
        assert_eq!(add.mnemonic(), "add");
        assert!(!add.has_side_effects());

        let cmp = Instruction::Cmp {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        assert!(cmp.has_side_effects());
    }

    #[test]
    fn test_instruction_generator() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1];
        let imms = vec![0, 1];

        let instructions = generator.generate_all(&regs, &imms);
        assert!(!instructions.is_empty());

        // Verify we have MovReg instructions
        let has_mov_reg = instructions
            .iter()
            .any(|i| matches!(i, Instruction::MovReg { .. }));
        assert!(has_mov_reg);

        // Verify we have Add instructions
        let has_add = instructions
            .iter()
            .any(|i| matches!(i, Instruction::Add { .. }));
        assert!(has_add);
    }

    #[test]
    fn test_random_instruction_generation() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![-1, 0, 1, 2];

        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Generate several random instructions and verify they're valid
        for _ in 0..100 {
            let instr = generator.generate_random(&mut rng, &regs, &imms);
            // Just verify it doesn't panic and produces valid instructions
            assert!(instr.opcode_id() < generator.opcode_count());
        }
    }

    #[test]
    fn test_instruction_mutation() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![-1, 0, 1, 2];

        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let original = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };

        // Mutate several times and verify we get valid instructions
        for _ in 0..100 {
            let mutated = generator.mutate(&mut rng, &original, &regs, &imms);
            assert!(mutated.opcode_id() < generator.opcode_count());
        }
    }

    /// Issue #87. The file-private `mutate_operand` helper at L1514 must
    /// clamp `Operand::Immediate` values returned for ADD/SUB/ADDS/SUBS/
    /// CMP/CMN (12-bit) and CCMP/CCMN (5-bit) so the result is encodable.
    /// Hostile `imms` table deliberately includes values that would be
    /// rejected by `is_encodable_aarch64` if returned unclamped.
    #[test]
    fn test_mutate_operand_clamps_arith_imm_to_encodable_range() {
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms: Vec<i64> = vec![0, 1, 0xFFF, 0x1000, 8192, 0x1_0000, 1_000_000, -1];
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // (imm_max, host instruction builder used to wrap the resulting Operand
        // so we can call `is_encodable_aarch64` on a real Instruction).
        type ImmCase = (i64, Box<dyn Fn(Operand) -> Instruction>);
        let cases: Vec<ImmCase> = vec![
            (
                0xFFF,
                Box::new(|rm| Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm,
                }),
            ),
            (
                0xFFF,
                Box::new(|rm| Instruction::Sub {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm,
                }),
            ),
            (
                0xFFF,
                Box::new(|rm| Instruction::Adds {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm,
                }),
            ),
            (
                0xFFF,
                Box::new(|rm| Instruction::Subs {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm,
                }),
            ),
            (
                0xFFF,
                Box::new(|rm| Instruction::Cmp {
                    rn: Register::X1,
                    rm,
                }),
            ),
            (
                0xFFF,
                Box::new(|rm| Instruction::Cmn {
                    rn: Register::X1,
                    rm,
                }),
            ),
            (
                31,
                Box::new(|rm| Instruction::Ccmp {
                    rn: Register::X1,
                    rm,
                    nzcv: 0,
                    cond: Condition::EQ,
                }),
            ),
            (
                31,
                Box::new(|rm| Instruction::Ccmn {
                    rn: Register::X1,
                    rm,
                    nzcv: 0,
                    cond: Condition::EQ,
                }),
            ),
        ];

        for (imm_max, build) in &cases {
            for _ in 0..500 {
                let new_rm =
                    super::mutate_operand(&mut rng, Operand::Immediate(0), &regs, &imms, *imm_max);
                let instr = build(new_rm);
                assert!(
                    instr.is_encodable_aarch64(),
                    "imm_max={imm_max}, produced non-encodable {:?}",
                    instr
                );
            }
        }
    }

    #[test]
    fn all_instruction_families_cover_trait_methods() {
        let generator = AArch64InstructionGenerator;
        let seen: BTreeSet<u8> = all_instruction_families()
            .iter()
            .map(|instr| {
                let id = instr.opcode_id();
                assert!(id < generator.opcode_count());
                assert!(!instr.mnemonic().is_empty());
                assert!(!format!("{}", instr).is_empty());
                let _ = instr.destination();
                let _ = instr.source_registers();
                let should_update_flags = matches!(
                    instr,
                    Instruction::Cmp { .. }
                        | Instruction::Cmn { .. }
                        | Instruction::Tst { .. }
                        | Instruction::Negs { .. }
                        | Instruction::Bics { .. }
                        | Instruction::Adds { .. }
                        | Instruction::Subs { .. }
                        | Instruction::Ands { .. }
                        | Instruction::Ccmp { .. }
                        | Instruction::Ccmn { .. }
                );
                assert_eq!(instr.has_side_effects(), should_update_flags);
                id
            })
            .collect();
        assert_eq!(seen.len(), all_instruction_families().len());
        assert_eq!(seen.len(), generator.opcode_count() as usize);
    }

    #[test]
    fn generate_all_emits_encodable_w_bitfield() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1];
        let imms = vec![0, 1];
        let all = generator.generate_all(&regs, &imms);
        let w_bitfields: Vec<&Instruction> = all
            .iter()
            .filter(|i| {
                matches!(
                    i,
                    Instruction::Ubfx {
                        reg_width: RegisterWidth::W32,
                        ..
                    } | Instruction::Sbfx {
                        reg_width: RegisterWidth::W32,
                        ..
                    } | Instruction::Bfi {
                        reg_width: RegisterWidth::W32,
                        ..
                    } | Instruction::Bfxil {
                        reg_width: RegisterWidth::W32,
                        ..
                    } | Instruction::Ubfiz {
                        reg_width: RegisterWidth::W32,
                        ..
                    } | Instruction::Sbfiz {
                        reg_width: RegisterWidth::W32,
                        ..
                    }
                )
            })
            .collect();
        assert!(
            !w_bitfields.is_empty(),
            "trait generator must emit W-form bit-field instructions"
        );
        for instr in w_bitfields {
            assert!(
                instr.is_encodable_aarch64(),
                "trait generator produced un-encodable W bit-field: {instr}"
            );
        }
    }

    #[test]
    fn generate_all_covers_every_aarch64_family() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1];
        let imms = vec![0, 1];
        let ids: BTreeSet<u8> = generator
            .generate_all(&regs, &imms)
            .iter()
            .map(InstructionType::opcode_id)
            .collect();
        for required in [
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(1),
            },
            Instruction::Mul {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X0,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 1,
                shift: 16,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 1,
                shift: 16,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 1,
                shift: 16,
            },
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::EQ,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X0),
            },
            Instruction::Ccmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
                nzcv: 0,
                cond: Condition::EQ,
            },
            Instruction::Ccmn {
                rn: Register::X0,
                rm: Operand::Immediate(1),
                nzcv: 0,
                cond: Condition::EQ,
            },
            Instruction::Sxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sxth {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sxtw {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Uxth {
                rd: Register::X0,
                rn: Register::X1,
            },
        ] {
            assert!(ids.contains(&required.opcode_id()), "missing {}", required);
        }
    }

    #[test]
    fn random_generation_reaches_representative_families() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![0, 1, 2, 16, 32];
        // The fixed seed keeps this broad sampling check deterministic in CI.
        let mut rng = ChaCha8Rng::seed_from_u64(0xA64);
        let mut ids = BTreeSet::new();

        for _ in 0..5_000 {
            ids.insert(
                generator
                    .generate_random(&mut rng, &regs, &imms)
                    .opcode_id(),
            );
        }

        for instr in [
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sdiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 1,
                shift: 0,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 1,
                shift: 0,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 1,
                shift: 0,
            },
            Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::NE,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(1),
            },
        ] {
            assert!(
                ids.contains(&instr.opcode_id()),
                "random never made {}",
                instr
            );
        }
    }

    #[test]
    fn random_shift_immediates_never_sample_zero() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![0, 1, 2, 16, 32];
        let mut rng = ChaCha8Rng::seed_from_u64(0x263);
        let mut seen = BTreeSet::new();

        for _ in 0..50_000 {
            let instr = generator.generate_random(&mut rng, &regs, &imms);
            let sampled = match instr {
                Instruction::Lsl {
                    shift: Operand::Immediate(amount),
                    ..
                } => Some(("lsl", amount)),
                Instruction::Lsr {
                    shift: Operand::Immediate(amount),
                    ..
                } => Some(("lsr", amount)),
                Instruction::Asr {
                    shift: Operand::Immediate(amount),
                    ..
                } => Some(("asr", amount)),
                Instruction::Ror {
                    shift: Operand::Immediate(amount),
                    ..
                } => Some(("ror", amount)),
                _ => None,
            };

            if let Some((mnemonic, amount)) = sampled {
                assert_ne!(amount, 0, "random {mnemonic} sampled immediate shift #0");
                seen.insert(mnemonic);
            }
        }

        assert_eq!(seen, BTreeSet::from(["asr", "lsl", "lsr", "ror"]));
    }

    /// Termination guard for the CCMP/CCMN random-generator arm:
    /// before the slot-28 rewrite this test would have hung in release
    /// builds because `pick_non_sp` retried forever on a `[SP]`-only
    /// pool. The current code collects the non-SP registers up front
    /// and falls back to `Mneg` when the filter yields an empty slice,
    /// so every call must return a valid `Instruction` in finite time.
    /// Not asserting which opcode comes back — both slot 32 (the
    /// multiply-accumulate sub-multiplexer) and slot 33's fallback can
    /// emit Mneg, so any "did the conditional-compare slot fire?" proxy gives false
    /// confidence. The 10000 samples + bounded loop is the contract:
    /// completing the loop without panicking or hanging is the test.
    #[test]
    fn random_generator_handles_sp_only_register_pool() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::SP];
        let imms = vec![0, 1];
        let mut rng = ChaCha8Rng::seed_from_u64(0xA645);
        for _ in 0..10_000 {
            let instr = generator.generate_random(&mut rng, &regs, &imms);
            assert!(instr.opcode_id() < generator.opcode_count());
        }
    }

    #[test]
    fn aarch64_random_generation_promotes_single_source_bit_ops_to_top_level_slots() {
        use std::collections::HashMap;

        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![0, 1, 2, 16, 32];
        let mut rng = ChaCha8Rng::seed_from_u64(0x115);
        let mut counts: HashMap<u8, u32> = HashMap::new();
        const N: u32 = 30_000;

        for _ in 0..N {
            let id = generator
                .generate_random(&mut rng, &regs, &imms)
                .opcode_id();
            *counts.entry(id).or_default() += 1;
        }

        for (label, instr) in [
            (
                "Clz",
                Instruction::Clz {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Cls",
                Instruction::Cls {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Rbit",
                Instruction::Rbit {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Rev",
                Instruction::Rev {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Rev32",
                Instruction::Rev32 {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "Rev16",
                Instruction::Rev16 {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
        ] {
            let id = instr.opcode_id();
            let count = counts.get(&id).copied().unwrap_or(0);
            assert!(
                count >= 500,
                "expected >= 500 samples for {} (id {}) in {} draws, got {}",
                label,
                id,
                N,
                count
            );
        }
    }

    /// Regression test for issue #93: ANDS/CSET/CSETM/ROR used to share
    /// slot 23 via a 4-way sub-multiplexer, giving each ~1/152 vs ~1/38
    /// for singleton top-level slots. Each should now hold its own slot.
    /// With N = 30_000 ChaCha8-seeded draws each singleton-slot opcode is
    /// expected near 789 hits; the old sub-mux would give ~197. The lower
    /// threshold catches under-sampling, while the wide 3x upper bound catches
    /// accidental over-weighting without treating every opcode family as
    /// uniformly distributed.
    #[test]
    fn slot_23_sub_multiplexer_removed_for_issue_93() {
        use std::collections::BTreeMap;
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![0, 1, 2, 16, 32];
        let mut rng = ChaCha8Rng::seed_from_u64(0x9300);
        let mut counts: BTreeMap<u8, u32> = BTreeMap::new();
        const N: u32 = 30_000;
        const TOP_LEVEL_SLOT_COUNT: u32 = 38;
        const EXPECTED_TOP_LEVEL_COUNT: u32 = N / TOP_LEVEL_SLOT_COUNT;
        const MAX_REASONABLE_TOP_LEVEL_COUNT: u32 = 3 * N / TOP_LEVEL_SLOT_COUNT;
        for _ in 0..N {
            let id = generator
                .generate_random(&mut rng, &regs, &imms)
                .opcode_id();
            *counts.entry(id).or_default() += 1;
        }

        for (&id, &count) in &counts {
            assert!(
                count <= MAX_REASONABLE_TOP_LEVEL_COUNT,
                "expected opcode id {} to stay <= {} samples in {} draws; got {} (single top-level expected {}, {} slots)",
                id,
                MAX_REASONABLE_TOP_LEVEL_COUNT,
                N,
                count,
                EXPECTED_TOP_LEVEL_COUNT,
                TOP_LEVEL_SLOT_COUNT,
            );
        }

        for instr in [
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                width: RegisterWidth::X64,
            },
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::EQ,
            },
            Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::EQ,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(1),
            },
        ] {
            let id = instr.opcode_id();
            let count = counts.get(&id).copied().unwrap_or(0);
            assert!(
                count >= 600,
                "expected >= 600 samples for {} (id {}) in {} draws, got {}",
                instr,
                id,
                N,
                count,
            );
            assert!(
                count <= MAX_REASONABLE_TOP_LEVEL_COUNT,
                "expected <= {} samples for {} (id {}) in {} draws, got {} (single top-level expected {}, {} slots)",
                MAX_REASONABLE_TOP_LEVEL_COUNT,
                instr,
                id,
                N,
                count,
                EXPECTED_TOP_LEVEL_COUNT,
                TOP_LEVEL_SLOT_COUNT,
            );
        }
    }

    #[test]
    fn mutate_shift_operand_never_samples_zero_immediate() {
        let regs = vec![Register::X0, Register::X1, Register::X2];

        for (seed, operand) in [
            (0x2630, Operand::Immediate(1)),
            (0x2631, Operand::Register(Register::X1)),
        ] {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let mut saw_immediate = false;

            for _ in 0..2_000 {
                let mutated = super::mutate_shift_operand(&mut rng, operand, &regs);
                if let Operand::Immediate(amount) = mutated {
                    assert_ne!(amount, 0, "mutate_shift_operand sampled shift #0");
                    saw_immediate = true;
                }
            }

            assert!(
                saw_immediate,
                "mutate_shift_operand never returned an immediate"
            );
        }
    }

    #[test]
    fn mutation_exercises_every_aarch64_instruction_shape() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1, Register::X2, Register::X3];
        let imms = vec![0, 1, 7, 16, 32];
        let mut rng = ChaCha8Rng::seed_from_u64(0xA640);

        for original in all_instruction_families() {
            for _ in 0..200 {
                let mutated = generator.mutate(&mut rng, &original, &regs, &imms);
                assert!(mutated.opcode_id() < generator.opcode_count());
            }
        }
    }
}
