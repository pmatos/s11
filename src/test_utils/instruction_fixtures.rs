use crate::ir::{
    Condition, Instruction, Operand, Register, RegisterWidth, VectorArrangement, VectorRegister,
};
use crate::isa::{RiscVInstruction, RiscVRegister};

/// One representative and its expected contracts for every opcode family
/// emitted by `AArch64InstructionGenerator`.
pub(crate) struct AArch64InstructionFamily {
    pub(crate) instruction: Instruction,
    pub(crate) opcode_id: u8,
    pub(crate) mnemonic: &'static str,
    pub(crate) display: &'static str,
    pub(crate) destination: Option<Register>,
    pub(crate) sources: &'static [Register],
    pub(crate) has_side_effects: bool,
    pub(crate) modifies_flags: bool,
    pub(crate) reads_flags: bool,
}

/// Canonical AArch64 family fixtures shared by IR, ISA, assembler, search,
/// and cost-model tests.
pub(crate) fn aarch64_instruction_families() -> Vec<AArch64InstructionFamily> {
    use Register::{X0, X1, X2, X3};

    macro_rules! family {
        (
            $instruction:expr,
            $opcode_id:expr,
            $mnemonic:literal,
            $display:literal,
            $destination:expr,
            $sources:expr,
            $has_side_effects:expr,
            $modifies_flags:expr,
            $reads_flags:expr
        ) => {
            AArch64InstructionFamily {
                instruction: $instruction,
                opcode_id: $opcode_id,
                mnemonic: $mnemonic,
                display: $display,
                destination: $destination,
                sources: $sources,
                has_side_effects: $has_side_effects,
                modifies_flags: $modifies_flags,
                reads_flags: $reads_flags,
            }
        };
    }

    vec![
        family!(
            Instruction::MovReg { rd: X0, rn: X1 },
            0,
            "mov",
            "mov x0, x1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::MovImm { rd: X0, imm: 7 },
            1,
            "mov",
            "mov x0, #7",
            Some(X0),
            &[],
            false,
            false,
            false
        ),
        family!(
            Instruction::Add {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
            },
            2,
            "add",
            "add x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Sub {
                rd: X0,
                rn: X1,
                rm: Operand::Immediate(3),
            },
            3,
            "sub",
            "sub x0, x1, #3",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::And {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
                width: RegisterWidth::X64,
            },
            4,
            "and",
            "and x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Orr {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
                width: RegisterWidth::X64,
            },
            5,
            "orr",
            "orr x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Eor {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
                width: RegisterWidth::X64,
            },
            6,
            "eor",
            "eor x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Lsl {
                rd: X0,
                rn: X1,
                shift: Operand::Register(X2),
            },
            7,
            "lsl",
            "lsl x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Lsr {
                rd: X0,
                rn: X1,
                shift: Operand::Immediate(4),
            },
            8,
            "lsr",
            "lsr x0, x1, #4",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Asr {
                rd: X0,
                rn: X1,
                shift: Operand::Register(X2),
            },
            9,
            "asr",
            "asr x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Mul {
                rd: X0,
                rn: X1,
                rm: X2,
            },
            10,
            "mul",
            "mul x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Sdiv {
                rd: X0,
                rn: X1,
                rm: X2,
            },
            11,
            "sdiv",
            "sdiv x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Udiv {
                rd: X0,
                rn: X1,
                rm: X2,
            },
            12,
            "udiv",
            "udiv x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Cmp {
                rn: X1,
                rm: Operand::Register(X2),
            },
            13,
            "cmp",
            "cmp x1, x2",
            None,
            &[X1, X2],
            true,
            true,
            false
        ),
        family!(
            Instruction::Cmn {
                rn: X1,
                rm: Operand::Immediate(9),
            },
            14,
            "cmn",
            "cmn x1, #9",
            None,
            &[X1],
            true,
            true,
            false
        ),
        family!(
            Instruction::Tst {
                rn: X1,
                rm: Operand::Register(X2),
                width: RegisterWidth::X64,
            },
            15,
            "tst",
            "tst x1, x2",
            None,
            &[X1, X2],
            true,
            true,
            false
        ),
        family!(
            Instruction::Csel {
                rd: X0,
                rn: X1,
                rm: X2,
                cond: Condition::EQ,
            },
            16,
            "csel",
            "csel x0, x1, x2, eq",
            Some(X0),
            &[X1, X2],
            false,
            false,
            true
        ),
        family!(
            Instruction::Csinc {
                rd: X0,
                rn: X1,
                rm: X2,
                cond: Condition::NE,
            },
            17,
            "csinc",
            "csinc x0, x1, x2, ne",
            Some(X0),
            &[X1, X2],
            false,
            false,
            true
        ),
        family!(
            Instruction::Csinv {
                rd: X0,
                rn: X1,
                rm: X2,
                cond: Condition::LT,
            },
            18,
            "csinv",
            "csinv x0, x1, x2, lt",
            Some(X0),
            &[X1, X2],
            false,
            false,
            true
        ),
        family!(
            Instruction::Csneg {
                rd: X0,
                rn: X1,
                rm: X2,
                cond: Condition::GT,
            },
            19,
            "csneg",
            "csneg x0, x1, x2, gt",
            Some(X0),
            &[X1, X2],
            false,
            false,
            true
        ),
        family!(
            Instruction::Mvn { rd: X0, rm: X1 },
            20,
            "mvn",
            "mvn x0, x1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Neg { rd: X0, rm: X1 },
            21,
            "neg",
            "neg x0, x1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Negs { rd: X0, rm: X1 },
            22,
            "negs",
            "negs x0, x1",
            Some(X0),
            &[X1],
            true,
            true,
            false
        ),
        family!(
            Instruction::MovN {
                rd: X0,
                imm: 0x55aa,
                shift: 16,
            },
            23,
            "movn",
            "movn x0, #21930, lsl #16",
            Some(X0),
            &[],
            false,
            false,
            false
        ),
        family!(
            Instruction::MovZ {
                rd: X0,
                imm: 0x55aa,
                shift: 32,
            },
            34,
            "movz",
            "movz x0, #21930, lsl #32",
            Some(X0),
            &[],
            false,
            false,
            false
        ),
        family!(
            Instruction::MovK {
                rd: X0,
                imm: 0x55aa,
                shift: 48,
            },
            35,
            "movk",
            "movk x0, #21930, lsl #48",
            Some(X0),
            &[X0],
            false,
            false,
            false
        ),
        family!(
            Instruction::Bic {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
            },
            24,
            "bic",
            "bic x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Bics {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
            },
            25,
            "bics",
            "bics x0, x1, x2",
            Some(X0),
            &[X1, X2],
            true,
            true,
            false
        ),
        family!(
            Instruction::Orn {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
            },
            26,
            "orn",
            "orn x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Eon {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
            },
            27,
            "eon",
            "eon x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Adds {
                rd: X0,
                rn: X1,
                rm: Operand::Immediate(1),
            },
            28,
            "adds",
            "adds x0, x1, #1",
            Some(X0),
            &[X1],
            true,
            true,
            false
        ),
        family!(
            Instruction::Subs {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
            },
            29,
            "subs",
            "subs x0, x1, x2",
            Some(X0),
            &[X1, X2],
            true,
            true,
            false
        ),
        family!(
            Instruction::Ands {
                rd: X0,
                rn: X1,
                rm: Operand::Register(X2),
                width: RegisterWidth::X64,
            },
            30,
            "ands",
            "ands x0, x1, x2",
            Some(X0),
            &[X1, X2],
            true,
            true,
            false
        ),
        family!(
            Instruction::Cset {
                rd: X0,
                cond: Condition::GE,
            },
            31,
            "cset",
            "cset x0, ge",
            Some(X0),
            &[],
            false,
            false,
            true
        ),
        family!(
            Instruction::Csetm {
                rd: X0,
                cond: Condition::LE,
            },
            32,
            "csetm",
            "csetm x0, le",
            Some(X0),
            &[],
            false,
            false,
            true
        ),
        family!(
            Instruction::Ror {
                rd: X0,
                rn: X1,
                shift: Operand::Immediate(8),
            },
            33,
            "ror",
            "ror x0, x1, #8",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Clz { rd: X0, rn: X1 },
            36,
            "clz",
            "clz x0, x1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Cls { rd: X0, rn: X1 },
            37,
            "cls",
            "cls x0, x1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Rbit { rd: X0, rn: X1 },
            38,
            "rbit",
            "rbit x0, x1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Rev { rd: X0, rn: X1 },
            39,
            "rev",
            "rev x0, x1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Rev32 { rd: X0, rn: X1 },
            40,
            "rev32",
            "rev32 x0, x1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Rev16 { rd: X0, rn: X1 },
            41,
            "rev16",
            "rev16 x0, x1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Madd {
                rd: X0,
                rn: X1,
                rm: X2,
                ra: X3,
            },
            42,
            "madd",
            "madd x0, x1, x2, x3",
            Some(X0),
            &[X1, X2, X3],
            false,
            false,
            false
        ),
        family!(
            Instruction::Msub {
                rd: X0,
                rn: X1,
                rm: X2,
                ra: X3,
            },
            43,
            "msub",
            "msub x0, x1, x2, x3",
            Some(X0),
            &[X1, X2, X3],
            false,
            false,
            false
        ),
        family!(
            Instruction::Mneg {
                rd: X0,
                rn: X1,
                rm: X2,
            },
            44,
            "mneg",
            "mneg x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Smulh {
                rd: X0,
                rn: X1,
                rm: X2,
            },
            45,
            "smulh",
            "smulh x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Umulh {
                rd: X0,
                rn: X1,
                rm: X2,
            },
            46,
            "umulh",
            "umulh x0, x1, x2",
            Some(X0),
            &[X1, X2],
            false,
            false,
            false
        ),
        family!(
            Instruction::Ccmp {
                rn: X1,
                rm: Operand::Register(X2),
                nzcv: 0,
                cond: Condition::EQ,
            },
            47,
            "ccmp",
            "ccmp x1, x2, #0, eq",
            None,
            &[X1, X2],
            true,
            true,
            true
        ),
        family!(
            Instruction::Ccmn {
                rn: X1,
                rm: Operand::Immediate(5),
                nzcv: 0,
                cond: Condition::EQ,
            },
            48,
            "ccmn",
            "ccmn x1, #5, #0, eq",
            None,
            &[X1],
            true,
            true,
            true
        ),
        family!(
            Instruction::Sxtb { rd: X0, rn: X1 },
            49,
            "sxtb",
            "sxtb x0, w1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Sxth { rd: X0, rn: X1 },
            50,
            "sxth",
            "sxth x0, w1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Sxtw { rd: X0, rn: X1 },
            51,
            "sxtw",
            "sxtw x0, w1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Uxtb { rd: X0, rn: X1 },
            52,
            "uxtb",
            "uxtb w0, w1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Uxth { rd: X0, rn: X1 },
            53,
            "uxth",
            "uxth w0, w1",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Ubfx {
                rd: X0,
                rn: X1,
                lsb: 8,
                width: 16,
                reg_width: RegisterWidth::X64,
            },
            54,
            "ubfx",
            "ubfx x0, x1, #8, #16",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Sbfx {
                rd: X0,
                rn: X1,
                lsb: 8,
                width: 16,
                reg_width: RegisterWidth::X64,
            },
            55,
            "sbfx",
            "sbfx x0, x1, #8, #16",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Bfi {
                rd: X0,
                rn: X1,
                lsb: 4,
                width: 8,
                reg_width: RegisterWidth::X64,
            },
            56,
            "bfi",
            "bfi x0, x1, #4, #8",
            Some(X0),
            &[X0, X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Bfxil {
                rd: X0,
                rn: X1,
                lsb: 4,
                width: 8,
                reg_width: RegisterWidth::X64,
            },
            57,
            "bfxil",
            "bfxil x0, x1, #4, #8",
            Some(X0),
            &[X0, X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Ubfiz {
                rd: X0,
                rn: X1,
                lsb: 4,
                width: 8,
                reg_width: RegisterWidth::X64,
            },
            58,
            "ubfiz",
            "ubfiz x0, x1, #4, #8",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Sbfiz {
                rd: X0,
                rn: X1,
                lsb: 4,
                width: 8,
                reg_width: RegisterWidth::X64,
            },
            59,
            "sbfiz",
            "sbfiz x0, x1, #4, #8",
            Some(X0),
            &[X1],
            false,
            false,
            false
        ),
        family!(
            Instruction::Movi {
                vd: VectorRegister::V0,
                arrangement: VectorArrangement::TwoD,
                imm: 0,
            },
            60,
            "movi",
            "movi v0.2d, #0",
            Some(Register::Vector(VectorRegister::V0)),
            &[],
            false,
            false,
            false
        ),
        family!(
            Instruction::VectorAdd {
                vd: VectorRegister::V0,
                vn: VectorRegister::V1,
                vm: VectorRegister::V2,
                arrangement: VectorArrangement::FourS,
            },
            61,
            "add",
            "add v0.4s, v1.4s, v2.4s",
            Some(Register::Vector(VectorRegister::V0)),
            &[
                Register::Vector(VectorRegister::V1),
                Register::Vector(VectorRegister::V2)
            ],
            false,
            false,
            false
        ),
        family!(
            Instruction::MovFromVectorLane {
                rd: X0,
                vn: VectorRegister::V1,
                lane: 1,
            },
            62,
            "mov",
            "mov x0, v1.d[1]",
            Some(X0),
            &[Register::Vector(VectorRegister::V1)],
            false,
            false,
            false
        ),
    ]
}

/// One representative and its expected contracts for every RISC-V scaffold
/// opcode family.
pub(crate) struct RiscVInstructionFamily {
    pub(crate) instruction: RiscVInstruction,
    pub(crate) opcode_id: u8,
    pub(crate) mnemonic: &'static str,
    pub(crate) display: &'static str,
    pub(crate) destination: Option<RiscVRegister>,
    pub(crate) sources: &'static [RiscVRegister],
    pub(crate) has_side_effects: bool,
}

/// Canonical RISC-V family fixtures shared by trait and mutation tests.
pub(crate) fn riscv_instruction_families() -> Vec<RiscVInstructionFamily> {
    use RiscVInstruction::*;
    use RiscVRegister::{X1, X2, X3};

    macro_rules! family {
        (
            $instruction:expr,
            $opcode_id:expr,
            $mnemonic:literal,
            $display:literal,
            $sources:expr
        ) => {
            RiscVInstructionFamily {
                instruction: $instruction,
                opcode_id: $opcode_id,
                mnemonic: $mnemonic,
                display: $display,
                destination: Some(X1),
                sources: $sources,
                has_side_effects: false,
            }
        };
    }

    vec![
        family!(
            Add {
                rd: X1,
                rs1: X2,
                rs2: X3,
            },
            0,
            "add",
            "add x1, x2, x3",
            &[X2, X3]
        ),
        family!(
            Sub {
                rd: X1,
                rs1: X2,
                rs2: X3,
            },
            1,
            "sub",
            "sub x1, x2, x3",
            &[X2, X3]
        ),
        family!(
            And {
                rd: X1,
                rs1: X2,
                rs2: X3,
            },
            2,
            "and",
            "and x1, x2, x3",
            &[X2, X3]
        ),
        family!(
            Or {
                rd: X1,
                rs1: X2,
                rs2: X3,
            },
            3,
            "or",
            "or x1, x2, x3",
            &[X2, X3]
        ),
        family!(
            Xor {
                rd: X1,
                rs1: X2,
                rs2: X3,
            },
            4,
            "xor",
            "xor x1, x2, x3",
            &[X2, X3]
        ),
        family!(
            Sll {
                rd: X1,
                rs1: X2,
                rs2: X3,
            },
            5,
            "sll",
            "sll x1, x2, x3",
            &[X2, X3]
        ),
        family!(
            Srl {
                rd: X1,
                rs1: X2,
                rs2: X3,
            },
            6,
            "srl",
            "srl x1, x2, x3",
            &[X2, X3]
        ),
        family!(
            Sra {
                rd: X1,
                rs1: X2,
                rs2: X3,
            },
            7,
            "sra",
            "sra x1, x2, x3",
            &[X2, X3]
        ),
        family!(
            Addi {
                rd: X1,
                rs1: X2,
                imm: 7,
            },
            8,
            "addi",
            "addi x1, x2, 7",
            &[X2]
        ),
        family!(
            Andi {
                rd: X1,
                rs1: X2,
                imm: 7,
            },
            9,
            "andi",
            "andi x1, x2, 7",
            &[X2]
        ),
        family!(
            Ori {
                rd: X1,
                rs1: X2,
                imm: 7,
            },
            10,
            "ori",
            "ori x1, x2, 7",
            &[X2]
        ),
        family!(
            Xori {
                rd: X1,
                rs1: X2,
                imm: 7,
            },
            11,
            "xori",
            "xori x1, x2, 7",
            &[X2]
        ),
        family!(
            Slli {
                rd: X1,
                rs1: X2,
                shamt: 4,
            },
            12,
            "slli",
            "slli x1, x2, 4",
            &[X2]
        ),
        family!(
            Srli {
                rd: X1,
                rs1: X2,
                shamt: 4,
            },
            13,
            "srli",
            "srli x1, x2, 4",
            &[X2]
        ),
        family!(
            Srai {
                rd: X1,
                rs1: X2,
                shamt: 4,
            },
            14,
            "srai",
            "srai x1, x2, 4",
            &[X2]
        ),
        family!(
            Lui {
                rd: X1,
                imm: 0x12345,
            },
            15,
            "lui",
            "lui x1, 74565",
            &[]
        ),
    ]
}
