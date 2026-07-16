//! Checked-in documentation support data.
//!
//! These constants are intentionally data-only. They let docs tests compare
//! public capability prose with the mnemonic set covered by the parser and the
//! Capstone conversion tripwire.

pub const AARCH64_REWRITABLE_MNEMONICS: &[&str] = &[
    "mov", "mvn", "neg", "negs", "movn", "movz", "movk", "add", "sub", "adds", "subs", "adc",
    "adcs", "sbc", "sbcs", "and", "ands", "orr", "eor", "bic", "bics", "orn", "eon", "lsl", "lsr",
    "asr", "ror", "mul", "madd", "msub", "mneg", "smulh", "umulh", "sdiv", "udiv", "cmp", "cmn",
    "tst", "ccmp", "ccmn", "csel", "csinc", "csinv", "csneg", "cset", "csetm", "clz", "cls",
    "rbit", "rev", "rev32", "rev16", "uxtb", "uxth", "sxtb", "sxth", "sxtw", "ubfx", "sbfx", "bfi",
    "bfxil", "ubfiz", "sbfiz", "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "str", "strb",
    "strh", "ldp", "stp", "ldpsw",
];

pub const AARCH64_FIXED_TERMINATORS: &[&str] = &[
    "b", "b.<cond>", "bl", "br", "ret", "cbz", "cbnz", "tbz", "tbnz",
];

pub const X86_REWRITABLE_MNEMONICS: &[&str] = &[
    "mov",
    "movzx",
    "movsx",
    "add",
    "sub",
    "and",
    "or",
    "xor",
    "cmp",
    "cmov<cond>",
];

/// Full-width text-IR families available to search but not liftable from
/// architectural machine code.
pub const X86_SYNTHESIZABLE_ONLY_MNEMONICS: &[&str] = &["set<cond>"];

pub const X86_FIXED_TERMINATORS: &[&str] = &["j<cond>"];
