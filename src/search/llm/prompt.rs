//! Prompt construction for the Codex-assisted search loop.
//!
//! AArch64-only by design (ADR-0003, reaffirmed by ADR-0004 decision 3, and
//! restated by issue #77 stage 3 step 27): the prompt body names "AArch64
//! superoptimizer" and renders AArch64 registers; the response parser
//! delegates to `parser::parse_line` which only accepts AArch64 mnemonics.
//! The LLM flow stays AArch64-only across all stages of #77 — no
//! generification of this module is planned.

use crate::ir::{Instruction, Register};
use crate::semantics::live_out::RegisterSet;

/// Render a register set as a comma-separated list (e.g. "x0, x1, x2").
fn render_register_set(mask: &RegisterSet<Register>) -> String {
    let mut names: Vec<String> = (0..=30u8)
        .filter_map(Register::from_index)
        .filter(|r| mask.contains(*r))
        .map(|r| format!("{}", r).to_lowercase())
        .collect();
    if mask.contains(Register::SP) {
        names.push("sp".to_string());
    }
    names.join(", ")
}

/// Build the full prompt sent to `codex exec`.
pub fn build_prompt(
    target: &[Instruction],
    live_in: &RegisterSet<Register>,
    live_out: &RegisterSet<Register>,
) -> String {
    let mut s = String::new();
    s.push_str(
        "You are an AArch64 superoptimizer. Given a short instruction sequence, return a \
SHORTER (fewer instructions) sequence that produces the same values for the listed \
live-out registers, given the listed live-in registers as inputs. Registers not in \
the live-out set may be clobbered freely. If you cannot find a strictly shorter \
equivalent, return an empty `assembly` field — do NOT return the input verbatim.\n\n",
    );
    s.push_str(&format!(
        "Live-in registers: {}\n",
        render_register_set(live_in)
    ));
    s.push_str(&format!(
        "Live-out registers: {}\n",
        render_register_set(live_out)
    ));
    s.push_str("\nTarget:\n");
    for instr in target {
        s.push_str(&format!("{}\n", instr));
    }
    s
}

/// JSON schema enforced via `codex exec --output-schema`.
pub const OUTPUT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "assembly": {
      "type": "string",
      "description": "AArch64 assembly, GNU syntax, one instruction per line."
    }
  },
  "required": ["assembly"],
  "additionalProperties": false
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};

    fn mask(regs: &[Register]) -> RegisterSet<Register> {
        let mut m = RegisterSet::empty();
        for r in regs {
            m.add(*r);
        }
        m
    }

    #[test]
    fn prompt_includes_live_in_live_out_and_target() {
        let target = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        let live_in = mask(&[Register::X1]);
        let live_out = mask(&[Register::X0]);
        let prompt = build_prompt(&target, &live_in, &live_out);
        assert!(prompt.contains("Live-in registers: x1"));
        assert!(prompt.contains("Live-out registers: x0"));
        assert!(prompt.contains("mov x0, x1"));
        assert!(prompt.contains("add x0, x0, #1"));
    }
}
