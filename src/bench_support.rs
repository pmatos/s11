//! Shared harness for the criterion benchmark suite (issue #70).
//!
//! Each bench file under `benches/` brings these helpers in via
//! `use s11::bench_support::*;`. The module lives in the library —
//! not under `benches/common/` — because `harness = false` benchmarks
//! cannot run `#[test]` blocks; we need a regular lib-test path to
//! exercise the helpers under TDD.

use crate::ir::Instruction;
use crate::parser::{LineResult, parse_line};
use crate::semantics::live_out::LiveOut;
use crate::validation::live_out::parse_live_out_contract;
use std::path::Path;

/// Parse a benchmark `.s` fixture into its target sequence plus the
/// live-out contract declared in its `// Live-out:` header.
///
/// Header grammar matches `validation::live_out::parse_live_out_contract`
/// — e.g. `// Live-out: x0,x1;nzcv`. Comments starting with `//` are
/// stripped by `parse_line`; every non-comment line is parsed as
/// AArch64 assembly.
///
/// Panics if no `// Live-out:` header is found — bench fixtures are
/// author-controlled, so a missing header is a fixture defect.
pub fn load_sequence(path: &Path) -> (Vec<Instruction>, LiveOut, bool) {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));

    let live_spec = source
        .lines()
        .find_map(|line| {
            let trimmed = line.trim_start();
            let body = trimmed.strip_prefix("//")?.trim_start();
            body.strip_prefix("Live-out:").map(str::trim)
        })
        .unwrap_or_else(|| {
            panic!(
                "fixture {} missing required `// Live-out:` header — see benches/README.md",
                path.display()
            )
        });

    let (live_out, flags_live) = parse_live_out_contract(live_spec).unwrap_or_else(|e| {
        panic!(
            "fixture {}: malformed live-out contract {live_spec:?}: {e:?}",
            path.display()
        )
    });

    let mut sequence = Vec::new();
    for line in source.lines() {
        match parse_line(line) {
            Ok(LineResult::Instruction(instr)) => sequence.push(instr),
            Ok(LineResult::Skip) => {}
            Err(e) => panic!(
                "fixture {}: parse error on line {line:?}: {e:?}",
                path.display()
            ),
        }
    }

    (sequence, live_out, flags_live)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_fixture(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .prefix("bench-fixture")
            .suffix(".s")
            .tempfile()
            .expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    #[test]
    fn load_sequence_parses_header_and_body() {
        let f = write_fixture(
            "// Live-out: x0\n\
             // commentary\n\
             mov x0, x1\n\
             add x0, x0, #1\n",
        );
        let (seq, live_out, flags_live) = load_sequence(f.path());
        assert_eq!(seq.len(), 2, "expected MOV + ADD");
        assert!(
            live_out.contains_register(crate::ir::Register::X0),
            "live-out must include X0"
        );
        assert!(!flags_live, "header without ;nzcv should be flags-dead");
    }

    #[test]
    fn load_sequence_picks_up_flags_live() {
        let f = write_fixture("// Live-out: x0;nzcv\nmov x0, #1\n");
        let (_, _, flags_live) = load_sequence(f.path());
        assert!(flags_live, "header with ;nzcv must report flags_live=true");
    }

    #[test]
    #[should_panic(expected = "missing required `// Live-out:` header")]
    fn load_sequence_panics_without_header() {
        let f = write_fixture("mov x0, #0\n");
        let _ = load_sequence(f.path());
    }
}
