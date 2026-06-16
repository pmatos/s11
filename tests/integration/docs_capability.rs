use std::fs;
use std::path::{Path, PathBuf};

use s11::docs_support::{
    AARCH64_FIXED_TERMINATORS, AARCH64_REWRITABLE_MNEMONICS, X86_SUPPORTED_MNEMONICS,
};

fn repo_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_doc(relative: &str) -> String {
    fs::read_to_string(repo_file(relative))
        .unwrap_or_else(|err| panic!("failed to read {relative}: {err}"))
}

fn normalized_doc(relative: &str) -> String {
    read_doc(relative)
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn docs_capability_matrix_exists_and_public_docs_link_it() {
    let matrix = read_doc("docs/capability.md");
    for heading in ["## AArch64", "## x86-64 / x86-32", "## RISC-V"] {
        assert!(
            matrix.contains(heading),
            "docs/capability.md is missing heading {heading}"
        );
    }

    for doc in ["README.md", "CONTEXT.md", "TUTORIAL.md", "CLAUDE.md"] {
        let body = read_doc(doc);
        assert!(
            body.contains("docs/capability.md"),
            "{doc} must link to docs/capability.md"
        );
    }
}

#[test]
fn docs_capability_lists_every_checked_in_aarch64_mnemonic() {
    let matrix = read_doc("docs/capability.md").to_ascii_lowercase();

    for mnemonic in AARCH64_REWRITABLE_MNEMONICS {
        assert!(
            matrix.contains(&format!("`{mnemonic}`")),
            "docs/capability.md must list rewritable AArch64 mnemonic `{mnemonic}`"
        );
    }

    for mnemonic in AARCH64_FIXED_TERMINATORS {
        assert!(
            matrix.contains(&format!("`{mnemonic}`")),
            "docs/capability.md must list fixed AArch64 terminator `{mnemonic}`"
        );
    }
}

#[test]
fn docs_capability_documents_w_logical_immediates() {
    let matrix = normalized_doc("docs/capability.md");
    assert!(
        matrix.contains(
            "logical-immediate forms for `and`, `ands`, `orr`, `eor`, and `tst` support both 64-bit `x` registers and 32-bit `w` registers"
        ),
        "docs/capability.md must document W-register logical-immediate support"
    );
    assert!(
        matrix.contains(
            "capstone `mov wd|wsp, #imm` bitmask aliases are accepted for the `orr wd|wsp, wzr, #imm` form"
        ),
        "docs/capability.md must document Capstone MOV aliases for W logical-immediate ORR"
    );
}

#[test]
fn docs_capability_documents_w_mov_add_sub_forms() {
    let matrix = normalized_doc("docs/capability.md");
    assert!(
        matrix.contains("register `mov` supports both 64-bit `x` and 32-bit `w` forms"),
        "docs/capability.md must document W-register MOV register support"
    );
    assert!(
        matrix.contains(
            "non-flag-setting `add` and `sub` support both 64-bit `x` and 32-bit `w` register/immediate/shifted-register forms"
        ),
        "docs/capability.md must document W-register ADD/SUB support"
    );
}

#[test]
fn enumerative_candidate_growth_visible_in_public_docs() {
    for doc in ["README.md", "TUTORIAL.md", "docs/capability.md"] {
        let body = normalized_doc(doc);
        assert!(
            body.contains("enumerative search scales with the generated instruction families"),
            "{doc} must document enumerative candidate-pool growth"
        );
        assert!(
            body.contains("candidate pool") && body.contains("length bucket"),
            "{doc} must use candidate-pool and length-bucket wording"
        );
    }

    let matrix = read_doc("docs/capability.md");
    assert!(
        matrix.contains("9,728") && matrix.contains("8^4") && matrix.contains("8^3"),
        "docs/capability.md must keep the default AArch64 multiply-candidate budget visible"
    );
}

#[test]
fn memory_operations_are_consistently_documented_with_known_gaps() {
    let matrix = normalized_doc("docs/capability.md");
    assert!(
        matrix.contains("memory loads and stores"),
        "docs/capability.md must document supported memory loads and stores"
    );
    assert!(
        matrix.contains("`ldur`, `stur`, and `ldr (literal)` are out of scope"),
        "docs/capability.md must document unsupported memory-operation gaps"
    );

    let tutorial = normalized_doc("TUTORIAL.md");
    assert!(
        tutorial.contains("load/store family added in adr-0007"),
        "TUTORIAL.md supported-instructions section must point to the load/store family"
    );
    assert!(
        tutorial.contains("`ldur`, `stur`, and `ldr (literal)` remain unsupported"),
        "TUTORIAL.md known-limitations section must keep unsupported memory gaps visible"
    );

    for mnemonic in ["ldr", "str"] {
        assert!(
            AARCH64_REWRITABLE_MNEMONICS.contains(&mnemonic),
            "`{mnemonic}` must be listed as a rewritable AArch64 mnemonic"
        );

        let line = format!("{mnemonic} x0, [x1]");
        assert!(
            matches!(
                s11::parser::parse_line(&line),
                Ok(s11::parser::LineResult::Instruction(_))
            ),
            "parser must accept supported memory instruction `{line}`"
        );
    }

    for mnemonic in ["ldur", "stur"] {
        assert!(
            !AARCH64_REWRITABLE_MNEMONICS.contains(&mnemonic),
            "`{mnemonic}` must not be listed as a rewritable AArch64 mnemonic"
        );

        let line = format!("{mnemonic} x0, [x1]");
        assert!(
            matches!(
                s11::parser::parse_line(&line),
                Err(s11::parser::ParseLineError::UnknownInstruction(ref unsupported))
                    if unsupported == mnemonic
            ),
            "parser must reject unsupported memory instruction `{line}`"
        );
    }

    assert!(
        s11::parser::parse_line("ldr x0, #0x1234").is_err(),
        "parser must reject out-of-scope LDR literal form"
    );
}

#[test]
fn stale_aarch64_count_and_branch_unsupported_claims_are_removed() {
    let mut docs = vec![
        "README.md".to_string(),
        "CONTEXT.md".to_string(),
        "TUTORIAL.md".to_string(),
        "CLAUDE.md".to_string(),
        "docs/adr/0002-mvp-restricts-flags-live-out.md".to_string(),
        "docs/adr/0003-llm-prompt-no-subset-hint.md".to_string(),
    ];

    for entry in fs::read_dir(repo_file("docs/adr")).expect("failed to read docs/adr") {
        let path = entry.expect("failed to read docs/adr entry").path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
            let relative = path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .expect("ADR path should be inside repo")
                .to_string_lossy()
                .trim_start_matches('/')
                .to_string();
            if !docs.contains(&relative) {
                docs.push(relative);
            }
        }
    }

    for doc in docs {
        let body = read_doc(&doc);
        for stale in [
            "20-opcode",
            "20 AArch64",
            "Branch instructions are not supported",
        ] {
            assert!(
                !body.contains(stale),
                "{doc} still contains stale claim `{stale}`"
            );
        }
    }
}

#[test]
fn x86_support_is_visible_in_public_docs() {
    let matrix = read_doc("docs/capability.md").to_ascii_lowercase();
    assert!(
        matrix.contains("trait-backed"),
        "docs/capability.md must describe x86 as using the shared trait-backed path"
    );
    assert!(
        !matrix.contains("parallel x86 pipeline"),
        "docs/capability.md must not describe x86 as a parallel pipeline"
    );
    for mnemonic in X86_SUPPORTED_MNEMONICS {
        assert!(
            matrix.contains(&format!("`{mnemonic}`")),
            "docs/capability.md must list x86 mnemonic `{mnemonic}`"
        );
    }

    for family in ["cmov<cond>", "j<cond>"] {
        assert!(
            matrix.contains(&format!("`{family}`")),
            "docs/capability.md must list x86 family `{family}`"
        );
    }
    assert!(
        matrix.contains("rewritable") && matrix.contains("`cmov<cond>`"),
        "docs/capability.md must describe CMOVcc as rewritable"
    );
    assert!(
        matrix.contains("fixed") && matrix.contains("terminator") && matrix.contains("`j<cond>`"),
        "docs/capability.md must describe Jcc as a fixed terminator"
    );

    for doc in [
        "README.md",
        "TUTORIAL.md",
        "CLAUDE.md",
        "docs/capability.md",
    ] {
        let body = read_doc(doc).to_ascii_lowercase();
        assert!(body.contains("x86-64"), "{doc} must mention x86-64");
        assert!(body.contains("x86-32"), "{doc} must mention x86-32");
        assert!(
            body.contains("hybrid") && body.contains("llm") && body.contains("aarch64-only"),
            "{doc} must say hybrid/LLM remain AArch64-only"
        );
    }
}

#[test]
fn riscv_status_says_scaffold_only_no_opt_path_and_no_machine_code_emission() {
    for doc in [
        "README.md",
        "CLAUDE.md",
        "docs/capability.md",
        "docs/adr/0005-riscv-assembler-strategy.md",
    ] {
        let body = read_doc(doc).to_ascii_lowercase();
        assert!(
            body.contains("scaffold-only"),
            "{doc} must say scaffold-only"
        );
        assert!(
            body.contains("machine-code emission is not yet implemented")
                || body.contains("no machine-code emission"),
            "{doc} must say RISC-V has no machine-code emission"
        );
        assert!(
            body.contains("no supported risc-v opt path")
                || body.contains("risc-v optimization is not yet supported"),
            "{doc} must say there is no supported RISC-V opt path"
        );
    }

    let readme = read_doc("README.md");
    assert!(
        !readme.contains("RISC-V (rv32 / rv64) backend behind the same ISA trait"),
        "README.md must not imply RISC-V is a working peer backend"
    );
}

#[test]
fn capability_matrix_links_resolve() {
    for doc in [
        "README.md",
        "CONTEXT.md",
        "TUTORIAL.md",
        "CLAUDE.md",
        "docs/adr/0005-riscv-assembler-strategy.md",
    ] {
        let body = read_doc(doc);
        let targets: Vec<&str> = body
            .split("](")
            .skip(1)
            .filter_map(|suffix| suffix.split(')').next())
            .filter(|target| target.contains("capability.md"))
            .collect();

        assert!(
            !targets.is_empty(),
            "{doc} must link to the capability matrix"
        );

        let base = repo_file(doc)
            .parent()
            .expect("document should have a parent directory")
            .to_path_buf();
        for target in targets {
            let target = target.split('#').next().unwrap_or(target);
            let resolved = base.join(target);
            assert!(
                resolved.exists(),
                "{doc} has unresolved capability matrix link {target}"
            );
        }
    }
}
