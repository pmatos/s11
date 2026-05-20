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
    for mnemonic in X86_SUPPORTED_MNEMONICS {
        assert!(
            matrix.contains(&format!("`{mnemonic}`")),
            "docs/capability.md must list x86 mnemonic `{mnemonic}`"
        );
    }

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
