use std::fs;
use std::process::Command;

fn assert_bump(current: &str, bump: &str, expected: &str) {
    let temp_dir = tempfile::tempdir().expect("create temporary manifest directory");
    let manifest = temp_dir.path().join("Cargo.toml");
    fs::write(
        &manifest,
        format!(
            "[package]\nname = \"version-fixture\"\nversion = \"{current}\"\n\n[dependencies]\nfixture = {{ version = \"9.8.7\" }}\n"
        ),
    )
    .expect("write temporary manifest");

    let output = Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/bump-version.sh"
    ))
    .arg(bump)
    .env("MANIFEST", &manifest)
    .output()
    .expect("run bump-version.sh");

    assert!(
        output.status.success(),
        "bump-version.sh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, format!("{expected}\n").as_bytes());

    let updated = fs::read_to_string(manifest).expect("read updated manifest");
    assert!(
        updated.contains(&format!("\nversion = \"{expected}\"\n")),
        "package version was not updated:\n{updated}"
    );
    assert!(
        updated.contains("fixture = { version = \"9.8.7\" }"),
        "dependency version was unexpectedly changed:\n{updated}"
    );
}

#[test]
fn patch_from_prerelease_finalizes_current_version() {
    assert_bump("0.1.1-dev", "patch", "0.1.1");
}
