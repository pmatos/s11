#!/usr/bin/env bash
set -euo pipefail

# Hermetic regardless of the caller's own shell: don't let an ambient
# RUSTFMT leak into test cases that aren't deliberately setting it.
unset RUSTFMT

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hook="$repo_root/.claude/hooks/cargo-fmt-clippy.sh"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

stub_bin="$workdir/bin"
mkdir -p "$stub_bin"

cat > "$stub_bin/rustfmt" << 'EOF'
#!/usr/bin/env bash
if [ -n "${RUSTFMT_STUB_ARGS_FILE:-}" ]; then
  printf '%s\n' "$*" > "$RUSTFMT_STUB_ARGS_FILE"
fi
printf '%s' "${FAKE_RUSTFMT_OUTPUT:-}"
exit "${FAKE_RUSTFMT_EXIT:-0}"
EOF

cat > "$stub_bin/cargo" << 'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "clippy" ]; then
  if [ -n "${CARGO_STUB_ARGS_FILE:-}" ]; then
    printf '%s\n' "$*" > "$CARGO_STUB_ARGS_FILE"
  fi
  printf '%s' "${FAKE_CARGO_OUTPUT:-}"
  exit "${FAKE_CARGO_EXIT:-0}"
fi
exit 1
EOF

# Minimal stand-in for `jq -r '.tool_input.file_path // empty'` against the
# single fixed-shape JSON payload this test constructs, so the suite is
# hermetic and doesn't depend on jq being installed on the host.
cat > "$stub_bin/jq" << 'EOF'
#!/usr/bin/env bash
sed -n 's/.*"file_path":"\([^"]*\)".*/\1/p'
EOF

chmod +x "$stub_bin/rustfmt" "$stub_bin/cargo" "$stub_bin/jq"

project_dir="$workdir/project"
mkdir -p "$project_dir"
cat > "$project_dir/Cargo.toml" << 'EOF'
[package]
name = "stub"
edition = "2021"
EOF
touch "$project_dir/main.rs"

run_hook() {
  local file_path=$1
  local extra_path="${2:-}"
  printf '{"tool_input":{"file_path":"%s"}}' "$file_path" \
    | PATH="${extra_path:+$extra_path:}$stub_bin:$PATH" CLAUDE_PROJECT_DIR="$project_dir" "$hook" \
    > "$workdir/stdout" 2> "$workdir/stderr"
  echo $?
}

assert_eq() {
  local expected=$1 actual=$2 msg=$3
  if [ "$expected" != "$actual" ]; then
    echo "FAIL: $msg (expected [$expected], got [$actual])" >&2
    exit 1
  fi
}

assert_contains() {
  local path=$1 needle=$2 msg=$3
  if ! grep -qF -- "$needle" "$path"; then
    echo "FAIL: $msg" >&2
    exit 1
  fi
}

# Non-.rs files are ignored before any command runs.
status=$(FAKE_RUSTFMT_EXIT=1 run_hook "$project_dir/notes.txt")
assert_eq "0" "$status" "non-.rs file should exit 0"
assert_eq "" "$(cat "$workdir/stdout")" "non-.rs file should produce no stdout"
assert_eq "" "$(cat "$workdir/stderr")" "non-.rs file should produce no stderr"

# A .rs path that doesn't exist is ignored.
status=$(FAKE_RUSTFMT_EXIT=1 run_hook "$project_dir/missing.rs")
assert_eq "0" "$status" "missing .rs file should exit 0"

# Clean fmt + clean clippy: silent success.
status=$(run_hook "$project_dir/main.rs")
assert_eq "0" "$status" "clean fmt+clippy should exit 0"
assert_eq "" "$(cat "$workdir/stdout")" "clean run should produce no stdout"
assert_eq "" "$(cat "$workdir/stderr")" "clean run should produce no stderr"

# Clippy warnings (exit 0 from cargo, non-empty output) still surface via
# exit 2 + stderr -- the only PostToolUse path Claude actually sees.
status=$(FAKE_CARGO_OUTPUT="warning: something" run_hook "$project_dir/main.rs")
assert_eq "2" "$status" "clippy warning should exit 2"
assert_eq "" "$(cat "$workdir/stdout")" "warning path should produce no stdout"
assert_contains "$workdir/stderr" "warning: something" "clippy warning missing from stderr"

# rustfmt failure alone still surfaces (clippy runs independently either way).
status=$(FAKE_RUSTFMT_EXIT=1 FAKE_RUSTFMT_OUTPUT="fmt error marker" run_hook "$project_dir/main.rs")
assert_eq "2" "$status" "rustfmt failure should exit 2"
assert_contains "$workdir/stderr" "fmt error marker" "rustfmt failure marker missing from stderr"

# RUSTFMT override is honored instead of the PATH-resolved rustfmt. Use a
# second stub outside stub_bin, distinct from the PATH-resolved one (which
# stays on its default clean-success behavior here), so the two are
# actually distinguishable rather than both resolving to the same binary.
override_bin="$workdir/override_bin"
mkdir -p "$override_bin"
cat > "$override_bin/rustfmt" << 'EOF'
#!/usr/bin/env bash
printf '%s' "override marker"
exit 1
EOF
chmod +x "$override_bin/rustfmt"
status=$(RUSTFMT="$override_bin/rustfmt" run_hook "$project_dir/main.rs")
assert_eq "2" "$status" "RUSTFMT override failure should exit 2"
assert_contains "$workdir/stderr" "override marker" "RUSTFMT override marker missing from stderr -- override was not honored"

# Edition is parsed from Cargo.toml and passed to rustfmt. The fixture uses
# a non-default edition (2021, not the hook's 2024 fallback) so a broken or
# deleted parser -- which would silently fall back to 2024 -- is caught
# instead of coincidentally producing the expected value.
args_file="$workdir/rustfmt_args"
RUSTFMT_STUB_ARGS_FILE="$args_file" run_hook "$project_dir/main.rs" > /dev/null
assert_contains "$args_file" "--edition 2021" "edition 2021 (parsed from Cargo.toml) not passed to rustfmt"

# A long clippy dump must not push a short rustfmt diagnostic out of the
# truncated report (regression: fmt+clippy were previously concatenated
# before a single tail -n 50).
long_clippy=$(seq 1 60 | sed 's/^/clippy line /')
status=$(FAKE_RUSTFMT_EXIT=1 FAKE_RUSTFMT_OUTPUT="FMT_MARKER" FAKE_CARGO_OUTPUT="$long_clippy" run_hook "$project_dir/main.rs")
assert_eq "2" "$status" "combined fmt+clippy failure should exit 2"
assert_contains "$workdir/stderr" "FMT_MARKER" "fmt marker dropped by output truncation"

# Clippy must cover tests/ and benches/, not just the default lib+bin
# targets, since the hook fires on any *.rs file including those.
cargo_args_file="$workdir/cargo_args"
CARGO_STUB_ARGS_FILE="$cargo_args_file" run_hook "$project_dir/main.rs" > /dev/null
assert_contains "$cargo_args_file" "--all-targets" "clippy invocation does not cover tests/benches (missing --all-targets)"

# A missing/broken jq falls through to the same silent no-op as a
# non-.rs file, rather than invoking rustfmt/clippy on a bogus path. Use a
# dedicated PATH entry ahead of stub_bin's own (working) jq, rather than
# mutating the shared stub, so this test can't leave later tests without jq.
broken_jq_bin="$workdir/broken_jq_bin"
mkdir -p "$broken_jq_bin"
cat > "$broken_jq_bin/jq" << 'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$broken_jq_bin/jq"
status=$(FAKE_RUSTFMT_EXIT=1 FAKE_CARGO_EXIT=1 run_hook "$project_dir/main.rs" "$broken_jq_bin")
assert_eq "0" "$status" "a failing jq should fall through to exit 0, not invoke rustfmt/clippy"

echo "All cargo-fmt-clippy.sh hook tests passed"
