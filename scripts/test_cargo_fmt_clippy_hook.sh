#!/usr/bin/env bash
set -euo pipefail

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

chmod +x "$stub_bin/rustfmt" "$stub_bin/cargo"

project_dir="$workdir/project"
mkdir -p "$project_dir"
cat > "$project_dir/Cargo.toml" << 'EOF'
[package]
name = "stub"
edition = "2024"
EOF
touch "$project_dir/main.rs"

run_hook() {
  local file_path=$1
  printf '{"tool_input":{"file_path":"%s"}}' "$file_path" \
    | PATH="$stub_bin:$PATH" CLAUDE_PROJECT_DIR="$project_dir" "$hook" \
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

# RUSTFMT override is honored instead of the PATH-resolved rustfmt.
status=$(RUSTFMT="$stub_bin/rustfmt" FAKE_RUSTFMT_EXIT=1 FAKE_RUSTFMT_OUTPUT="override marker" run_hook "$project_dir/main.rs")
assert_eq "2" "$status" "RUSTFMT override failure should exit 2"
assert_contains "$workdir/stderr" "override marker" "RUSTFMT override marker missing from stderr"

# Edition is parsed from Cargo.toml and passed to rustfmt.
args_file="$workdir/rustfmt_args"
RUSTFMT_STUB_ARGS_FILE="$args_file" run_hook "$project_dir/main.rs" > /dev/null
assert_contains "$args_file" "--edition 2024" "edition 2024 (parsed from Cargo.toml) not passed to rustfmt"

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

echo "All cargo-fmt-clippy.sh hook tests passed"
