#!/usr/bin/env bash
# PostToolUse hook: cargo fmt + clippy the file Claude Code just wrote/edited.
# Reads the hook JSON payload from stdin, per Claude Code's hook contract.
set -uo pipefail

file=$(jq -r '.tool_input.file_path // empty' 2>/dev/null || true)

case "$file" in
  *.rs) ;;
  *) exit 0 ;;
esac

[ -f "$file" ] || exit 0

cd "$CLAUDE_PROJECT_DIR" || exit 0

edition=$(sed -n 's/^edition[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n 1)
edition="${edition:-2024}"

fmt_output=$("${RUSTFMT:-rustfmt}" --edition "$edition" "$file" 2>&1)
fmt_status=$?

# On a cold target/ (fresh checkout, cargo clean, or a Cargo.lock bump),
# building this crate's z3/capstone/dynasmrt dependencies can exceed the
# 60s hook timeout; edits keep timing out until that cold build converges,
# though the edit and the rustfmt pass above still land either way.
clippy_output=$(cargo clippy --quiet --no-deps --all-targets 2>&1)
clippy_status=$?

fmt_report=""
if [ "$fmt_status" -ne 0 ]; then
  fmt_report=$(printf '%s\n' "$fmt_output" | tail -n 25)
  [ -z "$fmt_report" ] && fmt_report="rustfmt exited $fmt_status with no output"
fi

clippy_report=""
if [ "$clippy_status" -ne 0 ] || [ -n "$clippy_output" ]; then
  clippy_report=$(printf '%s\n' "$clippy_output" | tail -n 25)
  [ -z "$clippy_report" ] && clippy_report="cargo clippy exited $clippy_status with no output"
fi

combined=$(
  [ -n "$fmt_report" ] && echo "$fmt_report"
  [ -n "$clippy_report" ] && echo "$clippy_report"
  true # keep this subshell's exit status 0 even when both reports are empty
)

if [ -n "$combined" ]; then
  echo "$combined" >&2
  exit 2
fi

exit 0
