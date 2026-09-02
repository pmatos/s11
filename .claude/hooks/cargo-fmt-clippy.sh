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

fmt_output=$(rustfmt --edition 2024 "$file" 2>&1)
fmt_status=$?

clippy_output=$(cargo clippy --quiet --no-deps 2>&1)
clippy_status=$?

if [ "$clippy_status" -ne 0 ]; then
  {
    [ "$fmt_status" -ne 0 ] && echo "$fmt_output"
    echo "$clippy_output"
  } | tail -n 50 >&2
  exit 2
fi

{
  [ "$fmt_status" -ne 0 ] && echo "$fmt_output"
  [ -n "$clippy_output" ] && echo "$clippy_output"
} | tail -n 50

exit 0
