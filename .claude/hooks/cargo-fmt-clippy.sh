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

output=$(rustfmt --edition 2024 "$file" 2>&1 && cargo clippy --quiet --no-deps 2>&1)
status=$?

if [ "$status" -ne 0 ]; then
  echo "$output" | tail -n 50 >&2
  exit 2
fi

exit 0
