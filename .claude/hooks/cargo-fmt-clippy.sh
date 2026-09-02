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

cargo fmt -- "$file"
cargo clippy --quiet 2>&1 | tail -n 50

exit 0
