#!/usr/bin/env bash
# Local LLM-superoptimizer demo. Iterates the corpus and runs `s11 llm-opt`
# against each. Requires the codex CLI to be installed and authenticated
# (subscription).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Each row: filename, live-out spec.
TARGETS=(
  "01_mov_add.s|x0"
  "02_xor_zero.s|x0"
  "03_redundant_mov.s|x0"
  "04_add_chain.s|x0"
  "05_sub_via_add.s|x0"
  "06_double_via_shift.s|x0"
  "07_dead_compute.s|x0"
)

cd "$ROOT"

if [ ! -x "$ROOT/target/release/s11" ] && [ ! -x "$ROOT/target/debug/s11" ]; then
  echo "building s11 (debug) ..."
  cargo build
fi

S11="$ROOT/target/release/s11"
[ -x "$S11" ] || S11="$ROOT/target/debug/s11"

successes=0
total=${#TARGETS[@]}

for entry in "${TARGETS[@]}"; do
  file="${entry%%|*}"
  liveout="${entry##*|}"
  asm="$SCRIPT_DIR/$file"
  echo
  echo "=================================================================="
  echo "[$file] live-out=$liveout"
  echo "=================================================================="
  if "$S11" llm-opt --asm "$asm" --live-out "$liveout" --max-calls 5 --timeout 60 -v; then
    successes=$((successes + 1))
  fi
done

echo
echo "=================================================================="
echo "Demo complete: $successes / $total targets ran without runtime error."
echo "(Run with --verbose to see per-iteration outcomes.)"
echo "=================================================================="
