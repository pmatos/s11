#!/usr/bin/env bash
# Run cargo-mutants locally. This wrapper replaces the previous nightly /
# PR cargo-mutants CI workflows; mutation testing is now run on demand
# from a developer machine to avoid eating GitHub Actions minutes.
#
# Usage:
#   scripts/run-mutants.sh                 # full run
#   scripts/run-mutants.sh --diff          # only mutants in `git diff origin/main...`
#   scripts/run-mutants.sh --diff main     # diff vs an explicit base ref
#   scripts/run-mutants.sh --shard 0/8     # one shard of an 8-way split
#   scripts/run-mutants.sh -- --foo --bar  # forward extra flags to cargo-mutants
#
# Notes:
#   - Configuration (timeout multiplier, --bins) lives in .cargo/mutants.toml.
#   - Per-mutant timeout is forced to 180s here to match the previous CI
#     behaviour and keep wall-clock predictable.
#   - The baseline runs unit tests only (`cargo test --bins`), matching the
#     gating policy in .github/workflows/test.yml which lets integration
#     tests fail. Including them would mark every mutant as "caught" by a
#     pre-existing flake instead of by the mutation itself.

set -euo pipefail

cd "$(dirname "$0")/.."

mode="full"
diff_base="origin/main"
shard=""
extra=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --diff)
            mode="diff"
            shift
            if [[ $# -gt 0 && "$1" != --* ]]; then
                diff_base="$1"
                shift
            fi
            ;;
        --shard)
            shard="$2"
            shift 2
            ;;
        --)
            shift
            extra+=("$@")
            break
            ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

if ! command -v cargo-mutants >/dev/null; then
    echo "error: cargo-mutants is not installed. Install with:" >&2
    echo "  cargo install --locked cargo-mutants" >&2
    exit 1
fi

echo "==> Building AArch64 test binaries"
./build_tests.sh

echo "==> Baseline build + unit tests"
cargo build
cargo test --bins

args=(--baseline=skip --timeout 180 --in-place -vV)

case "$mode" in
    diff)
        echo "==> Computing diff vs $diff_base"
        git diff "$diff_base..." > mutants.pr.diff
        if [[ ! -s mutants.pr.diff ]]; then
            echo "no diff vs $diff_base; nothing to mutate."
            rm -f mutants.pr.diff
            exit 0
        fi
        args+=(--in-diff mutants.pr.diff)
        ;;
    full)
        :
        ;;
esac

if [[ -n "$shard" ]]; then
    args+=(--no-shuffle --shard "$shard" --sharding round-robin)
fi

echo "==> cargo mutants ${args[*]} ${extra[*]:-}"
# cargo-mutants returns non-zero when any mutant is missed; we still want
# to print the summary, so don't let `set -e` abort here.
set +e
cargo mutants "${args[@]}" "${extra[@]:-}"
status=$?
set -e

if [[ -d mutants.out ]]; then
    echo
    echo "==> Summary (scripts/mutants_summary.py)"
    python3 scripts/mutants_summary.py mutants.out
fi

exit "$status"
