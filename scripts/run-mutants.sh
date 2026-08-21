#!/usr/bin/env bash
# Run cargo-mutants locally. This wrapper replaces the previous nightly /
# PR cargo-mutants CI workflows; mutation testing is now run on demand
# from a developer machine to avoid eating GitHub Actions minutes.
#
# Shared cargo-mutants configuration (including --bins) lives in
# .cargo/mutants.toml. This wrapper runs with --in-place and --baseline=skip,
# so there is no baseline run for timeout_multiplier to scale; it therefore
# defaults each mutant to 180s and takes --timeout SECONDS to override. Its
# baseline and per-mutant runs use unit tests only (`cargo test --bins`);
# integration tests remain in the normal project quality gate rather than
# every local mutation run.

set -euo pipefail

print_usage() {
    cat <<'EOF'
Usage:
  scripts/run-mutants.sh                 # full run
  scripts/run-mutants.sh --diff          # only mutants in `git diff origin/main...`
  scripts/run-mutants.sh --diff main     # diff vs an explicit base ref
  scripts/run-mutants.sh --shard 0/8     # one shard of an 8-way split
  scripts/run-mutants.sh --timeout 45    # per-mutant timeout in seconds (default 180)
  scripts/run-mutants.sh -- --foo --bar  # forward extra flags to cargo-mutants
  scripts/run-mutants.sh -h | --help     # print this message
EOF
}

cd "$(dirname "$0")/.."

mode="full"
diff_base="origin/main"
shard=""
timeout_seconds="180"
extra=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --diff)
            mode="diff"
            shift
            if [[ $# -gt 0 && "$1" != -* ]]; then
                diff_base="$1"
                shift
            fi
            ;;
        --shard)
            if [[ $# -lt 2 ]]; then
                echo "error: --shard requires an argument (e.g. --shard 0/8)" >&2
                exit 2
            fi
            if [[ ! "$2" =~ ^[0-9]+/[0-9]+$ ]]; then
                echo "error: --shard argument must be N/M (e.g. --shard 0/8)" >&2
                exit 2
            fi
            shard="$2"
            shift 2
            ;;
        --timeout)
            if [[ $# -lt 2 ]]; then
                echo "error: --timeout requires an argument (e.g. --timeout 180)" >&2
                exit 2
            fi
            if [[ ! "$2" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                echo "error: --timeout argument must be a number of seconds (e.g. --timeout 180)" >&2
                exit 2
            fi
            timeout_seconds="$2"
            shift 2
            ;;
        --)
            shift
            extra+=("$@")
            break
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            print_usage >&2
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

args=(--baseline=skip --timeout "$timeout_seconds" --in-place -vV)

case "$mode" in
    diff)
        diff_file=$(mktemp -t mutants-pr-diff.XXXXXX)
        trap 'rm -f "$diff_file"' EXIT
        echo "==> Computing diff vs $diff_base"
        git diff "$diff_base..." > "$diff_file"
        if [[ ! -s "$diff_file" ]]; then
            echo "no diff vs $diff_base; nothing to mutate."
            exit 0
        fi
        args+=(--in-diff "$diff_file")
        ;;
    full)
        :
        ;;
esac

if [[ -n "$shard" ]]; then
    args+=(--no-shuffle --shard "$shard" --sharding round-robin)
fi

if [[ ${#extra[@]} -gt 0 ]]; then
    args+=("${extra[@]}")
fi

echo "==> cargo mutants ${args[*]}"
# cargo-mutants returns non-zero when any mutant is missed; we still want
# to print the summary, so don't let `set -e` abort here.
set +e
cargo mutants "${args[@]}"
status=$?
set -e

if [[ -d mutants.out ]]; then
    echo
    if command -v python3 >/dev/null; then
        echo "==> Summary (scripts/mutants_summary.py)"
        python3 scripts/mutants_summary.py mutants.out
    else
        echo "==> Skipping summary: python3 not found. Raw results in mutants.out/."
    fi
fi

exit "$status"
