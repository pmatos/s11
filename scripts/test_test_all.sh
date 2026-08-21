#!/bin/bash

set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT

mkdir -p "$temporary_root/bin" "$temporary_root/work/binaries"

cat >"$temporary_root/bin/just" <<'EOF'
#!/bin/bash
exit 0
EOF

cat >"$temporary_root/bin/cargo" <<'EOF'
#!/bin/bash
case "${STUB_CARGO_MODE:-fail}" in
    fail)
        echo "simulated analyzer failure" >&2
        exit 42
        ;;
    empty)
        exit 0
        ;;
    success)
        echo "0x1000: 1f 20 03 d5 nop"
        ;;
    *)
        echo "unknown STUB_CARGO_MODE: ${STUB_CARGO_MODE:-}" >&2
        exit 64
        ;;
esac
EOF

chmod +x "$temporary_root/bin/just" "$temporary_root/bin/cargo"

run_test_all() {
    local cargo_mode="$1"

    set +e
    output=$(
        cd "$temporary_root/work"
        STUB_CARGO_MODE="$cargo_mode" PATH="$temporary_root/bin:$PATH" \
            bash "$repository_root/test_all.sh" 2>&1
    )
    status=$?
    set -e
}

run_test_all fail

if [ "$status" -eq 0 ]; then
    echo "test_all.sh succeeded after cargo run failed" >&2
    echo "$output" >&2
    exit 1
fi

if grep -Fq "The optimizer successfully analyzed all AArch64 binaries!" <<<"$output"; then
    echo "test_all.sh printed its success banner after cargo run failed" >&2
    echo "$output" >&2
    exit 1
fi

echo "test_all.sh propagates analyzer command failures"

run_test_all empty

if [ "$status" -eq 0 ]; then
    echo "test_all.sh succeeded without disassembly output" >&2
    echo "$output" >&2
    exit 1
fi

if grep -Fq "The optimizer successfully analyzed all AArch64 binaries!" <<<"$output"; then
    echo "test_all.sh printed its success banner without disassembly output" >&2
    echo "$output" >&2
    exit 1
fi

echo "test_all.sh rejects empty analyzer output"

run_test_all success

if [ "$status" -ne 0 ]; then
    echo "test_all.sh failed after valid disassembly output" >&2
    echo "$output" >&2
    exit 1
fi

banner_count=$(
    grep -Fc "The optimizer successfully analyzed all AArch64 binaries!" \
        <<<"$output" || true
)
if [ "$banner_count" -ne 1 ]; then
    echo "test_all.sh printed its success banner $banner_count times; expected once" >&2
    echo "$output" >&2
    exit 1
fi

echo "test_all.sh accepts valid disassembly output"
