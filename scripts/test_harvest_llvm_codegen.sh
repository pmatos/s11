#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

actual="$(
    S11_HARVEST_EXTRACT_ONLY=1 "$ROOT/scripts/harvest_llvm_codegen.sh" <<'ASM'
    cmp x0, x1
    tst x10, x11
    add x8, x0, #1
    mov w9, w8
    mov fp, x9
    add sp, sp, #16
ASM
)"

expected="$(cat <<'EOF'
// Live-out: x8,x9,x29,sp
    cmp x0, x1
    tst x10, x11
    add x8, x0, #1
    mov w9, w8
    mov fp, x9
    add sp, sp, #16
EOF
)"

if [[ "$actual" != "$expected" ]]; then
    diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual")
    exit 1
fi

no_dest="$(
    S11_HARVEST_EXTRACT_ONLY=1 "$ROOT/scripts/harvest_llvm_codegen.sh" <<'ASM'
    cmp x0, x1
    tst x2, x3
ASM
)"

if [[ -n "$no_dest" ]]; then
    echo "expected a block with no destination registers to be skipped; got:" >&2
    printf '%s\n' "$no_dest" >&2
    exit 1
fi
