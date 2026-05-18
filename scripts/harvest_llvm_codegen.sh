#!/usr/bin/env bash
# Phase 2 — harvest AArch64 basic blocks from llvm-project's
# test/CodeGen/AArch64 corpus into benches/llvm_codegen/.
#
# Maintainer-run, NOT bench-time. Output `.s` files are committed
# alongside the bench target.
#
# Requires GNU coreutils — `shuf --random-source` is a GNU extension
# and is not available on stock macOS / BSD shuf. On macOS install
# coreutils via Homebrew and use `gshuf`, or run this on Linux.
#
# Usage:
#   scripts/harvest_llvm_codegen.sh [SEED] [SAMPLE_SIZE]
#
# Env:
#   LLVM_CACHE  Directory for the cached llvm-project clone
#               (default /tmp/s11-llvm).

set -euo pipefail

SEED="${1:-42}"
SAMPLE_SIZE="${2:-30}"
LLVM_CACHE="${LLVM_CACHE:-/tmp/s11-llvm}"

# 1. Precheck: llc must include the AArch64 backend.
if ! llc --version 2>/dev/null | grep -qE '^\s*aarch64\b'; then
    echo "error: llc lacks the AArch64 backend" >&2
    echo "       reinstall LLVM with AArch64 enabled or set PATH to a build that includes it." >&2
    exit 2
fi
# Precheck: GNU shuf with --random-source. BSD shuf rejects the flag.
if ! shuf --help 2>&1 | grep -q -- '--random-source'; then
    echo "error: this script needs GNU coreutils shuf (--random-source for deterministic sampling)" >&2
    echo "       on macOS:  brew install coreutils  and substitute gshuf, or run on Linux." >&2
    exit 2
fi

# 2. Clone (shallow) or update the llvm-project cache.
if [[ ! -d "$LLVM_CACHE/.git" ]]; then
    echo "[1/4] cloning llvm-project shallow into $LLVM_CACHE..."
    git clone --depth=1 --filter=blob:none \
        https://github.com/llvm/llvm-project.git "$LLVM_CACHE"
else
    echo "[1/4] refreshing llvm-project cache at $LLVM_CACHE..."
    git -C "$LLVM_CACHE" fetch --depth=1 origin main >/dev/null 2>&1 || true
    git -C "$LLVM_CACHE" reset --hard origin/main >/dev/null 2>&1 || true
fi

TEST_DIR="$LLVM_CACHE/llvm/test/CodeGen/AArch64"
if [[ ! -d "$TEST_DIR" ]]; then
    echo "error: expected $TEST_DIR after clone" >&2
    exit 3
fi

# 3. Sample $SAMPLE_SIZE .ll files deterministically.
echo "[2/4] sampling $SAMPLE_SIZE .ll files (seed=$SEED)..."
mapfile -t SAMPLES < <(
    find "$TEST_DIR" -maxdepth 1 -type f -name '*.ll' |
        sort |
        shuf --random-source=<(yes "$SEED" 2>/dev/null) -n "$SAMPLE_SIZE"
)

OUT_DIR="$(git rev-parse --show-toplevel)/benches/llvm_codegen"
mkdir -p "$OUT_DIR"

# Supported AArch64 mnemonics — keep in sync with CLAUDE.md:11 and the
# top-level mnemonic dispatch in src/parser/mod.rs. `uxtw` is intentionally
# omitted: the parser handles it as an extend-operand modifier only, not
# as a standalone instruction, so a harvested block containing it would
# panic in load_sequence at bench time.
SUPPORTED_MNEMONICS=(
    mov add sub and orr eor lsl lsr asr mul sdiv udiv cmp cmn tst
    csel csinc csinv csneg madd msub mneg smulh umulh ccmp ccmn
    ubfx sbfx bfi bfxil ubfiz sbfiz
    sxtb sxth sxtw uxtb uxth
)

# Build a regex matching exactly one supported mnemonic at line start.
MNEMONIC_RE="^[[:space:]]*("
for m in "${SUPPORTED_MNEMONICS[@]}"; do
    MNEMONIC_RE+="$m|"
done
MNEMONIC_RE="${MNEMONIC_RE%|})[[:space:]]"

# 4. Run llc on each sample, emit .s blocks the s11 parser can consume.
#
# The body extractor is an awk state machine. It walks the llc output
# one line at a time and accumulates a candidate straight-line block
# composed only of supported-mnemonic instruction lines. A block ends
# when any of these is hit:
#   - a label                                    (start of next block)
#   - a branch/return terminator (b/br/bl/blr/ret/cbz/cbnz/tbz/tbnz/b.cond)
# Assembler directives and comments don't break a block (they're
# noise inside a single function), but an unsupported instruction
# disqualifies the currently-accumulating block — the harvester does
# not silently splice supported lines across an unsupported one.
#
# The first qualifying block (2..32 supported instructions) is emitted
# and awk exits. This guarantees one straight-line block per fixture,
# preventing the previous behaviour of grep'ing across multiple basic
# blocks / functions and gluing unrelated paths together (PR #269 review).
echo "[3/4] running llc and extracting basic blocks..."
kept=0
for ll in "${SAMPLES[@]}"; do
    base="$(basename "${ll%.ll}")"
    asm="$(llc -mtriple=aarch64-linux-gnu -O2 -filetype=asm -o - "$ll" 2>/dev/null)" || continue

    body="$(printf '%s\n' "$asm" | awk -v mnemonic_re="$MNEMONIC_RE" '
        BEGIN { block = ""; count = 0; supported = 1; done = 0 }
        function finish() {
            if (supported && count >= 2 && count <= 32) {
                print block
                done = 1
                exit 0
            }
            block = ""; count = 0; supported = 1
        }
        # Blank lines and stripped comments — keep accumulating.
        /^[[:space:]]*$/ { next }
        /^[[:space:]]*\/\// { next }
        # Assembler directives (.text, .cfi_*, etc.) — keep accumulating.
        /^[[:space:]]*\./ { next }
        # Labels close the current block.
        /^[[:space:]]*[A-Za-z_.][A-Za-z0-9_.]*:/ { finish(); next }
        # Branch / return terminators close the current block.
        /^[[:space:]]*(b|br|bl|blr|ret|cbz|cbnz|tbz|tbnz)([[:space:]]|$)/ { finish(); next }
        /^[[:space:]]*b\.[a-z]+([[:space:]]|$)/ { finish(); next }
        # Supported instruction — append to the in-flight block.
        $0 ~ mnemonic_re {
            block = (count == 0 ? $0 : block "\n" $0)
            count++
            next
        }
        # Any other instruction disqualifies the block.
        { supported = 0 }
        # END fires even after `exit 0`, so guard against double-emit.
        END { if (!done) finish() }
    ')"

    # awk emits a block only on success; an empty body means no
    # qualifying block was found in this .ll.
    if [[ -z "$body" ]]; then
        continue
    fi

    out="$OUT_DIR/${base}.s"
    {
        printf '// Source: llvm-project/llvm/test/CodeGen/AArch64/%s\n' "$(basename "$ll")"
        printf '// Live-in: x0, x1\n'
        printf '// Live-out: x0\n'
        printf '%s\n' "$body"
    } > "$out"
    kept=$((kept+1))
done

echo "[4/4] wrote $kept fixtures to $OUT_DIR"
echo "Review them with:   git -C $(git rev-parse --show-toplevel) status -- benches/llvm_codegen"
