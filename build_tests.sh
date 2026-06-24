#!/bin/bash

# Build script for AArch64 + x86 test binaries.
#
# Issue #77 stage 3 step 26 will add RISC-V test-binary builds using
# riscv{32,64}-linux-gnu-gcc, gracefully skipped when the toolchain is
# absent (mirroring the existing gcc -m32 precedent). Blocked on step 23's
# RISC-V semantics work — useful RISC-V integration tests need
# `s11 disasm` and `s11 equiv` (asm-text) to produce meaningful output,
# which requires the concrete + SMT executors.
set -e

echo "Building AArch64 test binaries..."
echo "Current directory: $(pwd)"
echo "Checking for AArch64 cross-compiler..."
which aarch64-linux-gnu-gcc || (echo "ERROR: aarch64-linux-gnu-gcc not found!" && exit 1)

mkdir -p binaries binaries/x86_64 binaries/x86_32

# --- AArch64 (cross-compiled) ---
for test_file in tests/*.c; do
    base_name=$(basename "$test_file" .c)
    echo "Compiling AArch64 $base_name..."
    aarch64-linux-gnu-gcc -g -O0 -o "binaries/${base_name}_debug" "$test_file"
    aarch64-linux-gnu-gcc -O2     -o "binaries/${base_name}_opt"   "$test_file"
    aarch64-linux-gnu-gcc -O3     -o "binaries/${base_name}_opt3"  "$test_file"
done

# --- x86-64 (host gcc) ---
if command -v gcc >/dev/null && [ "$(gcc -dumpmachine | head -c 6)" = "x86_64" ]; then
    echo "Building x86-64 test binaries with host gcc..."
    for test_file in tests/*.c; do
        base_name=$(basename "$test_file" .c)
        echo "Compiling x86-64 $base_name..."
        gcc -g -O0 -o "binaries/x86_64/${base_name}_debug" "$test_file"
        gcc -O2     -o "binaries/x86_64/${base_name}_opt"   "$test_file"
    done

    # Hand-written register-only x86 assembly fixtures (tests/x86_asm/*.s).
    # gcc compiles the tests/*.c sources to memory-operand-heavy code the
    # x86 opt path does not model; these fixtures stay inside the supported
    # register/immediate subset and encode a known deterministic shortening
    # for the end-to-end opt integration tests. `-no-pie -nostdlib` gives a
    # fixed-address ELF so window addresses are stable across rebuilds.
    for asm_file in tests/x86_asm/*.s; do
        [ -e "$asm_file" ] || continue
        base_name=$(basename "$asm_file" .s)
        echo "Assembling x86-64 fixture $base_name..."
        gcc -no-pie -nostdlib -o "binaries/x86_64/${base_name}" "$asm_file"
    done
else
    echo "Skipping x86-64 (no x86_64 host gcc)."
fi

# --- x86-32 (gcc -m32, requires multilib) ---
if gcc -m32 -E -x c - </dev/null >/dev/null 2>&1; then
    echo "Building x86-32 test binaries with gcc -m32..."
    for test_file in tests/*.c; do
        base_name=$(basename "$test_file" .c)
        echo "Compiling x86-32 $base_name..."
        gcc -m32 -g -O0 -o "binaries/x86_32/${base_name}_debug" "$test_file" \
            || echo "  ... skipped (link or compile failure)"
    done
else
    echo "Skipping x86-32 (gcc -m32 not usable; install gcc-multilib to enable)."
fi

echo "Built binaries:"
ls -la binaries/ binaries/x86_64/ binaries/x86_32/ 2>/dev/null || true

echo "Verifying binary types:"
for binary in binaries/* binaries/x86_64/* binaries/x86_32/*; do
    [ -f "$binary" ] || continue
    echo "$(basename "$binary"): $(file "$binary" | cut -d: -f2-)"
done
