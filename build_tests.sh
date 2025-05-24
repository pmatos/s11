#!/bin/bash

# Build script for AArch64 test binaries
set -e

echo "Building AArch64 test binaries..."

# Create binaries directory
mkdir -p binaries

# Compile each test with different optimization levels
for test_file in tests/*.c; do
    base_name=$(basename "$test_file" .c)
    echo "Compiling $base_name..."
    
    # Debug version (no optimization)
    aarch64-linux-gnu-gcc -g -O0 -o "binaries/${base_name}_debug" "$test_file"
    
    # Optimized version
    aarch64-linux-gnu-gcc -O2 -o "binaries/${base_name}_opt" "$test_file"
    
    # Highly optimized version
    aarch64-linux-gnu-gcc -O3 -o "binaries/${base_name}_opt3" "$test_file"
done

echo "Built binaries:"
ls -la binaries/

echo "Verifying binary types:"
for binary in binaries/*; do
    echo "$(basename "$binary"): $(file "$binary" | cut -d: -f2-)"
done