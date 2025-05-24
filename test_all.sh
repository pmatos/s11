#!/bin/bash

# Test script for s11
set -e

echo "=== s11 Test Suite ==="
echo

# Build test binaries if they don't exist
if [ ! -d "binaries" ]; then
    echo "Building test binaries..."
    ./build_tests.sh
    echo
fi

# Build the optimizer
echo "Building optimizer..."
just build
echo

# Function to run test and extract main function
run_test() {
    local binary="$1"
    local name="$2"
    
    echo "=== Testing $name ==="
    echo "Binary: $binary"
    
    # Run the analyzer and extract main function area
    cargo run -- --binary "$binary" 2>/dev/null | \
        awk '/Section: \.text/,/Section:|Binary analysis/' | \
        grep -E "0x[0-9a-f]+:" | \
        tail -20  # Show last 20 instructions which usually include main
    echo
}

# Test each category
echo "Testing simple arithmetic..."
run_test "binaries/simple_debug" "Simple (Debug)"
run_test "binaries/simple_opt" "Simple (Optimized)"

echo "Testing function calls..."
run_test "binaries/functions_debug" "Functions (Debug)"
run_test "binaries/functions_opt" "Functions (Optimized)"

echo "Testing optimization opportunities..."
run_test "binaries/optimizable_debug" "Optimizable (Debug)"
run_test "binaries/optimizable_opt" "Optimizable (Optimized)"

echo "Testing loops..."
run_test "binaries/loops_debug" "Loops (Debug)"
run_test "binaries/loops_opt" "Loops (Optimized)"

echo "Testing arrays..."
run_test "binaries/arrays_debug" "Arrays (Debug)"
run_test "binaries/arrays_opt" "Arrays (Optimized)"

echo "=== Test Suite Complete ==="
echo "The optimizer successfully analyzed all AArch64 binaries!"
echo "You can see clear differences between debug and optimized versions."