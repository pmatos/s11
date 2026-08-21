#!/bin/bash
# Run all CI checks locally before pushing
# This helps ensure code will pass CI before committing

set -e  # Exit on first error

echo "=== Running CI Checks Locally ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $1 passed${NC}"
    else
        echo -e "${RED}✗ $1 failed${NC}"
        exit 1
    fi
}

# 1. Check repository CI policies and their shell regressions
echo "1. Checking repository CI policy..."
python3 -m unittest discover -s scripts -p 'test_*_policy.py'
print_status "Repository CI policy"
./scripts/test_test_all.sh
print_status "Analyzer script regressions"
echo

# 2. Check formatting
echo "2. Checking code formatting..."
cargo fmt -- --check
print_status "Code formatting"
echo

# 3. Build project
echo "3. Building project..."
cargo build --verbose
print_status "Build"
echo

# 4. Build test binaries (if build_tests.sh exists)
# Must run before `cargo test` because integration tests under tests/integration/
# load the cross-compiled AArch64 binaries from binaries/.
if [ -f "./build_tests.sh" ]; then
    echo "4. Building test binaries..."
    ./build_tests.sh
    print_status "Test binary build"
    echo
fi

# 5. Run unit + integration tests
echo "5. Running tests..."
cargo test --verbose
print_status "Tests"
echo

# 6. Run all tests (if test_all.sh exists)
if [ -f "./test_all.sh" ]; then
    echo "6. Running all tests..."
    ./test_all.sh
    print_status "All tests"
    echo
fi

# Note: Clippy is run separately in the rust-clippy workflow for security analysis

echo -e "${GREEN}=== All CI checks passed! ===${NC}"
echo "You can now commit and push your changes."
