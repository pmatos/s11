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

# 1. Check formatting
echo "1. Checking code formatting..."
cargo fmt -- --check
print_status "Code formatting"
echo

# 2. Build project
echo "2. Building project..."
cargo build --verbose
print_status "Build"
echo

# 3. Run unit tests
echo "3. Running unit tests..."
cargo test --verbose
print_status "Unit tests"
echo

# 4. Build test binaries (if build_tests.sh exists)
if [ -f "./build_tests.sh" ]; then
    echo "4. Building test binaries..."
    ./build_tests.sh
    print_status "Test binary build"
    echo
fi

# 5. Run all tests (if test_all.sh exists)
if [ -f "./test_all.sh" ]; then
    echo "5. Running all tests..."
    ./test_all.sh
    print_status "All tests"
    echo
fi

# Note: Clippy is run separately in the rust-clippy workflow for security analysis

echo -e "${GREEN}=== All CI checks passed! ===${NC}"
echo "You can now commit and push your changes."