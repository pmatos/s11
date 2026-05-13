# Justfile for the AArch64 Super-Optimizer MVP

# Default recipe to run when `just` is called without arguments
default: build

# Set the shell for recipes.
# On Windows, you might want to use PowerShell or bash (if available via WSL/Git Bash).
# Default is `sh -cu` on Unix, `cmd /c` on Windows.
# set shell := ["powershell", "-NoProfile", "-Command"] # Example for PowerShell on Windows
# set shell := ["bash", "-c"] # Example for bash

# Build the project in debug mode
build:
    @echo "Building project (debug)..."
    cargo build

# Build the project in release mode (optimized)
release:
    @echo "Building project (release)..."
    cargo build --release

# Run the project (debug build)
# Depends on the 'build' recipe, so it will build first if necessary.
run: build
    @echo "Running project (debug)..."
    cargo run

# Run the project (release build)
# Depends on the 'release' recipe.
run-release: release
    @echo "Running project (release)..."
    cargo run --release
    # Alternatively, run the executable directly:
    # ./target/release/s11

# Run tests (currently, the MVP doesn't have dedicated unit tests beyond main's demo)
test:
    @echo "Running tests..."
    cargo test

# Clean build artifacts
clean:
    @echo "Cleaning project..."
    cargo clean

# Check the code for errors without building
check:
    @echo "Checking code..."
    cargo check

# Format the code according to Rust style guidelines
fmt:
    @echo "Formatting code..."
    cargo fmt

# List available commands (this is a common pattern, `just -l` or `just --list` is built-in)
list:
    @just --list

# Analyze an AArch64 ELF binary
analyze binary_path: build
    @echo "Analyzing binary: {{binary_path}}"
    cargo run -- --binary "{{binary_path}}"

# Build test binaries
build-tests:
    @echo "Building AArch64 test binaries..."
    ./build_tests.sh

# Run all tests
test-all: build-tests build
    @echo "Running complete test suite..."
    ./test_all.sh

# Run the LLM-assisted superoptimizer demo against the local corpus.
# Requires `codex` CLI installed and authenticated (subscription).
llm-demo: build
    @echo "Running LLM-assisted superoptimizer demo..."
    ./tests/data/llm_demo/run_demo.sh

# Run cargo-mutants locally (slow; expect >30 min on a full run).
# Thin wrapper around scripts/run-mutants.sh; pass `--diff` or `--shard`
# arguments through with `just mutants -- --diff`.
mutants *ARGS:
    ./scripts/run-mutants.sh {{ARGS}}

# Generate an HTML coverage report locally (open target/llvm-cov/html/index.html).
# Requires `cargo install cargo-llvm-cov` and the `llvm-tools-preview` rustup component.
coverage: build-tests
    @echo "Collecting coverage (HTML)..."
    cargo llvm-cov --workspace --all-features --html

# Emit an LCOV report at target/llvm-cov/lcov.info — the format consumed by CI/Codecov.
coverage-lcov: build-tests
    @echo "Collecting coverage (LCOV)..."
    @mkdir -p target/llvm-cov
    cargo llvm-cov --workspace --all-features --lcov --output-path target/llvm-cov/lcov.info

# Help message (can be more detailed than just listing)
help:
    @echo "Available commands for AArch64 Super-Optimizer MVP (run with 'just <command>'):"
    @echo "  build         - Build the project (debug mode)"
    @echo "  release       - Build the project in release mode (optimized)"
    @echo "  run           - Build and run the project (debug mode)"
    @echo "  run-release   - Build and run the project (release mode)"
    @echo "  analyze PATH  - Analyze an AArch64 ELF binary at PATH"
    @echo "  test          - Run tests"
    @echo "  build-tests   - Build AArch64 test binaries"
    @echo "  test-all      - Run complete test suite"
    @echo "  mutants       - Run cargo-mutants locally (slow; informational)"
    @echo "  coverage      - Generate HTML coverage report via cargo-llvm-cov"
    @echo "  coverage-lcov - Generate LCOV coverage report (CI format)"
    @echo "  clean         - Remove build artifacts from the target directory"
    @echo "  check         - Check the code for errors without compiling"
    @echo "  fmt           - Format the Rust code"
    @echo "  list          - List all available recipes (same as 'just --list')"
    @echo "  help          - Display this help message"

# You can add comments to recipes using a leading '#'
# Example of a recipe with arguments:
# greet name:
#   @echo "Hello, {{name}}!"
# To run: just greet Linus
