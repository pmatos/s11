#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

assert_dry_run() {
    local expected=$1
    shift

    local actual
    actual=$(just --dry-run mutants "$@" 2>&1)
    if [[ "$actual" != "$expected" ]]; then
        echo "unexpected dry-run output for: just mutants $*" >&2
        echo "expected: $expected" >&2
        echo "actual:   $actual" >&2
        exit 1
    fi
}

assert_contains() {
    local path=$1
    local expected=$2

    if ! grep -Fq -- "$expected" "$path"; then
        echo "$path does not document: $expected" >&2
        exit 1
    fi
}

assert_absent() {
    local path=$1
    local stale=$2

    if grep -Fq -- "$stale" "$path"; then
        echo "$path still documents the invalid invocation: $stale" >&2
        exit 1
    fi
}

# Wrapper modes must reach run-mutants.sh without a leading separator.
assert_dry_run './scripts/run-mutants.sh --diff' --diff
assert_dry_run './scripts/run-mutants.sh --diff main' --diff main
assert_dry_run './scripts/run-mutants.sh --shard 0/8' --shard 0/8

# A separator remains required when intentionally forwarding cargo-mutants flags.
assert_dry_run './scripts/run-mutants.sh -- --foo' -- --foo

assert_contains Justfile 'just mutants --diff'
assert_contains CLAUDE.md 'just mutants --diff'
assert_contains CLAUDE.md 'just mutants --shard 0/8'
assert_contains README.md 'just mutants --diff'
assert_contains README.md 'just mutants --shard 0/8'
assert_contains README.md 'just mutants -- --foo'

for path in Justfile CLAUDE.md README.md; do
    assert_absent "$path" 'just mutants -- --diff'
    assert_absent "$path" 'just mutants -- --shard'
    assert_absent "$path" 'just mutants -- -- --'
done
