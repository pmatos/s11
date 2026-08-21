#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf "$FIXTURE"' EXIT

mkdir -p "$FIXTURE/bin" "$FIXTURE/scripts"
cp "$ROOT/scripts/run-mutants.sh" "$FIXTURE/scripts/run-mutants.sh"

printf '#!/usr/bin/env bash\nexit 0\n' > "$FIXTURE/build_tests.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$FIXTURE/bin/cargo-mutants"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "cargo" >> "$S11_MUTANTS_TEST_LOG"' \
    'printf " <%s>" "$@" >> "$S11_MUTANTS_TEST_LOG"' \
    'printf "\\n" >> "$S11_MUTANTS_TEST_LOG"' \
    > "$FIXTURE/bin/cargo"
chmod +x \
    "$FIXTURE/build_tests.sh" \
    "$FIXTURE/bin/cargo-mutants" \
    "$FIXTURE/bin/cargo" \
    "$FIXTURE/scripts/run-mutants.sh"

run_wrapper() {
    local log_file="$1"
    shift
    : > "$log_file"
    PATH="$FIXTURE/bin:$PATH" \
        S11_MUTANTS_TEST_LOG="$log_file" \
        "$FIXTURE/scripts/run-mutants.sh" "$@"
}

assert_logged_command() {
    local log_file="$1"
    local pattern="$2"
    local expected="$3"
    local actual

    if ! actual="$(grep -- "$pattern" "$log_file")"; then
        echo "expected a logged command matching '$pattern'; got:" >&2
        cat "$log_file" >&2
        exit 1
    fi

    if [[ "$actual" != "$expected" ]]; then
        diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual")
        exit 1
    fi
}

assert_mutants_command() {
    assert_logged_command "$1" '^cargo <mutants>' "$2"
}

# Rejected invocations must fail fast, before the (slow) build + baseline
# preflight runs any cargo command.
assert_rejected() {
    local expected_message="$1"
    shift
    local log_file="$FIXTURE/rejected.log"
    local stderr_file="$FIXTURE/rejected.stderr"
    local status

    : > "$log_file"
    set +e
    PATH="$FIXTURE/bin:$PATH" \
        S11_MUTANTS_TEST_LOG="$log_file" \
        "$FIXTURE/scripts/run-mutants.sh" "$@" \
        > /dev/null 2> "$stderr_file"
    status=$?
    set -e

    if [[ $status -ne 2 ]]; then
        echo "expected '$*' to exit 2; got $status" >&2
        cat "$stderr_file" >&2
        exit 1
    fi

    if ! grep -Fq -- "$expected_message" "$stderr_file"; then
        echo "expected a focused diagnostic for '$*'; got:" >&2
        cat "$stderr_file" >&2
        exit 1
    fi

    if [[ -s "$log_file" ]]; then
        echo "expected '$*' to be rejected before the cargo preflight; got:" >&2
        cat "$log_file" >&2
        exit 1
    fi
}

default_log="$FIXTURE/default.log"
run_wrapper "$default_log"
assert_mutants_command \
    "$default_log" \
    'cargo <mutants> <--baseline=skip> <--timeout> <180> <--in-place> <-vV>'
# The wrapper documents a unit-test-only baseline; pin it so a stray
# integration-test flag can't creep back in.
assert_logged_command "$default_log" '^cargo <test>' 'cargo <test> <--bins>'

override_log="$FIXTURE/override.log"
run_wrapper "$override_log" --timeout 45
assert_mutants_command \
    "$override_log" \
    'cargo <mutants> <--baseline=skip> <--timeout> <45> <--in-place> <-vV>'

fractional_log="$FIXTURE/fractional.log"
run_wrapper "$fractional_log" --timeout 2.5
assert_mutants_command \
    "$fractional_log" \
    'cargo <mutants> <--baseline=skip> <--timeout> <2.5> <--in-place> <-vV>'

shard_log="$FIXTURE/shard.log"
run_wrapper "$shard_log" --timeout 45 --shard 0/8
assert_mutants_command \
    "$shard_log" \
    'cargo <mutants> <--baseline=skip> <--timeout> <45> <--in-place> <-vV> <--no-shuffle> <--shard> <0/8> <--sharding> <round-robin>'

# The --diff branch needs a real git repository, so it is exercised by
# `just mutants --diff` rather than by this fixture.

assert_rejected \
    'error: --timeout requires an argument (e.g. --timeout 180)' \
    --timeout

assert_rejected \
    'error: --timeout argument must be a number of seconds (e.g. --timeout 180)' \
    --timeout abc

# A following flag must not be swallowed as the timeout value.
assert_rejected \
    'error: --timeout argument must be a number of seconds (e.g. --timeout 180)' \
    --timeout --shard 0/8
