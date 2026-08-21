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

assert_mutants_command() {
    local log_file="$1"
    local expected="$2"
    local actual

    actual="$(grep '^cargo <mutants>' "$log_file")"
    if [[ "$actual" != "$expected" ]]; then
        diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual")
        exit 1
    fi
}

default_log="$FIXTURE/default.log"
run_wrapper "$default_log"
assert_mutants_command \
    "$default_log" \
    'cargo <mutants> <--baseline=skip> <--timeout> <180> <--in-place> <-vV>'

override_log="$FIXTURE/override.log"
run_wrapper "$override_log" --timeout 45
assert_mutants_command \
    "$override_log" \
    'cargo <mutants> <--baseline=skip> <--timeout> <45> <--in-place> <-vV>'

missing_log="$FIXTURE/missing.log"
missing_stderr="$FIXTURE/missing.stderr"
: > "$missing_log"
set +e
PATH="$FIXTURE/bin:$PATH" \
    S11_MUTANTS_TEST_LOG="$missing_log" \
    "$FIXTURE/scripts/run-mutants.sh" --timeout \
    > /dev/null 2> "$missing_stderr"
missing_status=$?
set -e

if [[ $missing_status -ne 2 ]]; then
    echo "expected a missing timeout value to exit 2; got $missing_status" >&2
    exit 1
fi

if ! grep -Fq -- 'error: --timeout requires an argument (e.g. --timeout 180)' "$missing_stderr"; then
    echo "expected a focused missing-timeout diagnostic; got:" >&2
    cat "$missing_stderr" >&2
    exit 1
fi

if [[ -s "$missing_log" ]]; then
    echo "expected missing-timeout validation before cargo preflight; got:" >&2
    cat "$missing_log" >&2
    exit 1
fi
