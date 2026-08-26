#!/usr/bin/env bash
# Decide whether a failed Claude Code Review run should fail the job.
#
# The review is advisory. An unusable credential, an exhausted quota, or a
# throttled API means the reviewer never looked at the diff, which says nothing
# about the pull request, so those degrade to a warning annotation and leave the
# check green. A failure the reviewer hit *after* the model started working is a
# real problem with the review and still fails the job.
set -euo pipefail

REVIEW_OUTCOME="${REVIEW_OUTCOME:-}"
EXECUTION_FILE="${EXECUTION_FILE:-}"

warn() {
    echo "::warning title=Claude review skipped::$1"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        printf '### Claude review skipped\n\n%s\n' "$1" >>"${GITHUB_STEP_SUMMARY}"
    fi
    exit 0
}

fail() {
    echo "::error title=Claude review failed::$1"
    exit 1
}

if [ "${REVIEW_OUTCOME}" = "success" ]; then
    echo "Claude review completed successfully."
    exit 0
fi

# The action only publishes execution_file once its own run step finishes, so
# fall back to the fixed path it writes on the way out.
if [ -z "${EXECUTION_FILE}" ] && [ -n "${RUNNER_TEMP:-}" ]; then
    EXECUTION_FILE="${RUNNER_TEMP}/claude-execution-output.json"
fi

if [ -z "${EXECUTION_FILE}" ] || [ ! -f "${EXECUTION_FILE}" ]; then
    warn "The review action produced no execution log, so the reviewer never started; a missing or rejected CLAUDE_CODE_OAUTH_TOKEN is the usual cause."
fi

result_json="$(jq -c '[.. | objects | select(.type? == "result")] | last' "${EXECUTION_FILE}" 2>/dev/null || true)"
if [ -z "${result_json}" ] || [ "${result_json}" = "null" ]; then
    warn "The review execution log holds no result record, so the reviewer never reached the diff; a rejected CLAUDE_CODE_OAUTH_TOKEN is the usual cause."
fi

# Zero model usage means the run died on credentials, quota, or throttling
# before reading anything. It is the only signal available when the API reports
# no error text at all.
did_model_work="$(
    jq -r '
        if ((.total_cost_usd // 0) > 0)
            or ((.num_turns // 0) > 1)
            or (((.modelUsage // {}) | length) > 0)
        then "yes" else "no" end
    ' <<<"${result_json}"
)"
if [ "${did_model_work}" != "yes" ]; then
    warn "The reviewer exited without any model usage, which means an authentication, quota, or throttling problem with CLAUDE_CODE_OAUTH_TOKEN rather than a problem with this pull request."
fi

# Match only the result record's own fields: the surrounding transcript embeds
# the pull-request diff, where these words carry no meaning about the failure.
message="$(
    jq -r '[.result?, .error?, .subtype?] | map(select(type == "string")) | join(" ")' \
        <<<"${result_json}"
)"
if grep -qiE 'authentication|invalid.{0,3}api.{0,3}key|oauth|credit balance|usage limit|rate.?limit|quota|too many requests|overloaded|\b(401|403|429)\b' <<<"${message}"; then
    warn "The review run failed on credentials or quota rather than on the diff: ${message}"
fi

fail "The review ran but did not complete: ${message:-see the step log}"
