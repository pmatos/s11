"""Regression checks for the advisory Claude Code Review gate."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "claude-code-review.yml"
CLASSIFIER_PATH = (
    REPOSITORY_ROOT / ".github" / "scripts" / "classify_claude_review_failure.sh"
)

REVIEW_STEP_ID = "claude-review"
CLASSIFY_STEP_NAME = "Classify review outcome"


def workflow_step(contents: str, marker: str) -> str:
    """Extract the step introduced by marker without requiring a YAML dependency."""
    lines = contents.splitlines()

    for start, line in enumerate(lines):
        if line.strip() != marker:
            continue

        indentation = len(line) - len(line.lstrip())
        end = len(lines)
        for index in range(start + 1, len(lines)):
            candidate = lines[index]
            if not candidate.strip():
                continue
            candidate_indentation = len(candidate) - len(candidate.lstrip())
            if candidate_indentation <= indentation and candidate.lstrip().startswith(
                "- "
            ):
                end = index
                break
        return "\n".join(lines[start:end])

    raise ValueError(f"workflow step not found: {marker}")


def classify(outcome: str, execution_log: object | None) -> subprocess.CompletedProcess:
    """Run the classifier over one recorded review outcome."""
    environment = {"REVIEW_OUTCOME": outcome}

    with tempfile.TemporaryDirectory() as directory:
        if execution_log is not None:
            log_path = Path(directory) / "claude-execution-output.json"
            log_path.write_text(json.dumps(execution_log), encoding="utf-8")
            environment["EXECUTION_FILE"] = str(log_path)

        return subprocess.run(
            ["bash", str(CLASSIFIER_PATH)],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )


def result_record(**fields: object) -> list[dict]:
    """Build an execution log whose last record is a run result."""
    record = {"type": "result", "is_error": True}
    record.update(fields)
    return [{"type": "system", "subtype": "init"}, record]


class TestClaudeReviewWorkflow(unittest.TestCase):
    """The review must annotate, not block, when it cannot reach the diff."""

    def setUp(self) -> None:
        """Load the workflow definition once per test."""
        self.contents = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_review_step_does_not_fail_the_job_on_its_own(self) -> None:
        """A failed review is classified rather than propagated straight to red."""
        step = workflow_step(self.contents, f"id: {REVIEW_STEP_ID}")
        self.assertIn("continue-on-error: true", step)

    def test_classification_step_always_runs_over_the_review_outcome(self) -> None:
        """The classifier sees the outcome and the log for every review run."""
        step = workflow_step(self.contents, f"- name: {CLASSIFY_STEP_NAME}")
        self.assertIn("if: always()", step)
        self.assertIn(
            f"REVIEW_OUTCOME: ${{{{ steps.{REVIEW_STEP_ID}.outcome }}}}", step
        )
        self.assertIn(
            f"EXECUTION_FILE: ${{{{ steps.{REVIEW_STEP_ID}.outputs.execution_file }}}}",
            step,
        )
        self.assertIn(
            "run: bash .github/scripts/classify_claude_review_failure.sh", step
        )


class TestClaudeReviewClassifier(unittest.TestCase):
    """Credential and quota failures warn; failures of the review itself do not."""

    def test_successful_review_passes(self) -> None:
        """Nothing is annotated when the reviewer completed its run."""
        completed = classify("success", None)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("::warning", completed.stdout)

    def test_missing_execution_log_warns(self) -> None:
        """A reviewer that never started cannot have found a defect."""
        completed = classify("failure", None)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("::warning", completed.stdout)

    def test_run_without_model_usage_warns(self) -> None:
        """A rejected token ends the run before it bills a single turn."""
        completed = classify(
            "failure",
            result_record(
                subtype="success", num_turns=1, total_cost_usd=0, modelUsage={}
            ),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("::warning", completed.stdout)

    def test_quota_failure_after_real_work_warns(self) -> None:
        """Throttling mid-review is still not a defect in the pull request."""
        completed = classify(
            "failure",
            result_record(
                subtype="error",
                num_turns=4,
                total_cost_usd=0.1,
                result="API Error: 429 rate_limit_error",
                modelUsage={"claude-sonnet-5": {"inputTokens": 10}},
            ),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("::warning", completed.stdout)

    def test_failure_after_real_work_fails_the_job(self) -> None:
        """A reviewer that read the diff and then broke is a genuine failure."""
        completed = classify(
            "failure",
            result_record(
                subtype="error_during_execution",
                num_turns=7,
                total_cost_usd=0.42,
                result="Tool use failed while posting the review comment",
                modelUsage={"claude-sonnet-5": {"inputTokens": 100}},
            ),
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("::error", completed.stdout)


if __name__ == "__main__":
    unittest.main()
