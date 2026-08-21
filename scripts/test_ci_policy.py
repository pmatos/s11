"""Regression checks for required Test workflow gates."""

from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CI_CHECK_PATH = REPOSITORY_ROOT / "ci_check.sh"
TEST_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "test.yml"

INTEGRATION_TEST_COMMAND = "cargo test --test integration_tests -- --nocapture"
POLICY_DISCOVERY_COMMAND = (
    "python3 -m unittest discover -s scripts -p 'test_*_policy.py'"
)
SHELL_REGRESSION_COMMAND = "./scripts/test_test_all.sh"
MUTANTS_REGRESSION_COMMAND = "./scripts/test_run_mutants.sh"
MUTANTS_WORKFLOW_STEP = "Check mutation-wrapper command construction"


def has_required_command(contents: str, command: str) -> bool:
    """Return whether command appears on its own, without failure masking."""
    return command in {line.strip() for line in contents.splitlines()}


def workflow_step(contents: str, name: str) -> str:
    """Extract a named workflow step without requiring a YAML dependency."""
    lines = contents.splitlines()
    marker = f"- name: {name}"

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
            if candidate_indentation == indentation and candidate.lstrip().startswith("- "):
                end = index
                break
        return "\n".join(lines[start:end])

    raise ValueError(f"workflow step not found: {name}")


class TestCiPolicy(unittest.TestCase):
    def test_required_command_matcher_rejects_failure_masking(self):
        masked_workflow = f"run: {INTEGRATION_TEST_COMMAND} || true"

        self.assertFalse(
            has_required_command(masked_workflow, INTEGRATION_TEST_COMMAND)
        )

    def test_integration_tests_are_a_required_gate(self):
        workflow = TEST_WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertTrue(
            has_required_command(workflow, INTEGRATION_TEST_COMMAND),
            f"{INTEGRATION_TEST_COMMAND!r} must be present without failure masking",
        )

    def test_repository_policy_step_runs_all_regressions(self):
        workflow = TEST_WORKFLOW_PATH.read_text(encoding="utf-8")
        try:
            policy_step = workflow_step(workflow, "Check repository CI policy")
        except ValueError as error:
            self.fail(str(error))

        for command in (POLICY_DISCOVERY_COMMAND, SHELL_REGRESSION_COMMAND):
            with self.subTest(command=command):
                self.assertTrue(
                    has_required_command(policy_step, command),
                    f"repository CI policy step must run {command!r}",
                )

    def test_mutation_wrapper_regression_is_a_required_gate(self):
        workflow = TEST_WORKFLOW_PATH.read_text(encoding="utf-8")
        try:
            wrapper_step = workflow_step(workflow, MUTANTS_WORKFLOW_STEP)
        except ValueError as error:
            self.fail(str(error))

        self.assertTrue(
            has_required_command(wrapper_step, MUTANTS_REGRESSION_COMMAND),
            f"{MUTANTS_WORKFLOW_STEP!r} must run "
            f"{MUTANTS_REGRESSION_COMMAND!r} without failure masking",
        )

    def test_local_ci_gate_runs_all_regressions(self):
        ci_check = CI_CHECK_PATH.read_text(encoding="utf-8")

        for command in (
            POLICY_DISCOVERY_COMMAND,
            SHELL_REGRESSION_COMMAND,
            MUTANTS_REGRESSION_COMMAND,
        ):
            with self.subTest(command=command):
                self.assertTrue(
                    has_required_command(ci_check, command),
                    f"local CI gate must run {command!r}",
                )


if __name__ == "__main__":
    unittest.main()
