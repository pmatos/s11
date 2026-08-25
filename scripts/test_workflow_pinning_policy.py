"""Regression checks for immutable GitHub Actions workflow dependencies."""

from pathlib import Path
import re
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = REPOSITORY_ROOT / ".github" / "workflows"
RELEASE_WORKFLOW_PATH = WORKFLOW_DIRECTORY / "release.yml"
DEPENDABOT_PATH = REPOSITORY_ROOT / ".github" / "dependabot.yml"

USES_PATTERN = re.compile(
    r"^\s*(?:-\s*)?uses:\s*(?P<quote>['\"]?)"
    r"(?P<spec>[^\s#'\"]+)(?P=quote)"
    r"(?:\s+#\s*(?P<label>.+?))?\s*$"
)
FULL_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
VERSION_LABEL_PATTERN = re.compile(r"(?:v?\d+(?:\.\d+){0,2}|stable)(?:\s|$)")
SEMANTIC_RELEASE_PLUGIN_PATTERN = re.compile(
    r"^\s+(?P<package>@semantic-release/[a-z0-9-]+)@(?P<version>\S+)\s*$",
    re.MULTILINE,
)
EXACT_SEMVER_PATTERN = re.compile(
    r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)


def remote_action_pinning_violations(contents: str) -> list[str]:
    """Return policy failures for remote action references in a workflow."""
    violations = []

    for line_number, line in enumerate(contents.splitlines(), start=1):
        match = USES_PATTERN.match(line)
        if match is None:
            continue

        spec = match.group("spec")
        if spec.startswith(("./", "docker://")) or "@" not in spec:
            continue

        repository, reference = spec.rsplit("@", 1)
        if "/" not in repository:
            continue

        if FULL_COMMIT_SHA_PATTERN.fullmatch(reference) is None:
            violations.append(
                f"line {line_number}: {spec} must use a full 40-character commit SHA"
            )

        label = match.group("label")
        if label is None or VERSION_LABEL_PATTERN.match(label) is None:
            violations.append(
                f"line {line_number}: {spec} must include its tag or channel "
                "in a same-line comment"
            )

    return violations


def semantic_release_plugin_pinning_violations(contents: str) -> list[str]:
    """Return semantic-release plugin specs that do not use exact SemVer."""
    return [
        f"{match.group('package')}@{match.group('version')} must use an exact version"
        for match in SEMANTIC_RELEASE_PLUGIN_PATTERN.finditer(contents)
        if EXACT_SEMVER_PATTERN.fullmatch(match.group("version")) is None
    ]


def dependabot_update_block(contents: str, ecosystem: str) -> str:
    """Extract one package ecosystem's update block without a YAML dependency."""
    lines = contents.splitlines()
    marker = f'- package-ecosystem: "{ecosystem}"'

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
            if (
                candidate_indentation == indentation
                and candidate.lstrip().startswith("- package-ecosystem:")
            ):
                end = index
                break
        return "\n".join(lines[start:end])

    raise ValueError(f"Dependabot ecosystem not found: {ecosystem}")


class TestWorkflowPinningPolicy(unittest.TestCase):
    def test_remote_action_policy_rejects_mutable_or_opaque_references(self):
        workflow = """
        - uses: actions/checkout@v7
        - uses: actions/setup-node@abc123 # v7.0.0
        - uses: owner/action@0123456789012345678901234567890123456789
        """

        violations = remote_action_pinning_violations(workflow)

        self.assertEqual(4, len(violations))

    def test_remote_action_policy_allows_documented_shas_and_local_actions(self):
        workflow = """
        - uses: actions/checkout@0123456789012345678901234567890123456789 # v7.0.1
        - uses: dtolnay/rust-toolchain@abcdefabcdefabcdefabcdefabcdefabcdefabcd # stable
        - uses: ./.github/actions/local
        - uses: docker://alpine:3.23
        """

        self.assertEqual([], remote_action_pinning_violations(workflow))

    def test_all_remote_workflow_actions_use_documented_full_shas(self):
        violations = []
        workflow_paths = sorted(WORKFLOW_DIRECTORY.glob("*.y*ml"))

        for workflow_path in workflow_paths:
            relative_path = workflow_path.relative_to(REPOSITORY_ROOT)
            for violation in remote_action_pinning_violations(
                workflow_path.read_text(encoding="utf-8")
            ):
                violations.append(f"{relative_path}: {violation}")

        self.assertEqual([], violations, "\n".join(violations))

    def test_semantic_release_plugins_use_exact_versions(self):
        release_workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
        violations = semantic_release_plugin_pinning_violations(release_workflow)

        self.assertEqual([], violations, "\n".join(violations))

    def test_dependabot_keeps_sha_pinned_actions_current(self):
        dependabot_config = DEPENDABOT_PATH.read_text(encoding="utf-8")
        try:
            actions_updates = dependabot_update_block(
                dependabot_config, "github-actions"
            )
        except ValueError as error:
            self.fail(str(error))

        configured_lines = {line.strip() for line in actions_updates.splitlines()}
        for required_line in ('directory: "/"', 'interval: "weekly"'):
            with self.subTest(line=required_line):
                self.assertIn(required_line, configured_lines)


if __name__ == "__main__":
    unittest.main()
