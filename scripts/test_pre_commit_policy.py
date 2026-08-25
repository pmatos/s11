"""Regression checks for the repository's pre-commit policy."""

from pathlib import Path
import re
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPOSITORY_ROOT / ".pre-commit-config.yaml"

PINNED_REPOSITORIES = {
    "https://github.com/pre-commit/pre-commit-hooks": "v6.0.0",
    "https://github.com/astral-sh/ruff-pre-commit": "v0.16.4",
    "https://github.com/crate-ci/typos": "v1.49.0",
    "https://github.com/jsh9/pydoclint": "0.9.1",
}

GENERIC_HOOK_IDS = {
    "check-added-large-files",
    "check-case-conflict",
    "check-merge-conflict",
    "check-symlinks",
    "check-yaml",
    "check-toml",
    "debug-statements",
    "detect-private-key",
    "end-of-file-fixer",
    "mixed-line-ending",
    "name-tests-test",
    "trailing-whitespace",
}


def repository_block(contents: str, repository: str) -> str:
    """Return one repository declaration from a pre-commit configuration."""
    marker = f"  - repo: {repository}"
    start = contents.find(marker)
    if start < 0:
        raise ValueError(f"repository not found: {repository}")

    next_repository = contents.find("\n  - repo:", start + len(marker))
    if next_repository < 0:
        return contents[start:]
    return contents[start:next_repository]


def hook_ids(block: str) -> set[str]:
    """Return hook identifiers declared in a repository block."""
    return set(re.findall(r"^\s+- id: ([^\s]+)$", block, flags=re.MULTILINE))


class TestPreCommitPolicy(unittest.TestCase):
    def config(self) -> str:
        """Read the repository's pre-commit configuration."""
        self.assertTrue(CONFIG_PATH.is_file(), f"missing {CONFIG_PATH.name}")
        return CONFIG_PATH.read_text(encoding="utf-8")

    def test_external_hooks_are_pinned_exactly(self):
        contents = self.config()

        for repository, revision in PINNED_REPOSITORIES.items():
            with self.subTest(repository=repository):
                block = repository_block(contents, repository)
                self.assertIn(f"\n    rev: {revision}\n", block)

    def test_generic_repository_hygiene_hooks_are_enabled(self):
        block = repository_block(
            self.config(), "https://github.com/pre-commit/pre-commit-hooks"
        )

        self.assertEqual(hook_ids(block), GENERIC_HOOK_IDS)
        self.assertIn('args: ["--pytest-test-first"]', block)

    def test_ruff_fixes_before_it_formats(self):
        block = repository_block(
            self.config(), "https://github.com/astral-sh/ruff-pre-commit"
        )

        check_index = block.find("- id: ruff-check")
        format_index = block.find("- id: ruff-format")
        self.assertGreaterEqual(check_index, 0)
        self.assertGreater(format_index, check_index)
        self.assertIn("args: [--fix]", block[check_index:format_index])

    def test_typos_is_check_only(self):
        block = repository_block(
            self.config(), "https://github.com/crate-ci/typos"
        )

        self.assertEqual(hook_ids(block), {"typos"})
        self.assertIn("entry: typos", block)
        self.assertIn("args: []", block)
        self.assertNotIn("--write-changes", block)

    def test_rust_format_hook_is_fast_and_checks_the_whole_crate(self):
        block = repository_block(self.config(), "local")

        self.assertIn("entry: cargo fmt --all -- --check", block)
        self.assertIn("types: [rust]", block)
        self.assertIn("pass_filenames: false", block)


if __name__ == "__main__":
    unittest.main()
