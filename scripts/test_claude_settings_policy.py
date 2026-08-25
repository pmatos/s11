"""Regression checks for the tracked Claude Code permission policy.

Run with:
    python3 -m unittest discover -s scripts -p 'test_claude_settings_policy.py'
"""

import json
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_PATH = REPOSITORY_ROOT / ".claude" / "settings.json"

REQUIRED_DENY_RULES = frozenset(
    {
        "Bash(rm *)",
        "Bash(sudo *)",
        "Bash(chmod *)",
        "Bash(git checkout *)",
    }
)


def normalize_trailing_wildcard(rule: str) -> str:
    """Return the canonical spelling for a trailing Claude Bash wildcard."""
    if rule.endswith(":*)"):
        return f"{rule[:-3]} *)"
    return rule


def is_dangerous_shared_allow(rule: str) -> bool:
    """Identify broad destructive or host-mutating shared Bash grants."""
    normalized = normalize_trailing_wildcard(rule)
    if normalized == "Bash(sudo)" or normalized.startswith("Bash(sudo "):
        return True
    return normalized in REQUIRED_DENY_RULES


class TestClaudeSettingsPolicy(unittest.TestCase):
    def test_shared_policy_denies_destructive_shell_families(self):
        settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        permissions = settings.get("permissions", {})

        dangerous_allows = sorted(
            rule
            for rule in permissions.get("allow", [])
            if is_dangerous_shared_allow(rule)
        )
        normalized_denies = {
            normalize_trailing_wildcard(rule) for rule in permissions.get("deny", [])
        }
        missing_denies = sorted(REQUIRED_DENY_RULES - normalized_denies)

        failures = []
        if dangerous_allows:
            failures.append(
                "dangerous rules must not be allowed by shared settings: "
                + ", ".join(dangerous_allows)
            )
        if missing_denies:
            failures.append(
                "shared settings must explicitly deny: " + ", ".join(missing_denies)
            )

        self.assertFalse(failures, "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
