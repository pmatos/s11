"""Regression checks for immutable GitHub Actions workflow dependencies."""

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
import re
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = REPOSITORY_ROOT / ".github" / "workflows"
RELEASE_WORKFLOW_PATH = WORKFLOW_DIRECTORY / "release.yml"
DEPENDABOT_PATH = REPOSITORY_ROOT / ".github" / "dependabot.yml"

FULL_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
VERSION_LABEL_PATTERN = re.compile(r"(?:v?\d+(?:\.\d+){0,2}|stable)(?:\s|$)")
BLOCK_SCALAR_HEADER_PATTERN = re.compile(
    r"(?P<style>[|>])(?:[1-9][+-]?|[+-][1-9]?)?"
)
SEMANTIC_RELEASE_PLUGIN_PATTERN = re.compile(
    r"(?P<package>@semantic-release/[a-z0-9-]+)@(?P<version>\S+)"
)
EXACT_SEMVER_PATTERN = re.compile(
    r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)
DOUBLE_QUOTED_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}
HEX_ESCAPE_LENGTHS = {"x": 2, "u": 4, "U": 8}
EXPLICIT_MAPPING_KEY_ERROR = (
    "explicit mapping key must be a decodable literal scalar"
)


@dataclass(frozen=True)
class _MappingScalar:
    """One line-numbered YAML mapping scalar relevant to policy checks."""

    line_number: int
    key: str
    value: str | None
    comment: str | None
    error: str | None = None


def _quoted_scalar_at(text: str, start: int) -> tuple[str, int] | None:
    """Return one minimally decoded quoted scalar and its exclusive end."""
    quote = text[start]
    value = []
    index = start + 1

    while index < len(text):
        character = text[index]
        if character == quote:
            if quote == "'" and index + 1 < len(text) and text[index + 1] == quote:
                value.append(quote)
                index += 2
                continue
            return "".join(value), index + 1
        if quote == '"' and character == "\\" and index + 1 < len(text):
            escape = text[index + 1]
            if escape in DOUBLE_QUOTED_ESCAPES:
                value.append(DOUBLE_QUOTED_ESCAPES[escape])
                index += 2
                continue
            if escape in HEX_ESCAPE_LENGTHS:
                length = HEX_ESCAPE_LENGTHS[escape]
                digits = text[index + 2 : index + 2 + length]
                if len(digits) != length or re.fullmatch(r"[0-9A-Fa-f]+", digits) is None:
                    return None
                try:
                    value.append(chr(int(digits, 16)))
                except ValueError:
                    return None
                index += 2 + length
                continue
            return None
        value.append(character)
        index += 1

    return None


def _split_yaml_comment(line: str) -> tuple[str, str | None]:
    """Split at the first YAML comment marker outside quoted scalars."""
    index = 0
    while index < len(line):
        character = line[index]
        if character in "'\"":
            scalar = _quoted_scalar_at(line, index)
            if scalar is None:
                return line, None
            _, index = scalar
            continue
        if character == "#":
            return line[:index], line[index + 1 :].strip() or None
        index += 1

    return line, None


def _mapping_scalar_at(
    text: str, boundary: int
) -> tuple[str, str | None, str | None, str | None] | None:
    """Parse one mapping scalar beginning at a known mapping boundary."""
    index = boundary
    while index < len(text) and text[index].isspace():
        index += 1

    if (
        index < len(text)
        and text[index] == "-"
        and (index + 1 == len(text) or text[index + 1].isspace())
    ):
        index += 1
        while index < len(text) and text[index].isspace():
            index += 1

    if index >= len(text):
        return None

    explicit_key = text[index] == "?" and (
        index + 1 == len(text) or text[index + 1].isspace()
    )
    if explicit_key:
        index += 1
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text) or text[index] in "*&![{|>":
            return "", None, None, EXPLICIT_MAPPING_KEY_ERROR

    parsed_key = _mapping_key_at(text, index)
    if parsed_key is None:
        if explicit_key:
            return "", None, None, EXPLICIT_MAPPING_KEY_ERROR
        return None
    key, index = parsed_key

    while index < len(text) and text[index].isspace():
        index += 1
    if not key or index >= len(text) or text[index] != ":":
        if explicit_key:
            return "", None, None, EXPLICIT_MAPPING_KEY_ERROR
        return None

    value, block_style = _mapping_value_at(text, index + 1)
    return key, value, block_style, None


def _mapping_key_at(text: str, start: int) -> tuple[str, int] | None:
    """Parse one plain or quoted scalar used as a mapping key."""
    if start >= len(text):
        return None
    if text[start] in "'\"":
        return _quoted_scalar_at(text, start)

    index = start
    while index < len(text) and not text[index].isspace() and text[index] != ":":
        index += 1
    key = text[start:index]
    if not key:
        return None
    return key, index


def _mapping_value_at(text: str, start: int) -> tuple[str | None, str | None]:
    """Parse one mapping value after its YAML value indicator."""
    index = start
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        return None, None

    if text[index] in "'\"":
        scalar = _quoted_scalar_at(text, index)
        if scalar is None:
            return None, None
        value, value_end = scalar
        while value_end < len(text) and text[value_end] not in ",}]":
            if not text[value_end].isspace():
                return None, None
            value_end += 1
        return value, None

    value_end = index
    while value_end < len(text) and text[value_end] not in ",}]":
        value_end += 1
    value = text[index:value_end].strip()
    block_header = BLOCK_SCALAR_HEADER_PATTERN.fullmatch(value)
    if block_header is not None:
        return None, block_header.group("style")
    if value.startswith(
        ("*", "&", "!", "${{", "[", "{", "|", ">")
    ) or value in {"~", "null", "Null", "NULL"}:
        return None, None

    return value or None, None


def _explicit_mapping_key_at(text: str) -> tuple[str | None, int] | None:
    """Return an explicit key, or an opaque-key marker, and its column."""
    index = 0
    while index < len(text) and text[index].isspace():
        index += 1

    if (
        index < len(text)
        and text[index] == "-"
        and (index + 1 == len(text) or text[index + 1].isspace())
    ):
        index += 1
        while index < len(text) and text[index].isspace():
            index += 1

    indicator_column = index
    if (
        index >= len(text)
        or text[index] != "?"
        or (index + 1 < len(text) and not text[index + 1].isspace())
    ):
        return None

    index += 1
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] in "*&![{|>":
        return None, indicator_column
    parsed_key = _mapping_key_at(text, index)
    if parsed_key is None:
        return None, indicator_column
    key, index = parsed_key
    while index < len(text) and text[index].isspace():
        index += 1
    if not key or index != len(text):
        return None, indicator_column

    return key, indicator_column


def _explicit_mapping_value_at(
    text: str, indicator_column: int
) -> tuple[str | None, str | None] | None:
    """Parse a split explicit mapping value at its key's YAML column."""
    if (
        len(text) <= indicator_column
        or text[:indicator_column].strip()
        or text[indicator_column] != ":"
        or (
            indicator_column + 1 < len(text)
            and not text[indicator_column + 1].isspace()
        )
    ):
        return None

    return _mapping_value_at(text, indicator_column + 1)


def _mapping_scalars_on_line(
    text: str,
) -> Iterator[tuple[str, str | None, str | None, str | None]]:
    """Yield mapping scalars at block or flow mapping-entry boundaries."""
    scalar = _mapping_scalar_at(text, 0)
    if scalar is not None:
        yield scalar

    index = 0
    while index < len(text):
        character = text[index]
        if character in "'\"":
            quoted = _quoted_scalar_at(text, index)
            if quoted is None:
                return
            _, index = quoted
            continue
        if character in "{,":
            scalar = _mapping_scalar_at(text, index + 1)
            if scalar is not None:
                yield scalar
        index += 1


def _block_scalar_body(
    lines: list[str], header_index: int
) -> tuple[list[str], int]:
    """Return a de-indented block-scalar body and the next structural line."""
    header = lines[header_index]
    header_indentation = len(header) - len(header.lstrip(" "))
    body = []
    content_indentation = None
    index = header_index + 1

    while index < len(lines):
        line = lines[index]
        if not line.strip():
            body.append("")
            index += 1
            continue

        indentation = len(line) - len(line.lstrip(" "))
        if indentation <= header_indentation:
            break
        if content_indentation is None:
            content_indentation = indentation
        if indentation < content_indentation:
            break

        body.append(line[content_indentation:])
        index += 1

    return body, index


def _decode_block_scalar(style: str, body: list[str]) -> str:
    """Decode the line folding needed by workflow dependency scalars."""
    if style == "|":
        return "\n".join(body)

    value = []
    for index, line in enumerate(body):
        value.append(line)
        if index + 1 == len(body):
            continue
        value.append(" " if line and body[index + 1] else "\n")
    return "".join(value)


def _mapping_scalars(contents: str) -> Iterator[_MappingScalar]:
    """Yield decoded mapping scalars without rescanning block-scalar bodies."""
    lines = contents.splitlines()
    index = 0
    pending_explicit_key: tuple[str, int, int] | None = None

    while index < len(lines):
        mapping, comment = _split_yaml_comment(lines[index])

        if pending_explicit_key is not None:
            if not mapping.strip():
                index += 1
                continue
            key, indicator_column, key_line_number = pending_explicit_key
            explicit_value = _explicit_mapping_value_at(mapping, indicator_column)
            pending_explicit_key = None
            if explicit_value is not None:
                value, style = explicit_value
                line_number = index + 1
                if style is not None:
                    body, next_index = _block_scalar_body(lines, index)
                    value = _decode_block_scalar(style, body)
                    index = next_index
                else:
                    index += 1
                yield _MappingScalar(line_number, key, value, comment)
                continue
            yield _MappingScalar(key_line_number, key, None, None)

        explicit_key = _explicit_mapping_key_at(mapping)
        if explicit_key is not None:
            key, indicator_column = explicit_key
            if key is None:
                yield _MappingScalar(
                    index + 1,
                    "",
                    None,
                    None,
                    EXPLICIT_MAPPING_KEY_ERROR,
                )
            else:
                pending_explicit_key = (key, indicator_column, index + 1)
            index += 1
            continue

        scalars = list(_mapping_scalars_on_line(mapping))
        block_scalar = next(
            (scalar for scalar in scalars if scalar[2] is not None), None
        )

        if block_scalar is None:
            for key, value, _, error in scalars:
                yield _MappingScalar(index + 1, key, value, comment, error)
            index += 1
            continue

        body, next_index = _block_scalar_body(lines, index)
        for key, value, style, error in scalars:
            if style is not None:
                value = _decode_block_scalar(style, body)
            yield _MappingScalar(index + 1, key, value, comment, error)
        index = next_index

    if pending_explicit_key is not None:
        key, _, key_line_number = pending_explicit_key
        yield _MappingScalar(key_line_number, key, None, None)


def remote_action_pinning_violations(contents: str) -> list[str]:
    """Return policy failures for remote action references in a workflow."""
    violations = []

    for scalar in _mapping_scalars(contents):
        if scalar.error is not None:
            violations.append(f"line {scalar.line_number}: {scalar.error}")
            continue
        if scalar.key != "uses":
            continue
        if scalar.value is None or not scalar.value.strip():
            violations.append(
                f"line {scalar.line_number}: uses must be a decodable literal "
                "action reference"
            )
            continue

        spec = scalar.value.strip()
        if spec.startswith(("./", "docker://")):
            continue
        if any(character.isspace() for character in spec) or "@" not in spec:
            violations.append(
                f"line {scalar.line_number}: uses must be a decodable literal "
                "action reference"
            )
            continue

        repository, reference = spec.rsplit("@", 1)
        if "/" not in repository or not reference:
            violations.append(
                f"line {scalar.line_number}: uses must be a decodable literal "
                "action reference"
            )
            continue

        if FULL_COMMIT_SHA_PATTERN.fullmatch(reference) is None:
            violations.append(
                f"line {scalar.line_number}: {spec} must use a full 40-character "
                "commit SHA"
            )

        if (
            scalar.comment is None
            or VERSION_LABEL_PATTERN.match(scalar.comment) is None
        ):
            violations.append(
                f"line {scalar.line_number}: {spec} must include its tag or channel "
                "in a same-line comment"
            )

    return violations


def semantic_release_plugin_pinning_violations(contents: str) -> list[str]:
    """Return semantic-release plugin specs that do not use exact SemVer."""
    violations = []

    for scalar in _mapping_scalars(contents):
        if scalar.error is not None:
            violations.append(f"line {scalar.line_number}: {scalar.error}")
            continue
        if scalar.key != "extra_plugins":
            continue
        if scalar.value is None or not scalar.value.strip():
            violations.append(
                f"line {scalar.line_number}: extra_plugins must be a decodable "
                "literal plugin list"
            )
            continue
        for token in scalar.value.split():
            if not token.startswith("@semantic-release/"):
                continue
            match = SEMANTIC_RELEASE_PLUGIN_PATTERN.fullmatch(token)
            if match is None or EXACT_SEMVER_PATTERN.fullmatch(
                match.group("version")
            ) is None:
                violations.append(f"{token} must use an exact version")

    return violations


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

    def test_remote_action_policy_rejects_flow_style_references(self):
        workflow = """
        - { uses: actions/checkout@v7 }
        - { name: Checkout, uses: actions/setup-node@abc123 } # v7.0.0
        - { name: Toolchain, "uses": "dtolnay/rust-toolchain@stable" } # stable
        """

        self.assertEqual(
            [
                "line 2: actions/checkout@v7 must use a full 40-character commit SHA",
                "line 2: actions/checkout@v7 must include its tag or channel "
                "in a same-line comment",
                "line 3: actions/setup-node@abc123 must use a full 40-character "
                "commit SHA",
                "line 4: dtolnay/rust-toolchain@stable must use a full 40-character "
                "commit SHA",
            ],
            remote_action_pinning_violations(workflow),
        )

    def test_remote_action_policy_rejects_split_explicit_key_references(self):
        workflow = """
        - ? uses
          : actions/checkout@v7
        """

        self.assertEqual(
            [
                "line 3: actions/checkout@v7 must use a full 40-character "
                "commit SHA",
                "line 3: actions/checkout@v7 must include its tag or channel "
                "in a same-line comment",
            ],
            remote_action_pinning_violations(workflow),
        )

    def test_remote_action_policy_handles_explicit_key_scalar_forms(self):
        documented_sha = """
        - ? uses
          : actions/checkout@0123456789012345678901234567890123456789 # v7.0.1
        - ? uses
          : ./.github/actions/local
        - ? uses
          : docker://alpine:3.23
        """
        quoted_split_key = """
        - ? "uses"
          : actions/checkout@v7
        """
        flow_explicit_entry = '- { ? "uses": "owner/action@v7" }'
        folded_value = """
        - ? uses
          : >- # v7.0.1
            actions/checkout@v7
        """

        cases = [
            (documented_sha, []),
            (
                quoted_split_key,
                [
                    "line 3: actions/checkout@v7 must use a full 40-character "
                    "commit SHA",
                    "line 3: actions/checkout@v7 must include its tag or channel "
                    "in a same-line comment",
                ],
            ),
            (
                flow_explicit_entry,
                [
                    "line 1: owner/action@v7 must use a full 40-character commit "
                    "SHA",
                    "line 1: owner/action@v7 must include its tag or channel in a "
                    "same-line comment",
                ],
            ),
            (
                folded_value,
                [
                    "line 3: actions/checkout@v7 must use a full 40-character "
                    "commit SHA"
                ],
            ),
        ]

        for workflow, expected in cases:
            with self.subTest(workflow=workflow):
                self.assertEqual(expected, remote_action_pinning_violations(workflow))

    def test_remote_action_policy_allows_documented_shas_and_local_actions(self):
        workflow = """
        - uses: actions/checkout@0123456789012345678901234567890123456789 # v7.0.1
        - uses: dtolnay/rust-toolchain@abcdefabcdefabcdefabcdefabcdefabcdefabcd # stable
        - uses: ./.github/actions/local
        - uses: docker://alpine:3.23
        """

        self.assertEqual([], remote_action_pinning_violations(workflow))

    def test_remote_action_policy_handles_flow_quotes_comments_and_exclusions(self):
        workflow = """
        - { uses: actions/checkout@0123456789012345678901234567890123456789 } # v7.0.1
        - { name: "Toolchain #1", "uses": "dtolnay/rust-toolchain@abcdefabcdefabcdefabcdefabcdefabcdefabcd" } # stable
        - { 'uses': './.github/actions/local' }
        - { name: Container, uses: 'docker://alpine:3.23' }
        - { run: "echo '{ uses: owner/action@v7 } # not a YAML comment'" }
        """

        self.assertEqual([], remote_action_pinning_violations(workflow))

    def test_remote_action_policy_handles_multiline_and_nested_flow_mappings(self):
        workflow = """jobs:
          build:
            steps:
              - {
                  uses: actions/checkout@v7,
                }
              - {
                  uses: actions/setup-node@0123456789012345678901234567890123456789, # v7.0.0
                }
            compact: [{ uses: owner/action@abc123 }]
        """

        self.assertEqual(
            [
                "line 5: actions/checkout@v7 must use a full 40-character commit SHA",
                "line 5: actions/checkout@v7 must include its tag or channel "
                "in a same-line comment",
                "line 10: owner/action@abc123 must use a full 40-character commit "
                "SHA",
                "line 10: owner/action@abc123 must include its tag or channel "
                "in a same-line comment",
            ],
            remote_action_pinning_violations(workflow),
        )

    def test_remote_action_policy_rejects_folded_block_scalar_references(self):
        workflow = """
        - uses: >-
            actions/checkout@v7
        """

        self.assertEqual(
            [
                "line 2: actions/checkout@v7 must use a full 40-character "
                "commit SHA",
                "line 2: actions/checkout@v7 must include its tag or channel "
                "in a same-line comment",
            ],
            remote_action_pinning_violations(workflow),
        )

    def test_remote_action_policy_handles_block_scalar_references_and_bodies(self):
        workflow = """
        - uses: >- # v7.0.1
            actions/checkout@0123456789012345678901234567890123456789
        - uses: | # stable
            dtolnay/rust-toolchain@abcdefabcdefabcdefabcdefabcdefabcdefabcd
        - uses: >-
            ./.github/actions/local
        - uses: |
            docker://alpine:3.23
        - run: |
            echo "uses: owner/action@v7"
            uses: owner/action@v7
        """

        self.assertEqual([], remote_action_pinning_violations(workflow))

    def test_remote_action_policy_rejects_undecodable_target_scalars(self):
        workflow = """
        - uses: *floating-action
        - uses: "owner/action@v7
        - run: *floating-action
        - name: "uses: *floating-action"
        """

        self.assertEqual(
            [
                "line 2: uses must be a decodable literal action reference",
                "line 3: uses must be a decodable literal action reference",
            ],
            remote_action_pinning_violations(workflow),
        )

    def test_policies_reject_opaque_explicit_mapping_keys(self):
        workflows = [
            """
            ? *target-key
            : owner/action@v7
            """,
            """
            ? [uses]
            : owner/action@v7
            """,
            """
            ? "uses
            : owner/action@v7
            """,
            """
            values: { ? *target-key: owner/action@v7 }
            """,
            """
            values: { ? [uses]: owner/action@v7 }
            """,
            """
            values: { ? "uses: owner/action@v7 }
            """,
        ]
        expected = [
            "line 2: explicit mapping key must be a decodable literal scalar"
        ]

        for workflow in workflows:
            with self.subTest(workflow=workflow, policy="actions"):
                self.assertEqual(expected, remote_action_pinning_violations(workflow))
            with self.subTest(workflow=workflow, policy="plugins"):
                self.assertEqual(
                    expected, semantic_release_plugin_pinning_violations(workflow)
                )

    def test_policies_reject_unbound_explicit_target_keys(self):
        action_workflows = [
            """
            ? uses
            """,
            """
            ? uses
            name: unbound key
            """,
        ]
        plugin_workflows = [
            """
            ? extra_plugins
            """,
            """
            ? extra_plugins
            name: unbound key
            """,
        ]

        for workflow in action_workflows:
            with self.subTest(workflow=workflow, policy="actions"):
                self.assertEqual(
                    ["line 2: uses must be a decodable literal action reference"],
                    remote_action_pinning_violations(workflow),
                )
        for workflow in plugin_workflows:
            with self.subTest(workflow=workflow, policy="plugins"):
                self.assertEqual(
                    [
                        "line 2: extra_plugins must be a decodable literal plugin "
                        "list"
                    ],
                    semantic_release_plugin_pinning_violations(workflow),
                )

    def test_policies_reject_undecodable_explicit_target_values(self):
        action_workflows = [
            """
            ? uses
            : *floating-action
            """,
            """
            ? uses
            : "owner/action@v7
            """,
        ]
        plugin_workflows = [
            """
            ? extra_plugins
            : *floating-plugins
            """,
            """
            ? extra_plugins
            : "@semantic-release/changelog@6
            """,
        ]

        for workflow in action_workflows:
            with self.subTest(workflow=workflow, policy="actions"):
                self.assertEqual(
                    ["line 3: uses must be a decodable literal action reference"],
                    remote_action_pinning_violations(workflow),
                )
        for workflow in plugin_workflows:
            with self.subTest(workflow=workflow, policy="plugins"):
                self.assertEqual(
                    [
                        "line 3: extra_plugins must be a decodable literal plugin "
                        "list"
                    ],
                    semantic_release_plugin_pinning_violations(workflow),
                )

    def test_explicit_keys_bind_across_comments_at_the_same_yaml_column(self):
        workflow = """
        - ? uses
          # The explicit value indicator belongs to the key above.
          : actions/checkout@0123456789012345678901234567890123456789 # v7.0.1
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

    def test_semantic_release_plugin_policy_rejects_inline_mutable_versions(self):
        workflow = "extra_plugins: '@semantic-release/changelog@6'"

        self.assertEqual(
            ["@semantic-release/changelog@6 must use an exact version"],
            semantic_release_plugin_pinning_violations(workflow),
        )

    def test_semantic_release_plugin_policy_decodes_double_quoted_newlines(self):
        workflow = (
            r'extra_plugins: "@semantic-release/changelog@6.0.3\n'
            r'@semantic-release/git@10"'
        )

        self.assertEqual(
            ["@semantic-release/git@10 must use an exact version"],
            semantic_release_plugin_pinning_violations(workflow),
        )

    def test_semantic_release_plugin_policy_handles_mapping_and_scalar_styles(self):
        workflow = """
        extra_plugins: '@semantic-release/changelog@6'
        with: { extra_plugins: '@semantic-release/git@10' }
        literal:
          extra_plugins: |
            @semantic-release/changelog@6.0.3
            @semantic-release/git@10.0.1
        folded:
          extra_plugins: >-
            @semantic-release/exec@7.1.0
            @semantic-release/git@10.0.1
        commands:
          - run: |
              extra_plugins: '@semantic-release/exec@7'
          - run: "extra_plugins: '@semantic-release/exec@7'"
        """

        self.assertEqual(
            [
                "@semantic-release/changelog@6 must use an exact version",
                "@semantic-release/git@10 must use an exact version",
            ],
            semantic_release_plugin_pinning_violations(workflow),
        )

    def test_semantic_release_plugin_policy_handles_explicit_keys(self):
        workflow = """
        mutable:
          ? extra_plugins
          : '@semantic-release/changelog@6'
        exact:
          ? "extra_plugins"
          : >-
            @semantic-release/changelog@6.0.3
            @semantic-release/git@10.0.1
        unrelated:
          ? name
          : '@semantic-release/exec@7'
        commands:
          - run: |
              ? extra_plugins
              : '@semantic-release/exec@7'
        """

        self.assertEqual(
            ["@semantic-release/changelog@6 must use an exact version"],
            semantic_release_plugin_pinning_violations(workflow),
        )

    def test_semantic_release_plugin_policy_rejects_undecodable_target_scalars(self):
        workflow = """
        extra_plugins: *floating-plugins
        extra_plugins: "@semantic-release/changelog@6
        extra_plugins: >invalid
        run: *floating-plugins
        name: "extra_plugins: *floating-plugins"
        """

        self.assertEqual(
            [
                "line 2: extra_plugins must be a decodable literal plugin list",
                "line 3: extra_plugins must be a decodable literal plugin list",
                "line 4: extra_plugins must be a decodable literal plugin list",
            ],
            semantic_release_plugin_pinning_violations(workflow),
        )

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
