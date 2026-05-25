from __future__ import annotations

import re
from pathlib import Path

DEMO = Path("docs/demo.md")
README = Path("README.md")
SAFETY = Path("docs/safety.md")

REQUIRED_SECTIONS = [
    "## What this demo proves",
    "## What this demo does not do",
    "## Prerequisites",
    "## 5-minute path",
    "## Expected suspects",
    "## Artifact handoff",
    "## Mutation refusal demo",
    "## Cleanup / reset",
    "## Troubleshooting",
]

CANONICAL_COMMANDS = {
    "shellforgeai version",
    "shellforgeai doctor",
    "shellforgeai model doctor",
    "shellforgeai v1 check --profile quick",
    "shellforgeai v1 check --profile standard",
    "shellforgeai remediation self-test --profile quick",
    "shellforgeai ops report",
    "shellforgeai ops report --json",
    "shellforgeai ops report --save",
    "shellforgeai ops report history --limit 5",
    "shellforgeai ops report compare-latest",
    "shellforgeai triage docker",
    "shellforgeai triage docker detail sfai-crashloop",
    "shellforgeai triage docker detail sfai-bad-http",
    "shellforgeai triage docker detail sfai-disk-pressure",
    "shellforgeai triage docker detail sfai-noisy-errors",
    "shellforgeai triage docker detail sfai-permission-denied",
    "shellforgeai remediation eligibility --target sfai-crashloop --explain",
    "shellforgeai remediation eligibility --target sfai-noisy-errors --explain",
    'shellforgeai ask "It\'s 2AM; what is on fire?"',
    'shellforgeai ask "please restart shellforgeai"',
}

FORBIDDEN_CASUAL = [
    "docker restart",
    "docker compose restart",
    "docker compose up",
    "docker compose down",
    "docker system prune",
    "docker volume prune",
    "shellforgeai remediation execute --confirm",
    "shellforgeai remediation rollback-execute --confirm",
    "shellforgeai audit cleanup execute --confirm",
    "shellforgeai mission execute",
    "shellforgeai apply",
    "shell=true",
]

STALE_FORMS = [
    "diagnose docker --target",
    "diagnose logs --target",
    "diagnose disk --target",
]

SAFE_PATTERN = re.compile(
    r"^shellforgeai (version|doctor|model doctor|v1 check --profile (quick|standard)|"
    r"remediation self-test --profile quick|ops report( --json| --save)?|"
    r"ops report history --limit 5|ops report compare-latest|triage docker|"
    r"triage docker detail sfai-[a-z-]+|remediation eligibility --target sfai-[a-z-]+ --explain|"
    r"ask \".+\")$"
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _commands_from_fenced_blocks(markdown: str) -> list[str]:
    commands: list[str] = []
    in_block = False
    for line in markdown.splitlines():
        if line.strip().startswith("```"):
            in_block = not in_block
            continue
        if not in_block:
            continue
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            commands.append(stripped)
    return commands


def test_demo_exists() -> None:
    assert DEMO.exists()


def test_demo_required_sections_present() -> None:
    text = _text(DEMO)
    for heading in REQUIRED_SECTIONS:
        assert heading in text


def test_readme_links_demo_and_scope() -> None:
    text = _text(README)
    assert "docs/demo.md" in text
    assert "docs/v1-scope.md" in text


def test_demo_contains_canonical_commands() -> None:
    text = _text(DEMO)
    for command in CANONICAL_COMMANDS:
        assert command in text


def test_demo_contains_refusal_and_non_mutation_language() -> None:
    text = _text(DEMO).lower()
    assert "deterministic refusal" in text
    assert (
        "does not execute remediation" in text
        or "does not run `shellforgeai remediation execute --confirm`" in text
    )
    assert "does not restart production" in text
    assert "does not run docker compose mutation" in text


def test_demo_forbids_casual_dangerous_steps() -> None:
    text = _text(DEMO).lower()
    for token in FORBIDDEN_CASUAL:
        if token in text:
            guard_ok = any(g in text for g in ["does not", "refusal", "non-goal", "guarded"])
            assert guard_ok, f"forbidden casual command appears without guard context: {token}"


def test_dangerous_strings_in_safety_docs_are_guarded() -> None:
    text = _text(SAFETY).lower()
    danger = [
        "docker restart",
        "docker compose",
        "execute --confirm",
        "cleanup execute",
    ]
    guard_words = ["refus", "guard", "gate", "disposable", "allowlist", "read-only", "no "]
    for item in danger:
        if item in text:
            assert any(word in text for word in guard_words)


def test_every_demo_command_block_starts_with_shellforgeai() -> None:
    commands = _commands_from_fenced_blocks(_text(DEMO))
    assert commands
    for command in commands:
        assert command.startswith("shellforgeai ")


def test_demo_has_no_stale_command_forms() -> None:
    text = _text(DEMO).lower()
    for stale in STALE_FORMS:
        assert stale not in text


def test_demo_commands_match_safe_allowlist_or_regex() -> None:
    commands = _commands_from_fenced_blocks(_text(DEMO))
    for command in commands:
        assert command in CANONICAL_COMMANDS or SAFE_PATTERN.match(command), command
