from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "ARCHIVE_SOURCE_ACTION_RUNBOOK.md"
README = ROOT / "README.md"
SCRIPT = ROOT / "scripts" / "docker01_artifact_archive_plan.py"

REQUIRED_HEADINGS = [
    "# Archive Source-Action Operator Runbook",
    "## What this workflow is good at",
    "## What this workflow does not do",
    "## Evidence chain overview",
    "## Command sequence",
    "## Artifact map",
    "## Operator decision matrix",
    "## Status meaning",
    "## Troubleshooting partial/not_ready/failed",
    "## Safety contract",
    "## Future PR/lane requirements",
]

COMMAND_FLAGS = [
    "--root",
    "--validate",
    "--dry-run-receipt",
    "--validate-dry-run-receipt",
    "--execution-readiness",
    "--create-archive-bundle",
    "--validate-archive-bundle",
    "--archive-eligibility-review",
    "--archive-source-action-dry-run",
    "--validate-archive-source-action-dry-run",
    "--archive-source-action-review-packet",
    "--archive-source-action-decision-receipt",
    "--archive-source-action-readiness-gate",
    "--archive-source-action-status-report",
    "--archive-source-action-fixture-rehearsal",
    "--fixture-root",
    "--restore-before-exit",
]

FORBIDDEN_NEW_FLAGS = [
    "--cleanup",
    "--delete",
    "--move",
    "--prune",
    "--restart",
    "--execute",
    "--apply",
    "--approve",
    "--merge",
]

STATUSES = [
    "ready_for_operator_review",
    "ready_for_future_pr_review",
    "ready_for_human_review",
    "ready_for_source_action_review",
    "decision_recorded",
    "partial",
    "not_ready",
    "failed",
]


def test_runbook_file_exists_and_has_required_headings():
    assert RUNBOOK.is_file()
    text = RUNBOOK.read_text()
    for heading in REQUIRED_HEADINGS:
        assert heading in text


def test_runbook_documents_current_archive_source_action_command_chain():
    text = RUNBOOK.read_text()
    script_text = SCRIPT.read_text()
    for flag in COMMAND_FLAGS:
        assert flag in text
        assert flag in script_text
    assert "CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE" in text
    assert '--out "$STATUS_REPORT_DIR" --json' in text


def test_runbook_preserves_no_cleanup_shaped_command_surface_guardrails():
    text = RUNBOOK.read_text()
    for flag in FORBIDDEN_NEW_FLAGS:
        assert flag not in text
    assert "source action is not available" in text.lower()
    assert "future source action would require a separate pr/lane" in text.lower()
    assert "SeedOfEvil remains the final merge owner" in text
    assert "ready means reviewable evidence rather than executable" not in text.lower()
    assert "does not mean executable" in text.lower()


def test_runbook_includes_artifact_map_and_decision_matrix_contracts():
    text = RUNBOOK.read_text()
    assert (
        "| Step | Command | Main JSON artifact | Summary Markdown artifact | Safety expectation |"
        in text
    )
    matrix_header = (
        "| Status | What it means | Operator may do next | Operator must not do "
        "| Source action available | Cleanup available | Execution available |"
    )
    assert matrix_header in text
    for status in STATUSES:
        assert status in text
    for artifact in [
        "archive-source-action-dry-run.json",
        "archive-source-action-dry-run-validation.json",
        "archive-source-action-review-packet.json",
        "archive-source-action-decision-receipt.json",
        "archive-source-action-readiness-gate.json",
        "archive-source-action-status-report.json",
        "fixture-source-action-rehearsal.json",
    ]:
        assert artifact in text


def test_readme_keeps_capability_first_positioning_and_mutation_refusal():
    text = README.read_text()
    assert "ShellForgeAI is strongest at evidence-backed Docker/Linux triage" in text
    assert "guarded operator workflows" in text
    assert "audit-friendly receipts and manifests" in text
    assert "deterministic refusal of unsafe broad mutation" in text
    assert "docs/ARCHIVE_SOURCE_ACTION_RUNBOOK.md" in text
    assert "Asks do not execute" in text


def test_minimal_docs_reference_runbook_without_new_execution_lane():
    for rel in [
        "OPS.md",
        "docs/VALIDATION_LANES.md",
        "docs/VALIDATION_MATRIX.md",
        "docs/roadmap.md",
    ]:
        text = (ROOT / rel).read_text()
        assert "ARCHIVE_SOURCE_ACTION_RUNBOOK.md" in text
        assert (
            "no execution command" in text
            or "does not add a new execution command" in text
            or "adds no execution command" in text
        )
        assert "non-executable" in text


def test_archive_plan_script_was_not_given_forbidden_source_action_execution_flags():
    script_text = SCRIPT.read_text()
    for flag in FORBIDDEN_NEW_FLAGS:
        assert flag not in script_text
