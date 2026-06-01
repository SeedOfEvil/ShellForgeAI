from pathlib import Path

AUDIT = Path("docs/COMMAND_SURFACE_AUDIT.md")
CONTRACT = Path("docs/V2_COMMAND_CONTRACT.md")
README = Path("README.md")
OPS = Path("OPS.md")
ROADMAP = Path("docs/roadmap.md")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _lower(path: Path) -> str:
    return _read(path).lower()


def test_command_surface_audit_doc_exists() -> None:
    assert AUDIT.exists()


def test_v2_command_contract_doc_exists() -> None:
    assert CONTRACT.exists()


def test_readme_links_command_audit_or_v2_contract() -> None:
    text = _lower(README)
    assert "command_surface_audit.md" in text or "v2_command_contract.md" in text


def test_ops_links_command_audit_or_v2_contract() -> None:
    text = _lower(OPS)
    assert "command_surface_audit.md" in text or "v2_command_contract.md" in text


def test_roadmap_mentions_pr143_command_surface_audit() -> None:
    text = _lower(ROADMAP)
    assert "pr143" in text
    assert "command surface audit" in text or "command-surface audit" in text


def test_command_surface_audit_defines_classification_legend() -> None:
    text = _read(AUDIT)
    for classification in (
        "CORE",
        "SUPPORT",
        "GOVERNED",
        "LEGACY",
        "INTERNAL-ISH",
        "CANDIDATE_FOR_ALIAS_OR_DEPRECATION",
        "OUT_OF_V2",
    ):
        assert classification in text


def test_command_surface_audit_includes_core_commands() -> None:
    text = _lower(AUDIT)
    for command in (
        "shellforgeai doctor",
        "shellforgeai model doctor",
        "shellforgeai ops report",
        "shellforgeai ops report --brief",
        "shellforgeai triage docker",
        "shellforgeai triage docker detail <target>",
        "shellforgeai diagnose <target>",
        "shellforgeai v1 check",
    ):
        assert command in text


def test_command_surface_audit_includes_artifact_families() -> None:
    text = _lower(AUDIT)
    for family in (
        "ops report save/validate/history/compare/export",
        "v1 packet save/validate/history/compare/export",
        "session summary save/validate/history/compare/export",
    ):
        assert family in text


def test_command_surface_audit_includes_governed_commands() -> None:
    text = _lower(AUDIT)
    for command in (
        "remediation eligibility",
        "remediation plan",
        "remediation validate",
        "remediation preflight",
        "remediation execute",
        "rollback-execute",
        "audit cleanup review",
        "audit cleanup plan",
        "audit cleanup archive",
        "audit cleanup validate",
        "audit cleanup execute",
    ):
        assert command in text


def test_v2_contract_includes_golden_path() -> None:
    text = _lower(CONTRACT)
    for word in ("status", "triage", "propose", "apply-preview", "verify"):
        assert word in text
    assert "approve" in text or "gate" in text
    assert "handoff" in text or "receipt" in text


def test_v2_contract_states_safety_rules() -> None:
    text = _lower(CONTRACT)
    for phrase in (
        "no natural-language mutation",
        "no arbitrary shell execution",
        "read-only by default",
    ):
        assert phrase in text


def test_v2_contract_states_non_goals() -> None:
    text = _lower(CONTRACT)
    assert "broad autonomous remediation is out of v2" in text
    assert "gui/dashboard/platform expansion is out of scope" in text


def test_dangerous_commands_are_not_casual_v2_golden_path_commands() -> None:
    docs = {
        AUDIT: _read(AUDIT),
        CONTRACT: _read(CONTRACT),
    }
    dangerous = (
        "docker restart",
        "docker compose restart",
        "cleanup execute --confirm",
        "remediation execute --confirm",
        "rollback-execute --confirm",
    )
    governed_context = (
        "governed",
        "non-goal",
        "non-goals",
        "refused",
        "out_of_v2",
        "not golden path",
        "not v2 golden-path",
        "dangerous",
        "gated",
        "out of scope",
    )
    casual_context = ("core |", "| core |", "golden path command", "first pressure-mode")

    for path, text in docs.items():
        lines = text.splitlines()
        for idx, raw_line in enumerate(lines):
            line = raw_line.lower()
            for token in dangerous:
                if token not in line:
                    continue
                window = "\n".join(lines[max(0, idx - 2) : idx + 3]).lower()
                assert not any(casual in window for casual in casual_context), (
                    f"dangerous token presented casually in {path}: {token} | {raw_line!r}"
                )
                assert any(context in window for context in governed_context), (
                    f"dangerous token lacks governed/non-goal/refused context in {path}: "
                    f"{token} | {raw_line!r}"
                )
