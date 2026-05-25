from __future__ import annotations

from pathlib import Path

DOC = Path("docs/V1_COMMAND_SURFACE.md")
README = Path("README.md")
V1_SCOPE = Path("docs/v1-scope.md")
SAFETY = Path("docs/safety.md")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _lower(path: Path) -> str:
    return _text(path).lower()


def _section(text: str, heading: str) -> str:
    marker = f"## {heading}"
    start = text.find(marker)
    assert start >= 0, f"missing section: {heading}"
    rest = text[start + len(marker) :]
    end = rest.find("\n## ")
    return rest[:end] if end >= 0 else rest


def test_v1_command_surface_doc_exists() -> None:
    assert DOC.exists()


def test_docs_link_to_v1_command_surface() -> None:
    assert "docs/V1_COMMAND_SURFACE.md" in _text(README)
    assert "V1_COMMAND_SURFACE.md" in _text(V1_SCOPE)
    assert "V1_COMMAND_SURFACE.md" in _text(SAFETY)


def test_v1_command_surface_defines_required_safety_classes() -> None:
    text = _text(DOC)
    for cls in (
        "READ_ONLY",
        "ARTIFACT_WRITE",
        "GOVERNED_PLAN_ONLY",
        "GOVERNED_DISPOSABLE_MUTATION",
        "REFUSED_BY_DEFAULT",
        "OUT_OF_V1",
    ):
        assert cls in text


def test_v1_command_surface_includes_core_commands() -> None:
    text = _lower(DOC)
    for cmd in (
        "shellforgeai version",
        "shellforgeai doctor",
        "shellforgeai model doctor",
        "shellforgeai v1 check",
        "shellforgeai ops report",
        "shellforgeai triage docker",
        "shellforgeai remediation eligibility",
    ):
        assert cmd in text


def test_v1_command_surface_includes_artifact_commands() -> None:
    text = _lower(DOC)
    for cmd in (
        "shellforgeai ops report --save",
        "shellforgeai ops report validate",
        "shellforgeai ops report history",
        "shellforgeai ops report compare-latest",
        "shellforgeai ops report export",
        "shellforgeai ops report export-validate",
    ):
        assert cmd in text


def test_v1_command_surface_includes_deterministic_ask_routes() -> None:
    text = _lower(DOC)
    for needle in ("2am operator report", "what is on fire", "mutation refusal"):
        assert needle in text


def test_v1_command_surface_has_out_of_scope_statements() -> None:
    text = _lower(DOC)
    assert "production remediation is not v1" in text
    assert "docker compose" in text and "out of v1" in text
    assert "arbitrary shell execution" in text
    assert "shell=true" in text


def test_execute_and_rollback_are_governed_disposable_only() -> None:
    text = _lower(DOC)
    assert "remediation execute --execute --confirm" in text
    assert "remediation rollback-execute --execute --confirm" in text
    assert (
        "governed_disposable_mutation" in text
        or "governed_disposable_mutation" in _text(DOC).lower()
        or "governed_disposable_mutation".replace("_", "-") in text
    )
    assert "not casual v1 demo path" in text


def test_v1_demo_safe_path_omits_dangerous_commands() -> None:
    safe = _section(_text(DOC), "V1 demo safe path").lower()
    forbidden = (
        "docker restart",
        "docker compose restart",
        "docker compose up",
        "docker compose down",
        "docker system prune",
        "docker volume prune",
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "cleanup execute --confirm",
    )
    for token in forbidden:
        assert token not in safe
