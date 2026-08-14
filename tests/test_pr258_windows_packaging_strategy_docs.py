"""PR258 — Windows/PowerShell V1 and packaging strategy docs."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WINDOWS_DOC = REPO_ROOT / "docs" / "WINDOWS_POWERSHELL_V1.md"
PACKAGING_DOC = REPO_ROOT / "docs" / "PACKAGING_STRATEGY.md"
README = REPO_ROOT / "README.md"
ROADMAP = REPO_ROOT / "docs" / "roadmap.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _lower(path: Path) -> str:
    return _read(path).lower()


def test_windows_and_packaging_docs_exist() -> None:
    assert WINDOWS_DOC.exists()
    assert PACKAGING_DOC.exists()


def test_windows_doc_defines_current_validated_preview_scope() -> None:
    doc = _lower(WINDOWS_DOC)

    assert "windows server 2025 is the validated preview environment" in doc
    assert "current evidence coverage" in doc
    assert "current command surface" in doc
    assert "evidence and provenance remain authoritative" in doc
    assert "read-only" in doc
    assert "local host evidence first" in doc
    assert "powershell availability" in doc
    assert "execution-policy context" in doc
    assert "platform, os, architecture" in doc
    assert "services" in doc and "processes" in doc
    assert "event logs" in doc or "event-log" in doc
    assert "disk" in doc and "network" in doc


def test_windows_doc_keeps_operator_control_and_governed_utility_subordinate() -> None:
    doc = _lower(WINDOWS_DOC)

    assert "arbitrary powershell execution" in doc
    assert "winrm" in doc
    assert "remote execution" in doc
    assert "service restart or mutation" in doc
    assert "remediation" in doc
    assert "rollback" in doc
    assert "recovery" in doc
    assert "governed compatibility utility" in doc
    assert "outside the primary recommended workflow" in doc
    assert "not the current product roadmap or a future execution destination" in doc


def test_windows_doc_mentions_platform_detection_and_structured_unavailable_state() -> None:
    doc = _lower(WINDOWS_DOC)

    assert "platform detection" in doc
    assert "structured status" in doc
    assert '"platform": "windows"' in doc
    assert '"read_only": true' in doc
    assert '"mutation_performed": false' in doc


def test_packaging_doc_compares_required_options() -> None:
    doc = _lower(PACKAGING_DOC)

    assert "installer/bootstrap" in doc
    assert "uv-managed runtime" in doc or "uv`-managed runtime" in doc
    assert "pyinstaller" in doc
    assert "nuitka" in doc
    assert "windows embeddable python" in doc
    assert "pipx" in doc


def test_packaging_doc_recommends_staged_non_implementation_pr258() -> None:
    doc = _lower(PACKAGING_DOC)

    assert "recommended staged approach" in doc
    assert "do not build packaged binaries in pr258" in doc
    assert "do not add installer scripts in pr258" in doc
    assert "do not fetch packages or call network in pr258" in doc
    assert "read-only default" in doc
    assert "explicit confirmation gates" in doc


def test_strategy_docs_do_not_claim_autonomous_execution_or_repair() -> None:
    combined = f"{_lower(WINDOWS_DOC)}\n{_lower(PACKAGING_DOC)}"

    forbidden_claims = [
        "autonomous self-healing is supported",
        "natural-language command execution is supported",
        "automatic remediation is supported",
        "automatic rollback is supported",
        "automatic recovery is supported",
    ]

    for claim in forbidden_claims:
        assert claim not in combined

    assert (
        "no natural-language execution" in combined
        or "no natural-language command execution" in combined
    )
    assert "no autonomous self-healing" in combined or "autonomous self-healing" in combined


def test_readme_or_roadmap_pointer_stays_concise_if_present() -> None:
    combined = f"{_lower(README)}\n{_lower(ROADMAP)}"

    if "windows/powershell v1" not in combined and "windows read-only doctor" not in combined:
        return

    assert "windows is validated preview/early support" in combined
    assert "linux/docker" in combined
    assert "read-only" in combined
