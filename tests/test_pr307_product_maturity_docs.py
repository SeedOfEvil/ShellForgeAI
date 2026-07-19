"""PR307 product maturity documentation guardrails."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ACTIVE_DOCS = [
    Path("README.md"),
    Path("docs/PRODUCT_STATUS.md"),
    Path("docs/north-star.md"),
    Path("docs/safety.md"),
    Path("docs/v1-scope.md"),
    Path("docs/WINDOWS_POWERSHELL_V1.md"),
    Path("docs/codex-integration.md"),
    Path("docs/container-smoke-test.md"),
    Path("docs/profiles.md"),
    Path("docs/roadmap.md"),
    Path("OPS.md"),
]

README_LINKED_DOCS = [
    Path("docs/PRODUCT_STATUS.md"),
    Path("docs/demo.md"),
    Path("docs/cli.md"),
    Path("docs/safety.md"),
    Path("docs/architecture.md"),
    Path("docs/WINDOWS_POWERSHELL_V1.md"),
    Path("docs/VALIDATION_MATRIX.md"),
    Path("docs/V1_RELEASE_NOTES.md"),
    Path("docs/roadmap.md"),
    Path("docs/archive/PROJECT_HISTORY.md"),
]


def read(path: Path) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_product_status_is_canonical_and_complete() -> None:
    path = ROOT / "docs/PRODUCT_STATUS.md"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    lowered = text.lower()
    for phrase in ("v1 released", "early beta-quality", "guarded", "not production-autonomous"):
        assert phrase in lowered
    assert "linux/docker" in lowered and "primary" in lowered and "v1" in lowered
    assert "windows" in lowered and "preview/early support" in lowered
    assert "does not change the overall product classification" in lowered


def test_readme_status_platforms_and_required_sections() -> None:
    text = read(Path("README.md"))
    lowered = text.lower()
    assert "docs/PRODUCT_STATUS.md" in text
    assert "v1 released and early beta-quality" in lowered
    assert "linux/docker is the primary v1 lane" in lowered
    assert "windows support is preview/early support" in lowered
    required_sections = [
        "## what shellforgeai helps you accomplish",
        "## core workflows",
        "## how it works",
        "## guarded by design",
        "## install",
        "## quick start",
        "## where it runs",
        "## documentation map",
    ]
    for section in required_sections:
        assert section in lowered


def test_active_docs_do_not_use_stale_overall_alpha_wording() -> None:
    stale_patterns = [
        re.compile(r"status:\s*alpha", re.IGNORECASE),
        re.compile(r"currently\s+alpha", re.IGNORECASE),
        re.compile(r"in\s+this\s+alpha", re.IGNORECASE),
        re.compile(r"overall\s+(product\s+)?maturity\s*:\s*alpha", re.IGNORECASE),
    ]
    for path in ACTIVE_DOCS:
        text = read(path)
        for pattern in stale_patterns:
            assert not pattern.search(text), f"stale maturity wording in {path}: {pattern.pattern}"


def test_readme_links_and_repository_url_are_current() -> None:
    text = read(Path("README.md"))
    assert "https://github.com/SeedOfEvil/ShellForgeAI.git" in text
    for path in README_LINKED_DOCS:
        assert (ROOT / path).exists(), f"README-linked local doc missing: {path}"
        assert str(path).replace("docs/", "docs/", 1) in text


def test_readme_is_product_facing_not_pr_chronology() -> None:
    text = read(Path("README.md"))
    assert len(text.splitlines()) <= 500
    assert len(re.findall(r"\bPR\d+\b", text)) <= 2


def test_active_allowlist_excludes_history_and_release_notes_from_maturity_scan() -> None:
    assert Path("docs/archive/PROJECT_HISTORY.md") not in ACTIVE_DOCS
    assert Path("docs/V1_RELEASE_NOTES.md") not in ACTIVE_DOCS
