"""PR257 — README product-positioning guardrails."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _lower() -> str:
    return _readme().lower()


def test_readme_leads_with_cli_first_operator_positioning() -> None:
    readme = _lower()
    opening = readme[:3500]

    assert (
        "cli-first linux/docker operator knife" in opening
        or "cli-first linux/docker operator tooling" in opening
    )
    assert "what it helps with" in opening
    assert "operating model" in opening
    assert "evidence-backed" in opening and ("triage" in opening or "reports" in opening)


def test_readme_names_operator_capabilities_near_top() -> None:
    opening = _lower()[:5000]

    assert "docker/linux state" in opening or "linux/docker state" in opening
    assert "suspect ranking" in opening or "likely suspects" in opening
    assert any(
        token in opening
        for token in ["auditable receipts", "auditable reports", "manifests", "handoff"]
    )
    assert "2am" in opening or "what should i check first" in opening
    assert "validation-lane" in opening or "validation lane" in opening


def test_readme_preserves_read_only_and_confirm_gated_mutation_model() -> None:
    readme = _lower()

    assert "read-only by default" in readme
    assert "named, narrow, auditable recipes" in readme
    assert "explicit confirmation" in readme
    assert "refuses unsafe broad mutation" in readme or "refuse unsafe broad mutation" in readme
    assert "safe read-only next" in readme


def test_readme_does_not_claim_autonomous_or_natural_language_execution() -> None:
    readme = _lower()

    forbidden_claims = [
        "autonomous cleanup",
        "autonomous self-healing",
        "self-healing production infrastructure",
        "automatic remediation",
        "automatic rollback",
        "automatic recovery",
    ]

    for claim in forbidden_claims:
        assert claim not in readme

    assert "not autonomous self-healing" in readme or "not self-healing infrastructure" in readme
    assert (
        "no natural-language command execution" in readme
        or "not a natural-language mutation agent" in readme
    )


def test_readme_balances_capability_and_safety_language() -> None:
    opening = _lower()[:7000]

    capability_terms = [
        "inspect",
        "rank",
        "report",
        "receipts",
        "manifests",
        "handoff",
        "validation",
        "diagnostic",
    ]
    safety_terms = [
        "read-only",
        "refuse",
        "named, narrow, auditable",
        "explicit confirmation",
        "safe read-only next",
    ]

    assert sum(term in opening for term in capability_terms) >= 6
    assert sum(term in opening for term in safety_terms) >= 4
