"""PR257 — README product-positioning guardrails."""

from __future__ import annotations

import re
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

    assert "cli-first operator assistant" in opening
    assert "evidence-backed operator guidance" in opening
    workflow = "observe → investigate → diagnose → plan → recommend → validate → report → handoff"
    assert workflow in opening
    assert "linux/docker is the released v1 core" in opening


def test_readme_names_operator_capabilities_near_top() -> None:
    opening = _lower()[:5000]

    capability_terms = [
        "observe",
        "evidence",
        "diagnose",
        "rank",
        "plan",
        "recommend",
        "validate",
        "report",
        "handoff",
        "linux/docker",
    ]
    assert sum(term in opening for term in capability_terms) >= 8


def test_readme_preserves_read_only_and_confirm_gated_mutation_model() -> None:
    readme = _lower()

    assert "read-only by default" in readme
    assert "named, narrow, auditable governed recipes and workflows" in readme
    assert "explicit operator confirmation" in readme
    assert "deterministic mutation refusal" in readme
    assert "unsafe broad or mutation-shaped asks" in readme
    assert "operator control" in readme


def test_readme_does_not_claim_autonomous_or_natural_language_execution() -> None:
    readme = _lower()

    forbidden_positive_claims = [
        r"(?:provides|performs|supports|offers) autonomous cleanup",
        r"(?:provides|performs|supports|offers) autonomous self-healing",
        r"(?:is|provides|operates as) self-healing production infrastructure",
        r"(?:provides|performs|supports|offers) automatic remediation",
        r"(?:provides|performs|supports|offers) automatic rollback",
        r"(?:provides|performs|supports|offers) automatic recovery",
    ]

    for claim in forbidden_positive_claims:
        assert re.search(claim, readme) is None

    assert "never acts as autonomous self-healing infrastructure" in readme
    assert "natural-language and model output is advisory only" in readme
    assert "never becomes execution authority" in readme


def test_readme_balances_capability_and_safety_language() -> None:
    opening = _lower()[:7000]

    capability_terms = [
        "observe",
        "evidence",
        "diagnose",
        "rank",
        "plan",
        "recommend",
        "report",
        "handoff",
        "validate",
    ]
    safety_terms = [
        "read-only",
        "deterministic mutation refusal",
        "operator control",
        "named, narrow, auditable governed",
        "explicit operator confirmation",
        "advisory only",
        "never acts as autonomous self-healing",
    ]

    assert sum(term in opening for term in capability_terms) >= 8
    assert sum(term in opening for term in safety_terms) >= 6
