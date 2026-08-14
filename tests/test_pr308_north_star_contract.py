"""Semantic guardrails for the evidence-backed operator-guidance contract."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVE_DOCS = (
    "README.md",
    "docs/north-star.md",
    "docs/roadmap.md",
    "docs/PRODUCT_STATUS.md",
    "docs/v1-scope.md",
    "docs/safety.md",
)
LIFECYCLE = (
    "Observe",
    "Investigate",
    "Diagnose",
    "Plan",
    "Recommend",
    "Validate",
    "Report",
    "Handoff",
)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_north_star_defines_the_ordered_primary_workflow() -> None:
    text = read("docs/north-star.md")
    cursor = -1
    for stage in LIFECYCLE:
        cursor = text.find(stage, cursor + 1)
        assert cursor >= 0, f"missing or out-of-order stage: {stage}"


def test_solution_contract_is_operator_ready_and_validation_is_non_executing() -> None:
    text = read("docs/north-star.md").casefold()
    for concept in (
        "exact target",
        "evidence and provenance",
        "ordered procedure",
        "verification criteria",
        "rollback or recovery guidance",
        "limitations",
        "remaining risk",
        "does not execute the procedure",
    ):
        assert concept in text


def test_reasoning_pipeline_and_model_boundary_are_explicit() -> None:
    architecture = read("docs/architecture.md").casefold()
    for concept in (
        "platform routing",
        "typed collectors",
        "evidence and provenance",
        "deterministic assessment and ranking",
        "evidence-grounded model synthesis",
        "solution/runbook generation",
        "reports and handoff",
        "validation and policy",
    ):
        assert concept in architecture
    assert "it does not execute tools" in architecture
    assert "ends with an operator-ready handoff" in architecture
    assert "not a second product lifecycle or the product destination" in architecture
    assert "future execution preflight" not in architecture
    assert "future approved implementation" not in architecture
    assert (
        "cli → collectors → triage → ops reports → artifacts → governed remediation"
        not in architecture
    )


def test_current_platform_and_maturity_truth_remain() -> None:
    status = read("docs/PRODUCT_STATUS.md").casefold()
    for concept in (
        "v1 is released",
        "early beta-quality",
        "linux/docker is the supported v1 core",
        "windows support is preview/early support",
    ):
        assert concept in status


def test_governed_execution_is_compatibility_not_primary_workflow() -> None:
    for path in ACTIVE_DOCS:
        text = read(path).casefold()
        assert "compatibility/testing surfaces" in text, path
        assert "outside the primary recommended workflow" in text, path


def test_active_docs_link_to_canonical_direction() -> None:
    for path in ("README.md", "docs/PRODUCT_STATUS.md", "docs/v1-scope.md", "docs/safety.md"):
        assert "north-star.md" in read(path), path
    assert "docs/roadmap.md" in read("README.md")
