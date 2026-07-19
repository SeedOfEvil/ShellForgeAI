"""PR308 north-star lifecycle and implementation-boundary guardrails."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVE_DOCS = [
    Path("README.md"),
    Path("docs/north-star.md"),
    Path("docs/roadmap.md"),
    Path("docs/PRODUCT_STATUS.md"),
    Path("docs/v1-scope.md"),
    Path("docs/safety.md"),
]
LIFECYCLE = [
    "Understand",
    "Investigate",
    "Diagnose",
    "Propose",
    "Obtain approval",
    "Implement",
    "Verify",
    "Report",
]


def read(path: Path) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def assert_ordered(text: str, tokens: list[str]) -> None:
    cursor = -1
    lowered = text.lower()
    for token in tokens:
        found = lowered.find(token.lower(), cursor + 1)
        assert found > cursor, f"missing or out of order token: {token}"
        cursor = found


def test_north_star_is_canonical_final_state_contract() -> None:
    path = ROOT / "docs/north-star.md"
    assert path.exists()
    text = read(Path("docs/north-star.md"))
    lowered = text.lower()
    assert "canonical permanent final-state product contract" in lowered
    for phrase in (
        "shellforgeai",
        "one interactive cli",
        "operator intent",
        "evidence-backed plan, procedure, solution, or fix",
        "explicit operator approval",
        "bounded change",
        "verify the outcome",
        "report it",
    ):
        assert phrase in lowered


def test_lifecycle_appears_in_exact_order_and_stages_are_defined() -> None:
    text = read(Path("docs/north-star.md"))
    assert_ordered(text, LIFECYCLE)
    for phrase in (
        "evidence before recommendation",
        "exact target",
        "proposed change",
        "expected impact",
        "ordered procedure",
        "preconditions",
        "current-state gates",
        "approval identity",
        "verification criteria",
        "rollback or recovery awareness",
        "audit and receipt requirements",
        "factual",
    ):
        assert phrase in text.lower()


def test_implementation_boundary_blocks_arbitrary_execution() -> None:
    text = read(Path("docs/north-star.md")).lower()
    for phrase in (
        "implementation is part of the product promise",
        "only the specific solution it developed with the operator",
        "exact, reviewable, explicitly approved, bounded, and auditable change",
        "natural-language approval alone never becomes an executable command",
        "approval does not bypass capability support",
        "safety gates",
        "preconditions",
        "state revalidation",
        "verification requirements",
        "unsupported actions",
        "changed targets",
        "materially changed conditions block implementation",
    ):
        assert phrase in text


def test_permanent_exclusions_and_one_cli_definition_are_present() -> None:
    text = read(Path("docs/north-star.md")).lower()
    for phrase in (
        "no dashboard",
        "no autonomous background control plane",
        "no general-purpose shell",
        "no arbitrary natural-language execution",
        "no broad infrastructure orchestration or management platform",
        "no competing user interface",
        "one coherent shellforgeai cli product",
        "supported deterministic subcommands",
        "does not require removing deterministic subcommands",
    ):
        assert phrase in text


def test_roadmap_stages_and_current_final_state_distinction() -> None:
    text = read(Path("docs/roadmap.md"))
    lowered = text.lower()
    assert_ordered(
        text, ["Current product", "Stage A", "Stage B", "Stage C", "Stage D", "Final state"]
    )
    assert "complete final-state lifecycle is not yet implemented" in lowered
    assert "does not design schemas" in lowered
    assert "avoid generic mutation machinery" in lowered


def test_current_status_and_v1_scope_truth_remain() -> None:
    status = read(Path("docs/PRODUCT_STATUS.md")).lower()
    for phrase in (
        "v1 released",
        "early beta-quality",
        "linux/docker",
        "primary",
        "windows",
        "preview/early support",
    ):
        assert phrase in status
    v1 = read(Path("docs/v1-scope.md")).lower()
    for phrase in (
        "read-only by default",
        "natural-language mutation requests are deterministically refused",
        "production mutation is not part of the v1 release promise",
        "v1 is the released foundation, not the complete final-state lifecycle",
    ):
        assert phrase in v1


def test_active_documents_link_to_canonical_direction_without_full_duplication() -> None:
    for path in (
        Path("README.md"),
        Path("docs/PRODUCT_STATUS.md"),
        Path("docs/v1-scope.md"),
        Path("docs/safety.md"),
    ):
        assert "north-star.md" in read(path), f"missing north-star link in {path}"
    assert "docs/roadmap.md" in read(Path("README.md"))

    lifecycle_line = (
        "Understand → Investigate → Diagnose → Propose → Obtain approval → "
        "Implement → Verify → Report"
    )
    copies = [path for path in ACTIVE_DOCS if lifecycle_line in read(path)]
    assert copies == [
        Path("README.md"),
        Path("docs/north-star.md"),
        Path("docs/roadmap.md"),
    ]


def test_active_allowlist_excludes_archives_and_release_notes() -> None:
    assert Path("docs/archive/PROJECT_HISTORY.md") not in ACTIVE_DOCS
    assert Path("docs/V1_RELEASE_NOTES.md") not in ACTIVE_DOCS
    for path in ACTIVE_DOCS:
        assert (ROOT / path).exists()
