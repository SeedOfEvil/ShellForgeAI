"""Guard the semantic contracts owned by ShellForgeAI's active product docs."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = {
    "README.md": REPO_ROOT / "README.md",
    "docs/PRODUCT_STATUS.md": REPO_ROOT / "docs/PRODUCT_STATUS.md",
    "docs/v1-scope.md": REPO_ROOT / "docs/v1-scope.md",
    "docs/safety.md": REPO_ROOT / "docs/safety.md",
    "docs/roadmap.md": REPO_ROOT / "docs/roadmap.md",
    "docs/north-star.md": REPO_ROOT / "docs/north-star.md",
}


def _read(document: str) -> str:
    return DOCUMENTS[document].read_text(encoding="utf-8").casefold()


def _require_all(document: str, contract: str, *concepts: str) -> None:
    text = _read(document)
    for concept in concepts:
        assert concept.casefold() in text, (
            f"{document} drifted: {contract}; missing concept {concept!r}"
        )


def _require_any(document: str, contract: str, *alternatives: str) -> None:
    text = _read(document)
    assert any(alternative.casefold() in text for alternative in alternatives), (
        f"{document} drifted: {contract}; missing one of {alternatives!r}"
    )


def _forbid(document: str, contract: str, *concepts: str) -> None:
    text = _read(document)
    for concept in concepts:
        assert concept.casefold() not in text, (
            f"{document} drifted: {contract}; forbidden concept {concept!r}"
        )


def test_product_status_owns_current_maturity_and_platform_support() -> None:
    document = "docs/PRODUCT_STATUS.md"
    _require_all(
        document,
        "current maturity must remain V1 released, early beta-quality, and guarded",
        "canonical active maturity source",
        "v1 released",
        "early beta-quality",
        "guarded",
        "not production-autonomous",
    )
    _require_any(
        document,
        "Linux/Docker must remain the primary supported V1 operating lane",
        "linux/docker is the supported v1 core",
        "linux/docker is the primary supported v1 lane",
        "linux/docker is the primary v1 lane",
    )
    _require_any(
        document,
        "Windows must remain preview/early support",
        "windows support: preview/early support",
        "windows support is preview/early support",
        "windows remains preview/early support",
    )
    _require_all(
        document,
        "current maturity must remain separate from the final-state North Star",
        "current maturity describes the product available today",
        "north star",
        "not a claim that every approved solution is currently executable",
    )


def test_v1_scope_owns_the_released_foundation_contract() -> None:
    document = "docs/v1-scope.md"
    _require_all(
        document,
        "V1 must remain the released foundation rather than the complete final-state lifecycle",
        "v1 is released",
        "v1 is the released foundation",
        "not the complete final-state lifecycle",
    )
    _require_any(
        document,
        "North Star must remain the owner of final-state direction",
        "north star",
        "north-star.md",
    )
    _require_any(
        document,
        "Linux/Docker must remain the primary supported V1 lane",
        "linux/docker is the primary supported v1 lane",
        "linux/docker is the supported v1 core",
    )
    _require_all(
        document,
        "V1 mutation boundaries must remain read-only by default and governed",
        "read-only by default",
        "natural-language mutation requests are deterministically refused",
        "governed mutation lanes are explicit, gated",
        "no autonomous production remediation",
    )


def test_safety_owns_current_refusal_and_mutation_boundaries() -> None:
    document = "docs/safety.md"
    _require_all(
        document,
        "current safety must remain read-only by default with deterministic refusal",
        "read-only by default",
        "natural-language mutation requests are refused deterministically",
        "no arbitrary command execution from prompts",
        "governed remediation lanes are explicit and gated",
        "no autonomous production remediation",
    )
    _require_any(
        document,
        "arbitrary shell and natural-language execution must remain prohibited",
        "no natural-language execution, no arbitrary command execution",
        "no arbitrary shell, arbitrary powershell, or arbitrary command execution",
        "does not run arbitrary shell",
    )
    _require_all(
        document,
        "future implementation must remain bounded rather than raw natural-language execution",
        "future approved implementation",
        "supported, typed, bounded implementation",
        "not raw natural-language or arbitrary command execution",
    )


def test_roadmap_owns_staged_delivery_without_redefining_current_contracts() -> None:
    document = "docs/roadmap.md"
    _require_all(
        document,
        "Roadmap must remain forward-looking staged delivery with canonical ownership",
        "active roadmap is forward-looking",
        "product status owns current maturity",
        "v1 scope owns the released v1 contract",
        "safety owns current safety and mutation rules",
        "this roadmap owns staged delivery",
        "permanent final-state product contract is defined in [north star]",
    )
    _require_all(
        document,
        "the Stage A canonical-document drift guard must remain complete",
        "## stage a — product contract",
        "[x] maintain a semantic documentation drift guard",
        "without changing runtime behavior",
    )


def test_north_star_owns_final_state_without_overstating_current_v1() -> None:
    document = "docs/north-star.md"
    _require_all(
        document,
        "North Star must remain the permanent final-state contract",
        "canonical permanent final-state product contract",
        "current maturity",
        "product status",
        "current released scope",
        "v1 scope",
        "current safety and mutation rules",
        "safety",
    )
    _require_all(
        document,
        "future implementation must remain exact, bounded, and explicitly approved",
        "exact, reviewable, explicitly approved, bounded, and auditable change",
        "supported implementation capability",
    )
    _require_all(
        document,
        "final-state implementation must remain separated from current V1 maturity",
        "final-state contract, not a claim that every stage is universally implemented today",
        "v1 is the released foundation",
        "not the complete final-state lifecycle",
    )
    _require_all(
        document,
        "natural-language or model output must never directly become executable",
        "free-form model output",
        "natural-language approval alone never becomes an executable command",
        "does not authorize arbitrary shell",
        "no general-purpose shell",
        "no arbitrary natural-language execution",
    )


def test_readme_projects_canonical_facts_without_claiming_authority() -> None:
    document = "README.md"
    _require_all(
        document,
        "public positioning must remain CLI-first, guarded, and operator-controlled",
        "cli-first linux/docker operator tooling",
        "guarded",
        "operator-controlled",
        "not production-autonomous",
    )
    _require_any(
        document,
        "Linux/Docker must remain the primary supported V1 lane",
        "linux/docker is the primary v1 lane",
        "linux/docker: primary supported v1 operating lane",
    )
    _require_any(
        document,
        "public positioning must not promote Windows above preview/early support",
        "windows support is preview/early support",
        "windows: preview/early support",
    )
    _require_all(
        document,
        "public mutation positioning must preserve read-only and refusal boundaries",
        "read-only by default",
        "mutation-shaped asks are refused",
        "refuses unsafe broad mutation",
        "not a natural-language mutation agent",
    )
    _forbid(
        document,
        "README must remain a projection rather than a competing canonical authority",
        "readme owns current maturity",
        "readme owns the released v1 contract",
        "readme owns current safety",
        "windows is the primary supported v1 lane",
        "production-autonomous operator",
    )
