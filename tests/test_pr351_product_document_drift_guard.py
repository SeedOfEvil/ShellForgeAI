"""Guard canonical ownership and active product-document alignment."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8").casefold()


def require(path: str, *concepts: str) -> None:
    document = text(path)
    for concept in concepts:
        assert concept.casefold() in document, f"{path} missing {concept!r}"


def test_product_status_owns_maturity_and_platform_truth() -> None:
    require(
        "docs/PRODUCT_STATUS.md",
        "canonical active maturity source",
        "v1 is released",
        "early beta-quality",
        "linux/docker is the supported v1 core",
        "windows support is preview/early support",
        "not production-autonomous",
    )


def test_v1_scope_owns_release_and_safety_boundary() -> None:
    require(
        "docs/v1-scope.md",
        "v1 is the released foundation",
        "linux/docker is the primary supported v1 lane",
        "read-only by default",
        "natural-language mutation requests are deterministically refused",
        "apply` remains validation-only",
    )


def test_readme_is_affirmative_and_has_no_negative_identity_section() -> None:
    require(
        "README.md",
        "evidence-backed operator guidance",
        "operator-ready guidance",
        "evidence and model reasoning",
        "quick start",
        "install",
        "platforms",
    )
    assert "## what this is not" not in text("README.md")


def test_roadmap_is_outcome_based_and_preserves_canonical_ownership() -> None:
    require(
        "docs/roadmap.md",
        "organized by operator outcomes, not pr chronology",
        "product status](product_status.md) owns current maturity",
        "v1 scope](v1-scope.md) owns the released v1 contract",
        "safety](safety.md) owns current safety",
        "north star](north-star.md)",
        "avoid generic mutation machinery",
    )


def test_active_contract_preserves_governed_surface_classification() -> None:
    for path in (
        "README.md",
        "docs/north-star.md",
        "docs/roadmap.md",
        "docs/PRODUCT_STATUS.md",
        "docs/v1-scope.md",
        "docs/safety.md",
    ):
        require(path, "compatibility/testing surfaces", "outside the primary recommended workflow")
