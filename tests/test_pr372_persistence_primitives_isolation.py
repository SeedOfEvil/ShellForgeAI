"""PR372 ownership regressions for shared persistence primitives."""

import ast
from pathlib import Path

from shellforgeai.core import approved_change_approval_persistence as approval
from shellforgeai.core import operator_solution_artifact_persistence as operator_solution
from shellforgeai.core import persistence_primitives as primitives


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }


def test_neutral_authority_imports_no_artifact_domain():
    path = Path("src/shellforgeai/core/persistence_primitives.py")
    imports = _imported_modules(path)
    assert not any("approved_change" in module for module in imports)
    assert not any("operator_solution" in module for module in imports)


def test_operator_solution_has_no_approval_persistence_dependency():
    path = Path("src/shellforgeai/core/operator_solution_artifact_persistence.py")
    source = path.read_text(encoding="utf-8")
    assert "approved_change_approval_persistence" not in source
    assert "shellforgeai.core.persistence_primitives" in _imported_modules(path)


def test_domains_share_the_neutral_atomic_implementation(monkeypatch, tmp_path):
    assert operator_solution.atomic_no_replace_approval_directory_publish is (
        primitives.atomic_no_replace_directory_publish
    )
    expected = primitives.AtomicNoReplaceOutcome("unsupported", "test")
    monkeypatch.setattr(approval, "_atomic_publish", lambda source, destination: expected)
    assert (
        approval.atomic_no_replace_approval_directory_publish(
            tmp_path / "source", tmp_path / "destination"
        )
        is expected
    )
    assert approval.AtomicNoReplaceOutcome is primitives.AtomicNoReplaceOutcome
