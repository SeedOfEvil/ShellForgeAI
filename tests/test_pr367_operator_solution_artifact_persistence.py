"""Focused tests for deterministic canonical OperatorSolution persistence."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path

import pytest
from test_pr358_operator_solution_contract import make_solution, solution_data

from shellforgeai.core import operator_solution_artifact_persistence as persistence
from shellforgeai.core.operator_solution import (
    OperatorSolution,
    canonical_operator_solution_json,
    render_operator_solution_markdown,
)


def test_preparation_identity_is_full_deterministic_distinct_and_non_circular() -> None:
    solution = make_solution()
    first = persistence.prepare_operator_solution_artifact(solution)
    reordered = OperatorSolution.model_validate(dict(reversed(tuple(solution_data().items()))))
    second = persistence.prepare_operator_solution_artifact(reordered)
    digest = hashlib.sha256(first.canonical_json.encode()).hexdigest()
    assert first == second
    assert first.artifact_id == f"osol_{digest}"
    assert len(first.artifact_id) == 69
    assert first.artifact_id != solution.solution_id
    assert first.artifact_id not in first.canonical_json
    assert "artifact_id" not in json.loads(first.canonical_json)


def test_publish_exact_content_load_and_existing_noop(tmp_path: Path, monkeypatch) -> None:
    solution = make_solution()
    calls = 0
    original = persistence.atomic_no_replace_approval_directory_publish

    def observed(source: Path, destination: Path):
        nonlocal calls
        calls += 1
        assert not destination.exists()
        assert sorted(item.name for item in source.iterdir()) == sorted(
            [
                persistence.OPERATOR_SOLUTION_JSON_FILENAME,
                persistence.OPERATOR_SOLUTION_MARKDOWN_FILENAME,
            ]
        )
        return original(source, destination)

    monkeypatch.setattr(persistence, "atomic_no_replace_approval_directory_publish", observed)
    first = persistence.publish_operator_solution_artifact(solution, data_dir=tmp_path)
    assert first.status == "published", first.errors
    assert calls == 1
    directory = tmp_path / "operator_solutions" / first.artifact_id
    json_path = directory / "operator-solution.json"
    markdown_path = directory / "operator-solution.md"
    assert json_path.read_text() == canonical_operator_solution_json(solution)
    assert markdown_path.read_text() == render_operator_solution_markdown(solution)
    assert set(json.loads(json_path.read_text())) == set(solution.model_dump())
    before = (
        json_path.stat().st_mtime_ns,
        markdown_path.stat().st_mtime_ns,
        directory.stat().st_mtime_ns,
    )
    loaded = persistence.load_persisted_operator_solution_artifact(tmp_path, first.artifact_id)
    assert loaded.status == "loaded"
    assert loaded.solution == solution
    assert loaded.total_bytes_read == len(json_path.read_bytes()) + len(markdown_path.read_bytes())
    second = persistence.publish_operator_solution_artifact(solution, data_dir=tmp_path)
    assert second.status == "already_present"
    assert second.existing_identical_no_op
    assert calls == 1
    assert before == (
        json_path.stat().st_mtime_ns,
        markdown_path.stat().st_mtime_ns,
        directory.stat().st_mtime_ns,
    )


@pytest.mark.parametrize("filename", ["operator-solution.json", "operator-solution.md"])
def test_missing_file_conflicts_without_repair(tmp_path: Path, filename: str) -> None:
    solution = make_solution()
    first = persistence.publish_operator_solution_artifact(solution, data_dir=tmp_path)
    path = tmp_path / "operator_solutions" / first.artifact_id / filename
    path.unlink()
    result = persistence.publish_operator_solution_artifact(solution, data_dir=tmp_path)
    assert result.status == "conflict"
    assert not path.exists()


@pytest.mark.parametrize("kind", ["json", "markdown", "noncanonical_json", "wrong_identity"])
def test_tampering_fails_closed(tmp_path: Path, kind: str) -> None:
    solution = make_solution()
    result = persistence.publish_operator_solution_artifact(solution, data_dir=tmp_path)
    directory = tmp_path / "operator_solutions" / result.artifact_id
    json_path = directory / "operator-solution.json"
    markdown_path = directory / "operator-solution.md"
    if kind == "json":
        json_path.write_text("{")
    elif kind == "markdown":
        markdown_path.write_text("tampered")
    elif kind == "noncanonical_json":
        json_path.write_text(json.dumps(json.loads(json_path.read_text()), indent=2))
    else:
        json_path.write_text(canonical_operator_solution_json(make_solution(target="other target")))
    loaded = persistence.load_persisted_operator_solution_artifact(tmp_path, result.artifact_id)
    assert loaded.status == "invalid"
    assert loaded.solution is None


def test_partial_and_extra_destinations_fail_closed(tmp_path: Path) -> None:
    artifact = persistence.prepare_operator_solution_artifact(make_solution())
    directory = tmp_path / "operator_solutions" / artifact.artifact_id
    directory.mkdir(parents=True)
    (directory / "extra").write_text("unsafe")
    assert (
        persistence.load_persisted_operator_solution_artifact(tmp_path, artifact.artifact_id).status
        == "invalid"
    )
    assert (
        persistence.publish_operator_solution_artifact(artifact.solution, data_dir=tmp_path).status
        == "conflict"
    )
    assert (directory / "extra").exists()


@pytest.mark.parametrize(
    "artifact_id",
    [
        "",
        "osol_deadbeef",
        "wrong_" + "0" * 64,
        "osol_" + "A" * 64,
        "osol_" + "g" * 64,
        "osol_" + "0" * 64 + "x",
        "../osol_" + "0" * 64,
        "/osol_" + "0" * 64,
        "osol_\\" + "0" * 64,
        "..",
    ],
)
def test_invalid_exact_ids_are_rejected_before_filesystem_access(
    tmp_path: Path, artifact_id: str
) -> None:
    result = persistence.load_persisted_operator_solution_artifact(tmp_path, artifact_id)
    assert result.status == "invalid_id"
    assert not result.filesystem_accessed


def test_symlink_root_directory_and_file_are_refused(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "operator_solutions"
    root.symlink_to(outside, target_is_directory=True)
    artifact = persistence.prepare_operator_solution_artifact(make_solution())
    assert (
        persistence.load_persisted_operator_solution_artifact(tmp_path, artifact.artifact_id).status
        == "load_blocked"
    )
    root.unlink()
    published = persistence.publish_operator_solution_artifact(artifact.solution, data_dir=tmp_path)
    directory = root / published.artifact_id
    json_path = directory / "operator-solution.json"
    json_path.unlink()
    json_path.symlink_to(outside / "missing")
    assert (
        persistence.load_persisted_operator_solution_artifact(
            tmp_path, published.artifact_id
        ).status
        == "invalid"
    )
    other = root / ("osol_" + "0" * 64)
    other.symlink_to(directory, target_is_directory=True)
    assert persistence.load_persisted_operator_solution_artifact(tmp_path, other.name).status in {
        "invalid",
        "load_blocked",
    }


def test_module_has_no_operational_dependencies() -> None:
    source = Path(persistence.__file__).read_text()
    imports = {
        node.module or ""
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    }
    forbidden = (
        "collect",
        "provider",
        "routing",
        "subprocess",
        "docker",
        "powershell",
        "operator_solution_builder",
        "windows_operator_solution_builder",
    )
    assert not any(token in module for module in imports for token in forbidden)
