"""Focused acceptance tests for bounded OperatorSolution discovery."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from test_pr358_operator_solution_contract import make_solution
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import operator_solution_artifact_inventory as inventory
from shellforgeai.core import operator_solution_artifact_persistence as persistence


def test_absent_and_empty_root_are_complete_and_create_nothing(tmp_path: Path) -> None:
    absent = inventory.inventory_persisted_operator_solution_artifacts(tmp_path)
    assert absent.status == "operator_solution_inventory_empty"
    assert absent.inventory_complete and absent.entries == () and absent.anomalies == ()
    assert absent.mutation_performed is False and absent.execution_status == "not_executed"
    assert not (tmp_path / "operator_solutions").exists()
    (tmp_path / "operator_solutions").mkdir()
    assert inventory.inventory_persisted_operator_solution_artifacts(tmp_path).model_dump() == {
        **absent.model_dump(),
        "inventory_root_present": True,
    }


def test_valid_artifacts_use_loader_once_and_sort_only_by_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    published = [
        persistence.publish_operator_solution_artifact(
            make_solution(target=target), data_dir=tmp_path
        )
        for target in ("z-target", "a-target")
    ]
    calls: list[str] = []
    maintained = persistence.load_persisted_operator_solution_artifact

    def observed(data_dir: Path | str, artifact_id: str):
        calls.append(artifact_id)
        return maintained(data_dir, artifact_id)

    monkeypatch.setattr(inventory, "load_persisted_operator_solution_artifact", observed)
    first = inventory.inventory_persisted_operator_solution_artifacts(tmp_path)
    second = inventory.inventory_persisted_operator_solution_artifacts(tmp_path)
    expected = sorted(item.artifact_id for item in published)
    assert [item.artifact_id for item in first.entries] == expected
    assert calls == expected + expected
    assert first.model_dump() == second.model_dump()
    assert first.inventory_complete and not first.anomalies
    public = first.model_dump()
    assert not (
        {"procedure", "diagnosis_summary", "selected", "latest", "current"} & set(public)
    )


def test_unexpected_invalid_file_and_symlink_are_anomalies(tmp_path: Path) -> None:
    root = tmp_path / "operator_solutions"
    root.mkdir()
    for name in ("latest", "current", "osol_short", "OSOL_" + "a" * 64, "index.json"):
        (root / name).mkdir()
    exact_file = root / ("osol_" + "1" * 64)
    exact_file.write_text("not a directory")
    invalid = root / ("osol_" + "2" * 64)
    invalid.mkdir()
    if hasattr(os, "symlink"):
        (root / ("osol_" + "3" * 64)).symlink_to(invalid, target_is_directory=True)
    result = inventory.inventory_persisted_operator_solution_artifacts(tmp_path)
    categories = {item.entry_name: item.category for item in result.anomalies}
    assert result.status == "operator_solution_inventory_loaded_with_anomalies"
    assert not result.inventory_complete and result.entries == ()
    assert categories[exact_file.name] == "non_directory_entry"
    assert categories[invalid.name] == "invalid_operator_solution_artifact"
    assert categories["latest"] == "unexpected_name"
    if hasattr(os, "symlink"):
        assert categories["osol_" + "3" * 64] == "symlink_or_reparse_entry"


def test_fixed_bound_fails_before_any_loader_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "operator_solutions"
    root.mkdir()
    for number in range(inventory.MAX_OPERATOR_SOLUTION_INVENTORY_ENTRIES + 1):
        (root / f"unexpected-{number:04d}").mkdir()
    monkeypatch.setattr(
        inventory,
        "load_persisted_operator_solution_artifact",
        lambda *_args: pytest.fail("loader called after bound exceeded"),
    )
    result = inventory.inventory_persisted_operator_solution_artifacts(tmp_path)
    assert result.status == "operator_solution_inventory_limit_exceeded"
    assert not result.inventory_complete and result.entries == () and result.anomalies == ()
    assert result.scanned_entry_count == inventory.MAX_OPERATOR_SOLUTION_INVENTORY_ENTRIES + 1


def test_root_symlink_and_malformed_root_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "operator_solutions"
    root.write_text("not a directory")
    assert (
        inventory.inventory_persisted_operator_solution_artifacts(tmp_path).status
        == "operator_solution_inventory_blocked"
    )
    root.unlink()
    if not hasattr(os, "symlink"):
        return
    outside = tmp_path / "outside"
    outside.mkdir()
    root.symlink_to(outside, target_is_directory=True)
    assert (
        inventory.inventory_persisted_operator_solution_artifacts(tmp_path).status
        == "operator_solution_inventory_blocked"
    )


def test_uninspectable_root_is_blocked_without_loader_write_or_path_leakage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "operator_solutions"
    root.mkdir()
    before = tuple(tmp_path.rglob("*"))
    maintained_lstat = inventory.os.lstat
    injected_path = str(root / "private-injected-name")
    loader_calls = 0

    def blocked_root_probe(path: Path | str):
        if Path(path) == root:
            raise PermissionError(13, "permission denied", injected_path)
        return maintained_lstat(path)

    def observed_loader(*_args):
        nonlocal loader_calls
        loader_calls += 1
        pytest.fail("candidate loader called after blocked root probe")

    monkeypatch.setattr(inventory.os, "lstat", blocked_root_probe)
    monkeypatch.setattr(inventory, "load_persisted_operator_solution_artifact", observed_loader)

    result = inventory.inventory_persisted_operator_solution_artifacts(tmp_path)
    public = result.model_dump_json()

    assert result.status == "operator_solution_inventory_blocked"
    assert result.inventory_complete is False
    assert result.valid_entry_count == 0 and result.entries == ()
    assert result.anomaly_count == 0 and result.anomalies == ()
    assert loader_calls == 0
    assert tuple(tmp_path.rglob("*")) == before
    assert result.read_only is True and result.mutation_performed is False
    assert result.execution_status == "not_executed"
    assert "traceback" not in public.casefold()
    assert str(tmp_path) not in public
    assert injected_path not in public


def test_human_and_json_cli_are_bounded_and_path_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    published = persistence.publish_operator_solution_artifact(make_solution(), data_dir=tmp_path)
    runner = CliRunner()
    human = runner.invoke(app, ["handoff", "operator-solution-inventory"])
    assert human.exit_code == 0
    assert published.artifact_id in human.stdout
    assert "Read only: true" in human.stdout and "Selection: none" in human.stdout
    assert str(tmp_path) not in human.stdout and "diagnosis_summary" not in human.stdout
    machine = runner.invoke(app, ["handoff", "operator-solution-inventory", "--json"])
    assert machine.exit_code == 0
    payload = json.loads(machine.stdout)
    assert payload["valid_entry_count"] == 1
    assert payload["read_only"] is True and payload["artifact_selected"] is False
    assert str(tmp_path) not in machine.stdout and "procedure" not in machine.stdout
