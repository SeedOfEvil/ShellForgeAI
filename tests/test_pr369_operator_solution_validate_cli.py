"""Focused CLI tests for exact-ID canonical OperatorSolution validation."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_pr358_operator_solution_contract import make_solution
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.operator_solution_artifact_persistence import (
    prepare_operator_solution_artifact,
    publish_operator_solution_artifact,
)

MODULE = "shellforgeai.commands.handoff"
runner = CliRunner()
ARTIFACT_ID = "osol_" + "a" * 64


def _loaded_result(**changes: Any) -> SimpleNamespace:
    values = {
        "status": "loaded",
        "artifact_id": ARTIFACT_ID,
        "solution": make_solution(),
        "total_bytes_read": 1234,
        "filesystem_accessed": True,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_loaded_calls_loader_once_with_exact_id_and_data_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[Path, str]] = []
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))

    def load(data_dir: Path, artifact_id: str) -> SimpleNamespace:
        calls.append((data_dir, artifact_id))
        return _loaded_result()

    monkeypatch.setattr(f"{MODULE}.load_persisted_operator_solution_artifact", load)
    result = runner.invoke(app, ["handoff", "operator-solution-validate", ARTIFACT_ID, "--json"])

    assert result.exit_code == 0
    assert calls == [(tmp_path, ARTIFACT_ID)]
    assert json.loads(result.stdout) == {
        "artifact_id": ARTIFACT_ID,
        "execution_status": "not_executed",
        "filesystem_accessed": True,
        "integrity_scope": (
            "Persisted artifact integrity only; this does not establish freshness, current host "
            "state, current-state validity, approval, authorization, execution eligibility, or "
            "successful execution."
        ),
        "mode": "canonical_operator_solution_validate",
        "mutation_performed": False,
        "read_only": True,
        "status": "loaded",
        "total_bytes_read": 1234,
        "valid": True,
    }
    assert "solution_id" not in result.stdout
    assert "procedure" not in result.stdout


@pytest.mark.parametrize("status", ["not_found", "invalid_id", "invalid", "load_blocked"])
def test_failure_statuses_are_controlled_nonzero(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    monkeypatch.setattr(
        f"{MODULE}.load_persisted_operator_solution_artifact",
        lambda data_dir, artifact_id: _loaded_result(
            status=status,
            artifact_id="" if status == "invalid_id" else ARTIFACT_ID,
            solution=None,
            total_bytes_read=0,
            filesystem_accessed=status != "invalid_id",
        ),
    )
    result = runner.invoke(app, ["handoff", "operator-solution-validate", ARTIFACT_ID, "--json"])

    assert result.exit_code == 1
    assert json.loads(result.stdout)["status"] == status
    assert json.loads(result.stdout)["valid"] is False
    assert "traceback" not in result.output.casefold()


@pytest.mark.parametrize("artifact_id", ["../osol_" + "0" * 64, "osol_" + "A" * 64])
def test_invalid_ids_delegate_to_loader_without_filesystem_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, artifact_id: str
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["handoff", "operator-solution-validate", artifact_id, "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "invalid_id"
    assert payload["filesystem_accessed"] is False
    assert not (tmp_path / "operator_solutions").exists()


def test_human_output_is_deterministic_bounded_and_integrity_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        f"{MODULE}.load_persisted_operator_solution_artifact",
        lambda data_dir, artifact_id: _loaded_result(),
    )
    argv = ["handoff", "operator-solution-validate", ARTIFACT_ID]
    first = runner.invoke(app, argv)
    second = runner.invoke(app, argv)

    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert len(first.stdout) < 1000
    lowered = first.stdout.casefold()
    for excluded_claim in (
        "does not establish freshness",
        "current host state",
        "current-state validity",
        "approval",
        "authorization",
        "execution eligibility",
        "successful execution",
    ):
        assert excluded_claim in lowered
    assert "target-a" not in first.stdout


def test_real_validation_is_read_only_and_does_not_run_operational_authorities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = prepare_operator_solution_artifact(make_solution())
    publish_operator_solution_artifact(artifact.solution, data_dir=tmp_path)
    directory = tmp_path / "operator_solutions" / artifact.artifact_id
    before = {
        path.name: (path.stat().st_mtime_ns, path.read_bytes()) for path in directory.iterdir()
    }
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    for name in (
        "publish_operator_solution_artifact",
        "diagnose_target",
        "build_windows_evidence_context",
        "build_linux_operator_solution_from_diagnosis",
        "build_windows_operator_solution_from_evidence",
    ):
        monkeypatch.setattr(
            f"{MODULE}.{name}", lambda *args, name=name, **kwargs: pytest.fail(name)
        )

    result = runner.invoke(
        app, ["handoff", "operator-solution-validate", artifact.artifact_id, "--json"]
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["valid"] is True
    assert before == {
        path.name: (path.stat().st_mtime_ns, path.read_bytes()) for path in directory.iterdir()
    }


def test_legacy_validate_and_canonical_render_save_surfaces_remain_distinct() -> None:
    help_result = runner.invoke(app, ["handoff", "--help"])
    legacy_help = runner.invoke(app, ["handoff", "validate", "--help"])

    assert help_result.exit_code == legacy_help.exit_code == 0
    assert "operator-solution-validate" in help_result.stdout
    assert "Usage: root handoff validate" in legacy_help.stdout
    assert "Read-only validation of a saved ShellForgeAI handoff artifact" in legacy_help.stdout
    assert "--operator-solution" in help_result.stdout
    assert "--save" in help_result.stdout
