"""Focused integration tests for canonical OperatorSolution handoff save."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_pr358_operator_solution_contract import make_solution
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.operator_solution import OperatorSolution
from shellforgeai.core.operator_solution_artifact_persistence import (
    OperatorSolutionPublicationResult,
)
from shellforgeai.core.operator_solution_builder import OperatorSolutionBuildError

MODULE = "shellforgeai.commands.handoff"
runner = CliRunner()


def _result(status: str) -> OperatorSolutionPublicationResult:
    return OperatorSolutionPublicationResult(
        status=status,  # type: ignore[arg-type]
        artifact_id="osol_" + "a" * 64,
        existing_identical_no_op=status == "already_present",
    )


@pytest.mark.parametrize("system", ["linux", "windows"])
@pytest.mark.parametrize("status", ["published", "already_present"])
def test_save_builds_once_and_publishes_same_solution_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, system: str, status: str
) -> None:
    solution = make_solution()
    source = {"host": {"hostname": "chosen-host"}}
    calls: dict[str, Any] = {"collect": 0, "build": 0, "publisher": 0}
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(f"{MODULE}.detect_platform", lambda: SimpleNamespace(system=system))

    def collect(*args: Any) -> object:
        calls["collect"] += 1
        if system == "linux":
            assert args[1] == "chosen-host"
        return source

    def build(value: object, *args: Any, **kwargs: Any) -> OperatorSolution:
        calls["build"] += 1
        assert value is source
        if system == "windows":
            assert kwargs["target"] == "chosen-host"
        return solution

    def publish(value: OperatorSolution, *, data_dir: Path) -> OperatorSolutionPublicationResult:
        calls["publisher"] += 1
        calls["same"] = value is solution
        assert data_dir == tmp_path
        return _result(status)

    monkeypatch.setattr(f"{MODULE}.diagnose_target", collect)
    monkeypatch.setattr(f"{MODULE}.build_windows_evidence_context", collect)
    monkeypatch.setattr(f"{MODULE}.build_linux_operator_solution_from_diagnosis", build)
    monkeypatch.setattr(f"{MODULE}.build_windows_operator_solution_from_evidence", build)
    monkeypatch.setattr(f"{MODULE}.publish_operator_solution_artifact", publish)
    result = runner.invoke(
        app,
        ["handoff", "--operator-solution", "--save", "--target", "chosen-host", "--json"],
    )
    assert result.exit_code == 0
    assert calls == {"collect": 1, "build": 1, "publisher": 1, "same": True}
    payload = json.loads(result.stdout)
    assert payload == {
        "artifact_id": "osol_" + "a" * 64,
        "artifact_path": "operator_solutions/osol_" + "a" * 64,
        "artifact_written": status == "published",
        "execution_status": "not_executed",
        "existing_identical_no_op": status == "already_present",
        "mutation_performed": False,
        "status": status,
    }


@pytest.mark.parametrize("status", ["conflict", "publication_blocked"])
def test_publication_failures_are_bounded_and_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: str
) -> None:
    solution = make_solution()
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(f"{MODULE}._canonical_operator_solution", lambda ctx, target: solution)
    monkeypatch.setattr(
        f"{MODULE}.publish_operator_solution_artifact",
        lambda value, *, data_dir: _result(status),
    )
    result = runner.invoke(app, ["handoff", "--operator-solution", "--save", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["status"] == status
    assert "traceback" not in result.output.casefold()
    assert "errors" not in result.stdout


def test_producer_failure_skips_publisher(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        f"{MODULE}._canonical_operator_solution",
        lambda ctx, target: (_ for _ in ()).throw(OperatorSolutionBuildError("bad evidence")),
    )
    monkeypatch.setattr(
        f"{MODULE}.publish_operator_solution_artifact",
        lambda *args, **kwargs: pytest.fail("publisher must not run"),
    )
    result = runner.invoke(app, ["handoff", "--operator-solution", "--save"])
    assert result.exit_code == 1
    assert "could not be produced" in result.output.casefold()
    assert "traceback" not in result.output.casefold()


def test_ordinary_canonical_does_not_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    solution = make_solution()
    monkeypatch.setattr(f"{MODULE}._canonical_operator_solution", lambda ctx, target: solution)
    monkeypatch.setattr(
        f"{MODULE}.publish_operator_solution_artifact",
        lambda *args, **kwargs: pytest.fail("ordinary rendering must not persist"),
    )
    result = runner.invoke(app, ["handoff", "--operator-solution", "--json"])
    assert result.exit_code == 0
    assert OperatorSolution.model_validate_json(result.stdout) == solution


@pytest.mark.parametrize(
    "option",
    [
        "--brief",
        "--from-status",
        "--from-triage",
        "--from-propose",
        "--from-apply-preview",
        "--from-verify",
    ],
)
def test_remaining_canonical_incompatibilities_are_preserved(
    monkeypatch: pytest.MonkeyPatch, option: str
) -> None:
    monkeypatch.setattr(
        f"{MODULE}._canonical_operator_solution",
        lambda *args: pytest.fail("incompatibility must fail before collection"),
    )
    result = runner.invoke(app, ["handoff", "--operator-solution", option])
    assert result.exit_code == 2
    assert "cannot be combined" in result.output
