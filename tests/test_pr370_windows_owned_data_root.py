"""PR370 durable Windows data-root and bounded diagnostic contracts."""

import json
from pathlib import Path, PureWindowsPath

from test_pr358_operator_solution_contract import make_solution
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.operator_solution_artifact_persistence import (
    OperatorSolutionPublicationResult,
    load_persisted_operator_solution_artifact,
    publish_operator_solution_artifact,
)

MODULE = "shellforgeai.commands.handoff"


def test_durable_wrapper_pins_owned_absolute_cwd_independent_root() -> None:
    wrapper = Path("scripts/windows/sfai.cmd").read_text(encoding="utf-8")
    assert 'set "SHELLFORGEAI_DATA_DIR=%SHELLFORGEAI_RUNTIME_ROOT%\\data"' in wrapper
    assert 'mkdir "%SHELLFORGEAI_DATA_DIR%"' in wrapper
    data_assignment = next(
        line for line in wrapper.splitlines() if "SHELLFORGEAI_DATA_DIR=" in line
    )
    assert "%CD%" not in data_assignment and "~" not in data_assignment
    for cwd in (PureWindowsPath(r"C:\Windows\System32"), PureWindowsPath(r"D:\Unrelated Path")):
        root = PureWindowsPath(r"C:\Tools\ShellForgeAI") / "data"
        assert root.is_absolute()
        assert root == PureWindowsPath(r"C:\Tools\ShellForgeAI\data")
        assert cwd not in root.parents


def test_owned_root_canonical_save_validate_and_duplicate_no_rewrite(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    solution = make_solution()
    first = publish_operator_solution_artifact(solution, data_dir=data)
    assert first.status == "published"
    artifact = data / "operator_solutions" / first.artifact_id / "operator-solution.json"
    before = artifact.stat().st_mtime_ns
    second = publish_operator_solution_artifact(solution, data_dir=data)
    assert second.status == "already_present"
    assert second.existing_identical_no_op is True
    assert artifact.stat().st_mtime_ns == before
    assert load_persisted_operator_solution_artifact(data, first.artifact_id).status == "loaded"


def test_relative_root_stays_fail_closed_with_sanitized_reason(monkeypatch) -> None:
    monkeypatch.setattr(
        f"{MODULE}._canonical_operator_solution", lambda ctx, target: make_solution()
    )
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", "relative-data")
    result = CliRunner().invoke(app, ["handoff", "--operator-solution", "--save", "--json"])
    payload = json.loads(result.stdout)
    assert result.exit_code == 1
    assert payload["status"] == "publication_blocked"
    assert payload["reason_code"] == "invalid_data_root"
    assert payload["reason"] == "The configured data root is not a safe absolute directory."
    assert "relative-data" not in result.stdout


def test_arbitrary_persistence_error_is_not_projected(monkeypatch, tmp_path: Path) -> None:
    secret = r"C:\Users\attacker\token=super-secret"
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        f"{MODULE}._canonical_operator_solution", lambda ctx, target: make_solution()
    )
    monkeypatch.setattr(
        f"{MODULE}.publish_operator_solution_artifact",
        lambda value, *, data_dir: OperatorSolutionPublicationResult(
            status="publication_blocked", errors=(secret,)
        ),
    )
    result = CliRunner().invoke(app, ["handoff", "--operator-solution", "--save", "--json"])
    assert result.exit_code == 1
    assert secret not in result.output
    assert json.loads(result.stdout)["reason_code"] == "filesystem_publication_blocked"
    assert "traceback" not in result.output.casefold()
