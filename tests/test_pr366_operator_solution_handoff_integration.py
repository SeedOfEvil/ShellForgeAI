from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.evidence import TargetType
from shellforgeai.core.operator_solution import (
    OperatorSolution,
    canonical_operator_solution_json,
    render_operator_solution_markdown,
)
from shellforgeai.core.operator_solution_builder import (
    OperatorSolutionBuildError,
    build_linux_operator_solution_from_diagnosis,
)
from shellforgeai.core.windows_evidence_context import WINDOWS_EVIDENCE_SAFE_NEXT_COMMANDS
from shellforgeai.core.windows_operator_solution_builder import (
    WindowsOperatorSolutionBuildError,
    build_windows_operator_solution_from_evidence,
)
from shellforgeai.core.windows_operator_ux import (
    WINDOWS_OPERATOR_INTENT_HANDOFF,
    WindowsOperatorRoute,
)

runner = CliRunner()
MODULE = "shellforgeai.commands.handoff"


def _packet() -> dict[str, Any]:
    return {
        "platform": "windows",
        "visibility": "windows-local-read-only",
        "read_only": True,
        "mutation_performed": False,
        "host": {"hostname": "win-host"},
        "memory": {"available": True, "used_percent": 42},
        "disk": {"available": True, "root_free_bytes": 1000, "roots": []},
        "volumes": {"available": True, "summary": {}, "entries": []},
        "processes": {"available": True, "total_count": 4, "returned_count": 2},
        "services": {
            "available": True,
            "total_count": 3,
            "running_count": 2,
            "stopped_count": 1,
        },
        "events": {"available": True, "summary": {}, "entries": []},
        "network": {"available": True, "summary": {}, "entries": []},
        "limitations": ["Point-in-time visibility."],
        "evidence_gaps": [],
        "safe_next_commands": list(WINDOWS_EVIDENCE_SAFE_NEXT_COMMANDS),
    }


def _solution() -> OperatorSolution:
    return build_windows_operator_solution_from_evidence(
        _packet(),
        WindowsOperatorRoute(WINDOWS_OPERATOR_INTENT_HANDOFF, True, False),
        target="win-host",
        target_type=TargetType.host,
        session_ref="session-pr366",
    )


def _forbid_model_or_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("canonical handoff must not call a model or execute")

    monkeypatch.setattr("shellforgeai.llm.manager.build_provider", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)


def test_help_preserves_surface_and_registers_exact_option() -> None:
    result = runner.invoke(app, ["handoff", "--help"])
    assert result.exit_code == 0
    for value in (
        "--operator-solution",
        "--json",
        "--brief",
        "--save",
        "--target",
        "--from-status",
        "--from-triage",
        "--from-propose",
        "--from-apply-preview",
        "--from-verify",
        "validate",
        "export",
        "export-validate",
        "history",
        "compare",
        "compare-latest",
    ):
        assert value in result.stdout
    assert "--operator_solution" not in result.stdout
    assert "--operators-solution" not in result.stdout


def test_linux_json_and_markdown_delegate_once_and_are_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_model_or_execution(monkeypatch)
    diagnosis = object()
    solution = _solution()
    calls = {"diagnose": 0, "linux": 0, "windows": 0}

    monkeypatch.setattr(f"{MODULE}.detect_platform", lambda: SimpleNamespace(system="linux"))

    def diagnose(context: Any, target: str) -> object:
        calls["diagnose"] += 1
        assert context.session.session_id
        assert target == "explicit-host"
        return diagnosis

    def build(value: object) -> OperatorSolution:
        calls["linux"] += 1
        assert value is diagnosis
        return solution

    monkeypatch.setattr(f"{MODULE}.diagnose_target", diagnose)
    monkeypatch.setattr(f"{MODULE}.build_linux_operator_solution_from_diagnosis", build)
    monkeypatch.setattr(
        f"{MODULE}.build_windows_operator_solution_from_evidence",
        lambda *args, **kwargs: calls.__setitem__("windows", calls["windows"] + 1),
    )

    json_result = runner.invoke(
        app, ["handoff", "--operator-solution", "--target", "explicit-host", "--json"]
    )
    assert json_result.exit_code == 0
    assert json_result.stdout == canonical_operator_solution_json(solution) + "\n"
    assert OperatorSolution.model_validate_json(json_result.stdout) == solution
    assert calls == {"diagnose": 1, "linux": 1, "windows": 0}

    calls.update(diagnose=0, linux=0, windows=0)
    human = runner.invoke(app, ["handoff", "--operator-solution", "--target", "explicit-host"])
    assert human.exit_code == 0
    assert human.stdout == render_operator_solution_markdown(solution)
    repeated = runner.invoke(app, ["handoff", "--operator-solution", "--target", "explicit-host"])
    assert repeated.stdout == human.stdout
    assert calls == {"diagnose": 2, "linux": 2, "windows": 0}


def test_linux_default_target_is_current_host(monkeypatch: pytest.MonkeyPatch) -> None:
    targets: list[str] = []
    monkeypatch.setattr(f"{MODULE}.detect_platform", lambda: SimpleNamespace(system="linux"))
    monkeypatch.setattr(
        f"{MODULE}.diagnose_target", lambda context, target: targets.append(target) or object()
    )
    monkeypatch.setattr(
        f"{MODULE}.build_linux_operator_solution_from_diagnosis", lambda diagnosis: _solution()
    )
    result = runner.invoke(app, ["handoff", "--operator-solution", "--json"])
    assert result.exit_code == 0
    assert targets == ["host"]


def test_windows_collects_and_builds_once_with_maintained_handoff_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_model_or_execution(monkeypatch)
    packet = _packet()
    solution = _solution()
    calls = {"evidence": 0, "windows": 0, "linux": 0}
    monkeypatch.setattr(f"{MODULE}.detect_platform", lambda: SimpleNamespace(system="windows"))

    def evidence() -> dict[str, Any]:
        calls["evidence"] += 1
        return packet

    def build(
        value: dict[str, Any], route: WindowsOperatorRoute, **kwargs: Any
    ) -> OperatorSolution:
        calls["windows"] += 1
        assert value is packet
        assert route.intent == WINDOWS_OPERATOR_INTENT_HANDOFF
        assert route.host_is_windows and not route.explicit_windows
        assert kwargs["target"] == "win-host"
        assert kwargs["target_type"] is TargetType.host
        return solution

    monkeypatch.setattr(f"{MODULE}.build_windows_evidence_context", evidence)
    monkeypatch.setattr(f"{MODULE}.build_windows_operator_solution_from_evidence", build)
    monkeypatch.setattr(
        f"{MODULE}.build_linux_operator_solution_from_diagnosis",
        lambda value: calls.__setitem__("linux", calls["linux"] + 1),
    )
    result = runner.invoke(app, ["handoff", "--operator-solution", "--json"])
    assert result.exit_code == 0
    assert result.stdout == canonical_operator_solution_json(solution) + "\n"
    assert calls == {"evidence": 1, "windows": 1, "linux": 0}
    assert not solution.mutation_performed
    assert not solution.execution_allowed and not solution.execution_available
    assert solution.execution_status == "not_executed"


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
def test_incompatible_legacy_options_fail_before_collection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, option: str
) -> None:
    monkeypatch.setattr(
        f"{MODULE}.detect_platform",
        lambda: pytest.fail("platform/collection must not run"),
    )
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["handoff", "--operator-solution", option])
    assert result.exit_code == 2
    assert "cannot be combined" in result.output
    assert not list(tmp_path.rglob("*"))


@pytest.mark.parametrize(
    ("system", "error"),
    [
        ("linux", OperatorSolutionBuildError("invalid diagnosis")),
        ("windows", WindowsOperatorSolutionBuildError("invalid evidence")),
        ("darwin", None),
    ],
)
def test_unsupported_platform_and_controlled_producer_failures_are_clean(
    monkeypatch: pytest.MonkeyPatch, system: str, error: Exception | None
) -> None:
    monkeypatch.setattr(f"{MODULE}.detect_platform", lambda: SimpleNamespace(system=system))
    monkeypatch.setattr(f"{MODULE}.diagnose_target", lambda context, target: object())
    monkeypatch.setattr(f"{MODULE}.build_windows_evidence_context", _packet)

    def fail(*args: Any, **kwargs: Any) -> None:
        assert error is not None
        raise error

    monkeypatch.setattr(f"{MODULE}.build_linux_operator_solution_from_diagnosis", fail)
    monkeypatch.setattr(f"{MODULE}.build_windows_operator_solution_from_evidence", fail)
    result = runner.invoke(app, ["handoff", "--operator-solution"])
    assert result.exit_code == 1
    assert "could not be produced" in result.output.casefold()
    assert "traceback" not in result.output.casefold()
    assert "Handoff:" not in result.output


def test_docs_and_command_source_use_canonical_authorities_without_mapping_copy() -> None:
    command = Path("src/shellforgeai/commands/handoff.py").read_text(encoding="utf-8")
    contract = Path("docs/OPERATOR_SOLUTION_CONTRACT.md").read_text(encoding="utf-8")
    cli_docs = Path("docs/cli.md").read_text(encoding="utf-8")
    for symbol in (
        build_linux_operator_solution_from_diagnosis.__name__,
        build_windows_operator_solution_from_evidence.__name__,
        canonical_operator_solution_json.__name__,
        render_operator_solution_markdown.__name__,
        "WINDOWS_OPERATOR_INTENT_HANDOFF",
    ):
        assert symbol in command
    assert "LikelyCause(" not in command
    assert "OperatorSolution(" not in command
    assert "--operator-solution" in contract and "--operator-solution" in cli_docs
    assert build_linux_operator_solution_from_diagnosis.__name__ in contract
    assert build_windows_operator_solution_from_evidence.__name__ in contract
    assert (
        "CLI, artifact persistence, and report/handoff integration remain deferred" not in contract
    )


def test_default_legacy_json_and_brief_remain_v2() -> None:
    legacy = runner.invoke(app, ["handoff", "--json"])
    assert legacy.exit_code == 0
    assert json.loads(legacy.stdout)["mode"] == "v2_handoff"
    brief = runner.invoke(app, ["handoff", "--brief"])
    assert brief.exit_code == 0
    assert "First safe command:" in brief.stdout
