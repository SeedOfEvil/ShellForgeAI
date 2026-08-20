from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

import pytest

from shellforgeai.core.evidence import TargetType
from shellforgeai.core.operator_solution import (
    RecoveryMode,
    canonical_operator_solution_json,
    compute_operator_solution_sha256,
    render_operator_solution_markdown,
    validate_operator_solution,
)
from shellforgeai.core.windows_evidence_context import WINDOWS_EVIDENCE_SAFE_NEXT_COMMANDS
from shellforgeai.core.windows_operator_solution_builder import (
    WindowsOperatorSolutionBuildError,
    build_windows_operator_solution_from_evidence,
)
from shellforgeai.core.windows_operator_ux import (
    WINDOWS_OPERATOR_INTENT_DISK_CAPACITY,
    WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL,
    WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH,
    WINDOWS_OPERATOR_INTENT_PERFORMANCE,
    WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY,
    WINDOWS_OPERATOR_INTENT_SERVICES,
    WINDOWS_OPERATOR_INTENT_STATUS,
    WindowsOperatorRoute,
    windows_operator_safe_commands,
)


def _packet() -> dict[str, object]:
    # These are the maintained build_windows_evidence_context packet keys, not
    # a second schema. Values exercise every bounded native component.
    return {
        "platform": "windows",
        "visibility": "windows-local-read-only",
        "read_only": True,
        "mutation_performed": False,
        "host": {"hostname": "win-host", "fqdn": "win-host.example"},
        "platform_detail": {"system": "windows", "release": "2025"},
        "python_runtime": {"version": "3.12", "implementation": "CPython"},
        "memory": {"available": True, "used_percent": 50.0},
        "disk": {"available": True, "root_free_bytes": 1000, "roots": [{"root": "C:"}]},
        "volumes": {"available": True, "summary": {"returned": 1}, "entries": []},
        "processes": {"available": True, "total_count": 10, "returned_count": 2, "entries": []},
        "services": {
            "available": True,
            "total_count": 4,
            "running_count": 3,
            "stopped_count": 1,
            "entries": [{"name": "Spooler", "state": "stopped"}],
        },
        "events": {"available": True, "summary": {"returned": 0}, "entries": []},
        "network": {"available": True, "summary": {"interfaces": 1}, "entries": []},
        "limitations": ["Native CPU utilization is unavailable.", "Snapshot is point-in-time."],
        "evidence_gaps": ["DNS reachability is not collected."],
        "safe_next_commands": list(WINDOWS_EVIDENCE_SAFE_NEXT_COMMANDS),
    }


def _build(intent: str = WINDOWS_OPERATOR_INTENT_STATUS, packet: dict[str, object] | None = None):
    return build_windows_operator_solution_from_evidence(
        packet or _packet(),
        WindowsOperatorRoute(intent, True, False),
        target="win-host",
        target_type=TargetType.host,
        session_ref="session:windows-001",
    )


@pytest.mark.parametrize(
    "intent",
    [
        WINDOWS_OPERATOR_INTENT_STATUS,
        WINDOWS_OPERATOR_INTENT_PERFORMANCE,
        WINDOWS_OPERATOR_INTENT_SERVICES,
        WINDOWS_OPERATOR_INTENT_DISK_CAPACITY,
        WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH,
        WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY,
    ],
)
def test_supported_intents_produce_canonical_safe_solutions(intent: str) -> None:
    solution = _build(intent)
    assert validate_operator_solution(solution).valid
    assert solution.platform_system == "windows"
    assert solution.advisory_only and solution.read_only
    assert not solution.mutation_performed
    assert not solution.execution_allowed and not solution.execution_available
    assert solution.execution_status == "not_executed"
    assert solution.rollback_recovery.mode is RecoveryMode.not_applicable
    assert not solution.rollback_recovery.guidance
    commands = windows_operator_safe_commands(intent)
    assert [
        step.instruction.removeprefix("Run the maintained read-only command: `").removesuffix("`.")
        for step in solution.procedure
    ] == list(commands)


def test_evidence_is_conservative_and_raw_packet_is_not_embedded() -> None:
    solution = _build()
    assert "memory used_percent=50.0" in solution.diagnosis_summary
    assert "services observed total=4 running=3 stopped=1" in solution.diagnosis_summary
    assert "No root cause is proven" in solution.diagnosis_summary
    assert not solution.likely_causes  # stopped alone is not failure evidence
    payload = canonical_operator_solution_json(solution)
    assert "win-host.example" not in payload
    assert '"entries"' not in payload
    assert not any(ref.sha256 for ref in solution.provenance_references)
    assert all("/" not in ref.ref and "\\" not in ref.ref for ref in solution.provenance_references)


def test_missing_evidence_is_visible_not_healthy_or_a_cause() -> None:
    packet = _packet()
    packet["network"] = {"available": False}
    packet["events"] = {"available": False}
    solution = _build(packet=packet)
    assert not solution.likely_causes
    assert any("network evidence is unavailable" in item for item in solution.visibility_limits)
    assert any("events evidence is unavailable" in item for item in solution.visibility_limits)
    assert not any("healthy" in item.casefold() for item in solution.diagnosis_summary.split(";"))
    assert "fresh" in solution.verification_criteria[0].criterion.casefold()
    assert "read-only" in solution.verification_criteria[0].criterion.casefold()
    assert "repaired" not in canonical_operator_solution_json(solution).casefold()


@pytest.mark.parametrize(
    ("change", "route"),
    [
        ({"read_only": False}, None),
        ({"mutation_performed": True}, None),
        ({"platform": "linux"}, None),
        ({"visibility": "remote"}, None),
        (
            {
                "memory": {"available": False},
                "disk": {"available": False},
                "volumes": {"available": False},
                "processes": {"available": False},
                "services": {"available": False},
                "events": {"available": False},
                "network": {"available": False},
            },
            None,
        ),
        ({}, WindowsOperatorRoute(WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL, True, True)),
        ({}, WindowsOperatorRoute(WINDOWS_OPERATOR_INTENT_STATUS, False, True)),
    ],
)
def test_incompatible_inputs_fail_closed(
    change: dict[str, object], route: WindowsOperatorRoute | None
) -> None:
    packet = _packet()
    packet.update(change)
    with pytest.raises(WindowsOperatorSolutionBuildError):
        build_windows_operator_solution_from_evidence(
            packet,
            route or WindowsOperatorRoute(WINDOWS_OPERATOR_INTENT_STATUS, True, False),
            target="win-host",
            target_type=TargetType.host,
        )


def test_output_and_identity_are_deterministic() -> None:
    first = _build()
    reordered = {key: deepcopy(_packet()[key]) for key in reversed(_packet())}
    reordered["limitations"] = list(reversed(reordered["limitations"]))  # type: ignore[arg-type]
    reordered["incidental_metadata"] = {"timestamp": "tomorrow", "path": "/ignored"}
    second = _build(packet=reordered)
    assert first.solution_id == second.solution_id
    assert canonical_operator_solution_json(first) == canonical_operator_solution_json(second)
    assert render_operator_solution_markdown(first) == render_operator_solution_markdown(second)
    assert compute_operator_solution_sha256(first) == compute_operator_solution_sha256(second)


def test_public_contract_commands_docs_and_pure_boundary() -> None:
    import shellforgeai.core.windows_operator_solution_builder as module

    assert (
        build_windows_operator_solution_from_evidence.__name__
        == "build_windows_operator_solution_from_evidence"
    )
    assert module.__all__ == [
        "WindowsOperatorSolutionBuildError",
        "build_windows_operator_solution_from_evidence",
    ]
    assert not hasattr(module, "build_window_operator_solution_from_evidence")
    source_path = Path("src/shellforgeai/core/windows_operator_solution_builder.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    forbidden_roots = {"os", "pathlib", "socket", "subprocess", "requests"}
    forbidden_names = {
        "build_windows_evidence_context",
        "detect_platform",
        "build_provider",
        "open",
        "exec",
        "eval",
    }
    imports = {
        node.names[0].name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom)) and node.names
    }
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not imports & forbidden_roots
    assert not calls & forbidden_names
    for intent in (WINDOWS_OPERATOR_INTENT_STATUS, WINDOWS_OPERATOR_INTENT_SERVICES):
        assert all(
            command in windows_operator_safe_commands(intent)
            for command in windows_operator_safe_commands(intent)
        )
    docs = Path("docs/OPERATOR_SOLUTION_CONTRACT.md").read_text(encoding="utf-8")
    assert build_windows_operator_solution_from_evidence.__name__ in docs
    assert "deferred to PR360" not in docs
    assert "deferred to PR361" not in docs
