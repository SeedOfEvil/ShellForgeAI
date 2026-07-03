"""PR276 Windows evidence bundle opt-in processes component tests."""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_disks import windows_disks_payload
from shellforgeai.windows_evidence import (
    EVIDENCE_PROCESSES_DEFAULT_LIMIT,
    EVIDENCE_PROCESSES_MAX_LIMIT,
    render_windows_evidence_text,
    validate_evidence_processes_limit,
    windows_evidence_payload,
)
from shellforgeai.windows_processes import (
    MAX_PROCESSES_LIMIT,
    windows_processes_payload,
)
from shellforgeai.windows_services import RawServiceRecord, windows_services_payload
from shellforgeai.windows_status import windows_status_payload

ACCEPTANCE_SCRIPT = Path("scripts/windows_smoke_acceptance.py")
PACKET_SCRIPT = Path("scripts/windows_smoke_packet.py")

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")

ALLOWED_PROCESS_ITEM_KEYS = {"pid", "parent_pid", "name", "thread_count"}

FAKE_PROCESSES = tuple(
    {"pid": 100 + index, "parent_pid": 4, "name": f"proc{index:02d}.exe", "thread_count": 2 + index}
    for index in range(30)
)

FAKE_ROOTS = ("C:\\", "D:\\", "E:\\")

FAKE_RECORDS = (
    RawServiceRecord("wuauserv", "Windows Update", 1, 0x20),
    RawServiceRecord("Spooler", "Print Spooler", 4, 0x10),
    RawServiceRecord("Dnscache", "DNS Client", 4, 0x20),
)


def fake_process_enumerator() -> list[dict[str, Any]]:
    return [dict(item) for item in FAKE_PROCESSES]


def failing_process_enumerator() -> list[dict[str, Any]]:
    raise OSError("toolhelp snapshot failed")


def fake_processes_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_processes_payload(info, process_enumerator=fake_process_enumerator, limit=limit)


def failing_processes_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_processes_payload(
        info, process_enumerator=failing_process_enumerator, limit=limit
    )


def fake_disk_usage(_path: str | Path) -> tuple[int, int, int]:
    return (1000, 400, 600)


def fake_disks_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_disks_payload(
        info, root_discovery=lambda: list(FAKE_ROOTS), disk_usage=fake_disk_usage, limit=limit
    )


def fake_services_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_services_payload(info, enumerator=lambda: list(FAKE_RECORDS), max_services=limit)


def evidence_payload_for_mocked_windows(**kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("processes_builder", fake_processes_builder)
    kwargs.setdefault("disks_builder", fake_disks_builder)
    kwargs.setdefault("services_builder", fake_services_builder)
    return windows_evidence_payload(
        WINDOWS_INFO,
        status_builder=lambda info: windows_status_payload(
            info, disk_usage=fake_disk_usage, cwd=Path("C:/safe")
        ),
        **kwargs,
    )


def _load(script: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _acceptance_module() -> ModuleType:
    return _load(ACCEPTANCE_SCRIPT, "windows_smoke_acceptance_pr276")


def _packet_module() -> ModuleType:
    sys.modules.pop("windows_smoke_acceptance", None)
    return _load(PACKET_SCRIPT, "windows_smoke_packet_pr276")


def _cli_output(result) -> str:
    output = result.output
    with contextlib.suppress(ValueError):
        output += result.stderr
    return output


# ---------------------------------------------------------------------------
# Default bundle behavior stays doctor/status-only.
# ---------------------------------------------------------------------------


def test_default_mocked_windows_bundle_remains_doctor_status_only() -> None:
    payload = evidence_payload_for_mocked_windows()
    assert payload["status"] == "ok"
    assert sorted(payload["components"]) == ["doctor", "status"]
    assert "processes" not in payload["components"]
    assert payload["next_safe_command"] == "shellforgeai windows status --json"


def test_default_mocked_windows_bundle_component_count_is_two() -> None:
    summary = evidence_payload_for_mocked_windows()["summary"]
    assert summary["component_count"] == 2
    assert summary["ok_components"] == ["doctor", "status"]
    assert summary["failed_components"] == []


def test_default_bundle_has_no_embedded_processes_metadata() -> None:
    payload = evidence_payload_for_mocked_windows()
    assert "embedded_processes" not in payload
    assert "not_collected_in_pr276" not in payload
    assert "process_memory_read" not in payload["safety"]
    assert "process_command_line_read" not in payload["safety"]


# ---------------------------------------------------------------------------
# Opt-in processes component contract.
# ---------------------------------------------------------------------------


def test_include_processes_bundle_includes_processes_component() -> None:
    payload = evidence_payload_for_mocked_windows(include_processes=True)
    assert payload["status"] == "ok"
    assert sorted(payload["components"]) == ["doctor", "processes", "status"]


def test_processes_component_mode_is_windows_processes() -> None:
    component = evidence_payload_for_mocked_windows(include_processes=True)["components"][
        "processes"
    ]
    assert component["mode"] == "windows_processes"


def test_processes_component_status_is_ok() -> None:
    component = evidence_payload_for_mocked_windows(include_processes=True)["components"][
        "processes"
    ]
    assert component["status"] == "ok"


def test_processes_component_is_read_only_without_mutation() -> None:
    component = evidence_payload_for_mocked_windows(include_processes=True)["components"][
        "processes"
    ]
    assert component["read_only"] is True
    assert component["mutation_performed"] is False
    assert component["safety"]["process_termination_executed"] is False
    assert component["safety"]["process_control_executed"] is False


def test_processes_component_has_bounded_default_limit_25() -> None:
    assert EVIDENCE_PROCESSES_DEFAULT_LIMIT == 25
    assert EVIDENCE_PROCESSES_MAX_LIMIT == MAX_PROCESSES_LIMIT == 200
    component = evidence_payload_for_mocked_windows(include_processes=True)["components"][
        "processes"
    ]
    assert component["limit"] == 25
    assert component["returned_count"] == 25
    assert len(component["processes"]) == 25


def test_processes_limit_ten_is_applied() -> None:
    component = evidence_payload_for_mocked_windows(include_processes=True, processes_limit=10)[
        "components"
    ]["processes"]
    assert component["limit"] == 10
    assert component["returned_count"] == 10
    assert len(component["processes"]) == 10


def test_processes_truncation_is_represented_when_total_exceeds_returned() -> None:
    component = evidence_payload_for_mocked_windows(include_processes=True, processes_limit=10)[
        "components"
    ]["processes"]
    assert component["total_count"] == 30
    assert component["returned_count"] == 10
    assert component["truncated"] is True
    untruncated = evidence_payload_for_mocked_windows(include_processes=True, processes_limit=200)[
        "components"
    ]["processes"]
    assert untruncated["total_count"] == untruncated["returned_count"] == 30
    assert untruncated["truncated"] is False


def test_summary_component_count_is_three_with_processes() -> None:
    summary = evidence_payload_for_mocked_windows(include_processes=True)["summary"]
    assert summary["component_count"] == 3


def test_summary_ok_components_includes_processes() -> None:
    summary = evidence_payload_for_mocked_windows(include_processes=True)["summary"]
    assert "processes" in summary["ok_components"]
    assert summary["failed_components"] == []


def test_top_level_embedded_processes_block_is_explicit_and_bounded() -> None:
    payload = evidence_payload_for_mocked_windows(include_processes=True, processes_limit=10)
    assert payload["embedded_processes"] == {
        "included": True,
        "limit": 10,
        "returned_count": 10,
        "total_count": 30,
        "truncated": True,
    }
    not_collected = payload["not_collected_in_pr276"]
    assert sorted(not_collected) == [
        "command_line",
        "environment",
        "handles",
        "memory",
        "modules",
        "network_connections",
        "owner_user",
    ]
    assert "PR276" in not_collected["command_line"]
    assert payload["next_safe_command"] == "shellforgeai windows processes --json --limit 10"


def test_include_processes_reuses_existing_pr274_payload_builder() -> None:
    calls: list[tuple[PlatformInfo, int]] = []

    def builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
        calls.append((info, limit))
        return fake_processes_builder(info, limit)

    payload = evidence_payload_for_mocked_windows(include_processes=True, processes_builder=builder)
    assert calls == [(WINDOWS_INFO, EVIDENCE_PROCESSES_DEFAULT_LIMIT)]
    component = payload["components"]["processes"]
    assert component["method"] == "ctypes_toolhelp32_snapshot"
    assert component["windows_v1"]["scope"] == "local_read_only_processes_preview"


# ---------------------------------------------------------------------------
# Process item field allowlist (no PR274 surface expansion).
# ---------------------------------------------------------------------------


def test_process_items_remain_limited_to_safe_pr274_fields() -> None:
    component = evidence_payload_for_mocked_windows(include_processes=True)["components"][
        "processes"
    ]
    assert component["processes"], "expected at least one process item"
    for item in component["processes"]:
        assert set(item) == ALLOWED_PROCESS_ITEM_KEYS


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "command_line",
        "cmdline",
        "environment",
        "environ",
        "memory",
        "memory_bytes",
        "handles",
        "modules",
        "owner",
        "user",
        "token",
        "username",
        "connections",
        "network_connections",
        "exe_path",
        "executable_path",
    ],
)
def test_process_items_do_not_include_forbidden_field(forbidden_field: str) -> None:
    component = evidence_payload_for_mocked_windows(include_processes=True)["components"][
        "processes"
    ]
    for item in component["processes"]:
        assert forbidden_field not in item


# ---------------------------------------------------------------------------
# Services/disks opt-in behavior still works; combined composition.
# ---------------------------------------------------------------------------


def test_services_only_opt_in_behavior_still_works() -> None:
    payload = evidence_payload_for_mocked_windows(include_services=True)
    assert sorted(payload["components"]) == ["doctor", "services", "status"]
    assert payload["summary"]["component_count"] == 3
    assert "embedded_processes" not in payload
    assert payload["next_safe_command"] == "shellforgeai windows services --json --limit 25"


def test_disks_only_opt_in_behavior_still_works() -> None:
    payload = evidence_payload_for_mocked_windows(include_disks=True)
    assert sorted(payload["components"]) == ["disks", "doctor", "status"]
    assert payload["summary"]["component_count"] == 3
    assert "embedded_processes" not in payload
    assert payload["embedded_disks"]["included"] is True
    assert payload["next_safe_command"] == "shellforgeai windows disks --json"


def test_processes_only_gives_component_count_three() -> None:
    payload = evidence_payload_for_mocked_windows(include_processes=True)
    assert payload["summary"]["component_count"] == 3
    assert "embedded_disks" not in payload


def test_services_disks_and_processes_together_give_component_count_five() -> None:
    payload = evidence_payload_for_mocked_windows(
        include_services=True, include_disks=True, include_processes=True
    )
    assert payload["status"] == "ok"
    assert sorted(payload["components"]) == ["disks", "doctor", "processes", "services", "status"]
    assert payload["summary"]["component_count"] == 5
    assert payload["summary"]["failed_components"] == []
    assert payload["components"]["services"]["mode"] == "windows_services"
    assert payload["components"]["disks"]["mode"] == "windows_disks"
    assert payload["components"]["processes"]["mode"] == "windows_processes"
    assert payload["embedded_disks"]["included"] is True
    assert payload["embedded_processes"]["included"] is True


# ---------------------------------------------------------------------------
# Processes failure honesty.
# ---------------------------------------------------------------------------


def test_processes_failure_is_surfaced_in_failed_components() -> None:
    payload = evidence_payload_for_mocked_windows(
        include_processes=True, processes_builder=failing_processes_builder
    )
    assert payload["summary"]["failed_components"] == ["processes"]
    assert payload["components"]["processes"]["status"] == "error"
    assert payload["components"]["processes"]["reason"] == "process_enumeration_failed"
    assert "Traceback" not in json.dumps(payload)


def test_top_level_status_does_not_hide_processes_failure() -> None:
    payload = evidence_payload_for_mocked_windows(
        include_processes=True, processes_builder=failing_processes_builder
    )
    assert payload["status"] != "ok"
    assert payload["status"] == "component_failure"
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["process_termination_executed"] is False
    assert payload["embedded_processes"]["returned_count"] == 0
    assert payload["embedded_processes"]["total_count"] == 0


# ---------------------------------------------------------------------------
# Linux/Docker01 unsupported behavior.
# ---------------------------------------------------------------------------


def test_linux_include_processes_returns_structured_unsupported() -> None:
    payload = windows_evidence_payload(LINUX_INFO, include_processes=True, processes_limit=10)
    assert payload["status"] == "unsupported"
    assert payload["mode"] == "windows_evidence_bundle"
    assert payload["platform"] == {"system": "linux"}
    assert payload["mutation_performed"] is False
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"
    assert "components" not in payload
    assert "embedded_processes" not in payload


def test_linux_unsupported_does_not_attempt_processes_collection() -> None:
    def must_not_collect(_info: PlatformInfo, _limit: int) -> dict[str, Any]:
        raise AssertionError("processes collection must not run on Linux")

    payload = windows_evidence_payload(
        LINUX_INFO, include_processes=True, processes_builder=must_not_collect
    )
    assert payload["status"] == "unsupported"


def test_cli_linux_include_processes_unsupported(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_evidence.detect_platform", lambda: LINUX_INFO)
    monkeypatch.setattr("shellforgeai.windows_processes.detect_platform", lambda: LINUX_INFO)
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--json", "--include-processes", "--processes-limit", "10"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"
    assert "Traceback" not in _cli_output(result)


# ---------------------------------------------------------------------------
# Text output.
# ---------------------------------------------------------------------------


def test_text_output_with_processes_is_concise_and_summarized() -> None:
    payload = evidence_payload_for_mocked_windows(include_processes=True, processes_limit=10)
    text = render_windows_evidence_text(payload)
    assert "Components included: doctor, status, processes" in text
    assert "Processes component: status=ok; returned=10; total=30; limit=10; truncated=true" in text
    assert (
        "Not collected yet: PowerShell version, execution policy, services, "
        "event logs, firewall, Windows Update." in text
    )
    assert len(text.splitlines()) <= 12
    # No unbounded per-process listing in text output.
    assert "proc00.exe" not in text
    assert "pid=" not in text


def test_default_text_output_is_unchanged() -> None:
    text = render_windows_evidence_text(evidence_payload_for_mocked_windows())
    assert "Components included: doctor, status" in text
    assert "Processes component:" not in text
    assert "processes" in text.split("Not collected yet: ")[1]


# ---------------------------------------------------------------------------
# Limit validation.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0, -1, -25, 201, 10_000, "25", 2.5, None, True])
def test_invalid_processes_limit_rejected_by_validator(value: Any) -> None:
    with pytest.raises(ValueError):
        validate_evidence_processes_limit(value)


@pytest.mark.parametrize("value", [1, 10, 25, 200])
def test_valid_processes_limit_accepted(value: int) -> None:
    assert validate_evidence_processes_limit(value) == value


@pytest.mark.parametrize("raw", ["0", "-3", "201", "abc"])
def test_cli_invalid_processes_limit_fails_cleanly(raw: str) -> None:
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--json", "--include-processes", "--processes-limit", raw]
    )
    assert result.exit_code == 2
    assert "Traceback" not in _cli_output(result)


def test_cli_processes_limit_requires_include_processes() -> None:
    result = CliRunner().invoke(app, ["windows", "evidence", "--json", "--processes-limit", "10"])
    assert result.exit_code == 2
    # Rich wraps the error panel, so match on the unambiguous fragments.
    output = _cli_output(result)
    assert "--processes-limit requires" in output
    assert "--include-processes" in output


def test_cli_include_processes_flags_are_passed_through(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    def capture(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return windows_evidence_payload(LINUX_INFO)

    monkeypatch.setattr("shellforgeai.commands.windows.windows_evidence_payload", capture)
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--json", "--include-processes", "--processes-limit", "10"]
    )
    assert result.exit_code == 0
    assert seen == {"include_processes": True, "processes_limit": 10}


def test_cli_include_all_components_flags_are_passed_through(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    def capture(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return windows_evidence_payload(LINUX_INFO)

    monkeypatch.setattr("shellforgeai.commands.windows.windows_evidence_payload", capture)
    result = CliRunner().invoke(
        app,
        [
            "windows",
            "evidence",
            "--json",
            "--include-services",
            "--include-disks",
            "--include-processes",
            "--processes-limit",
            "10",
        ],
    )
    assert result.exit_code == 0
    assert seen == {
        "include_services": True,
        "services_limit": 25,
        "include_disks": True,
        "disks_limit": 32,
        "include_processes": True,
        "processes_limit": 10,
    }


def test_cli_default_evidence_call_shape_is_unchanged(monkeypatch) -> None:
    def capture(*args: Any, **kwargs: Any) -> dict[str, Any]:
        assert args == ()
        assert kwargs == {}
        return windows_evidence_payload(LINUX_INFO)

    monkeypatch.setattr("shellforgeai.commands.windows.windows_evidence_payload", capture)
    result = CliRunner().invoke(app, ["windows", "evidence", "--json"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Safety flags.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "powershell_executed",
        "winrm_used",
        "remote_execution",
        "process_termination_executed",
        "process_control_executed",
        "process_config_modified",
        "process_memory_read",
        "process_command_line_read",
        "process_environment_read",
        "process_handles_read",
        "process_modules_read",
        "process_owner_read",
        "service_restart_executed",
        "registry_modified",
        "execution_policy_modified",
        "software_install_executed",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "natural_language_execution",
        "shell_true",
        "arbitrary_command_execution",
        "network_call",
        "model_called",
        "secret_read",
        "auth_cache_read",
        "mutation_performed",
    ],
)
def test_bundle_safety_flags_remain_false_with_processes(key: str) -> None:
    payload = evidence_payload_for_mocked_windows(include_processes=True)
    assert payload["safety"][key] is False
    assert payload["components"]["processes"]["safety"].get(key, False) is False


def test_bundle_stays_read_only_with_processes() -> None:
    payload = evidence_payload_for_mocked_windows(include_processes=True)
    assert payload["read_only"] is True
    assert payload["safety"]["read_only"] is True
    assert payload["windows_v1"]["powershell_executed"] is False
    assert payload["windows_v1"]["winrm_used"] is False
    assert payload["windows_v1"]["remote_execution"] is False


# ---------------------------------------------------------------------------
# Validator: embedded processes component.
# ---------------------------------------------------------------------------


def _safe_flags() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "powershell_executed": False,
        "winrm_used": False,
        "remote_execution": False,
        "service_restart_executed": False,
        "process_termination_executed": False,
        "registry_modified": False,
        "execution_policy_modified": False,
        "software_install_executed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "secret_read": False,
        "auth_cache_read": False,
        "model_called": False,
        "network_call": False,
    }


def _processes_safe_flags() -> dict[str, bool]:
    flags = _safe_flags()
    flags.update(
        {
            "process_control_executed": False,
            "process_config_modified": False,
            "process_memory_read": False,
            "process_command_line_read": False,
            "process_environment_read": False,
            "process_handles_read": False,
            "process_modules_read": False,
            "process_owner_read": False,
        }
    )
    return flags


def _component(mode: str) -> dict[str, Any]:
    scope = "local_read_only_status" if mode == "windows_status" else "local_read_only_doctor"
    return {
        "schema_version": 1,
        "mode": mode,
        "status": "ok",
        "platform": {"system": "windows", "release": "2025", "machine": "AMD64"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": scope,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "host": {"hostname": "WIN2025-SFAI01", "cwd": "C:\\Tools\\ShellForgeAI"},
        "python_runtime": {
            "executable": "C:\\Tools\\ShellForgeAI\\Python314\\python.exe",
            "version": "3.14.6",
        },
        "filesystem": {"collection": "stdlib_only"},
        "safety": _safe_flags(),
    }


def _standalone_processes_payload() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_processes",
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_processes_preview",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "method": "ctypes_toolhelp32_snapshot",
        "limit": 50,
        "total_count": 3,
        "returned_count": 3,
        "truncated": False,
        "state": {"enumeration_failed": False},
        "processes": [
            {"pid": 0, "parent_pid": 0, "name": "System Idle Process", "thread_count": 4},
            {"pid": 4, "parent_pid": 0, "name": "System", "thread_count": 120},
            {"pid": 1234, "parent_pid": 4, "name": "svchost.exe", "thread_count": 12},
        ],
        "not_collected_in_pr274": {
            "command_line": "not collected because PR274 does not inspect process command lines",
            "environment": "not collected because PR274 does not inspect process environments",
            "memory": "not collected because PR274 does not inspect process memory",
            "handles": "not collected because PR274 does not inspect process handles",
            "modules": "not collected because PR274 does not enumerate modules",
            "owner_user": "not collected because PR274 does not inspect process tokens/users",
            "network_connections": "not collected because PR274 does not map network connections",
        },
        "safety": _processes_safe_flags(),
        "next_safe_command": "shellforgeai windows processes --json --limit 10",
    }


def _embedded_processes_component() -> dict[str, Any]:
    payload = _standalone_processes_payload()
    payload["limit"] = 25
    return payload


def _evidence_payload(include_processes: bool = False) -> dict[str, Any]:
    components: dict[str, Any] = {
        "doctor": _component("windows_doctor"),
        "status": _component("windows_status"),
    }
    ok_components = ["doctor", "status"]
    if include_processes:
        components["processes"] = _embedded_processes_component()
        ok_components.append("processes")
    payload: dict[str, Any] = {
        "schema_version": 1,
        "mode": "windows_evidence_bundle",
        "status": "ok",
        "platform": {"system": "windows", "release": "2025", "machine": "AMD64"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_evidence_bundle",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "host": {"hostname": "WIN2025-SFAI01"},
        "python_runtime": {"version": "3.14.6", "executable": "python.exe"},
        "components": components,
        "summary": {
            "component_count": len(components),
            "ok_components": ok_components,
            "failed_components": [],
        },
        "not_collected_in_pr264": {
            "powershell_version": True,
            "execution_policy": True,
            "services": True,
            "processes": True,
            "event_logs": True,
        },
        "safety": _safe_flags(),
    }
    if include_processes:
        payload["embedded_processes"] = {
            "included": True,
            "limit": 25,
            "returned_count": 3,
            "total_count": 3,
            "truncated": False,
        }
    return payload


def _write(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _evidence_result(tmp_path: Path, payload: Any) -> dict[str, Any]:
    module = _acceptance_module()
    evidence = _write(tmp_path / "windows-evidence.json", payload)
    args = module.parse_args(
        [
            "--evidence-json",
            str(evidence),
            "--expected-host",
            "WIN2025-SFAI01",
            "--expected-python",
            "3.14.6",
        ]
    )
    return module._result(args)


def test_validator_accepts_evidence_bundle_with_embedded_processes(tmp_path: Path) -> None:
    result = _evidence_result(tmp_path, _evidence_payload(include_processes=True))
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "evidence.components.processes.mode" in names
    assert "evidence.components.processes.limit" in names
    assert "evidence.components.processes.method" in names
    assert "evidence.embedded_processes.included" in names
    assert "evidence.embedded_processes.consistent" in names


def test_validator_still_accepts_default_evidence_bundle(tmp_path: Path) -> None:
    result = _evidence_result(tmp_path, _evidence_payload())
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "evidence.components.processes.mode" not in names
    assert "evidence.embedded_processes.included" not in names


def test_validator_rejects_embedded_processes_mutation_flag_true(tmp_path: Path) -> None:
    payload = _evidence_payload(include_processes=True)
    payload["components"]["processes"]["mutation_performed"] = True
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.components.processes.mutation_performed" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_embedded_processes_command_line_field(tmp_path: Path) -> None:
    payload = _evidence_payload(include_processes=True)
    payload["components"]["processes"]["processes"][0]["command_line"] = "C:\\evil.exe --flag"
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.components.processes.processes[0].allowed_fields_only"
        and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_embedded_processes_failure(tmp_path: Path) -> None:
    payload = _evidence_payload(include_processes=True)
    payload["components"]["processes"]["status"] = "error"
    payload["summary"]["ok_components"] = ["doctor", "status"]
    payload["summary"]["failed_components"] = ["processes"]
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    failed_names = {check["name"] for check in result["checks"] if not check["passed"]}
    assert "evidence.components.processes.status" in failed_names
    assert "evidence.summary.failed_components" in failed_names


def test_validator_rejects_inconsistent_embedded_processes_block(tmp_path: Path) -> None:
    payload = _evidence_payload(include_processes=True)
    payload["embedded_processes"]["limit"] = 5  # component says 25
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.embedded_processes.consistent" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_wrong_component_count_with_processes(tmp_path: Path) -> None:
    payload = _evidence_payload(include_processes=True)
    payload["summary"]["component_count"] = 2
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.summary.component_count" and not check["passed"]
        for check in result["checks"]
    )


def test_cross_check_embedded_vs_standalone_processes_match_passes(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence = _write(tmp_path / "windows-evidence.json", _evidence_payload(include_processes=True))
    processes = _write(tmp_path / "windows-processes.json", _standalone_processes_payload())
    result = module._result(
        module.parse_args(["--evidence-json", str(evidence), "--processes-json", str(processes)])
    )
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "cross_check.processes.mode" in names
    assert "cross_check.processes.status" in names
    assert "cross_check.processes.method" in names


def test_cross_check_embedded_vs_standalone_processes_mismatch_fails(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence = _write(tmp_path / "windows-evidence.json", _evidence_payload(include_processes=True))
    standalone = _standalone_processes_payload()
    standalone["method"] = "different_method"
    processes = _write(tmp_path / "windows-processes.json", standalone)
    result = module._result(
        module.parse_args(["--evidence-json", str(evidence), "--processes-json", str(processes)])
    )
    assert result["status"] == "failed"
    assert any(
        check["name"] == "cross_check.processes.method" and not check["passed"]
        for check in result["checks"]
    )


# ---------------------------------------------------------------------------
# Packet helper: embedded and standalone processes.
# ---------------------------------------------------------------------------


def _packet_args(
    tmp_path: Path, evidence_payload: dict[str, Any], processes_payload: dict[str, Any] | None
) -> list[str]:
    evidence = _write(tmp_path / "windows-evidence.json", evidence_payload)
    status = _write(tmp_path / "windows-status.json", _component("windows_status"))
    doctor = _write(tmp_path / "windows-doctor.json", _component("windows_doctor"))
    args = [
        "--evidence-json",
        str(evidence),
        "--status-json",
        str(status),
        "--doctor-json",
        str(doctor),
        "--expected-host",
        "WIN2025-SFAI01",
        "--expected-python",
        "3.14.6",
        "--json",
    ]
    if processes_payload is not None:
        processes = _write(tmp_path / "windows-processes.json", processes_payload)
        args.extend(["--processes-json", str(processes)])
    return args


def test_packet_helper_summarizes_embedded_processes(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(
        _packet_args(tmp_path, _evidence_payload(include_processes=True), None)
    )
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    assert packet["embedded_processes"] == {
        "mode": "windows_processes",
        "status": "ok",
        "method": "ctypes_toolhelp32_snapshot",
        "limit": 25,
        "returned_count": 3,
        "total_count": 3,
        "truncated": False,
    }
    markdown = module.render_markdown(packet)
    assert "## Embedded processes component" in markdown
    assert "- Limit: 25" in markdown
    assert "- Returned processes: 3" in markdown
    assert "- Truncated: false" in markdown
    assert (
        "- Command lines, environments, memory, handles, modules, owners/users, "
        "and network connections were not collected." in markdown
    )


def test_packet_helper_without_processes_has_no_embedded_block(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(_packet_args(tmp_path, _evidence_payload(), None))
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    assert "embedded_processes" not in packet
    assert "## Embedded processes component" not in module.render_markdown(packet)


def test_packet_helper_still_accepts_standalone_processes_artifact(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(
        _packet_args(tmp_path, _evidence_payload(), _standalone_processes_payload())
    )
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    artifact = packet["artifacts"]["processes_json"]
    assert artifact["mode"] == "windows_processes"
    assert artifact["status"] == "ok"
    processes_summary = packet["windows"]["processes"]
    assert processes_summary["total_count"] == 3
    assert processes_summary["limit"] == 50


def test_packet_helper_with_embedded_and_standalone_processes(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(
        _packet_args(
            tmp_path, _evidence_payload(include_processes=True), _standalone_processes_payload()
        )
    )
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    assert packet["embedded_processes"]["total_count"] == 3
    assert packet["windows"]["processes"]["total_count"] == 3
    markdown = module.render_markdown(packet)
    assert "## Embedded processes component" in markdown
    assert "## Processes summary" in markdown


# ---------------------------------------------------------------------------
# Source safety guardrails.
# ---------------------------------------------------------------------------


def test_pr276_source_has_no_forbidden_execution_paths() -> None:
    for path in (
        Path("src/shellforgeai/windows_evidence.py"),
        Path("src/shellforgeai/windows_processes.py"),
        Path("src/shellforgeai/commands/windows.py"),
    ):
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        # "subprocess" appears in prose docstrings ("never uses subprocesses"),
        # so it is banned below as an import rather than as a source string.
        for forbidden in (
            "shell=true",
            "pwsh",
            "powershell.exe",
            "invoke-command",
            "new-pssession",
            "psremoting",
            "winrm ",
            "taskkill",
            "terminateprocess",
            "openprocess",
            "readprocessmemory",
            "ntqueryinformationprocess",
            "docker",
            "compose",
            "codex",
            "openai",
        ):
            assert forbidden not in lowered, f"{path} contains forbidden string {forbidden!r}"
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.keyword) and node.arg == "shell":
                assert node.value is not ast.Constant(value=True)
        for banned_module in ("subprocess", "socket", "http", "urllib", "winreg", "wmi", "psutil"):
            assert banned_module not in imported, f"{path} imports {banned_module}"


def test_pr276_evidence_path_performs_no_product_file_writes() -> None:
    for path in (
        Path("src/shellforgeai/windows_evidence.py"),
        Path("src/shellforgeai/commands/windows.py"),
    ):
        source = path.read_text(encoding="utf-8")
        for forbidden in ("write_text", "write_bytes", ".write(", "open(", "unlink", "rmtree"):
            assert forbidden not in source, f"{path} contains forbidden call {forbidden!r}"


def test_cli_inventory_still_classifies_windows_evidence_read_only() -> None:
    source = Path("scripts/cli_refactor_inventory.py").read_text(encoding="utf-8")
    assert (
        '"windows evidence": {"module": "windows.py", "category": "read_only", "known_pr": 264}'
        in source
    )
