"""PR275 Windows processes saved-artifact validator and packet support tests."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ACCEPTANCE_SCRIPT = Path("scripts/windows_smoke_acceptance.py")
PACKET_SCRIPT = Path("scripts/windows_smoke_packet.py")


def _load(script: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _acceptance_module() -> ModuleType:
    return _load(ACCEPTANCE_SCRIPT, "windows_smoke_acceptance_pr275")


def _packet_module() -> ModuleType:
    sys.modules.pop("windows_smoke_acceptance", None)
    return _load(PACKET_SCRIPT, "windows_smoke_packet_pr275")


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
    flags["process_control_executed"] = False
    flags["process_config_modified"] = False
    flags["process_memory_read"] = False
    flags["process_command_line_read"] = False
    flags["process_environment_read"] = False
    flags["process_handles_read"] = False
    flags["process_modules_read"] = False
    flags["process_owner_read"] = False
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


def _evidence_payload() -> dict[str, Any]:
    return {
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
        "components": {
            "doctor": _component("windows_doctor"),
            "status": _component("windows_status"),
        },
        "summary": {
            "component_count": 2,
            "ok_components": ["doctor", "status"],
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


def _processes_payload() -> dict[str, Any]:
    """A PR274-shaped windows_processes artifact, matching the WIN2025-SFAI01 smoke."""

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


def _write(path: Path, payload: Any, encoding: str = "utf-8") -> Path:
    text = json.dumps(payload, sort_keys=True)
    if encoding == "utf-8-bom":
        path.write_text(text, encoding="utf-8-sig")
    elif encoding == "utf-16le-bom":
        path.write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))
    elif encoding == "utf-16":
        path.write_text(text, encoding="utf-16")
    else:
        path.write_text(text, encoding="utf-8")
    return path


def _all_paths(
    tmp_path: Path, encodings: tuple[str, str, str, str] = ("utf-8",) * 4
) -> tuple[Path, Path, Path, Path]:
    evidence = _write(tmp_path / "windows-evidence.json", _evidence_payload(), encodings[0])
    status = _write(tmp_path / "windows-status.json", _component("windows_status"), encodings[1])
    doctor = _write(tmp_path / "windows-doctor.json", _component("windows_doctor"), encodings[2])
    processes = _write(tmp_path / "windows-processes.json", _processes_payload(), encodings[3])
    return evidence, status, doctor, processes


def _processes_args(processes: Path, *extra: str) -> list[str]:
    return [
        "--processes-json",
        str(processes),
        "--expected-host",
        "WIN2025-SFAI01",
        "--expected-python",
        "3.14.6",
        *extra,
    ]


def _packet_args(
    evidence: Path, status: Path, doctor: Path, processes: Path | None, *extra: str
) -> list[str]:
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
        *extra,
    ]
    if processes is not None:
        args[6:6] = ["--processes-json", str(processes)]
    return args


def _processes_result(tmp_path: Path, payload: Any) -> dict[str, Any]:
    module = _acceptance_module()
    processes = _write(tmp_path / "windows-processes.json", payload)
    return module._result(module.parse_args(_processes_args(processes)))


def _assert_processes_check_fails(tmp_path: Path, payload: Any, expected_check: str) -> None:
    result = _processes_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == expected_check and not check["passed"] for check in result["checks"]
    )


def test_valid_processes_artifact_passes_validator(tmp_path: Path) -> None:
    module = _acceptance_module()
    processes = _write(tmp_path / "windows-processes.json", _processes_payload())
    result = module._result(module.parse_args(_processes_args(processes)))
    assert result["status"] == "ok"
    assert result["artifacts"]["processes"] == {
        "mode": "windows_processes",
        "status": "ok",
        "validated": True,
    }
    assert result["inputs"]["processes_json"] == str(processes)
    assert module.main(_processes_args(processes, "--json")) == 0


def test_existing_validation_without_processes_is_unchanged(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence, status, doctor, _ = _all_paths(tmp_path)
    result = module._result(
        module.parse_args(
            [
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
            ]
        )
    )
    assert result["status"] == "ok"
    assert set(result["artifacts"]) == {"evidence", "status", "doctor"}
    assert set(result["inputs"]) == {"evidence_json", "status_json", "doctor_json"}


def test_evidence_status_doctor_processes_together_pass(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence, status, doctor, processes = _all_paths(tmp_path)
    result = module._result(
        module.parse_args(
            [
                "--evidence-json",
                str(evidence),
                "--status-json",
                str(status),
                "--doctor-json",
                str(doctor),
                *_processes_args(processes),
            ]
        )
    )
    assert result["status"] == "ok"
    assert result["artifacts"]["processes"]["validated"] is True
    assert result["artifacts"]["evidence"]["validated"] is True
    assert result["artifacts"]["status"]["validated"] is True
    assert result["artifacts"]["doctor"]["validated"] is True


def test_packet_includes_processes_hash_size_mode_status(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, processes = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, processes, "--json"))
    )
    assert packet["status"] == "ok"
    artifact = packet["artifacts"]["processes_json"]
    assert artifact["path"] == str(processes)
    assert len(artifact["sha256"]) == 64
    assert artifact["size_bytes"] > 0
    assert artifact["mode"] == "windows_processes"
    assert artifact["status"] == "ok"


def test_packet_json_includes_processes_summary(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, processes = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, processes, "--json"))
    )
    summary = packet["windows"]["processes"]
    assert summary == {
        "method": "ctypes_toolhelp32_snapshot",
        "total_count": 3,
        "returned_count": 3,
        "limit": 50,
        "truncated": False,
    }


def test_packet_markdown_includes_processes_summary(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, processes = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, processes, "--markdown"))
    )
    markdown = module.render_markdown(packet)
    assert "| processes_json |" in markdown
    assert "## Processes summary" in markdown
    assert "- Method: ctypes_toolhelp32_snapshot" in markdown
    assert "- Total processes: 3" in markdown
    assert "- Returned processes: 3" in markdown
    assert "- Limit: 50" in markdown
    assert "- Truncated: false" in markdown
    assert (
        "- Command lines, environments, memory, handles, modules, owners/users, "
        "and network connections were not collected." in markdown
    )


def test_packet_without_processes_is_unchanged(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, _ = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, None, "--json"))
    )
    assert packet["status"] == "ok"
    assert set(packet["artifacts"]) == {"evidence_json", "status_json", "doctor_json"}
    assert "processes" not in packet["windows"]
    assert "## Processes summary" not in module.render_markdown(packet)


def test_packet_fails_when_processes_validation_fails(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, _ = _all_paths(tmp_path)
    payload = _processes_payload()
    payload["safety"]["process_termination_executed"] = True
    processes = _write(tmp_path / "windows-processes.json", payload)
    args = module.parse_args(_packet_args(evidence, status, doctor, processes, "--json"))
    packet = module.build_packet(args)
    assert packet["status"] == "failed"
    assert any(
        check["name"] == "processes.safety.process_termination_executed"
        for check in packet["failed_checks"]
    )
    assert module.main(_packet_args(evidence, status, doctor, processes, "--json")) == 1


def test_packet_writes_explicit_output_files_only(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, processes = _all_paths(tmp_path)
    out_json = tmp_path / "packet.json"
    out_markdown = tmp_path / "PR275-QA-EVIDENCE.md"
    exit_code = module.main(
        _packet_args(
            evidence,
            status,
            doctor,
            processes,
            "--commit",
            "abc1234",
            "--pr",
            "275",
            "--out-json",
            str(out_json),
            "--out-markdown",
            str(out_markdown),
        )
    )
    assert exit_code == 0
    packet = json.loads(out_json.read_text(encoding="utf-8"))
    assert packet["pr"] == 275
    assert packet["artifacts"]["processes_json"]["mode"] == "windows_processes"
    assert packet["windows"]["processes"]["method"] == "ctypes_toolhelp32_snapshot"
    assert "## Processes summary" in out_markdown.read_text(encoding="utf-8")


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-bom", "utf-16le-bom"])
def test_processes_artifact_encodings_pass(tmp_path: Path, encoding: str) -> None:
    module = _acceptance_module()
    processes = _write(tmp_path / "windows-processes.json", _processes_payload(), encoding)
    result = module._result(module.parse_args(_processes_args(processes)))
    assert result["status"] == "ok"


def test_mixed_encodings_across_all_artifacts_pass(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence, status, doctor, processes = _all_paths(
        tmp_path, ("utf-8", "utf-8-bom", "utf-16", "utf-16le-bom")
    )
    result = module._result(
        module.parse_args(
            [
                "--evidence-json",
                str(evidence),
                "--status-json",
                str(status),
                "--doctor-json",
                str(doctor),
                *_processes_args(processes),
            ]
        )
    )
    assert result["status"] == "ok"

    packet_module = _packet_module()
    packet = packet_module.build_packet(
        packet_module.parse_args(_packet_args(evidence, status, doctor, processes, "--json"))
    )
    assert packet["status"] == "ok"


def test_missing_processes_path_fails_cleanly(tmp_path: Path) -> None:
    module = _acceptance_module()
    missing = tmp_path / "missing-processes.json"
    result = module._result(module.parse_args(_processes_args(missing)))
    assert result["status"] == "failed"
    assert any(
        check["name"] == "processes.file_exists" and not check["passed"]
        for check in result["checks"]
    )
    assert module.main(_processes_args(missing, "--json")) == 1


def test_invalid_processes_json_fails_cleanly(tmp_path: Path) -> None:
    module = _acceptance_module()
    processes = tmp_path / "windows-processes.json"
    processes.write_text("{not json", encoding="utf-8")
    result = module._result(module.parse_args(_processes_args(processes)))
    assert result["status"] == "failed"
    assert any(
        check["name"] == "processes.json_parse" and not check["passed"]
        for check in result["checks"]
    )
    assert module.main(_processes_args(processes)) == 1


def test_non_object_processes_json_fails_cleanly(tmp_path: Path) -> None:
    result = _processes_result(tmp_path, ["not", "an", "object"])
    assert result["status"] == "failed"
    assert any(
        check["name"] == "processes.object" and not check["passed"] for check in result["checks"]
    )


def test_wrong_mode_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["mode"] = "windows_services"
    _assert_processes_check_fails(tmp_path, payload, "processes.mode")


def test_non_ok_status_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["status"] = "unsupported"
    _assert_processes_check_fails(tmp_path, payload, "processes.status")


def test_non_windows_platform_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["platform"] = {"system": "linux"}
    _assert_processes_check_fails(tmp_path, payload, "processes.platform.system")


def test_read_only_false_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["read_only"] = False
    _assert_processes_check_fails(tmp_path, payload, "processes.read_only")


def test_mutation_performed_true_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["mutation_performed"] = True
    _assert_processes_check_fails(tmp_path, payload, "processes.mutation_performed")


def test_wrong_schema_version_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["schema_version"] = 2
    _assert_processes_check_fails(tmp_path, payload, "processes.schema_version")


def test_windows_v1_unavailable_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["windows_v1"]["available"] = False
    _assert_processes_check_fails(tmp_path, payload, "processes.windows_v1.available")


def test_wrong_scope_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["windows_v1"]["scope"] = "local_read_only_services"
    _assert_processes_check_fails(tmp_path, payload, "processes.windows_v1.scope")


def test_missing_method_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    del payload["method"]
    _assert_processes_check_fails(tmp_path, payload, "processes.method")


def test_wrong_method_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["method"] = "powershell_get_process"
    _assert_processes_check_fails(tmp_path, payload, "processes.method")


@pytest.mark.parametrize("limit", [0, -1, 201, "50", True, None])
def test_invalid_limit_fails(tmp_path: Path, limit: Any) -> None:
    payload = _processes_payload()
    payload["limit"] = limit
    _assert_processes_check_fails(tmp_path, payload, "processes.limit")


def test_negative_total_count_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["total_count"] = -1
    _assert_processes_check_fails(tmp_path, payload, "processes.total_count")


def test_negative_returned_count_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["returned_count"] = -1
    _assert_processes_check_fails(tmp_path, payload, "processes.returned_count")


def test_returned_count_greater_than_limit_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["limit"] = 2
    _assert_processes_check_fails(tmp_path, payload, "processes.returned_le_limit")


def test_returned_count_greater_than_total_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["total_count"] = 2
    _assert_processes_check_fails(tmp_path, payload, "processes.returned_le_total")


@pytest.mark.parametrize("truncated", ["false", 0, None])
def test_non_boolean_truncated_fails(tmp_path: Path, truncated: Any) -> None:
    payload = _processes_payload()
    payload["truncated"] = truncated
    _assert_processes_check_fails(tmp_path, payload, "processes.truncated")


def test_missing_truncated_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    del payload["truncated"]
    _assert_processes_check_fails(tmp_path, payload, "processes.truncated")


def test_consistent_truncation_passes(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["limit"] = 2
    payload["returned_count"] = 2
    payload["truncated"] = True
    payload["processes"] = payload["processes"][:2]
    result = _processes_result(tmp_path, payload)
    assert result["status"] == "ok"


def test_inconsistent_truncation_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["truncated"] = True
    _assert_processes_check_fails(tmp_path, payload, "processes.truncation_consistent")


def test_processes_not_list_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["processes"] = {"pid": 4}
    _assert_processes_check_fails(tmp_path, payload, "processes.processes.list")


def test_missing_processes_list_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    del payload["processes"]
    _assert_processes_check_fails(tmp_path, payload, "processes.processes.list")


def test_processes_list_count_mismatch_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["processes"] = payload["processes"][:2]
    _assert_processes_check_fails(
        tmp_path, payload, "processes.processes.returned_count_consistent"
    )


def test_non_object_process_item_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["processes"][0] = "svchost.exe"
    _assert_processes_check_fails(tmp_path, payload, "processes.processes[0].object")


@pytest.mark.parametrize(
    "field",
    [
        "command_line",
        "cmdline",
        "environment",
        "environ",
        "memory",
        "memory_bytes",
        "handles",
        "handle_count_detail",
        "modules",
        "loaded_modules",
        "owner",
        "user",
        "token",
        "network_connections",
        "connections",
        "path",
        "exe_path",
        "executable",
    ],
)
def test_process_item_with_forbidden_field_fails(tmp_path: Path, field: str) -> None:
    payload = _processes_payload()
    payload["processes"][0][field] = "forbidden"
    _assert_processes_check_fails(tmp_path, payload, "processes.processes[0].allowed_fields_only")


def test_process_item_with_negative_pid_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["processes"][0]["pid"] = -1
    _assert_processes_check_fails(tmp_path, payload, "processes.processes[0].pid")


def test_process_item_with_non_string_name_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["processes"][0]["name"] = 42
    _assert_processes_check_fails(tmp_path, payload, "processes.processes[0].name")


@pytest.mark.parametrize(
    "key",
    [
        "command_line",
        "environment",
        "memory",
        "handles",
        "modules",
        "owner_user",
        "network_connections",
    ],
)
def test_missing_not_collected_key_fails(tmp_path: Path, key: str) -> None:
    payload = _processes_payload()
    del payload["not_collected_in_pr274"][key]
    _assert_processes_check_fails(tmp_path, payload, f"processes.not_collected_in_pr274.{key}")


def test_missing_not_collected_block_fails(tmp_path: Path) -> None:
    payload = _processes_payload()
    del payload["not_collected_in_pr274"]
    _assert_processes_check_fails(
        tmp_path, payload, "processes.not_collected_in_pr274.command_line"
    )


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
        "secret_read",
        "auth_cache_read",
        "model_called",
        "network_call",
    ],
)
def test_safety_flag_true_fails(tmp_path: Path, key: str) -> None:
    payload = _processes_payload()
    payload["safety"][key] = True
    _assert_processes_check_fails(tmp_path, payload, f"processes.safety.{key}")


@pytest.mark.parametrize("key", ["powershell_executed", "winrm_used", "remote_execution"])
def test_windows_v1_flag_true_fails(tmp_path: Path, key: str) -> None:
    payload = _processes_payload()
    payload["windows_v1"][key] = True
    _assert_processes_check_fails(tmp_path, payload, f"processes.windows_v1.{key}")


def test_expected_host_mismatch_fails_when_host_data_exists(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["host"] = {"hostname": "OTHER-HOST"}
    _assert_processes_check_fails(tmp_path, payload, "processes.host.expected")


def test_expected_python_mismatch_fails_when_runtime_data_exists(tmp_path: Path) -> None:
    payload = _processes_payload()
    payload["python_runtime"] = {"version": "3.12.1", "executable": "python.exe"}
    _assert_processes_check_fails(tmp_path, payload, "processes.python_runtime.expected")


def test_expected_host_and_python_skipped_when_absent(tmp_path: Path) -> None:
    result = _processes_result(tmp_path, _processes_payload())
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "processes.host.expected" not in names
    assert "processes.python_runtime.expected" not in names


def test_source_safety_no_subprocess() -> None:
    for script in (ACCEPTANCE_SCRIPT, PACKET_SCRIPT):
        source = script.read_text(encoding="utf-8").lower()
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "shell=true" not in source


def test_source_safety_no_powershell_or_winrm_execution() -> None:
    for script in (ACCEPTANCE_SCRIPT, PACKET_SCRIPT):
        source = script.read_text(encoding="utf-8").lower()
        assert "powershell.exe" not in source
        assert "pwsh" not in source
        assert "winrs" not in source
        assert "enter-pssession" not in source
        assert "invoke-command" not in source
        assert "urllib.request" not in source
        assert "http.client" not in source
        assert "socket" not in source


def test_source_safety_no_product_command_imports() -> None:
    for script in (ACCEPTANCE_SCRIPT, PACKET_SCRIPT):
        source = script.read_text(encoding="utf-8")
        assert "from shellforgeai" not in source
        assert "import shellforgeai" not in source
        assert "src.shellforgeai" not in source
        assert "shellforgeai.commands" not in source
