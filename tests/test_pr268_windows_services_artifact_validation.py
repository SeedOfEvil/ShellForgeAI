"""PR268 Windows services saved-artifact validator and packet support tests."""

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
    return _load(ACCEPTANCE_SCRIPT, "windows_smoke_acceptance_pr268")


def _packet_module() -> ModuleType:
    sys.modules.pop("windows_smoke_acceptance", None)
    return _load(PACKET_SCRIPT, "windows_smoke_packet_pr268")


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


def _services_safe_flags() -> dict[str, bool]:
    flags = _safe_flags()
    flags["service_control_executed"] = False
    flags["service_config_modified"] = False
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


def _services_payload() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_services",
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_services",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "services": {
            "collection": "local_windows_service_state_summary",
            "total_count": 3,
            "state_counts": {
                "running": 2,
                "stopped": 1,
                "paused": 0,
                "start_pending": 0,
                "stop_pending": 0,
                "continue_pending": 0,
                "pause_pending": 0,
                "unknown": 0,
            },
            "items": [
                {
                    "name": "Dhcp",
                    "display_name": "DHCP Client",
                    "state": "running",
                    "service_type": "win32_share_process",
                },
                {
                    "name": "Dnscache",
                    "display_name": "DNS Client",
                    "state": "running",
                    "service_type": "win32_share_process",
                },
                {
                    "name": "Spooler",
                    "display_name": "Print Spooler",
                    "state": "stopped",
                    "service_type": "win32_own_process",
                },
            ],
            "collection_limits": {"max_services": 500, "truncated": False},
        },
        "not_collected_in_pr267": {
            "service_binary_path": "not collected in PR267",
            "service_account": "not collected in PR267",
            "event_logs": "planned for later read-only Windows evidence PR",
        },
        "safety": _services_safe_flags(),
        "next_safe_command": "shellforgeai windows status --json",
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
    services = _write(tmp_path / "windows-services.json", _services_payload(), encodings[3])
    return evidence, status, doctor, services


def _services_args(services: Path, *extra: str) -> list[str]:
    return [
        "--services-json",
        str(services),
        "--expected-host",
        "WIN2025-SFAI01",
        "--expected-python",
        "3.14.6",
        *extra,
    ]


def _packet_args(
    evidence: Path, status: Path, doctor: Path, services: Path | None, *extra: str
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
    if services is not None:
        args[6:6] = ["--services-json", str(services)]
    return args


def _services_result(tmp_path: Path, payload: Any) -> dict[str, Any]:
    module = _acceptance_module()
    services = _write(tmp_path / "windows-services.json", payload)
    return module._result(module.parse_args(_services_args(services)))


def _assert_services_check_fails(tmp_path: Path, payload: Any, expected_check: str) -> None:
    result = _services_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == expected_check and not check["passed"] for check in result["checks"]
    )


def test_valid_services_artifact_passes_validator(tmp_path: Path) -> None:
    module = _acceptance_module()
    services = _write(tmp_path / "windows-services.json", _services_payload())
    result = module._result(module.parse_args(_services_args(services)))
    assert result["status"] == "ok"
    assert result["artifacts"]["services"] == {
        "mode": "windows_services",
        "status": "ok",
        "validated": True,
    }
    assert result["inputs"]["services_json"] == str(services)
    assert module.main(_services_args(services, "--json")) == 0


def test_existing_validation_without_services_is_unchanged(tmp_path: Path) -> None:
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


def test_evidence_status_doctor_services_together_pass(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence, status, doctor, services = _all_paths(tmp_path)
    result = module._result(
        module.parse_args(
            [
                "--evidence-json",
                str(evidence),
                "--status-json",
                str(status),
                "--doctor-json",
                str(doctor),
                *_services_args(services),
            ]
        )
    )
    assert result["status"] == "ok"
    assert result["artifacts"]["services"]["validated"] is True
    assert result["artifacts"]["evidence"]["validated"] is True
    assert result["artifacts"]["status"]["validated"] is True
    assert result["artifacts"]["doctor"]["validated"] is True


def test_packet_includes_services_hash_size_mode_status(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, services = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, services, "--json"))
    )
    assert packet["status"] == "ok"
    artifact = packet["artifacts"]["services_json"]
    assert artifact["path"] == str(services)
    assert len(artifact["sha256"]) == 64
    assert artifact["size_bytes"] > 0
    assert artifact["mode"] == "windows_services"
    assert artifact["status"] == "ok"
    assert artifact["total"] == 3
    assert artifact["running"] == 2
    assert artifact["stopped"] == 1
    assert artifact["unknown"] == 0


def test_packet_markdown_includes_services_row_and_summary(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, services = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, services, "--markdown"))
    )
    markdown = module.render_markdown(packet)
    assert "| services_json |" in markdown
    assert "## Services summary" in markdown
    assert "- Total services: 3" in markdown
    assert "- Running: 2" in markdown
    assert "- Stopped: 1" in markdown
    assert "- Unknown: 0" in markdown


def test_packet_without_services_is_unchanged(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, _ = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, None, "--json"))
    )
    assert packet["status"] == "ok"
    assert set(packet["artifacts"]) == {"evidence_json", "status_json", "doctor_json"}
    assert "## Services summary" not in module.render_markdown(packet)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-bom", "utf-16le-bom"])
def test_services_artifact_encodings_pass(tmp_path: Path, encoding: str) -> None:
    module = _acceptance_module()
    services = _write(tmp_path / "windows-services.json", _services_payload(), encoding)
    result = module._result(module.parse_args(_services_args(services)))
    assert result["status"] == "ok"


def test_mixed_encodings_across_all_artifacts_pass(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence, status, doctor, services = _all_paths(
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
                *_services_args(services),
            ]
        )
    )
    assert result["status"] == "ok"

    packet_module = _packet_module()
    packet = packet_module.build_packet(
        packet_module.parse_args(_packet_args(evidence, status, doctor, services, "--json"))
    )
    assert packet["status"] == "ok"


def test_missing_services_path_fails_cleanly(tmp_path: Path) -> None:
    module = _acceptance_module()
    missing = tmp_path / "missing-services.json"
    result = module._result(module.parse_args(_services_args(missing)))
    assert result["status"] == "failed"
    assert any(
        check["name"] == "services.file_exists" and not check["passed"]
        for check in result["checks"]
    )
    assert module.main(_services_args(missing, "--json")) == 1


def test_invalid_services_json_fails_cleanly(tmp_path: Path) -> None:
    module = _acceptance_module()
    services = tmp_path / "windows-services.json"
    services.write_text("{not json", encoding="utf-8")
    result = module._result(module.parse_args(_services_args(services)))
    assert result["status"] == "failed"
    assert any(
        check["name"] == "services.json_parse" and not check["passed"] for check in result["checks"]
    )
    assert module.main(_services_args(services)) == 1


def test_non_object_services_json_fails_cleanly(tmp_path: Path) -> None:
    result = _services_result(tmp_path, ["not", "an", "object"])
    assert result["status"] == "failed"
    assert any(
        check["name"] == "services.object" and not check["passed"] for check in result["checks"]
    )


def test_wrong_mode_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["mode"] = "windows_status"
    _assert_services_check_fails(tmp_path, payload, "services.mode")


def test_non_ok_status_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["status"] = "error"
    _assert_services_check_fails(tmp_path, payload, "services.status")


def test_non_windows_platform_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["platform"] = {"system": "linux"}
    _assert_services_check_fails(tmp_path, payload, "services.platform.system")


def test_read_only_false_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["read_only"] = False
    _assert_services_check_fails(tmp_path, payload, "services.read_only")


def test_mutation_performed_true_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["mutation_performed"] = True
    _assert_services_check_fails(tmp_path, payload, "services.mutation_performed")


def test_wrong_schema_version_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["schema_version"] = 2
    _assert_services_check_fails(tmp_path, payload, "services.schema_version")


def test_windows_v1_unavailable_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["windows_v1"]["available"] = False
    _assert_services_check_fails(tmp_path, payload, "services.windows_v1.available")


def test_missing_services_summary_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    del payload["services"]
    _assert_services_check_fails(tmp_path, payload, "services.services.object")


def test_missing_total_count_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    del payload["services"]["total_count"]
    _assert_services_check_fails(tmp_path, payload, "services.services.total_count")


@pytest.mark.parametrize("key", ["running", "stopped", "unknown"])
def test_missing_state_count_fails(tmp_path: Path, key: str) -> None:
    payload = _services_payload()
    del payload["services"]["state_counts"][key]
    _assert_services_check_fails(tmp_path, payload, f"services.services.state_counts.{key}")


def test_negative_total_count_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["services"]["total_count"] = -1
    _assert_services_check_fails(tmp_path, payload, "services.services.total_count")


@pytest.mark.parametrize("key", ["running", "stopped", "unknown"])
def test_negative_state_count_fails(tmp_path: Path, key: str) -> None:
    payload = _services_payload()
    payload["services"]["state_counts"][key] = -2
    _assert_services_check_fails(tmp_path, payload, f"services.services.state_counts.{key}")


def test_missing_services_items_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    del payload["services"]["items"]
    _assert_services_check_fails(tmp_path, payload, "services.services.items")


def test_consistent_truncation_passes(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["services"]["total_count"] = 5
    payload["services"]["state_counts"]["running"] = 4
    payload["services"]["collection_limits"] = {"max_services": 3, "truncated": True}
    result = _services_result(tmp_path, payload)
    assert result["status"] == "ok"


def test_inconsistent_truncation_fails(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["services"]["collection_limits"] = {"truncated": True}
    _assert_services_check_fails(tmp_path, payload, "services.services.truncation_consistent")


@pytest.mark.parametrize(
    "key",
    [
        "powershell_executed",
        "winrm_used",
        "remote_execution",
        "service_restart_executed",
        "service_control_executed",
        "service_config_modified",
        "process_termination_executed",
        "registry_modified",
        "execution_policy_modified",
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
    payload = _services_payload()
    payload["safety"][key] = True
    _assert_services_check_fails(tmp_path, payload, f"services.safety.{key}")


def test_expected_host_mismatch_fails_when_host_data_exists(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["host"] = {"hostname": "OTHER-HOST"}
    _assert_services_check_fails(tmp_path, payload, "services.host.expected")


def test_expected_host_and_python_skipped_when_absent(tmp_path: Path) -> None:
    result = _services_result(tmp_path, _services_payload())
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "services.host.expected" not in names
    assert "services.python_runtime.expected" not in names


def test_expected_python_mismatch_fails_when_runtime_data_exists(tmp_path: Path) -> None:
    payload = _services_payload()
    payload["python_runtime"] = {"version": "3.12.1", "executable": "python.exe"}
    _assert_services_check_fails(tmp_path, payload, "services.python_runtime.expected")


def test_source_safety_no_subprocess() -> None:
    for script in (ACCEPTANCE_SCRIPT, PACKET_SCRIPT):
        source = script.read_text(encoding="utf-8").lower()
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "shell=true" not in source


def test_source_safety_no_product_command_imports() -> None:
    for script in (ACCEPTANCE_SCRIPT, PACKET_SCRIPT):
        source = script.read_text(encoding="utf-8")
        assert "from shellforgeai" not in source
        assert "import shellforgeai" not in source
        assert "src.shellforgeai" not in source
        assert "shellforgeai.commands" not in source


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
