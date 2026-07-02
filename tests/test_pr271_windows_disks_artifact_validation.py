"""PR271 Windows disks saved-artifact validator and packet support tests."""

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
    return _load(ACCEPTANCE_SCRIPT, "windows_smoke_acceptance_pr271")


def _packet_module() -> ModuleType:
    sys.modules.pop("windows_smoke_acceptance", None)
    return _load(PACKET_SCRIPT, "windows_smoke_packet_pr271")


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


def _disks_safe_flags() -> dict[str, bool]:
    flags = _safe_flags()
    flags["directory_scan_performed"] = False
    flags["file_scan_performed"] = False
    flags["disk_mutation_performed"] = False
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
    safety = _safe_flags()
    safety["service_control_executed"] = False
    safety["service_config_modified"] = False
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
            "total_count": 2,
            "state_counts": {"running": 1, "stopped": 1, "unknown": 0},
            "items": [
                {"name": "Dhcp", "display_name": "DHCP Client", "state": "running"},
                {"name": "Spooler", "display_name": "Print Spooler", "state": "stopped"},
            ],
            "collection_limits": {"max_services": 500, "truncated": False},
        },
        "safety": safety,
        "next_safe_command": "shellforgeai windows status --json",
    }


def _disks_payload() -> dict[str, Any]:
    """A PR270-shaped windows_disks artifact, matching the WIN2025-SFAI01 smoke.

    Three roots total: one available, two unavailable sanitized as
    ``disk_usage_failed``.
    """

    return {
        "schema_version": 1,
        "mode": "windows_disks",
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_disks",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "collection": {
            "method": "stdlib_only",
            "root_discovery": "os.listdrives_or_current_root_fallback",
            "directory_scan_performed": False,
            "file_scan_performed": False,
            "limit": 32,
            "truncated": False,
        },
        "summary": {
            "total_roots": 3,
            "returned_roots": 3,
            "available_roots": 1,
            "unavailable_roots": 2,
        },
        "disks": [
            {"root": "A:\\", "status": "unavailable", "error": "disk_usage_failed"},
            {
                "root": "C:\\",
                "status": "ok",
                "total_bytes": 137438953472,
                "used_bytes": 68719476736,
                "free_bytes": 68719476736,
            },
            {"root": "D:\\", "status": "unavailable", "error": "disk_usage_failed"},
        ],
        "not_collected_in_pr270": {
            "drive_labels": "not collected because PR270 uses stdlib-only root usage checks",
            "volume_serials": "not collected because PR270 does not query Windows APIs or registry",
            "bitlocker": "planned for later read-only Windows evidence PR only if safe",
            "smart_health": "not collected because PR270 does not query device health APIs",
            "file_inventory": "not collected because PR270 does not enumerate files or directories",
        },
        "safety": _disks_safe_flags(),
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
    disks = _write(tmp_path / "windows-disks.json", _disks_payload(), encodings[3])
    return evidence, status, doctor, disks


def _disks_args(disks: Path, *extra: str) -> list[str]:
    return [
        "--disks-json",
        str(disks),
        "--expected-host",
        "WIN2025-SFAI01",
        "--expected-python",
        "3.14.6",
        *extra,
    ]


def _packet_args(
    evidence: Path, status: Path, doctor: Path, disks: Path | None, *extra: str
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
    if disks is not None:
        args[6:6] = ["--disks-json", str(disks)]
    return args


def _disks_result(tmp_path: Path, payload: Any) -> dict[str, Any]:
    module = _acceptance_module()
    disks = _write(tmp_path / "windows-disks.json", payload)
    return module._result(module.parse_args(_disks_args(disks)))


def _assert_disks_check_fails(tmp_path: Path, payload: Any, expected_check: str) -> None:
    result = _disks_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == expected_check and not check["passed"] for check in result["checks"]
    )


def test_valid_disks_artifact_passes_validator(tmp_path: Path) -> None:
    module = _acceptance_module()
    disks = _write(tmp_path / "windows-disks.json", _disks_payload())
    result = module._result(module.parse_args(_disks_args(disks)))
    assert result["status"] == "ok"
    assert result["artifacts"]["disks"] == {
        "mode": "windows_disks",
        "status": "ok",
        "validated": True,
    }
    assert result["inputs"]["disks_json"] == str(disks)
    assert module.main(_disks_args(disks, "--json")) == 0


def test_existing_validation_without_disks_is_unchanged(tmp_path: Path) -> None:
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


def test_evidence_status_doctor_disks_together_pass(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence, status, doctor, disks = _all_paths(tmp_path)
    result = module._result(
        module.parse_args(
            [
                "--evidence-json",
                str(evidence),
                "--status-json",
                str(status),
                "--doctor-json",
                str(doctor),
                *_disks_args(disks),
            ]
        )
    )
    assert result["status"] == "ok"
    assert result["artifacts"]["disks"]["validated"] is True
    assert result["artifacts"]["evidence"]["validated"] is True
    assert result["artifacts"]["status"]["validated"] is True
    assert result["artifacts"]["doctor"]["validated"] is True


def test_evidence_status_doctor_services_disks_together_pass(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence, status, doctor, disks = _all_paths(tmp_path)
    services = _write(tmp_path / "windows-services.json", _services_payload())
    result = module._result(
        module.parse_args(
            [
                "--evidence-json",
                str(evidence),
                "--status-json",
                str(status),
                "--doctor-json",
                str(doctor),
                "--services-json",
                str(services),
                *_disks_args(disks),
            ]
        )
    )
    assert result["status"] == "ok"
    assert result["artifacts"]["services"]["validated"] is True
    assert result["artifacts"]["disks"]["validated"] is True


def test_packet_includes_disks_hash_size_mode_status(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, disks = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, disks, "--json"))
    )
    assert packet["status"] == "ok"
    artifact = packet["artifacts"]["disks_json"]
    assert artifact["path"] == str(disks)
    assert len(artifact["sha256"]) == 64
    assert artifact["size_bytes"] > 0
    assert artifact["mode"] == "windows_disks"
    assert artifact["status"] == "ok"


def test_packet_includes_safe_disk_summary_fields(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, disks = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, disks, "--json"))
    )
    artifact = packet["artifacts"]["disks_json"]
    assert artifact["total_roots"] == 3
    assert artifact["returned_roots"] == 3
    assert artifact["available_roots"] == 1
    assert artifact["unavailable_roots"] == 2
    assert artifact["limit"] == 32
    assert artifact["truncated"] is False


def test_packet_markdown_includes_disks_row_and_summary(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, disks = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, disks, "--markdown"))
    )
    markdown = module.render_markdown(packet)
    assert "| disks_json |" in markdown
    assert "## Disks summary" in markdown
    assert "- Total roots: 3" in markdown
    assert "- Returned roots: 3" in markdown
    assert "- Available roots: 1" in markdown
    assert "- Unavailable roots: 2" in markdown
    assert "- Limit: 32" in markdown
    assert "- Truncated: false" in markdown
    assert "disk_usage_failed" in markdown


def test_packet_without_disks_is_unchanged(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, _ = _all_paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(_packet_args(evidence, status, doctor, None, "--json"))
    )
    assert packet["status"] == "ok"
    assert set(packet["artifacts"]) == {"evidence_json", "status_json", "doctor_json"}
    assert "## Disks summary" not in module.render_markdown(packet)


def test_packet_writes_explicit_output_files_only(tmp_path: Path) -> None:
    module = _packet_module()
    evidence, status, doctor, disks = _all_paths(tmp_path)
    out_json = tmp_path / "packet.json"
    out_markdown = tmp_path / "PR271-QA-EVIDENCE.md"
    exit_code = module.main(
        _packet_args(
            evidence,
            status,
            doctor,
            disks,
            "--commit",
            "abc1234",
            "--pr",
            "271",
            "--out-json",
            str(out_json),
            "--out-markdown",
            str(out_markdown),
        )
    )
    assert exit_code == 0
    packet = json.loads(out_json.read_text(encoding="utf-8"))
    assert packet["pr"] == 271
    assert packet["artifacts"]["disks_json"]["mode"] == "windows_disks"
    assert "## Disks summary" in out_markdown.read_text(encoding="utf-8")


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-bom", "utf-16le-bom"])
def test_disks_artifact_encodings_pass(tmp_path: Path, encoding: str) -> None:
    module = _acceptance_module()
    disks = _write(tmp_path / "windows-disks.json", _disks_payload(), encoding)
    result = module._result(module.parse_args(_disks_args(disks)))
    assert result["status"] == "ok"


def test_mixed_encodings_across_all_artifacts_pass(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence, status, doctor, disks = _all_paths(
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
                *_disks_args(disks),
            ]
        )
    )
    assert result["status"] == "ok"

    packet_module = _packet_module()
    packet = packet_module.build_packet(
        packet_module.parse_args(_packet_args(evidence, status, doctor, disks, "--json"))
    )
    assert packet["status"] == "ok"


def test_missing_disks_path_fails_cleanly(tmp_path: Path) -> None:
    module = _acceptance_module()
    missing = tmp_path / "missing-disks.json"
    result = module._result(module.parse_args(_disks_args(missing)))
    assert result["status"] == "failed"
    assert any(
        check["name"] == "disks.file_exists" and not check["passed"] for check in result["checks"]
    )
    assert module.main(_disks_args(missing, "--json")) == 1


def test_invalid_disks_json_fails_cleanly(tmp_path: Path) -> None:
    module = _acceptance_module()
    disks = tmp_path / "windows-disks.json"
    disks.write_text("{not json", encoding="utf-8")
    result = module._result(module.parse_args(_disks_args(disks)))
    assert result["status"] == "failed"
    assert any(
        check["name"] == "disks.json_parse" and not check["passed"] for check in result["checks"]
    )
    assert module.main(_disks_args(disks)) == 1


def test_non_object_disks_json_fails_cleanly(tmp_path: Path) -> None:
    result = _disks_result(tmp_path, ["not", "an", "object"])
    assert result["status"] == "failed"
    assert any(
        check["name"] == "disks.object" and not check["passed"] for check in result["checks"]
    )


def test_wrong_mode_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["mode"] = "windows_status"
    _assert_disks_check_fails(tmp_path, payload, "disks.mode")


def test_non_ok_status_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["status"] = "error"
    _assert_disks_check_fails(tmp_path, payload, "disks.status")


def test_non_windows_platform_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["platform"] = {"system": "linux"}
    _assert_disks_check_fails(tmp_path, payload, "disks.platform.system")


def test_read_only_false_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["read_only"] = False
    _assert_disks_check_fails(tmp_path, payload, "disks.read_only")


def test_mutation_performed_true_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["mutation_performed"] = True
    _assert_disks_check_fails(tmp_path, payload, "disks.mutation_performed")


def test_wrong_schema_version_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["schema_version"] = 2
    _assert_disks_check_fails(tmp_path, payload, "disks.schema_version")


def test_windows_v1_unavailable_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["windows_v1"]["available"] = False
    _assert_disks_check_fails(tmp_path, payload, "disks.windows_v1.available")


def test_wrong_scope_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["windows_v1"]["scope"] = "local_read_only_services"
    _assert_disks_check_fails(tmp_path, payload, "disks.windows_v1.scope")


def test_wrong_collection_method_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["collection"]["method"] = "powershell"
    _assert_disks_check_fails(tmp_path, payload, "disks.collection.method")


@pytest.mark.parametrize(
    "key",
    [
        "powershell_executed",
        "winrm_used",
        "remote_execution",
        "directory_scan_performed",
        "file_scan_performed",
        "service_restart_executed",
        "process_termination_executed",
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
    payload = _disks_payload()
    payload["safety"][key] = True
    _assert_disks_check_fails(tmp_path, payload, f"disks.safety.{key}")


@pytest.mark.parametrize(
    "key",
    ["disk_mutation_executed", "mount_modified", "format_executed"],
)
def test_optional_safety_flag_true_fails_when_present(tmp_path: Path, key: str) -> None:
    payload = _disks_payload()
    payload["safety"][key] = True
    _assert_disks_check_fails(tmp_path, payload, f"disks.safety.{key}")


@pytest.mark.parametrize(
    "key",
    ["disk_mutation_executed", "mount_modified", "format_executed"],
)
def test_optional_safety_flag_false_passes_when_present(tmp_path: Path, key: str) -> None:
    payload = _disks_payload()
    payload["safety"][key] = False
    result = _disks_result(tmp_path, payload)
    assert result["status"] == "ok"


@pytest.mark.parametrize("key", ["directory_scan_performed", "file_scan_performed"])
def test_collection_scan_flag_true_fails(tmp_path: Path, key: str) -> None:
    payload = _disks_payload()
    payload["collection"][key] = True
    _assert_disks_check_fails(tmp_path, payload, f"disks.collection.{key}")


def test_missing_summary_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    del payload["summary"]
    _assert_disks_check_fails(tmp_path, payload, "disks.summary.object")


def test_negative_total_roots_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["summary"]["total_roots"] = -1
    _assert_disks_check_fails(tmp_path, payload, "disks.summary.total_roots")


def test_returned_greater_than_total_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["summary"]["total_roots"] = 2
    _assert_disks_check_fails(tmp_path, payload, "disks.summary.returned_le_total")


@pytest.mark.parametrize("limit", [0, -1, 65, "10", True, None])
def test_invalid_limit_fails(tmp_path: Path, limit: Any) -> None:
    payload = _disks_payload()
    payload["collection"]["limit"] = limit
    _assert_disks_check_fails(tmp_path, payload, "disks.collection.limit")


@pytest.mark.parametrize("truncated", ["false", 0, None])
def test_non_boolean_truncated_fails(tmp_path: Path, truncated: Any) -> None:
    payload = _disks_payload()
    payload["collection"]["truncated"] = truncated
    _assert_disks_check_fails(tmp_path, payload, "disks.collection.truncated")


def test_missing_truncated_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    del payload["collection"]["truncated"]
    _assert_disks_check_fails(tmp_path, payload, "disks.collection.truncated")


def test_consistent_truncation_passes(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["collection"]["limit"] = 2
    payload["collection"]["truncated"] = True
    payload["summary"] = {
        "total_roots": 3,
        "returned_roots": 2,
        "available_roots": 1,
        "unavailable_roots": 1,
    }
    payload["disks"] = payload["disks"][1:]
    result = _disks_result(tmp_path, payload)
    assert result["status"] == "ok"


def test_inconsistent_truncation_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["summary"]["returned_roots"] = 2
    payload["summary"]["unavailable_roots"] = 1
    payload["disks"] = payload["disks"][1:]
    _assert_disks_check_fails(tmp_path, payload, "disks.summary.truncation_consistent")


def test_missing_disks_list_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    del payload["disks"]
    _assert_disks_check_fails(tmp_path, payload, "disks.disks.list")


def test_disks_list_count_mismatch_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["disks"] = payload["disks"][:2]
    _assert_disks_check_fails(tmp_path, payload, "disks.disks.returned_count_consistent")


def test_sanitized_unavailable_roots_pass(tmp_path: Path) -> None:
    result = _disks_result(tmp_path, _disks_payload())
    assert result["status"] == "ok"


def test_all_available_roots_pass(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["disks"] = [payload["disks"][1]]
    payload["summary"] = {
        "total_roots": 1,
        "returned_roots": 1,
        "available_roots": 1,
        "unavailable_roots": 0,
    }
    result = _disks_result(tmp_path, payload)
    assert result["status"] == "ok"


def test_unavailable_root_with_traceback_string_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["disks"][0]["error"] = (
        'Traceback (most recent call last):\n  File "x.py", line 1\nOSError: boom'
    )
    _assert_disks_check_fails(tmp_path, payload, "disks.disks[0].sanitized_error")


def test_unavailable_root_with_raw_exception_field_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["disks"][0]["exception"] = "OSError(22, 'The device is not ready')"
    _assert_disks_check_fails(tmp_path, payload, "disks.disks[0].sanitized_fields")


def test_available_root_with_negative_bytes_fails(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["disks"][1]["free_bytes"] = -1
    _assert_disks_check_fails(tmp_path, payload, "disks.disks[1].free_bytes")


def test_expected_host_mismatch_fails_when_host_data_exists(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["host"] = {"hostname": "OTHER-HOST"}
    _assert_disks_check_fails(tmp_path, payload, "disks.host.expected")


def test_expected_python_mismatch_fails_when_runtime_data_exists(tmp_path: Path) -> None:
    payload = _disks_payload()
    payload["python_runtime"] = {"version": "3.12.1", "executable": "python.exe"}
    _assert_disks_check_fails(tmp_path, payload, "disks.python_runtime.expected")


def test_expected_host_and_python_skipped_when_absent(tmp_path: Path) -> None:
    result = _disks_result(tmp_path, _disks_payload())
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "disks.host.expected" not in names
    assert "disks.python_runtime.expected" not in names


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
