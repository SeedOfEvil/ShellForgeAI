"""PR272 Windows evidence bundle opt-in disks component tests."""

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
from shellforgeai.windows_disks import (
    DEFAULT_DISKS_LIMIT,
    MAX_DISKS_LIMIT,
    windows_disks_payload,
)
from shellforgeai.windows_evidence import (
    EVIDENCE_DISKS_DEFAULT_LIMIT,
    EVIDENCE_DISKS_MAX_LIMIT,
    render_windows_evidence_text,
    validate_evidence_disks_limit,
    windows_evidence_payload,
)
from shellforgeai.windows_services import RawServiceRecord, windows_services_payload
from shellforgeai.windows_status import windows_status_payload

ACCEPTANCE_SCRIPT = Path("scripts/windows_smoke_acceptance.py")
PACKET_SCRIPT = Path("scripts/windows_smoke_packet.py")

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")

FAKE_ROOTS = ("C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "H:\\", "I:\\")

FAKE_RECORDS = (
    RawServiceRecord("wuauserv", "Windows Update", 1, 0x20),
    RawServiceRecord("Spooler", "Print Spooler", 4, 0x10),
    RawServiceRecord("Dnscache", "DNS Client", 4, 0x20),
)


def fake_root_discovery() -> list[str]:
    return list(FAKE_ROOTS)


def failing_root_discovery() -> list[str]:
    raise PermissionError("access denied to drive enumeration")


def fake_disk_usage(_path: str | Path) -> tuple[int, int, int]:
    return (1000, 400, 600)


def fake_disks_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_disks_payload(
        info, root_discovery=fake_root_discovery, disk_usage=fake_disk_usage, limit=limit
    )


def failing_disks_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_disks_payload(
        info, root_discovery=failing_root_discovery, disk_usage=fake_disk_usage, limit=limit
    )


def fake_services_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_services_payload(info, enumerator=lambda: list(FAKE_RECORDS), max_services=limit)


def evidence_payload_for_mocked_windows(**kwargs: Any) -> dict[str, Any]:
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
    return _load(ACCEPTANCE_SCRIPT, "windows_smoke_acceptance_pr272")


def _packet_module() -> ModuleType:
    sys.modules.pop("windows_smoke_acceptance", None)
    return _load(PACKET_SCRIPT, "windows_smoke_packet_pr272")


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
    assert "disks" not in payload["components"]
    assert payload["next_safe_command"] == "shellforgeai windows status --json"


def test_default_mocked_windows_bundle_component_count_is_two() -> None:
    summary = evidence_payload_for_mocked_windows()["summary"]
    assert summary["component_count"] == 2
    assert summary["ok_components"] == ["doctor", "status"]
    assert summary["failed_components"] == []


def test_default_bundle_has_no_embedded_disks_metadata() -> None:
    payload = evidence_payload_for_mocked_windows()
    assert "embedded_disks" not in payload
    assert "not_collected_in_pr272" not in payload
    assert "directory_scan_performed" not in payload["safety"]
    assert "disk_mutation_performed" not in payload["safety"]


# ---------------------------------------------------------------------------
# Opt-in disks component contract.
# ---------------------------------------------------------------------------


def test_include_disks_bundle_includes_disks_component() -> None:
    payload = evidence_payload_for_mocked_windows(include_disks=True)
    assert payload["status"] == "ok"
    assert sorted(payload["components"]) == ["disks", "doctor", "status"]


def test_disks_component_mode_is_windows_disks() -> None:
    component = evidence_payload_for_mocked_windows(include_disks=True)["components"]["disks"]
    assert component["mode"] == "windows_disks"


def test_disks_component_status_is_ok() -> None:
    component = evidence_payload_for_mocked_windows(include_disks=True)["components"]["disks"]
    assert component["status"] == "ok"


def test_disks_component_is_read_only_without_mutation() -> None:
    component = evidence_payload_for_mocked_windows(include_disks=True)["components"]["disks"]
    assert component["read_only"] is True
    assert component["mutation_performed"] is False
    assert component["safety"]["directory_scan_performed"] is False
    assert component["safety"]["file_scan_performed"] is False


def test_disks_component_has_bounded_limit_field() -> None:
    component = evidence_payload_for_mocked_windows(include_disks=True)["components"]["disks"]
    assert isinstance(component["limit"], int)
    assert 1 <= component["limit"] <= EVIDENCE_DISKS_MAX_LIMIT
    assert component["returned_roots"] <= component["limit"]


def test_default_disks_limit_matches_standalone_safe_default_32() -> None:
    assert EVIDENCE_DISKS_DEFAULT_LIMIT == DEFAULT_DISKS_LIMIT == 32
    assert EVIDENCE_DISKS_MAX_LIMIT == MAX_DISKS_LIMIT == 64
    component = evidence_payload_for_mocked_windows(include_disks=True)["components"]["disks"]
    assert component["limit"] == 32
    assert component["collection"]["limit"] == 32


def test_disks_limit_five_is_applied() -> None:
    component = evidence_payload_for_mocked_windows(include_disks=True, disks_limit=5)[
        "components"
    ]["disks"]
    assert component["limit"] == 5
    assert component["returned_roots"] == 5
    assert len(component["disks"]) == 5


def test_disks_truncation_is_represented_when_total_exceeds_returned() -> None:
    component = evidence_payload_for_mocked_windows(include_disks=True, disks_limit=5)[
        "components"
    ]["disks"]
    assert component["total_roots"] == 7
    assert component["returned_roots"] == 5
    assert component["truncated"] is True
    untruncated = evidence_payload_for_mocked_windows(include_disks=True)["components"]["disks"]
    assert untruncated["total_roots"] == untruncated["returned_roots"] == 7
    assert untruncated["truncated"] is False


def test_summary_component_count_is_three_with_disks() -> None:
    summary = evidence_payload_for_mocked_windows(include_disks=True)["summary"]
    assert summary["component_count"] == 3


def test_summary_ok_components_includes_disks() -> None:
    summary = evidence_payload_for_mocked_windows(include_disks=True)["summary"]
    assert "disks" in summary["ok_components"]
    assert summary["failed_components"] == []


def test_top_level_embedded_disks_block_is_explicit_and_bounded() -> None:
    payload = evidence_payload_for_mocked_windows(include_disks=True, disks_limit=5)
    assert payload["embedded_disks"] == {
        "included": True,
        "limit": 5,
        "returned_roots": 5,
        "total_roots": 7,
        "truncated": True,
    }
    assert payload["not_collected_in_pr272"] == {
        "directory_scan": "not collected because PR272 only uses root-level stdlib disk usage",
        "file_scan": "not collected because PR272 does not scan files",
        "disk_repair": "not available because PR272 is read-only",
    }


def test_include_disks_reuses_existing_disks_payload_builder() -> None:
    calls: list[tuple[PlatformInfo, int]] = []

    def builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
        calls.append((info, limit))
        return fake_disks_builder(info, limit)

    payload = evidence_payload_for_mocked_windows(include_disks=True, disks_builder=builder)
    assert calls == [(WINDOWS_INFO, EVIDENCE_DISKS_DEFAULT_LIMIT)]
    component = payload["components"]["disks"]
    assert component["collection"]["method"] == "stdlib_only"
    assert component["collection"]["root_discovery"] == "os.listdrives_or_current_root_fallback"
    assert payload["next_safe_command"] == "shellforgeai windows disks --json"


# ---------------------------------------------------------------------------
# Services + disks composition.
# ---------------------------------------------------------------------------


def test_services_and_disks_together_give_component_count_four() -> None:
    payload = evidence_payload_for_mocked_windows(include_services=True, include_disks=True)
    assert payload["status"] == "ok"
    assert sorted(payload["components"]) == ["disks", "doctor", "services", "status"]
    assert payload["summary"]["component_count"] == 4
    assert payload["summary"]["failed_components"] == []
    assert payload["components"]["services"]["mode"] == "windows_services"
    assert payload["components"]["disks"]["mode"] == "windows_disks"
    assert payload["embedded_disks"]["included"] is True


def test_services_only_opt_in_behavior_still_works() -> None:
    payload = evidence_payload_for_mocked_windows(include_services=True)
    assert sorted(payload["components"]) == ["doctor", "services", "status"]
    assert payload["summary"]["component_count"] == 3
    assert "embedded_disks" not in payload
    assert payload["next_safe_command"] == "shellforgeai windows services --json --limit 25"


# ---------------------------------------------------------------------------
# Disks failure honesty.
# ---------------------------------------------------------------------------


def test_disks_failure_is_surfaced_in_failed_components() -> None:
    payload = evidence_payload_for_mocked_windows(
        include_disks=True, disks_builder=failing_disks_builder
    )
    assert payload["summary"]["failed_components"] == ["disks"]
    assert payload["components"]["disks"]["status"] == "error"
    assert "Traceback" not in json.dumps(payload)


def test_top_level_status_does_not_hide_disks_failure() -> None:
    payload = evidence_payload_for_mocked_windows(
        include_disks=True, disks_builder=failing_disks_builder
    )
    assert payload["status"] != "ok"
    assert payload["status"] == "component_failure"
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["disk_mutation_performed"] is False
    assert payload["embedded_disks"]["returned_roots"] == 0
    assert payload["embedded_disks"]["total_roots"] == 0


# ---------------------------------------------------------------------------
# Linux/Docker01 unsupported behavior.
# ---------------------------------------------------------------------------


def test_linux_include_disks_returns_structured_unsupported() -> None:
    payload = windows_evidence_payload(LINUX_INFO, include_disks=True, disks_limit=5)
    assert payload["status"] == "unsupported"
    assert payload["mode"] == "windows_evidence_bundle"
    assert payload["platform"] == {"system": "linux"}
    assert payload["mutation_performed"] is False
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"
    assert "components" not in payload
    assert "embedded_disks" not in payload


def test_linux_unsupported_does_not_attempt_disks_collection() -> None:
    def must_not_collect(_info: PlatformInfo, _limit: int) -> dict[str, Any]:
        raise AssertionError("disks collection must not run on Linux")

    payload = windows_evidence_payload(
        LINUX_INFO, include_disks=True, disks_builder=must_not_collect
    )
    assert payload["status"] == "unsupported"


def test_cli_linux_include_disks_unsupported(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_evidence.detect_platform", lambda: LINUX_INFO)
    monkeypatch.setattr("shellforgeai.windows_disks.detect_platform", lambda: LINUX_INFO)
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--json", "--include-disks", "--disks-limit", "5"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"
    assert "Traceback" not in _cli_output(result)


# ---------------------------------------------------------------------------
# Text output.
# ---------------------------------------------------------------------------


def test_text_output_with_disks_is_concise_and_summarized() -> None:
    payload = evidence_payload_for_mocked_windows(include_disks=True, disks_limit=5)
    text = render_windows_evidence_text(payload)
    assert "Components included: doctor, status, disks" in text
    assert "Disks component: status=ok; returned=5; total=7; limit=5; truncated=true" in text
    assert len(text.splitlines()) <= 12
    # No unbounded per-root listing in text output.
    assert "E:\\" not in text
    assert "I:\\" not in text


def test_default_text_output_is_unchanged() -> None:
    text = render_windows_evidence_text(evidence_payload_for_mocked_windows())
    assert "Components included: doctor, status" in text
    assert "Disks component:" not in text


# ---------------------------------------------------------------------------
# Limit validation.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0, -1, -32, 65, 10_000, "32", 2.5, None, True])
def test_invalid_disks_limit_rejected_by_validator(value: Any) -> None:
    with pytest.raises(ValueError):
        validate_evidence_disks_limit(value)


@pytest.mark.parametrize("value", [1, 5, 32, 64])
def test_valid_disks_limit_accepted(value: int) -> None:
    assert validate_evidence_disks_limit(value) == value


@pytest.mark.parametrize("raw", ["0", "-3", "65", "abc"])
def test_cli_invalid_disks_limit_fails_cleanly(raw: str) -> None:
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--json", "--include-disks", "--disks-limit", raw]
    )
    assert result.exit_code == 2
    assert "Traceback" not in _cli_output(result)


def test_cli_disks_limit_requires_include_disks() -> None:
    result = CliRunner().invoke(app, ["windows", "evidence", "--json", "--disks-limit", "5"])
    assert result.exit_code == 2
    # Rich wraps the error panel, so match on the unambiguous fragments.
    output = _cli_output(result)
    assert "--disks-limit requires" in output
    assert "--include-disks" in output


def test_cli_include_disks_flags_are_passed_through(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    def capture(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return windows_evidence_payload(LINUX_INFO)

    monkeypatch.setattr("shellforgeai.commands.windows.windows_evidence_payload", capture)
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--json", "--include-disks", "--disks-limit", "5"]
    )
    assert result.exit_code == 0
    assert seen == {"include_disks": True, "disks_limit": 5}


def test_cli_include_services_and_disks_flags_are_passed_through(monkeypatch) -> None:
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
            "--services-limit",
            "25",
            "--include-disks",
            "--disks-limit",
            "5",
        ],
    )
    assert result.exit_code == 0
    assert seen == {
        "include_services": True,
        "services_limit": 25,
        "include_disks": True,
        "disks_limit": 5,
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
        "network_call",
        "model_called",
        "secret_read",
        "auth_cache_read",
        "mutation_performed",
        "directory_scan_performed",
        "file_scan_performed",
        "disk_mutation_performed",
    ],
)
def test_bundle_safety_flags_remain_false_with_disks(key: str) -> None:
    payload = evidence_payload_for_mocked_windows(include_disks=True)
    assert payload["safety"][key] is False
    assert payload["components"]["disks"]["safety"].get(key, False) is False


def test_bundle_stays_read_only_with_disks() -> None:
    payload = evidence_payload_for_mocked_windows(include_disks=True)
    assert payload["read_only"] is True
    assert payload["safety"]["read_only"] is True
    assert payload["windows_v1"]["powershell_executed"] is False
    assert payload["windows_v1"]["winrm_used"] is False
    assert payload["windows_v1"]["remote_execution"] is False


# ---------------------------------------------------------------------------
# Validator: embedded disks component.
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


def _disks_safe_flags() -> dict[str, bool]:
    flags = _safe_flags()
    flags["directory_scan_performed"] = False
    flags["file_scan_performed"] = False
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


def _standalone_disks_payload() -> dict[str, Any]:
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
        "safety": _disks_safe_flags(),
        "next_safe_command": "shellforgeai windows status --json",
    }


def _embedded_disks_component() -> dict[str, Any]:
    payload = _standalone_disks_payload()
    payload["limit"] = 32
    payload["returned_roots"] = 3
    payload["total_roots"] = 3
    payload["truncated"] = False
    return payload


def _embedded_services_component() -> dict[str, Any]:
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
        "limit": 25,
        "returned_count": 2,
        "total_count": 2,
        "truncated": False,
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
            "collection_limits": {"max_services": 25, "truncated": False},
        },
        "safety": safety,
        "next_safe_command": "shellforgeai windows status --json",
    }


def _evidence_payload(
    include_disks: bool = False, include_services: bool = False
) -> dict[str, Any]:
    components: dict[str, Any] = {
        "doctor": _component("windows_doctor"),
        "status": _component("windows_status"),
    }
    ok_components = ["doctor", "status"]
    if include_services:
        components["services"] = _embedded_services_component()
        ok_components.append("services")
    if include_disks:
        components["disks"] = _embedded_disks_component()
        ok_components.append("disks")
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
    if include_disks:
        payload["embedded_disks"] = {
            "included": True,
            "limit": 32,
            "returned_roots": 3,
            "total_roots": 3,
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


def test_validator_accepts_evidence_bundle_with_embedded_disks(tmp_path: Path) -> None:
    result = _evidence_result(tmp_path, _evidence_payload(include_disks=True))
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "evidence.components.disks.mode" in names
    assert "evidence.components.disks.limit" in names
    assert "evidence.components.disks.bounded_consistent" in names
    assert "evidence.embedded_disks.included" in names
    assert "evidence.embedded_disks.consistent" in names


def test_validator_still_accepts_default_evidence_bundle(tmp_path: Path) -> None:
    result = _evidence_result(tmp_path, _evidence_payload())
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "evidence.components.disks.mode" not in names
    assert "evidence.embedded_disks.included" not in names


def test_validator_accepts_evidence_with_services_and_disks(tmp_path: Path) -> None:
    result = _evidence_result(
        tmp_path, _evidence_payload(include_disks=True, include_services=True)
    )
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "evidence.components.services.mode" in names
    assert "evidence.components.disks.mode" in names


def test_validator_rejects_embedded_disks_mutation_flag_true(tmp_path: Path) -> None:
    payload = _evidence_payload(include_disks=True)
    payload["components"]["disks"]["mutation_performed"] = True
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.components.disks.mutation_performed" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_embedded_disks_directory_scan_true(tmp_path: Path) -> None:
    payload = _evidence_payload(include_disks=True)
    payload["components"]["disks"]["safety"]["directory_scan_performed"] = True
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.components.disks.safety.directory_scan_performed"
        and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_embedded_disks_failure(tmp_path: Path) -> None:
    payload = _evidence_payload(include_disks=True)
    payload["components"]["disks"]["status"] = "error"
    payload["summary"]["ok_components"] = ["doctor", "status"]
    payload["summary"]["failed_components"] = ["disks"]
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    failed_names = {check["name"] for check in result["checks"] if not check["passed"]}
    assert "evidence.components.disks.status" in failed_names
    assert "evidence.summary.failed_components" in failed_names


def test_validator_rejects_inconsistent_bounded_disks_fields(tmp_path: Path) -> None:
    payload = _evidence_payload(include_disks=True)
    payload["components"]["disks"]["returned_roots"] = 40  # exceeds limit 32
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.components.disks.bounded_consistent" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_inconsistent_embedded_disks_block(tmp_path: Path) -> None:
    payload = _evidence_payload(include_disks=True)
    payload["embedded_disks"]["limit"] = 5  # component says 32
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.embedded_disks.consistent" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_wrong_component_count_with_disks(tmp_path: Path) -> None:
    payload = _evidence_payload(include_disks=True)
    payload["summary"]["component_count"] = 2
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.summary.component_count" and not check["passed"]
        for check in result["checks"]
    )


def test_cross_check_embedded_vs_standalone_disks_match_passes(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence = _write(tmp_path / "windows-evidence.json", _evidence_payload(include_disks=True))
    disks = _write(tmp_path / "windows-disks.json", _standalone_disks_payload())
    result = module._result(
        module.parse_args(["--evidence-json", str(evidence), "--disks-json", str(disks)])
    )
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "cross_check.disks.mode" in names
    assert "cross_check.disks.status" in names
    assert "cross_check.disks.total_roots" in names


def test_cross_check_embedded_vs_standalone_disks_mismatch_fails(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence = _write(tmp_path / "windows-evidence.json", _evidence_payload(include_disks=True))
    standalone = _standalone_disks_payload()
    standalone["summary"]["total_roots"] = 99
    standalone["collection"]["truncated"] = True
    disks = _write(tmp_path / "windows-disks.json", standalone)
    result = module._result(
        module.parse_args(["--evidence-json", str(evidence), "--disks-json", str(disks)])
    )
    assert result["status"] == "failed"
    assert any(
        check["name"] == "cross_check.disks.total_roots" and not check["passed"]
        for check in result["checks"]
    )


# ---------------------------------------------------------------------------
# Packet helper: embedded and standalone disks.
# ---------------------------------------------------------------------------


def _packet_args(
    tmp_path: Path, evidence_payload: dict[str, Any], disks_payload: dict[str, Any] | None
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
    if disks_payload is not None:
        disks = _write(tmp_path / "windows-disks.json", disks_payload)
        args.extend(["--disks-json", str(disks)])
    return args


def test_packet_helper_summarizes_embedded_disks(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(_packet_args(tmp_path, _evidence_payload(include_disks=True), None))
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    assert packet["embedded_disks"] == {
        "mode": "windows_disks",
        "status": "ok",
        "limit": 32,
        "returned_roots": 3,
        "total_roots": 3,
        "truncated": False,
        "available_roots": 1,
        "unavailable_roots": 2,
    }
    markdown = module.render_markdown(packet)
    assert "## Embedded disks component" in markdown
    assert "- Limit: 32" in markdown
    assert "- Returned roots: 3" in markdown
    assert "- Truncated: false" in markdown


def test_packet_helper_without_disks_has_no_embedded_block(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(_packet_args(tmp_path, _evidence_payload(), None))
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    assert "embedded_disks" not in packet
    assert "## Embedded disks component" not in module.render_markdown(packet)


def test_packet_helper_still_accepts_standalone_disks_artifact(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(
        _packet_args(tmp_path, _evidence_payload(), _standalone_disks_payload())
    )
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    artifact = packet["artifacts"]["disks_json"]
    assert artifact["mode"] == "windows_disks"
    assert artifact["status"] == "ok"
    assert artifact["total_roots"] == 3
    assert artifact["limit"] == 32


def test_packet_helper_with_embedded_and_standalone_disks(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(
        _packet_args(tmp_path, _evidence_payload(include_disks=True), _standalone_disks_payload())
    )
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    assert packet["embedded_disks"]["total_roots"] == 3
    assert packet["artifacts"]["disks_json"]["total_roots"] == 3
    markdown = module.render_markdown(packet)
    assert "## Embedded disks component" in markdown
    assert "## Disks summary" in markdown


# ---------------------------------------------------------------------------
# Source safety guardrails.
# ---------------------------------------------------------------------------


def test_pr272_source_has_no_forbidden_execution_paths() -> None:
    for path in (
        Path("src/shellforgeai/windows_evidence.py"),
        Path("src/shellforgeai/windows_disks.py"),
        Path("src/shellforgeai/commands/windows.py"),
    ):
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        for forbidden in (
            "shell=true",
            "subprocess",
            "pwsh",
            "powershell.exe",
            "invoke-command",
            "new-pssession",
            "psremoting",
            "winrm ",
            "diskpart",
            "chkdsk",
            "mkfs",
            "format.com",
            "mountvol",
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
        for banned_module in ("subprocess", "socket", "http", "urllib", "winreg", "wmi"):
            assert banned_module not in imported, f"{path} imports {banned_module}"


def test_pr272_evidence_path_performs_no_product_file_writes() -> None:
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
