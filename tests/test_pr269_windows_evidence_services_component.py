"""PR269 Windows evidence bundle opt-in services component tests."""

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
from shellforgeai.windows_evidence import (
    EVIDENCE_SERVICES_DEFAULT_LIMIT,
    EVIDENCE_SERVICES_MAX_LIMIT,
    render_windows_evidence_text,
    validate_evidence_services_limit,
    windows_evidence_payload,
)
from shellforgeai.windows_services import RawServiceRecord, windows_services_payload
from shellforgeai.windows_status import windows_status_payload

ACCEPTANCE_SCRIPT = Path("scripts/windows_smoke_acceptance.py")
PACKET_SCRIPT = Path("scripts/windows_smoke_packet.py")

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")

FAKE_RECORDS = (
    RawServiceRecord("wuauserv", "Windows Update", 1, 0x20),
    RawServiceRecord("Spooler", "Print Spooler", 4, 0x10),
    RawServiceRecord("Audiosrv", "Windows Audio", 4, 0x10),
    RawServiceRecord("SysMain", "SysMain", 7, 0x20),
    RawServiceRecord("TrustedInstaller", "Windows Modules Installer", 2, 0x10),
    RawServiceRecord("BITS", "Background Intelligent Transfer Service", 3, 0x20),
    RawServiceRecord("Dnscache", "DNS Client", 4, 0x20),
)


def fake_enumerator() -> list[RawServiceRecord]:
    return list(FAKE_RECORDS)


def fake_disk_usage(_path: str | Path) -> tuple[int, int, int]:
    return (1000, 400, 600)


def evidence_payload_for_mocked_windows(**kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault(
        "services_builder",
        lambda info, limit: windows_services_payload(
            info, enumerator=fake_enumerator, max_services=limit
        ),
    )
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
    return _load(ACCEPTANCE_SCRIPT, "windows_smoke_acceptance_pr269")


def _packet_module() -> ModuleType:
    sys.modules.pop("windows_smoke_acceptance", None)
    return _load(PACKET_SCRIPT, "windows_smoke_packet_pr269")


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
    assert "services" not in payload["components"]
    assert payload["next_safe_command"] == "shellforgeai windows status --json"


def test_default_mocked_windows_bundle_component_count_is_two() -> None:
    summary = evidence_payload_for_mocked_windows()["summary"]
    assert summary["component_count"] == 2
    assert summary["ok_components"] == ["doctor", "status"]
    assert summary["failed_components"] == []


def test_default_bundle_not_collected_still_lists_services() -> None:
    not_collected = evidence_payload_for_mocked_windows()["not_collected_in_pr264"]
    assert "services" in not_collected
    assert "opt-in" not in str(not_collected["services"])


# ---------------------------------------------------------------------------
# Opt-in services component contract.
# ---------------------------------------------------------------------------


def test_include_services_bundle_includes_services_component() -> None:
    payload = evidence_payload_for_mocked_windows(include_services=True)
    assert payload["status"] == "ok"
    assert sorted(payload["components"]) == ["doctor", "services", "status"]


def test_services_component_mode_is_windows_services() -> None:
    component = evidence_payload_for_mocked_windows(include_services=True)["components"]["services"]
    assert component["mode"] == "windows_services"


def test_services_component_status_is_ok() -> None:
    component = evidence_payload_for_mocked_windows(include_services=True)["components"]["services"]
    assert component["status"] == "ok"


def test_services_component_is_read_only_without_mutation() -> None:
    component = evidence_payload_for_mocked_windows(include_services=True)["components"]["services"]
    assert component["read_only"] is True
    assert component["mutation_performed"] is False


def test_services_component_has_bounded_limit_field() -> None:
    component = evidence_payload_for_mocked_windows(include_services=True)["components"]["services"]
    assert isinstance(component["limit"], int)
    assert 1 <= component["limit"] <= EVIDENCE_SERVICES_MAX_LIMIT
    assert component["returned_count"] <= component["limit"]


def test_default_services_limit_is_conservative_25() -> None:
    assert EVIDENCE_SERVICES_DEFAULT_LIMIT == 25
    component = evidence_payload_for_mocked_windows(include_services=True)["components"]["services"]
    assert component["limit"] == 25
    assert component["services"]["collection_limits"]["max_services"] == 25


def test_services_limit_five_is_applied() -> None:
    component = evidence_payload_for_mocked_windows(include_services=True, services_limit=5)[
        "components"
    ]["services"]
    assert component["limit"] == 5
    assert component["returned_count"] == 5
    assert len(component["services"]["items"]) == 5


def test_services_truncation_is_represented_when_total_exceeds_returned() -> None:
    component = evidence_payload_for_mocked_windows(include_services=True, services_limit=5)[
        "components"
    ]["services"]
    assert component["total_count"] == 7
    assert component["returned_count"] == 5
    assert component["truncated"] is True
    untruncated = evidence_payload_for_mocked_windows(include_services=True)["components"][
        "services"
    ]
    assert untruncated["total_count"] == untruncated["returned_count"] == 7
    assert untruncated["truncated"] is False


def test_summary_component_count_is_three_with_services() -> None:
    summary = evidence_payload_for_mocked_windows(include_services=True)["summary"]
    assert summary["component_count"] == 3


def test_summary_ok_components_includes_services() -> None:
    summary = evidence_payload_for_mocked_windows(include_services=True)["summary"]
    assert "services" in summary["ok_components"]
    assert summary["failed_components"] == []


def test_include_services_reuses_existing_services_payload_builder() -> None:
    calls: list[tuple[PlatformInfo, int]] = []

    def builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
        calls.append((info, limit))
        return windows_services_payload(info, enumerator=fake_enumerator, max_services=limit)

    payload = evidence_payload_for_mocked_windows(include_services=True, services_builder=builder)
    assert calls == [(WINDOWS_INFO, EVIDENCE_SERVICES_DEFAULT_LIMIT)]
    component = payload["components"]["services"]
    assert component["services"]["collection"] == "local_windows_service_state_summary"
    assert payload["next_safe_command"] == "shellforgeai windows services --json --limit 25"


# ---------------------------------------------------------------------------
# Services failure honesty.
# ---------------------------------------------------------------------------


def failing_enumerator() -> list[RawServiceRecord]:
    raise PermissionError("access denied to service control manager")


def test_services_failure_is_surfaced_in_failed_components() -> None:
    payload = evidence_payload_for_mocked_windows(
        include_services=True,
        services_builder=lambda info, limit: windows_services_payload(
            info, enumerator=failing_enumerator, max_services=limit
        ),
    )
    assert payload["summary"]["failed_components"] == ["services"]
    assert payload["components"]["services"]["status"] == "error"
    assert "Traceback" not in json.dumps(payload)


def test_top_level_status_does_not_hide_services_failure() -> None:
    payload = evidence_payload_for_mocked_windows(
        include_services=True,
        services_builder=lambda info, limit: windows_services_payload(
            info, enumerator=failing_enumerator, max_services=limit
        ),
    )
    assert payload["status"] != "ok"
    assert payload["status"] == "component_failure"
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["service_control_executed"] is False


# ---------------------------------------------------------------------------
# Linux/Docker01 unsupported behavior.
# ---------------------------------------------------------------------------


def test_linux_include_services_returns_structured_unsupported() -> None:
    payload = windows_evidence_payload(LINUX_INFO, include_services=True, services_limit=25)
    assert payload["status"] == "unsupported"
    assert payload["mode"] == "windows_evidence_bundle"
    assert payload["platform"] == {"system": "linux"}
    assert payload["mutation_performed"] is False
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"
    assert "components" not in payload


def test_linux_unsupported_does_not_attempt_services_collection() -> None:
    def must_not_collect(_info: PlatformInfo, _limit: int) -> dict[str, Any]:
        raise AssertionError("services collection must not run on Linux")

    payload = windows_evidence_payload(
        LINUX_INFO, include_services=True, services_builder=must_not_collect
    )
    assert payload["status"] == "unsupported"


def test_cli_linux_include_services_unsupported(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_evidence.detect_platform", lambda: LINUX_INFO)
    monkeypatch.setattr("shellforgeai.windows_services.detect_platform", lambda: LINUX_INFO)
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--json", "--include-services", "--services-limit", "25"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


# ---------------------------------------------------------------------------
# Text output.
# ---------------------------------------------------------------------------


def test_text_output_with_services_is_concise_and_summarized() -> None:
    payload = evidence_payload_for_mocked_windows(include_services=True, services_limit=5)
    text = render_windows_evidence_text(payload)
    assert "Components included: doctor, status, services" in text
    assert "Services component: status=ok; returned=5; total=7; truncated=true" in text
    assert "running=3" in text
    assert "stopped=1" in text
    assert len(text.splitlines()) <= 12
    # No unbounded service listing in text output.
    assert "Spooler" not in text
    assert "Dnscache" not in text


def test_default_text_output_is_unchanged() -> None:
    text = render_windows_evidence_text(evidence_payload_for_mocked_windows())
    assert "Components included: doctor, status" in text
    assert "Services component:" not in text
    assert (
        "Not collected yet: PowerShell version, execution policy, services, "
        "processes, event logs, firewall, Windows Update." in text
    )


# ---------------------------------------------------------------------------
# Limit validation.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0, -1, -25, 501, 10_000, "25", 2.5, None, True])
def test_invalid_services_limit_rejected_by_validator(value: Any) -> None:
    with pytest.raises(ValueError):
        validate_evidence_services_limit(value)


@pytest.mark.parametrize("value", [1, 5, 25, 250, 500])
def test_valid_services_limit_accepted(value: int) -> None:
    assert validate_evidence_services_limit(value) == value


@pytest.mark.parametrize("raw", ["0", "-3", "501", "abc"])
def test_cli_invalid_services_limit_fails_cleanly(raw: str) -> None:
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--json", "--include-services", "--services-limit", raw]
    )
    assert result.exit_code == 2
    assert "Traceback" not in _cli_output(result)


def test_cli_services_limit_requires_include_services() -> None:
    result = CliRunner().invoke(app, ["windows", "evidence", "--json", "--services-limit", "25"])
    assert result.exit_code == 2
    # Rich wraps the error panel, so match on the unambiguous fragments.
    output = _cli_output(result)
    assert "--services-limit requires" in output
    assert "--include-services" in output


def test_cli_include_services_flags_are_passed_through(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    def capture(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return windows_evidence_payload(LINUX_INFO)

    monkeypatch.setattr("shellforgeai.commands.windows.windows_evidence_payload", capture)
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--json", "--include-services", "--services-limit", "5"]
    )
    assert result.exit_code == 0
    assert seen == {"include_services": True, "services_limit": 5}


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
        "service_control_executed",
        "service_config_modified",
        "registry_modified",
        "execution_policy_modified",
        "shell_true",
        "arbitrary_command_execution",
        "network_call",
        "model_called",
        "secret_read",
        "auth_cache_read",
        "mutation_performed",
    ],
)
def test_bundle_safety_flags_remain_false(key: str) -> None:
    payload = evidence_payload_for_mocked_windows(include_services=True)
    assert payload["safety"][key] is False
    assert payload["components"]["services"]["safety"][key] is False


def test_bundle_stays_read_only_with_services() -> None:
    payload = evidence_payload_for_mocked_windows(include_services=True)
    assert payload["read_only"] is True
    assert payload["safety"]["read_only"] is True
    assert payload["windows_v1"]["powershell_executed"] is False
    assert payload["windows_v1"]["winrm_used"] is False
    assert payload["windows_v1"]["remote_execution"] is False


# ---------------------------------------------------------------------------
# Validator: embedded services component.
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


def _embedded_services_component() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_services",
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "limit": 25,
        "returned_count": 3,
        "total_count": 3,
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
            "collection_limits": {"max_services": 25, "truncated": False},
        },
        "safety": _services_safe_flags(),
        "next_safe_command": "shellforgeai windows status --json",
    }


def _evidence_payload(include_services: bool = False) -> dict[str, Any]:
    components: dict[str, Any] = {
        "doctor": _component("windows_doctor"),
        "status": _component("windows_status"),
    }
    ok_components = ["doctor", "status"]
    if include_services:
        components["services"] = _embedded_services_component()
        ok_components.append("services")
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


def _standalone_services_payload() -> dict[str, Any]:
    payload = _embedded_services_component()
    for key in ("limit", "returned_count", "total_count", "truncated"):
        payload.pop(key)
    payload["services"]["collection_limits"] = {"max_services": 500, "truncated": False}
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


def test_validator_accepts_evidence_bundle_with_embedded_services(tmp_path: Path) -> None:
    result = _evidence_result(tmp_path, _evidence_payload(include_services=True))
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "evidence.components.services.mode" in names
    assert "evidence.components.services.limit" in names
    assert "evidence.components.services.bounded_consistent" in names


def test_validator_still_accepts_default_evidence_bundle(tmp_path: Path) -> None:
    result = _evidence_result(tmp_path, _evidence_payload(include_services=False))
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "evidence.components.services.mode" not in names


def test_validator_rejects_embedded_services_mutation_flag_true(tmp_path: Path) -> None:
    payload = _evidence_payload(include_services=True)
    payload["components"]["services"]["mutation_performed"] = True
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.components.services.mutation_performed" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_embedded_service_control_executed_true(tmp_path: Path) -> None:
    payload = _evidence_payload(include_services=True)
    payload["components"]["services"]["safety"]["service_control_executed"] = True
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.components.services.safety.service_control_executed"
        and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_embedded_services_failure(tmp_path: Path) -> None:
    payload = _evidence_payload(include_services=True)
    payload["components"]["services"]["status"] = "error"
    payload["summary"]["ok_components"] = ["doctor", "status"]
    payload["summary"]["failed_components"] = ["services"]
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    failed_names = {check["name"] for check in result["checks"] if not check["passed"]}
    assert "evidence.components.services.status" in failed_names
    assert "evidence.summary.failed_components" in failed_names


def test_validator_rejects_inconsistent_bounded_fields(tmp_path: Path) -> None:
    payload = _evidence_payload(include_services=True)
    payload["components"]["services"]["returned_count"] = 40  # exceeds limit 25
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.components.services.bounded_consistent" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_rejects_wrong_component_count_with_services(tmp_path: Path) -> None:
    payload = _evidence_payload(include_services=True)
    payload["summary"]["component_count"] = 2
    result = _evidence_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.summary.component_count" and not check["passed"]
        for check in result["checks"]
    )


# ---------------------------------------------------------------------------
# Packet helper: embedded and standalone services.
# ---------------------------------------------------------------------------


def _packet_args(
    tmp_path: Path, evidence_payload: dict[str, Any], services_payload: dict[str, Any] | None
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
    if services_payload is not None:
        services = _write(tmp_path / "windows-services.json", services_payload)
        args.extend(["--services-json", str(services)])
    return args


def test_packet_helper_summarizes_embedded_services(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(_packet_args(tmp_path, _evidence_payload(include_services=True), None))
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    assert packet["embedded_services"] == {
        "mode": "windows_services",
        "status": "ok",
        "limit": 25,
        "returned_count": 3,
        "total_count": 3,
        "truncated": False,
        "running": 2,
        "stopped": 1,
        "unknown": 0,
    }
    markdown = module.render_markdown(packet)
    assert "## Embedded services component" in markdown
    assert "- Limit: 25" in markdown
    assert "- Returned services: 3" in markdown
    assert "- Truncated: false" in markdown


def test_packet_helper_without_services_has_no_embedded_block(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(
        _packet_args(tmp_path, _evidence_payload(include_services=False), None)
    )
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    assert "embedded_services" not in packet
    assert "## Embedded services component" not in module.render_markdown(packet)


def test_packet_helper_still_accepts_standalone_services_artifact(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(
        _packet_args(
            tmp_path, _evidence_payload(include_services=False), _standalone_services_payload()
        )
    )
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    artifact = packet["artifacts"]["services_json"]
    assert artifact["mode"] == "windows_services"
    assert artifact["status"] == "ok"
    assert artifact["total"] == 3


def test_packet_helper_with_embedded_and_standalone_services(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(
        _packet_args(
            tmp_path, _evidence_payload(include_services=True), _standalone_services_payload()
        )
    )
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    assert packet["embedded_services"]["total_count"] == 3
    assert packet["artifacts"]["services_json"]["total"] == 3
    markdown = module.render_markdown(packet)
    assert "## Embedded services component" in markdown
    assert "## Services summary" in markdown


def test_cross_check_embedded_vs_standalone_mismatch_fails(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence = _write(tmp_path / "windows-evidence.json", _evidence_payload(include_services=True))
    standalone = _standalone_services_payload()
    standalone["services"]["total_count"] = 99
    services = _write(tmp_path / "windows-services.json", standalone)
    result = module._result(
        module.parse_args(["--evidence-json", str(evidence), "--services-json", str(services)])
    )
    assert result["status"] == "failed"
    assert any(
        check["name"] == "cross_check.services.total_count" and not check["passed"]
        for check in result["checks"]
    )


def test_cross_check_embedded_vs_standalone_match_passes(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence = _write(tmp_path / "windows-evidence.json", _evidence_payload(include_services=True))
    services = _write(tmp_path / "windows-services.json", _standalone_services_payload())
    result = module._result(
        module.parse_args(["--evidence-json", str(evidence), "--services-json", str(services)])
    )
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "cross_check.services.mode" in names
    assert "cross_check.services.status" in names


# ---------------------------------------------------------------------------
# Source safety guardrails.
# ---------------------------------------------------------------------------


def test_pr269_source_has_no_forbidden_execution_paths() -> None:
    for path in (
        Path("src/shellforgeai/windows_evidence.py"),
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
            "sc.exe",
            "controlservice",
            "startservice",
            "changeserviceconfig",
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


def test_cli_inventory_still_classifies_windows_evidence_read_only() -> None:
    source = Path("scripts/cli_refactor_inventory.py").read_text(encoding="utf-8")
    assert (
        '"windows evidence": {"module": "windows.py", "category": "read_only", "known_pr": 264}'
        in source
    )
