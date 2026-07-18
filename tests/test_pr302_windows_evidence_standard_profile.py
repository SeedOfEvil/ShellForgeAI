from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_events import DEFAULT_EVENTS_LIMIT, DEFAULT_SINCE_HOURS
from shellforgeai.windows_evidence import (
    EVIDENCE_NETWORK_DEFAULT_ADDRESS_LIMIT,
    EVIDENCE_NETWORK_DEFAULT_INTERFACE_LIMIT,
    EVIDENCE_PROCESSES_DEFAULT_LIMIT,
    EVIDENCE_SERVICES_DEFAULT_LIMIT,
    EVIDENCE_VOLUMES_DEFAULT_LIMIT,
    render_windows_evidence_text,
    resolve_windows_evidence_profile,
    validate_windows_evidence_profile,
    windows_evidence_payload,
)

WINDOWS = PlatformInfo("windows", "WIN", "nt", "2025", "AMD64")
LINUX = PlatformInfo("linux", "linux", "posix", "6.8", "x86_64")
PROFILE_COMPONENTS = ["doctor", "status", "services", "processes", "events", "network", "volumes"]
PROFILE_LINE = (
    "Evidence profile: standard; components=doctor,status,services,processes,events,network,volumes"
)
PROFILE_BOUNDS = {
    "services_limit": 25,
    "processes_limit": 25,
    "events_limit": 50,
    "events_since_hours": 24,
    "network_interface_limit": 32,
    "network_address_limit": 16,
    "volumes_limit": 32,
}


def common(mode: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": mode,
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_evidence",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "host": {"hostname": "WIN", "python": "3.14"},
        "python_runtime": {"version": "3.14", "executable": "python"},
        "filesystem": {"cwd": "C:/Tools/ShellForgeAI", "home": "C:/Users/Operator"},
        "safety": {
            key: False
            for key in (
                "powershell_executed",
                "winrm_used",
                "remote_execution",
                "service_restart_executed",
                "service_control_executed",
                "service_config_modified",
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
                "packet_capture",
                "socket_inventory",
                "dns_lookup",
                "route_table_lookup",
                "network_mutation",
                "event_log_write_performed",
                "event_log_clear_performed",
                "event_log_export_performed",
                "event_subscription_created",
                "process_control_executed",
                "process_config_modified",
                "process_memory_read",
                "process_command_line_read",
                "process_environment_read",
                "process_handles_read",
                "process_modules_read",
                "process_owner_read",
                "directory_scan_performed",
                "file_scan_performed",
                "disk_mutation_performed",
            )
        },
    }


def doctor(info: PlatformInfo) -> dict[str, Any]:
    assert info.system == "windows"
    p = common("windows_doctor")
    p["windows_v1"]["scope"] = "local_read_only_doctor"
    return p


def status(info: PlatformInfo) -> dict[str, Any]:
    assert info.system == "windows"
    payload = common("windows_status")
    payload["windows_v1"]["scope"] = "local_read_only_status"
    payload["memory"] = {"available": False}
    return payload


def services(info: PlatformInfo, limit: int) -> dict[str, Any]:
    assert info.system == "windows" and limit == 25
    p = common("windows_services")
    p["windows_v1"]["scope"] = "local_read_only_services"
    p["services"] = {
        "items": [],
        "collection_limits": {"truncated": False},
        "total_count": 0,
        "state_counts": {"running": 0, "stopped": 0, "unknown": 0},
    }
    return p


def processes(info: PlatformInfo, limit: int) -> dict[str, Any]:
    assert info.system == "windows" and limit == 25
    p = common("windows_processes")
    p["windows_v1"]["scope"] = "local_read_only_processes_preview"
    p.update(
        {
            "method": "ctypes_toolhelp32_snapshot",
            "limit": limit,
            "returned_count": 0,
            "total_count": 0,
            "truncated": False,
            "processes": [],
            "state": {"enumeration_failed": False},
            "not_collected_in_pr274": {
                "command_line": "not collected",
                "environment": "not collected",
                "memory": "not collected",
                "handles": "not collected",
                "modules": "not collected",
                "owner_user": "not collected",
                "network_connections": "not collected",
            },
        }
    )
    return p


def events(info: PlatformInfo, limit: int, since_hours: int) -> dict[str, Any]:
    assert info.system == "windows" and (limit, since_hours) == (50, 24)
    p = common("windows_events")
    p.update(
        {
            "collection": {
                "method": "wevtapi_system_metadata",
                "channel": "System",
                "levels": ["critical", "error", "warning"],
                "since_hours": since_hours,
                "limit": limit,
                "truncated": False,
                "rendered_messages_collected": False,
                "event_xml_collected": False,
                "event_data_collected": False,
                "user_data_collected": False,
                "remote_session_used": False,
            },
            "summary": {
                "events_returned": 0,
                "critical": 0,
                "error": 0,
                "warning": 0,
                "unknown": 0,
                "truncated": False,
                "since_hours": since_hours,
                "limit": limit,
            },
            "events": [],
            "top_provider_event_pairs": [],
            "warnings": [],
            "errors": [],
            "limitations": [],
        }
    )
    return p


def network(info: PlatformInfo, interface_limit: int, address_limit: int) -> dict[str, Any]:
    assert info.system == "windows" and (interface_limit, address_limit) == (32, 16)
    p = common("windows_network")
    p.update(
        {
            "method": "psutil_net_if_addrs_stats_counters",
            "caps": {
                "max_interfaces": interface_limit,
                "max_addresses_per_interface": address_limit,
            },
            "summary": {
                "interfaces_total": 0,
                "interfaces_returned": 0,
                "interfaces_up": 0,
                "interfaces_down": 0,
                "ipv4_addresses": 0,
                "ipv6_addresses": 0,
                "interfaces_with_errors": 0,
                "truncated": False,
            },
            "interfaces": [],
            "limitations": [],
            "warnings": [],
            "errors": [],
        }
    )
    return p


def volumes(info: PlatformInfo, limit: int) -> dict[str, Any]:
    assert info.system == "windows" and limit == 32
    p = common("windows_volumes")
    p.update(
        {
            "collection": {
                "method": "psutil_local_drive_roots",
                "limit": limit,
                "truncated": False,
                "directory_scan_performed": False,
                "file_scan_performed": False,
                "remote_volume_probe_performed": False,
            },
            "summary": {
                "partitions_observed": 0,
                "local_drive_roots": 0,
                "returned_volumes": 0,
                "available_volumes": 0,
                "unavailable_volumes": 0,
                "fixed_volumes": 0,
                "removable_volumes": 0,
                "cdrom_volumes": 0,
                "read_only_volumes": 0,
                "skipped_remote": 0,
                "skipped_non_drive_root": 0,
                "skipped_unsafe_identifier": 0,
            },
            "volumes": [],
            "limitations": [],
            "warnings": [],
            "errors": [],
        }
    )
    return p


def forbidden(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    raise AssertionError("builder must not be called")


def payload(**kwargs: Any) -> dict[str, Any]:
    return windows_evidence_payload(
        WINDOWS,
        doctor_builder=doctor,
        status_builder=status,
        services_builder=services,
        disks_builder=forbidden,
        processes_builder=processes,
        events_builder=events,
        network_builder=network,
        volumes_builder=volumes,
        **kwargs,
    )


def _patch_cli_payload(
    monkeypatch: pytest.MonkeyPatch, profile_info: PlatformInfo = WINDOWS
) -> None:
    import shellforgeai.commands.windows as windows_commands

    def fake_windows_evidence_payload(**kwargs: Any) -> dict[str, Any]:
        return windows_evidence_payload(
            profile_info,
            doctor_builder=doctor,
            status_builder=status,
            services_builder=services,
            disks_builder=forbidden,
            processes_builder=processes,
            events_builder=events,
            network_builder=network,
            volumes_builder=volumes,
            **kwargs,
        )

    monkeypatch.setattr(windows_commands, "windows_evidence_payload", fake_windows_evidence_payload)


def test_cli_json_serializer_preserves_only_profile_component_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_cli_payload(monkeypatch)
    runner = CliRunner()

    profile_result = runner.invoke(app, ["windows", "evidence", "--profile", "standard", "--json"])
    assert profile_result.exit_code == 0
    assert profile_result.stderr == ""
    assert "Traceback" not in profile_result.output
    profile_raw = profile_result.output.rstrip("\n")
    profile_payload = json.loads(profile_raw)
    assert list(profile_payload["components"]) == PROFILE_COMPONENTS
    assert profile_payload["profile"]["components"] == PROFILE_COMPONENTS
    assert profile_payload["summary"]["ok_components"] == PROFILE_COMPONENTS
    assert profile_payload["summary"]["component_count"] == 7
    assert "disks" not in profile_payload["components"]
    assert "embedded_disks" not in profile_payload
    assert profile_payload["next_safe_command"] == "shellforgeai windows volumes --json"
    assert profile_raw != json.dumps(profile_payload, sort_keys=True)

    spec = importlib.util.spec_from_file_location(
        "acceptance_pr302_cli_serializer", Path("scripts/windows_smoke_acceptance.py")
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    profile_checks = module._validate_evidence(profile_payload, None, None)
    assert all(c.passed for c in profile_checks), [c.name for c in profile_checks if not c.passed]
    assert any(c.name == "evidence.profile.actual_components" and c.passed for c in profile_checks)

    default_result = runner.invoke(app, ["windows", "evidence", "--json"])
    assert default_result.exit_code == 0
    default_raw = default_result.output.rstrip("\n")
    default_payload = json.loads(default_raw)
    assert "profile" not in default_payload
    assert list(default_payload["components"]) == ["doctor", "status"]
    assert default_payload["next_safe_command"] == "shellforgeai windows status --json"
    assert default_raw == json.dumps(default_payload, sort_keys=True)

    manual_result = runner.invoke(app, ["windows", "evidence", "--include-volumes", "--json"])
    assert manual_result.exit_code == 0
    manual_raw = manual_result.output.rstrip("\n")
    manual_payload = json.loads(manual_raw)
    assert "profile" not in manual_payload
    assert list(manual_payload["components"]) == ["doctor", "status", "volumes"]
    assert manual_payload["next_safe_command"] == "shellforgeai windows volumes --json"
    assert manual_raw == json.dumps(manual_payload, sort_keys=True)

    _patch_cli_payload(monkeypatch, LINUX)
    unsupported_result = runner.invoke(
        app, ["windows", "evidence", "--profile", "standard", "--json"]
    )
    assert unsupported_result.exit_code == 0
    unsupported_raw = unsupported_result.output.rstrip("\n")
    unsupported_payload = json.loads(unsupported_raw)
    assert unsupported_payload["status"] == "unsupported"
    assert "profile" not in unsupported_payload
    assert "components" not in unsupported_payload
    assert unsupported_raw == json.dumps(unsupported_payload, sort_keys=True)


def test_cli_registration_and_validation() -> None:
    result = CliRunner().invoke(app, ["windows", "evidence", "--help"])
    assert result.exit_code == 0
    assert "--profile" in result.output
    assert "standard" in result.output
    assert "Mutually exclusive" in result.output
    assert (
        CliRunner().invoke(app, ["windows", "evidence", "--profile", "invalid", "--json"]).exit_code
        == 2
    )
    assert (
        "Traceback"
        not in CliRunner()
        .invoke(app, ["windows", "evidence", "--profile", "invalid", "--json"])
        .output
    )


@pytest.mark.parametrize(
    "bad", ["Standard", "STANDARD", "", " standard", "standard ", "unknown", True, 1]
)
def test_profile_validator_rejects_malformed_values(bad: Any) -> None:
    with pytest.raises(ValueError, match="windows evidence profile must be exactly 'standard'"):
        validate_windows_evidence_profile(bad)
    assert validate_windows_evidence_profile("standard") == "standard"


def test_resolver_pure_exact_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    import shellforgeai.windows_evidence as we

    monkeypatch.setattr(we, "detect_platform", forbidden)
    first = resolve_windows_evidence_profile("standard")
    second = resolve_windows_evidence_profile("standard")
    assert first == {
        "include_services": True,
        "services_limit": EVIDENCE_SERVICES_DEFAULT_LIMIT,
        "include_disks": False,
        "include_processes": True,
        "processes_limit": EVIDENCE_PROCESSES_DEFAULT_LIMIT,
        "include_events": True,
        "events_limit": DEFAULT_EVENTS_LIMIT,
        "events_since_hours": DEFAULT_SINCE_HOURS,
        "include_network": True,
        "network_interface_limit": EVIDENCE_NETWORK_DEFAULT_INTERFACE_LIMIT,
        "network_address_limit": EVIDENCE_NETWORK_DEFAULT_ADDRESS_LIMIT,
        "include_volumes": True,
        "volumes_limit": EVIDENCE_VOLUMES_DEFAULT_LIMIT,
    }
    assert first is not second
    first["services_limit"] = 1
    assert resolve_windows_evidence_profile("standard")["services_limit"] == 25


def test_default_and_manual_preserved() -> None:
    default = payload()
    assert "profile" not in default
    assert list(default["components"]) == ["doctor", "status"]
    assert default["summary"] == {
        "component_count": 2,
        "ok_components": ["doctor", "status"],
        "failed_components": [],
    }
    assert default["next_safe_command"] == "shellforgeai windows status --json"
    assert "Evidence profile:" not in render_windows_evidence_text(default)
    manual = payload(include_volumes=True, volumes_limit=32)
    assert "profile" not in manual
    assert list(manual["components"]) == ["doctor", "status", "volumes"]
    assert manual["next_safe_command"] == "shellforgeai windows volumes --json"


def test_standard_profile_exact_composition_text_and_manual_parity() -> None:
    profiled = payload(profile="standard")
    manual = payload(
        include_services=True,
        services_limit=25,
        include_processes=True,
        processes_limit=25,
        include_events=True,
        events_limit=50,
        events_since_hours=24,
        include_network=True,
        network_interface_limit=32,
        network_address_limit=16,
        include_volumes=True,
        volumes_limit=32,
    )
    assert profiled["profile"] == {
        "name": "standard",
        "components": PROFILE_COMPONENTS,
        "bounds": PROFILE_BOUNDS,
    }
    assert list(profiled["components"]) == PROFILE_COMPONENTS
    assert "disks" not in profiled["components"] and "embedded_disks" not in profiled
    assert profiled["summary"] == {
        "component_count": 7,
        "ok_components": PROFILE_COMPONENTS,
        "failed_components": [],
    }
    assert profiled["next_safe_command"] == "shellforgeai windows volumes --json"
    without_profile = dict(profiled)
    without_profile.pop("profile")
    assert without_profile == manual
    text = render_windows_evidence_text(profiled).splitlines()
    assert (
        text[
            text.index(
                "Components included: doctor, status, services, processes, events, network, volumes"
            )
            + 1
        ]
        == PROFILE_LINE
    )
    assert text.index(PROFILE_LINE) < text.index(
        "Component summary: ok=doctor,status,services,processes,events,network,volumes; failed=none"
    )


@pytest.mark.parametrize(
    "args",
    [
        ["--include-services"],
        ["--services-limit", "1"],
        ["--include-disks"],
        ["--disks-limit", "1"],
        ["--include-processes"],
        ["--processes-limit", "1"],
        ["--include-events"],
        ["--events-limit", "1"],
        ["--events-since-hours", "1"],
        ["--include-network"],
        ["--network-interface-limit", "1"],
        ["--network-address-limit", "1"],
        ["--include-volumes"],
        ["--volumes-limit", "1"],
    ],
)
def test_conflict_matrix_cli_and_api(args: list[str]) -> None:
    result = CliRunner().invoke(
        app, ["windows", "evidence", "--profile", "standard", *args, "--json"]
    )
    assert result.exit_code == 2
    assert "--profile" in result.output
    assert args[0] in result.output
    assert "Traceback" not in result.output
    with pytest.raises(ValueError, match="mutually exclusive"):
        windows_evidence_payload(
            WINDOWS, profile="standard", include_services=True, doctor_builder=forbidden
        )


def test_unsupported_profile_invokes_no_builders_and_has_no_profile() -> None:
    data = windows_evidence_payload(
        LINUX,
        profile="standard",
        doctor_builder=forbidden,
        status_builder=forbidden,
        services_builder=forbidden,
        disks_builder=forbidden,
        processes_builder=forbidden,
        events_builder=forbidden,
        network_builder=forbidden,
        volumes_builder=forbidden,
    )
    assert data["status"] == "unsupported"
    assert "profile" not in data and "components" not in data
    assert data["read_only"] is True and data["mutation_performed"] is False


def test_component_failure_and_healthy_empty_behavior() -> None:
    def bad_network(info: PlatformInfo, interface_limit: int, address_limit: int) -> dict[str, Any]:
        raise RuntimeError("secret path C:/Users/operator")

    data = windows_evidence_payload(
        WINDOWS,
        profile="standard",
        doctor_builder=doctor,
        status_builder=status,
        services_builder=services,
        disks_builder=forbidden,
        processes_builder=processes,
        events_builder=events,
        network_builder=bad_network,
        volumes_builder=volumes,
    )
    assert data["profile"]["name"] == "standard"
    assert list(data["components"]) == PROFILE_COMPONENTS
    assert data["status"] == "component_failure"
    assert data["summary"]["component_count"] == 7
    assert data["summary"]["failed_components"] == ["network"]
    assert "secret path" not in json.dumps(data)
    assert data["next_safe_command"] == "shellforgeai windows volumes --json"
    assert payload(profile="standard")["status"] == "ok"


def test_acceptance_profile_fixtures(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "acceptance_pr302", Path("scripts/windows_smoke_acceptance.py")
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    good = payload(profile="standard")
    checks = module._validate_evidence(good, None, None)
    assert all(c.passed for c in checks), [c.name for c in checks if not c.passed]
    bad = dict(good)
    bad["profile"] = {**good["profile"], "extra": True}
    assert not all(c.passed for c in module._validate_evidence(bad, None, None))
    bad = dict(good)
    bad["profile"] = {**good["profile"], "bounds": {**PROFILE_BOUNDS, "services_limit": True}}
    assert not all(c.passed for c in module._validate_evidence(bad, None, None))
    bad = dict(good)
    bad["components"] = {**good["components"], "disks": {"status": "ok"}}
    assert not all(c.passed for c in module._validate_evidence(bad, None, None))


def test_pr302_source_guardrails_positive_control() -> None:
    files = [
        Path("src/shellforgeai/windows_evidence.py"),
        Path("src/shellforgeai/commands/windows.py"),
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in files)
    forbidden_terms = [
        "subprocess",
        "shell=True",
        "subprocess.run",
        "powershell_executed = True",
        "winrm_used = True",
        "qga",
        "registry_api",
        "model_called = True",
        "read_only=False",
        '"disks",\n    "memory"',
    ]
    assert not [term for term in forbidden_terms if term in text]
    assert "WINDOWS_EVIDENCE_STANDARD_PROFILE_COMPONENTS" in text
    unsafe = text + "\nsubprocess.run(['pwsh'], shell=True)\n"
    assert [term for term in forbidden_terms if term in unsafe]
