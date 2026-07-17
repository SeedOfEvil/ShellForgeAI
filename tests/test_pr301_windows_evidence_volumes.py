from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_evidence import (
    EVIDENCE_VOLUMES_DEFAULT_LIMIT,
    render_windows_evidence_text,
    validate_evidence_volumes_limit,
    windows_evidence_payload,
)

WINDOWS = PlatformInfo("windows", "WIN", "nt", "2025", "AMD64")
LINUX = PlatformInfo("linux", "linux", "posix", "6.8", "x86_64")


def base(mode, scope):
    return {
        "schema_version": 1,
        "mode": mode,
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": scope,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {
            k: False
            for k in (
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
                "secret_read",
                "auth_cache_read",
                "model_called",
                "network_call",
            )
        },
        "host": {"hostname": "WIN", "python": "3.14"},
        "python_runtime": {"version": "3.14", "executable": "python"},
        "filesystem": {"cwd": "C:/Tools/ShellForgeAI", "home": "C:/Users/Operator"},
    }


def doctor(_info):
    return base("windows_doctor", "local_read_only_doctor")


def status(_info):
    return base("windows_status", "local_read_only_status")


def volumes_payload(limit=32, *, status_value="ok", empty=False, unavailable=False):
    vols = (
        []
        if empty
        else [
            {
                "drive": "C:",
                "mountpoint": "C:\\",
                "filesystem": "NTFS",
                "kind": "fixed",
                "access": "read_write",
                "status": "unavailable" if unavailable else "ok",
                "warnings": [],
                **(
                    {"error": "disk_usage_failed"}
                    if unavailable
                    else {"total_bytes": 10, "used_bytes": 4, "free_bytes": 6, "used_percent": 40.0}
                ),
            }
        ]
    )
    available = sum(1 for v in vols if v["status"] == "ok")
    return {
        "schema_version": 1,
        "mode": "windows_volumes",
        "status": status_value,
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "collection": {
            "method": "psutil_local_drive_roots",
            "limit": limit,
            "truncated": False,
            "directory_scan_performed": False,
            "file_scan_performed": False,
            "remote_volume_probe_performed": False,
        },
        "summary": {
            "partitions_observed": 0 if empty else 2,
            "local_drive_roots": len(vols),
            "returned_volumes": len(vols),
            "available_volumes": available,
            "unavailable_volumes": len(vols) - available,
            "fixed_volumes": len(vols),
            "removable_volumes": 0,
            "cdrom_volumes": 0,
            "read_only_volumes": 0,
            "skipped_remote": 1 if vols else 0,
            "skipped_non_drive_root": 0,
            "skipped_unsafe_identifier": 0,
        },
        "volumes": vols,
        "limitations": [
            "Only local drive-root volumes were inspected.",
            (
                "No files, directories, network shares, volume GUIDs, labels, serials, "
                "encryption state, physical disks, or storage health were inspected."
            ),
        ],
        "warnings": [],
        "errors": [] if status_value == "ok" else [{"type": "raw", "message": "RAW C:/secret"}],
        "safety": {
            k: False
            for k in (
                "directory_scan_performed",
                "file_scan_performed",
                "remote_execution",
                "network_call",
                "powershell_executed",
                "winrm_used",
                "shell_true",
                "arbitrary_command_execution",
                "registry_modified",
                "disk_mutation_performed",
                "cleanup_executed",
                "remediation_executed",
                "rollback_executed",
                "recovery_executed",
                "secret_read",
                "auth_cache_read",
                "model_called",
            )
        }
        | {"read_only": True, "mutation_performed": False},
    }


def evidence(**kwargs):
    return windows_evidence_payload(WINDOWS, doctor_builder=doctor, status_builder=status, **kwargs)


def test_cli_registration_and_standalone_unchanged():
    help_result = CliRunner().invoke(app, ["windows", "evidence", "--help"])
    assert help_result.exit_code == 0
    assert "--include-volumes" in help_result.stdout
    assert "--volumes-limit" in help_result.stdout
    assert "1-64" in help_result.stdout and "default 32" in help_result.stdout
    assert "local drive-root" in help_result.stdout
    volumes_help = CliRunner().invoke(app, ["windows", "volumes", "--help"])
    assert volumes_help.exit_code == 0
    assert (
        "--include-volumes" not in volumes_help.stdout
        and "--volumes-limit" not in volumes_help.stdout
    )


def test_default_omission_and_builder_not_called():
    default_payload = evidence()

    def boom(*_args):
        raise AssertionError("volumes builder called")

    injected = evidence(volumes_builder=boom)
    assert injected == default_payload
    assert list(injected["components"]) == ["doctor", "status"]
    assert "volumes" not in injected["components"] and "embedded_volumes" not in injected
    assert injected["next_safe_command"] == "shellforgeai windows status --json"
    assert render_windows_evidence_text(injected) == render_windows_evidence_text(default_payload)


def test_opt_in_defaults_forwards_embeds_orders_and_text_privacy():
    calls = []
    payload = evidence(
        include_volumes=True,
        volumes_builder=lambda info, limit: (
            calls.append((info.system, limit)) or volumes_payload(limit)
        ),
    )
    assert calls == [("windows", 32)]
    assert EVIDENCE_VOLUMES_DEFAULT_LIMIT == 32
    assert list(payload["components"]) == ["doctor", "status", "volumes"]
    assert payload["embedded_volumes"]["limit"] == 32
    assert payload["next_safe_command"] == "shellforgeai windows volumes --json"
    text = render_windows_evidence_text(payload)
    assert (
        "Volumes component: status=ok; returned=1/1; available=1; unavailable=0; "
        "fixed=1; removable=0; cdrom=0; read_only=0; limit=32; truncated=false" in text
    )
    assert (
        "C:\\" not in text
        and "NTFS" not in text
        and "total_bytes" not in text
        and "disk_usage_failed" not in text
    )


def test_bounds_boolean_rejection_and_dependency_error():
    for value in (1, 32, 64):
        assert validate_evidence_volumes_limit(value) == value
    for value in (0, 65, -1, True, False, "8", 1.5):
        try:
            validate_evidence_volumes_limit(value)
        except ValueError:
            pass
        else:
            raise AssertionError(value)
    result = CliRunner().invoke(app, ["windows", "evidence", "--volumes-limit", "8", "--json"])
    assert result.exit_code != 0
    assert "include-volumes" in result.output and "Traceback" not in result.output


def test_component_combinations_order_and_independent_limits():
    payload = evidence(
        include_services=True,
        services_builder=lambda _i, _l: {
            "status": "ok",
            "services": {"items": [], "collection_limits": {"truncated": False}, "total_count": 0},
        },
        include_disks=True,
        disks_builder=lambda _i, _l: {
            "status": "ok",
            "summary": {"total_roots": 0, "returned_roots": 0},
            "collection": {"truncated": False},
        },
        include_processes=True,
        processes_builder=lambda _i, _l: {
            "status": "ok",
            "returned_count": 0,
            "total_count": 0,
            "truncated": False,
        },
        include_events=True,
        events_builder=lambda _i, _l, _h: {
            "status": "ok",
            "summary": {
                "events_returned": 0,
                "critical": 0,
                "error": 0,
                "warning": 0,
                "unknown": 0,
                "truncated": False,
                "limit": _l,
                "since_hours": _h,
            },
            "collection": {"limit": _l, "since_hours": _h},
        },
        include_network=True,
        network_builder=lambda _i, il, al: {
            "schema_version": 1,
            "mode": "windows_network",
            "status": "ok",
            "method": "psutil_net_if_addrs_stats_counters",
            "caps": {"max_interfaces": il, "max_addresses_per_interface": al},
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
        },
        include_volumes=True,
        volumes_limit=8,
        volumes_builder=lambda _i, limit: volumes_payload(limit),
    )
    assert list(payload["components"]) == [
        "doctor",
        "status",
        "services",
        "disks",
        "processes",
        "events",
        "network",
        "volumes",
    ]
    assert payload["components"]["volumes"]["collection"]["limit"] == 8
    assert payload["summary"]["component_count"] == 8


def test_unsupported_linux_full_cli_does_not_call_builder_or_psutil(monkeypatch):
    monkeypatch.setattr("shellforgeai.windows_evidence.detect_platform", lambda: LINUX)
    monkeypatch.setattr(
        "shellforgeai.windows_volumes.windows_volumes_payload",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("called")),
    )
    result = CliRunner().invoke(app, ["windows", "evidence", "--include-volumes", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported" and payload["platform"] == {"system": "linux"}
    assert "components" not in payload and "embedded_volumes" not in payload
    assert payload["read_only"] is True and payload["mutation_performed"] is False


def test_healthy_empty_unavailable_and_failure_normalization_no_leakage():
    empty = evidence(
        include_volumes=True, volumes_builder=lambda _i, limit: volumes_payload(limit, empty=True)
    )
    assert empty["status"] == "ok" and "volumes" in empty["summary"]["ok_components"]
    assert (
        empty["embedded_volumes"]["local_drive_roots"] == 0
        and empty["embedded_volumes"]["truncated"] is False
    )
    unavailable = evidence(
        include_volumes=True,
        volumes_builder=lambda _i, limit: volumes_payload(limit, unavailable=True),
    )
    assert (
        unavailable["status"] == "ok"
        and unavailable["components"]["volumes"]["volumes"][0]["error"] == "disk_usage_failed"
    )

    def raised(*_args):
        raise RuntimeError("RAW_MARKER /home/operator/secret RuntimeError")

    malformed = [
        raised,
        lambda *_: volumes_payload(status_value="error"),
        lambda *_: {"mode": "wrong"},
        lambda *_: None,
        lambda *_: [],
    ]
    for builder in malformed:
        payload = evidence(include_volumes=True, volumes_limit=4, volumes_builder=builder)
        dumped = json.dumps(payload)
        comp = payload["components"]["volumes"]
        assert payload["status"] == "component_failure"
        assert payload["summary"]["failed_components"] == ["volumes"]
        assert (
            comp["status"] == "error" and comp["collection"]["limit"] == 4 and comp["volumes"] == []
        )
        assert comp["errors"] == [
            {
                "type": "volumes_component_failed",
                "message": "Windows volume/filesystem metadata component failed.",
            }
        ]
        assert (
            "RAW_MARKER" not in dumped
            and "/home/operator" not in dumped
            and "RuntimeError" not in dumped
            and "Traceback" not in dumped
        )


def test_acceptance_fixtures_and_rejections():
    path = Path(__file__).resolve().parents[1] / "scripts" / "windows_smoke_acceptance.py"
    spec = importlib.util.spec_from_file_location("windows_smoke_acceptance_pr301", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    healthy = evidence(
        include_volumes=True, volumes_builder=lambda _i, limit: volumes_payload(limit)
    )
    default = evidence()
    failed = evidence(
        include_volumes=True,
        volumes_builder=lambda *_: (_ for _ in ()).throw(RuntimeError("C:/raw")),
    )
    for artifact in (
        healthy,
        default,
        failed,
        evidence(
            include_volumes=True,
            volumes_builder=lambda _i, limit: volumes_payload(limit, empty=True),
        ),
    ):
        checks = mod._validate_evidence(artifact, None, None)
        assert all(c.passed for c in checks), [c.to_dict() for c in checks if not c.passed]
    cases = [
        (failed, lambda p: p.__setitem__("status", "ok")),
        (healthy, lambda p: p["embedded_volumes"].__setitem__("limit", 99)),
        (
            healthy,
            lambda p: p["components"]["volumes"]["summary"].__setitem__("available_volumes", 9),
        ),
        (
            healthy,
            lambda p: p["components"]["volumes"]["volumes"][0].__setitem__("label", "SECRET"),
        ),
        (healthy, lambda p: p["components"]["volumes"]["safety"].__setitem__("network_call", True)),
    ]
    for source, mutate in cases:
        bad = json.loads(json.dumps(source))
        mutate(bad)
        assert not all(c.passed for c in mod._validate_evidence(bad, None, None))


def test_source_guardrails_positive_control():
    files = [
        Path("src/shellforgeai/windows_evidence.py"),
        Path("src/shellforgeai/commands/windows.py"),
    ]
    patterns = [
        r"subprocess\.(run|Popen|call|check_call|check_output)\(",
        r"shell\s*=\s*True",
        r"(?<![\"'])powershell(?!_executed[\"'])",
        r"(?<![\"'])winrm(?!_used[\"'])",
        r"os\.walk\(",
        r"os\.listdir\(",
        r"os\.scandir\(",
        r"Path\.iterdir\(",
        r"read_only\s*=\s*False",
    ]

    def violations(source):
        return [pat for pat in patterns if re.search(pat, source)]

    actual = []
    for path in files:
        actual.extend(violations(path.read_text(encoding="utf-8")))
    assert not actual
    assert violations("subprocess.run(['x'], shell=True); read_only = False; os.walk('.')")
