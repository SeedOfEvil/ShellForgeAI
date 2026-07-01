from __future__ import annotations

import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_services import (
    DEFAULT_MAX_SERVICES,
    RawServiceRecord,
    bounded_max_services,
    render_windows_services_text,
    service_state_label,
    service_type_label,
    windows_services_payload,
)

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")
UNKNOWN_INFO = PlatformInfo("unknown", "Mystery-test", "posix", "0", "riscv")

FAKE_RECORDS = (
    RawServiceRecord("wuauserv", "Windows Update", 1, 0x20),
    RawServiceRecord("Spooler", "Print Spooler", 4, 0x10),
    RawServiceRecord("Audiosrv", "Windows Audio", 4, 0x10),
    RawServiceRecord("SysMain", "SysMain", 7, 0x20),
    RawServiceRecord("TrustedInstaller", "Windows Modules Installer", 2, 0x10),
    RawServiceRecord("BITS", "Background Intelligent Transfer Service", 3, 0x20),
    RawServiceRecord("MysterySvc", "Mystery Service", 99, 0x9999),
)


def fake_enumerator() -> list[RawServiceRecord]:
    return list(FAKE_RECORDS)


def services_payload_for_mocked_windows(**kwargs):
    return windows_services_payload(WINDOWS_INFO, enumerator=fake_enumerator, **kwargs)


def test_pr_specific_test_file_exists() -> None:
    assert Path("tests/test_pr267_windows_read_only_services.py").exists()


def test_mocked_windows_services_contract() -> None:
    payload = services_payload_for_mocked_windows()
    assert payload["status"] == "ok"
    assert payload["mode"] == "windows_services"
    assert payload["platform"] == {"system": "windows"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["windows_v1"]["available"] is True
    assert payload["windows_v1"]["scope"] == "local_read_only_services"
    assert payload["windows_v1"]["powershell_executed"] is False
    assert payload["windows_v1"]["winrm_used"] is False
    assert payload["windows_v1"]["remote_execution"] is False
    assert payload["next_safe_command"] == "shellforgeai windows status --json"


def test_mocked_windows_services_totals_and_state_counts() -> None:
    services = services_payload_for_mocked_windows()["services"]
    assert services["collection"] == "local_windows_service_state_summary"
    assert services["total_count"] == 7
    assert services["state_counts"] == {
        "running": 2,
        "stopped": 1,
        "paused": 1,
        "start_pending": 1,
        "stop_pending": 1,
        "continue_pending": 0,
        "pause_pending": 0,
        "unknown": 1,
    }


def test_mocked_windows_service_items_sorted_and_safe_fields_only() -> None:
    items = services_payload_for_mocked_windows()["services"]["items"]
    assert [item["name"] for item in items] == [
        "Audiosrv",
        "BITS",
        "MysterySvc",
        "Spooler",
        "SysMain",
        "TrustedInstaller",
        "wuauserv",
    ]
    for item in items:
        assert set(item) == {"name", "display_name", "state", "service_type"}
    spooler = next(item for item in items if item["name"] == "Spooler")
    assert spooler == {
        "name": "Spooler",
        "display_name": "Print Spooler",
        "state": "running",
        "service_type": "win32_own_process",
    }


def test_service_state_mapping_is_deterministic() -> None:
    assert service_state_label(1) == "stopped"
    assert service_state_label(2) == "start_pending"
    assert service_state_label(3) == "stop_pending"
    assert service_state_label(4) == "running"
    assert service_state_label(5) == "continue_pending"
    assert service_state_label(6) == "pause_pending"
    assert service_state_label(7) == "paused"
    assert service_state_label(0) == "unknown"
    assert service_state_label(99) == "unknown"


def test_service_type_mapping_is_deterministic() -> None:
    assert service_type_label(0x10) == "win32_own_process"
    assert service_type_label(0x20) == "win32_share_process"
    assert service_type_label(0x110) == "win32_own_process"  # interactive flag stripped
    assert service_type_label(0x1) == "kernel_driver"
    assert service_type_label(0x2) == "file_system_driver"
    assert service_type_label(0x9999) == "unknown"


def test_collection_limit_and_truncated_flag() -> None:
    payload = services_payload_for_mocked_windows(max_services=3)
    services = payload["services"]
    assert services["collection_limits"] == {"max_services": 3, "truncated": True}
    assert services["total_count"] == 7
    assert [item["name"] for item in services["items"]] == ["Audiosrv", "BITS", "MysterySvc"]
    untruncated = services_payload_for_mocked_windows()["services"]
    assert untruncated["collection_limits"] == {
        "max_services": DEFAULT_MAX_SERVICES,
        "truncated": False,
    }
    assert len(untruncated["items"]) == 7


def test_max_services_limit_is_bounded() -> None:
    assert bounded_max_services(0) == 1
    assert bounded_max_services(-5) == 1
    assert bounded_max_services(10_000) == 500
    assert bounded_max_services(250) == 250
    assert bounded_max_services(DEFAULT_MAX_SERVICES) == 500


def test_mocked_windows_services_not_collected_sections() -> None:
    not_collected = services_payload_for_mocked_windows()["not_collected_in_pr267"]
    for key in (
        "service_binary_path",
        "service_account",
        "service_description",
        "service_dependencies",
        "service_recovery_options",
        "process_details",
        "event_logs",
        "firewall",
        "windows_update",
    ):
        assert key in not_collected


def test_mocked_windows_services_safety_flags() -> None:
    safety = services_payload_for_mocked_windows()["safety"]
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
        "mutation_performed",
    ):
        assert safety[key] is False
    assert safety["read_only"] is True


def test_enumeration_failure_returns_structured_error_without_traceback() -> None:
    def failing_enumerator() -> list[RawServiceRecord]:
        raise PermissionError("access denied to service control manager")

    payload = windows_services_payload(WINDOWS_INFO, enumerator=failing_enumerator)
    assert payload["status"] == "error"
    assert payload["mode"] == "windows_services"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["reason"] == "service enumeration failed: PermissionError"
    assert "services" not in payload
    safety = payload["safety"]
    assert safety["service_control_executed"] is False
    assert safety["service_config_modified"] is False
    assert safety["powershell_executed"] is False
    assert safety["winrm_used"] is False
    assert safety["network_call"] is False


def test_linux_platform_returns_deterministic_unsupported_json() -> None:
    payload = windows_services_payload(LINUX_INFO)
    expected = {
        "schema_version": 1,
        "mode": "windows_services",
        "status": "unsupported",
        "platform": {"system": "linux"},
        "reason": "Windows services evidence is only available on Windows hosts.",
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": False,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "powershell_executed": False,
            "winrm_used": False,
            "remote_execution": False,
            "service_restart_executed": False,
            "service_control_executed": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "secret_read": False,
            "auth_cache_read": False,
            "model_called": False,
            "network_call": False,
        },
        "next_safe_command": "shellforgeai platform doctor --json",
    }
    assert payload == expected
    assert json.loads(json.dumps(payload, sort_keys=True)) == expected


def test_linux_unsupported_output_points_to_platform_doctor() -> None:
    payload = windows_services_payload(LINUX_INFO)
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_unknown_platform_returns_structured_unsupported() -> None:
    payload = windows_services_payload(UNKNOWN_INFO)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "unknown"}
    assert payload["mutation_performed"] is False
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_text_output_is_concise() -> None:
    text = render_windows_services_text(services_payload_for_mocked_windows())
    assert "ShellForgeAI Windows services" in text
    assert "Status: ok" in text
    assert "Total services: 7" in text
    assert "States: running=2" in text
    assert "Collection limit: max_services=500; truncated=false" in text
    assert "Not collected yet:" in text
    assert "Next safe command: shellforgeai windows status --json" in text
    assert len(text.splitlines()) <= 12


def test_unsupported_text_output_is_concise() -> None:
    text = render_windows_services_text(windows_services_payload(LINUX_INFO))
    assert "Status: unsupported" in text
    assert "Windows services evidence is only available on Windows hosts." in text
    assert "Next safe command: shellforgeai platform doctor --json" in text
    assert len(text.splitlines()) <= 10


def test_cli_windows_services_json_invokes_unsupported_on_linux(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_services.detect_platform", lambda: LINUX_INFO)
    result = CliRunner().invoke(app, ["windows", "services", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "linux"}
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_cli_windows_services_json_invokes_mocked_windows(monkeypatch) -> None:
    expected = services_payload_for_mocked_windows()
    monkeypatch.setattr(
        "shellforgeai.commands.windows.windows_services_payload",
        lambda **_kwargs: expected,
    )
    result = CliRunner().invoke(app, ["windows", "services", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["mode"] == "windows_services"
    assert payload["windows_v1"]["available"] is True
    assert payload["services"]["total_count"] == 7


def test_cli_windows_services_limit_flag_is_passed_through(monkeypatch) -> None:
    seen: dict[str, int] = {}

    def capture(**kwargs):
        seen.update(kwargs)
        return windows_services_payload(LINUX_INFO)

    monkeypatch.setattr("shellforgeai.commands.windows.windows_services_payload", capture)
    result = CliRunner().invoke(app, ["windows", "services", "--json", "--limit", "25"])
    assert result.exit_code == 0
    assert seen == {"max_services": 25}


def test_cli_inventory_classifies_windows_services_read_only() -> None:
    source = Path("scripts/cli_refactor_inventory.py").read_text(encoding="utf-8")
    assert (
        '"windows services": {"module": "windows.py", "category": "read_only", "known_pr": 267}'
        in source
    )
    assert (
        "confirm_gated_mutation" not in source.split('"windows services"', 1)[1].split("},", 1)[0]
    )
    assert "remediation" not in source.split('"windows services"', 1)[1].split("},", 1)[0]


def test_pr267_source_has_no_forbidden_execution_paths() -> None:
    for path in (
        Path("src/shellforgeai/windows_services.py"),
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
            "docker",
            "compose",
            "codex",
            "openai",
            "secret_read = true",
            "auth_cache_read = true",
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
        for banned_module in (
            "subprocess",
            "socket",
            "http",
            "urllib",
            "winreg",
            "wmi",
        ):
            assert banned_module not in imported, f"{path} imports {banned_module}"


def test_pr267_source_uses_only_enumeration_scm_apis() -> None:
    source = Path("src/shellforgeai/windows_services.py").read_text(encoding="utf-8")
    lowered = source.lower()
    for forbidden_api in (
        "controlservice",
        "startservice",
        "deleteservice",
        "changeserviceconfig",
        "createservice",
        "openservicew",
        "regopenkey",
        "regqueryvalue",
        "regsetvalue",
        "regcreatekey",
        "regdeletekey",
    ):
        assert forbidden_api not in lowered, f"forbidden API reference {forbidden_api!r}"
    assert "OpenSCManagerW" in source
    assert "EnumServicesStatusExW" in source
    assert "CloseServiceHandle" in source
