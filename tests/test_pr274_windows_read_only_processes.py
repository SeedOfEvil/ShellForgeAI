from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_processes import (
    DEFAULT_PROCESSES_LIMIT,
    render_windows_processes_text,
    validate_processes_limit,
    windows_processes_payload,
)

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")

FAKE_PROCESSES = [
    {"pid": 4, "parent_pid": 0, "name": "System", "thread_count": 120},
    {"pid": 100, "parent_pid": 4, "name": "smss.exe", "thread_count": 2},
    {"pid": 1234, "parent_pid": 1000, "name": "C:/unsafe/path/example.exe", "thread_count": 4},
]
MANY_PROCESSES = [
    {"pid": pid, "parent_pid": 1, "name": f"p{pid}.exe", "thread_count": 1} for pid in range(1, 61)
]


def fake_processes():
    return list(FAKE_PROCESSES)


def test_pr_specific_test_file_exists() -> None:
    assert Path("tests/test_pr274_windows_read_only_processes.py").exists()


def test_mocked_windows_processes_contract() -> None:
    payload = windows_processes_payload(WINDOWS_INFO, process_enumerator=fake_processes)
    assert payload["status"] == "ok"
    assert payload["mode"] == "windows_processes"
    assert payload["platform"] == {"system": "windows"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["windows_v1"] == {
        "available": True,
        "scope": "local_read_only_processes_preview",
        "remote_execution": False,
        "powershell_executed": False,
        "winrm_used": False,
    }
    assert payload["method"] == "ctypes_toolhelp32_snapshot"
    assert payload["limit"] == DEFAULT_PROCESSES_LIMIT == 50
    assert payload["state"] == {"enumeration_failed": False}


def test_limit_10_honors_limit_and_truncates_when_total_exceeds_limit() -> None:
    payload = windows_processes_payload(
        WINDOWS_INFO, process_enumerator=lambda: MANY_PROCESSES, limit=10
    )
    assert payload["limit"] == 10
    assert payload["total_count"] == 60
    assert payload["returned_count"] == 10
    assert len(payload["processes"]) == 10
    assert payload["returned_count"] <= payload["limit"]
    assert payload["truncated"] is True


@pytest.mark.parametrize("invalid", [0, 201])
def test_invalid_limits_are_rejected(invalid: int) -> None:
    with pytest.raises(ValueError):
        validate_processes_limit(invalid)


@pytest.mark.parametrize("invalid", ["0", "201"])
def test_cli_invalid_limits_fail_cleanly(invalid: str) -> None:
    result = CliRunner().invoke(app, ["windows", "processes", "--json", "--limit", invalid])
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_process_items_include_only_allowed_fields_and_basename() -> None:
    payload = windows_processes_payload(WINDOWS_INFO, process_enumerator=fake_processes)
    for item in payload["processes"]:
        assert set(item) == {"pid", "parent_pid", "name", "thread_count"}
        forbidden = json.dumps(item).lower()
        for word in ("command", "environment", "memory", "handles", "modules", "owner", "token"):
            assert word not in forbidden
    assert payload["processes"][2]["name"] == "example.exe"


def test_not_collected_in_pr274_documents_exclusions() -> None:
    not_collected = windows_processes_payload(WINDOWS_INFO, process_enumerator=fake_processes)[
        "not_collected_in_pr274"
    ]
    for key in (
        "command_line",
        "environment",
        "memory",
        "handles",
        "modules",
        "owner_user",
        "network_connections",
    ):
        assert key in not_collected


def test_safety_flags_are_false_for_forbidden_behavior() -> None:
    safety = windows_processes_payload(WINDOWS_INFO, process_enumerator=fake_processes)["safety"]
    assert safety["read_only"] is True
    assert safety["mutation_performed"] is False
    for key in (
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
    ):
        assert safety[key] is False


def test_linux_unsupported_output_is_structured_and_does_not_enumerate() -> None:
    called = False

    def enumerator():
        nonlocal called
        called = True
        return MANY_PROCESSES

    payload = windows_processes_payload(LINUX_INFO, process_enumerator=enumerator)
    assert called is False
    assert payload["status"] == "unsupported"
    assert payload["mode"] == "windows_processes"
    assert payload["platform"] == {"system": "linux"}
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"
    assert "processes" not in payload


def test_cli_windows_processes_json_invokes_and_is_unsupported_on_linux() -> None:
    result = CliRunner().invoke(app, ["windows", "processes", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["mode"] == "windows_processes"
    assert payload["status"] == "unsupported"
    assert payload["read_only"] is True


def test_cli_windows_processes_json_limit_10_invokes() -> None:
    result = CliRunner().invoke(app, ["windows", "processes", "--json", "--limit", "10"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["mode"] == "windows_processes"
    assert payload["status"] == "unsupported"


def test_cli_text_output_is_concise() -> None:
    text = render_windows_processes_text(
        windows_processes_payload(WINDOWS_INFO, process_enumerator=fake_processes, limit=2)
    )
    assert "ShellForgeAI Windows processes" in text
    assert "Processes: total=3; returned=2; limit=2; truncated=true" in text
    assert "Not collected:" in text
    assert len(text.splitlines()) <= 14


def test_source_safety_has_no_forbidden_execution_or_writes() -> None:
    source = Path("src/shellforgeai/windows_processes.py").read_text()
    tree = ast.parse(source)
    imports = [node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)]
    assert "subprocess" not in imports
    lower = source.lower()
    for forbidden in (
        "pwsh",
        "invoke-command",
        "psremoting",
        "docker",
        "compose",
        "open(",
        "write_text",
        "write_bytes",
        "shell=true",
        "terminateprocess",
        "openprocess",
        "readprocessmemory",
    ):
        assert forbidden not in lower
