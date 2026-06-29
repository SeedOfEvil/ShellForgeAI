from __future__ import annotations

import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_doctor import render_windows_doctor_text, windows_doctor_payload

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")


def test_pr_specific_test_file_exists() -> None:
    assert Path("tests/test_pr261_windows_read_only_doctor.py").exists()


def test_mocked_windows_doctor_returns_ok_read_only_no_mutation() -> None:
    payload = windows_doctor_payload(WINDOWS_INFO)
    assert payload["status"] == "ok"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["windows_v1"]["available"] is True
    assert payload["windows_v1"]["powershell_executed"] is False
    assert payload["windows_v1"]["winrm_used"] is False


def test_mocked_windows_doctor_not_collected_sections() -> None:
    not_collected = windows_doctor_payload(WINDOWS_INFO)["not_collected_in_pr261"]
    for key in (
        "powershell_version",
        "execution_policy",
        "services",
        "processes",
        "event_logs",
    ):
        assert key in not_collected


def test_mocked_windows_doctor_safety_contract() -> None:
    safety = windows_doctor_payload(WINDOWS_INFO)["safety"]
    for key in (
        "read_only",
        "mutation_performed",
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
    ):
        assert key in safety
    assert safety["read_only"] is True
    assert all(value is False for key, value in safety.items() if key != "read_only")


def test_linux_platform_returns_deterministic_unsupported_json() -> None:
    payload = windows_doctor_payload(LINUX_INFO)
    expected = {
        "schema_version": 1,
        "mode": "windows_doctor",
        "status": "unsupported",
        "platform": {"system": "linux"},
        "reason": "Windows doctor is only available on Windows hosts.",
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
    payload = windows_doctor_payload(LINUX_INFO)
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_text_output_is_concise() -> None:
    text = render_windows_doctor_text(windows_doctor_payload(LINUX_INFO))
    assert "ShellForgeAI Windows doctor" in text
    assert "Status: unsupported" in text
    assert "Next safe command: shellforgeai platform doctor --json" in text
    assert len(text.splitlines()) <= 8


def test_cli_windows_doctor_json_invokes_unsupported_on_linux(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_doctor.detect_platform", lambda: LINUX_INFO)
    result = CliRunner().invoke(app, ["windows", "doctor", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "linux"}


def test_cli_windows_doctor_json_invokes_mocked_windows(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_doctor.detect_platform", lambda: WINDOWS_INFO)
    result = CliRunner().invoke(app, ["windows", "doctor", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["platform"]["system"] == "windows"
    assert payload["windows_v1"]["available"] is True


def test_cli_inventory_classifies_windows_module_read_only_platform_status() -> None:
    source = Path("scripts/cli_refactor_inventory.py").read_text(encoding="utf-8")
    assert (
        '"windows doctor": {"module": "windows.py", "category": "read_only", "known_pr": 261}'
        in source
    )
    assert "windows.py" in source
    assert "confirm_gated_mutation" not in source.split('"windows doctor"', 1)[1].split("},", 1)[0]
    assert "remediation" not in source.split('"windows doctor"', 1)[1].split("},", 1)[0]


def test_no_unexpected_command_module_introduced() -> None:
    commands = {p.name for p in Path("src/shellforgeai/commands").glob("*.py")}
    assert "windows.py" in commands
    assert "windows.py" in Path("scripts/cli_refactor_inventory.py").read_text(encoding="utf-8")


def test_windows_doctor_source_has_no_forbidden_execution_imports_or_calls() -> None:
    for path in (
        Path("src/shellforgeai/windows_doctor.py"),
        Path("src/shellforgeai/commands/windows.py"),
    ):
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        assert "shell=true" not in lowered
        assert "subprocess" not in lowered
        assert "invoke-command" not in lowered
        assert "new-pssession" not in lowered
        assert "winrm" not in lowered.replace("winrm_used", "")
        assert "psremoting" not in lowered
        assert "docker" not in lowered
        assert "compose" not in lowered
        assert "codex" not in lowered
        assert "openai" not in lowered
        assert "secret" not in lowered.replace("secret_read", "").replace(
            "secret_or_auth_cache_read", ""
        )
        assert "auth_cache" not in lowered.replace("auth_cache_read", "").replace(
            "secret_or_auth_cache_read", ""
        )
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert "subprocess" not in imported
        assert "requests" not in imported
        assert "urllib" not in imported
        assert "httpx" not in imported
        assert "socketserver" not in imported
