from __future__ import annotations

import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_status import render_windows_status_text, windows_status_payload

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")


def fake_disk_usage(_path: str | Path) -> tuple[int, int, int]:
    return (1000, 400, 600)


def test_pr_specific_test_file_exists() -> None:
    assert Path("tests/test_pr262_windows_read_only_status.py").exists()


def test_mocked_windows_status_contract() -> None:
    payload = windows_status_payload(WINDOWS_INFO, disk_usage=fake_disk_usage, cwd=Path("C:/safe"))
    assert payload["status"] == "ok"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["windows_v1"]["available"] is True
    assert payload["windows_v1"]["powershell_executed"] is False
    assert payload["windows_v1"]["winrm_used"] is False
    assert payload["windows_v1"]["remote_execution"] is False


def test_mocked_windows_status_includes_host_runtime_and_filesystem_basics() -> None:
    payload = windows_status_payload(WINDOWS_INFO, disk_usage=fake_disk_usage, cwd=Path("C:/safe"))
    assert payload["host"]["hostname"] is not None
    assert payload["host"]["fqdn"] is not None
    assert payload["host"]["cwd"] == "C:/safe"
    assert payload["host"]["user_context_collected"] is False
    assert payload["host"]["secret_or_auth_cache_read"] is False
    assert payload["python_runtime"]["executable"]
    assert payload["python_runtime"]["version"]
    assert payload["python_runtime"]["implementation"]
    assert payload["filesystem"]["collection"] == "stdlib_only"
    assert payload["filesystem"]["cwd_usage"] == {
        "total_bytes": 1000,
        "used_bytes": 400,
        "free_bytes": 600,
    }
    assert payload["filesystem"]["root_usage"]["path"] == "C:\\"
    assert payload["filesystem"]["root_usage"]["total_bytes"] == 1000
    assert payload["filesystem"]["root_usage"]["used_bytes"] == 400
    assert payload["filesystem"]["root_usage"]["free_bytes"] == 600


def test_mocked_windows_status_not_collected_sections() -> None:
    not_collected = windows_status_payload(
        WINDOWS_INFO, disk_usage=fake_disk_usage, cwd=Path("C:/safe")
    )["not_collected_in_pr262"]
    for key in (
        "powershell_version",
        "execution_policy",
        "services",
        "processes",
        "event_logs",
    ):
        assert key in not_collected


def test_linux_platform_returns_deterministic_unsupported_json() -> None:
    payload = windows_status_payload(LINUX_INFO)
    expected = {
        "schema_version": 1,
        "mode": "windows_status",
        "status": "unsupported",
        "platform": {"system": "linux"},
        "reason": "Windows status is only available on Windows hosts.",
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
    payload = windows_status_payload(LINUX_INFO)
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_text_output_is_concise() -> None:
    text = render_windows_status_text(
        windows_status_payload(WINDOWS_INFO, disk_usage=fake_disk_usage, cwd=Path("C:/safe"))
    )
    assert "ShellForgeAI Windows status" in text
    assert "Status: ok" in text
    assert "Disk:" in text
    assert "Memory:" in text
    assert "Load average is not available on Windows" in text
    assert "Not collected yet:" in text
    assert "Next safe command: shellforgeai windows doctor --json" in text
    assert len(text.splitlines()) <= 12


def test_cli_windows_status_json_invokes_unsupported_on_linux(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_status.detect_platform", lambda: LINUX_INFO)
    result = CliRunner().invoke(app, ["windows", "status", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "linux"}
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_cli_windows_status_json_invokes_mocked_windows(monkeypatch) -> None:
    expected = windows_status_payload(WINDOWS_INFO, disk_usage=fake_disk_usage, cwd=Path("C:/safe"))
    monkeypatch.setattr("shellforgeai.commands.windows.windows_status_payload", lambda: expected)
    result = CliRunner().invoke(app, ["windows", "status", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["platform"]["system"] == "windows"
    assert payload["windows_v1"]["available"] is True
    assert payload["filesystem"]["cwd_usage"]["free_bytes"] == 600


def test_cli_inventory_classifies_windows_status_read_only_platform_status() -> None:
    source = Path("scripts/cli_refactor_inventory.py").read_text(encoding="utf-8")
    assert (
        '"windows status": {"module": "windows.py", "category": "read_only", "known_pr": 262}'
        in source
    )
    assert "confirm_gated_mutation" not in source.split('"windows status"', 1)[1].split("},", 1)[0]
    assert "remediation" not in source.split('"windows status"', 1)[1].split("},", 1)[0]


def test_windows_status_source_has_no_forbidden_execution_paths() -> None:
    for path in (
        Path("src/shellforgeai/windows_status.py"),
        Path("src/shellforgeai/commands/windows.py"),
    ):
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        assert "shell=true" not in lowered
        assert "subprocess" not in lowered
        assert "invoke-command" not in lowered
        assert "new-pssession" not in lowered
        assert "psremoting" not in lowered
        assert "docker" not in lowered
        assert "compose" not in lowered
        assert "codex" not in lowered
        assert "openai" not in lowered
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.keyword) and node.arg == "shell":
                assert node.value is not ast.Constant(value=True)
        assert "subprocess" not in imported
