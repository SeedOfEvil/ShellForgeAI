from __future__ import annotations

import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_doctor import windows_doctor_payload
from shellforgeai.windows_evidence import render_windows_evidence_text, windows_evidence_payload
from shellforgeai.windows_status import windows_status_payload

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")


def fake_disk_usage(_path: str | Path) -> tuple[int, int, int]:
    return (1000, 400, 600)


def evidence_payload_for_mocked_windows():
    return windows_evidence_payload(
        WINDOWS_INFO,
        status_builder=lambda info: windows_status_payload(
            info, disk_usage=fake_disk_usage, cwd=Path("C:/safe")
        ),
    )


LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")


def test_mocked_windows_evidence_bundle_contract() -> None:
    payload = evidence_payload_for_mocked_windows()
    assert payload["status"] == "ok"
    assert payload["mode"] == "windows_evidence_bundle"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["windows_v1"]["available"] is True
    assert "doctor" in payload["components"]
    assert "status" in payload["components"]
    assert payload["summary"]["component_count"] == 2
    assert payload["summary"]["ok_components"] == ["doctor", "status"]
    assert payload["summary"]["failed_components"] == []


def test_mocked_windows_evidence_safety_flags() -> None:
    safety = evidence_payload_for_mocked_windows()["safety"]
    for key in (
        "powershell_executed",
        "winrm_used",
        "remote_execution",
        "shell_true",
        "arbitrary_command_execution",
        "network_call",
        "model_called",
        "secret_read",
        "auth_cache_read",
        "service_restart_executed",
        "process_termination_executed",
        "registry_modified",
        "execution_policy_modified",
    ):
        assert safety[key] is False


def test_mocked_windows_evidence_not_collected_sections() -> None:
    not_collected = evidence_payload_for_mocked_windows()["not_collected_in_pr264"]
    for key in (
        "powershell_version",
        "execution_policy",
        "services",
        "processes",
        "event_logs",
    ):
        assert key in not_collected


def test_reuses_existing_doctor_and_status_payload_builders() -> None:
    doctor = windows_doctor_payload(WINDOWS_INFO)
    status = windows_status_payload(WINDOWS_INFO, disk_usage=fake_disk_usage, cwd=Path("C:/safe"))
    payload = windows_evidence_payload(
        WINDOWS_INFO,
        doctor_builder=lambda _info: doctor,
        status_builder=lambda _info: status,
    )
    assert payload["components"]["doctor"] is doctor
    assert payload["components"]["status"] is status


def test_linux_platform_returns_deterministic_unsupported_json() -> None:
    payload = windows_evidence_payload(LINUX_INFO)
    expected = {
        "schema_version": 1,
        "mode": "windows_evidence_bundle",
        "status": "unsupported",
        "platform": {"system": "linux"},
        "reason": "Windows evidence bundle is only available on Windows hosts.",
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


def test_text_output_is_concise() -> None:
    text = render_windows_evidence_text(evidence_payload_for_mocked_windows())
    assert "ShellForgeAI Windows evidence bundle" in text
    assert "Status: ok" in text
    assert "Components included: doctor, status" in text
    assert "Not collected yet:" in text
    assert "Next safe command: shellforgeai windows status --json" in text
    assert len(text.splitlines()) <= 11


def test_cli_windows_evidence_json_invokes_mocked_windows(monkeypatch) -> None:
    expected = evidence_payload_for_mocked_windows()
    monkeypatch.setattr("shellforgeai.commands.windows.windows_evidence_payload", lambda: expected)
    result = CliRunner().invoke(app, ["windows", "evidence", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["mode"] == "windows_evidence_bundle"
    assert payload["windows_v1"]["available"] is True


def test_component_failure_is_surfaced_honestly() -> None:
    payload = windows_evidence_payload(
        WINDOWS_INFO,
        doctor_builder=lambda _info: {"mode": "windows_doctor", "status": "unsupported"},
        status_builder=lambda _info: {"mode": "windows_status", "status": "ok"},
    )
    assert payload["status"] == "component_failure"
    assert payload["summary"]["ok_components"] == ["status"]
    assert payload["summary"]["failed_components"] == ["doctor"]


def test_cli_inventory_classifies_windows_evidence_read_only_platform_status() -> None:
    source = Path("scripts/cli_refactor_inventory.py").read_text(encoding="utf-8")
    assert (
        '"windows evidence": {"module": "windows.py", "category": "read_only", "known_pr": 264}'
        in source
    )
    assert (
        "confirm_gated_mutation" not in source.split('"windows evidence"', 1)[1].split("},", 1)[0]
    )
    assert "remediation" not in source.split('"windows evidence"', 1)[1].split("},", 1)[0]


def test_pr264_command_source_has_no_forbidden_execution_paths() -> None:
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
            "invoke-command",
            "new-pssession",
            "psremoting",
            "winrm ",
            "docker",
            "compose",
            "codex",
            "openai",
            "secret_read = true",
            "auth_cache_read = true",
        ):
            assert forbidden not in lowered
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
