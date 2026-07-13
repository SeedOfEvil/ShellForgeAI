from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_memory import windows_memory_payload

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")


def _raw(total: int = 32 * 1024**3, available: int = 24 * 1024**3) -> dict[str, int]:
    return {"total_bytes": total, "available_bytes": available, "memory_load_percent": 25}


def test_pr_specific_test_file_exists() -> None:
    assert Path("tests/test_pr294_windows_memory_command.py").exists()


def test_windows_memory_cli_help_registered() -> None:
    result = CliRunner().invoke(app, ["windows", "--help"])
    assert result.exit_code == 0
    assert "memory" in result.stdout
    assert "disks" in result.stdout
    assert "processes" in result.stdout
    assert "services" in result.stdout


def test_windows_memory_json_success_uses_existing_collector(monkeypatch) -> None:
    calls = {"count": 0}

    def fake_detect() -> PlatformInfo:
        return WINDOWS_INFO

    def fake_source() -> dict[str, int]:
        calls["count"] += 1
        return _raw()

    monkeypatch.setattr("shellforgeai.windows_memory.detect_platform", fake_detect)
    monkeypatch.setattr("shellforgeai.windows_memory._read_global_memory_status", fake_source)
    result = CliRunner().invoke(app, ["windows", "memory", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert calls["count"] == 1
    assert payload["mode"] == "windows_memory"
    assert payload["status"] == "ok"
    assert payload["platform"] == {"system": "windows"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    memory = payload["memory"]
    assert memory["available"] is True
    assert isinstance(memory["total_bytes"], int)
    assert isinstance(memory["used_bytes"], int)
    assert isinstance(memory["available_bytes"], int)
    assert isinstance(memory["used_percent"], float)
    assert memory["total_bytes"] >= memory["available_bytes"] >= 0
    assert memory["total_bytes"] >= memory["used_bytes"] >= 0
    assert 0 <= memory["used_percent"] <= 100


def test_windows_memory_text_success_is_concise_and_non_mutating(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_memory.detect_platform", lambda: WINDOWS_INFO)
    monkeypatch.setattr("shellforgeai.windows_memory._read_global_memory_status", _raw)
    result = CliRunner().invoke(app, ["windows", "memory"])
    assert result.exit_code == 0
    out = result.stdout
    assert "Windows memory" in out
    assert "Total:" in out
    assert "Used:" in out
    assert "Available:" in out
    assert "Used percent:" in out
    assert "Read-only: true" in out
    assert '"memory"' not in out
    forbidden = ("cleanup", "optimization", "repair", "remediation", "leak detection")
    assert not any(term in out.lower() for term in forbidden)


def test_windows_memory_partial_source_failure_has_bounded_json(monkeypatch) -> None:
    def failing_source() -> dict[str, int]:
        raise OSError("denied")

    monkeypatch.setattr("shellforgeai.windows_memory.detect_platform", lambda: WINDOWS_INFO)
    monkeypatch.setattr("shellforgeai.windows_memory._read_global_memory_status", failing_source)
    result = CliRunner().invoke(app, ["windows", "memory", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["mutation_performed"] is False
    assert payload["memory"]["available"] is False
    assert payload["memory"]["total_bytes"] is None
    assert payload["memory"]["used_bytes"] is None
    assert "Traceback" not in result.stdout


def test_windows_memory_unsupported_platform_does_not_call_collector(monkeypatch) -> None:
    def forbidden_source() -> dict[str, int]:
        raise AssertionError("collector must not run on non-Windows")

    monkeypatch.setattr("shellforgeai.windows_memory.detect_platform", lambda: LINUX_INFO)
    monkeypatch.setattr("shellforgeai.windows_memory._read_global_memory_status", forbidden_source)
    result = CliRunner().invoke(app, ["windows", "memory", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "linux"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert "memory" not in payload


def test_windows_memory_value_sanity_edges() -> None:
    ok = windows_memory_payload(WINDOWS_INFO, memory_source=lambda: _raw(total=100, available=0))
    assert ok["memory"]["used_bytes"] == 100
    assert ok["memory"]["used_percent"] == 100.0
    zero = windows_memory_payload(WINDOWS_INFO, memory_source=lambda: _raw(total=0, available=0))
    assert zero["memory"]["available"] is False
    contradictory = windows_memory_payload(
        WINDOWS_INFO, memory_source=lambda: _raw(total=100, available=101)
    )
    assert contradictory["memory"]["available"] is False


def test_windows_memory_json_deterministic(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_memory.detect_platform", lambda: WINDOWS_INFO)
    monkeypatch.setattr("shellforgeai.windows_memory._read_global_memory_status", _raw)
    runner = CliRunner()
    first = runner.invoke(app, ["windows", "memory", "--json"])
    second = runner.invoke(app, ["windows", "memory", "--json"])
    assert first.exit_code == second.exit_code == 0
    assert json.loads(first.stdout) == json.loads(second.stdout)
