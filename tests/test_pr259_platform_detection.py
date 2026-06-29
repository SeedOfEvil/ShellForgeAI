from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import (
    PlatformInfo,
    detect_platform,
    platform_doctor_payload,
    support_status,
    unsupported_platform_payload,
    windows_doctor_evidence,
)


def _patch_platform(monkeypatch, system: str) -> None:
    monkeypatch.setattr("shellforgeai.platform_detection.platform.system", lambda: system)
    monkeypatch.setattr(
        "shellforgeai.platform_detection.platform.platform", lambda **_: f"{system}-test"
    )
    monkeypatch.setattr("shellforgeai.platform_detection.platform.release", lambda: "release-test")
    monkeypatch.setattr("shellforgeai.platform_detection.platform.machine", lambda: "machine-test")
    monkeypatch.setattr("shellforgeai.platform_detection.os.name", "posix", raising=False)


def test_linux_platform_detection_returns_linux(monkeypatch) -> None:
    _patch_platform(monkeypatch, "Linux")
    assert detect_platform().system == "linux"


def test_windows_platform_detection_returns_windows(monkeypatch) -> None:
    _patch_platform(monkeypatch, "Windows")
    assert detect_platform().system == "windows"


def test_darwin_platform_detection_returns_darwin(monkeypatch) -> None:
    _patch_platform(monkeypatch, "Darwin")
    assert detect_platform().system == "darwin"


def test_unknown_platform_detection_returns_unknown(monkeypatch) -> None:
    _patch_platform(monkeypatch, "Plan9")
    assert detect_platform().system == "unknown"


def test_linux_support_status_reports_linux_docker_lane_available() -> None:
    support = support_status(PlatformInfo("linux", "Linux-test", "posix", "6", "x86_64"))
    assert support == {
        "supported": True,
        "lane": "linux_docker_v1",
        "windows_v1_available": False,
        "linux_docker_available": True,
    }


def test_windows_support_status_reports_limited_read_only_doctor_available(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.platform_detection.platform.win32_ver",
        lambda: ("2025", "26100", "", ""),
    )
    monkeypatch.setattr("shellforgeai.platform_detection.shutil.which", lambda name: None)
    payload = platform_doctor_payload(
        PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
    )
    assert payload["status"] == "limited"
    assert payload["platform"]["system"] == "windows"
    assert payload["support"]["lane"] == "windows_read_only_doctor_v1"
    assert payload["support"]["windows_v1_available"] is True
    assert payload["support"]["windows_read_only_doctor_available"] is True
    assert payload["support"]["linux_docker_available"] is False
    assert payload["windows_evidence"]["windows_build"]["value"] == "26100"
    assert "read-only doctor evidence" in payload["message"].lower()


def test_windows_output_is_read_only_and_no_mutation(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.platform_detection.platform.win32_ver",
        lambda: ("2025", "26100", "", ""),
    )
    monkeypatch.setattr("shellforgeai.platform_detection.shutil.which", lambda name: None)
    payload = platform_doctor_payload(
        PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
    )
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["windows_evidence"]["read_only"] is True
    assert payload["windows_evidence"]["mutation_performed"] is False


def test_windows_evidence_collects_narrow_deterministic_fields(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.platform_detection.platform.win32_ver",
        lambda: ("2025", "26100", "", ""),
    )
    monkeypatch.setattr(
        "shellforgeai.platform_detection.shutil.which",
        lambda name: f"C:/Program Files/{name}/{name}.exe" if name == "pwsh" else None,
    )
    evidence = windows_doctor_evidence(
        PlatformInfo("windows", "Windows-2025-test", "nt", "2025", "AMD64")
    )
    assert evidence["mode"] == "windows_read_only_doctor_evidence"
    assert evidence["platform_name"] == "Windows"
    assert evidence["os_family"] == "windows"
    assert evidence["windows_version"] == {"status": "ok", "value": "2025", "reason": None}
    assert evidence["windows_build"] == {"status": "ok", "value": "26100", "reason": None}
    assert evidence["architecture"] == {"status": "ok", "value": "AMD64", "reason": None}
    assert evidence["python_version"]["status"] == "ok"
    assert evidence["python_platform"]["value"] == "Windows-2025-test"
    assert evidence["shell_availability"]["powershell"]["available"] is False
    assert evidence["shell_availability"]["pwsh"]["available"] is True
    assert evidence["shell_availability"]["pwsh"]["version"]["status"] == "limited"


def test_windows_evidence_gracefully_reports_missing_data(monkeypatch) -> None:
    def raise_win32_ver():
        raise OSError("not available")

    monkeypatch.setattr("shellforgeai.platform_detection.platform.win32_ver", raise_win32_ver)
    monkeypatch.setattr("shellforgeai.platform_detection.shutil.which", lambda name: None)
    evidence = windows_doctor_evidence(PlatformInfo("windows", "", "nt", "", ""))
    assert evidence["windows_version"]["status"] == "limited"
    assert evidence["windows_build"]["status"] == "limited"
    assert evidence["architecture"]["status"] == "limited"
    assert evidence["python_platform"]["status"] == "limited"
    assert evidence["shell_availability"]["powershell"]["available"] is False


def test_unsupported_output_is_structured_json_compatible_and_deterministic() -> None:
    payload = unsupported_platform_payload(
        platform_system="windows",
        requested_lane="linux_docker_v1",
        reason="This command is not available on Windows yet.",
    )
    assert payload == {
        "schema_version": 1,
        "mode": "unsupported_platform",
        "status": "unsupported",
        "platform": "windows",
        "requested_lane": "linux_docker_v1",
        "supported_lanes": ["platform_doctor"],
        "read_only": True,
        "mutation_performed": False,
        "reason": "This command is not available on Windows yet.",
        "next_safe_command": "shellforgeai platform doctor --json",
    }
    assert json.loads(json.dumps(payload, sort_keys=True)) == payload


def test_unsupported_output_includes_required_fields() -> None:
    payload = unsupported_platform_payload(
        platform_system="darwin",
        requested_lane="linux_docker_v1",
        reason="Linux/Docker lane is not available on Darwin.",
    )
    for key in ("requested_lane", "platform", "reason", "next_safe_command"):
        assert payload[key]


def test_platform_doctor_json_is_strict_and_read_only(monkeypatch) -> None:
    _patch_platform(monkeypatch, "Linux")
    result = CliRunner().invoke(app, ["platform", "doctor", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["mode"] == "platform_doctor"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert set(payload) == {
        "schema_version",
        "mode",
        "status",
        "platform",
        "support",
        "read_only",
        "mutation_performed",
        "message",
        "next_safe_command",
    }


def test_platform_doctor_human_output_is_concise(monkeypatch) -> None:
    _patch_platform(monkeypatch, "Windows")
    result = CliRunner().invoke(app, ["platform", "doctor"])
    assert result.exit_code == 0
    assert "ShellForgeAI platform doctor" in result.stdout
    assert "Limited Windows read-only doctor evidence is available" in result.stdout
    assert len(result.stdout.splitlines()) <= 8


def test_platform_detector_forbidden_implementation_strings() -> None:
    source = Path("src/shellforgeai/platform_detection.py").read_text(encoding="utf-8").lower()
    assert "import subprocess" not in source
    assert "shell=true" not in source
    assert "import subprocess" not in source
    assert "shell=true" not in source
    assert "popen" not in source
    assert "check_output" not in source
    assert "new-pssession" not in source
    assert "docker(" not in source
    assert "compose " not in source
    assert "compose(" not in source
    assert "auth_cache" not in source
    assert "socket." not in source
    assert "httpx" not in source
    assert "urllib" not in source
