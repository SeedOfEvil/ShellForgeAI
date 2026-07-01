"""PR266 Windows saved evidence packet helper tests."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import runpy
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path("scripts/windows_smoke_packet.py")


def _module() -> ModuleType:
    sys.path.insert(0, str(Path("scripts").resolve()))
    spec = importlib.util.spec_from_file_location("windows_smoke_packet_pr266", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_direct_by_path(args: list[str], monkeypatch: pytest.MonkeyPatch) -> tuple[int, str]:
    scripts_dir = str(Path("scripts").resolve())
    monkeypatch.setattr(sys, "path", [entry for entry in sys.path if entry != scripts_dir])
    sys.modules.pop("windows_smoke_acceptance", None)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), *args])
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        try:
            runpy.run_path(str(SCRIPT), run_name="__main__")
        except SystemExit as exc:
            code = int(exc.code or 0)
        else:
            code = 0
    return code, stdout.getvalue()


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


def _evidence_payload() -> dict[str, Any]:
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
        "components": {
            "doctor": _component("windows_doctor"),
            "status": _component("windows_status"),
        },
        "summary": {
            "component_count": 2,
            "ok_components": ["doctor", "status"],
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


def _write(path: Path, payload: Any, encoding: str = "utf-8") -> Path:
    text = json.dumps(payload, sort_keys=True)
    if encoding == "utf-8-bom":
        path.write_text(text, encoding="utf-8-sig")
    elif encoding == "utf-16":
        path.write_text(text, encoding="utf-16")
    else:
        path.write_text(text, encoding="utf-8")
    return path


def _paths(
    tmp_path: Path, encodings: tuple[str, str, str] = ("utf-8", "utf-8", "utf-8")
) -> tuple[Path, Path, Path]:
    evidence = _write(tmp_path / "windows-evidence.json", _evidence_payload(), encodings[0])
    status = _write(tmp_path / "windows-status.json", _component("windows_status"), encodings[1])
    doctor = _write(tmp_path / "windows-doctor.json", _component("windows_doctor"), encodings[2])
    return evidence, status, doctor


def _args(evidence: Path, status: Path, doctor: Path, *extra: str) -> list[str]:
    return [
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
        *extra,
    ]


def test_valid_artifacts_produce_json_packet_with_metadata(tmp_path: Path) -> None:
    module = _module()
    evidence, status, doctor = _paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(
            _args(evidence, status, doctor, "--json", "--pr", "266", "--commit", "abc123")
        )
    )
    assert packet["status"] == "ok"
    assert packet["pr"] == 266
    assert packet["commit"] == "abc123"
    assert packet["windows"] == {
        "host": "WIN2025-SFAI01",
        "python": "3.14.6",
        "platform_system": "windows",
    }
    for artifact in packet["artifacts"].values():
        assert len(artifact["sha256"]) == 64
        assert artifact["size_bytes"] > 0


def test_markdown_packet_has_artifact_table(tmp_path: Path) -> None:
    module = _module()
    evidence, status, doctor = _paths(tmp_path)
    packet = module.build_packet(module.parse_args(_args(evidence, status, doctor, "--markdown")))
    markdown = module.render_markdown(packet)
    assert "| Artifact | Path | SHA256 | Size bytes | Mode | Status |" in markdown
    assert "validated saved artifacts only" in markdown


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-bom", "utf-16"])
def test_single_encoding_artifacts_pass(tmp_path: Path, encoding: str) -> None:
    module = _module()
    evidence, status, doctor = _paths(tmp_path, (encoding, encoding, encoding))
    packet = module.build_packet(module.parse_args(_args(evidence, status, doctor, "--json")))
    assert packet["status"] == "ok"


def test_mixed_encodings_pass(tmp_path: Path) -> None:
    module = _module()
    evidence, status, doctor = _paths(tmp_path, ("utf-8", "utf-8-bom", "utf-16"))
    packet = module.build_packet(module.parse_args(_args(evidence, status, doctor, "--json")))
    assert packet["status"] == "ok"


def test_missing_output_mode_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    evidence, status, doctor = _paths(tmp_path)
    with pytest.raises(SystemExit):
        module.parse_args(_args(evidence, status, doctor))


def test_missing_evidence_path_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    _, status, doctor = _paths(tmp_path)
    code = module.main(_args(tmp_path / "missing.json", status, doctor, "--json"))
    assert code == 1


def test_invalid_evidence_json_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    evidence, status, doctor = _paths(tmp_path)
    evidence.write_text("{", encoding="utf-8")
    packet = module.build_packet(module.parse_args(_args(evidence, status, doctor, "--json")))
    assert packet["status"] == "failed"
    assert any(check["name"] == "evidence.json_parse" for check in packet["failed_checks"])


@pytest.mark.parametrize(
    ("where", "key", "value", "check"),
    [
        ("top", "read_only", False, "evidence.read_only"),
        ("top", "mutation_performed", True, "evidence.mutation_performed"),
        ("safety", "powershell_executed", True, "evidence.safety.powershell_executed"),
        ("safety", "winrm_used", True, "evidence.safety.winrm_used"),
        ("safety", "remote_execution", True, "evidence.safety.remote_execution"),
        ("safety", "shell_true", True, "evidence.safety.shell_true"),
        (
            "safety",
            "arbitrary_command_execution",
            True,
            "evidence.safety.arbitrary_command_execution",
        ),
        ("safety", "network_call", True, "evidence.safety.network_call"),
        ("safety", "model_called", True, "evidence.safety.model_called"),
        ("safety", "secret_read", True, "evidence.safety.secret_read"),
        ("safety", "auth_cache_read", True, "evidence.safety.auth_cache_read"),
    ],
)
def test_validator_failure_produces_failed_packet(
    tmp_path: Path, where: str, key: str, value: bool, check: str
) -> None:
    module = _module()
    payload = _evidence_payload()
    if where == "top":
        payload[key] = value
    else:
        payload[where][key] = value
    evidence = _write(tmp_path / "windows-evidence.json", payload)
    status = _write(tmp_path / "windows-status.json", _component("windows_status"))
    doctor = _write(tmp_path / "windows-doctor.json", _component("windows_doctor"))
    packet = module.build_packet(module.parse_args(_args(evidence, status, doctor, "--json")))
    assert packet["status"] == "failed"
    assert any(failed["name"] == check for failed in packet["failed_checks"])


def test_expected_host_and_python_mismatch_fail(tmp_path: Path) -> None:
    module = _module()
    evidence, status, doctor = _paths(tmp_path)
    packet = module.build_packet(
        module.parse_args(
            [
                "--evidence-json",
                str(evidence),
                "--status-json",
                str(status),
                "--doctor-json",
                str(doctor),
                "--expected-host",
                "OTHER",
                "--expected-python",
                "3.13",
                "--json",
            ]
        )
    )
    assert packet["status"] == "failed"
    names = {check["name"] for check in packet["failed_checks"]}
    assert "evidence.host.expected" in names
    assert "evidence.python_runtime.expected" in names


def test_explicit_output_files_and_default_stdout_only(tmp_path: Path) -> None:
    module = _module()
    evidence, status, doctor = _paths(tmp_path)
    out_json = tmp_path / "packet.json"
    out_md = tmp_path / "packet.md"
    assert (
        module.main(
            _args(
                evidence, status, doctor, "--out-json", str(out_json), "--out-markdown", str(out_md)
            )
        )
        == 0
    )
    assert json.loads(out_json.read_text())["status"] == "ok"
    assert "# Windows Smoke Evidence Packet" in out_md.read_text()
    before = {p.name for p in tmp_path.iterdir()}
    assert module.main(_args(evidence, status, doctor, "--json")) == 0
    assert {p.name for p in tmp_path.iterdir()} == before


def test_direct_by_path_execution_emits_json_without_scripts_on_sys_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence, status, doctor = _paths(tmp_path)
    code, stdout = _run_direct_by_path(_args(evidence, status, doctor, "--json"), monkeypatch)
    packet = json.loads(stdout)
    assert code == 0
    assert packet["status"] == "ok"
    assert packet["mode"] == "windows_smoke_packet"


def test_direct_by_path_execution_emits_markdown_without_scripts_on_sys_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence, status, doctor = _paths(tmp_path)
    code, stdout = _run_direct_by_path(_args(evidence, status, doctor, "--markdown"), monkeypatch)
    assert code == 0
    assert "# Windows Smoke Evidence Packet" in stdout
    assert "| Artifact | Path | SHA256 | Size bytes | Mode | Status |" in stdout


def test_source_safety() -> None:
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "subprocess" not in source
    assert "src.shellforgeai" not in source and "shellforgeai.commands" not in source
    assert "powershell.exe" not in source and "pwsh" not in source
    assert "winrs" not in source and "enter-pssession" not in source
