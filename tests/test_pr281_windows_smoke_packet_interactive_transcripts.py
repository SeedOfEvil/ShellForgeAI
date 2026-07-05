"""PR281 Windows smoke packet interactive transcript integration tests."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path("scripts/windows_smoke_packet.py")


def _module() -> ModuleType:
    scripts_dir = str(Path("scripts").resolve())
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location("windows_smoke_packet_pr281", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
        "host": {"hostname": "WIN2025-SFAI01"},
        "python_runtime": {"executable": "python.exe", "version": "3.14.6"},
        "filesystem": {"collection": "stdlib_only"},
        "safety": _safe_flags(),
    }


def _evidence_payload() -> dict[str, Any]:
    return {
        **_component("windows_evidence_bundle"),
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_evidence_bundle",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
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
    }


def _slow_text() -> str:
    return """
Windows host detected: WIN2025Server
Diagnose performance summary (read-only).
Load average is not available on Windows; Linux-only collectors skipped on Windows.
Memory summary unavailable: not_collected_on_windows.
Safe read-only alternatives include shellforgeai windows status --json.
"""


def _mutation_text() -> str:
    return """
Refused: natural-language mutation is not allowed.
This is read-only and requires explicit confirmation.
No command was executed.
No cleanup was executed.
"""


def _write_json(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _write_text(path: Path, text: str, encoding: str = "utf-8") -> Path:
    path.write_text(text, encoding=encoding)
    return path


def _base_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    return (
        _write_json(tmp_path / "windows-evidence.json", _evidence_payload()),
        _write_json(tmp_path / "windows-status.json", _component("windows_status")),
        _write_json(tmp_path / "windows-doctor.json", _component("windows_doctor")),
    )


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


def _packet(tmp_path: Path, *extra: str) -> dict[str, Any]:
    module = _module()
    evidence, status, doctor = _base_paths(tmp_path)
    return module.build_packet(module.parse_args(_args(evidence, status, doctor, "--json", *extra)))


def test_json_only_packet_behavior_still_passes_without_transcripts(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    assert packet["status"] == "ok"
    assert "interactive" not in packet
    assert "slow_transcript" not in packet["artifacts"]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16"])
def test_packet_with_valid_transcripts_json_status_ok_and_hashes(
    tmp_path: Path, encoding: str
) -> None:
    slow = _write_text(tmp_path / "interactive-slow.txt", _slow_text(), encoding)
    mutation = _write_text(
        tmp_path / "interactive-mutation-refusal.txt", _mutation_text(), encoding
    )
    packet = _packet(
        tmp_path,
        "--slow-transcript",
        str(slow),
        "--mutation-transcript",
        str(mutation),
    )
    assert packet["status"] == "ok"
    assert packet["interactive"]["status"] == "ok"
    assert packet["interactive"]["summary"]["failed"] == 0
    assert (
        packet["artifacts"]["slow_transcript"]["sha256"]
        == hashlib.sha256(slow.read_bytes()).hexdigest()
    )
    assert (
        packet["artifacts"]["mutation_transcript"]["sha256"]
        == hashlib.sha256(mutation.read_bytes()).hexdigest()
    )
    assert packet["artifacts"]["slow_transcript"]["size_bytes"] > 0
    assert packet["artifacts"]["mutation_transcript"]["accepted"] is True


def test_packet_with_valid_transcripts_markdown_status_ok_and_hashes(tmp_path: Path) -> None:
    module = _module()
    slow = _write_text(tmp_path / "interactive-slow.txt", _slow_text())
    mutation = _write_text(tmp_path / "interactive-mutation-refusal.txt", _mutation_text())
    packet = _packet(
        tmp_path, "--slow-transcript", str(slow), "--mutation-transcript", str(mutation)
    )
    markdown = module.render_markdown(packet)
    assert "Packet status: **ok**" in markdown
    assert "## Interactive transcript summary" in markdown
    assert hashlib.sha256(slow.read_bytes()).hexdigest() in markdown
    assert hashlib.sha256(mutation.read_bytes()).hexdigest() in markdown
    assert "Acceptance summary:" in markdown


def test_partial_transcript_arguments_fail_cleanly(tmp_path: Path) -> None:
    module = _module()
    evidence, status, doctor = _base_paths(tmp_path)
    slow = _write_text(tmp_path / "interactive-slow.txt", _slow_text())
    with pytest.raises(SystemExit):
        module.parse_args(_args(evidence, status, doctor, "--json", "--slow-transcript", str(slow)))
    with pytest.raises(SystemExit):
        module.parse_args(
            _args(evidence, status, doctor, "--json", "--mutation-transcript", str(slow))
        )


@pytest.mark.parametrize(
    ("missing_name", "expected_check"),
    [("slow", "slow.file_exists"), ("mutation", "mutation.file_exists")],
)
def test_missing_transcript_path_fails_cleanly(
    tmp_path: Path, missing_name: str, expected_check: str
) -> None:
    slow = tmp_path / "missing-slow.txt"
    mutation = tmp_path / "missing-mutation.txt"
    if missing_name != "slow":
        slow = _write_text(tmp_path / "interactive-slow.txt", _slow_text())
    if missing_name != "mutation":
        mutation = _write_text(tmp_path / "interactive-mutation-refusal.txt", _mutation_text())
    packet = _packet(
        tmp_path, "--slow-transcript", str(slow), "--mutation-transcript", str(mutation)
    )
    assert packet["status"] == "failed"
    assert packet["interactive"]["status"] == "failed"
    assert any(check["name"] == expected_check for check in packet["failed_checks"])


@pytest.mark.parametrize(
    ("slow_text", "mutation_text", "expected_check"),
    [
        ("Traceback\n" + _slow_text(), _mutation_text(), "slow.no_traceback"),
        (_slow_text(), "cleanup executed\n" + _mutation_text(), "mutation.no_cleanup_executed"),
        ("not enough markers", _mutation_text(), "slow.windows_aware_marker"),
        (_slow_text(), "command was executed", "mutation.no_shell_command_execution_executed"),
    ],
)
def test_invalid_transcript_causes_failed_packet_and_nonzero_exit(
    tmp_path: Path, slow_text: str, mutation_text: str, expected_check: str
) -> None:
    module = _module()
    evidence, status, doctor = _base_paths(tmp_path)
    slow = _write_text(tmp_path / "interactive-slow.txt", slow_text)
    mutation = _write_text(tmp_path / "interactive-mutation-refusal.txt", mutation_text)
    args = _args(
        evidence,
        status,
        doctor,
        "--json",
        "--slow-transcript",
        str(slow),
        "--mutation-transcript",
        str(mutation),
    )
    packet = module.build_packet(module.parse_args(args))
    assert packet["status"] == "failed"
    assert module.main(args) == 1
    assert any(check["name"] == expected_check for check in packet["failed_checks"])


def test_mutation_transcript_with_no_command_was_executed_passes(tmp_path: Path) -> None:
    mutation = "Refused: read-only and not allowed. No command was executed."
    packet = _packet(
        tmp_path,
        "--slow-transcript",
        str(_write_text(tmp_path / "interactive-slow.txt", _slow_text())),
        "--mutation-transcript",
        str(_write_text(tmp_path / "interactive-mutation-refusal.txt", mutation)),
    )
    assert packet["status"] == "ok"


def test_explicit_outputs_write_files_and_stdout_only_writes_no_files(tmp_path: Path) -> None:
    module = _module()
    evidence, status, doctor = _base_paths(tmp_path)
    slow = _write_text(tmp_path / "interactive-slow.txt", _slow_text())
    mutation = _write_text(tmp_path / "interactive-mutation-refusal.txt", _mutation_text())
    out_json = tmp_path / "packet.json"
    out_markdown = tmp_path / "packet.md"
    args = _args(
        evidence,
        status,
        doctor,
        "--slow-transcript",
        str(slow),
        "--mutation-transcript",
        str(mutation),
        "--out-json",
        str(out_json),
        "--out-markdown",
        str(out_markdown),
    )
    assert module.main(args) == 0
    assert json.loads(out_json.read_text(encoding="utf-8"))["status"] == "ok"
    assert "Interactive transcript summary" in out_markdown.read_text(encoding="utf-8")
    before = {path.name for path in tmp_path.iterdir()}
    assert module.main(_args(evidence, status, doctor, "--json")) == 0
    assert {path.name for path in tmp_path.iterdir()} == before


def test_source_safety_for_packet_helper() -> None:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    imported_names = {
        alias.name
        for node in imports
        for alias in (node.names if isinstance(node, ast.Import) else [])
    }
    assert "subprocess" not in imported_names
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "src.shellforgeai" not in source and "shellforgeai.commands" not in source
    assert "powershell.exe" not in source and "pwsh" not in source
    assert "winrm(" not in source and "winrs" not in source and "enter-pssession" not in source
    assert "eval(" not in source and "exec(" not in source
