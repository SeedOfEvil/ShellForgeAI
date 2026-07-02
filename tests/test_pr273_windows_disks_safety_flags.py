"""PR273 Windows disks safety-flag normalization tests.

PR273 is safety-schema consistency only: the standalone ``windows disks``
payload, the embedded evidence disks component, the saved-artifact validator,
and the packet helper must all agree on the explicit disk safety flags
``directory_scan_performed``, ``file_scan_performed``, and
``disk_mutation_performed``. No new collection, scanning, or mutation surface
is added.
"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_disks import (
    DEFAULT_DISKS_LIMIT,
    windows_disks_payload,
)
from shellforgeai.windows_evidence import windows_evidence_payload
from shellforgeai.windows_status import windows_status_payload

ACCEPTANCE_SCRIPT = Path("scripts/windows_smoke_acceptance.py")
PACKET_SCRIPT = Path("scripts/windows_smoke_packet.py")

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")

FAKE_ROOTS = ("C:\\", "D:\\", "E:\\")

DISK_SAFETY_FLAGS = (
    "directory_scan_performed",
    "file_scan_performed",
    "disk_mutation_performed",
)


def fake_root_discovery() -> list[str]:
    return list(FAKE_ROOTS)


def fake_disk_usage(_path: str | Path) -> tuple[int, int, int]:
    return (1000, 400, 600)


def disks_payload_for_mocked_windows(**kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("root_discovery", fake_root_discovery)
    kwargs.setdefault("disk_usage", fake_disk_usage)
    return windows_disks_payload(WINDOWS_INFO, **kwargs)


def fake_disks_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
    return windows_disks_payload(
        info, root_discovery=fake_root_discovery, disk_usage=fake_disk_usage, limit=limit
    )


def evidence_payload_for_mocked_windows(**kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("disks_builder", fake_disks_builder)
    return windows_evidence_payload(
        WINDOWS_INFO,
        status_builder=lambda info: windows_status_payload(
            info, disk_usage=fake_disk_usage, cwd=Path("C:/safe")
        ),
        **kwargs,
    )


def _load(script: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _acceptance_module() -> ModuleType:
    return _load(ACCEPTANCE_SCRIPT, "windows_smoke_acceptance_pr273")


def _packet_module() -> ModuleType:
    sys.modules.pop("windows_smoke_acceptance", None)
    return _load(PACKET_SCRIPT, "windows_smoke_packet_pr273")


def _cli_output(result) -> str:
    output = result.output
    with contextlib.suppress(ValueError):
        output += result.stderr
    return output


# ---------------------------------------------------------------------------
# Standalone disks payload: explicit disk safety flags.
# ---------------------------------------------------------------------------


def test_standalone_disks_safety_reports_directory_scan_performed_false() -> None:
    safety = disks_payload_for_mocked_windows()["safety"]
    assert safety["directory_scan_performed"] is False


def test_standalone_disks_safety_reports_file_scan_performed_false() -> None:
    safety = disks_payload_for_mocked_windows()["safety"]
    assert safety["file_scan_performed"] is False


def test_standalone_disks_safety_reports_disk_mutation_performed_false() -> None:
    safety = disks_payload_for_mocked_windows()["safety"]
    assert safety["disk_mutation_performed"] is False


def test_standalone_disks_remains_read_only_true() -> None:
    payload = disks_payload_for_mocked_windows()
    assert payload["read_only"] is True
    assert payload["safety"]["read_only"] is True


def test_standalone_disks_remains_mutation_performed_false() -> None:
    payload = disks_payload_for_mocked_windows()
    assert payload["mutation_performed"] is False
    assert payload["safety"]["mutation_performed"] is False


def test_standalone_disks_mode_is_unchanged() -> None:
    payload = disks_payload_for_mocked_windows()
    assert payload["mode"] == "windows_disks"
    assert payload["status"] == "ok"


def test_standalone_disks_error_payload_carries_disk_safety_flags() -> None:
    def failing_discovery() -> list[str]:
        raise OSError("drive enumeration failed")

    payload = windows_disks_payload(WINDOWS_INFO, root_discovery=failing_discovery)
    assert payload["status"] == "error"
    for key in DISK_SAFETY_FLAGS:
        assert payload["safety"][key] is False


# ---------------------------------------------------------------------------
# Limit behavior is unchanged by the schema normalization.
# ---------------------------------------------------------------------------


def test_standalone_disks_still_honors_default_limit() -> None:
    payload = disks_payload_for_mocked_windows()
    assert DEFAULT_DISKS_LIMIT == 32
    assert payload["collection"]["limit"] == 32
    assert payload["collection"]["truncated"] is False
    assert payload["summary"]["returned_roots"] == 3


def test_standalone_disks_still_honors_limit_1() -> None:
    payload = disks_payload_for_mocked_windows(limit=1)
    assert payload["collection"]["limit"] == 1
    assert payload["collection"]["truncated"] is True
    assert payload["summary"]["returned_roots"] == 1
    assert len(payload["disks"]) == 1
    for key in DISK_SAFETY_FLAGS:
        assert payload["safety"][key] is False


def test_cli_invalid_limit_0_still_fails_cleanly() -> None:
    result = CliRunner().invoke(app, ["windows", "disks", "--json", "--limit", "0"])
    assert result.exit_code != 0
    assert "Traceback" not in _cli_output(result)


def test_cli_invalid_limit_above_max_still_fails_cleanly() -> None:
    result = CliRunner().invoke(app, ["windows", "disks", "--json", "--limit", "65"])
    assert result.exit_code != 0
    assert "Traceback" not in _cli_output(result)


# ---------------------------------------------------------------------------
# Evidence bundle: embedded and top-level disk safety flags.
# ---------------------------------------------------------------------------


def test_embedded_disks_component_carries_all_three_disk_safety_flags() -> None:
    component = evidence_payload_for_mocked_windows(include_disks=True)["components"]["disks"]
    for key in DISK_SAFETY_FLAGS:
        assert component["safety"][key] is False


def test_top_level_evidence_safety_carries_all_three_disk_safety_flags() -> None:
    payload = evidence_payload_for_mocked_windows(include_disks=True)
    for key in DISK_SAFETY_FLAGS:
        assert payload["safety"][key] is False


def test_default_evidence_component_count_remains_two() -> None:
    payload = evidence_payload_for_mocked_windows()
    assert payload["summary"]["component_count"] == 2
    assert payload["summary"]["ok_components"] == ["doctor", "status"]


def test_default_evidence_does_not_include_disks() -> None:
    payload = evidence_payload_for_mocked_windows()
    assert "disks" not in payload["components"]
    assert "embedded_disks" not in payload


def test_include_disks_evidence_component_count_remains_three() -> None:
    payload = evidence_payload_for_mocked_windows(include_disks=True)
    assert payload["summary"]["component_count"] == 3
    assert sorted(payload["components"]) == ["disks", "doctor", "status"]


def test_include_services_and_disks_still_works_with_component_count_four() -> None:
    from shellforgeai.windows_services import RawServiceRecord, windows_services_payload

    records = (
        RawServiceRecord("wuauserv", "Windows Update", 1, 0x20),
        RawServiceRecord("Spooler", "Print Spooler", 4, 0x10),
    )

    def services_builder(info: PlatformInfo, limit: int) -> dict[str, Any]:
        return windows_services_payload(info, enumerator=lambda: list(records), max_services=limit)

    payload = evidence_payload_for_mocked_windows(
        include_services=True, include_disks=True, services_builder=services_builder
    )
    assert payload["summary"]["component_count"] == 4
    assert sorted(payload["components"]) == ["disks", "doctor", "services", "status"]
    for key in DISK_SAFETY_FLAGS:
        assert payload["safety"][key] is False
        assert payload["components"]["disks"]["safety"][key] is False


def test_embedded_and_standalone_disks_safety_blocks_agree() -> None:
    standalone = disks_payload_for_mocked_windows()
    embedded = evidence_payload_for_mocked_windows(include_disks=True)["components"]["disks"]
    assert standalone["safety"] == embedded["safety"]


# ---------------------------------------------------------------------------
# Validator: PR273 explicit disk safety flags.
# ---------------------------------------------------------------------------


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


def _disks_safe_flags() -> dict[str, bool]:
    flags = _safe_flags()
    flags["directory_scan_performed"] = False
    flags["file_scan_performed"] = False
    flags["disk_mutation_performed"] = False
    return flags


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


def _standalone_disks_payload() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_disks",
        "status": "ok",
        "platform": {"system": "windows"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_disks",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "collection": {
            "method": "stdlib_only",
            "root_discovery": "os.listdrives_or_current_root_fallback",
            "directory_scan_performed": False,
            "file_scan_performed": False,
            "limit": 32,
            "truncated": False,
        },
        "summary": {
            "total_roots": 3,
            "returned_roots": 3,
            "available_roots": 1,
            "unavailable_roots": 2,
        },
        "disks": [
            {"root": "A:\\", "status": "unavailable", "error": "disk_usage_failed"},
            {
                "root": "C:\\",
                "status": "ok",
                "total_bytes": 137438953472,
                "used_bytes": 68719476736,
                "free_bytes": 68719476736,
            },
            {"root": "D:\\", "status": "unavailable", "error": "disk_usage_failed"},
        ],
        "safety": _disks_safe_flags(),
        "next_safe_command": "shellforgeai windows status --json",
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


def _write(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _disks_result(tmp_path: Path, payload: Any) -> dict[str, Any]:
    module = _acceptance_module()
    disks = _write(tmp_path / "windows-disks.json", payload)
    return module._result(module.parse_args(["--disks-json", str(disks)]))


def test_validator_accepts_pr273_disks_artifact_with_explicit_flags(tmp_path: Path) -> None:
    result = _disks_result(tmp_path, _standalone_disks_payload())
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    for key in DISK_SAFETY_FLAGS:
        assert f"disks.safety.{key}" in names


def test_validator_fails_cleanly_when_disk_mutation_performed_true(tmp_path: Path) -> None:
    payload = _standalone_disks_payload()
    payload["safety"]["disk_mutation_performed"] = True
    result = _disks_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "disks.safety.disk_mutation_performed" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_fails_cleanly_when_directory_scan_performed_true(tmp_path: Path) -> None:
    payload = _standalone_disks_payload()
    payload["safety"]["directory_scan_performed"] = True
    result = _disks_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "disks.safety.directory_scan_performed" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_fails_cleanly_when_file_scan_performed_true(tmp_path: Path) -> None:
    payload = _standalone_disks_payload()
    payload["safety"]["file_scan_performed"] = True
    result = _disks_result(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == "disks.safety.file_scan_performed" and not check["passed"]
        for check in result["checks"]
    )


def test_validator_fails_legacy_disks_artifact_missing_disk_mutation_flag(tmp_path: Path) -> None:
    """A pre-PR273 artifact without the explicit flag fails strict validation clearly."""

    payload = _standalone_disks_payload()
    del payload["safety"]["disk_mutation_performed"]
    result = _disks_result(tmp_path, payload)
    assert result["status"] == "failed"
    failing = [
        check
        for check in result["checks"]
        if check["name"] == "disks.safety.disk_mutation_performed" and not check["passed"]
    ]
    assert failing
    assert "disk_mutation_performed" in failing[0]["reason"]


def test_validator_requires_disk_mutation_flag_on_embedded_disks(tmp_path: Path) -> None:
    module = _acceptance_module()
    evidence = _evidence_payload()
    embedded = _standalone_disks_payload()
    embedded["limit"] = 32
    embedded["returned_roots"] = 3
    embedded["total_roots"] = 3
    embedded["truncated"] = False
    evidence["components"]["disks"] = embedded
    evidence["summary"]["component_count"] = 3
    evidence["summary"]["ok_components"] = ["doctor", "status", "disks"]
    evidence["embedded_disks"] = {
        "included": True,
        "limit": 32,
        "returned_roots": 3,
        "total_roots": 3,
        "truncated": False,
    }
    evidence["safety"].update({key: False for key in DISK_SAFETY_FLAGS})
    path = _write(tmp_path / "windows-evidence.json", evidence)
    result = module._result(module.parse_args(["--evidence-json", str(path)]))
    assert result["status"] == "ok"
    names = {check["name"] for check in result["checks"]}
    assert "evidence.components.disks.safety.disk_mutation_performed" in names

    embedded["safety"]["disk_mutation_performed"] = True
    path = _write(tmp_path / "windows-evidence.json", evidence)
    result = module._result(module.parse_args(["--evidence-json", str(path)]))
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.components.disks.safety.disk_mutation_performed"
        and not check["passed"]
        for check in result["checks"]
    )


# ---------------------------------------------------------------------------
# Packet helper: disk safety summary.
# ---------------------------------------------------------------------------


def _packet_args(tmp_path: Path, disks_payload: dict[str, Any]) -> list[str]:
    evidence = _write(tmp_path / "windows-evidence.json", _evidence_payload())
    status = _write(tmp_path / "windows-status.json", _component("windows_status"))
    doctor = _write(tmp_path / "windows-doctor.json", _component("windows_doctor"))
    disks = _write(tmp_path / "windows-disks.json", disks_payload)
    return [
        "--evidence-json",
        str(evidence),
        "--status-json",
        str(status),
        "--doctor-json",
        str(doctor),
        "--disks-json",
        str(disks),
        "--expected-host",
        "WIN2025-SFAI01",
        "--expected-python",
        "3.14.6",
        "--json",
    ]


def test_packet_helper_reports_disks_artifact_disk_safety_summary(tmp_path: Path) -> None:
    module = _packet_module()
    args = module.parse_args(_packet_args(tmp_path, _standalone_disks_payload()))
    packet = module.build_packet(args)
    assert packet["status"] == "ok"
    artifact = packet["artifacts"]["disks_json"]
    assert artifact["mode"] == "windows_disks"
    assert artifact["disk_safety"] == {
        "directory_scan_performed": False,
        "file_scan_performed": False,
        "disk_mutation_performed": False,
    }
    markdown = module.render_markdown(packet)
    assert "- Directory scan performed: false" in markdown
    assert "- File scan performed: false" in markdown
    assert "- Disk mutation performed: false" in markdown


def test_packet_helper_reports_failed_validation_for_unsafe_disk_flags(tmp_path: Path) -> None:
    module = _packet_module()
    unsafe = _standalone_disks_payload()
    unsafe["safety"]["disk_mutation_performed"] = True
    args = module.parse_args(_packet_args(tmp_path, unsafe))
    packet = module.build_packet(args)
    assert packet["status"] == "failed"
    assert packet["validator"]["status"] == "failed"
    assert any(
        check["name"] == "disks.safety.disk_mutation_performed" for check in packet["failed_checks"]
    )
    assert packet["artifacts"]["disks_json"]["disk_safety"]["disk_mutation_performed"] is True


# ---------------------------------------------------------------------------
# Linux/Docker unsupported behavior stays structured.
# ---------------------------------------------------------------------------


def test_cli_linux_windows_disks_json_remains_structured_unsupported(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_disks.detect_platform", lambda: LINUX_INFO)
    result = CliRunner().invoke(app, ["windows", "disks", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["mode"] == "windows_disks"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"
    assert "Traceback" not in _cli_output(result)


def test_cli_linux_evidence_include_disks_remains_structured_unsupported(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_evidence.detect_platform", lambda: LINUX_INFO)
    monkeypatch.setattr("shellforgeai.windows_disks.detect_platform", lambda: LINUX_INFO)
    result = CliRunner().invoke(app, ["windows", "evidence", "--json", "--include-disks"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["mode"] == "windows_evidence_bundle"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert "components" not in payload
    assert "Traceback" not in _cli_output(result)


# ---------------------------------------------------------------------------
# Source safety guardrails.
# ---------------------------------------------------------------------------

_DISKS_EVIDENCE_SOURCES = (
    Path("src/shellforgeai/windows_disks.py"),
    Path("src/shellforgeai/windows_evidence.py"),
    Path("src/shellforgeai/commands/windows.py"),
)


def test_pr273_disks_evidence_path_uses_no_subprocess() -> None:
    for path in _DISKS_EVIDENCE_SOURCES:
        source = path.read_text(encoding="utf-8")
        assert "subprocess" not in source.lower(), f"{path} references subprocess"
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for banned_module in ("subprocess", "socket", "http", "urllib", "winreg", "wmi"):
            assert banned_module not in imported, f"{path} imports {banned_module}"


def test_pr273_disks_evidence_path_has_no_powershell_or_winrm_execution() -> None:
    for path in _DISKS_EVIDENCE_SOURCES:
        lowered = path.read_text(encoding="utf-8").lower()
        for forbidden in (
            "shell=true",
            "pwsh",
            "powershell.exe",
            "invoke-command",
            "new-pssession",
            "psremoting",
            "winrm ",
            "diskpart",
            "chkdsk",
            "mkfs",
            "format.com",
            "mountvol",
        ):
            assert forbidden not in lowered, f"{path} contains forbidden string {forbidden!r}"


def test_pr273_disks_evidence_path_has_no_docker_or_compose_execution() -> None:
    for path in _DISKS_EVIDENCE_SOURCES:
        lowered = path.read_text(encoding="utf-8").lower()
        for forbidden in ("docker", "compose", "codex", "openai"):
            assert forbidden not in lowered, f"{path} contains forbidden string {forbidden!r}"


def test_pr273_disks_evidence_path_performs_no_product_file_writes() -> None:
    for path in _DISKS_EVIDENCE_SOURCES:
        source = path.read_text(encoding="utf-8")
        for forbidden in ("write_text", "write_bytes", ".write(", "open(", "unlink", "rmtree"):
            assert forbidden not in source, f"{path} contains forbidden call {forbidden!r}"


# ---------------------------------------------------------------------------
# Regression suites from earlier Windows PRs remain present.
# ---------------------------------------------------------------------------


def test_prior_windows_regression_suites_still_exist() -> None:
    for name in (
        "test_pr272_windows_evidence_disks_component.py",
        "test_pr271_windows_disks_artifact_validation.py",
        "test_pr270_windows_read_only_disks.py",
        "test_pr269_windows_evidence_services_component.py",
        "test_pr268_windows_services_artifact_validation.py",
        "test_pr267_windows_read_only_services.py",
    ):
        assert Path("tests", name).exists(), f"missing regression suite {name}"
