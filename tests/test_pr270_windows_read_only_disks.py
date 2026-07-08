from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_disks import (
    DEFAULT_DISKS_LIMIT,
    normalized_sorted_roots,
    render_windows_disks_text,
    validate_disks_limit,
    windows_disks_payload,
)

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")
UNKNOWN_INFO = PlatformInfo("unknown", "Mystery-test", "posix", "0", "riscv")

FAKE_ROOTS = ("D:\\", "C:\\", "E:\\")
FAKE_USAGE = {
    "C:\\": (500_000_000_000, 200_000_000_000, 300_000_000_000),
    "D:\\": (1_000_000_000_000, 750_000_000_000, 250_000_000_000),
    "E:\\": (250_000_000_000, 100_000_000_000, 150_000_000_000),
}

# 40 deterministic fake roots so the default limit of 32 can truncate.
MANY_ROOTS = tuple(f"{letter}{digit}:\\" for letter in "ABCD" for digit in "0123456789")


def fake_root_discovery() -> list[str]:
    return list(FAKE_ROOTS)


def fake_disk_usage(root: str):
    return FAKE_USAGE[root]


def flat_disk_usage(_root: str):
    return (100, 40, 60)


def disks_payload_for_mocked_windows(**kwargs):
    kwargs.setdefault("root_discovery", fake_root_discovery)
    kwargs.setdefault("disk_usage", fake_disk_usage)
    return windows_disks_payload(WINDOWS_INFO, **kwargs)


def test_pr_specific_test_file_exists() -> None:
    assert Path("tests/test_pr270_windows_read_only_disks.py").exists()


def test_mocked_windows_disks_contract() -> None:
    payload = disks_payload_for_mocked_windows()
    assert payload["status"] == "ok"
    assert payload["mode"] == "windows_disks"
    assert payload["platform"] == {"system": "windows"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["windows_v1"]["available"] is True
    assert payload["windows_v1"]["scope"] == "local_read_only_disks"
    assert payload["windows_v1"]["powershell_executed"] is False
    assert payload["windows_v1"]["winrm_used"] is False
    assert payload["windows_v1"]["remote_execution"] is False
    assert payload["next_safe_command"] == "shellforgeai windows status --json"


def test_mocked_windows_collection_block_is_stdlib_only_and_scan_free() -> None:
    collection = disks_payload_for_mocked_windows()["collection"]
    assert collection == {
        "method": "stdlib_only",
        "root_discovery": "os.listdrives_or_current_root_fallback",
        "directory_scan_performed": False,
        "file_scan_performed": False,
        "limit": DEFAULT_DISKS_LIMIT,
        "truncated": False,
    }


def test_mocked_disk_root_returns_total_used_free_bytes() -> None:
    disks = disks_payload_for_mocked_windows()["disks"]
    c_drive = next(item for item in disks if item["root"] == "C:\\")
    assert c_drive == {
        "root": "C:\\",
        "status": "ok",
        "total_bytes": 500_000_000_000,
        "used_bytes": 200_000_000_000,
        "free_bytes": 300_000_000_000,
        "used_percent": 40.0,
    }
    for item in disks:
        assert set(item) == {
            "root",
            "status",
            "total_bytes",
            "used_bytes",
            "free_bytes",
            "used_percent",
        }


def test_multiple_mocked_roots_are_sorted_deterministic() -> None:
    disks = disks_payload_for_mocked_windows()["disks"]
    assert [item["root"] for item in disks] == ["C:\\", "D:\\", "E:\\"]
    shuffled = normalized_sorted_roots(["e:\\", "C:\\", "D:\\", "C:\\", ""])
    assert shuffled == ["C:\\", "D:\\", "e:\\"]


def test_default_limit_is_32_and_truncates_many_roots() -> None:
    assert DEFAULT_DISKS_LIMIT == 32
    payload = windows_disks_payload(
        WINDOWS_INFO, root_discovery=lambda: list(MANY_ROOTS), disk_usage=flat_disk_usage
    )
    assert payload["collection"]["limit"] == 32
    assert payload["collection"]["truncated"] is True
    assert payload["summary"]["total_roots"] == 40
    assert payload["summary"]["returned_roots"] == 32
    assert [item["root"] for item in payload["disks"]] == sorted(MANY_ROOTS)[:32]


def test_limit_5_returns_5_and_sets_truncated_when_more_roots_exist() -> None:
    payload = windows_disks_payload(
        WINDOWS_INFO,
        root_discovery=lambda: list(MANY_ROOTS),
        disk_usage=flat_disk_usage,
        limit=5,
    )
    assert payload["collection"]["limit"] == 5
    assert payload["collection"]["truncated"] is True
    assert payload["summary"]["returned_roots"] == 5
    assert len(payload["disks"]) == 5
    untruncated = disks_payload_for_mocked_windows(limit=5)
    assert untruncated["collection"]["truncated"] is False
    assert untruncated["summary"]["returned_roots"] == 3


def test_invalid_limits_are_rejected() -> None:
    for invalid in (0, -1, 65, 1000):
        with pytest.raises(ValueError):
            validate_disks_limit(invalid)
    assert validate_disks_limit(1) == 1
    assert validate_disks_limit(32) == 32
    assert validate_disks_limit(64) == 64


def test_cli_invalid_limit_0_fails_cleanly() -> None:
    result = CliRunner().invoke(app, ["windows", "disks", "--json", "--limit", "0"])
    assert result.exit_code != 0
    assert result.exception is None or not isinstance(result.exception, AssertionError)
    assert "Traceback" not in result.output


def test_cli_invalid_limit_65_fails_cleanly() -> None:
    result = CliRunner().invoke(app, ["windows", "disks", "--json", "--limit", "65"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_disk_usage_failure_is_sanitized_without_traceback() -> None:
    def failing_usage(root: str):
        if root == "D:\\":
            raise PermissionError("device not ready")
        return FAKE_USAGE[root]

    payload = disks_payload_for_mocked_windows(disk_usage=failing_usage)
    assert payload["status"] == "ok"
    d_drive = next(item for item in payload["disks"] if item["root"] == "D:\\")
    assert d_drive == {"root": "D:\\", "status": "unavailable", "error": "disk_usage_failed"}
    assert "PermissionError" not in json.dumps(payload)
    assert "device not ready" not in json.dumps(payload)


def test_summary_counts_available_and_unavailable_roots() -> None:
    def failing_usage(root: str):
        if root == "D:\\":
            raise OSError("disk gone")
        return FAKE_USAGE[root]

    summary = disks_payload_for_mocked_windows(disk_usage=failing_usage)["summary"]
    assert summary == {
        "total_roots": 3,
        "returned_roots": 3,
        "available_roots": 2,
        "unavailable_roots": 1,
        # C:\ sorts first and is available, so it is the primary root here.
        "primary_root_free_bytes": 300_000_000_000,
    }


def test_root_discovery_failure_returns_structured_error_without_traceback() -> None:
    def failing_discovery() -> list[str]:
        raise OSError("drive enumeration failed")

    payload = windows_disks_payload(WINDOWS_INFO, root_discovery=failing_discovery)
    assert payload["status"] == "error"
    assert payload["mode"] == "windows_disks"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["reason"] == "root discovery failed: OSError"
    assert "disks" not in payload
    assert "drive enumeration failed" not in json.dumps(payload)


def test_mocked_windows_disks_not_collected_sections() -> None:
    not_collected = disks_payload_for_mocked_windows()["not_collected_in_pr270"]
    for key in (
        "drive_labels",
        "volume_serials",
        "bitlocker",
        "smart_health",
        "file_inventory",
    ):
        assert key in not_collected


def test_mocked_windows_disks_safety_flags() -> None:
    safety = disks_payload_for_mocked_windows()["safety"]
    for key in (
        "powershell_executed",
        "winrm_used",
        "remote_execution",
        "directory_scan_performed",
        "file_scan_performed",
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
        "mutation_performed",
    ):
        assert safety[key] is False
    assert safety["read_only"] is True


def test_linux_platform_returns_deterministic_unsupported_json() -> None:
    payload = windows_disks_payload(LINUX_INFO)
    expected = {
        "schema_version": 1,
        "mode": "windows_disks",
        "status": "unsupported",
        "platform": {"system": "linux"},
        "reason": "Windows disks preview is only available on Windows hosts.",
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
            "directory_scan_performed": False,
            "file_scan_performed": False,
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
    payload = windows_disks_payload(LINUX_INFO)
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_unknown_platform_returns_structured_unsupported() -> None:
    payload = windows_disks_payload(UNKNOWN_INFO)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "unknown"}
    assert payload["mutation_performed"] is False
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_text_output_is_concise() -> None:
    text = render_windows_disks_text(disks_payload_for_mocked_windows())
    assert "ShellForgeAI Windows disks" in text
    assert "Status: ok" in text
    assert "Roots: total=3; returned=3; available=3; unavailable=0" in text
    assert "Disk usage: free=700000000000 of total=1750000000000 bytes" in text
    assert "Collection limit: limit=32; truncated=false" in text
    assert "Not collected yet:" in text
    assert "Next safe command: shellforgeai windows status --json" in text
    assert len(text.splitlines()) <= 12


def test_unsupported_text_output_is_concise() -> None:
    text = render_windows_disks_text(windows_disks_payload(LINUX_INFO))
    assert "Status: unsupported" in text
    assert "Windows disks preview is only available on Windows hosts." in text
    assert "Next safe command: shellforgeai platform doctor --json" in text
    assert len(text.splitlines()) <= 10


def test_cli_windows_disks_json_invokes_unsupported_on_linux(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_disks.detect_platform", lambda: LINUX_INFO)
    result = CliRunner().invoke(app, ["windows", "disks", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "linux"}
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_cli_windows_disks_json_invokes_mocked_windows(monkeypatch) -> None:
    expected = disks_payload_for_mocked_windows()
    monkeypatch.setattr(
        "shellforgeai.commands.windows.windows_disks_payload",
        lambda **_kwargs: expected,
    )
    result = CliRunner().invoke(app, ["windows", "disks", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["mode"] == "windows_disks"
    assert payload["windows_v1"]["available"] is True
    assert payload["summary"]["total_roots"] == 3


def test_cli_windows_disks_limit_flag_is_passed_through(monkeypatch) -> None:
    seen: dict[str, int] = {}

    def capture(**kwargs):
        seen.update(kwargs)
        return windows_disks_payload(LINUX_INFO)

    monkeypatch.setattr("shellforgeai.commands.windows.windows_disks_payload", capture)
    result = CliRunner().invoke(app, ["windows", "disks", "--json", "--limit", "8"])
    assert result.exit_code == 0
    assert seen == {"limit": 8}


def test_cli_inventory_classifies_windows_disks_read_only() -> None:
    source = Path("scripts/cli_refactor_inventory.py").read_text(encoding="utf-8")
    assert (
        '"windows disks": {"module": "windows.py", "category": "read_only", "known_pr": 270}'
        in source
    )
    disks_entry = source.split('"windows disks"', 1)[1].split("},", 1)[0]
    assert "confirm_gated_mutation" not in disks_entry
    assert "remediation" not in disks_entry
    assert "cleanup" not in disks_entry


def test_pr270_source_has_no_forbidden_execution_paths() -> None:
    for path in (
        Path("src/shellforgeai/windows_disks.py"),
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
            "wmic",
            "diskpart",
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
            "httpx",
            "winreg",
            "wmi",
            "ctypes",
        ):
            assert banned_module not in imported, f"{path} imports {banned_module}"


def test_pr270_module_uses_stdlib_only_allowed_imports() -> None:
    source = Path("src/shellforgeai/windows_disks.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    allowed = {"__future__", "collections", "os", "pathlib", "shutil", "sys", "typing"}
    assert imported - {"shellforgeai"} <= allowed, f"unexpected imports: {imported - allowed}"
    assert "shutil" in imported
    assert "os.listdrives" in source


def test_pr270_module_does_not_scan_directories_or_files() -> None:
    source = Path("src/shellforgeai/windows_disks.py").read_text(encoding="utf-8")
    lowered = source.lower()
    for forbidden in (
        "os.walk",
        "os.scandir",
        "os.listdir(",
        "listdir(",
        "iterdir",
        "rglob",
        "glob(",
        ".open(",
        "open(",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
    ):
        assert forbidden not in lowered, f"windows_disks.py contains {forbidden!r}"
