"""PR287: Windows local memory + disk evidence enrichment.

Windows answers should be more useful without pretending Windows has Linux
concepts. This suite covers the new read-only Windows physical-memory summary,
the enriched disk/root posture (used_percent, primary_root_free_bytes), the
explicit unavailable/not-applicable markers (load average, inodes, Linux-only
collectors), and the evidence/status/diagnose integration. Everything stays
read-only: no shell, no PowerShell, no WinRM/remoting, no mutation.
"""

from __future__ import annotations

import ast
import io
import json
import tokenize
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.collectors import collect_windows_performance_evidence
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_disks import (
    INODES_UNAVAILABLE_MARKER,
    LINUX_INODE_COLLECTORS_SKIPPED_MARKER,
    render_windows_disks_text,
    windows_disks_payload,
)
from shellforgeai.windows_evidence import windows_evidence_payload
from shellforgeai.windows_memory import (
    LOAD_AVERAGE_UNAVAILABLE_MARKER,
    MEMORY_UNAVAILABLE_MARKER,
    render_windows_memory_text,
    windows_memory_payload,
    windows_memory_summary,
)
from shellforgeai.windows_status import render_windows_status_text, windows_status_payload

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")
LINUX_INFO = PlatformInfo("linux", "Linux-test", "posix", "6.8", "x86_64")

# 16 GiB total, 6 GiB available -> 10 GiB used, 62.5% used.
FAKE_MEMORY = {
    "total_bytes": 16 * 1024**3,
    "available_bytes": 6 * 1024**3,
    "memory_load_percent": 62,
}


def fake_memory_source() -> dict[str, int]:
    return dict(FAKE_MEMORY)


def failing_memory_source() -> dict[str, int]:
    raise OSError("GlobalMemoryStatusEx failed in test")


def memory_payload_available() -> dict:
    return windows_memory_payload(WINDOWS_INFO, memory_source=fake_memory_source)


def memory_payload_unavailable() -> dict:
    return windows_memory_payload(WINDOWS_INFO, memory_source=failing_memory_source)


FAKE_ROOTS = ("C:\\", "D:\\")
FAKE_USAGE = {
    "C:\\": (500_000_000_000, 200_000_000_000, 300_000_000_000),
    "D:\\": (1_000_000_000_000, 750_000_000_000, 250_000_000_000),
}


def disks_payload() -> dict:
    return windows_disks_payload(
        WINDOWS_INFO,
        root_discovery=lambda: list(FAKE_ROOTS),
        disk_usage=lambda root: FAKE_USAGE[root],
    )


# ---------------------------------------------------------------------------
# 1. Windows memory JSON shape
# ---------------------------------------------------------------------------


def test_pr_specific_test_file_exists() -> None:
    assert Path("tests/test_pr287_windows_memory_disk_enrichment.py").exists()


def test_memory_available_json_shape() -> None:
    payload = memory_payload_available()
    assert payload["status"] == "ok"
    assert payload["mode"] == "windows_memory"
    assert payload["platform"] == {"system": "windows"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    memory = payload["memory"]
    assert memory["available"] is True
    assert memory["total_bytes"] == 16 * 1024**3
    assert memory["available_bytes"] == 6 * 1024**3
    assert memory["used_bytes"] == 10 * 1024**3
    assert memory["used_percent"] == 62.5
    assert memory["source"] == "ctypes_global_memory_status_ex"
    assert memory["limitations"] == []


def test_memory_unavailable_returns_explicit_limitation_not_crash() -> None:
    payload = memory_payload_unavailable()
    assert payload["status"] == "ok"  # fail soft
    memory = payload["memory"]
    assert memory["available"] is False
    assert memory["total_bytes"] is None
    assert memory["available_bytes"] is None
    assert memory["used_bytes"] is None
    assert memory["used_percent"] is None
    assert MEMORY_UNAVAILABLE_MARKER in memory["limitations"]
    assert MEMORY_UNAVAILABLE_MARKER in payload["limitations"]


def test_memory_load_average_marker_is_always_explicit() -> None:
    for payload in (memory_payload_available(), memory_payload_unavailable()):
        assert LOAD_AVERAGE_UNAVAILABLE_MARKER in payload["limitations"]


def test_memory_rejects_impossible_values_as_unavailable() -> None:
    def bogus() -> dict[str, int]:
        return {"total_bytes": 0, "available_bytes": 0, "memory_load_percent": 0}

    payload = windows_memory_payload(WINDOWS_INFO, memory_source=bogus)
    assert payload["memory"]["available"] is False
    assert MEMORY_UNAVAILABLE_MARKER in payload["memory"]["limitations"]


def test_memory_unsupported_on_non_windows() -> None:
    payload = windows_memory_payload(LINUX_INFO)
    assert payload["status"] == "unsupported"
    assert payload["platform"] == {"system": "linux"}
    assert payload["next_safe_command"] == "shellforgeai platform doctor --json"


def test_memory_text_render_is_concise_and_honest() -> None:
    text = render_windows_memory_text(memory_payload_available())
    assert "ShellForgeAI Windows memory" in text
    assert "Memory: memory used=62.5%" in text
    assert LOAD_AVERAGE_UNAVAILABLE_MARKER in text
    assert len(text.splitlines()) <= 10
    unavailable = render_windows_memory_text(memory_payload_unavailable())
    assert MEMORY_UNAVAILABLE_MARKER in unavailable


def test_memory_summary_helper() -> None:
    assert windows_memory_summary(memory_payload_available()).startswith("memory used=62.5%")
    assert windows_memory_summary(memory_payload_unavailable()) == MEMORY_UNAVAILABLE_MARKER


# ---------------------------------------------------------------------------
# 2. Windows disk JSON shape
# ---------------------------------------------------------------------------


def test_disk_items_have_used_percent() -> None:
    payload = disks_payload()
    assert payload["platform"] == {"system": "windows"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    c_drive = next(item for item in payload["disks"] if item["root"] == "C:\\")
    assert c_drive["total_bytes"] == 500_000_000_000
    assert c_drive["free_bytes"] == 300_000_000_000
    assert c_drive["used_bytes"] == 200_000_000_000
    assert c_drive["used_percent"] == 40.0


def test_disk_summary_has_primary_root_free_bytes() -> None:
    summary = disks_payload()["summary"]
    assert summary["primary_root_free_bytes"] == 300_000_000_000


def test_disk_inode_fields_are_explicitly_not_applicable() -> None:
    payload = disks_payload()
    # No inode values are ever reported on Windows.
    assert "inodes" not in payload
    for item in payload["disks"]:
        assert "inode" not in json.dumps(item).lower()
    assert INODES_UNAVAILABLE_MARKER in payload["limitations"]
    assert LINUX_INODE_COLLECTORS_SKIPPED_MARKER in payload["limitations"]
    assert payload["not_collected_in_pr270"]["inodes"].startswith("not applicable on Windows")


def test_disk_text_render_surfaces_free_and_inode_markers() -> None:
    text = render_windows_disks_text(disks_payload())
    assert "disk/root free space collected from Windows local read-only evidence" in text
    assert INODES_UNAVAILABLE_MARKER in text
    assert LINUX_INODE_COLLECTORS_SKIPPED_MARKER in text


# ---------------------------------------------------------------------------
# 3. Unavailable / not-applicable markers persist
# ---------------------------------------------------------------------------


def test_status_carries_memory_and_load_average_marker() -> None:
    payload = windows_status_payload(
        WINDOWS_INFO,
        disk_usage=lambda _p: (1000, 400, 600),
        cwd=Path("C:/safe"),
        memory_source=fake_memory_source,
    )
    assert payload["memory"]["available"] is True
    assert payload["memory"]["used_percent"] == 62.5
    assert LOAD_AVERAGE_UNAVAILABLE_MARKER in payload["resource_limitations"]
    text = render_windows_status_text(payload)
    assert "Memory: memory used=62.5%" in text
    assert LOAD_AVERAGE_UNAVAILABLE_MARKER in text


def test_status_memory_unavailable_is_explicit_not_crash() -> None:
    payload = windows_status_payload(
        WINDOWS_INFO,
        disk_usage=lambda _p: (1000, 400, 600),
        cwd=Path("C:/safe"),
        memory_source=failing_memory_source,
    )
    assert payload["status"] == "ok"
    assert payload["memory"]["available"] is False
    assert MEMORY_UNAVAILABLE_MARKER in payload["memory"]["limitations"]


# ---------------------------------------------------------------------------
# 4. Evidence / status / diagnose integration
# ---------------------------------------------------------------------------


class _FakeContext:
    class session:  # noqa: N801 - test stub
        session_id = "sf_test_pr287"
        online_enabled = False


def test_diagnose_windows_cpu_memory_uses_real_memory_when_available(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.collectors.windows_memory_payload",
        lambda info: memory_payload_available(),
    )
    items = collect_windows_performance_evidence(_FakeContext(), WINDOWS_INFO)
    by_source = {i.source: i for i in items}
    assert "system.cpu_memory" in by_source
    mem_item = by_source["system.cpu_memory"]
    assert mem_item.metadata["status"] == "ok"
    assert "memory used=62.5%" in mem_item.summary
    assert "0.0GiB/0.0GiB" not in mem_item.summary


def test_diagnose_windows_cpu_memory_degrades_to_marker(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.collectors.windows_memory_payload",
        lambda info: memory_payload_unavailable(),
    )
    items = collect_windows_performance_evidence(_FakeContext(), WINDOWS_INFO)
    by_source = {i.source: i for i in items}
    assert MEMORY_UNAVAILABLE_MARKER in by_source["system.cpu_memory"].summary
    # Load average stays an explicit unavailable marker regardless.
    assert "Load average is not available on Windows" in by_source["host.resources"].summary


def _windows_status_with_memory(memory_source) -> dict:
    return windows_status_payload(
        WINDOWS_INFO,
        disk_usage=lambda _p: (1000, 400, 600),
        cwd=Path("C:/safe"),
        memory_source=memory_source,
    )


def test_windows_status_json_includes_memory(monkeypatch) -> None:
    # The real payload reads disk usage from a live Windows root, so reuse the
    # existing pattern of injecting a precomputed payload into the command.
    payload = _windows_status_with_memory(fake_memory_source)
    monkeypatch.setattr("shellforgeai.commands.windows.windows_status_payload", lambda: payload)
    result = CliRunner().invoke(app, ["windows", "status", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["memory"]["available"] is True
    assert parsed["memory"]["used_percent"] == 62.5
    assert LOAD_AVERAGE_UNAVAILABLE_MARKER in parsed["resource_limitations"]


def test_windows_evidence_bundle_includes_memory_and_disk_facts() -> None:
    # Exercise the real bundle aggregation with a status component that carries
    # an explicit "unavailable" memory block (fail-soft path).
    def status_builder(info):
        return _windows_status_with_memory(failing_memory_source)

    payload = windows_evidence_payload(WINDOWS_INFO, status_builder=status_builder)
    status_component = payload["components"]["status"]
    assert "memory" in status_component
    assert status_component["memory"]["available"] is False
    assert MEMORY_UNAVAILABLE_MARKER in status_component["memory"]["limitations"]
    # The bundle also exposes the disk/root free posture via the status filesystem.
    root_usage = status_component["filesystem"]["root_usage"]
    assert root_usage["free_bytes"] == 600


def test_windows_doctor_json_stays_read_only_and_non_mutating(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_doctor.detect_platform", lambda: WINDOWS_INFO)
    result = CliRunner().invoke(app, ["windows", "doctor", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    # Doctor does not invent memory/disk facts it does not collect.
    assert "0.0GiB" not in result.stdout


# ---------------------------------------------------------------------------
# 6. Safety / source tests
# ---------------------------------------------------------------------------

MEMORY_SOURCE_PATH = Path("src/shellforgeai/windows_memory.py")
DISKS_SOURCE_PATH = Path("src/shellforgeai/windows_disks.py")


def _code_only_lower(path: Path) -> str:
    """Return module source with docstrings/comments stripped, lower-cased.

    The honest safety docstring names the techniques it refuses to use
    (PowerShell, WinRM, subprocess); scanning code tokens only avoids matching
    those negations while still catching any real execution path.
    """
    source = path.read_text(encoding="utf-8")
    kept: list[str] = []
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type in (tokenize.STRING, tokenize.COMMENT, tokenize.FSTRING_MIDDLE):
            continue
        kept.append(tok.string)
    return " ".join(kept).lower()


def test_memory_source_has_no_forbidden_execution_paths() -> None:
    code = _code_only_lower(MEMORY_SOURCE_PATH)
    for forbidden in (
        "shell=true",
        "subprocess",
        "pwsh",
        "powershell",
        "invoke-command",
        "psremoting",
        "winrm",
        "wmic",
        "os.system",
        "popen",
        "docker",
        "compose",
        "codex",
        "openai",
        "urllib",
        "httpx",
        "socket",
        "auth.json",
        "auth_cache",
        "keyring",
    ):
        assert forbidden not in code, f"windows_memory.py code contains forbidden {forbidden!r}"


def test_memory_module_imports_are_read_only_stdlib() -> None:
    tree = ast.parse(MEMORY_SOURCE_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.keyword) and node.arg == "shell":
            assert node.value != ast.Constant(value=True)
    allowed = {"__future__", "ctypes", "os", "collections", "typing", "shellforgeai"}
    assert imported <= allowed, f"unexpected imports: {imported - allowed}"
    # ctypes is used only for the documented read-only GlobalMemoryStatusEx call.
    assert "GlobalMemoryStatusEx" in MEMORY_SOURCE_PATH.read_text(encoding="utf-8")


def test_memory_module_does_not_read_process_memory_or_files() -> None:
    lowered = MEMORY_SOURCE_PATH.read_text(encoding="utf-8").lower()
    for forbidden in (
        "readprocessmemory",
        "openprocess",
        "toolhelp",
        "open(",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
    ):
        assert forbidden not in lowered, f"windows_memory.py contains {forbidden!r}"


def test_disks_enrichment_adds_no_inode_values() -> None:
    lowered = DISKS_SOURCE_PATH.read_text(encoding="utf-8").lower()
    # Inodes may be named in the not-applicable markers, but never collected.
    assert "statvfs" not in lowered
    assert "f_files" not in lowered
    assert "f_ffree" not in lowered
