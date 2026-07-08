"""PR279: Windows interactive slow-system diagnostics must be platform-aware.

PR278 fixed the JSON ``null`` crash, but the interactive slow-system route
still ran Linux-oriented collectors (``uptime``, ``df``, ``ip``, ``ss``,
``ps``, ``systemctl``, ``/proc`` and ``/etc/resolv.conf`` reads) on Windows
and rendered misleading values such as ``loadavg=None`` and
``0.0GiB/0.0GiB`` memory.

PR279 makes ``diagnose_target`` platform-aware for the performance/health
family: on Windows it returns bounded read-only evidence built from
structured Linux-only skip records, explicit unavailable-metric markers, and
the existing stdlib-only ``windows status``/``windows disks`` payloads. No
new collection surfaces, no shell execution, no remoting, and no mutation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.collectors import (
    LINUX_ONLY_COLLECTOR_SKIP_STATUS,
    LINUX_ONLY_PERFORMANCE_COLLECTOR_SKIPS,
    NOT_COLLECTED_ON_WINDOWS_REASON,
    WINDOWS_METRIC_UNAVAILABLE_STATUS,
    WINDOWS_PERFORMANCE_NEXT_SAFE_COMMANDS,
    _summarize,
    collect_windows_performance_evidence,
)
from shellforgeai.core.diagnose import diagnose_target
from shellforgeai.interactive.repl import (
    _deterministic_operator_summary,
    _evidence_highlights,
    _summary_for_check,
    select_followup_investigation,
)
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.tools.base import ToolResult
from shellforgeai.windows_memory import windows_memory_payload

runner = CliRunner()

ROOT = Path(__file__).resolve().parents[1]
COLLECTORS_PATH = ROOT / "src" / "shellforgeai" / "core" / "collectors.py"
DIAGNOSE_PATH = ROOT / "src" / "shellforgeai" / "core" / "diagnose.py"
REPL_PATH = ROOT / "src" / "shellforgeai" / "interactive" / "repl.py"
CHANGED_SOURCES = (COLLECTORS_PATH, DIAGNOSE_PATH, REPL_PATH)

WINDOWS_INFO = PlatformInfo(
    system="windows",
    python_platform="Windows-2025Server-10.0.26100",
    os_name="nt",
    release="2025Server",
    machine="AMD64",
)

LINUX_INFO = PlatformInfo(
    system="linux",
    python_platform="Linux-6.8",
    os_name="posix",
    release="6.8.0",
    machine="x86_64",
)

# Windows-like system.cpu_memory payload with JSON null fields (PR278 shape).
WINDOWS_CPU_MEMORY_PAYLOAD = json.dumps(
    {
        "cpus": 8,
        "effective_cpus": None,
        "loadavg": [],
        "mem_total_mb": 0.0,
        "mem_available_mb": 0.0,
        "mem_used_mb": 0.0,
        "mem_percent": None,
        "swap_total_mb": 0.0,
        "swap_used_mb": 0.0,
        "swap_percent": None,
    }
)

# Linux-only tool functions that must never be invoked on the Windows route.
LINUX_ONLY_TOOL_FUNCTIONS = [
    ("shellforgeai.tools.host", "host_uptime", "host.uptime"),
    ("shellforgeai.tools.disk", "usage", "disk.usage"),
    ("shellforgeai.tools.disk", "inodes", "disk.inodes"),
    ("shellforgeai.tools.network", "interfaces", "network.interfaces"),
    ("shellforgeai.tools.network", "default_route", "network.default_route"),
    ("shellforgeai.tools.network", "dns", "network.dns"),
    ("shellforgeai.tools.network", "listeners", "network.listeners"),
    ("shellforgeai.tools.process", "top", "process.top"),
    ("shellforgeai.tools.process", "io", "process.io"),
    ("shellforgeai.tools.system", "os_release", "system.os_release"),
    ("shellforgeai.tools.system", "cpu_memory", "system.cpu_memory"),
    ("shellforgeai.tools.system", "pressure", "system.pressure"),
    ("shellforgeai.tools.system", "cgroup_limits", "system.cgroup_limits"),
    ("shellforgeai.tools.system", "container_detect", "system.container_detect"),
    ("shellforgeai.tools.storage", "mounts", "storage.mounts"),
    ("shellforgeai.tools.systemd", "list_failed", "systemd.list_failed"),
]


class _FakeSession:
    session_id = "sf_test_pr279"
    online_enabled = False


class _FakeContext:
    session = _FakeSession()


def _fake_windows_status_payload(info: Any = None, **_: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_status",
        "status": "ok",
        "platform": {"system": "windows"},
        "host": {"hostname": "WIN2025-SFAI01", "fqdn": "WIN2025-SFAI01.local"},
        "filesystem": {
            "root_usage": {
                "path": "C:\\",
                "total_bytes": 256 * 1024**3,
                "used_bytes": 100 * 1024**3,
                "free_bytes": 156 * 1024**3,
            }
        },
        "read_only": True,
        "mutation_performed": False,
    }


def _fake_windows_disks_payload(info: Any = None, **_: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_disks",
        "status": "ok",
        "platform": {"system": "windows"},
        "summary": {"returned_roots": 2, "available_roots": 2},
        "disks": [],
        "read_only": True,
        "mutation_performed": False,
    }


def _failing_memory_source() -> dict[str, int]:
    raise OSError("memory pinned unavailable in pr279 fixture")


def _fake_windows_memory_payload_unavailable(info: Any = None, **_: Any) -> dict[str, Any]:
    return windows_memory_payload(WINDOWS_INFO, memory_source=_failing_memory_source)


@pytest.fixture
def windows_platform(monkeypatch: Any) -> list[str]:
    """Fake Windows platform detection and trap Linux-only tool execution.

    Returns the list of Linux-only tool invocations observed; it must stay
    empty for every Windows-route test.

    Memory is pinned to the deterministic unavailable fixture so the PR279-era
    unavailable-memory assertions stay true-unavailable fixtures on any host,
    including real Windows where PR287 memory enrichment would otherwise report
    real memory posture.
    """
    monkeypatch.setattr("shellforgeai.core.diagnose.detect_platform", lambda: WINDOWS_INFO)
    monkeypatch.setattr("shellforgeai.core.collectors.detect_platform", lambda: WINDOWS_INFO)
    monkeypatch.setattr(
        "shellforgeai.core.collectors.windows_status_payload",
        _fake_windows_status_payload,
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.windows_disks_payload",
        _fake_windows_disks_payload,
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.windows_memory_payload",
        _fake_windows_memory_payload_unavailable,
    )
    attempted: list[str] = []
    for module, func, label in LINUX_ONLY_TOOL_FUNCTIONS:

        def _sentinel(*args: Any, _label: str = label, **kwargs: Any) -> ToolResult:
            attempted.append(_label)
            return ToolResult(tool=_label, ok=False, exit_code=1, stderr="should not run")

        monkeypatch.setattr(f"{module}.{func}", _sentinel)
    return attempted


def _windows_diagnosis(windows_platform: list[str]):
    return diagnose_target(_FakeContext(), "performance", online=False, since="30m")


def _checks(res) -> list[dict[str, str]]:
    return [
        {
            "tool": i.source,
            "status": str(i.metadata.get("status", "ok" if i.ok else "unavailable")),
            "summary": i.summary,
        }
        for i in res.evidence.items
    ]


# ---------------------------------------------------------------------------
# Windows route: Linux-only collectors are skipped, not executed
# ---------------------------------------------------------------------------


def test_windows_performance_route_skips_linux_only_collectors(
    windows_platform: list[str],
) -> None:
    res = _windows_diagnosis(windows_platform)
    assert windows_platform == [], f"Linux-only collectors ran on Windows: {windows_platform}"
    skip_sources = {
        i.source
        for i in res.evidence.items
        if i.metadata.get("status") == LINUX_ONLY_COLLECTOR_SKIP_STATUS
    }
    assert {s for s, _, _ in LINUX_ONLY_PERFORMANCE_COLLECTOR_SKIPS} <= skip_sources


@pytest.mark.parametrize(
    "mechanism",
    ["uptime", "df", "ip", "ss", "ps", "systemctl", "/proc", "/etc/resolv.conf"],
)
def test_windows_route_does_not_attempt_linux_mechanism(
    windows_platform: list[str], mechanism: str
) -> None:
    res = _windows_diagnosis(windows_platform)
    assert windows_platform == []
    # The mechanism is documented as a structured skip instead of an attempt.
    skips = [
        i
        for i in res.evidence.items
        if i.metadata.get("status") == LINUX_ONLY_COLLECTOR_SKIP_STATUS
        and mechanism in json.loads(i.content).get("mechanism", "")
    ]
    assert skips, f"no structured skip record mentions {mechanism}"
    for item in skips:
        assert item.ok is True
        payload = json.loads(item.content)
        assert payload["status"] == LINUX_ONLY_COLLECTOR_SKIP_STATUS
        assert payload["reason"] == NOT_COLLECTED_ON_WINDOWS_REASON


def test_windows_route_emits_structured_skip_records(windows_platform: list[str]) -> None:
    res = _windows_diagnosis(windows_platform)
    skip_items = [
        i
        for i in res.evidence.items
        if i.metadata.get("status") == LINUX_ONLY_COLLECTOR_SKIP_STATUS
    ]
    assert len(skip_items) == len(LINUX_ONLY_PERFORMANCE_COLLECTOR_SKIPS)
    for item in skip_items:
        assert "Linux-only collector skipped on Windows" in item.summary
        assert item.metadata.get("platform") == "windows"


def test_windows_route_survives_json_null_collector_payload(
    windows_platform: list[str], monkeypatch: Any
) -> None:
    # Even if a Windows-shaped JSON-null payload is summarized (PR278 shape),
    # the platform-aware route must not crash or render fake values.
    summary = _summarize(ToolResult(tool="system.cpu_memory", stdout=WINDOWS_CPU_MEMORY_PAYLOAD))
    assert "cpus=8" in summary
    assert "0.0GiB/0.0GiB" not in summary
    res = _windows_diagnosis(windows_platform)
    assert res.evidence.items


# ---------------------------------------------------------------------------
# Windows summary: unavailable markers instead of fake metrics
# ---------------------------------------------------------------------------


def test_windows_summary_has_no_loadavg_none(windows_platform: list[str]) -> None:
    res = _windows_diagnosis(windows_platform)
    text = _deterministic_operator_summary("performance", _checks(res))
    assert "loadavg=None" not in text
    assert "Load average is not available on Windows" in text


def test_windows_summary_has_no_fake_zero_memory(windows_platform: list[str]) -> None:
    res = _windows_diagnosis(windows_platform)
    text = _deterministic_operator_summary("performance", _checks(res))
    assert "0.0GiB/0.0GiB" not in text
    assert "Memory summary unavailable from this collector" in text


def test_windows_summary_includes_unavailable_markers(windows_platform: list[str]) -> None:
    res = _windows_diagnosis(windows_platform)
    markers = [
        i
        for i in res.evidence.items
        if i.metadata.get("status") == WINDOWS_METRIC_UNAVAILABLE_STATUS
    ]
    assert markers, "expected explicit windows_metric_unavailable evidence markers"
    sources = {i.source for i in markers}
    assert {"host.resources", "system.cpu_memory"} <= sources


def test_windows_summary_includes_next_safe_commands(windows_platform: list[str]) -> None:
    res = _windows_diagnosis(windows_platform)
    text = _deterministic_operator_summary("performance", _checks(res))
    assert "shellforgeai windows status --json" in text
    assert "shellforgeai windows processes --json --limit 10" in text
    assert list(res.safe_next_commands) == list(WINDOWS_PERFORMANCE_NEXT_SAFE_COMMANDS)


def test_windows_summary_identifies_platform(windows_platform: list[str]) -> None:
    res = _windows_diagnosis(windows_platform)
    text = _deterministic_operator_summary("performance", _checks(res))
    assert "Windows" in text
    highlights = _evidence_highlights(_checks(res))
    assert any("Windows host detected" in line for line in highlights)
    assert any("Linux-only collectors skipped on Windows" in line for line in highlights)


def test_windows_route_is_read_only_and_non_mutating(windows_platform: list[str]) -> None:
    res = _windows_diagnosis(windows_platform)
    assert res.safety.get("read_only") is True
    assert res.safety.get("mutation_performed") is False
    for key in (
        "remediation_executed",
        "rollback_executed",
        "cleanup_executed",
        "docker_compose_executed",
        "container_restarted",
        "natural_language_execution",
        "shell_true",
        "arbitrary_command_execution",
    ):
        assert res.safety.get(key) is False


def test_windows_route_queues_no_linux_followup(windows_platform: list[str]) -> None:
    res = _windows_diagnosis(windows_platform)
    followup = select_followup_investigation(
        "performance", _checks(res), "Hey this system feels a bit slow"
    )
    assert followup is None


def test_repl_summary_for_check_does_not_render_loadavg_none() -> None:
    c = ToolResult(tool="host.resources", stdout=str({"loadavg": None}))
    summary = _summary_for_check(c)
    assert "None" not in summary
    assert "unavailable" in summary


def test_collector_summarize_host_resources_none_marker() -> None:
    r = ToolResult(tool="host.resources", stdout=str({"loadavg": None}))
    summary = _summarize(r)
    assert "None" not in summary
    assert "unavailable" in summary


def test_collector_summarize_cpu_memory_zero_total_marker() -> None:
    r = ToolResult(tool="system.cpu_memory", stdout=WINDOWS_CPU_MEMORY_PAYLOAD)
    summary = _summarize(r)
    assert "0.0GiB" not in summary
    assert "memory summary unavailable" in summary
    assert "cpus=8" in summary


# ---------------------------------------------------------------------------
# Interactive slow-system route on Windows (end-to-end, no model required)
# ---------------------------------------------------------------------------


class _UnsubstantiveProvider:
    """Provider stand-in proving the summary never depends on model output."""

    def complete(self, req: Any) -> Any:
        return type("R", (), {"text": "## Assessment"})()


class _UnavailableProvider:
    def complete(self, req: Any) -> Any:
        raise RuntimeError("model synthesis unavailable in this test")


def _run_interactive_slow(monkeypatch: Any, tmp_path: Any, provider: Any) -> Any:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", lambda *_: provider)
    return runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="Hey this system feels a bit slow\n/exit\n",
    )


def test_interactive_windows_slow_route_completes_without_model(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Any
) -> None:
    res = _run_interactive_slow(monkeypatch, tmp_path, _UnsubstantiveProvider())
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == [], f"Linux-only collectors ran: {windows_platform}"
    assert "Traceback" not in out
    assert "ValueError" not in out
    assert "malformed node or string" not in out
    assert "loadavg=None" not in out
    assert "0.0GiB/0.0GiB" not in out
    assert "read-only evidence item(s)." in out
    assert "Windows host" in out
    assert "shellforgeai windows status --json" in out
    for forbidden in [
        "remediation executed",
        "rollback executed",
        "recovery executed",
        "cleanup executed",
        "Restarting",
        "Executing command",
        "shell=True",
    ]:
        assert forbidden not in out


def test_interactive_windows_slow_route_bounded_when_model_unavailable(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Any
) -> None:
    res = _run_interactive_slow(monkeypatch, tmp_path, _UnavailableProvider())
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Traceback" not in out
    assert "model synthesis unavailable" in out
    # The deterministic Windows summary still renders without the model.
    assert "Windows host" in out
    assert "shellforgeai windows status --json" in out


# ---------------------------------------------------------------------------
# Linux/Docker behavior remains unchanged
# ---------------------------------------------------------------------------


def test_linux_performance_route_unchanged(monkeypatch: Any) -> None:
    monkeypatch.setattr("shellforgeai.core.diagnose.detect_platform", lambda: LINUX_INFO)
    calls: list[str] = []

    def _recorder(name: str):
        def _collect(*args: Any, **kwargs: Any) -> list:
            calls.append(name)
            return []

        return _collect

    for name in [
        "collect_host_evidence",
        "collect_health_evidence",
        "collect_performance_evidence",
        "collect_disk_evidence",
        "collect_network_evidence",
        "collect_local_knowledge_evidence",
        "collect_windows_performance_evidence",
    ]:
        monkeypatch.setattr(f"shellforgeai.core.diagnose.{name}", _recorder(name))
    monkeypatch.setattr(
        "shellforgeai.core.diagnose._docker_triage_context", lambda items, target: ({}, {}, [])
    )
    res = diagnose_target(_FakeContext(), "performance", online=False, since="30m")
    assert "collect_performance_evidence" in calls
    assert "collect_windows_performance_evidence" not in calls
    assert res.target == "performance"


def test_windows_collection_not_used_on_linux(monkeypatch: Any) -> None:
    monkeypatch.setattr("shellforgeai.core.diagnose.detect_platform", lambda: LINUX_INFO)
    src = DIAGNOSE_PATH.read_text(encoding="utf-8")
    assert 'platform_info.system == "windows"' in src


# ---------------------------------------------------------------------------
# Windows evidence collection unit coverage
# ---------------------------------------------------------------------------


def test_collect_windows_performance_evidence_reuses_safe_payloads(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(
        "shellforgeai.core.collectors.windows_status_payload",
        _fake_windows_status_payload,
    )
    monkeypatch.setattr(
        "shellforgeai.core.collectors.windows_disks_payload",
        _fake_windows_disks_payload,
    )
    items = collect_windows_performance_evidence(_FakeContext(), WINDOWS_INFO)
    by_source = {i.source: i for i in items}
    assert "windows.status" in by_source
    assert "windows.disks" in by_source
    assert "hostname=WIN2025-SFAI01" in by_source["windows.status"].summary
    assert "drive_roots=2" in by_source["windows.disks"].summary


def test_collect_windows_performance_evidence_degrades_without_traceback(
    monkeypatch: Any,
) -> None:
    def _boom(*args: Any, **kwargs: Any) -> dict:
        raise FileNotFoundError("C:\\ not present in this test environment")

    monkeypatch.setattr("shellforgeai.core.collectors.windows_status_payload", _boom)
    monkeypatch.setattr("shellforgeai.core.collectors.windows_disks_payload", _boom)
    items = collect_windows_performance_evidence(_FakeContext(), WINDOWS_INFO)
    by_source = {i.source: i for i in items}
    assert by_source["windows.status"].metadata["status"] == WINDOWS_METRIC_UNAVAILABLE_STATUS
    assert by_source["windows.disks"].metadata["status"] == WINDOWS_METRIC_UNAVAILABLE_STATUS


# ---------------------------------------------------------------------------
# Source safety
# ---------------------------------------------------------------------------


def test_changed_sources_have_no_eval_or_exec() -> None:
    for path in CHANGED_SOURCES:
        source = path.read_text(encoding="utf-8")
        assert "eval(" not in source.replace("literal_eval(", ""), path
        assert "exec(" not in source, path


def test_changed_sources_have_no_shell_true() -> None:
    for path in CHANGED_SOURCES:
        assert "shell=True" not in path.read_text(encoding="utf-8"), path


def test_changed_sources_add_no_powershell_or_winrm() -> None:
    for path in CHANGED_SOURCES:
        source = path.read_text(encoding="utf-8").lower()
        for banned in ["powershell", "winrm", "invoke-command", "pwsh"]:
            assert banned not in source, (path, banned)


def test_changed_sources_read_no_secrets_or_auth_cache() -> None:
    for path in CHANGED_SOURCES:
        source = path.read_text(encoding="utf-8").lower()
        for banned in ["auth.json", "auth_cache", "auth-cache", "keyring", "credential"]:
            assert banned not in source, (path, banned)
