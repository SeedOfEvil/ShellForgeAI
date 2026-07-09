"""PR288: retire stale Windows memory-unavailable assertions after PR287.

PR287 made Windows memory genuinely available when ``GlobalMemoryStatusEx``
succeeds, so operator-facing Windows slow/status/handoff/strongest-signal
paths must no longer be forced by QA fixtures to say
"Memory summary unavailable from this collector on Windows" when memory is
actually available. This suite pins the PR287 memory collector to explicit
available/unavailable fixtures and asserts both sides of the contract
end-to-end:

* available-memory paths use or acknowledge real Windows memory posture and
  never claim memory is unavailable;
* unavailable-memory paths keep the honest unavailable marker and never
  invent memory values;
* honest Windows limitations (load average, inodes, Linux-only collector
  skips) stay explicit in both cases;
* the mutation-refusal safety behavior is unchanged.

Everything stays read-only: no shell, no PowerShell, no WinRM/remoting, no
network/model calls, no mutation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.repl import WINDOWS_MEMORY_UNAVAILABLE_MARKER
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.tools.base import ToolResult
from shellforgeai.windows_memory import windows_memory_payload

runner = CliRunner()

WINDOWS_INFO = PlatformInfo(
    system="windows",
    python_platform="Windows-2025Server-10.0.26100",
    os_name="nt",
    release="2025Server",
    machine="AMD64",
)

# 8 GiB total, 6.4 GiB available -> 1.6 GiB used, 20.0% used.
AVAILABLE_MEMORY_RAW = {
    "total_bytes": 8 * 1024**3,
    "available_bytes": int(6.4 * 1024**3),
    "memory_load_percent": 20,
}
AVAILABLE_MEMORY_SUMMARY = "memory used=20.0% available=6.4GiB/8.0GiB (Windows local read-only)"
MEMORY_COLLECTED_LINE = "Memory summary collected from Windows local read-only evidence"

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


def _fake_windows_status_payload(info: Any = None, **_: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_status",
        "status": "ok",
        "platform": {"system": "windows", "release": "2025Server"},
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


def _available_memory_source() -> dict[str, int]:
    return dict(AVAILABLE_MEMORY_RAW)


def _failing_memory_source() -> dict[str, int]:
    raise OSError("memory pinned unavailable in pr288 fixture")


def _fake_windows_memory_payload_available(info: Any = None, **_: Any) -> dict[str, Any]:
    return windows_memory_payload(WINDOWS_INFO, memory_source=_available_memory_source)


def _fake_windows_memory_payload_unavailable(info: Any = None, **_: Any) -> dict[str, Any]:
    return windows_memory_payload(WINDOWS_INFO, memory_source=_failing_memory_source)


def _pin_windows_memory(monkeypatch: Any, *, available: bool) -> None:
    fake = (
        _fake_windows_memory_payload_available
        if available
        else _fake_windows_memory_payload_unavailable
    )
    monkeypatch.setattr("shellforgeai.core.collectors.windows_memory_payload", fake)
    monkeypatch.setattr("shellforgeai.interactive.repl.windows_memory_payload", fake)


@pytest.fixture
def windows_platform(monkeypatch: Any) -> list[str]:
    """Fake Windows platform detection and trap Linux-only tool execution.

    Memory is intentionally NOT pinned here: each test pins it explicitly to
    the available or unavailable fixture so both contract sides are exercised
    deterministically on any host.
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
    attempted: list[str] = []
    for module, func, label in LINUX_ONLY_TOOL_FUNCTIONS:

        def _sentinel(*args: Any, _label: str = label, **kwargs: Any) -> ToolResult:
            attempted.append(_label)
            return ToolResult(tool=_label, ok=False, exit_code=1, stderr="should not run")

        monkeypatch.setattr(f"{module}.{func}", _sentinel)
    return attempted


def _fail_provider(*_: Any) -> Any:
    raise AssertionError("deterministic Windows route must not call model provider")


def _run_interactive(monkeypatch: Any, tmp_path: Path, prompt: str) -> Any:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")
    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    return runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input=f"{prompt}\n/exit\n",
    )


def _run_ask(monkeypatch: Any, tmp_path: Path, prompt: str) -> Any:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")
    monkeypatch.setattr("shellforgeai.cli.build_provider", _fail_provider)
    return runner.invoke(app, ["ask", prompt])


def test_pr_specific_test_file_exists() -> None:
    assert Path("tests/test_pr288_windows_memory_assertion_cleanup.py").exists()


# ---------------------------------------------------------------------------
# 1. Available-memory Windows slow guidance
# ---------------------------------------------------------------------------


def test_slow_first_pass_uses_real_memory_when_available(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_windows_memory(monkeypatch, available=True)
    res = _run_interactive(
        monkeypatch,
        tmp_path,
        "I am seeing weird latency in the app. Give me a practical first-pass diagnosis.",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows latency first-pass diagnosis" in out
    # Real Windows memory posture is used/acknowledged.
    assert AVAILABLE_MEMORY_SUMMARY in out
    assert MEMORY_COLLECTED_LINE in out
    # The stale blanket unavailable claim is gone in the available-memory path.
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER not in out
    # Honest Windows limitations remain explicit.
    assert "Load average is not available on Windows" in out
    assert "Linux-only collectors skipped on Windows" in out
    assert "sfai.cmd windows status --json" in out


# ---------------------------------------------------------------------------
# 2. Unavailable-memory Windows slow guidance
# ---------------------------------------------------------------------------


def test_slow_first_pass_stays_honest_when_memory_unavailable(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_windows_memory(monkeypatch, available=False)
    res = _run_interactive(
        monkeypatch,
        tmp_path,
        "I am seeing weird latency in the app. Give me a practical first-pass diagnosis.",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows latency first-pass diagnosis" in out
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER in out
    # No invented memory values in the unavailable path.
    assert "memory used=" not in out
    assert AVAILABLE_MEMORY_SUMMARY not in out
    assert "0.0GiB/0.0GiB" not in out
    assert "Load average is not available on Windows" in out


# ---------------------------------------------------------------------------
# 3. Strongest-signal path
# ---------------------------------------------------------------------------


def test_strongest_signal_includes_memory_when_available(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_windows_memory(monkeypatch, available=True)
    res = _run_interactive(
        monkeypatch,
        tmp_path,
        "Compare CPU, memory, disk, and process health and tell me the strongest signal.",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "## Windows CPU/memory/disk/process comparison" in out
    # Memory participates in the comparison with real posture.
    assert f"- Memory: {AVAILABLE_MEMORY_SUMMARY}" in out
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER not in out
    # Honest limitation for load average remains.
    assert "Load average unavailable on Windows" in out
    assert "Strongest available signal:" in out or "No single strong signal was found" in out


def test_strongest_signal_states_limitation_when_memory_unavailable(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_windows_memory(monkeypatch, available=False)
    res = _run_interactive(
        monkeypatch,
        tmp_path,
        "Compare CPU, memory, disk, and process health and tell me the strongest signal.",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "## Windows CPU/memory/disk/process comparison" in out
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER in out
    assert "memory used=" not in out
    assert "Load average unavailable on Windows" in out


def test_ask_strongest_signal_uses_memory_when_available(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_windows_memory(monkeypatch, available=True)
    res = _run_ask(
        monkeypatch,
        tmp_path,
        (
            "For this Windows host, what is the strongest CPU memory disk "
            "and process signal right now?"
        ),
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows CPU/memory/disk/process comparison" in out
    assert AVAILABLE_MEMORY_SUMMARY in out
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER not in out


# ---------------------------------------------------------------------------
# 4. Handoff / status path
# ---------------------------------------------------------------------------


def test_handoff_does_not_claim_memory_unavailable_when_available(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_windows_memory(monkeypatch, available=True)
    res = _run_ask(monkeypatch, tmp_path, "Write a concise operator handoff for this Windows host.")
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows host handoff" in out
    assert "WIN2025-SFAI01" in out
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER not in out


def test_handoff_keeps_unavailable_wording_when_memory_unavailable(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_windows_memory(monkeypatch, available=False)
    res = _run_ask(monkeypatch, tmp_path, "Write a concise operator handoff for this Windows host.")
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows host handoff" in out
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER in out
    assert "memory used=" not in out


def test_status_intent_uses_memory_when_available(monkeypatch: Any, tmp_path: Path) -> None:
    _pin_windows_memory(monkeypatch, available=True)
    res = _run_ask(monkeypatch, tmp_path, "show me the windows status")
    out = res.stdout
    assert res.exit_code == 0
    assert "Windows status" in out
    assert "windows-local-read-only" in out
    assert MEMORY_COLLECTED_LINE in out
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER not in out
    assert "Load average is not available on Windows" in out
    assert "Linux-only collectors skipped on Windows" in out


def test_status_intent_keeps_unavailable_wording_when_memory_unavailable(
    monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_windows_memory(monkeypatch, available=False)
    res = _run_ask(monkeypatch, tmp_path, "show me the windows status")
    out = res.stdout
    assert res.exit_code == 0
    assert "Windows status" in out
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER in out
    assert "memory used=" not in out


def test_first_check_guidance_tracks_memory_availability(monkeypatch: Any, tmp_path: Path) -> None:
    _pin_windows_memory(monkeypatch, available=True)
    res = _run_ask(monkeypatch, tmp_path, "On WIN2025-SFAI01 what should I check first?")
    out = res.stdout
    assert res.exit_code == 0
    assert "What to check first" in out
    assert MEMORY_COLLECTED_LINE in out
    assert WINDOWS_MEMORY_UNAVAILABLE_MARKER not in out
    assert "Load average is not available on Windows" in out
    assert "Linux-only collectors skipped on Windows" in out
    assert "No command was executed." in out


# ---------------------------------------------------------------------------
# 6. Safety regression: mutation prompt still refuses with memory available
# ---------------------------------------------------------------------------


def test_mutation_prompt_still_refuses_with_memory_available(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_windows_memory(monkeypatch, available=True)
    res = _run_interactive(monkeypatch, tmp_path, "Clean up Windows and restart services to fix it")
    out = res.stdout
    assert res.exit_code == 0
    assert "Refused: natural-language mutation is not allowed" in out
    assert "No command was executed" in out
    assert "No action was taken" in out
    assert "sfai.cmd windows status --json" in out
    # No cleanup/restart/remediation/rollback/recovery execution.
    for forbidden in (
        "cleanup executed",
        "remediation executed",
        "rollback executed",
        "recovery executed",
        "Executing command",
    ):
        assert forbidden not in out
    # No project/repo invariant acknowledgement or Docker framing; the refusal
    # is the answer, not provider/model metadata (the startup banner's
    # provider/model line is session metadata, not the refusal answer).
    assert "AGENTS.md" not in out
    assert "repo invariants" not in out
    assert "Understood" not in out
    assert "Read-only Docker triage ranking" not in out
    assert "containers_seen=0" not in out
