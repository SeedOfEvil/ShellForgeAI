"""PR286 Windows interactive assessment leakage guard tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.repl import (
    _contains_project_instruction_acknowledgement,
    _deterministic_operator_summary,
    _is_bad_model_assessment,
)
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.tools.base import ToolResult

runner = CliRunner()

WINDOWS_INFO = PlatformInfo(
    system="windows",
    python_platform="Windows-2025Server-10.0.26100",
    os_name="nt",
    release="2025Server",
    machine="AMD64",
)

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

_BAD_ASSESSMENT_TAIL = (
    "operate within the ShellForgeAI repo conventions and preserve the stated "
    "safety, CLI, routing, and UX invariants."
)
BAD_ASSESSMENT = f"Understood. Iâ€™ll {_BAD_ASSESSMENT_TAIL}"
BAD_ASSESSMENT_UNICODE = f"Understood. I’ll {_BAD_ASSESSMENT_TAIL}"
BAD_ASSESSMENT_ASCII = f"Understood. I'll {_BAD_ASSESSMENT_TAIL}"


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


@pytest.fixture
def windows_platform(monkeypatch: Any) -> list[str]:
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


class _BadAcknowledgementProvider:
    def complete(self, req: Any) -> Any:
        return type("R", (), {"text": BAD_ASSESSMENT})()


class _UnavailableProvider:
    def complete(self, req: Any) -> Any:
        raise RuntimeError("model unavailable in pr286 test")


@pytest.mark.parametrize(
    "text",
    [
        BAD_ASSESSMENT_ASCII,
        BAD_ASSESSMENT_UNICODE,
        BAD_ASSESSMENT,
        "Understood. I'll treat this repo as ShellForgeAI and preserve the safety, CLI surface.",
        "I will treat this workspace as ShellForgeAI and follow the AGENTS.md invariants.",
        "Understood; documentation invariants are preserved.",
        "Understood; evidence-first routing and documentation invariants are preserved.",
        "Understood. I'll operate within the ShellForgeAI workspace conventions.",
        "Understood. ShellForgeAI project conventions and UX invariants are preserved.",
        "Understood. Iâ€™ll treat this repo as ShellForgeAI and follow workspace instructions.",
        "I'm in C:\\Tools\\ShellForgeAI\\src and will follow project instructions.",
        BAD_ASSESSMENT,
    ],
)
def test_project_instruction_acknowledgement_text_is_rejected(text: str) -> None:
    assert _contains_project_instruction_acknowledgement(text)
    assert _is_bad_model_assessment(text)


@pytest.mark.parametrize(
    "text",
    [
        "Windows local read-only diagnosis completed. Safety posture: no mutation was performed.",
        "Next safe command: ShellForgeAI windows status --json for follow-up evidence.",
        "Run sfai.cmd windows status --json after reviewing this Windows evidence.",
        "Windows host evidence: load average is unavailable and Linux-only collectors skipped.",
        "Read-only evidence shows load average is unavailable on Windows.",
    ],
)
def test_legitimate_diagnostic_text_is_not_rejected(text: str) -> None:
    assert not _contains_project_instruction_acknowledgement(text)
    assert not _is_bad_model_assessment(text)


def test_deterministic_windows_fallback_has_operator_useful_content() -> None:
    checks = [
        {"tool": "platform.detect", "status": "ok", "summary": "Windows host detected."},
        {
            "tool": "host.uptime",
            "status": "linux_only_collector_skipped",
            "summary": "Linux-only collector skipped on Windows.",
        },
        {
            "tool": "host.resources",
            "status": "windows_metric_unavailable",
            "summary": "Load average is not available on Windows.",
        },
        {
            "tool": "system.cpu_memory",
            "status": "windows_metric_unavailable",
            "summary": "Memory summary unavailable from this collector on Windows.",
        },
    ]
    text = _deterministic_operator_summary("performance", checks)
    assert "Windows host" in text
    assert "Linux-only collectors skipped" in text
    assert "Load average is not available on Windows" in text
    assert "Memory summary unavailable" in text
    assert "sfai.cmd windows status --json" in text
    assert "sfai.cmd windows doctor --json" in text
    assert "sfai.cmd windows evidence --json" in text
    assert "sfai.cmd windows processes --json --limit 10" in text
    assert "AGENTS.md" not in text
    assert "treat this repo" not in text
    assert "documentation invariants" not in text


def test_windows_slow_path_replaces_project_instruction_acknowledgement(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.interactive.repl.build_provider",
        lambda *_: _BadAcknowledgementProvider(),
    )
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="This system feels a bit slow\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Traceback" not in out
    assert "Windows host" in out
    assert "sfai.cmd windows status --json" in out
    assert "sfai.cmd windows processes --json --limit 10" in out
    assert "operate within the ShellForgeAI repo conventions" not in out
    assert "UX invariants" not in out
    assert "preserve the stated safety" not in out
    assert "AGENTS.md" not in out
    assert "treat this repo" not in out
    assert "documentation invariants" not in out
    assert "system prompt" not in out.lower()
    model_artifacts = list(tmp_path.rglob("model-response.md"))
    assert model_artifacts
    assert "operate within the ShellForgeAI repo conventions" in model_artifacts[0].read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "cleanup executed",
        "remediation executed",
        "rollback executed",
        "recovery executed",
        "Executing command",
        "natural-language mutation execution",
    ):
        assert forbidden not in out


def test_windows_slow_typo_path_replaces_project_instruction_acknowledgement(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.interactive.repl.build_provider",
        lambda *_: _BadAcknowledgementProvider(),
    )
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="This system feels sloww\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Diagnose performance" in out
    assert "Windows host" in out
    assert "Linux-only collectors skipped" in out
    assert "sfai.cmd windows status --json" in out
    assert "operate within the ShellForgeAI repo conventions" not in out
    assert "UX invariants" not in out


def test_model_unavailable_still_uses_deterministic_windows_fallback(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.interactive.repl.build_provider",
        lambda *_: _UnavailableProvider(),
    )
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="This system feels a bit slow\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "model synthesis unavailable" in out or "model unavailable" in out
    assert "Windows host" in out
    assert "sfai.cmd windows status --json" in out


def test_source_safety_for_assessment_guard() -> None:
    source = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    guard_slice = source.split("def _contains_project_instruction_acknowledgement", 1)[1].split(
        "def start_interactive", 1
    )[0]
    assert "shell=True" not in guard_slice
    assert "sub" + "process" not in guard_slice
    assert "Power" + "Shell" not in guard_slice
    assert "Win" + "RM" not in guard_slice
    assert "eval(" not in guard_slice
    assert "exec(" not in guard_slice
    assert "auth" not in guard_slice.lower()
    assert "secret" not in guard_slice.lower()


def _run_windows_parity(monkeypatch: Any, tmp_path: Path, prompt: str) -> Any:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.interactive.repl.build_provider",
        lambda *_: _BadAcknowledgementProvider(),
    )
    return runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input=f"{prompt}\n/exit\n",
    )


def test_windows_latency_exact_prompt_is_operator_facing_fallback(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    res = _run_windows_parity(
        monkeypatch,
        tmp_path,
        "I am seeing weird latency in the app. Give me a practical first-pass diagnosis.",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows latency first-pass diagnosis" in out
    assert "Windows-local read-only" in out or "Windows host" in out
    assert "Load average is not available on Windows" in out
    assert "Memory summary unavailable" in out
    assert "sfai.cmd windows status --json" in out
    assert "sfai.cmd windows processes --json --limit 10" in out
    assert "AGENTS.md" not in out
    assert "ShellForgeAI repo conventions" not in out
    assert "project constraints" not in out


def test_windows_strongest_signal_prompt_compares_categories_once(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    res = _run_windows_parity(
        monkeypatch,
        tmp_path,
        "Compare CPU, memory, disk, and process health and tell me the strongest signal.",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert out.count("## Windows CPU/memory/disk/process comparison") == 1
    assert "- CPU/load:" in out
    assert "- Memory:" in out
    assert "- Disk:" in out
    assert "- Process health:" in out
    assert "Load average unavailable on Windows" in out
    assert "Memory summary unavailable" in out
    assert "Strongest available signal:" in out or "No single strong signal was found" in out
    assert out.count("## Assessment") <= 1


def test_windows_exact_next_checks_are_deterministic_without_docker_leakage(
    monkeypatch: Any, tmp_path: Path
) -> None:
    res = _run_windows_parity(
        monkeypatch,
        tmp_path,
        "What exactly should I check next if this is a Windows host?",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert "What to check first" in out
    assert "sfai.cmd windows status --json" in out
    assert "sfai.cmd windows doctor --json" in out
    assert "sfai.cmd windows evidence --json" in out
    assert "sfai.cmd windows services --json --limit 25" in out
    assert "shellforgeai triage docker" not in out
    assert "docker compose" not in out.lower()


def test_windows_handoff_prompt_is_windows_native(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    res = _run_windows_parity(
        monkeypatch,
        tmp_path,
        "Give me a concise operator handoff for the current host.",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows host handoff" in out
    assert "windows-local-read-only" in out
    assert "WIN2025-SFAI01" in out
    assert "sfai.cmd windows status --json" in out
    assert "sfai.cmd windows services --json --limit 25" in out
    assert "Docker/container" not in out
    assert "container evidence" not in out


def test_windows_mutation_exact_prompt_refuses_with_safe_alternatives(
    monkeypatch: Any, tmp_path: Path
) -> None:
    res = _run_windows_parity(
        monkeypatch,
        tmp_path,
        "Can you restart the unhealthy services and clean temp files if needed?",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert "Refused: natural-language mutation is not allowed" in out
    assert "Cleanup, restart, and service control are mutating/service-impacting" in out
    assert "No command was executed" in out
    assert "No action was taken" in out
    assert "sfai.cmd windows status --json" in out
    assert "sfai.cmd windows services --json --limit 25" in out
