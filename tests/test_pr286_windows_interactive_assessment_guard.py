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
    _interactive_windows_mutation_refusal,
    _is_bad_model_assessment,
)
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
BAD_PROJECT_INVARIANTS = (
    "Understood. I'll follow the ShellForgeAI project invariants and AGENTS.md "
    "guidance for any work in this repo."
)
BAD_PROJECT_INVARIANTS_UNICODE = BAD_PROJECT_INVARIANTS.replace("I'll", "I’ll")
BAD_PROJECT_INVARIANTS_MOJIBAKE = BAD_PROJECT_INVARIANTS.replace("I'll", "Iâ€™ll")
BAD_WORKSPACE_INVARIANTS = (
    "Understood. I'll treat this workspace as ShellForgeAI and preserve the "
    "AGENTS.md invariants, especially the safety boundary, CLI compatibility, "
    "evidence-first routing, and UX constraints."
)
BAD_WORKSPACE_INVARIANTS_UNICODE = BAD_WORKSPACE_INVARIANTS.replace("I'll", "I’ll")
BAD_WORKSPACE_INVARIANTS_MOJIBAKE = BAD_WORKSPACE_INVARIANTS.replace("I'll", "Iâ€™ll")
BAD_REPO_LINUX_HARNESS = (
    "Understood. I'll follow the ShellForgeAI repo invariants and treat this as "
    "a CLI-first Linux operations harness with validation-only apply, "
    "evidence-first routing, and no unsafe execution."
)
BAD_REPO_LINUX_HARNESS_UNICODE = BAD_REPO_LINUX_HARNESS.replace("I'll", "I’ll")
BAD_REPO_LINUX_HARNESS_MOJIBAKE = BAD_REPO_LINUX_HARNESS.replace("I'll", "Iâ€™ll")


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


def _failing_memory_source() -> dict[str, int]:
    raise OSError("memory pinned unavailable in pr286 fixture")


def _fake_windows_memory_payload_unavailable(info: Any = None, **_: Any) -> dict[str, Any]:
    return windows_memory_payload(WINDOWS_INFO, memory_source=_failing_memory_source)


def _pin_windows_memory_unavailable(monkeypatch: Any) -> None:
    """Pin the PR287 memory collector to a deterministic unavailable fixture.

    The unavailable-memory assertions in this file are true-unavailable
    fixtures only because of this pin; on a real Windows host the collector
    would report real memory posture and the stale blanket assertions would
    otherwise fail. Available-memory expectations live in
    tests/test_pr288_windows_memory_assertion_cleanup.py.
    """
    monkeypatch.setattr(
        "shellforgeai.core.collectors.windows_memory_payload",
        _fake_windows_memory_payload_unavailable,
    )
    monkeypatch.setattr(
        "shellforgeai.interactive.repl.windows_memory_payload",
        _fake_windows_memory_payload_unavailable,
    )


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
    _pin_windows_memory_unavailable(monkeypatch)
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


class _StreamingBadAcknowledgementProvider:
    def stream_complete(self, req: Any) -> Any:
        yield {"type": "text", "text": BAD_WORKSPACE_INVARIANTS}
        yield {"type": "final", "response": type("R", (), {"text": BAD_WORKSPACE_INVARIANTS})()}


@pytest.mark.parametrize(
    "text",
    [
        BAD_ASSESSMENT_ASCII,
        BAD_ASSESSMENT_UNICODE,
        BAD_ASSESSMENT,
        BAD_PROJECT_INVARIANTS,
        BAD_PROJECT_INVARIANTS_UNICODE,
        BAD_PROJECT_INVARIANTS_MOJIBAKE,
        BAD_WORKSPACE_INVARIANTS,
        BAD_WORKSPACE_INVARIANTS_UNICODE,
        BAD_WORKSPACE_INVARIANTS_MOJIBAKE,
        BAD_REPO_LINUX_HARNESS,
        BAD_REPO_LINUX_HARNESS_UNICODE,
        BAD_REPO_LINUX_HARNESS_MOJIBAKE,
        (
            "Understood. I’ll operate within the ShellForgeAI project constraints and "
            "preserve the safety, CLI, evidence-first routing, and UX invariants from "
            "AGENTS.md."
        ),
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
        (
            "Run sfai.cmd windows status --json, sfai.cmd windows evidence --json, "
            "and sfai.cmd windows processes --json --limit 10."
        ),
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


def test_windows_fallback_without_memory_evidence_includes_metric_limitation_markers() -> None:
    # No system.cpu_memory check at all is a true unavailable-memory fixture:
    # the summary must keep the honest unavailable marker rather than invent
    # memory values. The available-memory counterpart is covered by PR287/PR288.
    text = _deterministic_operator_summary(
        "performance",
        [{"tool": "platform.detect", "status": "ok", "summary": "Windows host detected."}],
    )
    assert "Windows metric limitations" in text
    assert "Load average is not available on Windows" in text
    assert "Memory summary unavailable from this collector on Windows" in text
    assert "Linux-only collectors skipped on Windows" in text


def test_windows_slow_path_replaces_project_instruction_acknowledgement(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows slow route must not call model provider")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
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
    assert not list(tmp_path.rglob("model-response.md"))
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
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows slow typo route must not call model provider")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="This system feels sloww\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows latency first-pass diagnosis" in out
    assert "Windows host" in out
    assert "Linux-only collectors skipped" in out
    assert "sfai.cmd windows status --json" in out
    assert "operate within the ShellForgeAI repo conventions" not in out
    assert "UX invariants" not in out


def test_windows_slow_prompt_uses_deterministic_route_without_model(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows slow route must not call model provider")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="This system feels a bit slow\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows latency first-pass diagnosis" in out
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
    assert "AGENTS.md guidance" not in out
    assert "ShellForgeAI repo conventions" not in out
    assert "ShellForgeAI project invariants" not in out
    assert "work in this repo" not in out
    assert "project constraints" not in out
    assert "existing CLI surface" not in out


def test_windows_latency_exact_prompt_routes_before_model_synthesis(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("exact Windows latency route must not call model provider")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input=(
            "I am seeing weird latency in the app. "
            "Give me a practical first-pass diagnosis.\n/exit\n"
        ),
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows latency first-pass diagnosis" in out
    assert "sfai.cmd windows status --json" in out
    assert "AGENTS.md guidance" not in out
    assert "ShellForgeAI project invariants" not in out
    assert "work in this repo" not in out


def test_windows_capture_then_gate_blocks_streamed_bad_model_output(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_EXPERIMENTAL_STREAMING", "1")
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.interactive.repl.build_provider",
        lambda *_: _StreamingBadAcknowledgementProvider(),
    )
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="High load\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Understood" not in out
    assert "AGENTS.md invariants" not in out
    assert "workspace as ShellForgeAI" not in out
    assert "Windows host" in out
    assert "sfai.cmd windows status --json" in out
    model_artifacts = list(tmp_path.rglob("model-response.md"))
    assert model_artifacts
    assert BAD_WORKSPACE_INVARIANTS in model_artifacts[0].read_text(encoding="utf-8")


def test_windows_system_status_does_not_call_model(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows status route must not call model provider")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="show me the system status\n/pending\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert "windows-local-read-only" in out
    assert "sfai.cmd windows status --json" in out
    assert "sfai.cmd windows evidence --json" in out
    assert "shellforgeai triage docker" not in out


def test_windows_mutation_refusal_is_ascii_console_safe() -> None:
    text = _interactive_windows_mutation_refusal("Clean up Windows and restart services to fix it")
    text.encode("ascii", errors="strict")
    text.encode("cp1252", errors="strict")
    assert "No command was executed" in text
    assert "No action was taken" in text
    assert "->" not in text
    assert "→" not in text


def test_ask_windows_latency_prompt_is_windows_operator_output(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows ask latency route must not call model provider")

    monkeypatch.setattr("shellforgeai.cli.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        [
            "ask",
            "I am seeing weird latency in the app. Give me a practical first-pass diagnosis.",
        ],
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows latency first-pass diagnosis" in out
    assert "Windows host" in out
    assert "Load average is not available on Windows" in out
    assert "sfai.cmd windows status --json" in out
    assert "Evidence-backed ask:" not in out
    assert "Ready. What do you want" not in out
    assert "repo invariants" not in out


def test_ask_windows_status_prompt_is_deterministic_operator_output(
    monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows ask status route must not call model provider")

    monkeypatch.setattr("shellforgeai.cli.build_provider", _fail_provider)
    res = runner.invoke(app, ["ask", "show me the windows status"])
    out = res.stdout
    assert res.exit_code == 0
    assert "Windows status" in out
    assert "windows-local-read-only" in out
    assert "Load average is not available on Windows" in out
    assert "Linux-only collectors skipped on Windows" in out
    assert "sfai.cmd windows status --json" in out
    assert "sfai.cmd windows doctor --json" in out
    assert "sfai.cmd windows evidence --json" in out
    assert "sfai.cmd windows processes --json --limit 10" in out
    assert "Provider:" not in out
    assert "Model:" not in out
    assert "Evidence-backed ask:" not in out
    assert "AGENTS.md" not in out
    assert "project constraints" not in out
    assert "repo invariants" not in out
    assert "CLI invariants" not in out
    assert "Read-only Docker triage ranking" not in out
    assert "containers_seen=0" not in out


def test_ask_windows_strongest_signal_prompt_is_windows_native(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows ask strongest-signal route must not call model provider")

    monkeypatch.setattr("shellforgeai.cli.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        [
            "ask",
            (
                "For this Windows host, what is the strongest CPU memory disk "
                "and process signal right now?"
            ),
        ],
    )
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows CPU/memory/disk/process comparison" in out
    assert "- CPU/load:" in out
    assert "- Memory:" in out
    assert "- Disk:" in out
    assert "- Process health:" in out
    assert "Strongest available signal:" in out or "No single strong signal was found" in out
    assert "Understood" not in out


def test_ask_windows_next_check_prompt_avoids_docker(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    _pin_windows_memory_unavailable(monkeypatch)

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows ask next-check route must not call model provider")

    monkeypatch.setattr("shellforgeai.cli.build_provider", _fail_provider)
    res = runner.invoke(app, ["ask", "On WIN2025-SFAI01 what should I check first?"])
    out = res.stdout
    assert res.exit_code == 0
    assert "What to check first" in out
    assert "Windows metric limitations" in out
    assert "Load average is not available on Windows" in out
    assert "Memory summary unavailable" in out
    assert "Linux-only collectors skipped on Windows" in out
    assert "sfai.cmd windows status --json" in out
    assert "No command was executed." in out
    assert "No cleanup was performed." in out
    assert "No rollback or recovery was performed." in out
    assert "Read-only Docker triage ranking" not in out
    assert "containers_seen=0" not in out
    assert "shellforgeai triage docker --json" not in out


def test_ask_windows_handoff_prompt_avoids_docker(
    windows_platform: list[str], monkeypatch: Any, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows ask handoff route must not call model provider")

    monkeypatch.setattr("shellforgeai.cli.build_provider", _fail_provider)
    res = runner.invoke(app, ["ask", "Write a concise operator handoff for this Windows host."])
    out = res.stdout
    assert res.exit_code == 0
    assert windows_platform == []
    assert "Windows host handoff" in out
    assert "WIN2025-SFAI01" in out
    assert "Docker suspects" not in out
    assert "container-visible evidence" not in out


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
    _pin_windows_memory_unavailable(monkeypatch)
    res = _run_windows_parity(
        monkeypatch,
        tmp_path,
        "What exactly should I check next if this is a Windows host?",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert "What to check first" in out
    assert "Windows metric limitations" in out
    assert "Load average is not available on Windows" in out
    assert "Memory summary unavailable" in out
    assert "Linux-only collectors skipped on Windows" in out
    assert "sfai.cmd windows status --json" in out
    assert "sfai.cmd windows doctor --json" in out
    assert "sfai.cmd windows evidence --json" in out
    assert "sfai.cmd windows services --json --limit 25" in out
    assert "No command was executed." in out
    assert "No cleanup was performed." in out
    assert "No rollback or recovery was performed." in out
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
