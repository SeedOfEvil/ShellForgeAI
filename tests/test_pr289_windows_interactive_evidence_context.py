"""PR289: Windows interactive evidence-context parity with Linux.

After PR288, Windows collectors and safety gates were clean, but fallthrough
interactive/model questions on Windows (for example "What is running on this
system?") reached the model with no host evidence and could leak
project/policy preamble ("Understood. I'll operate within the ShellForgeAI
invariants...") to operator stdout.

This suite pins the PR289 contract:

* the shared Windows evidence-context builder assembles a bounded read-only
  packet (host, platform, memory, disk, processes, services, limitations)
  from the existing Windows collectors, failing soft per component;
* interactive/ask model calls on Windows carry that packet in the prompt so
  the model answers from actual host evidence, without phrase-keyed canned
  handlers;
* model output is captured and gated before stdout: project/policy preamble,
  AGENTS.md leakage, provider-metadata-primary answers, and Docker/container
  primary framing are replaced by an evidence-grounded Windows answer;
* thin evidence is stated honestly with the safe read-only commands that fill
  the gap, and no processes/services/metrics are invented;
* mutation requests remain refused with no command execution.

Everything stays read-only: no shell, no PowerShell, no WinRM/remoting, no
network/model calls, no mutation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.windows_evidence_context import (
    build_windows_evidence_context,
    is_rejected_windows_model_answer,
    render_windows_evidence_answer,
    windows_evidence_prompt_facts,
)
from shellforgeai.platform_detection import PlatformInfo
from shellforgeai.windows_memory import windows_memory_payload

runner = CliRunner()

WINDOWS_INFO = PlatformInfo(
    system="windows",
    python_platform="Windows-2025Server-10.0.26100",
    os_name="nt",
    release="2025Server",
    machine="AMD64",
)

# 8 GiB total, 6.4 GiB available -> 1.6 GiB used, 20.0% used (matches the
# WIN2025-SFAI01 posture SeedOfEvil observed).
AVAILABLE_MEMORY_RAW = {
    "total_bytes": 8 * 1024**3,
    "available_bytes": int(6.4 * 1024**3),
}

OBSERVED_BAD_PREAMBLE = (
    "Understood. I’ll operate within the ShellForgeAI invariants: read-only "
    "evidence first, no arbitrary/destructive execution, preserve CLI "
    "behavior, and keep user-facing UX/docs consistent."
)

GOOD_EVIDENCE_ANSWER = (
    "On this Windows host the read-only evidence packet shows 182 visible "
    "processes (bounded preview of 10, including System and svchost.exe) and "
    "98 services with 61 running. Process/service evidence is read-only. "
    "For more detail run sfai.cmd windows processes --json --limit 10 or "
    "sfai.cmd windows services --json."
)


def _available_memory_source() -> dict[str, int]:
    return dict(AVAILABLE_MEMORY_RAW)


def _failing_memory_source() -> dict[str, int]:
    raise OSError("memory pinned unavailable in pr289 fixture")


def _fake_status_payload(info: Any = None, **_: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_status",
        "status": "ok",
        "platform": {"system": "windows", "release": "2025Server"},
        "host": {"hostname": "WIN2025-SFAI01", "fqdn": "WIN2025-SFAI01.local"},
        "python_runtime": {"version": "3.14.0", "implementation": "CPython"},
        "filesystem": {
            "root_usage": {
                "path": "C:\\",
                "total_bytes": 256 * 1024**3,
                "used_bytes": 100 * 1024**3,
                "free_bytes": 156 * 1024**3,
            }
        },
        "memory": (
            windows_memory_payload(WINDOWS_INFO, memory_source=_available_memory_source)["memory"]
        ),
        "read_only": True,
        "mutation_performed": False,
    }


def _fake_memory_payload(info: Any = None, **_: Any) -> dict[str, Any]:
    return windows_memory_payload(WINDOWS_INFO, memory_source=_available_memory_source)


def _fake_memory_payload_unavailable(info: Any = None, **_: Any) -> dict[str, Any]:
    return windows_memory_payload(WINDOWS_INFO, memory_source=_failing_memory_source)


def _fake_disks_payload(info: Any = None, **_: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_disks",
        "status": "ok",
        "platform": {"system": "windows"},
        "summary": {
            "total_roots": 2,
            "returned_roots": 2,
            "available_roots": 1,
            "unavailable_roots": 1,
            "primary_root_free_bytes": 156 * 1024**3,
        },
        "disks": [
            {
                "root": "C:\\",
                "status": "ok",
                "total_bytes": 256 * 1024**3,
                "used_bytes": 100 * 1024**3,
                "free_bytes": 156 * 1024**3,
                "used_percent": 39.1,
            },
            {"root": "D:\\", "status": "unavailable", "error": "disk_usage_failed"},
        ],
        "read_only": True,
        "mutation_performed": False,
    }


def _fake_processes_payload(info: Any = None, **_: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_processes",
        "status": "ok",
        "platform": {"system": "windows"},
        "total_count": 182,
        "returned_count": 10,
        "truncated": True,
        "state": {"enumeration_failed": False},
        "processes": [
            {"pid": 4, "parent_pid": 0, "name": "System", "thread_count": 150},
            {"pid": 1204, "parent_pid": 4, "name": "svchost.exe", "thread_count": 12},
            {"pid": 2100, "parent_pid": 4, "name": "lsass.exe", "thread_count": 9},
        ],
        "read_only": True,
        "mutation_performed": False,
    }


def _fake_services_payload(info: Any = None, **_: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_services",
        "status": "ok",
        "platform": {"system": "windows"},
        "services": {
            "total_count": 98,
            "state_counts": {"running": 61, "stopped": 37},
            "items": [
                {"name": "Dhcp", "state": "running", "type": "win32_own_process"},
                {"name": "Dnscache", "state": "running", "type": "win32_share_process"},
                {"name": "Spooler", "state": "stopped", "type": "win32_own_process"},
            ],
            "collection_limits": {"max_services": 10, "truncated": True},
        },
        "read_only": True,
        "mutation_performed": False,
    }


def _raising_payload(info: Any = None, **_: Any) -> dict[str, Any]:
    raise OSError("collector pinned to fail in pr289 fixture")


def _pin_context_builders(monkeypatch: Any, *, processes_and_services: bool = True) -> None:
    base = "shellforgeai.core.windows_evidence_context"
    monkeypatch.setattr(f"{base}.windows_status_payload", _fake_status_payload)
    monkeypatch.setattr(f"{base}.windows_memory_payload", _fake_memory_payload)
    monkeypatch.setattr(f"{base}.windows_disks_payload", _fake_disks_payload)
    if processes_and_services:
        monkeypatch.setattr(f"{base}.windows_processes_payload", _fake_processes_payload)
        monkeypatch.setattr(f"{base}.windows_services_payload", _fake_services_payload)
    else:
        monkeypatch.setattr(f"{base}.windows_processes_payload", _raising_payload)
        monkeypatch.setattr(f"{base}.windows_services_payload", _raising_payload)


@pytest.fixture
def windows_interactive(monkeypatch: Any, tmp_path: Path) -> Any:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.detect_platform", lambda: WINDOWS_INFO
    )
    return monkeypatch


class _CaptureProvider:
    """Fake provider capturing prompts; never touches network or a real model."""

    prompts: list[str] = []

    def __init__(self, text: str) -> None:
        self._text = text

    def complete(self, req: Any) -> Any:
        type(self).prompts.append(req.prompt)
        return type(
            "R",
            (),
            {
                "ok": True,
                "text": self._text,
                "provider": "fake",
                "model": "fake-model",
                "raw": {},
                "error": None,
                "usage": None,
            },
        )()


class _GoodEvidenceProvider(_CaptureProvider):
    def __init__(self) -> None:
        super().__init__(GOOD_EVIDENCE_ANSWER)


class _BadPreambleProvider(_CaptureProvider):
    def __init__(self) -> None:
        super().__init__(OBSERVED_BAD_PREAMBLE)


# --- 1. context builder includes Windows evidence facts ---------------------


def test_context_builder_includes_windows_evidence_facts(monkeypatch: Any) -> None:
    _pin_context_builders(monkeypatch)
    packet = build_windows_evidence_context(WINDOWS_INFO)

    assert packet["platform"] == "windows"
    assert packet["visibility"] == "windows-local-read-only"
    assert packet["read_only"] is True
    assert packet["mutation_performed"] is False
    assert packet["host"]["hostname"] == "WIN2025-SFAI01"
    assert packet["platform_detail"]["release"] == "2025Server"

    memory = packet["memory"]
    assert memory["available"] is True
    assert memory["total_bytes"] == 8 * 1024**3
    assert memory["available_bytes"] == int(6.4 * 1024**3)
    assert memory["used_bytes"] == 8 * 1024**3 - int(6.4 * 1024**3)
    assert memory["used_percent"] == 20.0
    assert memory["source"]

    disk = packet["disk"]
    assert disk["available"] is True
    assert disk["root_free_bytes"] == 156 * 1024**3
    assert disk["roots"][0]["root"] == "C:\\"
    assert disk["roots"][0]["used_percent"] == 39.1
    assert disk["unavailable_roots"] == ["D:\\"]
    assert "Inodes are not available on Windows" in disk["inode_limitation"]

    processes = packet["processes"]
    assert processes["available"] is True
    assert processes["total_count"] == 182
    assert processes["returned_count"] == 3
    assert processes["entries"][0]["name"] == "System"
    assert processes["collection"] == "read_only"

    services = packet["services"]
    assert services["available"] is True
    assert services["total_count"] == 98
    assert services["running_count"] == 61
    assert services["stopped_count"] == 37
    assert {e["name"] for e in services["entries"]} == {"Dhcp", "Dnscache", "Spooler"}
    assert services["collection"] == "read_only"

    limitations = packet["limitations"]
    assert "Load average is not available on Windows" in limitations
    assert "Inodes are not available on Windows" in limitations
    assert "Linux-only collectors skipped on Windows" in limitations
    assert packet["evidence_gaps"] == []


def test_context_builder_fails_soft_per_component(monkeypatch: Any) -> None:
    base = "shellforgeai.core.windows_evidence_context"
    for name in (
        "windows_status_payload",
        "windows_memory_payload",
        "windows_disks_payload",
        "windows_processes_payload",
        "windows_services_payload",
    ):
        monkeypatch.setattr(f"{base}.{name}", _raising_payload)
    packet = build_windows_evidence_context(WINDOWS_INFO)
    assert packet["read_only"] is True
    assert packet["mutation_performed"] is False
    assert packet["memory"]["available"] is False
    assert packet["processes"]["available"] is False
    assert packet["services"]["available"] is False
    gaps = " ".join(packet["evidence_gaps"])
    assert "process detail" in gaps
    assert "service detail" in gaps
    assert "Load average is not available on Windows" in packet["limitations"]


def test_prompt_facts_rows_carry_key_numbers(monkeypatch: Any) -> None:
    _pin_context_builders(monkeypatch)
    packet = build_windows_evidence_context(WINDOWS_INFO)
    rows = windows_evidence_prompt_facts(packet)
    joined = " | ".join(f"{r['tool']}: {r['status']} {r['summary']}" for r in rows)
    assert "hostname=WIN2025-SFAI01" in joined
    assert "memory used=20.0%" in joined
    assert "available=6.4GiB/8.0GiB" in joined
    assert "free=156.0GiB/256.0GiB" in joined
    assert "processes total=182" in joined
    assert "services total=98 running=61" in joined
    assert "Load average is not available on Windows" in joined
    assert "Inodes are not available on Windows" in joined


# --- bad-output guard --------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        OBSERVED_BAD_PREAMBLE,
        "Understood. I'll operate within the ShellForgeAI invariants and help.",
        "Understood. I'll follow the project instructions for this task.",
        "Per AGENTS.md, this repo is a CLI-first ops harness.",
        "I will preserve the ShellForgeAI project constraints and repo invariants.",
        "The CLI invariants and UX invariants require read-only behavior.",
        "For work in this repo, evidence-first routing applies.",
        "The system prompt says to use collected evidence first.",
        "I'll treat this per the workspace conventions.",
        "Provider: codex\nModel: gpt-5\nUsage: 120 tokens",
        "Docker containers look healthy; compose services are all up.",
        "",
        "   ",
    ],
)
def test_windows_answer_guard_rejects_bad_output(text: str) -> None:
    assert is_rejected_windows_model_answer(text)


@pytest.mark.parametrize(
    "text",
    [
        GOOD_EVIDENCE_ANSWER,
        "This Windows host shows 182 processes; no Docker evidence is in this packet.",
        (
            "Windows evidence: memory used=20.0% available=6.4GiB/8.0GiB, root "
            "free 156.0GiB. Load average is not available on Windows."
        ),
        (
            "From the evidence currently loaded, I can see host and memory facts. "
            "I do not have process/service detail in this evidence packet. "
            "Run sfai.cmd windows services --json to fill the gap."
        ),
    ],
)
def test_windows_answer_guard_accepts_evidence_grounded_output(text: str) -> None:
    assert not is_rejected_windows_model_answer(text)


# --- 2. exact failure regression: "What is running on this system?" ---------


def test_what_is_running_passes_process_service_evidence_to_model(
    windows_interactive: Any,
) -> None:
    _pin_context_builders(windows_interactive)
    _GoodEvidenceProvider.prompts = []
    windows_interactive.setattr(
        "shellforgeai.interactive.repl.build_provider", lambda *_: _GoodEvidenceProvider()
    )
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="What is running on this system?\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert "Traceback" not in out

    # The model context carries real Windows process/service evidence.
    assert _GoodEvidenceProvider.prompts
    prompt = _GoodEvidenceProvider.prompts[0]
    assert "processes total=182" in prompt
    assert "services total=98 running=61" in prompt
    assert "hostname=WIN2025-SFAI01" in prompt
    assert "windows_evidence" in prompt
    assert "Load average is not available on Windows" in prompt

    # The operator answer is the evidence-grounded model answer.
    assert "182 visible" in out
    assert "98 services" in out

    # No project/policy preamble, no AGENTS.md, no Docker-primary framing.
    assert "Understood" not in out
    assert "operate within" not in out
    assert "AGENTS.md" not in out
    assert "invariants" not in out
    assert "project instructions" not in out
    assert "workspace conventions" not in out
    assert not out.lstrip().lower().startswith("docker")


def test_what_is_running_bad_preamble_is_gated_to_evidence_answer(
    windows_interactive: Any, tmp_path: Path
) -> None:
    _pin_context_builders(windows_interactive)
    _BadPreambleProvider.prompts = []
    windows_interactive.setattr(
        "shellforgeai.interactive.repl.build_provider", lambda *_: _BadPreambleProvider()
    )
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="What is running on this system?\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0

    # The bad output never reaches stdout as the answer.
    assert "Understood" not in out
    assert "operate within the ShellForgeAI invariants" not in out
    assert "AGENTS.md" not in out

    # The fallback answers from visible process/service evidence.
    assert "From the evidence currently loaded" in out
    assert "processes total=182" in out.lower() or "Processes total=182" in out
    assert "services total=98 running=61" in out.lower() or "Services total=98" in out
    assert "read-only" in out.lower()
    assert "sfai.cmd windows processes --json --limit 10" in out
    assert "sfai.cmd windows services --json" in out
    assert "shellforgeai windows status --json" in out
    assert "No command was executed" in out

    # Raw bad output stays in the existing model-response audit artifact only.
    artifacts = list(tmp_path.rglob("model-response.md"))
    assert artifacts
    assert "operate within the ShellForgeAI invariants" in artifacts[0].read_text(encoding="utf-8")


# --- 3. evidence-thin path ---------------------------------------------------


def test_thin_evidence_states_gap_and_suggests_safe_commands(
    windows_interactive: Any,
) -> None:
    _pin_context_builders(windows_interactive, processes_and_services=False)
    _BadPreambleProvider.prompts = []
    windows_interactive.setattr(
        "shellforgeai.interactive.repl.build_provider", lambda *_: _BadPreambleProvider()
    )
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="What is running on this system?\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert "Understood" not in out
    assert "I do not have process detail in this evidence packet." in out
    assert "I do not have service detail in this evidence packet." in out
    assert "Run these read-only commands to fill the gap:" in out
    assert "sfai.cmd windows processes --json --limit 10" in out
    assert "sfai.cmd windows services --json" in out
    # No invented process/service facts.
    assert "svchost" not in out
    assert "System" not in out.replace("this system", "").replace("Safety:", "")
    assert "running=" not in out


def test_thin_evidence_prompt_tells_model_about_gaps(windows_interactive: Any) -> None:
    _pin_context_builders(windows_interactive, processes_and_services=False)
    _GoodEvidenceProvider.prompts = []
    windows_interactive.setattr(
        "shellforgeai.interactive.repl.build_provider", lambda *_: _GoodEvidenceProvider()
    )
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="What is running on this system?\n/exit\n",
    )
    assert res.exit_code == 0
    assert _GoodEvidenceProvider.prompts
    prompt = _GoodEvidenceProvider.prompts[0]
    assert "not present in this evidence packet" in prompt
    assert "evidence_gaps" in prompt


# --- 4. slow prompt uses real Windows memory/disk facts ----------------------


def test_slow_prompt_uses_real_memory_and_disk_facts(
    windows_interactive: Any,
) -> None:
    windows_interactive.setattr("shellforgeai.core.diagnose.detect_platform", lambda: WINDOWS_INFO)
    windows_interactive.setattr(
        "shellforgeai.core.collectors.detect_platform", lambda: WINDOWS_INFO
    )
    windows_interactive.setattr(
        "shellforgeai.core.collectors.windows_status_payload", _fake_status_payload
    )
    windows_interactive.setattr(
        "shellforgeai.core.collectors.windows_disks_payload", _fake_disks_payload
    )
    windows_interactive.setattr(
        "shellforgeai.core.collectors.windows_memory_payload", _fake_memory_payload
    )
    windows_interactive.setattr(
        "shellforgeai.interactive.repl.windows_memory_payload", _fake_memory_payload
    )

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows slow route must not call the model provider")

    windows_interactive.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="Hey this system feels slow?\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    # Real memory facts, no false unavailable claim.
    assert "memory used=20.0%" in out
    assert "available=6.4GiB/8.0GiB" in out
    assert "Memory summary unavailable" not in out
    # Real disk/root facts from the reused Windows payloads.
    assert "root_free=156.0GiB/256.0GiB" in out
    # Honest limitation, Windows-native framing, no Docker.
    assert "Load average is not available on Windows" in out
    assert "Windows host" in out
    assert "docker" not in out.lower()
    assert "Understood" not in out
    assert "AGENTS.md" not in out


# --- 5. mutation refusal ------------------------------------------------------


def test_mutation_request_is_refused_without_execution(windows_interactive: Any) -> None:
    _pin_context_builders(windows_interactive)

    def _fail_provider(*_: Any) -> Any:
        raise AssertionError("Windows mutation refusal must not call the model provider")

    windows_interactive.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="Clean up Windows and restart services to fix it\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0
    assert "Refused: natural-language mutation is not allowed." in out
    assert "No command was executed" in out
    assert "No action was taken" in out
    assert "Safe Windows read-only alternatives:" in out
    assert "shellforgeai windows status --json" in out
    for forbidden in (
        "cleanup executed",
        "remediation executed",
        "rollback executed",
        "recovery executed",
        "Executing command",
    ):
        assert forbidden not in out


# --- ask command parity -------------------------------------------------------


def _pin_ask_windows(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.detect_platform", lambda: WINDOWS_INFO
    )
    _pin_context_builders(monkeypatch)


def test_ask_what_is_running_includes_windows_evidence_in_model_context(
    monkeypatch: Any, tmp_path: Path
) -> None:
    _pin_ask_windows(monkeypatch, tmp_path)
    _GoodEvidenceProvider.prompts = []
    monkeypatch.setattr("shellforgeai.cli.build_provider", lambda *_: _GoodEvidenceProvider())
    res = runner.invoke(app, ["ask", "What is running on this system?"])
    out = res.stdout
    assert res.exit_code == 0
    assert _GoodEvidenceProvider.prompts
    prompt = _GoodEvidenceProvider.prompts[0]
    assert "processes total=182" in prompt
    assert "services total=98 running=61" in prompt
    assert "windows_evidence" in prompt
    assert "182 visible" in out
    assert "Understood" not in out
    assert "AGENTS.md" not in out


def test_ask_bad_preamble_is_gated_to_evidence_answer(monkeypatch: Any, tmp_path: Path) -> None:
    _pin_ask_windows(monkeypatch, tmp_path)
    _BadPreambleProvider.prompts = []
    monkeypatch.setattr("shellforgeai.cli.build_provider", lambda *_: _BadPreambleProvider())
    res = runner.invoke(app, ["ask", "What is running on this system?"])
    out = res.stdout
    assert res.exit_code == 0
    assert "Understood" not in out
    assert "operate within the ShellForgeAI invariants" not in out
    assert "From the evidence currently loaded" in out
    assert "sfai.cmd windows processes --json --limit 10" in out
    assert "sfai.cmd windows services --json" in out
    # Provider metadata is not the primary answer for gated Windows output.
    assert "Provider:" not in out
    assert "Model:" not in out


def test_ask_model_failure_falls_back_to_windows_evidence(monkeypatch: Any, tmp_path: Path) -> None:
    _pin_ask_windows(monkeypatch, tmp_path)

    class _FailingProvider:
        def complete(self, req: Any) -> Any:
            return type(
                "R",
                (),
                {"ok": False, "text": "", "error": "codex auth failed", "raw": {}},
            )()

    monkeypatch.setattr("shellforgeai.cli.build_provider", lambda *_: _FailingProvider())
    res = runner.invoke(app, ["ask", "What is running on this system?"])
    out = res.stdout
    assert res.exit_code == 0
    assert "From the evidence currently loaded" in out
    assert "Model assistance is unavailable" in out
    assert "shellforgeai model doctor --json" in out


# --- deterministic fallback renderer ------------------------------------------


def test_fallback_answer_is_ascii_console_safe(monkeypatch: Any) -> None:
    _pin_context_builders(monkeypatch)
    packet = build_windows_evidence_context(WINDOWS_INFO)
    text = render_windows_evidence_answer("What is running on this system?", packet)
    text.encode("ascii", errors="strict")
    text.encode("cp1252", errors="strict")
    assert "Process/service evidence above is read-only." in text
    assert "No command was executed" in text


def test_fallback_answer_with_unavailable_memory_keeps_honest_marker(
    monkeypatch: Any,
) -> None:
    base = "shellforgeai.core.windows_evidence_context"
    _pin_context_builders(monkeypatch)
    monkeypatch.setattr(f"{base}.windows_memory_payload", _fake_memory_payload_unavailable)
    monkeypatch.setattr(f"{base}.windows_status_payload", _raising_payload)
    packet = build_windows_evidence_context(WINDOWS_INFO)
    text = render_windows_evidence_answer("status?", packet)
    assert "Memory summary unavailable from this collector on Windows" in text
    assert "memory used=" not in text


# --- 6. safety/source assertions ----------------------------------------------


def test_source_safety_for_windows_evidence_context() -> None:
    source = Path("src/shellforgeai/core/windows_evidence_context.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "sub" + "process" not in source
    assert "Power" + "Shell" not in source.replace("no shell, no remoting", "")
    assert "Win" + "RM" not in source
    assert "os.system" not in source
    assert "eval(" not in source
    assert "exec(" not in source
    assert "socket" not in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "auth" not in source.lower()
    assert "secret" not in source.lower()
    # "tokens:" / "*_tokens" appear only as metadata-primary rejection terms in
    # the bad-output guard; assert no credential-style token access exists.
    for credential_pattern in ("token_read", "read_token", "auth.json", "credential"):
        assert credential_pattern not in source.lower()


def test_no_new_execution_surface_in_wired_paths() -> None:
    ask_source = Path("src/shellforgeai/commands/ask.py").read_text(encoding="utf-8")
    assert "shell=True" not in ask_source
    repl_source = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    pr289_slice = repl_source.split("PR289", 1)[1]
    assert "shell=True" not in pr289_slice
