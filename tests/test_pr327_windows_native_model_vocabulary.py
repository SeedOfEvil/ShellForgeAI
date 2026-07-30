"""PR327 Windows-native evidence prompt and output-boundary tests."""

from __future__ import annotations

from copy import deepcopy

import pytest

from shellforgeai.core.windows_evidence_context import (
    WINDOWS_CONTEXT_PROCESS_LIMIT,
    WINDOWS_CONTEXT_SERVICE_LIMIT,
    contains_linux_primary_operational_framing,
    is_rejected_windows_model_answer,
    project_windows_evidence_for_model,
    render_windows_evidence_answer,
)
from shellforgeai.llm.prompts import (
    build_contextual_prompt,
    build_model_prompt,
    build_windows_evidence_model_prompt,
)


@pytest.fixture
def packet() -> dict:
    return {
        "platform": "windows",
        "visibility": "windows-local-read-only",
        "read_only": True,
        "mutation_performed": False,
        "host": {"hostname": "WIN2025-SFAI01", "fqdn": ""},
        "platform_detail": {"system": "windows", "release": "2025Server"},
        "python_runtime": {"version": "3.14", "implementation": "CPython"},
        "memory": {
            "available": True,
            "total_bytes": 8589934592,
            "available_bytes": 6871947673,
            "used_bytes": 1717986919,
            "used_percent": 20.0,
        },
        "disk": {
            "available": True,
            "root_path": "C:\\",
            "root_total_bytes": 274877906944,
            "root_free_bytes": 167503724544,
            "roots": [{"root": "C:\\"}],
            "inode_limitation": "Inode usage is not available on Windows",
        },
        "processes": {
            "available": True,
            "total_count": 182,
            "returned_count": 2,
            "limit": WINDOWS_CONTEXT_PROCESS_LIMIT,
            "entries": [{"pid": 4, "name": "System"}, {"pid": 1204, "name": "svchost.exe"}],
        },
        "services": {
            "available": True,
            "total_count": 98,
            "running_count": 61,
            "stopped_count": 37,
            "returned_count": 1,
            "limit": WINDOWS_CONTEXT_SERVICE_LIMIT,
            "entries": [{"name": "Dhcp", "state": "running"}],
        },
        "limitations": ["Linux-only collectors skipped on Windows", "Inode usage is not available"],
        "evidence_gaps": ["Windows event detail is not present in this evidence packet"],
        "safe_next_commands": ["shellforgeai windows status --json"],
    }


def test_windows_prompt_has_native_identity_capabilities_and_real_facts(packet: dict) -> None:
    prompt = build_windows_evidence_model_prompt(
        "What is running?", {"windows_evidence": packet}, mode="full"
    )
    for expected in (
        "Windows-local read-only evidence",
        "Windows services",
        "Event Logs",
        "drives and volumes",
        "WIN2025-SFAI01",
        "8589934592",
        "Windows event detail is not present",
        '"mutation_permitted": false',
    ):
        assert expected in prompt
    assert len(prompt) < 7000


@pytest.mark.parametrize(
    "prohibited",
    [
        "CLI-first Linux operations harness",
        "disk.inodes",
        "systemd.status",
        "systemd.list_failed",
        "journal.unit",
        "journalctl",
        "docker.detect",
        "nginx.detect",
        "ssh.detect",
        "firewall.detect",
        "Linux-only collectors skipped",
        "Inode usage",
        "AGENTS.md",
    ],
)
def test_windows_prompt_omits_linux_identity_collectors_and_markers(
    packet: dict, prohibited: str
) -> None:
    assert prohibited not in build_windows_evidence_model_prompt(
        "Summarize", {"windows_evidence": packet}
    )


def test_projection_is_non_mutating_bounded_and_preserves_facts_and_gaps(packet: dict) -> None:
    original = deepcopy(packet)
    projection = project_windows_evidence_for_model(packet)
    assert packet == original
    assert not projection["limitations"] and "inode_limitation" not in projection["disk"]
    assert projection["memory"]["total_bytes"] == packet["memory"]["total_bytes"]
    assert projection["evidence_gaps"] == packet["evidence_gaps"]
    assert len(projection["processes"]["entries"]) <= WINDOWS_CONTEXT_PROCESS_LIMIT
    assert len(projection["services"]["entries"]) <= WINDOWS_CONTEXT_SERVICE_LIMIT


@pytest.mark.parametrize(
    "answer",
    [
        "Run systemctl status Spooler.",
        "Use journalctl to inspect logs.",
        "Inspect the systemd unit.",
        "Restart the systemd service.",
        "Run df -i.",
        "Run ps aux.",
        "Inspect /var/log/messages.",
        "This indicates inode pressure.",
        "Check for inode exhaustion.",
        "Use the inode-equivalent.",
        "Check inodes next.",
        "Use the Linux service manager.",
    ],
)
def test_precise_linux_primary_operations_are_rejected(answer: str) -> None:
    assert contains_linux_primary_operational_framing(answer)
    assert is_rejected_windows_model_answer(answer)


@pytest.mark.parametrize(
    "answer",
    [
        "The unit reported by this application is healthy.",
        "The Windows service state is running.",
        "The Windows Event Log evidence has no supplied error entry.",
        "The supplied drive evidence does not show storage pressure.",
        "This Windows container answer uses the requested Windows container evidence.",
    ],
)
def test_generic_and_windows_native_words_are_accepted(answer: str) -> None:
    assert not contains_linux_primary_operational_framing(answer)
    assert not is_rejected_windows_model_answer(answer)


def test_existing_container_primary_gate_is_preserved() -> None:
    assert is_rejected_windows_model_answer("Docker containers should be checked first.")


def test_fallback_is_windows_native_and_omits_linux_primary_vocabulary(packet: dict) -> None:
    answer = render_windows_evidence_answer("Summarize", packet)
    for expected in ("Windows evidence summary", "Memory", "Processes", "Services"):
        assert expected in answer
    for phrase in ("systemd", "journalctl", "inode", "df -i", "ps aux", "/var/log"):
        assert phrase not in answer.lower()


def test_linux_default_prompt_builders_remain_linux_only() -> None:
    context = {"evidence": [{"tool": "disk.usage", "status": "ok", "summary": "safe"}]}
    direct = build_model_prompt("Status?", context, max_chars=2500)
    assert direct == build_contextual_prompt("Status?", context, mode="standard")
    assert "CLI-first Linux operations harness" in direct and "disk.inodes" in direct
    assert "Windows-local read-only evidence" not in direct
