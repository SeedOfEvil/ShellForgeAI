"""PR381 explicit native-Windows process analytical routing truth."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_module
from shellforgeai.cli import app
from shellforgeai.core import ask_docker_grounding as docker_grounding_module
from shellforgeai.core import command_suggestions as command_suggestions_module
from shellforgeai.core import windows_operator_ux as ux
from shellforgeai.core.ask_routing import EVIDENCE_BACKED, route_ask_intent
from shellforgeai.interactive.commands import route_input

CANONICAL = (
    "Which running Windows processes have the largest working set, "
    "and do any deserve attention?"
)


@pytest.mark.parametrize(
    "prompt",
    (
        CANONICAL,
        "Which Windows processes have the largest working set?",
        "Which running Windows processes deserve attention based on the observed working set?",
        "Which Windows processes stand out from the working-set evidence?",
        "Using the observed working set, which running Windows processes should I inspect first?",
    ),
)
def test_explicit_windows_process_analysis_uses_running_inventory(prompt: str) -> None:
    route = ux.classify_windows_operator_intent(prompt, host_system="Windows")
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY
    assert ux.classify_windows_operator_intent(prompt, host_system="Linux").intent == route.intent


@pytest.mark.parametrize(
    "prompt",
    (
        "Which running Docker containers deserve attention and why?",
        "Which Docker containers have the largest memory footprint?",
        "Rank the running Docker containers by what deserves attention.",
        "Which running systemd services deserve attention and why?",
        "Which Linux processes deserve attention?",
        "Show Linux services.",
    ),
)
def test_explicit_non_windows_scope_is_not_stolen(prompt: str) -> None:
    assert ux.classify_windows_operator_intent(prompt, host_system="Windows") is None


@pytest.mark.parametrize(
    "prompt",
    (
        "Which processes should I inspect first based on what you observed?",
        "Rank the observed running items by operator attention and explain the ordering "
        "without claiming an unobserved fault.",
        "Which running components stand out most from the evidence?",
    ),
)
def test_generic_pr344_analysis_keeps_shared_route(prompt: str) -> None:
    assert ux.classify_windows_operator_intent(prompt, host_system="Windows") is None
    assert route_ask_intent(prompt).mode == EVIDENCE_BACKED
    assert route_ask_intent(prompt).target == "docker"


@pytest.mark.parametrize(
    "prompt",
    (
        "Which running items deserve attention and why?",
        "What is running on this system?",
        "Give me an evidence-backed inventory of what is running.",
        "Show the running processes and services on this host.",
    ),
)
def test_existing_windows_inventory_families_are_unchanged(prompt: str) -> None:
    route = ux.classify_windows_operator_intent(prompt, host_system="Windows")
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY


@pytest.mark.parametrize(
    "prompt",
    (
        "Which running Windows processes have the largest working set? Restart the worst one.",
        "Which running Windows processes deserve attention based on working set, "
        "and then kill the top one?",
    ),
)
def test_mutation_precedes_windows_process_analysis(prompt: str) -> None:
    route = ux.classify_windows_operator_intent(prompt, host_system="Windows")
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL


@pytest.mark.parametrize(
    "prompt",
    (
        f"{CANONICAL}; rm -rf /tmp/example",
        'Which running Windows processes deserve attention; powershell.exe -Command '
        '"Stop-Process -Id 1234"',
    ),
)
def test_shell_suffix_fails_closed(prompt: str) -> None:
    assert route_input(prompt).name in {"shell_refused", "mutation_refused"}
    assert route_ask_intent(prompt).mode != EVIDENCE_BACKED


def test_canonical_native_windows_ask_has_only_windows_provenance(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls: list[str] = []
    requests = []
    packet = {
        "platform": "windows",
        "visibility": "windows-local-read-only",
        "read_only": True,
        "mutation_performed": False,
        "host": {"hostname": "WIN-TEST"},
        "platform_detail": {},
        "memory": {"available": False},
        "disk": {"available": False},
        "processes": {
            "available": True,
            "total_count": 1,
            "returned_count": 1,
            "limit": 10,
            "truncated": False,
            "items": [
                {
                    "pid": 4242,
                    "name": "example.exe",
                    "thread_count": 4,
                    "working_set_available": True,
                    "working_set_bytes": 268435456,
                }
            ],
        },
        "services": {"available": False},
        "events": {"available": False},
        "network": {"available": False},
        "volumes": {"available": False},
        "limitations": [
            "Process working-set values are bounded point-in-time observations; size alone "
            "does not establish that a process is unhealthy."
        ],
        "evidence_gaps": ["Native per-process CPU attribution is unavailable."],
        "safe_next_commands": [],
    }

    def forbidden(*_args, **_kwargs):
        pytest.fail("canonical native-Windows route must not enter Docker provenance")

    class Provider:
        def complete(self, request):
            calls.append("model")
            requests.append(request)
            return type(
                "Response",
                (),
                {
                    "ok": True,
                    "text": "Advisory assessment from the observed Windows working set.",
                    "provider": "fake",
                    "model": "fake",
                    "raw": {},
                    "error": None,
                    "usage": None,
                },
            )()

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr(docker_grounding_module, "build_docker_evidence_context", forbidden)
    monkeypatch.setattr(
        command_suggestions_module, "filter_unsupported_command_suggestions", forbidden
    )
    monkeypatch.setattr(cli_module, "_emit_docker_grounding_answer", forbidden)
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context",
        lambda: calls.append("windows_evidence") or packet,
    )
    monkeypatch.setattr(cli_module, "build_provider", lambda *_args: Provider())

    result = CliRunner().invoke(app, ["ask", CANONICAL])

    assert result.exit_code == 0, result.stdout
    assert calls == ["windows_evidence", "model"]
    assert len(requests) == 1
    prompt = requests[0].prompt
    assert "example.exe" in prompt
    assert "268435456" in prompt
    assert "working_set_available" in prompt
    assert "Native per-process CPU attribution is unavailable" in prompt
    assert "deterministic_docker_evidence" not in prompt
    assert "Docker triage evidence" not in prompt
    assert "using current ShellForgeAI Docker triage evidence" not in prompt
    assert "Intent: Windows running-system inventory" in result.stdout
    assert "Intent: Docker" not in result.stdout
    assert packet["read_only"] is True
    assert packet["mutation_performed"] is False
    audit_path = tmp_path / "audit" / "events.jsonl"
    audit_rows = (
        [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
        if audit_path.exists()
        else []
    )
    assert not any(row.get("action") == "docker_evidence_grounded" for row in audit_rows)


def test_mutation_and_shell_refusals_do_no_downstream_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        pytest.fail("refusal must precede evidence, provider, and action")

    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context", forbidden
    )
    monkeypatch.setattr(cli_module, "build_provider", forbidden)
    mutation = CliRunner().invoke(
        app,
        ["ask", "Which running Windows processes have the largest working set? Restart it."],
    )
    shell = CliRunner().invoke(app, ["ask", f"{CANONICAL}; rm -rf /tmp/example"])
    assert mutation.exit_code == 0
    assert "Refused: natural-language mutation" in mutation.stdout
    assert "No command was executed. No action was taken." in mutation.stdout
    assert shell.exit_code == 0
    assert "not a shell" in shell.stdout
    assert "No evidence was collected" in shell.stdout
