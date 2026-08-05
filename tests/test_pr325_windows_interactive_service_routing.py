"""PR325 Windows-native interactive service routing tests.

PR325 adds one bounded, deterministic, read-only Windows service intent to the
interactive routing layer only. It executes nothing, collects nothing, calls no
model, and leaves the shared ``ask`` classifier and mutation refusal unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import windows_operator_ux as ux
from shellforgeai.core.latest_context import render_latest_context_pending
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import (
    _render_windows_read_only_intent,
    _windows_interactive_command,
    _windows_interactive_pending_context,
)

runner = CliRunner()

SERVICES_COMMAND = "shellforgeai windows services --json --limit 25"

# Bounded read-only service inventory/health phrases PR325 accepts.
ACCEPTED_SERVICE_PHRASES = (
    "show service status",
    "show services",
    "show me the services",
    "show Windows services",
    "Windows services",
    "service status",
    "services status",
    "service health",
    "services health",
    "are services healthy",
    "are the services healthy",
    "what services are running",
    "which services are running",
    "list services",
    "list Windows services",
    "show failed services",
    "check services",
    "check Windows services",
    "show me Windows services",
    "what Windows services are running",
)

# Phrases that merely contain the word "service" and must never be routed.
REJECTED_SERVICE_PHRASES = (
    "customer service",
    "customer service status",
    "service desk",
    "service account",
    "service agreement",
    "professional services",
    "software as a service",
    "this application provides a service",
    "tell me what service means",
)

# Named-service lookup stays deferred beyond PR325.
DEFERRED_NAMED_SERVICE_PHRASES = (
    "is the Spooler service running",
    "is W32Time running",
    "check service MSSQLSERVER",
)

# Other-platform service scopes must keep their existing routing.
FOREIGN_SCOPE_SERVICE_PHRASES = (
    "show systemd services",
    "show Linux services",
    "check Docker services",
    "Docker Compose service status",
    "journal service status",
)

WINDOWS_MUTATION_PHRASES = (
    "restart Windows services",
    "restart the service",
    "start the service",
    "stop the service",
    "kill the service process",
    "remediate Windows services",
    "apply the service fix",
    "roll back the service change",
    "clean up and restart services",
)

# Generic/Linux evidence vocabulary that must never appear in a service answer.
GENERIC_EVIDENCE_MARKERS = (
    "container-limited",
    "systemctl",
    "journalctl",
    "uptime",
    "inode",
    "triage docker",
    "Docker service guidance",
)


# ---------------------------------------------------------------------------
# 1-2. Accepted and rejected phrase matrices (pure classifier)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("phrase", ACCEPTED_SERVICE_PHRASES)
def test_accepted_service_phrases_route_to_windows_services(phrase: str) -> None:
    route = ux.classify_windows_interactive_intent(phrase, host_system="Windows")
    assert route is not None, phrase
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_SERVICES
    assert route.host_is_windows is True


@pytest.mark.parametrize(
    "phrase",
    REJECTED_SERVICE_PHRASES + DEFERRED_NAMED_SERVICE_PHRASES + FOREIGN_SCOPE_SERVICE_PHRASES,
)
def test_false_positive_and_deferred_phrases_are_not_classified(phrase: str) -> None:
    assert ux.classify_windows_interactive_intent(phrase, host_system="Windows") is None
    assert ux.classify_windows_interactive_intent(phrase, host_system="Linux") is None


def test_bare_service_word_is_not_a_route() -> None:
    for phrase in ("service", "services", "a service", "the service"):
        assert ux.classify_windows_interactive_intent(phrase, host_system="Windows") is None


# ---------------------------------------------------------------------------
# 3-4. Windows/non-Windows host scoping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "phrase", ("show service status", "what services are running", "services health")
)
def test_generic_service_phrases_are_not_hijacked_on_non_windows_hosts(phrase: str) -> None:
    assert ux.classify_windows_interactive_intent(phrase, host_system="Linux") is None
    assert ux.classify_windows_interactive_intent(phrase, host_system="Darwin") is None


@pytest.mark.parametrize(
    "phrase", ("show Windows services", "Windows services", "list Windows services")
)
def test_explicit_windows_service_phrases_on_linux_render_non_windows_host_route(
    phrase: str,
) -> None:
    route = ux.classify_windows_interactive_intent(phrase, host_system="Linux")
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_SERVICES
    assert route.host_is_windows is False
    assert route.explicit_windows is True
    rendered = ux.render_windows_operator_guidance(route)
    assert "Context: Windows guidance requested from a non-Windows host." in rendered
    assert "No Windows probing was performed." in rendered
    assert "Windows commands below are commands to run on the Windows host." in rendered
    assert SERVICES_COMMAND in rendered


# ---------------------------------------------------------------------------
# 5. Mutation-refusal precedence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("phrase", WINDOWS_MUTATION_PHRASES)
def test_mutation_refusal_wins_over_the_new_read_only_service_route(phrase: str) -> None:
    route = ux.classify_windows_interactive_intent(phrase, host_system="Windows")
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL
    rendered = ux.render_windows_operator_guidance(route)
    assert rendered.startswith(
        "Refused: natural-language mutation is not allowed.\n"
        "No command was executed. No action was taken."
    )
    assert (
        "Cleanup, restart, and service control are mutating/service-impacting actions." in rendered
    )


def test_conservatively_unclassified_mutation_wording_is_not_captured_as_read_only() -> None:
    """PR325 must not turn borderline mutation wording into a read-only route.

    ``fix the services`` is not classified by the maintained mutation predicate
    today (it requires ``fix it``). PR325 leaves that predicate untouched and,
    critically, does not absorb the phrase into the new read-only service route.
    """
    assert ux.classify_windows_operator_intent("fix the services", host_system="Windows") is None
    assert ux.classify_windows_interactive_intent("fix the services", host_system="Windows") is None


# ---------------------------------------------------------------------------
# 6. Shared ask classifier is unchanged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("phrase", ACCEPTED_SERVICE_PHRASES)
def test_shared_ask_classifier_still_returns_none_for_service_phrases(phrase: str) -> None:
    assert ux.classify_windows_operator_intent(phrase, host_system="Windows") is None
    assert ux.classify_windows_operator_intent(phrase, host_system="Linux") is None


def test_existing_intents_are_returned_unchanged_by_the_interactive_classifier() -> None:
    cases = (
        ("show me the system status", "Windows", ux.WINDOWS_OPERATOR_INTENT_STATUS),
        ("what should I check first", "Windows", ux.WINDOWS_OPERATOR_INTENT_NEXT_CHECK),
        ("system feels slow", "Windows", ux.WINDOWS_OPERATOR_INTENT_PERFORMANCE),
        (
            "Compare CPU memory disk and processes for the strongest signal",
            "Windows",
            ux.WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL,
        ),
        ("operator handoff", "Windows", ux.WINDOWS_OPERATOR_INTENT_HANDOFF),
        (
            "Clean up Windows and restart services",
            "Linux",
            ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL,
        ),
    )
    for text, host, intent in cases:
        shared = ux.classify_windows_operator_intent(text, host_system=host)
        interactive = ux.classify_windows_interactive_intent(text, host_system=host)
        assert shared is not None and shared.intent == intent
        assert interactive == shared
    for text in ("cpu memory disk", "this slow cooker is nice", "docker container status"):
        assert ux.classify_windows_operator_intent(
            text, host_system="Linux"
        ) == ux.classify_windows_interactive_intent(text, host_system="Linux")


class _RuntimeReached(RuntimeError):
    """Marker raised in place of runtime construction."""


def test_ask_command_does_not_use_the_interactive_classifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shellforgeai import cli

    def _runtime_reached(_ctx: Any) -> Any:
        raise _RuntimeReached

    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setattr(cli, "_ctx", _runtime_reached)
    result = runner.invoke(cli.app, ["ask", "show service status"])
    # The service route is interactive-only, so `ask` must fall straight through
    # the pure Windows route to ordinary runtime handling instead of rendering
    # Windows services guidance.
    assert "## Windows services guidance" not in result.stdout
    assert isinstance(result.exception, _RuntimeReached)


# ---------------------------------------------------------------------------
# 7. Deterministic service command ordering
# ---------------------------------------------------------------------------


def test_service_safe_commands_are_ordered_deduplicated_and_immutable() -> None:
    commands = ux.windows_operator_safe_commands(ux.WINDOWS_OPERATOR_INTENT_SERVICES)
    assert commands == (
        SERVICES_COMMAND,
        "shellforgeai windows evidence --profile standard --json",
        "shellforgeai windows events --json --limit 50 --since-hours 24",
        "shellforgeai windows status --json",
        "shellforgeai windows doctor --json",
    )
    assert commands[0] == ux.WINDOWS_SERVICES_COMMAND
    assert commands[1] == ux.WINDOWS_STANDARD_EVIDENCE_COMMAND
    assert len(commands) == len(set(commands))
    assert all(
        not any(term in command for term in ("cleanup", "clean up", "restart", "kill", "terminate"))
        for command in commands
    )
    assert all("sfai.cmd" not in command for command in commands)
    commands += ("mutating",)
    assert ux.windows_operator_safe_commands(ux.WINDOWS_OPERATOR_INTENT_SERVICES)[-1] != "mutating"
    assert _windows_interactive_command(ux.WINDOWS_OPERATOR_INTENT_SERVICES) == SERVICES_COMMAND


def test_existing_intent_command_ordering_is_untouched() -> None:
    for intent in (
        ux.WINDOWS_OPERATOR_INTENT_STATUS,
        ux.WINDOWS_OPERATOR_INTENT_NEXT_CHECK,
        ux.WINDOWS_OPERATOR_INTENT_PERFORMANCE,
        ux.WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL,
        ux.WINDOWS_OPERATOR_INTENT_HANDOFF,
        ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL,
    ):
        assert ux.windows_operator_safe_commands(intent)[0] == ux.WINDOWS_STANDARD_EVIDENCE_COMMAND


# ---------------------------------------------------------------------------
# 8-9. Deterministic rendering without generic Linux wording
# ---------------------------------------------------------------------------


def test_windows_service_guidance_rendering_contract() -> None:
    rendered = ux.render_windows_operator_guidance(
        ux.WindowsOperatorRoute(ux.WINDOWS_OPERATOR_INTENT_SERVICES, True, False)
    )
    assert rendered.startswith("## Windows services guidance")
    assert "Context: Windows local read-only." in rendered
    assert "Context/visibility: windows-local-read-only." in rendered
    assert f"Start with this bounded read-only check:\n- {SERVICES_COMMAND}" in rendered
    assert "No command was executed. No action was taken." in rendered
    assert (
        "No cleanup, restart, service control, process termination, remediation, "
        "rollback, or recovery was performed."
    ) in rendered
    assert ux.WINDOWS_STANDARD_EVIDENCE_COMMAND in rendered
    lowered = rendered.lower()
    assert all(marker.lower() not in lowered for marker in GENERIC_EVIDENCE_MARKERS)


def test_repl_service_renderer_matches_maintained_guidance_on_both_hosts() -> None:
    for is_windows in (True, False):
        rendered = _render_windows_read_only_intent(
            intent=ux.WINDOWS_OPERATOR_INTENT_SERVICES, is_windows=is_windows
        )
        assert rendered == ux.render_windows_operator_guidance(
            ux.WindowsOperatorRoute(ux.WINDOWS_OPERATOR_INTENT_SERVICES, is_windows, True)
        )
        assert rendered.startswith("## Windows services guidance")
        assert SERVICES_COMMAND in rendered
        lowered = rendered.lower()
        assert all(marker.lower() not in lowered for marker in GENERIC_EVIDENCE_MARKERS)


def test_existing_read_only_intent_rendering_is_preserved() -> None:
    for intent in ("windows_status", "windows_doctor", "windows_evidence", "windows_processes"):
        rendered = _render_windows_read_only_intent(intent=intent, is_windows=True)
        assert "Windows metric limitations to expect:" in rendered
        assert "Load average is not available on Windows." in rendered


# ---------------------------------------------------------------------------
# 10-14. Native Windows REPL routing: no model, no diagnosis, no collector
# ---------------------------------------------------------------------------


def _fail_provider(*_: Any) -> Any:
    raise AssertionError("deterministic Windows service route reached the model provider")


def _forbidden(label: str) -> Any:
    def _raise(*_: Any, **__: Any) -> Any:
        raise AssertionError(f"deterministic Windows service route reached {label}")

    return _raise


def _run_windows_interactive(monkeypatch: Any, tmp_path: Any, transcript: str) -> Any:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Windows")
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    monkeypatch.setattr("shellforgeai.cli.build_provider", _fail_provider)
    monkeypatch.setattr(
        "shellforgeai.interactive.repl.diagnose_target", _forbidden("diagnose_target")
    )
    for collector in (
        "collect_host_evidence",
        "collect_health_evidence",
        "collect_performance_evidence",
        "collect_service_evidence",
    ):
        monkeypatch.setattr(f"shellforgeai.core.collectors.{collector}", _forbidden(collector))
    monkeypatch.setattr(
        "shellforgeai.interactive.repl.windows_services_payload",
        lambda *, max_services: {
            "status": "ok",
            "platform": {"system": "windows"},
            "read_only": True,
            "mutation_performed": False,
            "windows_v1": {"available": True},
            "services": {
                "total_count": 0,
                "state_counts": {},
                "runtime_summary": {},
                "items": [],
                "collection_limits": {"max_services": max_services, "truncated": False},
            },
            "next_safe_command": "shellforgeai windows status --json",
        },
    )
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context",
        _forbidden("the Windows evidence context builder"),
    )
    return runner.invoke(app, ["interactive", "--yes-trust", "--no-trust-cache"], input=transcript)


@pytest.mark.parametrize(
    "phrase",
    (
        "show service status",
        "what services are running",
        "are services healthy",
        "show me the services",
        "list services",
    ),
)
def test_native_windows_service_questions_route_before_generic_handling(
    monkeypatch: Any, tmp_path: Any, phrase: str
) -> None:
    res = _run_windows_interactive(monkeypatch, tmp_path, f"{phrase}\n/exit\n")
    out = res.stdout
    assert res.exception is None, out
    assert res.exit_code == 0, out
    assert "## Windows evidence" in out
    assert "Intent: windows_services" in out
    assert ux.WINDOWS_STANDARD_EVIDENCE_COMMAND in out
    assert "Deterministic evidence above is the authoritative current evidence." in out
    assert "Traceback" not in out
    lowered = out.lower()
    assert all(marker.lower() not in lowered for marker in GENERIC_EVIDENCE_MARKERS)
    assert ux.WINDOWS_STANDARD_EVIDENCE_COMMAND in out


def test_windows_service_route_leaves_no_model_or_codex_process(
    monkeypatch: Any, tmp_path: Any
) -> None:
    from shellforgeai.llm.codex import CodexProvider

    before = set(CodexProvider._active_procs)
    res = _run_windows_interactive(
        monkeypatch,
        tmp_path,
        "show service status\nwhat services are running\ncheck services\n/exit\n",
    )
    assert res.exception is None, res.stdout
    assert res.exit_code == 0, res.stdout
    assert "Traceback" not in res.stdout
    assert set(CodexProvider._active_procs) == before


def test_windows_service_mutation_requests_remain_refused(monkeypatch: Any, tmp_path: Any) -> None:
    res = _run_windows_interactive(
        monkeypatch,
        tmp_path,
        "restart Windows services\nstop the service\nclean up and restart services\n/exit\n",
    )
    out = res.stdout
    assert res.exception is None, out
    assert res.exit_code == 0, out
    assert out.count("Refused: natural-language mutation is not allowed.") == 3
    assert "Cleanup, restart, and service control are mutating/service-impacting" in out
    assert "No command was executed" in out
    assert "## Windows services guidance" not in out
    for marker in ("service restart executed", "cleanup executed", "rollback executed"):
        assert marker not in out


def test_linux_generic_service_prompt_is_not_rerouted_to_windows(
    monkeypatch: Any, tmp_path: Any
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Linux")
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="show service status\n/exit\n",
    )
    assert res.exit_code == 0
    assert "## Windows services guidance" not in res.stdout
    assert SERVICES_COMMAND not in res.stdout


def test_linux_explicit_windows_service_prompt_renders_unsupported_guidance_only(
    monkeypatch: Any, tmp_path: Any
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.interactive.repl.platform.system", lambda: "Linux")
    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", _fail_provider)
    monkeypatch.setattr("shellforgeai.cli.build_provider", _fail_provider)
    res = runner.invoke(
        app,
        ["interactive", "--yes-trust", "--no-trust-cache"],
        input="show Windows services\n/exit\n",
    )
    out = res.stdout
    assert res.exit_code == 0, out
    assert "## Windows services guidance" in out
    assert "Context: Windows guidance requested from a non-Windows host." in out
    assert "No Windows probing was performed." in out
    assert ux.WINDOWS_STANDARD_EVIDENCE_COMMAND in out
    assert "Traceback" not in out


# ---------------------------------------------------------------------------
# 14. Pending-context service ordering
# ---------------------------------------------------------------------------


def test_pending_context_after_service_route_is_service_first() -> None:
    ctx = _windows_interactive_pending_context(
        session_id="pr325-session",
        intent=ux.WINDOWS_OPERATOR_INTENT_SERVICES,
        source_command=SERVICES_COMMAND,
    )
    assert ctx.target == "windows-local-read-only"
    assert ctx.diagnosis_kind == "windows_services"
    assert ctx.source_command == SERVICES_COMMAND
    assert ctx.facts["visibility"] == "windows-local-read-only"
    assert ctx.deterministic_only is True
    assert ctx.model_assessment_status == "not_called"
    assert ctx.safe_next_commands[0] == SERVICES_COMMAND
    assert list(ctx.safe_next_commands) == list(
        ux.windows_operator_safe_commands(ux.WINDOWS_OPERATOR_INTENT_SERVICES)
    )
    assert "windows_services" in ctx.suggested_followup_categories
    rendered = render_latest_context_pending(ctx)
    assert "windows-local-read-only" in rendered
    assert "windows_services" in rendered
    services_index = rendered.index(SERVICES_COMMAND)
    for later in (
        "shellforgeai windows events --json --limit 50 --since-hours 24",
        "shellforgeai windows status --json",
        "shellforgeai windows doctor --json",
    ):
        assert services_index < rendered.index(later)
    for stale in (
        "shellforgeai triage docker",
        "remediation eligibility",
        "remediation self-test",
        "rollback",
        "recovery-execute",
    ):
        assert stale not in rendered


def test_existing_pending_context_ordering_is_unchanged() -> None:
    ctx = _windows_interactive_pending_context(
        session_id="pr325-session",
        intent="windows_status",
        source_command="shellforgeai windows status --json",
    )
    assert ctx.safe_next_commands[0] == ux.WINDOWS_STANDARD_EVIDENCE_COMMAND
    assert ctx.suggested_followup_categories == [
        "windows_status",
        "windows_doctor",
        "windows_evidence",
        "windows_processes",
    ]


# ---------------------------------------------------------------------------
# 15. Explicit interactive phrase routing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "phrase",
    ("Windows services", "show Windows services", "show me Windows services", "windows services"),
)
def test_explicit_windows_service_phrases_route_to_windows_read_only_intent(phrase: str) -> None:
    routed = route_input(phrase)
    assert routed.name == "windows_read_only_intent"
    assert routed.args == "windows_services"
    assert routed.argv == ("windows_services",)


@pytest.mark.parametrize(
    "phrase",
    (
        "restart Windows services",
        "stop Windows services",
        "clean up Windows services",
        "remediate Windows services",
    ),
)
def test_explicit_windows_service_mutation_phrases_are_refused_by_route_input(phrase: str) -> None:
    assert route_input(phrase).name == "mutation_refused"


def test_existing_explicit_windows_phrases_still_route() -> None:
    for phrase, intent in (
        ("windows status", "windows_status"),
        ("windows doctor", "windows_doctor"),
        ("windows evidence", "windows_evidence"),
        ("windows processes", "windows_processes"),
    ):
        routed = route_input(phrase)
        assert routed.name == "windows_read_only_intent"
        assert routed.args == intent
    assert route_input("windows processes limit 10").argv == ("windows_processes", "10")


def test_pr325_adds_no_cli_command_or_slash_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "windows-services" not in result.stdout
    commands_source = Path("src/shellforgeai/interactive/commands.py").read_text(encoding="utf-8")
    assert "/services" not in commands_source
    assert "/windows-services" not in commands_source


# ---------------------------------------------------------------------------
# 17. Source import / static safety boundaries
# ---------------------------------------------------------------------------


def test_pure_helper_has_no_execution_or_io_surface() -> None:
    helper = Path("src/shellforgeai/core/windows_operator_ux.py").read_text(encoding="utf-8")
    forbidden = (
        "sub" + "process",
        "os.system",
        "shell=True",
        "Power" + "Shell",
        "Win" + "RM",
        "W" + "MI",
        "C" + "IM",
        "winreg",
        "build_provider",
        "auth_cache",
        "credential",
        "secret",
        "token",
        "open(",
        "Path(",
        "requests",
        "urllib",
        "socket",
        "http",
        "sc.exe",
        "Set-Service",
        "Restart-Service",
    )
    assert not any(term in helper for term in forbidden)
    imports = sorted(line.strip() for line in helper.splitlines() if "import " in line)
    assert imports == [
        "from __future__ import annotations",
        "from dataclasses import dataclass",
        "from typing import Final",
        "import re",
    ]


def test_service_route_source_slice_is_read_only() -> None:
    helper = Path("src/shellforgeai/core/windows_operator_ux.py").read_text(encoding="utf-8")
    repl = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    commands = Path("src/shellforgeai/interactive/commands.py").read_text(encoding="utf-8")
    slice_ = "\n".join(
        line
        for line in (helper + repl + commands).splitlines()
        if "windows_services" in line or "WINDOWS_OPERATOR_INTENT_SERVICES" in line
    )
    assert slice_
    forbidden = (
        "sub" + "process",
        "os.system",
        "shell=True",
        "Power" + "Shell",
        "Win" + "RM",
        "W" + "MI",
        "C" + "IM",
        "winreg",
        "build_provider",
        "auth_cache",
        "credential",
        "secret",
        "diagnose_target",
        "collect_evidence",
    )
    assert not any(term in slice_ for term in forbidden)
    # Positive control: the guard would catch a real execution lane.
    assert "sub" + "process" in slice_ + "\nsubprocess.run(['sc', 'start'])\n"


def test_top_level_ask_and_collector_modules_are_untouched_by_the_service_route() -> None:
    ask = Path("src/shellforgeai/commands/ask.py").read_text(encoding="utf-8")
    assert "classify_windows_operator_intent" in ask
    assert "classify_windows_interactive_intent" not in ask
    assert "WINDOWS_OPERATOR_INTENT_SERVICES" not in ask
    repl = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    assert "classify_windows_interactive_intent" in repl
    collectors = Path("src/shellforgeai/core/collectors.py").read_text(encoding="utf-8")
    assert "WINDOWS_OPERATOR_INTENT_SERVICES" not in collectors
    services = Path("src/shellforgeai/windows_services.py").read_text(encoding="utf-8")
    assert "WINDOWS_OPERATOR_INTENT_SERVICES" not in services
    assert "classify_windows_interactive_intent" not in services
