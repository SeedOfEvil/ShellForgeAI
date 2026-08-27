"""PR378 native Windows support and running-inventory routing truth."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_module
from shellforgeai.cli import app
from shellforgeai.core import ask_docker_grounding as docker_grounding_module
from shellforgeai.core import command_suggestions as command_suggestions_module
from shellforgeai.core import windows_operator_ux as ux
from shellforgeai.platform_detection import PlatformInfo, platform_doctor_payload

PROMPT = "Which running items deserve attention and why?"


def _windows_info() -> PlatformInfo:
    return PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")


def test_native_windows_platform_doctor_is_consistently_supported_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "shellforgeai.platform_detection.platform.win32_ver", lambda: ("", "", "", "")
    )
    monkeypatch.setattr("shellforgeai.platform_detection.shutil.which", lambda _name: None)
    payload = platform_doctor_payload(_windows_info())

    assert payload["status"] == "ok"
    assert payload["support"] == {
        "supported": True,
        "lane": "windows_read_only_doctor_v1",
        "windows_v1_available": True,
        "windows_read_only_doctor_available": True,
        "linux_docker_available": False,
    }
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    evidence = payload["windows_evidence"]
    assert evidence["read_only"] is True
    assert evidence["mutation_performed"] is False
    assert evidence["unsupported_or_limited"]
    assert evidence["windows_version"]["status"] == "limited"


def test_windows_platform_doctor_human_output_agrees_and_is_cp1252_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "shellforgeai.commands.platform.platform_doctor_payload",
        lambda: platform_doctor_payload(_windows_info()),
    )
    result = CliRunner().invoke(app, ["platform", "doctor"])
    assert result.exit_code == 0
    assert "Status: ok" in result.stdout
    assert "Lane: windows_read_only_doctor_v1" in result.stdout
    assert "bounded Windows read-only V1 lane is available" in result.stdout
    assert "unsupported" not in result.stdout.casefold()
    result.stdout.encode("cp1252", errors="strict")


@pytest.mark.parametrize(
    ("text", "system", "expected"),
    [
        (PROMPT, "Windows", ux.WINDOWS_OPERATOR_INTENT_RUNNING_INVENTORY),
        (PROMPT, "Linux", None),
        ("Which running Docker containers deserve attention and why?", "Windows", None),
        ("Which running systemd services deserve attention and why?", "Windows", None),
    ],
)
def test_exact_analytical_prompt_preserves_platform_scope(
    text: str, system: str, expected: str | None
) -> None:
    route = ux.classify_windows_operator_intent(text, host_system=system)
    assert (route.intent if route else None) == expected


def test_running_inventory_mutation_is_refused_before_advisory() -> None:
    route = ux.classify_windows_operator_intent(
        "Which running items deserve attention and then restart them?", host_system="Windows"
    )
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL


def test_running_inventory_mutation_refusal_does_no_downstream_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        pytest.fail("refusal must precede evidence, model, recipe, preflight, and execution")

    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context", forbidden
    )
    monkeypatch.setattr("shellforgeai.cli.build_provider", forbidden)
    result = CliRunner().invoke(
        app, ["ask", "Which running items deserve attention and then restart them?"]
    )

    assert result.exit_code == 0
    assert result.stdout.startswith("Refused: natural-language mutation is not allowed.")
    assert "No command was executed. No action was taken." in result.stdout
    assert "No cleanup, restart, service control, process termination" in result.stdout


def test_ask_exact_prompt_uses_existing_windows_packet_and_label(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls: list[str] = []
    requests = []
    packet = {
        "platform": "windows",
        "visibility": "windows-local-read-only",
        "read_only": True,
        "mutation_performed": False,
        "host": {},
        "platform_detail": {},
        "memory": {"available": False},
        "disk": {"available": False},
        "processes": {"available": False},
        "services": {"available": False},
        "events": {"available": False},
        "network": {"available": False},
        "volumes": {"available": False},
        "limitations": ["bounded"],
        "evidence_gaps": [],
        "safe_next_commands": [],
    }

    class Provider:
        def complete(self, request):
            calls.append("model")
            requests.append(request)
            assert "Container inventory is not collected" in request.prompt
            return type(
                "Response",
                (),
                {
                    "ok": True,
                    "text": "Bounded Windows assessment.",
                    "provider": "fake",
                    "model": "fake",
                    "raw": {},
                    "error": None,
                    "usage": None,
                },
            )()

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        docker_grounding_module,
        "build_docker_evidence_context",
        lambda: pytest.fail("native Windows inventory must not build Docker evidence"),
    )
    monkeypatch.setattr(
        command_suggestions_module,
        "filter_unsupported_command_suggestions",
        lambda *_args, **_kwargs: pytest.fail(
            "native Windows inventory must not enter Docker command filtering"
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "_emit_docker_grounding_answer",
        lambda *_args, **_kwargs: pytest.fail(
            "native Windows inventory must not emit or audit Docker grounding"
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context",
        lambda: calls.append("evidence") or packet,
    )
    monkeypatch.setattr("shellforgeai.cli.build_provider", lambda *_: Provider())
    result = CliRunner().invoke(app, ["ask", PROMPT])

    assert result.exit_code == 0, result.stdout
    assert calls == ["evidence", "model"]
    assert len(requests) == 1
    prompt = requests[0].prompt
    assert "Windows host and uses Windows-local read-only evidence" in prompt
    assert "Container inventory is not collected" in prompt
    assert "deterministic_docker_evidence" not in prompt
    assert "Docker triage evidence" not in prompt
    assert "using current ShellForgeAI Docker triage evidence" not in prompt
    assert "Intent: Windows running-system inventory" in result.stdout
    assert "Intent: Docker" not in result.stdout
    assert packet["read_only"] is True
    assert packet["mutation_performed"] is False
    json.dumps(packet)  # packet remains JSON-compatible
    audit_path = tmp_path / "audit" / "events.jsonl"
    audit_rows = (
        [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
        if audit_path.exists()
        else []
    )
    assert not any(row.get("action") == "docker_evidence_grounded" for row in audit_rows)
    assert not any(
        (row.get("details") or {}).get("operation") == "docker_evidence_grounded"
        or (row.get("details") or {}).get("topic") == "docker grounding"
        for row in audit_rows
    )


def test_linux_same_prompt_retains_pr222_docker_grounding(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls: list[str] = []
    original_builder = docker_grounding_module.build_docker_evidence_context

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("shellforgeai.commands.ask.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "shellforgeai.core.windows_evidence_context.build_windows_evidence_context",
        lambda: pytest.fail("Linux Docker grounding must not build Windows evidence"),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene", lambda: {"containers": []}
    )
    monkeypatch.setattr(
        docker_grounding_module,
        "build_docker_evidence_context",
        lambda: calls.append("docker_evidence") or original_builder(),
    )

    class Provider:
        def complete(self, request):
            calls.append("model")
            return type(
                "Response",
                (),
                {
                    "ok": True,
                    "text": "No deterministic suspect is currently available.",
                    "provider": "fake",
                    "model": "fake",
                    "raw": {},
                    "error": None,
                    "usage": None,
                },
            )()

    monkeypatch.setattr(cli_module, "build_provider", lambda *_: Provider())
    result = CliRunner().invoke(app, ["ask", PROMPT])

    assert result.exit_code == 0, result.stdout
    assert calls == ["docker_evidence", "model"]
    events = (tmp_path / "audit" / "events.jsonl").read_text(encoding="utf-8")
    rows = [json.loads(line) for line in events.splitlines() if line.strip()]
    assert any(row.get("action") == "docker_evidence_grounded" for row in rows)
    assert "Intent: Windows" not in result.stdout
