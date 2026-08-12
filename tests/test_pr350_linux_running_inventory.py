from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core import collectors
from shellforgeai.core.ask_routing import EVIDENCE_BACKED, route_ask_intent
from shellforgeai.core.evidence import EvidenceBundle, EvidenceCategory, EvidenceItem, TargetType
from shellforgeai.interactive.commands import route_input


def _prompts() -> tuple[str, ...]:
    contract = json.loads(Path("config/operator_parity_v1.json").read_text(encoding="utf-8"))
    scenario = next(s for s in contract["scenarios"] if s["id"] == "running_system_inventory")
    return tuple(v["prompt"] for v in scenario["variants"])


@pytest.mark.parametrize("prompt", _prompts())
def test_authoritative_inventory_prompts_use_one_bounded_route(prompt: str) -> None:
    interactive = route_input(prompt)
    ask = route_ask_intent(prompt)
    assert (interactive.name, interactive.args) == ("diagnose", "running_inventory")
    assert (ask.mode, ask.target, ask.intent_label) == (
        EVIDENCE_BACKED,
        "running_inventory",
        "running_inventory",
    )
    assert ask.mutation_request is False


@pytest.mark.parametrize(
    ("prompt", "target"),
    (
        ("What services are running?", "services"),
        ("Show running services.", "services"),
        ("List services.", "services"),
        ("Is Docker running?", "docker"),
        ("Show Docker suspects.", "docker"),
        ("How much disk space is left?", "disk"),
        ("Check disk usage.", "disk"),
        ("What processes are using CPU?", "performance"),
        ("Check network.", "network"),
    ),
)
def test_inventory_matcher_does_not_steal_narrow_routes(prompt: str, target: str) -> None:
    assert route_ask_intent(prompt).target == target


def test_inventory_matcher_preserves_plain_and_refusal_routes() -> None:
    assert route_ask_intent("Explain what a process is.").mode != EVIDENCE_BACKED
    assert route_input("Can you restart nginx for me?").name == "diagnose"
    assert route_ask_intent("Can you restart nginx for me?").mutation_request is True


def test_process_inventory_preserves_count_and_adds_structured_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        collectors,
        "collect_service_evidence",
        lambda *_: [
            EvidenceItem(
                source="process.snapshot",
                category=EvidenceCategory.host,
                title="Process snapshot",
                summary="processes=7 running=1 sleeping=6 zombies=0",
                content="processes=7 running=1 sleeping=6 zombies=0",
            )
        ],
    )
    monkeypatch.setattr(collectors, "collect_docker_evidence", lambda *_: [])
    item = collectors.collect_running_inventory_evidence(SimpleNamespace())[0]
    assert "processes=7" in item.content
    assert item.metadata == {
        "observation_scope": "point_in_time",
        "collector": "ps",
        "observer_effect": True,
        "count_adjusted": False,
    }


@pytest.mark.parametrize("docker_available", [True, False])
def test_ask_inventory_is_evidence_first_and_survives_provider_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path, docker_available: bool
) -> None:
    calls: list[str] = []
    rendered: list[str] = []

    class Output:
        def flush(self) -> None:
            calls.append("flush")

    class Console:
        file = Output()

        def print(self, value: Any, **_kwargs: Any) -> None:
            text = str(value)
            rendered.append(text)
            calls.append("evidence" if "## Linux" in text else "output")

    class Provider:
        attempts = 0

        def complete(self, _request: Any) -> Any:
            self.attempts += 1
            calls.append("provider")
            assert calls.index("evidence") < calls.index("flush") < calls.index("provider")
            return SimpleNamespace(ok=False, text="", error="offline", metadata={})

    items = [
        EvidenceItem(
            source="process.snapshot",
            category=EvidenceCategory.host,
            title="Process snapshot",
            summary="processes=7 running=1 sleeping=6 zombies=0",
            content="processes=7 running=1 sleeping=6 zombies=0",
        ),
        EvidenceItem(
            source="service.manager_detect",
            category=EvidenceCategory.service,
            title="Service manager",
            summary="manager=systemd",
            content="manager=systemd",
        ),
        EvidenceItem(
            source="docker.containers",
            category=EvidenceCategory.host,
            title="Container inventory",
            summary="observed containers",
            content="[]",
            ok=docker_available,
        ),
    ]
    diagnosis = SimpleNamespace(
        session_id="pr350",
        evidence=EvidenceBundle(
            target="running_inventory", target_type=TargetType.generic, items=items
        ),
        findings=[SimpleNamespace(title="Observed inventory", detail="bounded facts")],
        safe_next_commands=[],
    )
    provider = Provider()
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(cli_mod, "console", Console())
    monkeypatch.setattr(cli_mod, "diagnose_target", lambda *_args, **_kwargs: diagnosis)
    monkeypatch.setattr(cli_mod, "build_provider", lambda *_: provider)

    result = CliRunner().invoke(app, ["ask", _prompts()[0]])
    assert result.exit_code == 1
    assert provider.attempts == 1
    assert calls.count("provider") == 1
    assert calls[:3] == ["evidence", "flush", "provider"]
    evidence = rendered[0]
    assert "point-in-time ps measurements" in evidence
    assert "does not subtract or guess" in evidence
    assert "not every service unit" in evidence
    assert "shellforgeai ops report" in evidence
    assert (
        "bounded to the maintained Docker inventory" in evidence
        if docker_available
        else "Container visibility is unavailable" in evidence
    )
    assert "deterministic evidence above remains" in "\n".join(rendered).lower()


def test_inventory_safe_next_is_a_maintained_read_only_command() -> None:
    from shellforgeai.core.evidence_first_response import (
        EvidenceFirstResponse,
        render_evidence_first,
    )

    rendered = render_evidence_first(
        EvidenceFirstResponse(
            platform="Linux",
            evidence_label="running inventory evidence",
            evidence_source="typed collectors",
            intent="running_inventory",
            evidence_available=True,
            limitations=("point in time", "bounded visibility"),
            safe_next_commands=("shellforgeai ops report",),
        )
    )
    assert "Safe next step:\nshellforgeai ops report" in rendered
