"""PR28 follow-up #2: theme polish + healthy-web target_container_status.

- Confirms busybox-style "bad address" / "wget: ..." log lines classify as
  network themes (so sfai-bad-network's logs don't slip past the brief).
- Confirms target_container_status surfaces sfai-healthy-web from
  docker.containers + docker.problem_summary so the model does not fall
  back to a local nginx process check.
- Confirms ask "is the healthy web service okay?" routes through Docker and
  carries a target_container_status block in the prompt.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.ask_routing import (
    extract_container_target,
    target_container_status,
)
from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem
from shellforgeai.interactive.commands import route_input
from shellforgeai.tools import containers

runner = CliRunner()


# ---------- theme classification: busybox-style ----------


@pytest.mark.parametrize(
    "line",
    [
        "wget: bad address 'upstream.invalid'",
        "ping: bad address 'upstream.invalid'",
        "ERROR bad address",
        "name resolution failed",
        "unable to resolve upstream.invalid",
    ],
)
def test_busybox_dns_lines_classify_dns_failure(line: str) -> None:
    themes = containers._classify_log(line)
    assert themes.get("dns_failure", 0) >= 1, line


@pytest.mark.parametrize(
    "line",
    [
        "wget: download timed out",
        "wget: can't connect to remote host",
        "curl: (7) Failed to connect",
        "broken pipe",
    ],
)
def test_unknown_network_error_lines_classify(line: str) -> None:
    themes = containers._classify_log(line)
    assert themes.get("unknown_network_error", 0) >= 1, line


# ---------- routing: healthy-web ----------


def test_healthy_web_routes_to_docker():
    cmd = route_input("is the healthy web service okay?")
    assert cmd.name == "diagnose"
    assert cmd.args == "docker"


def test_extract_target_for_healthy_web():
    assert extract_container_target("is the healthy web service okay?") == "sfai-healthy-web"
    assert extract_container_target("check sfai-healthy-web") == "sfai-healthy-web"


# ---------- target_container_status helper ----------


def _items_for_healthy_web() -> list[EvidenceItem]:
    inv = {
        "containers": [
            {
                "id": "abc",
                "name": "sfai-healthy-web",
                "image": "nginx:alpine",
                "status": "Up 5 minutes (healthy)",
                "state": "running",
                "running_for": "5 minutes",
                "labels": "expected=healthy",
            },
            {
                "id": "def",
                "name": "sfai-bad-network",
                "image": "busybox:latest",
                "status": "Up 5 minutes",
                "state": "running",
                "running_for": "5 minutes",
                "labels": "expected=dns-upstream-failure",
            },
        ],
        "total": 2,
    }
    summary = {
        "available": True,
        "total": 2,
        "failing": [],
        "noisy": [
            {
                "name": "sfai-bad-network",
                "state": "running",
                "exit_code": 0,
                "log_themes": {"dns_failure": 4},
                "log_sample": ["wget: bad address 'upstream.invalid'"],
            }
        ],
    }
    return [
        EvidenceItem(
            source="docker.containers",
            category=EvidenceCategory.host,
            ok=True,
            title="Container inventory",
            summary="docker containers=2 running=2 exited=0 restarting=0",
            content=json.dumps(inv),
        ),
        EvidenceItem(
            source="docker.problem_summary",
            category=EvidenceCategory.logs,
            ok=True,
            title="Container problem summary",
            summary="docker_total=2 failing=0 noisy=1",
            content=json.dumps(summary),
        ),
    ]


def test_target_container_status_healthy_web():
    items = _items_for_healthy_web()
    status = target_container_status(items, "sfai-healthy-web")
    assert status is not None
    assert status["name"] == "sfai-healthy-web"
    assert status["image"] == "nginx:alpine"
    assert status["state"] == "running"
    assert status["health"] == "healthy"
    assert status["bucket"] == "healthy"
    assert status["log_themes"] == []


def test_target_container_status_bad_network_themes():
    items = _items_for_healthy_web()
    status = target_container_status(items, "sfai-bad-network")
    assert status is not None
    assert status["state"] == "running"
    assert status["bucket"] == "noisy"
    assert "dns_resolution" in status["log_themes"]
    assert any("bad address" in line for line in status["log_sample"])


def test_target_container_status_returns_none_when_unknown():
    items = _items_for_healthy_web()
    assert target_container_status(items, "sfai-does-not-exist") is None
    assert target_container_status(items, "") is None


def test_target_container_status_returns_none_without_inventory():
    assert target_container_status([], "sfai-healthy-web") is None


# ---------- CLI integration: healthy-web ----------


class _FakeProvider:
    def __init__(self):
        self.last_prompt = None

    def complete(self, req):
        self.last_prompt = req.prompt
        return SimpleNamespace(
            ok=True,
            text="ok answer",
            provider="openai-codex",
            model="codex-fake",
            usage={
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "output_tokens": 5,
                "reasoning_output_tokens": 0,
            },
            error=None,
            raw=None,
        )


@pytest.fixture
def patch_provider(monkeypatch):
    holder = {"provider": _FakeProvider()}
    monkeypatch.setattr("shellforgeai.cli.build_provider", lambda *a, **k: holder["provider"])
    return holder


def _diag_with_inventory():
    items = _items_for_healthy_web()
    return SimpleNamespace(
        session_id="sess-hw",
        target="docker",
        target_type=SimpleNamespace(value="generic"),
        findings=[],
        evidence=SimpleNamespace(
            items=items,
            model_dump_json=lambda indent=2: json.dumps({"items": []}),
        ),
        proposed_plan=SimpleNamespace(model_dump_json=lambda indent=2: "{}"),
        warnings=[],
        errors=[],
    )


def test_ask_healthy_web_carries_status_in_prompt(monkeypatch, patch_provider):
    monkeypatch.setattr("shellforgeai.cli.diagnose_target", lambda *a, **k: _diag_with_inventory())
    res = runner.invoke(app, ["ask", "is the healthy web service okay?"])
    assert res.exit_code == 0, res.stdout
    prompt = patch_provider["provider"].last_prompt or ""
    assert "sfai-healthy-web" in prompt
    assert "nginx:alpine" in prompt
    assert "healthy" in prompt
    assert "target_container_status" in prompt
    assert "do NOT fall back to a local-process check" in prompt


def test_ask_bad_network_carries_status_and_themes(monkeypatch, patch_provider):
    monkeypatch.setattr("shellforgeai.cli.diagnose_target", lambda *a, **k: _diag_with_inventory())
    monkeypatch.setattr("shellforgeai.core.collectors.collect_network_evidence", lambda _ctx: [])
    res = runner.invoke(app, ["ask", "why is bad-network failing?"])
    assert res.exit_code == 0, res.stdout
    prompt = patch_provider["provider"].last_prompt or ""
    assert "sfai-bad-network" in prompt
    assert "dns_resolution" in prompt
    assert "target_container_status" in prompt
    # Reachability brief still present.
    assert "container_log_evidence" in prompt
