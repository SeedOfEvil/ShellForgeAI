"""PR222 — model-backed ``ask`` is grounded in deterministic Docker evidence.

Docker/operator questions that reach the model-backed ``ask`` path must:

* explain/route from deterministic ShellForgeAI Docker triage evidence
  (top suspect, severity, confidence, evidence themes, safe next command),
* never emit unsupported or mutation-style command suggestions, and
* fall back to safe deterministic guidance when the model/auth is unavailable.

Broad mutation/auto-fix requests stay refused. These tests use a fake
deterministic triage scene and a fake model backend — no real Docker, no real
model/Codex auth, no network.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core import triage_ranking as triage_mod

runner = CliRunner()


# --- fixtures -------------------------------------------------------------


def _docker_scene() -> dict:
    """A realistic scene where ``beszel-agent`` is the unambiguous top suspect."""
    return {
        "containers": [
            {
                "name": "beszel-agent",
                "state": "restarting",
                "image": "henrygd/beszel-agent",
                "status": "Restarting (1) 5 seconds ago",
                "exit_code": 1,
                "restart_count": 9,
                "oom_killed": False,
                "health": None,
                "log_text": "\n".join(
                    [
                        "2026-06-19T02:00:01 CRITICAL boot failure: agent exited",
                        "2026-06-19T02:00:02 ERROR connect() to 127.0.0.1:45876 "
                        "failed (111: Connection refused)",
                        "2026-06-19T02:00:03 ERROR connect() to 127.0.0.1:45876 "
                        "failed (111: Connection refused)",
                    ]
                ),
            },
            {
                "name": "sfai-noisy-web",
                "state": "running",
                "image": "nginx",
                "status": "Up 3 minutes",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_text": "\n".join(
                    [
                        "2026-06-19T02:00:01 ERROR worker timeout after 30s",
                        "2026-06-19T02:00:02 ERROR worker timeout after 30s",
                        "2026-06-19T02:00:03 WARN queue depth high",
                    ]
                ),
            },
        ]
    }


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))


@pytest.fixture
def patched_scene(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _docker_scene())


@pytest.fixture
def empty_scene(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: {"containers": []})


class _FakeProvider:
    """Fake model backend; no real Codex/network. Configurable text/ok."""

    def __init__(self, text: str = "Here is what I see.", ok: bool = True):
        self._text = text
        self._ok = ok
        self.last_prompt: str | None = None
        self.completes = 0

    def complete(self, req):
        self.completes += 1
        self.last_prompt = req.prompt
        return SimpleNamespace(
            ok=self._ok,
            text=self._text if self._ok else "",
            provider="openai-codex",
            model="codex-fake",
            usage={
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "output_tokens": 5,
                "reasoning_output_tokens": 0,
            },
            error=None if self._ok else "not found on path: codex",
            raw=None,
        )


@pytest.fixture
def fake_provider(monkeypatch):
    holder = {"provider": _FakeProvider()}
    monkeypatch.setattr(cli_mod, "build_provider", lambda *_a, **_k: holder["provider"])
    return holder


def _set_provider(holder, **kwargs) -> _FakeProvider:
    holder["provider"] = _FakeProvider(**kwargs)
    return holder["provider"]


def _ask(question: str):
    out = runner.invoke(app, ["ask", question])
    return out


def _expected_top() -> dict:
    ranked = triage_mod.rank_scene(_docker_scene())
    return ranked["suspects"][0]


UNSUPPORTED = (
    "shellforgeai diagnose beszel-agent",
    "shellforgeai fix docker",
    "shellforgeai restart compose",
    "shellforgeai cleanup docker",
    "shellforgeai prune docker",
    "docker system prune",
    "docker compose restart",
    "docker image rm",
)


def test_docker_ask_emits_registry_backed_safe_detail_command(patched_scene, fake_provider):
    out = _ask("why is beszel-agent suspicious?")
    assert out.exit_code == 0, out.stdout
    assert "Safe next step:" in out.stdout
    assert "shellforgeai triage docker detail beszel-agent --json" in out.stdout
    assert "Top suspect: beszel-agent" in out.stdout


def test_fake_model_unsupported_command_is_filtered_before_final_output(
    patched_scene, fake_provider
):
    _set_provider(
        fake_provider,
        text=(
            "Run shellforgeai diagnose beszel-agent, then shellforgeai fix docker, "
            "then docker system prune and docker compose restart."
        ),
    )
    out = _ask("why is beszel-agent suspicious?")
    assert out.exit_code == 0, out.stdout
    for command in UNSUPPORTED:
        assert command not in out.stdout
    assert "shellforgeai triage docker detail beszel-agent --json" in out.stdout


def test_missing_evidence_emits_registry_evidence_gathering_command(empty_scene, fake_provider):
    out = _ask("why is beszel-agent suspicious?")
    assert out.exit_code == 0, out.stdout
    assert "shellforgeai triage docker --json" in out.stdout
    assert "shellforgeai diagnose" not in out.stdout


def test_broad_cleanup_restart_ask_is_refused_and_suggests_no_mutation(fake_provider):
    out = _ask("Clean up docker and restart compose to fix it")
    assert out.exit_code == 0, out.stdout
    lowered = out.stdout.lower()
    assert "cannot" in lowered or "can't" in lowered or "refus" in lowered
    for command in UNSUPPORTED:
        assert command not in out.stdout
    assert "no restart, cleanup" in lowered and "executed" in lowered
    assert "shellforgeai ops report --brief" in out.stdout


def test_docker_ask_safety_flags_remain_read_only_no_mutation(patched_scene, fake_provider):
    out = _ask("why is beszel-agent suspicious?")
    assert out.exit_code == 0, out.stdout
    lowered = out.stdout.lower()
    assert "no cleanup, restart, remediation, rollback, or docker mutation was performed" in lowered
    for command in UNSUPPORTED:
        assert command not in out.stdout
