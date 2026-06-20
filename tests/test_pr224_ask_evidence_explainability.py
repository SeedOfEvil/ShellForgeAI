"""PR224 — ask evidence explainability for Docker/operator answers.

Uses fake deterministic Docker evidence and a fake model backend. No real
Docker, model auth, network, or mutation is required.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core import triage_ranking as triage_mod
from shellforgeai.core.safe_commands import is_known_safe_shellforgeai_command

runner = CliRunner()

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


def _docker_scene() -> dict:
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
                        "CRITICAL boot failure: agent exited",
                        "ERROR connect() failed (111: Connection refused)",
                        "ERROR connect() failed (111: Connection refused)",
                    ]
                ),
            }
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
    def __init__(self, *, ok: bool = True, text: str = "Model summary from evidence.") -> None:
        self.ok = ok
        self.text = text

    def complete(self, req):
        return SimpleNamespace(
            ok=self.ok,
            text=self.text if self.ok else "",
            provider="fake",
            model="fake-model",
            usage={},
            error=None if self.ok else "auth failed",
            raw=None,
        )


@pytest.fixture
def fake_provider(monkeypatch):
    holder = {"provider": _FakeProvider()}
    monkeypatch.setattr(cli_mod, "build_provider", lambda *_a, **_k: holder["provider"])
    return holder


def _ask(*args: str):
    return runner.invoke(app, ["ask", *args])


def _expected_top() -> dict:
    return triage_mod.rank_scene(_docker_scene())["suspects"][0]


def test_explain_evidence_section_includes_used_sources_and_actual_fields(
    patched_scene, fake_provider
) -> None:
    top = _expected_top()
    out = _ask("why is beszel-agent suspicious?", "--explain-evidence")
    assert out.exit_code == 0, out.stdout
    assert "Evidence used:" in out.stdout
    assert "Docker triage evidence: used" in out.stdout
    assert "Docker status / ops report: used" in out.stdout
    assert f"Top suspect: {top['name']}" in out.stdout
    assert f"Severity: {top['severity']}" in out.stdout
    assert f"Confidence: {top['confidence']}" in out.stdout
    assert "Evidence themes:" in out.stdout
    assert "log error signal" in out.stdout or "restart churn" in out.stdout
    assert "Safe next command:" in out.stdout
    safe = "shellforgeai triage docker detail beszel-agent --json"
    assert safe in out.stdout
    assert is_known_safe_shellforgeai_command(safe)
    assert "No cleanup performed." in out.stdout
    assert "No restart performed." in out.stdout
    assert "No remediation performed." in out.stdout
    assert "No Docker/Compose mutation performed." in out.stdout


def test_missing_evidence_explanation_suggests_registry_gathering_command(
    empty_scene, fake_provider
) -> None:
    out = _ask("why is beszel-agent suspicious?", "--explain-evidence")
    assert out.exit_code == 0, out.stdout
    assert "Docker triage evidence: missing" in out.stdout
    assert "Docker status / ops report: missing" in out.stdout
    assert "To gather evidence, run:" in out.stdout
    safe = "shellforgeai triage docker --json"
    assert safe in out.stdout
    assert is_known_safe_shellforgeai_command(safe)
    explain = out.stdout.split("Evidence used:", 1)[1]
    assert "Top suspect:" not in explain
    assert "No diagnosis guessed without deterministic evidence." in out.stdout


def test_explain_evidence_filters_unsupported_commands_from_model_output(
    patched_scene, fake_provider
) -> None:
    fake_provider["provider"] = _FakeProvider(
        text=(
            "Try shellforgeai diagnose beszel-agent then shellforgeai fix docker "
            "and docker system prune and docker compose restart."
        )
    )
    out = _ask("why is beszel-agent suspicious?", "--explain-evidence")
    assert out.exit_code == 0, out.stdout
    for command in UNSUPPORTED:
        assert command not in out.stdout
    assert "shellforgeai triage docker detail beszel-agent --json" in out.stdout


def test_mutation_request_remains_refused_with_explain_evidence(fake_provider) -> None:
    out = _ask("Clean up docker and restart compose to fix it", "--explain-evidence")
    assert out.exit_code == 0, out.stdout
    low = out.stdout.lower()
    assert "refus" in low or "will not execute" in low
    assert "safe read-only next command" in low or "to gather evidence" in low
    assert "No cleanup performed." in out.stdout
    assert "No restart performed." in out.stdout
    assert "No remediation performed." in out.stdout
    for command in UNSUPPORTED:
        assert command not in out.stdout


def test_model_auth_failure_still_prints_deterministic_explanation(
    patched_scene, fake_provider
) -> None:
    fake_provider["provider"] = _FakeProvider(ok=False)
    out = _ask("why is beszel-agent suspicious?", "--explain-evidence")
    assert out.exit_code == 0, out.stdout
    assert "Evidence used:" in out.stdout
    assert "Docker triage evidence: used" in out.stdout
    assert "Top suspect: beszel-agent" in out.stdout
    assert "shellforgeai model doctor --json" in out.stdout
    for command in UNSUPPORTED:
        assert command not in out.stdout
