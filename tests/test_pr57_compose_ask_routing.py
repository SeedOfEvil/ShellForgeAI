from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.ask_routing import extract_compose_target

runner = CliRunner()


def test_extract_compose_target_supported_forms() -> None:
    assert extract_compose_target("compose context for shellforgeai") == "shellforgeai"
    assert extract_compose_target("show compose context for shellforgeai") == "shellforgeai"
    assert extract_compose_target("what compose project owns shellforgeai?") == "shellforgeai"
    assert extract_compose_target("what compose service is shellforgeai?") == "shellforgeai"
    assert extract_compose_target("is shellforgeai compose managed?") == "shellforgeai"
    assert extract_compose_target("compose context for 'shellforgeai'") == "shellforgeai"
    assert extract_compose_target('compose context for "shellforgeai"') == "shellforgeai"


def test_extract_compose_target_rejects_unsafe_tokens() -> None:
    assert extract_compose_target("compose context for") == ""
    assert extract_compose_target("compose context for shellforgeai;rm -rf /") == ""
    assert extract_compose_target("compose context for shellforgeai\nextra") == ""


def test_ask_compose_context_success(monkeypatch) -> None:
    payload = {
        "container": "shellforgeai",
        "compose": {
            "detected": True,
            "project": "shellforgeai",
            "service": "shellforgeai",
            "working_dir": "/srv/compose/shellforgeai",
            "config_files": ["/srv/compose/shellforgeai/compose.yml"],
            "compose_version": "2.40.3",
            "oneoff": False,
        },
    }

    class _Res:
        ok = True
        stdout = json.dumps(payload)

    monkeypatch.setattr("shellforgeai.cli.containers.inspect", lambda target: _Res())
    res = runner.invoke(app, ["ask", "compose context for shellforgeai"])
    assert res.exit_code == 0
    assert "Compose context for `shellforgeai`:" in res.stdout
    assert "- Compose-managed: yes" in res.stdout
    assert "- Safety: read-only; no docker compose command was executed" in res.stdout


def test_ask_compose_context_missing_target_suggests_safe_cli() -> None:
    res = runner.invoke(app, ["ask", "compose context for"])
    assert res.exit_code == 0
    assert "No compose target found" in res.stdout
    assert "shellforgeai compose inspect <container>" in res.stdout


def test_ask_compose_context_mutation_refused() -> None:
    res = runner.invoke(app, ["ask", "docker compose restart shellforgeai"])
    assert res.exit_code == 0
    assert "Refusing natural-language Compose mutation" in res.stdout
    assert "Compose context is read-only" in res.stdout
