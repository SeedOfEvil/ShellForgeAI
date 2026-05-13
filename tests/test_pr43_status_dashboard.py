import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def test_status_text_sections(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["status"])
    assert out.exit_code == 0
    for section in (
        "ShellForgeAI",
        "Model",
        "Safety",
        "Latest activity",
        "Approvals",
        "Guards / drift",
        "Audit / index",
        "Next suggested read-only actions",
    ):
        assert section in out.stdout


def test_status_json_schema_and_safety(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["status", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    for key in (
        "schema_version",
        "created_at",
        "shellforgeai",
        "model",
        "safety",
        "latest",
        "approvals",
        "guards",
        "audit",
        "retention",
        "recommendations",
    ):
        assert key in payload
    assert payload["schema_version"] == "1"
    assert payload["safety"]["execution_allowed"] is False
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["execution_status"] == "not_executed"


def test_status_attention_when_safety_violation_seen(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    p = tmp_path / "audit" / "events.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(
            {
                "event_id": "evt_1",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "kind": "ask",
                "action": "checked",
                "status": "success",
                "summary": "bad",
                "safety": {
                    "execution_allowed": True,
                    "execution_status": "not_executed",
                    "mutation_performed": False,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = runner.invoke(app, ["status", "--json"])
    payload = json.loads(out.stdout)
    assert payload["health_level"] == "attention"


def test_ask_status_routes_without_model(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["ask", "is ShellForgeAI healthy?"])
    assert out.exit_code == 0
    assert "status dashboard" in out.stdout
    assert "pending approvals" in out.stdout
