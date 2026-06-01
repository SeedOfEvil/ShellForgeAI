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
        "Status:",
        "Risk:",
        "First safe command:",
        "Safety: Read-only. No mutation executed.",
    ):
        assert section in out.stdout


def test_status_json_schema_and_safety(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["status", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    for key in (
        "schema_version",
        "mode",
        "status",
        "read_only",
        "mutation_performed",
        "summary",
        "suspects",
        "safety",
        "first_safe_command",
    ):
        assert key in payload
    assert payload["schema_version"] == "1"
    assert payload["mode"] == "status"
    assert payload["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True


def test_status_json_stays_read_only_when_audit_metadata_exists(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    p = tmp_path / "audit" / "events.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"event_id": "evt_1"}) + "\n", encoding="utf-8")
    out = runner.invoke(app, ["status", "--json"])
    payload = json.loads(out.stdout)
    assert payload["mode"] == "status"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_ask_status_routes_without_model(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["ask", "is ShellForgeAI healthy?"])
    assert out.exit_code == 0
    assert "Read-only status" in out.stdout
    assert "First safe command" in out.stdout
