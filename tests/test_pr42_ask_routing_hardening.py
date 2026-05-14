from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import _is_retention_ask, app
from shellforgeai.core.export_pack import is_export_intent
from shellforgeai.core.incident_index import is_incident_search_ask_intent

runner = CliRunner()


def test_retention_phrases_route_internally() -> None:
    assert _is_retention_ask("audit retention status")
    assert _is_retention_ask("show audit retention")
    assert _is_retention_ask("show retention report")
    assert _is_retention_ask("how much audit data do I have")


def test_host_auditd_phrases_do_not_route_to_retention() -> None:
    assert not _is_retention_ask("auditd status")
    assert not _is_retention_ask("Linux audit logs")
    assert not _is_retention_ask("/var/log/audit errors")
    assert not _is_retention_ask("audit status")


def test_ask_dry_run_cleanup_never_deletes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    f = tmp_path / "exports" / "old-pack.json"
    f.parent.mkdir(parents=True)
    f.write_text("x", encoding="utf-8")
    out = runner.invoke(app, ["ask", "what can I safely prune"])
    assert out.exit_code == 0
    assert "Dry-run only" in out.stdout
    assert "shellforgeai audit prune --dry-run" in out.stdout
    assert f.exists()


def test_ask_retention_status_shows_cli_hint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "e1.json").write_text("x", encoding="utf-8")
    out = runner.invoke(app, ["ask", "audit retention status"])
    assert out.exit_code == 0
    assert "ShellForgeAI metadata hygiene summary" in out.stdout
    assert "shellforgeai audit retention" in out.stdout
    assert "No deletion was performed" in out.stdout


def test_incident_and_export_phrase_intents_cover_pr42_examples() -> None:
    assert is_incident_search_ask_intent("search audit for bad-network").matched
    assert is_incident_search_ask_intent("show audit timeline").matched
    ex = is_export_intent("create a redacted audit pack")
    assert ex.matched and ex.prefer_redact
    assert is_export_intent("package this for external sharing").matched
