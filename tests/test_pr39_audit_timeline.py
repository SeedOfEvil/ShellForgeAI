import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.cli import app

runner = CliRunner()


def test_event_writer_defaults(tmp_path: Path):
    s = AuditStorage(tmp_path)
    e1 = s.write_event(kind="ask", action="checked", status="success", summary="a")
    e2 = s.write_event(kind="ask", action="checked", status="success", summary="b")
    assert e1["event_id"] != e2["event_id"]
    assert e1["safety"]["execution_allowed"] is False
    assert e1["safety"]["execution_status"] == "not_executed"


def test_timeline_and_filters(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    s = AuditStorage(tmp_path)
    s.write_event(
        kind="diagnose", action="created", status="success", session_id="sf_1", summary="d"
    )
    s.write_event(
        kind="approval", action="approved", status="success", proposal_id="prop_1", summary="a"
    )

    out = runner.invoke(app, ["audit", "timeline", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert len(payload) == 2

    out2 = runner.invoke(app, ["audit", "timeline", "--kind", "approval"])
    assert "approval" in out2.stdout
    assert "diagnose" not in out2.stdout


def test_audit_show_and_validate(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    s = AuditStorage(tmp_path)
    evt = s.write_event(kind="guard_check", action="checked", status="refused", summary="drift")

    show = runner.invoke(app, ["audit", "show", evt["event_id"]])
    assert show.exit_code == 0
    assert evt["event_id"] in show.stdout

    ok = runner.invoke(app, ["audit", "validate"])
    assert ok.exit_code == 0

    (tmp_path / "audit" / "events.jsonl").write_text("{bad\n", encoding="utf-8")
    bad = runner.invoke(app, ["audit", "validate"])
    assert bad.exit_code == 1
    assert "malformed JSON" in bad.stdout
