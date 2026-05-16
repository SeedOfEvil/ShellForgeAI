from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app


def test_cleanup_plan_and_execute_flow(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    exports = tmp_path / "exports"
    exports.mkdir(parents=True)
    (exports / "old.txt").write_text("x", encoding="utf-8")
    runner = CliRunner()
    r = runner.invoke(app, ["audit", "cleanup", "plan", "--category", "exports", "--json"])
    assert r.exit_code == 0
    assert '"plan_id"' in r.stdout


def test_cleanup_execute_requires_confirm(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    exports = tmp_path / "exports"
    exports.mkdir(parents=True)
    (exports / "old.txt").write_text("x", encoding="utf-8")
    runner = CliRunner()
    p = runner.invoke(app, ["audit", "cleanup", "plan", "--category", "exports", "--json"])
    assert p.exit_code == 0
    import json

    plan_id = json.loads(p.stdout)["plan_id"]
    no = runner.invoke(app, ["audit", "cleanup", "execute", plan_id])
    assert no.exit_code != 0
    ok = runner.invoke(app, ["audit", "cleanup", "execute", plan_id, "--confirm"])
    assert ok.exit_code == 0
