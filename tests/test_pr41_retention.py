from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def test_audit_retention_and_prune_dry_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "e1.json").write_text("x")
    (tmp_path / "apply_bundles").mkdir()
    (tmp_path / "apply_bundles" / "b1.json").write_text("y")

    out = runner.invoke(app, ["audit", "retention", "--json"])
    assert out.exit_code == 0
    assert '"execution": "none"' in out.stdout

    dry = runner.invoke(app, ["audit", "prune", "--category", "exports"])
    assert dry.exit_code == 0
    assert "Prune plan (dry-run):" in dry.stdout
    assert (tmp_path / "exports" / "e1.json").exists()


def test_audit_prune_execute_and_archive_validate(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "exports").mkdir()
    f = tmp_path / "exports" / "e1.json"
    f.write_text("x")

    run = runner.invoke(app, ["audit", "prune", "--category", "exports", "--execute"])
    assert run.exit_code == 0
    assert not f.exists()

    (tmp_path / "exports" / "e2.json").write_text("x")
    arc = runner.invoke(app, ["audit", "archive", "--older-than-days", "0"])
    assert arc.exit_code == 0
    archive = list((tmp_path / "archives").glob("*.tar.gz"))[0]
    ok = runner.invoke(app, ["audit", "archive-validate", str(archive)])
    assert ok.exit_code == 0
