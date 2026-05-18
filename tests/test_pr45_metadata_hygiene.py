import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.metadata_hygiene import HygieneThresholds, human_bytes, scan_metadata_hygiene

runner = CliRunner()


def test_metadata_scanner_counts_and_sizes(tmp_path: Path) -> None:
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "a.json").write_text("x" * 10)
    (tmp_path / "audit_exports").mkdir()
    (tmp_path / "audit_exports" / "b.json").write_text("y" * 20)
    out: dict = scan_metadata_hygiene(tmp_path, HygieneThresholds(total_warn_bytes=1_000_000))
    assert out["categories"]["exports"]["count"] == 1
    assert out["categories"]["audit_exports"]["bytes"] == 20


def test_metadata_scanner_skips_symlink_outside(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside_external"
    outside.mkdir()
    (outside / "x.txt").write_text("12345")
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "link").symlink_to(outside, target_is_directory=True)
    out: dict = scan_metadata_hygiene(tmp_path)
    assert out["categories"]["exports"]["count"] == 0
    assert out["categories"]["exports"]["bytes"] == 0


def test_human_bytes_formatting() -> None:
    assert human_bytes(0) == "0 B"
    assert "KiB" in human_bytes(2048)


def test_doctor_includes_metadata_hygiene_and_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "e1.bin").write_text("z" * 10)
    out = runner.invoke(app, ["doctor"])
    assert out.exit_code == 0
    assert "Metadata hygiene" in out.stdout
    assert "Suggested safe next steps" in out.stdout
    jout = runner.invoke(app, ["doctor", "--json"])
    assert jout.exit_code == 0
    assert '"metadata_hygiene"' in jout.stdout


def test_retention_top_and_recommendations(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "big.bin").write_text("a" * 5000)
    out = runner.invoke(app, ["audit", "retention", "--top", "1"])
    assert out.exit_code == 0
    assert "top 1 largest metadata items" in out.stdout
    jout = runner.invoke(app, ["audit", "retention", "--json"])
    assert '"execution": "none"' in jout.stdout


def test_ask_clean_now_refuses_mutation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    f = tmp_path / "exports" / "old.json"
    f.parent.mkdir(parents=True)
    f.write_text("data")
    out = runner.invoke(app, ["ask", "clean it now"])
    assert out.exit_code == 0
    assert "Refusing automatic deletion" in out.stdout
    assert f.exists()


def test_doctor_json_severity_and_no_contamination(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    (tmp_path / "exports").mkdir(parents=True)
    (tmp_path / "exports" / "huge.bin").write_text("x" * 32)
    out = runner.invoke(app, ["doctor", "--json"])
    assert out.exit_code == 0
    text = out.stdout.strip()
    assert text.startswith("{")
    parsed = json.loads(text)
    assert parsed["metadata_hygiene"]["severity"] in {"warning", "critical"}
    assert isinstance(parsed["metadata_hygiene"]["reasons"], list)
    assert parsed["metadata_hygiene"]["recommendations"]
    assert "Metadata hygiene" not in out.stdout


def test_retention_json_is_strict_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "exports").mkdir(parents=True)
    out = runner.invoke(app, ["audit", "retention", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert payload["execution"] == "none"


def test_cleanup_plan_reports_counts_and_safety(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    exports = tmp_path / "exports"
    exports.mkdir(parents=True)
    (exports / "a.json").write_text("a")
    (exports / "b.json").write_text("b")
    out = runner.invoke(
        app,
        ["audit", "cleanup", "plan", "--category", "exports", "--keep-latest", "1"],
    )
    assert out.exit_code == 0
    assert "matched:" in out.stdout
    assert "candidates for archive/delete:" in out.stdout
    json_out = runner.invoke(
        app,
        ["audit", "cleanup", "plan", "--category", "exports", "--keep-latest", "1", "--json"],
    )
    assert json_out.exit_code == 0
    payload = json.loads(json_out.stdout)
    assert payload["summary"]["matched_count"] == 2
    assert payload["summary"]["kept_count"] == 1
    assert payload["safety"]["requires_confirm"] is True
