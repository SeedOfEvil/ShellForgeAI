from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app


def _build_plan_and_archive(tmp_path: Path, monkeypatch) -> tuple[CliRunner, str, Path]:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    exports = tmp_path / "exports"
    exports.mkdir(parents=True)
    (exports / "old.txt").write_text("hello", encoding="utf-8")
    runner = CliRunner()
    plan = runner.invoke(app, ["audit", "cleanup", "plan", "--category", "exports", "--json"])
    assert plan.exit_code == 0
    plan_id = json.loads(plan.stdout)["plan_id"]
    arc = runner.invoke(app, ["audit", "cleanup", "archive", plan_id])
    assert arc.exit_code == 0
    archive = next((tmp_path / "cleanup_archives").glob("*.tar.gz"))
    return runner, plan_id, archive


def test_cleanup_validate_receipt_still_passes(tmp_path: Path, monkeypatch) -> None:
    runner, plan_id, _archive = _build_plan_and_archive(tmp_path, monkeypatch)
    exec_ok = runner.invoke(app, ["audit", "cleanup", "execute", plan_id, "--confirm"])
    assert exec_ok.exit_code == 0
    receipt_dir = next((tmp_path / "cleanup_receipts").glob("cleanup_receipt_*"))
    res = runner.invoke(app, ["audit", "cleanup", "validate", str(receipt_dir)])
    assert res.exit_code == 0
    assert "Cleanup validation passed" in res.stdout


def test_cleanup_validate_archive_tarball_passes(tmp_path: Path, monkeypatch) -> None:
    runner, _plan_id, archive = _build_plan_and_archive(tmp_path, monkeypatch)
    res = runner.invoke(app, ["audit", "cleanup", "validate", str(archive)])
    assert res.exit_code == 0
    assert "Cleanup archive validation passed" in res.stdout


def test_cleanup_validate_archive_missing_manifest_fails_clean(tmp_path: Path, monkeypatch) -> None:
    runner, _plan_id, archive = _build_plan_and_archive(tmp_path, monkeypatch)
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(archive, "r:gz") as src, tarfile.open(bad, "w:gz") as dst:
        for member in src.getmembers():
            if member.name == "archive-manifest.json":
                continue
            f = src.extractfile(member)
            if f is None:
                dst.addfile(member)
            else:
                dst.addfile(member, io.BytesIO(f.read()))
    res = runner.invoke(app, ["audit", "cleanup", "validate", str(bad)])
    assert res.exit_code == 1
    assert "Cleanup archive validation failed" in res.stdout
    assert "traceback" not in res.stdout.lower()


def test_cleanup_validate_archive_checksum_mismatch_fails_clean(
    tmp_path: Path, monkeypatch
) -> None:
    runner, _plan_id, archive = _build_plan_and_archive(tmp_path, monkeypatch)
    bad = tmp_path / "bad-checksum.tar.gz"
    with tarfile.open(archive, "r:gz") as src, tarfile.open(bad, "w:gz") as dst:
        for member in src.getmembers():
            f = src.extractfile(member)
            if member.name == "checksums.sha256":
                content = f.read().decode("utf-8") if f else ""
                content = content.replace("a", "b", 1)
                data = content.encode("utf-8")
                m = tarfile.TarInfo(member.name)
                m.size = len(data)
                dst.addfile(m, io.BytesIO(data))
            elif f is None:
                dst.addfile(member)
            else:
                dst.addfile(member, io.BytesIO(f.read()))
    res = runner.invoke(app, ["audit", "cleanup", "validate", str(bad)])
    assert res.exit_code == 1
    assert "checksum mismatch" in res.stdout.lower()
    assert "traceback" not in res.stdout.lower()


def test_cleanup_validate_wrong_type_fails_clean(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    wrong = tmp_path / "note.txt"
    wrong.write_text("not a receipt", encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(app, ["audit", "cleanup", "validate", str(wrong)])
    assert res.exit_code == 1
    assert "expected cleanup receipt directory" in res.stdout
    assert "traceback" not in res.stdout.lower()


def test_cleanup_report_archive_path_fails_clean(tmp_path: Path, monkeypatch) -> None:
    runner, _plan_id, archive = _build_plan_and_archive(tmp_path, monkeypatch)
    res = runner.invoke(app, ["audit", "cleanup", "report", str(archive)])
    assert res.exit_code == 1
    assert "to validate cleanup archives" in res.stdout
    assert "traceback" not in res.stdout.lower()


def test_cleanup_report_receipt_path_works(tmp_path: Path, monkeypatch) -> None:
    runner, plan_id, _archive = _build_plan_and_archive(tmp_path, monkeypatch)
    exec_ok = runner.invoke(app, ["audit", "cleanup", "execute", plan_id, "--confirm"])
    assert exec_ok.exit_code == 0
    receipt_dir = next((tmp_path / "cleanup_receipts").glob("cleanup_receipt_*"))
    res = runner.invoke(app, ["audit", "cleanup", "report", str(receipt_dir)])
    assert res.exit_code == 0
    assert "Cleanup report" in res.stdout
