import hashlib
import io
import tarfile
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.retention import create_archive, validate_archive

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

    # PR46: --execute requires --confirm as a second explicit gate.
    refused = runner.invoke(app, ["audit", "prune", "--category", "exports", "--execute"])
    assert refused.exit_code == 1
    assert f.exists()

    run = runner.invoke(app, ["audit", "prune", "--category", "exports", "--execute", "--confirm"])
    assert run.exit_code == 0
    assert not f.exists()

    (tmp_path / "exports" / "e2.json").write_text("x")
    arc = runner.invoke(app, ["audit", "archive", "--older-than-days", "0"])
    assert arc.exit_code == 0
    archive = list((tmp_path / "archives").glob("*.tar.gz"))[0]
    ok = runner.invoke(app, ["audit", "archive-validate", str(archive)])
    assert ok.exit_code == 0


def test_validate_archive_duplicate_basenames_tar(tmp_path: Path) -> None:
    root = tmp_path / "exports"
    (root / "export_a").mkdir(parents=True)
    (root / "export_b").mkdir(parents=True)
    (root / "export_a" / "summary.md").write_text("A")
    (root / "export_b" / "summary.md").write_text("B")
    archive = create_archive([root], tmp_path, source="test")
    ok, errs, _ = validate_archive(archive)
    assert ok, errs


def test_validate_archive_mismatch_reports_exact_path(tmp_path: Path) -> None:
    root = tmp_path / "exports"
    (root / "export_a").mkdir(parents=True)
    (root / "export_b").mkdir(parents=True)
    a = root / "export_a" / "summary.md"
    b = root / "export_b" / "summary.md"
    a.write_text("A")
    b.write_text("B")
    archive = create_archive([root], tmp_path, source="test")
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(archive, "r:gz") as src, tarfile.open(bad, "w:gz") as out:
        for member in src.getmembers():
            if member.name == "checksums.sha256":
                extracted = src.extractfile(member)
                assert extracted is not None
                checks = extracted.read().decode("utf-8")
                checks = checks.replace(
                    hashlib.sha256(b.read_bytes()).hexdigest(),
                    hashlib.sha256(b"tampered").hexdigest(),
                )
                info = tarfile.TarInfo("checksums.sha256")
                data = checks.encode("utf-8")
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
            else:
                fileobj = src.extractfile(member) if member.isfile() else None
                out.addfile(member, fileobj)
    ok, errs, _ = validate_archive(bad)
    assert not ok
    assert any("checksum mismatch: payload/exports/export_b/summary.md" in e for e in errs)


def test_validate_archive_missing_path_and_traversal(tmp_path: Path) -> None:
    ad = tmp_path / "arc"
    (ad / "payload" / "exports" / "export_b").mkdir(parents=True)
    f = ad / "payload" / "exports" / "export_b" / "summary.md"
    f.write_text("B")
    digest = hashlib.sha256(f.read_bytes()).hexdigest()
    (ad / "archive-manifest.json").write_text(
        '{"execution_allowed":false,"execution_status":"not_executed","mutation_performed":false}'
    )
    (ad / "archive-summary.md").write_text("ok")
    (ad / "checksums.sha256").write_text(
        f"{digest}  payload/exports/export_a/summary.md\n"
        f"{digest}  ../evil.txt\n"
        f"{digest}  /tmp/evil.txt\n"
    )
    ok, errs, _ = validate_archive(ad)
    assert not ok
    assert any(
        "missing payload for checksum entry: payload/exports/export_a/summary.md" in e for e in errs
    )
    assert any("invalid checksum path: ../evil.txt" in e for e in errs)
    assert any("invalid checksum path: /tmp/evil.txt" in e for e in errs)
