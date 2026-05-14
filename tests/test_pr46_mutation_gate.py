"""PR46: first guarded mutation gate — ShellForgeAI metadata prune execution.

These tests use only tmp_path, no Docker, no root, no internet.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.cli import app

runner = CliRunner()


def _seed_exports(tmp_path: Path) -> Path:
    d = tmp_path / "exports"
    d.mkdir(parents=True, exist_ok=True)
    (d / "e1.json").write_text("export-one")
    (d / "e2.json").write_text("export-two")
    return d


def _seed_apply_bundles(tmp_path: Path) -> Path:
    d = tmp_path / "apply_bundles"
    d.mkdir(parents=True, exist_ok=True)
    (d / "b1.json").write_text("bundle-one")
    return d


def _seed_audit_exports(tmp_path: Path) -> Path:
    d = tmp_path / "audit_exports"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ae.json").write_text("audit-export")
    return d


def _seed_actions(tmp_path: Path) -> Path:
    d = tmp_path / "actions"
    d.mkdir(parents=True, exist_ok=True)
    (d / "a1.json").write_text("action-one")
    return d


def _seed_indexes(tmp_path: Path) -> Path:
    d = tmp_path / "audit"
    d.mkdir(parents=True, exist_ok=True)
    (d / "incident-index.json").write_text("{}")
    return d


def _read_events(tmp_path: Path) -> list[dict]:
    return AuditStorage(tmp_path).read_events()


# --- Dry-run -----------------------------------------------------------------


def test_prune_dry_run_deletes_nothing_and_reports_plan(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    r = runner.invoke(app, ["audit", "prune", "--category", "exports"])
    assert r.exit_code == 0, r.stdout
    assert "Prune plan (dry-run):" in r.stdout
    assert "selected: 2" in r.stdout
    assert "execution: none" in r.stdout
    assert "--execute --confirm" in r.stdout
    assert (tmp_path / "exports" / "e1.json").exists()
    events = _read_events(tmp_path)
    assert any(
        e["action"] == "prune"
        and e["status"] == "planned"
        and e["details"].get("metadata_cleanup_executed") is False
        for e in events
    )


# --- Execute gate ------------------------------------------------------------


def test_prune_execute_without_confirm_refuses_and_deletes_nothing(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    r = runner.invoke(app, ["audit", "prune", "--category", "exports", "--execute"])
    assert r.exit_code == 1
    assert "--confirm" in r.stdout
    assert (tmp_path / "exports" / "e1.json").exists()
    events = _read_events(tmp_path)
    assert any(
        e["status"] == "refused" and e["details"].get("reason") == "missing_confirm" for e in events
    )


def test_prune_execute_with_confirm_deletes_and_writes_receipt(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    exp_dir = _seed_exports(tmp_path)
    r = runner.invoke(app, ["audit", "prune", "--category", "exports", "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    assert "Prune executed:" in r.stdout
    assert "scope: ShellForgeAI-owned metadata only" in r.stdout
    assert "remediation_execution: false" in r.stdout
    assert not (exp_dir / "e1.json").exists()
    assert not (exp_dir / "e2.json").exists()

    receipt_dir = tmp_path / "prune_receipts"
    receipts = list(receipt_dir.glob("prune_*.json"))
    assert receipts, "expected at least one prune receipt"
    payload = json.loads(receipts[0].read_text())
    assert payload["mode"] == "execute"
    assert payload["category"] == "exports"
    assert len(payload["deleted"]) == 2
    assert payload["bytes_removed"] > 0
    assert payload["safety"]["shellforgeai_metadata_only"] is True
    assert payload["safety"]["remediation_execution"] is False
    assert payload["safety"]["docker_mutation"] is False
    assert payload["safety"]["service_mutation"] is False
    assert payload["safety"]["package_mutation"] is False
    md = list(receipt_dir.glob("prune_*.md"))
    assert md, "expected markdown receipt"

    events = _read_events(tmp_path)
    executed = [e for e in events if e["action"] == "prune" and e["status"] == "success"]
    assert executed, "expected an executed audit event"
    ev = executed[0]
    assert ev["details"]["metadata_cleanup_executed"] is True
    assert ev["details"]["remediation_execution"] is False
    assert ev["details"]["shellforgeai_owned_paths_only"] is True
    # audit schema must still report no remediation execution
    assert ev["safety"]["execution_allowed"] is False
    assert ev["safety"]["execution_status"] == "not_executed"
    assert ev["safety"]["mutation_performed"] is False


def test_prune_execute_does_not_touch_files_outside_data_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    outside = tmp_path.parent / "outside_marker.txt"
    outside.write_text("keep me")
    try:
        r = runner.invoke(
            app, ["audit", "prune", "--category", "exports", "--execute", "--confirm"]
        )
        assert r.exit_code == 0
        assert outside.exists()
        assert outside.read_text() == "keep me"
    finally:
        outside.unlink(missing_ok=True)


# --- Selection guards --------------------------------------------------------


def test_prune_execute_with_empty_selection_refuses(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "exports").mkdir()  # empty
    r = runner.invoke(app, ["audit", "prune", "--category", "exports", "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "empty" in r.stdout.lower()
    events = _read_events(tmp_path)
    assert any(
        e["status"] == "refused" and e["details"].get("reason") == "empty_selection" for e in events
    )


def test_prune_unknown_category_refuses(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    r = runner.invoke(app, ["audit", "prune", "--category", "totally-bogus"])
    assert r.exit_code == 1
    assert "unknown" in r.stdout.lower()
    events = _read_events(tmp_path)
    assert any(
        e["status"] == "refused" and e["details"].get("reason") == "unknown_category"
        for e in events
    )


def test_prune_protected_category_refuses(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    r = runner.invoke(
        app,
        ["audit", "prune", "--category", "approvals", "--execute", "--confirm"],
    )
    assert r.exit_code == 1
    assert "protected" in r.stdout.lower()
    events = _read_events(tmp_path)
    assert any(
        e["status"] == "refused" and e["details"].get("reason") == "protected_category"
        for e in events
    )


def test_prune_audit_events_category_protected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    r = runner.invoke(
        app,
        ["audit", "prune", "--category", "audit-events", "--execute", "--confirm"],
    )
    assert r.exit_code == 1
    assert "protected" in r.stdout.lower()


def test_prune_default_excludes_artifacts_approvals_and_audit_events(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "sf_keep.txt").write_text("keep")
    (tmp_path / "approvals").mkdir()
    (tmp_path / "approvals" / "ap1.json").write_text("approve")
    r = runner.invoke(app, ["audit", "prune", "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    # default categories should not have touched artifacts/approvals
    assert (tmp_path / "artifacts" / "sf_keep.txt").exists()
    assert (tmp_path / "approvals" / "ap1.json").exists()
    # but exports were deleted
    assert not (tmp_path / "exports" / "e1.json").exists()


# --- Category coverage -------------------------------------------------------


def test_prune_apply_bundles_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    _seed_apply_bundles(tmp_path)
    r = runner.invoke(
        app,
        ["audit", "prune", "--category", "apply-bundles", "--execute", "--confirm"],
    )
    assert r.exit_code == 0, r.stdout
    assert not (tmp_path / "apply_bundles" / "b1.json").exists()
    assert (tmp_path / "exports" / "e1.json").exists()


def test_prune_audit_exports_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_audit_exports(tmp_path)
    _seed_exports(tmp_path)
    r = runner.invoke(
        app,
        ["audit", "prune", "--category", "audit-exports", "--execute", "--confirm"],
    )
    assert r.exit_code == 0, r.stdout
    assert not (tmp_path / "audit_exports" / "ae.json").exists()
    assert (tmp_path / "exports" / "e1.json").exists()


def test_prune_actions_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_actions(tmp_path)
    _seed_exports(tmp_path)
    r = runner.invoke(app, ["audit", "prune", "--category", "actions", "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    assert not (tmp_path / "actions" / "a1.json").exists()
    assert (tmp_path / "exports" / "e1.json").exists()


def test_prune_indexes_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_indexes(tmp_path)
    _seed_exports(tmp_path)
    r = runner.invoke(app, ["audit", "prune", "--category", "indexes", "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    assert not (tmp_path / "audit" / "incident-index.json").exists()
    assert (tmp_path / "exports" / "e1.json").exists()


# --- Ask refusal -------------------------------------------------------------


def test_ask_clean_old_metadata_does_not_execute(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    r = runner.invoke(app, ["ask", "clean up old metadata"])
    assert r.exit_code == 0, r.stdout
    # nothing was deleted
    assert (tmp_path / "exports" / "e1.json").exists()


def test_ask_delete_old_exports_now_is_refused(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    r = runner.invoke(app, ["ask", "delete old exports now"])
    assert r.exit_code == 0, r.stdout
    out = r.stdout.lower()
    assert "refus" in out
    assert "--execute --confirm" in r.stdout
    assert (tmp_path / "exports" / "e1.json").exists()


def test_ask_cleanup_now_is_refused(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    r = runner.invoke(app, ["ask", "cleanup now"])
    assert r.exit_code == 0, r.stdout
    assert "--execute --confirm" in r.stdout
    assert (tmp_path / "exports" / "e1.json").exists()


def test_ask_free_up_disk_is_refused(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    r = runner.invoke(app, ["ask", "free up shellforgeai disk"])
    assert r.exit_code == 0, r.stdout
    assert "--execute --confirm" in r.stdout
    assert (tmp_path / "exports" / "e1.json").exists()
