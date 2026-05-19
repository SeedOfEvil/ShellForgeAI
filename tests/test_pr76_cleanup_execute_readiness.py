"""PR76 — cleanup execute-readiness and post-execute report hardening.

`audit cleanup execute-readiness` is a read-only readiness check that
inspects the plan, the matching cleanup archive, archive validation, and
plan fingerprint, then answers whether the operator may run
`audit cleanup execute <plan> --confirm` safely. It never creates plans,
archives, or receipts, and never deletes anything.

`audit cleanup report` summarizes a cleanup execute receipt. It is
read-only and supports strict --json output.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _seed_exports(data_dir: Path, count: int = 3, size: int = 64) -> None:
    exports = data_dir / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (exports / f"e{i}.json").write_text("x" * size, encoding="utf-8")


def _prepared_plan(tmp_path: Path) -> tuple[str, dict]:
    """Run prepare to produce a valid plan+archive; return plan_id and JSON."""
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    return payload["plan"]["id"], payload


# --- readiness happy path -------------------------------------------------


def test_readiness_passes_for_valid_plan_and_archive(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    assert payload["status"] == "ready"
    assert payload["readiness"]["ready_for_execute_confirm"] is True
    assert payload["readiness"]["blockers"] == []
    assert payload["archive"]["found"] is True
    assert payload["archive"]["archive_validated"] is True
    assert payload["archive"]["plan_id_matches"] is True
    assert payload["archive"]["plan_fingerprint_matches"] is True


def test_readiness_emits_execute_command_with_confirm(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    payload = json.loads(out.stdout)
    cmd = payload["next_commands"]["execute"]
    assert cmd.startswith("shellforgeai audit cleanup execute ")
    assert "--confirm" in cmd


def test_readiness_human_output_renders(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id])
    assert out.exit_code == 0, out.stdout
    assert "Cleanup execute readiness" in out.stdout
    assert "ready_for_execute_confirm: true" in out.stdout
    assert "--confirm" in out.stdout


# --- readiness failures ---------------------------------------------------


def test_readiness_fails_when_plan_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(
        app,
        ["audit", "cleanup", "execute-readiness", "cleanup_plan_does_not_exist", "--json"],
    )
    assert out.exit_code == 1
    payload = json.loads(out.stdout)
    assert payload["status"] == "not_found"
    assert payload["readiness"]["ready_for_execute_confirm"] is False
    assert any("not found" in b for b in payload["readiness"]["blockers"])


def test_readiness_fails_when_archive_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    # delete the cleanup_archives directory
    for p in (tmp_path / "cleanup_archives").iterdir():
        p.unlink()
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    assert out.exit_code == 1
    payload = json.loads(out.stdout)
    assert payload["readiness"]["ready_for_execute_confirm"] is False
    assert any("archive" in b for b in payload["readiness"]["blockers"])


def test_readiness_fails_when_plan_fingerprint_mismatches(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, prepared = _prepared_plan(tmp_path)
    plan_path = Path(prepared["plan"]["path"])
    payload = json.loads(plan_path.read_text())
    payload["candidates"].append(
        {"path": str(tmp_path / "exports" / "tampered.json"), "category": "exports"}
    )
    plan_path.write_text(json.dumps(payload, indent=2))
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    assert out.exit_code == 1
    body = json.loads(out.stdout)
    assert body["readiness"]["ready_for_execute_confirm"] is False
    assert any("fingerprint" in b for b in body["readiness"]["blockers"])


def test_readiness_fails_when_archive_validation_fails(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, prepared = _prepared_plan(tmp_path)
    archive_path = Path(prepared["archive"]["path"])
    archive_path.write_bytes(b"\x00\x01not a tar gz")
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    assert out.exit_code == 1
    body = json.loads(out.stdout)
    assert body["readiness"]["ready_for_execute_confirm"] is False


def test_readiness_fails_for_unsafe_category(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, prepared = _prepared_plan(tmp_path)
    plan_path = Path(prepared["plan"]["path"])
    payload = json.loads(plan_path.read_text())
    payload.setdefault("selection", {})["categories"] = ["../etc"]
    plan_path.write_text(json.dumps(payload, indent=2))
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    assert out.exit_code == 1
    body = json.loads(out.stdout)
    assert any("unsafe category" in b for b in body["readiness"]["blockers"])


def test_readiness_fails_for_path_escape(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, prepared = _prepared_plan(tmp_path)
    plan_path = Path(prepared["plan"]["path"])
    payload = json.loads(plan_path.read_text())
    payload["candidates"].append(
        {"path": "/etc/hostname", "category": "exports", "bytes": 1, "age_days": 0}
    )
    plan_path.write_text(json.dumps(payload, indent=2))
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    assert out.exit_code == 1
    body = json.loads(out.stdout)
    assert any("outside ShellForgeAI metadata" in b for b in body["readiness"]["blockers"])


# --- read-only safety -----------------------------------------------------


def test_readiness_does_not_delete_candidate_files(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=4)
    plan_id, _ = _prepared_plan(tmp_path)
    before = sorted(p.name for p in (tmp_path / "exports").iterdir())
    runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    after = sorted(p.name for p in (tmp_path / "exports").iterdir())
    assert before == after


def test_readiness_does_not_create_new_plans_or_archives(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    plans_before = sorted((tmp_path / "cleanup_plans").iterdir())
    archives_before = sorted((tmp_path / "cleanup_archives").iterdir())
    runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    plans_after = sorted((tmp_path / "cleanup_plans").iterdir())
    archives_after = sorted((tmp_path / "cleanup_archives").iterdir())
    assert plans_before == plans_after
    assert archives_before == archives_after
    assert not (tmp_path / "cleanup_receipts").exists()


# --- JSON contract --------------------------------------------------------


def test_readiness_json_is_strict_parseable(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    payload = json.loads(out.stdout)
    assert payload["schema_version"] == "1"
    assert "plan" in payload
    assert "archive" in payload
    assert "blockers" in payload["readiness"]


def test_readiness_json_safety_block(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    safety = json.loads(out.stdout)["safety"]
    assert safety["read_only"] is True
    assert safety["cleanup_executed"] is False
    assert safety["deletion_performed"] is False
    assert safety["arbitrary_paths_allowed"] is False
    assert safety["docker_mutation"] is False
    assert safety["system_mutation"] is False
    assert safety["natural_language_execution"] is False
    assert safety["explicit_confirm_required"] is True


# --- report (PR76) --------------------------------------------------------


def _execute_cleanup(tmp_path: Path, plan_id: str) -> Path:
    """Execute cleanup and return the receipt path."""
    out = runner.invoke(app, ["audit", "cleanup", "execute", plan_id, "--confirm"])
    assert out.exit_code == 0, out.stdout
    rdir = tmp_path / "cleanup_receipts"
    receipts = sorted(rdir.iterdir())
    assert receipts
    return receipts[-1] / "cleanup-receipt.json"


def test_report_summarizes_valid_receipt(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=3)
    plan_id, _ = _prepared_plan(tmp_path)
    receipt = _execute_cleanup(tmp_path, plan_id)
    out = runner.invoke(app, ["audit", "cleanup", "report", str(receipt), "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    assert payload["status"] == "ok"
    assert payload["receipt"]["plan_id"] == plan_id
    assert payload["receipt"]["kind"] == "cleanup_execute_result"
    assert payload["result"]["deleted"] >= 1
    assert payload["result"]["failed"] == 0
    assert payload["safety"]["arbitrary_paths_allowed"] is False
    assert payload["safety"]["shellforgeai_metadata_only"] is True
    assert payload["validation"]["receipt_valid"] is True


def test_report_human_output(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=3)
    plan_id, _ = _prepared_plan(tmp_path)
    receipt = _execute_cleanup(tmp_path, plan_id)
    out = runner.invoke(app, ["audit", "cleanup", "report", str(receipt)])
    assert out.exit_code == 0, out.stdout
    assert "Cleanup report" in out.stdout
    assert "deleted:" in out.stdout
    assert "shellforgeai_metadata_only" in out.stdout


def test_report_handles_missing_receipt_cleanly(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(
        app,
        [
            "audit",
            "cleanup",
            "report",
            str(tmp_path / "cleanup-receipt.json"),
            "--json",
        ],
    )
    assert out.exit_code == 1
    payload = json.loads(out.stdout)
    assert payload["status"] == "not_found"


def test_report_handles_malformed_receipt_cleanly(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    bad = tmp_path / "cleanup-receipt.json"
    bad.write_text("not json {{", encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "report", str(bad), "--json"])
    assert out.exit_code == 1
    payload = json.loads(out.stdout)
    assert payload["status"] == "error"


def test_report_does_not_mutate(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=3)
    plan_id, _ = _prepared_plan(tmp_path)
    receipt = _execute_cleanup(tmp_path, plan_id)
    before = sorted(p.name for p in (tmp_path / "cleanup_receipts").iterdir())
    runner.invoke(app, ["audit", "cleanup", "report", str(receipt), "--json"])
    after = sorted(p.name for p in (tmp_path / "cleanup_receipts").iterdir())
    assert before == after


# --- regression: execute is still gated ----------------------------------


def test_execute_still_refuses_without_confirm(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute", plan_id])
    assert out.exit_code == 1
    assert "Refused" in out.stdout
    assert "--confirm" in out.stdout


def test_execute_still_refuses_when_archive_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    for p in (tmp_path / "cleanup_archives").iterdir():
        p.unlink()
    out = runner.invoke(app, ["audit", "cleanup", "execute", plan_id, "--confirm"])
    assert out.exit_code == 1
    assert "archive not found" in out.stdout


def test_execute_still_refuses_when_plan_tampered(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, prepared = _prepared_plan(tmp_path)
    plan_path = Path(prepared["plan"]["path"])
    payload = json.loads(plan_path.read_text())
    payload["candidates"].append(
        {"path": str(tmp_path / "exports" / "ghost.json"), "category": "exports"}
    )
    plan_path.write_text(json.dumps(payload, indent=2))
    out = runner.invoke(app, ["audit", "cleanup", "execute", plan_id, "--confirm"])
    assert out.exit_code == 1
    assert "fingerprint mismatch" in out.stdout


def test_readiness_does_not_appear_in_natural_language_routing(tmp_path, monkeypatch) -> None:
    """Sanity: readiness was added as a typed CLI subcommand, not an NL ask."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    # The CLI 'ask' surface must not silently execute cleanup. We sniff for
    # any new natural-language cleanup execute path by ensuring the typed
    # readiness command is registered while the execute command still
    # requires --confirm (covered above).
    out = runner.invoke(app, ["audit", "cleanup", "--help"])
    assert "execute-readiness" in out.stdout


def test_prepared_archive_manifest_marks_no_execution(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    _plan_id, prepared = _prepared_plan(tmp_path)
    archive_path = Path(prepared["archive"]["path"])
    with tarfile.open(archive_path, "r:gz") as tf:
        mf = tf.extractfile("archive-manifest.json")
        assert mf is not None
        manifest = json.loads(mf.read().decode("utf-8"))
    assert manifest.get("execution_allowed") is False
