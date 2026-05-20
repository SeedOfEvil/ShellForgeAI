"""PR77 — cleanup execution operator confirmation polish and post-execute QA.

Polish-only:
- `audit cleanup execute-readiness` clearly distinguishes "ready" from
  "approved" and never deletes anything.
- `audit cleanup execute` without `--confirm` refuses with explicit gate
  reasons.
- `audit cleanup report` exposes a post-execute QA checklist
  (including `audit cleanup validate <receipt>`).

No gate weakening. No new mutation surface.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _seed_exports(data_dir: Path, count: int = 3) -> None:
    exports = data_dir / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (exports / f"e{i}.json").write_text("x" * 64, encoding="utf-8")


def _prepared_plan(tmp_path: Path) -> tuple[str, dict]:
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    return payload["plan"]["id"], payload


# --- execute-readiness JSON polish ---------------------------------------


def test_readiness_json_top_level_operator_fields(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    payload = json.loads(out.stdout)
    assert payload["ready_for_execute_confirm"] is True
    assert payload["operator_action_required"] is True
    assert payload["read_only"] is True
    assert payload["cleanup_executed"] is False
    assert payload["deletion_performed"] is False


def test_readiness_json_includes_gates(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    gates = json.loads(out.stdout)["gates"]
    for key in (
        "plan_present",
        "archive_found",
        "archive_validated",
        "checksums_ok",
        "plan_id_matches",
        "plan_fingerprint_matches",
        "explicit_confirm_required",
    ):
        assert key in gates, key
    assert gates["explicit_confirm_required"] is True
    assert gates["archive_validated"] is True


def test_readiness_json_includes_next_commands(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    nc = json.loads(out.stdout)["next_commands"]
    assert "execute" in nc
    assert "--confirm" in nc["execute"]


def test_readiness_json_safety_pr77_fields(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    safety = json.loads(out.stdout)["safety"]
    assert safety["read_only"] is True
    assert safety["cleanup_executed"] is False
    assert safety["deletion_performed"] is False
    assert safety["mutation_performed"] is False
    assert safety["arbitrary_paths_allowed"] is False
    assert safety["docker_mutation"] is False
    assert safety["system_mutation"] is False
    assert safety["natural_language_execution"] is False
    assert safety["shellforgeai_metadata_only"] is True


# --- execute-readiness human output polish -------------------------------


def test_readiness_human_states_nothing_was_deleted(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id])
    assert out.exit_code == 0
    assert "did not delete anything" in out.stdout
    assert "deletion_performed: false" in out.stdout
    assert "cleanup_executed: false" in out.stdout


def test_readiness_human_lists_explicit_confirm_execute_command(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id])
    assert "Next commands:" in out.stdout
    assert "shellforgeai audit cleanup execute" in out.stdout
    assert "--confirm" in out.stdout
    assert "report" in out.stdout


def test_readiness_human_validated_gates_block_present(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id])
    assert "Validated gates:" in out.stdout
    assert "matching archive: present" in out.stdout
    assert "archive validation: passed" in out.stdout
    assert "plan fingerprint: matched" in out.stdout
    assert "explicit confirm: still required" in out.stdout


def test_readiness_human_blocked_does_not_present_execute_as_safe(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    for p in (tmp_path / "cleanup_archives").iterdir():
        p.unlink()
    out = runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id])
    assert out.exit_code == 1
    assert "Blockers:" in out.stdout
    assert "Do not execute until blockers are resolved." in out.stdout
    assert "Next commands:" not in out.stdout


# --- execute refusal polish ----------------------------------------------


def test_execute_refusal_without_confirm_lists_required_gates(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "execute", plan_id])
    assert out.exit_code == 1
    assert "Refused" in out.stdout
    assert "--confirm" in out.stdout
    assert "Nothing was deleted." in out.stdout
    assert "matching archive" in out.stdout
    assert "archive validation" in out.stdout
    assert "matching plan fingerprint" in out.stdout


def test_execute_refusal_without_confirm_does_not_delete(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=4)
    plan_id, _ = _prepared_plan(tmp_path)
    before = sorted(p.name for p in (tmp_path / "exports").iterdir())
    runner.invoke(app, ["audit", "cleanup", "execute", plan_id])
    after = sorted(p.name for p in (tmp_path / "exports").iterdir())
    assert before == after
    assert not (tmp_path / "cleanup_receipts").exists()


# --- report polish -------------------------------------------------------


def _execute_cleanup(tmp_path: Path, plan_id: str) -> Path:
    out = runner.invoke(app, ["audit", "cleanup", "execute", plan_id, "--confirm"])
    assert out.exit_code == 0, out.stdout
    receipts = sorted((tmp_path / "cleanup_receipts").iterdir())
    return receipts[-1] / "cleanup-receipt.json"


def test_report_json_includes_post_execute_checks(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    receipt = _execute_cleanup(tmp_path, plan_id)
    out = runner.invoke(app, ["audit", "cleanup", "report", str(receipt), "--json"])
    payload = json.loads(out.stdout)
    checks = payload.get("post_execute_checks") or payload.get("next_commands")
    assert isinstance(checks, list) and checks
    assert any("audit cleanup validate" in c for c in checks)
    assert any("audit retention" in c for c in checks)
    assert any("audit cleanup review" in c for c in checks)
    assert any("doctor" in c for c in checks)


def test_report_json_top_level_fields(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    receipt = _execute_cleanup(tmp_path, plan_id)
    out = runner.invoke(app, ["audit", "cleanup", "report", str(receipt), "--json"])
    payload = json.loads(out.stdout)
    assert payload["receipt_kind"] == "cleanup_execute_result"
    assert payload["receipt_valid"] is True
    assert payload["receipt_plan_id"] == plan_id
    assert payload["deleted"] >= 1
    assert payload["failed"] == 0
    assert payload["bytes_removed"] >= 0


def test_report_human_shows_post_execute_checks(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    receipt = _execute_cleanup(tmp_path, plan_id)
    out = runner.invoke(app, ["audit", "cleanup", "report", str(receipt)])
    assert out.exit_code == 0
    assert "Post-execute checks:" in out.stdout
    assert "audit cleanup validate" in out.stdout


def test_report_does_not_mutate(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    receipt = _execute_cleanup(tmp_path, plan_id)
    before_receipts = sorted(p.name for p in (tmp_path / "cleanup_receipts").iterdir())
    before_exports_exists = (tmp_path / "exports").exists()
    runner.invoke(app, ["audit", "cleanup", "report", str(receipt), "--json"])
    runner.invoke(app, ["audit", "cleanup", "report", str(receipt)])
    after_receipts = sorted(p.name for p in (tmp_path / "cleanup_receipts").iterdir())
    after_exports_exists = (tmp_path / "exports").exists()
    assert before_receipts == after_receipts
    assert before_exports_exists == after_exports_exists


def test_report_missing_receipt_clean_json(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(
        app,
        ["audit", "cleanup", "report", str(tmp_path / "no-receipt.json"), "--json"],
    )
    assert out.exit_code == 1
    payload = json.loads(out.stdout)
    assert payload["status"] == "not_found"
    # No traceback leaked
    assert "Traceback" not in out.stdout


# --- safety regression: readiness/report do not call execute -------------


def test_readiness_does_not_create_receipt(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    plan_id, _ = _prepared_plan(tmp_path)
    runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id, "--json"])
    runner.invoke(app, ["audit", "cleanup", "execute-readiness", plan_id])
    assert not (tmp_path / "cleanup_receipts").exists()
