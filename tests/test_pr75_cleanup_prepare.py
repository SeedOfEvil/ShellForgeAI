"""PR75 — guided real /data cleanup prepare workflow.

`audit cleanup prepare` is a guided "review -> dry-run plan -> archive ->
validate archive" workflow. It creates ShellForgeAI-owned plan and archive
metadata but never deletes candidate files and never calls cleanup execute.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _seed_exports(data_dir: Path, count: int = 3, size: int = 64) -> None:
    exports = data_dir / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (exports / f"e{i}.json").write_text("x" * size, encoding="utf-8")


# --- workflow behavior ----------------------------------------------------


def test_prepare_creates_plan_for_exports(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    assert payload["plan"]["created"] is True
    assert payload["plan"]["id"].startswith("cleanup_plan_")
    assert Path(payload["plan"]["path"]).exists()


def test_prepare_creates_matching_archive(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    archive_path = Path(payload["archive"]["path"])
    assert archive_path.exists()
    assert payload["archive"]["plan_fingerprint"] == payload["plan"]["fingerprint"]


def test_prepare_archive_fingerprint_matches_plan(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    archive_path = Path(payload["archive"]["path"])
    with tarfile.open(archive_path, "r:gz") as tf:
        mf = tf.extractfile("archive-manifest.json")
        assert mf is not None
        manifest = json.loads(mf.read().decode("utf-8"))
    assert manifest["plan_fingerprint"] == payload["plan"]["fingerprint"]
    assert manifest["plan_id"] == payload["plan"]["id"]


def test_prepare_validates_archive(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    assert payload["archive"]["validated"] is True
    assert payload["archive"]["checksums_ok"] is True


def test_prepare_ready_for_operator_decision_when_valid(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    assert payload["decision"]["ready_for_operator_decision"] is True
    assert payload["decision"]["prepared_for_review"] is True


def test_prepare_reports_execute_and_deletion_false(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    assert payload["decision"]["execute_performed"] is False
    assert payload["decision"]["deletion_performed"] is False
    assert payload["decision"]["operator_approval_required"] is True


def test_prepare_does_not_delete_candidate_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=5, size=20)
    before = sorted(p.name for p in (tmp_path / "exports").iterdir())
    runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    after = sorted(p.name for p in (tmp_path / "exports").iterdir())
    assert before == after


def test_prepare_does_not_call_cleanup_execute(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    with patch("shellforgeai.cli.delete_paths") as delp:
        out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
        assert out.exit_code == 0
        delp.assert_not_called()


def test_prepare_plan_includes_fingerprint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    assert "fingerprint" in payload["plan"]
    assert len(payload["plan"]["fingerprint"]) == 64  # sha256 hex


def test_prepare_prints_execute_command_but_does_not_run_it(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports"])
    assert out.exit_code == 0
    assert "cleanup execute" in out.stdout
    assert "--confirm" in out.stdout
    assert "operator-approved only" in out.stdout
    assert "deletion_performed: false" in out.stdout
    assert "execute_performed: false" in out.stdout
    # candidate files still exist
    assert any((tmp_path / "exports").iterdir())


def test_prepare_no_candidates_when_empty(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    assert payload["status"] == "no_candidates"
    assert payload["plan"]["candidate_count"] == 0
    assert payload["decision"]["execute_performed"] is False


# --- JSON contract --------------------------------------------------------


def test_prepare_json_strict_parseable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    text = out.stdout.strip()
    assert text.startswith("{")
    assert text.endswith("}")
    json.loads(text)


def test_prepare_json_no_text_before_or_after(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    assert "ShellForgeAI cleanup prepare" not in out.stdout
    assert "Decision:" not in out.stdout


def test_prepare_json_has_required_fields(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    for key in (
        "schema_version",
        "kind",
        "status",
        "category",
        "plan",
        "archive",
        "decision",
        "safety",
        "warnings",
    ):
        assert key in payload, f"missing {key}"
    assert payload["schema_version"] == "1"
    assert payload["kind"] == "cleanup_prepare_result"


def test_prepare_json_decision_safety_invariants(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    decision = payload["decision"]
    assert decision["execute_performed"] is False
    assert decision["deletion_performed"] is False
    assert decision["operator_approval_required"] is True
    safety = payload["safety"]
    assert safety["cleanup_executed"] is False
    assert safety["mutation_performed"] is False
    assert safety["deletion_performed"] is False
    assert safety["arbitrary_paths_allowed"] is False
    assert safety["docker_mutation"] is False
    assert safety["system_mutation"] is False


# --- category safety ------------------------------------------------------


def test_prepare_unknown_category_refuses(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "bogus"])
    assert out.exit_code == 1
    assert "Refused" in out.stdout
    assert not (tmp_path / "cleanup_plans").exists()
    assert not (tmp_path / "cleanup_archives").exists()


def test_prepare_path_traversal_category_refuses(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "../../etc"])
    assert out.exit_code == 1
    assert not (tmp_path / "cleanup_plans").exists()
    assert not (tmp_path / "cleanup_archives").exists()


def test_prepare_unknown_category_json_blocked(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "bogus", "--json"])
    assert out.exit_code == 1
    payload = json.loads(out.stdout)
    assert payload["status"] == "blocked"
    assert payload["plan"]["created"] is False
    assert payload["archive"]["created"] is False
    assert payload["decision"]["ready_for_operator_decision"] is False


def test_prepare_exports_category_works(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert payload["category"] == "exports"


# --- safety regression ----------------------------------------------------


def test_prepare_does_not_call_docker(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    with patch("shellforgeai.cli.subprocess") as sp:
        runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
        # subprocess module imported; nothing should be invoked from prepare
        sp.run.assert_not_called()
        if hasattr(sp, "Popen"):
            sp.Popen.assert_not_called()


def test_pr71_execute_still_requires_confirm(tmp_path: Path, monkeypatch) -> None:
    """PR71 execute gates remain: --confirm is still required."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    prep = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(prep.stdout)
    plan_id = payload["plan"]["id"]
    out = runner.invoke(app, ["audit", "cleanup", "execute", plan_id])
    assert out.exit_code == 1
    assert "confirm" in out.stdout.lower()


def test_prepare_keep_latest_filters_candidates(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=6, size=10)
    out = runner.invoke(
        app,
        [
            "audit",
            "cleanup",
            "prepare",
            "--category",
            "exports",
            "--keep-latest",
            "2",
            "--json",
        ],
    )
    payload = json.loads(out.stdout)
    # 6 items, keep latest 2 -> 4 candidates
    assert payload["plan"]["candidate_count"] == 4
    # files still on disk (not deleted)
    assert len(list((tmp_path / "exports").iterdir())) == 6


# --- next_commands wiring (PR75 blocker fix) ------------------------------


def test_prepare_next_commands_review_plan_present(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    nc = payload["next_commands"]
    assert "review_plan" in nc
    assert "validate_archive" in nc
    assert "execute_if_approved" in nc


def test_prepare_review_plan_command_actually_works(tmp_path: Path, monkeypatch) -> None:
    """The review_plan next command must succeed against the generated plan."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    cmd = payload["next_commands"]["review_plan"]
    assert cmd[0] == "shellforgeai"
    # Invoke the actual CLI (drop the "shellforgeai" head).
    res = runner.invoke(app, cmd[1:])
    assert res.exit_code == 0, res.stdout


def test_prepare_validate_archive_command_actually_works(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    cmd = payload["next_commands"]["validate_archive"]
    res = runner.invoke(app, cmd[1:])
    assert res.exit_code == 0, res.stdout


def test_prepare_execute_command_requires_confirm(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    cmd = payload["next_commands"]["execute_if_approved"]
    assert "--confirm" in cmd
    # Without --confirm the execute command still refuses (PR71 regression).
    plan_id = payload["plan"]["id"]
    res = runner.invoke(app, ["audit", "cleanup", "execute", plan_id])
    assert res.exit_code == 1
    assert "confirm" in res.stdout.lower()


# --- cleanup plan validation (Option A) -----------------------------------


def _generate_plan(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "prepare", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    return Path(payload["plan"]["path"])


def test_cleanup_validate_passes_for_generated_plan(tmp_path: Path, monkeypatch) -> None:
    plan_path = _generate_plan(tmp_path, monkeypatch)
    out = runner.invoke(app, ["audit", "cleanup", "validate", str(plan_path)])
    assert out.exit_code == 0, out.stdout
    assert "Cleanup plan validation passed" in out.stdout
    assert "execution_allowed: false" in out.stdout
    assert "mutation_performed: false" in out.stdout


def test_cleanup_validate_plan_rejects_execution_allowed_true(tmp_path: Path, monkeypatch) -> None:
    plan_path = _generate_plan(tmp_path, monkeypatch)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["execution_allowed"] = True
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "validate", str(plan_path)])
    assert out.exit_code == 1
    assert "execution_allowed must be false" in out.stdout


def test_cleanup_validate_plan_rejects_mutation_performed_true(tmp_path: Path, monkeypatch) -> None:
    plan_path = _generate_plan(tmp_path, monkeypatch)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["mutation_performed"] = True
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "validate", str(plan_path)])
    assert out.exit_code == 1
    assert "mutation_performed must be false" in out.stdout


def test_cleanup_validate_plan_rejects_requires_archive_false(tmp_path: Path, monkeypatch) -> None:
    plan_path = _generate_plan(tmp_path, monkeypatch)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["requires_archive"] = False
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "validate", str(plan_path)])
    assert out.exit_code == 1
    assert "requires_archive must be true" in out.stdout


def test_cleanup_validate_plan_rejects_requires_confirm_false(tmp_path: Path, monkeypatch) -> None:
    plan_path = _generate_plan(tmp_path, monkeypatch)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["requires_confirm"] = False
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "validate", str(plan_path)])
    assert out.exit_code == 1
    assert "requires_confirm must be true" in out.stdout


def test_cleanup_validate_plan_rejects_safety_metadata_only_false(
    tmp_path: Path, monkeypatch
) -> None:
    plan_path = _generate_plan(tmp_path, monkeypatch)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["safety"]["shellforgeai_metadata_only"] = False
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "validate", str(plan_path)])
    assert out.exit_code == 1
    assert "shellforgeai_metadata_only must be true" in out.stdout


def test_cleanup_validate_plan_rejects_unsafe_candidate_path(tmp_path: Path, monkeypatch) -> None:
    plan_path = _generate_plan(tmp_path, monkeypatch)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["candidates"].append(
        {
            "path": "../../etc/passwd",
            "category": "exports",
            "bytes": 1,
            "age_days": 0,
            "reason": "x",
            "safe_to_delete": True,
            "requires_archive_first": False,
        }
    )
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "validate", str(plan_path)])
    assert out.exit_code == 1
    assert "unsafe candidate path" in out.stdout


def test_cleanup_validate_plan_does_not_require_remediation_fields(
    tmp_path: Path, monkeypatch
) -> None:
    """Plan validator must not require post-execute receipt fields."""
    plan_path = _generate_plan(tmp_path, monkeypatch)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    # The plan has no remediation_execution / docker_mutation keys at top level.
    assert "remediation_execution" not in payload
    out = runner.invoke(app, ["audit", "cleanup", "validate", str(plan_path)])
    assert out.exit_code == 0, out.stdout
