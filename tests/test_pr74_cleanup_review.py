"""PR74 — /data cleanup review pack and safe housekeeping runbook.

Read-only cleanup review is an operator decision aid:
- summarizes ShellForgeAI metadata footprint,
- groups categories by size/count,
- identifies cleanup_supported vs report-only categories,
- recommends a conservative dry-run cleanup plan command,
- restates the PR71 deletion gates,
- never creates plans/archives, never deletes, never mutates anything.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _seed_exports(data_dir: Path, count: int = 2, size: int = 64) -> None:
    exports = data_dir / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (exports / f"e{i}.json").write_text("x" * size, encoding="utf-8")


# --- core review behavior --------------------------------------------------


def test_cleanup_review_works_with_empty_data_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "review"])
    assert out.exit_code == 0
    assert "ShellForgeAI cleanup review" in out.stdout
    assert "execution: none" in out.stdout
    assert "review_only: true" in out.stdout
    assert "cleanup_executed: false" in out.stdout


def test_cleanup_review_summarizes_total_bytes_and_items(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=3, size=100)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert payload["summary"]["total_items"] >= 3
    assert payload["summary"]["total_bytes"] >= 300
    assert payload["summary"]["largest_category"] == "exports"


def test_cleanup_review_groups_categories_by_size(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "small.json").write_text("a" * 10, encoding="utf-8")
    (tmp_path / "audit_exports").mkdir()
    (tmp_path / "audit_exports" / "big.json").write_text("b" * 500, encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    cats = payload["categories"]
    sizes = [c["bytes"] for c in cats]
    assert sizes == sorted(sizes, reverse=True)
    assert payload["summary"]["largest_category"] == "audit-exports"


def test_cleanup_review_marks_review_only_true(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    assert payload["review_only"] is True
    assert payload["safety"]["review_only"] is True


def test_cleanup_review_marks_cleanup_executed_false(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    assert payload["safety"]["cleanup_executed"] is False


def test_cleanup_review_marks_mutation_performed_false(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["arbitrary_paths_allowed"] is False
    assert payload["safety"]["docker_mutation"] is False
    assert payload["safety"]["system_mutation"] is False
    assert payload["safety"]["natural_language_execution"] is False


def test_cleanup_review_recommends_exports_first_lane(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    assert payload["safest_first_lane"] == "exports"
    cmds = [r["command_display"] for r in payload["recommendations"]]
    assert any("--category exports" in c for c in cmds)
    assert all(r["mutation"] is False for r in payload["recommendations"])


def test_cleanup_review_does_not_recommend_unsupported_categories(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    approvals = tmp_path / "approvals" / "pending"
    approvals.mkdir(parents=True)
    (approvals / "p.json").write_text("{}", encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    approvals_entry = next(c for c in payload["categories"] if c["name"] == "approvals")
    assert approvals_entry["cleanup_supported"] is False
    assert approvals_entry["recommended"] is False
    assert "report-only" in approvals_entry["reason"]
    for rec in payload["recommendations"]:
        assert rec["category"] != "approvals"
        assert rec["category"] != "audit-events"


def test_cleanup_review_includes_required_gates(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    gates = payload["required_gates_before_deletion"]
    for required in (
        "cleanup_plan",
        "matching_archive",
        "archive_validation",
        "matching_plan_fingerprint",
        "explicit_confirm",
        "receipt_validation",
    ):
        assert required in gates


def test_cleanup_review_includes_next_safe_dry_run_command(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    cmds = payload["next_safe_commands"]
    assert any("cleanup plan" in c for c in cmds)
    assert any("cleanup archive" in c for c in cmds)
    assert any("cleanup validate" in c for c in cmds)
    assert all("execute" not in c for c in cmds)


# --- no side effects ------------------------------------------------------


def test_cleanup_review_does_not_create_cleanup_plan_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    runner.invoke(app, ["audit", "cleanup", "review"])
    runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    assert not (tmp_path / "cleanup_plans").exists()


def test_cleanup_review_does_not_create_archives(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    runner.invoke(app, ["audit", "cleanup", "review"])
    assert not (tmp_path / "cleanup_archives").exists()
    assert not (tmp_path / "archives").exists()


def test_cleanup_review_does_not_delete_candidate_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=4, size=20)
    before = sorted(p.name for p in (tmp_path / "exports").iterdir())
    runner.invoke(app, ["audit", "cleanup", "review"])
    runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    runner.invoke(app, ["audit", "cleanup", "review", "--category", "exports"])
    after = sorted(p.name for p in (tmp_path / "exports").iterdir())
    assert before == after


# --- JSON shape -----------------------------------------------------------


def test_cleanup_review_json_strict_parseable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    assert out.exit_code == 0
    text = out.stdout.strip()
    assert text.startswith("{")
    assert text.endswith("}")
    json.loads(text)


def test_cleanup_review_json_includes_required_fields(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    for key in (
        "schema_version",
        "status",
        "data_root",
        "review_only",
        "summary",
        "categories",
        "recommendations",
        "required_gates_before_deletion",
        "safety",
        "warnings",
    ):
        assert key in payload, f"missing key: {key}"
    assert payload["schema_version"] == "1"


def test_cleanup_review_json_safety_invariants(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    safety = payload["safety"]
    assert safety["review_only"] is True
    assert safety["cleanup_executed"] is False
    assert safety["mutation_performed"] is False
    assert safety["arbitrary_paths_allowed"] is False
    assert safety["docker_mutation"] is False
    assert safety["system_mutation"] is False
    assert safety["natural_language_execution"] is False


def test_cleanup_review_no_text_before_or_after_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    assert out.exit_code == 0
    text = out.stdout.strip()
    assert text.startswith("{")
    assert text.endswith("}")
    assert "ShellForgeAI cleanup review" not in out.stdout
    assert "Recommended review lanes" not in out.stdout


# --- filters --------------------------------------------------------------


def test_cleanup_review_category_filter_limits_output(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    (tmp_path / "audit_exports").mkdir()
    (tmp_path / "audit_exports" / "x.json").write_text("z" * 10, encoding="utf-8")
    out = runner.invoke(app, ["audit", "cleanup", "review", "--category", "exports", "--json"])
    payload = json.loads(out.stdout)
    names = [c["name"] for c in payload["categories"]]
    assert names == ["exports"]


def test_cleanup_review_top_limits_category_display(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--top", "2", "--json"])
    payload = json.loads(out.stdout)
    assert len(payload["categories"]) == 2


def test_cleanup_review_unknown_category_is_clean(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "review", "--category", "bogus", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert payload["categories"] == []
    assert any("unknown category" in w for w in payload["warnings"])


def test_cleanup_review_no_candidates_message(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    out = runner.invoke(app, ["audit", "cleanup", "review", "--category", "bogus"])
    assert out.exit_code == 0
    assert "No cleanup candidates found" in out.stdout
    assert "No deletion was performed" in out.stdout


# --- ask routing regression (PR70 ask path unchanged) ---------------------


def test_ask_clean_now_still_refuses(tmp_path: Path, monkeypatch) -> None:
    """Natural-language cleanup mutation refusal stays intact (PR70 regression)."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["ask", "clean it now"])
    assert out.exit_code == 0
    assert "Refusing automatic deletion" in out.stdout
    assert (tmp_path / "exports" / "e0.json").exists()
    assert not (tmp_path / "cleanup_plans").exists()
    assert not (tmp_path / "cleanup_archives").exists()


def test_cleanup_review_does_not_mutate_data_dir(tmp_path: Path, monkeypatch) -> None:
    """Review must not create plans, archives, receipts, or audit-prune state."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path, count=5)
    before = set(p.name for p in tmp_path.iterdir())
    runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    after = set(p.name for p in tmp_path.iterdir())
    new_dirs = after - before
    forbidden = {
        "cleanup_plans",
        "cleanup_archives",
        "cleanup_receipts",
        "archives",
        "prune_receipts",
        "execution_receipts",
    }
    assert new_dirs.isdisjoint(forbidden), (
        f"cleanup review should not create {forbidden & new_dirs}"
    )


def test_cleanup_review_recommended_command_is_dry_run_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_exports(tmp_path)
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    payload = json.loads(out.stdout)
    for rec in payload["recommendations"]:
        cmd = rec["command_display"]
        assert "--execute" not in cmd
        assert "--confirm" not in cmd
        assert "cleanup plan" in cmd
