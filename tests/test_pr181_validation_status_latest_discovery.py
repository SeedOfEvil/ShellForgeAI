"""PR181 — deterministic ``--latest`` validation-artifact discovery + explanation.

These tests cover the polish to ``scripts/validation_status.py --latest``: it now
chooses the most relevant validation evidence artifact deterministically
(preferring recent PR-specific run directories over older persisted manifests),
supports ``--pr`` / ``--commit`` / ``--run-root`` / ``--include-legacy`` filters,
and explains the selected and skipped candidates with ``--explain-selection``.

They are tooling tests only. They never run Docker/Compose, never run a real
long pytest, never run ruff, never mutate services/containers or real
``/srv/data``/``/tmp``, and never require the Docker daemon. ``tmp_path``
fixtures and fake JSON evidence are used throughout, and the real artifact roots
are redirected to nonexistent temp paths so no host artifact leaks in.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
VIEWER_PATH = SCRIPTS / "validation_status.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


vs = _load("pr181_validation_status", VIEWER_PATH)


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
@pytest.fixture
def isolated_roots(tmp_path, monkeypatch):
    """Redirect the real artifact roots away from the host and clear overrides.

    Returns a small namespace of injectable roots:
      * ``runs`` — env override mapped to ``run_dir`` candidates.
      * ``persisted`` — env override mapped to persisted ``manifest`` candidates.
      * ``legacy`` — env override mapped to ``legacy_manifest`` candidates.
    """
    nowhere = tmp_path / "_nonexistent"
    monkeypatch.setattr(vs, "TMP_ROOT", nowhere / "tmp")
    monkeypatch.setattr(vs, "MAINLINE_TMP_ROOT", nowhere / "mainline")
    monkeypatch.setattr(vs, "PERSISTED_ROOT", nowhere / "persisted")
    monkeypatch.setattr(vs, "LEGACY_ROOT", nowhere / "legacy")
    for env in (vs.RUNS_DIR_ENV, vs.PERSISTED_DIR_ENV, vs.LEGACY_DIR_ENV):
        monkeypatch.delenv(env, raising=False)

    runs = tmp_path / "runs"
    persisted = tmp_path / "persisted"
    legacy = tmp_path / "legacy"
    runs.mkdir()
    persisted.mkdir()
    legacy.mkdir()
    monkeypatch.setenv(vs.RUNS_DIR_ENV, str(runs))
    monkeypatch.setenv(vs.PERSISTED_DIR_ENV, str(persisted))
    monkeypatch.setenv(vs.LEGACY_DIR_ENV, str(legacy))

    class Roots:
        pass

    roots = Roots()
    roots.runs = runs
    roots.persisted = persisted
    roots.legacy = legacy
    return roots


def _write(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _incomplete_hb(pr=180, commit="0b407fa") -> dict:
    return {
        "schema_version": 1,
        "mode": "validation_heartbeat",
        "pr": pr,
        "commit": commit,
        "status": "running",
        "active_phase": "full_pytest",
        "last_completed_phase": "targeted_tests",
        "phase_status": {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "running",
        },
        "full_pytest_exit_code": None,
    }


def _setup_failure_manifest(pr=180, commit="0b407fa") -> dict:
    return {
        "schema_version": 1,
        "mode": "docker01_pr_validation_manifest",
        "pr": pr,
        "commit": commit,
        "status": "failed",
        "classification": "setup_failure",
        "phase_status": {
            "ruff": "failed",
            "compileall": "not_started",
            "targeted_tests": "not_started",
            "full_pytest": "not_started",
        },
        "failed_phase": "ruff",
    }


def _make_run_dir(parent: Path, name: str, evidence: dict, *, mtime: float, kind="hb") -> Path:
    run_dir = parent / name
    fname = {
        "hb": "validation-heartbeat.json",
        "manifest": "manifest.json",
        "status": "validation-status.json",
    }[kind]
    target = _write(run_dir / fname, evidence)
    os.utime(target, (mtime, mtime))
    return run_dir


def _json(argv: list[str], capsys) -> dict:
    assert vs.main(argv) == 0
    out = capsys.readouterr().out
    return json.loads(out)


def _human(argv: list[str], capsys) -> str:
    assert vs.main(argv) == 0
    return capsys.readouterr().out


# --------------------------------------------------------------------------- #
# 1-6. Latest discovery
# --------------------------------------------------------------------------- #
def test_01_latest_prefers_run_dir_over_older_persisted(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.persisted,
        "old-manifest",
        _setup_failure_manifest(),
        mtime=2_000_000,
        kind="manifest",
    )
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-0b407fa-validation-20260610T123118Z",
        _incomplete_hb(),
        mtime=1_000_000,
    )
    report = _json(["--latest", "--json"], capsys)
    assert report["source"]["run_dir"].endswith("sfai-pr180-0b407fa-validation-20260610T123118Z")
    assert report["source"]["kind"] == "run_dir"


def test_02_latest_json_includes_selected_path_and_reason(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-0b407fa-validation-20260610T123118Z",
        _incomplete_hb(),
        mtime=1_000_000,
    )
    report = _json(["--latest", "--json"], capsys)
    selection = report["selection"]
    assert selection["selected_path"].endswith("validation-20260610T123118Z")
    assert selection["selected_reason"] == "latest matching PR-specific validation run"
    assert report["source"]["selection_reason"] == "latest matching PR-specific validation run"


def test_03_explain_selection_includes_candidates(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    _make_run_dir(
        isolated_roots.persisted,
        "old-manifest",
        _setup_failure_manifest(),
        mtime=900_000,
        kind="manifest",
    )
    report = _json(["--latest", "--json", "--explain-selection"], capsys)
    candidates = report["selection"]["candidates"]
    assert len(candidates) == 2
    assert report["selection"]["candidate_count"] == 2


def test_04_candidate_list_marks_selected(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    report = _json(["--latest", "--json", "--explain-selection"], capsys)
    selected = [c for c in report["selection"]["candidates"] if c["selected"]]
    assert len(selected) == 1
    assert selected[0]["reason"]


def test_05_candidate_list_includes_skipped_reason(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    _make_run_dir(
        isolated_roots.persisted,
        "old-manifest",
        _setup_failure_manifest(),
        mtime=900_000,
        kind="manifest",
    )
    report = _json(["--latest", "--json", "--explain-selection"], capsys)
    skipped = [c for c in report["selection"]["candidates"] if not c["selected"]]
    assert skipped
    assert all(c["skipped_reason"] for c in skipped)
    assert any("persisted" in c["skipped_reason"] for c in skipped)


def test_06_no_candidates_returns_not_found(isolated_roots, capsys):
    report = _json(["--latest", "--json"], capsys)
    assert report["status"] == "not_found"
    assert report["classification"] == "not_found"
    assert report["pass_eligible"] is False
    assert report["rerun_required"] is True


def test_06b_no_candidates_human_has_no_traceback(isolated_roots, capsys):
    out = _human(["--latest"], capsys)
    assert "Status: NOT_FOUND" in out
    assert "Traceback" not in out
    assert "First safe command:" in out


# --------------------------------------------------------------------------- #
# 7-12. PR/commit filters
# --------------------------------------------------------------------------- #
def test_07_pr_filter_selects_matching(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-aaa1111-validation-A",
        _incomplete_hb(pr=180),
        mtime=1_000_000,
    )
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr181-bbb2222-validation-B",
        _incomplete_hb(pr=181, commit="bbb2222"),
        mtime=2_000_000,
    )
    report = _json(["--latest", "--pr", "180", "--json"], capsys)
    assert report["source"]["pr"] == 180
    assert "pr180" in report["source"]["run_dir"]


def test_08_commit_filter_selects_matching(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-aaa1111-validation-A",
        _incomplete_hb(commit="aaa1111"),
        mtime=1_000_000,
    )
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr181-bbb2222-validation-B",
        _incomplete_hb(pr=181, commit="bbb2222"),
        mtime=2_000_000,
    )
    report = _json(["--latest", "--commit", "aaa1111", "--json"], capsys)
    assert "aaa1111" in report["source"]["run_dir"]


def test_09_pr_and_commit_requires_both(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-aaa1111-validation-A",
        _incomplete_hb(commit="aaa1111"),
        mtime=1_000_000,
    )
    # PR matches but commit does not -> not_found.
    report = _json(["--latest", "--pr", "180", "--commit", "zzz9999", "--json"], capsys)
    assert report["status"] == "not_found"


def test_10_unmatched_pr_returns_not_found(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs, "sfai-pr180-aaa1111-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    report = _json(["--latest", "--pr", "999", "--json"], capsys)
    assert report["status"] == "not_found"


def test_11_unmatched_commit_returns_not_found(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-aaa1111-validation-A",
        _incomplete_hb(commit="aaa1111"),
        mtime=1_000_000,
    )
    report = _json(["--latest", "--commit", "deadbee", "--json"], capsys)
    assert report["status"] == "not_found"


def test_12_ambiguous_commit_prefix_newest_with_warning(isolated_roots, capsys):
    # Two run dirs share the same commit prefix; newest must win deterministically.
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-abc1234-validation-A",
        _incomplete_hb(commit="abc1234"),
        mtime=1_000_000,
    )
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-abc1234-validation-B",
        _incomplete_hb(commit="abc1234"),
        mtime=2_000_000,
    )
    report = _json(["--latest", "--commit", "abc", "--json"], capsys)
    assert report["source"]["run_dir"].endswith("validation-B")
    assert any("multiple matching candidates" in w for w in report["warnings"])


# --------------------------------------------------------------------------- #
# 13-15. Legacy behavior
# --------------------------------------------------------------------------- #
def test_13_persisted_manifest_does_not_outrank_run_dir(isolated_roots, capsys):
    # Persisted manifest is newer, but the PR-specific run dir must still win.
    _make_run_dir(
        isolated_roots.persisted,
        "fresh-manifest",
        _setup_failure_manifest(),
        mtime=5_000_000,
        kind="manifest",
    )
    _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    report = _json(["--latest", "--json"], capsys)
    assert report["source"]["kind"] == "run_dir"


def test_14_include_legacy_includes_legacy_candidates(isolated_roots, capsys):
    _make_run_dir(isolated_roots.legacy, "legacy-run", _incomplete_hb(), mtime=1_000_000)
    # Without --include-legacy: not discovered -> not_found.
    report_without = _json(["--latest", "--json"], capsys)
    assert report_without["status"] == "not_found"
    # With --include-legacy: the legacy candidate appears.
    report_with = _json(["--latest", "--include-legacy", "--json", "--explain-selection"], capsys)
    assert report_with["selection"]["candidate_count"] == 1
    assert report_with["selection"]["candidates"][0]["kind"] == "legacy_manifest"


def test_15_old_incomplete_artifact_remains_incomplete(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    report = _json(["--latest", "--json"], capsys)
    assert report["status"] == "incomplete"
    assert report["rerun_required"] is True


# --------------------------------------------------------------------------- #
# 16-20. Conservative classification
# --------------------------------------------------------------------------- #
def test_16_setup_failure_remains_failed(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-0b407fa-validation-A",
        _setup_failure_manifest(),
        mtime=1_000_000,
        kind="manifest",
    )
    report = _json(["--latest", "--json"], capsys)
    assert report["status"] == "failed"
    assert report["classification"] == "setup_failure"


def test_17_incomplete_artifact_remains_incomplete(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    report = _json(["--latest", "--json"], capsys)
    assert report["status"] == "incomplete"


def test_18_fallback_packet_presence_does_not_pass(isolated_roots, capsys):
    run_dir = _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    _write(run_dir / vs.FALLBACK_PACKET_NAME, {"mode": "validation_container_fallback"})
    report = _json(["--latest", "--json"], capsys)
    assert report["status"] != "passed"
    assert report["pass_eligible"] is False


def test_19_lane_b_marker_no_pass_without_full_pytest(isolated_roots, capsys):
    # A targeted-only (Lane B) manifest must not read as passed without full
    # pytest completion evidence.
    manifest = {
        "mode": "docker01_pr_validation_manifest",
        "pr": 180,
        "commit": "0b407fa",
        "status": "passed",
        "lane": {"selected": "targeted_runtime", "full_validation_required": False},
        "phase_status": {
            "ruff": "passed",
            "compileall": "passed",
            "targeted_tests": "passed",
            "full_pytest": "not_required",
        },
        "full_pytest_exit_code": None,
    }
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-0b407fa-validation-A",
        manifest,
        mtime=1_000_000,
        kind="manifest",
    )
    report = _json(["--latest", "--json"], capsys)
    assert report["pass_eligible"] is False
    assert report["qa_marker"]["validation_lane"] == "B"


def test_20_no_false_pass_when_phase_evidence_missing(isolated_roots, capsys):
    manifest = {
        "mode": "docker01_pr_validation_manifest",
        "pr": 180,
        "commit": "0b407fa",
        "status": "passed",
        "phase_status": {},
        "full_pytest_exit_code": None,
    }
    _make_run_dir(
        isolated_roots.runs,
        "sfai-pr180-0b407fa-validation-A",
        manifest,
        mtime=1_000_000,
        kind="manifest",
    )
    report = _json(["--latest", "--json"], capsys)
    assert report["pass_eligible"] is False


# --------------------------------------------------------------------------- #
# 21-29. JSON / safety
# --------------------------------------------------------------------------- #
def test_21_json_output_remains_strict(isolated_roots, capsys):
    _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    assert vs.main(["--latest", "--json", "--explain-selection"]) == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert out.strip() == json.dumps(parsed, sort_keys=True)


def _safety(isolated_roots, capsys) -> dict:
    _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    return _json(["--latest", "--json"], capsys)["safety"]


def test_22_safety_validation_executed_false(isolated_roots, capsys):
    assert _safety(isolated_roots, capsys)["validation_executed"] is False


def test_23_safety_pytest_executed_false(isolated_roots, capsys):
    assert _safety(isolated_roots, capsys)["pytest_executed"] is False


def test_24_safety_ruff_executed_false(isolated_roots, capsys):
    assert _safety(isolated_roots, capsys)["ruff_executed"] is False


def test_25_safety_docker_compose_executed_false(isolated_roots, capsys):
    assert _safety(isolated_roots, capsys)["docker_compose_executed"] is False


def test_26_safety_container_restarted_false(isolated_roots, capsys):
    assert _safety(isolated_roots, capsys)["container_restarted"] is False


def test_27_safety_mutation_performed_false(isolated_roots, capsys):
    assert _safety(isolated_roots, capsys)["mutation_performed"] is False


def test_28_safety_artifact_repaired_false(isolated_roots, capsys):
    assert _safety(isolated_roots, capsys)["artifact_repaired"] is False


def test_29_safety_artifact_deleted_false(isolated_roots, capsys):
    assert _safety(isolated_roots, capsys)["artifact_deleted"] is False


# --------------------------------------------------------------------------- #
# 30-31. Path bounds
# --------------------------------------------------------------------------- #
def test_30_broad_run_root_rejected(isolated_roots, capsys):
    report = _json(["--latest", "--run-root", "/", "--json"], capsys)
    assert report["status"] == "not_found"
    assert any("too broad" in w for w in report["warnings"])


def test_31_path_traversal_run_root_rejected(isolated_roots, capsys):
    report = _json(["--latest", "--run-root", "../../etc", "--json"], capsys)
    assert report["status"] == "not_found"
    assert any("traversal" in w for w in report["warnings"])


def test_31b_run_root_scans_only_within(isolated_roots, tmp_path, capsys):
    root = tmp_path / "myroot"
    _make_run_dir(root, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000)
    report = _json(["--latest", "--run-root", str(root), "--json"], capsys)
    assert report["source"]["run_dir"].startswith(str(root))
    assert report["selection"]["filters"]["run_root"] == str(root)


# --------------------------------------------------------------------------- #
# 32-35. Regression
# --------------------------------------------------------------------------- #
def test_32_pr177_viewer_tests_still_importable():
    mod = _load("pr181_check_177", REPO_ROOT / "tests" / "test_pr177_validation_status_viewer.py")
    assert hasattr(mod, "test_22_latest_chooses_most_recent_run")


def test_33_explicit_run_dir_bypasses_discovery(isolated_roots, tmp_path, capsys):
    run_dir = _make_run_dir(tmp_path, "explicit", _incomplete_hb(), mtime=1_000_000)
    report = _json(["--run-dir", str(run_dir), "--json"], capsys)
    assert report["source"]["run_dir"] == str(run_dir)
    # Explicit run-dir takes priority; no latest-selection block is attached.
    assert report["selection"] is None


def test_34_viewer_does_not_execute_or_mutate(isolated_roots, capsys):
    run_dir = _make_run_dir(
        isolated_roots.runs, "sfai-pr180-0b407fa-validation-A", _incomplete_hb(), mtime=1_000_000
    )
    before = {p.name: p.stat().st_mtime for p in run_dir.iterdir()}
    _json(["--latest", "--json", "--explain-selection"], capsys)
    after = {p.name: p.stat().st_mtime for p in run_dir.iterdir()}
    assert before == after


def test_35_no_subprocess_or_model_in_viewer():
    sub = "subprocess"
    text = VIEWER_PATH.read_text(encoding="utf-8")
    assert f"import {sub}" not in text
    assert f"{sub}.run" not in text
    assert "codex" not in text.lower()
    assert "openai" not in text.lower()
