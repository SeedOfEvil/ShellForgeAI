"""PR217 Docker01 hygiene discovery noise normalization tests."""

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_hygiene_report.py"


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


h = _load("pr217_hygiene_discovery_noise", HELPER_PATH)


def _report(created: str, items: int = 0):
    return {
        "schema_version": 1,
        "mode": h.MODE,
        "status": "ok",
        "created_at": created,
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "disk_use_percent": "47%",
            "candidate_cleanup_items_total": items,
            "candidate_cleanup_bytes_estimated": items * 100,
        },
        "candidate_cleanup": [],
        "safety": h.safety_block(),
        "warnings": [],
    }


def make_report(root: Path, name: str, created: str, items: int = 0) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "hygiene-report.json").write_text(json.dumps(_report(created, items)))
    (d / "hygiene-summary.md").write_text("# Hygiene\nNo cleanup was performed.\n")
    (d / "candidate-cleanup-plan.md").write_text(
        "# Candidate Cleanup Plan\nProposal only. No cleanup was performed.\n"
    )
    (d / "commands-run.json").write_text("[]")
    return d


def make_stale_bundle(root: Path, name: str = "sfai-pr212-hygiene-review-bundle") -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "hygiene-review.json").write_text("{}")
    (d / "hygiene-review-summary.md").write_text("review bundle, not report\n")
    (d / "manifest.json").write_text("{}")
    return d


def test_history_ignores_review_bundle_shaped_candidate_with_valid_report(tmp_path):
    report = make_report(tmp_path, "sfai-docker01-hygiene-report-1", "2026-01-01T00:00:00+00:00")
    stale = make_stale_bundle(tmp_path)

    history = h.build_history(tmp_path)

    assert history["status"] == "ok"
    assert history["valid_reports_found"] == 1
    assert history["reports"][0]["report_dir"] == str(report.resolve())
    assert history["ignored_candidates_count"] == 1
    assert history["ignored_candidates"] == [
        {"path": str(stale.resolve()), "reason": h.IGNORED_MISSING_REQUIRED_REASON}
    ]
    assert "partial" not in " ".join(history["warnings"])
    assert "ignored 1 stale/non-report hygiene candidate" in history["warnings"]


def test_history_empty_when_only_stale_candidates(tmp_path):
    make_stale_bundle(tmp_path)

    history = h.build_history(tmp_path)

    assert history["status"] == "empty"
    assert history["valid_reports_found"] == 0
    assert history["reports"] == []
    assert history["ignored_candidates_count"] == 1


def test_ignored_candidates_are_bounded_but_count_is_total(tmp_path):
    for i in range(h.MAX_IGNORED_CANDIDATES + 5):
        make_stale_bundle(tmp_path, f"sfai-docker01-hygiene-review-bundle-{i:02d}")

    history = h.build_history(tmp_path)

    assert history["status"] == "empty"
    assert history["ignored_candidates_count"] == h.MAX_IGNORED_CANDIDATES + 5
    assert len(history["ignored_candidates"]) == h.MAX_IGNORED_CANDIDATES
    assert {c["reason"] for c in history["ignored_candidates"]} == {
        h.IGNORED_MISSING_REQUIRED_REASON
    }


def test_malformed_required_report_json_is_partial_not_ignored(tmp_path):
    d = make_report(tmp_path, "sfai-docker01-hygiene-report-bad", "2026-01-01T00:00:00+00:00")
    (d / "hygiene-report.json").write_text("{")

    history = h.build_history(tmp_path)

    assert history["status"] == "partial"
    assert history["reports"][0]["status"] == "partial"
    assert history["ignored_candidates_count"] == 0


def test_missing_required_report_shaped_candidate_is_ignored(tmp_path):
    d = tmp_path / "sfai-docker01-hygiene-report-incomplete"
    d.mkdir()
    (d / "hygiene-report.json").write_text(json.dumps(_report("2026-01-01T00:00:00+00:00")))

    history = h.build_history(tmp_path)

    assert history["status"] == "empty"
    assert history["reports"] == []
    assert history["ignored_candidates"][0]["path"] == str(d.resolve())


def test_compare_latest_uses_two_newest_valid_reports_and_ignores_stale(tmp_path):
    old = make_report(tmp_path, "sfai-docker01-hygiene-report-old", "2026-01-01T00:00:00+00:00", 1)
    mid = make_report(tmp_path, "sfai-docker01-hygiene-report-mid", "2026-01-02T00:00:00+00:00", 2)
    new = make_report(tmp_path, "sfai-docker01-hygiene-report-new", "2026-01-03T00:00:00+00:00", 4)
    make_stale_bundle(tmp_path)

    compare = h.build_compare_latest(tmp_path)

    assert compare["status"] == "ok"
    assert compare["old_report_dir"] == str(mid.resolve())
    assert compare["new_report_dir"] == str(new.resolve())
    assert compare["ignored_candidates_count"] == 1
    assert str(old.resolve()) not in {compare["old_report_dir"], compare["new_report_dir"]}


def test_compare_latest_not_available_shape_with_fewer_than_two_valid_reports(tmp_path):
    make_report(tmp_path, "sfai-docker01-hygiene-report-one", "2026-01-01T00:00:00+00:00")
    make_stale_bundle(tmp_path)

    compare = h.build_compare_latest(tmp_path)

    assert compare["status"] == "failed"
    assert "fewer than two" in compare["warnings"][0]
    assert compare["ignored_candidates_count"] == 1


def test_review_bundle_latest_selects_valid_report_not_stale_bundle(tmp_path):
    report = make_report(tmp_path, "sfai-docker01-hygiene-report-new", "2026-01-03T00:00:00+00:00")
    stale = make_stale_bundle(tmp_path, "sfai-docker01-hygiene-review-bundle-20260103")
    out = tmp_path / "out-review"

    bundle = h.build_review_bundle_latest(tmp_path, out=out)

    assert bundle["status"] == "ok"
    assert bundle["source_report_dir"] == str(report.resolve())
    assert bundle["source_report_dir"] != str(stale.resolve())
    assert bundle["ignored_candidates_count"] == 1


def test_source_safety_no_shell_true_no_mutating_discovery_options_or_delete_paths():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    for forbidden in (
        "--execute",
        "--apply",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
    ):
        assert forbidden not in source
    for forbidden_call in (".unlink(", ".rmdir(", "shutil.rmtree", "os.remove", "os.unlink"):
        assert forbidden_call not in source
