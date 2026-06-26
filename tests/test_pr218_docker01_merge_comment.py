import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "docker01_merge_readiness.py"
spec = importlib.util.spec_from_file_location("merge", HELPER)
merge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge)

COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def base_report(status="pass_candidate"):
    return {
        "schema_version": 1,
        "mode": "docker01_merge_readiness",
        "status": status,
        "pr": 218,
        "commit": COMMIT,
        "short_sha": COMMIT[:12],
        "created_at": "2026-06-17T00:00:00Z",
        "inputs": {
            "pr_lane_status_available": status != "unknown",
            "validation_status_available": status != "unknown",
            "qa_bundle_available": status != "unknown",
            "hygiene_available": True,
        },
        "summary": {
            "source_matches": True,
            "compose_matches": True,
            "container_matches": True,
            "container_running": True,
            "container_healthy": True,
            "restart_count_acceptable": True,
            "validation_pass_eligible": True,
            "qa_bundle_passed": True,
            "safety_assertions_passed": True,
            "full_pytest_run": True,
            "duplicate_full_pytest_detected": False,
        },
        "evidence": {
            "validation": {
                "status": "passed",
                "classification": "passed",
                "pass_eligible": True,
                "rerun_required": False,
            },
            "hygiene": {
                "history_status": "ok",
                "compare_latest_status": "ok",
                "review_bundle_status": "ok",
                "ignored_stale_candidates": ["old"],
                "warnings": ["ignored stale hygiene candidate"],
            },
            "qa_bundle": {
                "status": "passed",
                "commands_passed": 10,
                "commands_failed": 0,
                "safety_assertions_passed": 8,
                "safety_assertions_failed": 0,
                "bundle_path": "/tmp/fake",
            },
        },
        "blocking_reasons": []
        if status != "hold_candidate"
        else ["Validation evidence is not pass-eligible (failed/failed)."],
        "warnings": ["ignored stale hygiene candidate"],
        "safety": dict(merge.SAFETY_FLAGS),
    }


def test_pass_candidate_comment_is_paste_ready():
    text = merge.render_comment(base_report("pass_candidate"))
    assert "Verdict: PASS / mergeable." in text
    assert "PR218" in text and COMMIT[:12] in text
    assert "SeedOfEvil remains final merge owner" in text
    assert "Blocking reasons: none" in text
    assert "Ignored stale hygiene candidates: 1" in text
    assert "no Docker prune" in text and "no shell=True" in text
    assert "Approved for merge by evidence review." in text


def test_hold_candidate_comment_includes_blockers():
    text = merge.render_comment(base_report("hold_candidate"))
    assert "Verdict: HOLD / needs follow-up." in text
    assert "Validation evidence is not pass-eligible" in text
    assert "evidence-only comment draft" in text
    assert "no mutation performed" in text


def test_unknown_comment_reports_missing_evidence_not_pass():
    text = merge.render_comment(base_report("unknown"))
    assert "Verdict: NEEDS EVIDENCE / cannot determine." in text
    assert "does not have enough Docker01 evidence" in text
    assert "validation status evidence" in text
    assert "PASS / mergeable" not in text


def test_comment_stdout_and_out_file(tmp_path, capsys, monkeypatch):
    report = base_report("pass_candidate")
    monkeypatch.setattr(merge, "build_report", lambda pr, commit: (report, {}))
    assert merge.main(["--pr", "218", "--commit", COMMIT, "--comment"]) == 0
    assert "Verdict: PASS / mergeable." in capsys.readouterr().out
    out = tmp_path / "out"
    assert merge.main(["--pr", "218", "--commit", COMMIT, "--out", str(out), "--comment"]) == 0
    assert (out / "merge-comment.md").read_text(encoding="utf-8").startswith("Verdict: PASS")
    data = json.loads((out / "merge-readiness.json").read_text(encoding="utf-8"))
    assert data["comment_file"] == "merge-comment.md"


def test_comment_json_conflict_fails_clearly():
    with pytest.raises(SystemExit, match="--comment cannot be combined with --json"):
        merge.main(["--pr", "218", "--commit", COMMIT, "--comment", "--json"])


def test_from_json_comment_works(tmp_path, capsys):
    path = tmp_path / "merge-readiness.json"
    path.write_text(json.dumps(base_report("hold_candidate")), encoding="utf-8")
    assert merge.main(["--from-json", str(path), "--comment"]) == 0
    assert "Verdict: HOLD / needs follow-up." in capsys.readouterr().out


def test_renderer_safety_source_and_allowlist():
    src = HELPER.read_text(encoding="utf-8")
    forbidden_fragments = [
        "api.github.com",
        "post-comment",
        "approve-pr",
        "gh pr merge",
        "run_full_pytest.py",
        "docker01_operator_qa_bundle.py --pr",
        "docker build",
        "docker restart",
        "docker compose up",
        "docker system prune",
        "shell=True",
    ]
    scrubbed = src.replace('"--post-comment"', "").replace('"no shell=True"', "")
    for fragment in forbidden_fragments:
        if fragment == "post-comment":
            assert "--post-comment" in merge.UNSAFE_CLI_OPTIONS
        elif fragment == "shell=True":
            assert fragment not in scrubbed
        else:
            assert fragment not in src
    for opt in [
        "--execute",
        "--apply",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--rm",
        "--rmi",
        "--post-comment",
        "--approve",
        "--merge",
    ]:
        assert opt in merge.UNSAFE_CLI_OPTIONS
    for cmd in (["pytest", "-q"], ["docker", "restart", "x"], ["gh", "pr", "merge"]):
        assert not merge.is_command_allowed(list(cmd))
