import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "docker01_merge_readiness.py"
spec = importlib.util.spec_from_file_location("merge", HELPER)
merge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge)

PR = 216
COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def lane(status="already_complete", good=True):
    return {
        "status": status,
        "state": {"container_status": "running", "container_health": "healthy", "restart_count": 0},
        "checks": [
            {"name": "source_head_matches", "passed": good},
            {"name": "compose_image_matches", "passed": good},
            {"name": "container_labels_match", "passed": good},
            {"name": "container_image_matches", "passed": good},
            {"name": "container_running", "passed": True},
            {"name": "container_healthy", "passed": True},
            {"name": "restart_count_acceptable", "passed": True},
        ],
    }


def validation(status="passed", classification="passed", pass_eligible=True, rerun_required=False):
    return {
        "status": status,
        "classification": classification,
        "pass_eligible": pass_eligible,
        "rerun_required": rerun_required,
        "full_pytest": "passed",
        "source": {"run_dir": "/tmp/run"},
    }


def write_qa(
    root,
    commit=COMMIT,
    status="passed",
    failed_assertions=0,
    stamp="20260616T010000Z",
    pr=PR,
    hygiene=None,
    warnings=None,
):
    b = root / f"sfai-pr{pr}-{commit[:12]}-operator-qa-bundle-{stamp}"
    b.mkdir(parents=True)
    doc = {
        "mode": "docker01_operator_qa_bundle",
        "status": status,
        "pr": pr,
        "commit": commit,
        "short_sha": commit[:12],
        "summary": {
            "commands_passed": 10,
            "commands_failed": 0 if status == "passed" else 1,
            "safety_assertions_passed": 8,
            "safety_assertions_failed": failed_assertions,
        },
        "hygiene": hygiene
        or {
            "history_status": "ok",
            "compare_latest_status": "ok",
            "review_bundle_status": "ok",
            "warnings": [],
        },
        "warnings": warnings or [],
    }
    (b / "qa-results.json").write_text(json.dumps(doc), encoding="utf-8")
    return b


def patch(monkeypatch, tmp_path, lane_doc=None, validation_doc=None):
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    monkeypatch.setattr(merge, "load_pr_lane_status", lambda pr, commit: lane_doc or lane())
    monkeypatch.setattr(
        merge, "load_validation_status", lambda pr, commit: validation_doc or validation()
    )


def report(monkeypatch, tmp_path, **kw):
    write_qa(
        tmp_path,
        status=kw.pop("qa_status", "passed"),
        failed_assertions=kw.pop("failed_assertions", 0),
        hygiene=kw.pop("hygiene", None),
        warnings=kw.pop("warnings", None),
    )
    patch(
        monkeypatch,
        tmp_path,
        lane_doc=kw.pop("lane_doc", None),
        validation_doc=kw.pop("validation_doc", None),
    )
    return merge.build_report(PR, COMMIT, created_at="2026-06-16T00:00:00Z")[0]


def test_json_contract_and_human_summary(monkeypatch, tmp_path, capsys):
    r = report(monkeypatch, tmp_path)
    assert r["mode"] == "docker01_merge_readiness"
    assert r["read_only"] is True and r["mutation_performed"] is False
    text = merge.render_markdown(r)
    assert "SeedOfEvil remains final merge owner" in text
    assert "# Docker01 Merge-Readiness Evidence" in text
    assert json.loads(merge.strict_json(r))["mode"] == "docker01_merge_readiness"


def test_out_writes_required_files_manifest_checksums(monkeypatch, tmp_path):
    r = report(monkeypatch, tmp_path / "evidence")
    out = tmp_path / "out"
    merge.write_out(
        out,
        r,
        {
            "raw-validation-status.json": validation(),
            "raw-pr-lane-status.json": lane(),
            "raw-qa-bundle-summary.json": {"status": "passed"},
        },
    )
    names = {p.name for p in out.iterdir()}
    assert {
        "merge-readiness.json",
        "merge-readiness-summary.md",
        "manifest.json",
        "checksums.json",
        "raw-validation-status.json",
        "raw-pr-lane-status.json",
        "raw-qa-bundle-summary.json",
    } <= names
    chk = json.loads((out / "checksums.json").read_text())
    assert chk["files"]["merge-readiness.json"]["sha256"]
    assert chk["files"]["merge-readiness.json"]["size"] > 0


def test_complete_good_evidence_pass_candidate(monkeypatch, tmp_path):
    assert report(monkeypatch, tmp_path)["status"] == "pass_candidate"


def test_validation_failures_hold(monkeypatch, tmp_path):
    for v in [
        validation("failed", "failed", False, True),
        validation("failed", "setup_failure", False, True),
        validation("incomplete", "interrupted_or_incomplete", False, True),
    ]:
        assert (
            report(monkeypatch, tmp_path / v["classification"], validation_doc=v)["status"]
            == "hold_candidate"
        )


def test_qa_failed_or_safety_failure_hold(monkeypatch, tmp_path):
    assert report(monkeypatch, tmp_path / "a", qa_status="failed")["status"] == "hold_candidate"
    assert report(monkeypatch, tmp_path / "b", failed_assertions=1)["status"] == "hold_candidate"


def test_pr_lane_needs_deploy_or_blocked_hold(monkeypatch, tmp_path):
    assert (
        report(monkeypatch, tmp_path / "a", lane_doc=lane("needs_deploy"))["status"]
        == "hold_candidate"
    )
    assert (
        report(monkeypatch, tmp_path / "b", lane_doc=lane("blocked"))["status"] == "hold_candidate"
    )


def test_missing_evidence_unknown(monkeypatch, tmp_path):
    patch(
        monkeypatch,
        tmp_path,
        lane_doc={"status": "not_available"},
        validation_doc={"status": "not_found", "classification": "not_found"},
    )
    r, raw = merge.build_report(PR, COMMIT)
    assert r["status"] == "unknown"
    assert r["inputs"]["qa_bundle_available"] is False


def test_stale_different_commit_not_selected(monkeypatch, tmp_path):
    write_qa(tmp_path, commit="1111111111111111111111111111111111111111")
    patch(monkeypatch, tmp_path)
    r, _ = merge.build_report(PR, COMMIT)
    assert r["status"] == "unknown"
    assert r["evidence"]["qa_bundle"]["status"] == "not_found"


def test_warnings_are_non_blocking(monkeypatch, tmp_path):
    h = {
        "history_status": "partial",
        "compare_latest_status": "ok",
        "review_bundle_status": "skipped",
        "warnings": ["known metadata hygiene advisory", "model doctor auth_readiness=unknown"],
    }
    r = report(monkeypatch, tmp_path, hygiene=h)
    assert r["status"] == "pass_candidate"
    assert r["warnings"]


def test_finds_latest_exact_qa_and_reads_hygiene(monkeypatch, tmp_path):
    write_qa(tmp_path, status="failed", stamp="20260616T010000Z")
    latest = write_qa(
        tmp_path,
        status="passed",
        stamp="20260616T020000Z",
        hygiene={
            "history_status": "ok",
            "compare_latest_status": "ok",
            "review_bundle_status": "ok",
            "warnings": ["w"],
        },
    )
    patch(monkeypatch, tmp_path)
    r, _ = merge.build_report(PR, COMMIT)
    assert r["evidence"]["qa_bundle"]["bundle_path"] == str(latest)
    assert r["evidence"]["hygiene"]["warnings"] == ["w"]


def test_missing_raw_files_recorded_not_available_not_crash(tmp_path, monkeypatch):
    patch(monkeypatch, tmp_path)
    qa, raw = merge.find_qa_bundle(PR, COMMIT)
    assert qa["status"] == "not_found"
    assert raw["status"] == "not_available"


def test_safety_no_pytest_qa_docker_mutation_and_no_shell_true():
    src = HELPER.read_text()
    forbidden = [
        "run_full_pytest.py",
        "docker01_operator_qa_bundle.py --pr",
        "docker build",
        "docker restart",
        "docker compose up",
        "docker system prune",
        "shell=True",
    ]
    for word in forbidden:
        if word == "shell=True":
            assert "subprocess.run" in src and "shell=True" not in src.replace(
                "shell" + "=True", ""
            )
        else:
            assert word not in src
    for opt in [
        "--execute",
        "--apply",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
    ]:
        assert opt in merge.UNSAFE_CLI_OPTIONS
    assert not merge.is_command_allowed(["docker", "restart", "shellforgeai"])
    assert not merge.is_command_allowed(["pytest", "-q"])
    assert not merge.is_command_allowed(["python", "scripts/docker01_operator_qa_bundle.py"])
    assert all(v is False for k, v in merge.SAFETY_FLAGS.items() if k != "read_only")
    assert merge.SAFETY_FLAGS["read_only"] is True
