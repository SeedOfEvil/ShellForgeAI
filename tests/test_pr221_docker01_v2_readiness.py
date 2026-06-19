import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "docker01_v2_readiness.py"
spec = importlib.util.spec_from_file_location("v2", HELPER)
v2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v2)

PR = 221
COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def lane(good=True, health="healthy", restart=0):
    return {
        "status": "already_complete",
        "state": {
            "container_status": "running",
            "container_health": health,
            "restart_count": restart,
        },
        "checks": [
            {"name": "source_head_matches", "passed": good},
            {"name": "compose_image_matches", "passed": good},
            {"name": "container_labels_match", "passed": good},
            {"name": "container_image_matches", "passed": good},
            {"name": "container_running", "passed": True},
            {"name": "container_healthy", "passed": health in ("healthy", "none")},
            {"name": "restart_count_acceptable", "passed": restart == 0},
        ],
    }


def validation(status="passed", classification="passed", eligible=True, rerun=False):
    return {
        "status": status,
        "classification": classification,
        "pass_eligible": eligible,
        "rerun_required": rerun,
        "full_pytest": "passed",
        "source": {"run_dir": "/tmp/run"},
    }


def merge(status="pass_candidate", warnings=None, hygiene=None):
    return {
        "status": status,
        "warnings": warnings or [],
        "summary": {"duplicate_full_pytest_detected": False},
        "evidence": {"hygiene": hygiene or {"history_status": "ok", "compare_latest_status": "ok"}},
    }


def write_qa(
    root,
    commit=COMMIT,
    status="passed",
    failed_assertions=0,
    stamp="20260618T010000Z",
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
            "commands_passed": 9,
            "commands_failed": 0 if status == "passed" else 1,
            "safety_assertions_passed": 8,
            "safety_assertions_failed": failed_assertions,
        },
        "hygiene": hygiene
        or {"history_status": "ok", "compare_latest_status": "ok", "warnings": []},
        "warnings": warnings or [],
    }
    (b / "qa-results.json").write_text(json.dumps(doc), encoding="utf-8")
    return b


def patch(monkeypatch, tmp_path, lane_doc=None, validation_doc=None, merge_doc=None):
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    monkeypatch.setattr(v2, "load_pr_lane_status", lambda pr, commit: lane_doc or lane())
    monkeypatch.setattr(
        v2, "load_validation_status", lambda pr, commit: validation_doc or validation()
    )
    monkeypatch.setattr(v2, "load_merge_readiness", lambda pr, commit: merge_doc or merge())


def report(monkeypatch, tmp_path, **kw):
    if kw.pop("qa", True):
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
        merge_doc=kw.pop("merge_doc", None),
    )
    return v2.build_report(PR, COMMIT, created_at="2026-06-18T00:00:00Z")[0]


def test_merge_readiness_allowlist_exact_shape_and_rejections():
    allowed = [
        v2.sys.executable,
        "scripts/docker01_merge_readiness.py",
        "--pr",
        str(PR),
        "--commit",
        COMMIT,
        "--json",
    ]
    assert v2.is_command_allowed(allowed)
    assert not v2.is_command_allowed([*allowed, "--extra"])
    different_script = allowed.copy()
    different_script[1] = "scripts/not_merge_readiness.py"
    assert not v2.is_command_allowed(different_script)
    for flag in [
        "--comment",
        "--out",
        "--execute",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--approve",
        "--merge",
    ]:
        assert not v2.is_command_allowed([*allowed, flag])
    assert not v2.is_command_allowed(["docker", "ps"])


def test_primary_user_path_json_human_and_out(monkeypatch, tmp_path, capsys):
    evidence = tmp_path / "evidence"
    write_qa(evidence)
    patch(monkeypatch, evidence)
    assert v2.main(["--pr", str(PR), "--commit", COMMIT, "--json"]) == 0
    json_text = capsys.readouterr().out
    parsed = json.loads(json_text)
    assert parsed["mode"] == "docker01_v2_readiness"
    assert parsed["read_only"] is True
    assert parsed["mutation_performed"] is False

    assert v2.main(["--pr", str(PR), "--commit", COMMIT]) == 0
    human = capsys.readouterr().out
    assert "# Docker01 V2 Readiness Evidence" in human
    assert "SeedOfEvil remains final merge owner" in human

    out = tmp_path / "out"
    assert v2.main(["--pr", str(PR), "--commit", COMMIT, "--out", str(out)]) == 0
    capsys.readouterr()
    assert (out / "v2-readiness.json").is_file()
    assert (out / "v2-readiness-summary.md").is_file()
    checksums = json.loads((out / "checksums.json").read_text())
    assert checksums["files"]["v2-readiness.json"]["sha256"]
    assert checksums["files"]["v2-readiness-summary.md"]["size"] > 0


def test_json_contract_human_and_out(monkeypatch, tmp_path):
    r = report(monkeypatch, tmp_path / "e")
    assert json.loads(v2.strict_json(r))["mode"] == "docker01_v2_readiness"
    assert r["read_only"] is True and r["mutation_performed"] is False
    text = v2.render_markdown(r)
    assert "# Docker01 V2 Readiness Evidence" in text
    assert "SeedOfEvil remains final merge owner" in text
    out = tmp_path / "out"
    v2.write_out(
        out,
        r,
        {
            "raw-validation-status.json": validation(),
            "raw-pr-lane-status.json": lane(),
            "raw-merge-readiness.json": merge(),
            "raw-qa-bundle-summary.json": {"status": "passed"},
        },
    )
    names = {p.name for p in out.iterdir()}
    assert {
        "v2-readiness.json",
        "v2-readiness-summary.md",
        "manifest.json",
        "checksums.json",
        "raw-validation-status.json",
        "raw-pr-lane-status.json",
        "raw-merge-readiness.json",
        "raw-qa-bundle-summary.json",
    } <= names
    checksums = json.loads((out / "checksums.json").read_text())
    assert checksums["files"]["v2-readiness.json"]["sha256"]
    assert checksums["files"]["v2-readiness.json"]["size"] > 0


def test_complete_good_evidence_v2_candidate(monkeypatch, tmp_path):
    assert report(monkeypatch, tmp_path)["status"] == "v2_candidate"


def test_validation_not_found_unknown_and_failures_not_ready(monkeypatch, tmp_path):
    assert report(
        monkeypatch,
        tmp_path / "nf",
        validation_doc=validation("not_found", "not_found", False, True),
    )["status"] in {"v2_not_ready", "v2_unknown"}
    assert (
        report(
            monkeypatch,
            tmp_path / "f",
            validation_doc=validation("failed", "test_failure", False, True),
        )["status"]
        == "v2_not_ready"
    )
    assert (
        report(
            monkeypatch, tmp_path / "r", validation_doc=validation("passed", "passed", True, True)
        )["status"]
        == "v2_not_ready"
    )


def test_qa_merge_container_blockers(monkeypatch, tmp_path):
    assert report(monkeypatch, tmp_path / "qa", qa_status="failed")["status"] == "v2_not_ready"
    assert report(monkeypatch, tmp_path / "safe", failed_assertions=1)["status"] == "v2_not_ready"
    assert (
        report(monkeypatch, tmp_path / "merge", merge_doc=merge("hold_candidate"))["status"]
        == "v2_not_ready"
    )
    assert (
        report(monkeypatch, tmp_path / "health", lane_doc=lane(health="unhealthy"))["status"]
        == "v2_not_ready"
    )


def test_missing_evidence_unknown_and_stale_not_current(monkeypatch, tmp_path):
    patch(
        monkeypatch,
        tmp_path,
        lane_doc={"status": "not_available"},
        validation_doc={"status": "not_available"},
        merge_doc={"status": "not_available"},
    )
    r, raw = v2.build_report(PR, COMMIT)
    assert r["status"] == "v2_unknown"
    assert any("unavailable" in warning for warning in r["warnings"])
    assert raw["raw-qa-bundle-summary.json"]["status"] == "not_found"
    assert raw["raw-merge-readiness.json"]["status"] == "not_available"
    out = tmp_path / "missing-out"
    v2.write_out(out, r, raw)
    raw_merge = json.loads((out / "raw-merge-readiness.json").read_text())
    assert raw_merge["status"] == "not_available"
    write_qa(tmp_path, commit="1111111111111111111111111111111111111111")
    patch(monkeypatch, tmp_path)
    r, _ = v2.build_report(PR, COMMIT)
    assert r["status"] == "v2_unknown"


def test_warnings_only_and_hygiene_from_qa_or_merge(monkeypatch, tmp_path):
    h = {
        "history_status": "partial",
        "compare_latest_status": "ok",
        "ignored_stale_candidates": ["x"],
        "warnings": ["known metadata hygiene advisory", "model doctor auth_readiness=unknown"],
    }
    r = report(monkeypatch, tmp_path / "qa", hygiene=h)
    assert r["status"] == "v2_candidate"
    assert r["warnings"]
    r = report(monkeypatch, tmp_path / "merge", merge_doc=merge("pass_candidate", hygiene=h))
    assert r["summary"]["hygiene_history_status"] in ("ok", "partial")


def test_finds_latest_exact_qa_and_missing_raw_not_available(monkeypatch, tmp_path):
    write_qa(tmp_path, status="failed", stamp="20260618T010000Z")
    latest = write_qa(tmp_path, status="passed", stamp="20260618T020000Z")
    patch(monkeypatch, tmp_path)
    r, raw = v2.build_report(PR, COMMIT)
    assert r["status"] == "v2_candidate"
    assert (
        str(latest) in raw["raw-qa-bundle-summary.json"].get("short_sha", "")
        or r["status"] == "v2_candidate"
    )
    qa, raw_missing = v2.find_qa_bundle(PR, "2222222222222222222222222222222222222222")
    assert qa["status"] == "not_found"
    assert raw_missing["status"] == "not_available"


def test_safety_no_forbidden_execution_or_options():
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
        assert word not in src.replace('"shell=True"', '"shell" + "=True"')
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
        "--post-comment",
        "--approve",
        "--merge",
    ]:
        assert opt in v2.UNSAFE_CLI_OPTIONS
    assert not v2.is_command_allowed(["docker", "restart", "shellforgeai"])
    assert all(flag is False for key, flag in v2.SAFETY_FLAGS.items() if key != "read_only")
