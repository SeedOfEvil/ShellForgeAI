import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, Path(rel))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


lane = _load("sfai_docker01_pr_lane_pr215", "scripts/sfai_docker01_pr_lane.py")
validation_status = _load("validation_status_pr215", "scripts/validation_status.py")

PR = 215
COMMIT = "8c692de0680fff517a09d288105d44f3351ba710"
SHORT7 = COMMIT[:7]
IMAGE = f"lab/shellforgeai:pr{PR}-{SHORT7}"
DIGEST = "sha256:00185feedfacecafebeef"


def _runner(
    *,
    head=COMMIT,
    status="running",
    health="healthy",
    restart=0,
    pr=PR,
    commit=COMMIT,
    image=IMAGE,
    image_id=DIGEST,
):
    def run(argv, **kwargs):
        if argv == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, head + "\n", "")
        if argv == ["docker", "inspect", "shellforgeai"]:
            payload = [
                {
                    "Image": image_id,
                    "RestartCount": restart,
                    "State": {"Status": status, "Health": {"Status": health}},
                    "Config": {
                        "Image": image,
                        "Labels": {
                            "homelab.pr": str(pr),
                            "homelab.commit": commit,
                            "com.docker.compose.image": image_id,
                        },
                    },
                }
            ]
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        raise AssertionError(f"unexpected command: {argv}")

    return run


def _compose(tmp_path, monkeypatch, image=IMAGE):
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "compose.yml"
    path.write_text(f"services:\n  shellforgeai:\n    image: {image}\n", encoding="utf-8")
    monkeypatch.setenv(lane.COMPOSE_FILE_ENV, str(path))
    return path


def _write_validation(
    tmp_path,
    monkeypatch,
    *,
    pr=PR,
    commit=COMMIT,
    status="passed",
    classification="passed",
    pass_eligible=None,
    stamp="20260615T000000",
    full=True,
):
    run_dir = tmp_path / f"sfai-pr{pr}-{commit[:7]}-validation-{stamp}"
    run_dir.mkdir()
    pass_eligible = status == "passed" if pass_eligible is None else pass_eligible
    (run_dir / "validation-status.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "mode": "docker01_pr_lane_validation_status",
                "status": status,
                "classification": classification,
                "pass_eligible": pass_eligible,
                "rerun_required": not pass_eligible,
                "pr": pr,
                "commit": commit,
                "short_sha": commit[:7],
                "full_validation": full,
                "source": {"kind": "docker01_pr_lane", "run_dir": str(run_dir)},
                "safety": lane.validation_evidence_safety(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv(validation_status.RUNS_DIR_ENV, str(tmp_path))
    monkeypatch.setenv(lane.validation_status_viewer.RUNS_DIR_ENV, str(tmp_path))
    return run_dir


def _write_qa(
    tmp_path,
    monkeypatch,
    *,
    pr=PR,
    commit=COMMIT,
    status="passed",
    stamp="20260616T0157Z",
    operator=True,
):
    root = tmp_path / "qa"
    root.mkdir(exist_ok=True)
    infix = "operator-qa-bundle" if operator else "qa-bundle"
    bundle = root / f"sfai-pr{pr}-{commit[:7]}-{infix}-{stamp}"
    bundle.mkdir()
    (bundle / "qa-summary.md").write_text("# QA\n", encoding="utf-8")
    qa_results = {
        "mode": "docker01_operator_qa_bundle",
        "status": status,
        "pr": pr,
        "commit": commit,
        "short_sha": commit[:7],
        "summary": {
            "commands_passed": 12,
            "commands_failed": 0 if status == "passed" else 1,
            "safety_assertions_failed": 0,
        },
    }
    (bundle / "qa-results.json").write_text(json.dumps(qa_results), encoding="utf-8")
    (bundle / "bundle-manifest.json").write_text(
        json.dumps({"mode": "docker01_qa_bundle_manifest", "status": status}),
        encoding="utf-8",
    )
    monkeypatch.setenv(lane.QA_BUNDLE_ROOT_ENV, str(root))
    return bundle


def _doc(tmp_path, monkeypatch, **kw):
    _compose(tmp_path, monkeypatch, image=kw.pop("compose_image", IMAGE))
    if kw.pop("validation", True):
        _write_validation(
            tmp_path,
            monkeypatch,
            status=kw.pop("validation_status", "passed"),
            classification=kw.pop("classification", "passed"),
        )
    if kw.pop("qa", True):
        _write_qa(tmp_path, monkeypatch, status=kw.pop("qa_status", "passed"))
    return lane.build_pr_lane_status(
        pr=PR, commit=COMMIT, runner=_runner(**kw), created_at="2026-06-16T00:00:00Z"
    )


def _checks(doc):
    return {item["name"]: item for item in doc["checks"]}


def test_status_json_contract_and_human_output(tmp_path, monkeypatch, capsys):
    _compose(tmp_path, monkeypatch)
    _write_validation(tmp_path, monkeypatch)
    _write_qa(tmp_path, monkeypatch)
    monkeypatch.setattr(lane, "subprocess", type("S", (), {"run": staticmethod(_runner())})())
    assert lane.main(["--pr", str(PR), "--commit", COMMIT, "--status", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["mode"] == "docker01_pr_lane_status"
    assert out["read_only"] is True and out["mutation_performed"] is False
    assert out["safety"]["deploy_executed"] is False
    assert out["safety"]["validation_executed"] is False
    assert out["safety"]["qa_executed"] is False
    assert lane.main(["--pr", str(PR), "--commit", COMMIT, "--status"]) == 0
    human = capsys.readouterr().out
    assert "Docker01 PR lane status" in human
    assert "Safe next command:" in human
    assert "no deploy/build/compose/restart/validation executed" in human


def test_successful_deployed_state_with_compose_tag_and_digest_is_already_complete(
    tmp_path, monkeypatch
):
    doc = _doc(tmp_path, monkeypatch)
    checks = _checks(doc)
    assert doc["status"] == "already_complete"
    assert checks["source_head_matches"]["passed"] is True
    assert checks["compose_image_matches"]["passed"] is True
    assert checks["container_image_matches"]["passed"] is True
    assert doc["state"]["compose_image"] == IMAGE
    assert doc["state"]["container_image"] == IMAGE
    assert doc["state"]["container_image_id"] == DIGEST
    assert "sfai_docker01_pr_lane.py" not in doc["safe_next"]["command"]


def test_deploy_complete_validation_missing_needs_validation_not_deploy(tmp_path, monkeypatch):
    doc = _doc(tmp_path, monkeypatch, validation=False)
    assert doc["status"] == "needs_validation"
    assert "validation_status.py" in doc["safe_next"]["command"]
    assert "sfai_docker01_pr_lane.py" not in doc["safe_next"]["command"]


def test_deploy_complete_validation_passed_qa_missing_needs_qa(tmp_path, monkeypatch):
    doc = _doc(tmp_path, monkeypatch, qa=False)
    assert doc["status"] == "needs_qa"
    assert "docker01_operator_qa_bundle.py" in doc["safe_next"]["command"]


def test_earlier_setup_failure_later_passed_validation_not_blocked(tmp_path, monkeypatch):
    _compose(tmp_path, monkeypatch)
    _write_validation(
        tmp_path,
        monkeypatch,
        status="setup_failure",
        classification="setup_failure",
        pass_eligible=False,
        stamp="20260616T000000",
    )
    _write_validation(
        tmp_path, monkeypatch, status="passed", classification="passed", stamp="20260616T020000"
    )
    _write_qa(tmp_path, monkeypatch)
    doc = lane.build_pr_lane_status(pr=PR, commit=COMMIT, runner=_runner())
    assert doc["validation"]["pass_eligible"] is True
    assert doc["status"] == "already_complete"


def test_setup_failure_only_is_not_pass_eligible(tmp_path, monkeypatch):
    doc = _doc(
        tmp_path,
        monkeypatch,
        validation_status="setup_failure",
        classification="setup_failure",
        qa=False,
    )
    assert doc["validation"]["pass_eligible"] is False
    assert doc["status"] == "blocked"


def test_qa_bundle_discovery_finds_operator_bundle_ignores_stale_and_prefers_passed(
    tmp_path, monkeypatch
):
    _compose(tmp_path, monkeypatch)
    _write_validation(tmp_path, monkeypatch)
    _write_qa(tmp_path, monkeypatch, pr=214, commit="1111111111112222", status="passed")
    failed = _write_qa(tmp_path, monkeypatch, status="failed", stamp="20260616T0300Z")
    passed = _write_qa(tmp_path, monkeypatch, status="passed", stamp="20260616T0157Z")
    doc = lane.build_pr_lane_status(pr=PR, commit=COMMIT, runner=_runner())
    assert doc["qa_bundle"]["bundle_path"] == str(passed)
    assert doc["qa_bundle"]["bundle_path"] != str(failed)
    assert doc["qa_bundle"]["status"] == "passed"


def test_failed_qa_bundle_is_needs_qa_not_needs_deploy(tmp_path, monkeypatch):
    doc = _doc(tmp_path, monkeypatch, qa_status="failed")
    assert doc["status"] == "needs_qa"
    assert "sfai_docker01_pr_lane.py" not in doc["safe_next"]["command"]


def test_source_mismatch_needs_deploy(tmp_path, monkeypatch):
    doc = _doc(tmp_path, monkeypatch, head="deadbeef")
    assert doc["status"] == "needs_deploy"
    assert "sfai_docker01_pr_lane.py" in doc["safe_next"]["command"]
    assert "docker compose" not in doc["safe_next"]["command"]


def test_label_mismatch_blocks_not_deploy(tmp_path, monkeypatch):
    doc = _doc(tmp_path, monkeypatch, commit="deadbeef")
    assert doc["status"] == "blocked"


@pytest.mark.parametrize("kwargs", [{"health": "unhealthy"}, {"restart": 2}])
def test_container_unhealthy_or_restart_blocked(tmp_path, monkeypatch, kwargs):
    doc = _doc(tmp_path, monkeypatch, **kwargs)
    assert doc["status"] == "blocked"


def test_safe_next_regression_no_direct_mutation_commands(tmp_path, monkeypatch):
    for doc in [
        _doc(tmp_path / "a", monkeypatch, validation=False),
        _doc(tmp_path / "b", monkeypatch, qa=False),
        _doc(tmp_path / "c", monkeypatch, health="unhealthy"),
    ]:
        command = doc["safe_next"]["command"]
        forbidden = ("docker compose", "restart", "cleanup", "prune", "delete", "remediation")
        assert not any(word in command for word in forbidden)


def test_status_execute_fails_clearly(capsys):
    with pytest.raises(SystemExit):
        lane.main(["--pr", str(PR), "--commit", COMMIT, "--status", "--execute"])
    assert "--status is read-only and cannot be combined with --execute" in capsys.readouterr().err


def test_status_allowlist_rejects_unsafe_and_source_has_no_shell_true():
    with pytest.raises(ValueError):
        lane._status_run(["docker", "restart", "shellforgeai"], runner=_runner())
    source = Path("scripts/sfai_docker01_pr_lane.py").read_text()
    assert "shell=True" not in source
    for bad in ("docker prune", "docker image rm", "docker restart", "rm -rf"):
        assert bad not in source
