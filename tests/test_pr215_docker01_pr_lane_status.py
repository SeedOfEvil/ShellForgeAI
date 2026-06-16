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
COMMIT = "abcdef1234567890abcdef1234567890abcdef12"
SHORT = COMMIT[:12]


def _runner(
    *, head=COMMIT, status="running", health="healthy", restart=0, pr=PR, commit=COMMIT, image=None
):
    image = image or f"shellforgeai:pr{pr}-{commit[:12]}"

    def run(argv, **kwargs):
        if argv == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, head + "\n", "")
        if argv == ["docker", "inspect", "shellforgeai"]:
            payload = [
                {
                    "RestartCount": restart,
                    "State": {"Status": status, "Health": {"Status": health}},
                    "Config": {
                        "Image": image,
                        "Labels": {
                            "homelab.pr": str(pr),
                            "homelab.commit": commit,
                            "homelab.compose_image": image,
                        },
                    },
                }
            ]
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
        raise AssertionError(f"unexpected command: {argv}")

    return run


def _write_validation(
    tmp_path,
    monkeypatch,
    *,
    pr=PR,
    commit=COMMIT,
    status="passed",
    classification="passed",
    full=True,
):
    run_dir = tmp_path / f"sfai-pr{pr}-{commit[:12]}-validation-20260615T000000"
    run_dir.mkdir()
    (run_dir / "validation-status.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "mode": "docker01_pr_lane_validation_status",
                "status": status,
                "classification": classification,
                "pass_eligible": status == "passed",
                "rerun_required": status != "passed",
                "pr": pr,
                "commit": commit,
                "short_sha": commit[:12],
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


def _write_qa(tmp_path, monkeypatch, *, pr=PR, commit=COMMIT, status="passed"):
    root = tmp_path / "qa"
    root.mkdir(exist_ok=True)
    bundle = root / f"sfai-pr{pr}-{commit[:12]}-qa-bundle-20260615T000000Z"
    bundle.mkdir()
    (bundle / "qa-summary.md").write_text("# QA\n", encoding="utf-8")
    (bundle / "bundle-manifest.json").write_text(
        json.dumps(
            {
                "mode": "docker01_qa_bundle_manifest",
                "status": status,
                "summary": {
                    "commands_passed": 12,
                    "commands_failed": 0 if status == "passed" else 1,
                    "safety_assertions_failed": 0,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv(lane.QA_BUNDLE_ROOT_ENV, str(root))
    return bundle


def _doc(tmp_path, monkeypatch, **kw):
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
        pr=PR, commit=COMMIT, runner=_runner(**kw), created_at="2026-06-15T00:00:00Z"
    )


def test_status_json_contract_and_human_output(tmp_path, monkeypatch, capsys):
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


def test_already_complete(tmp_path, monkeypatch):
    doc = _doc(tmp_path, monkeypatch)
    assert doc["status"] == "already_complete"
    assert "qa-summary.md" in doc["safe_next"]["command"]


def test_matching_deploy_missing_qa_needs_qa(tmp_path, monkeypatch):
    doc = _doc(tmp_path, monkeypatch, qa=False)
    assert doc["status"] == "needs_qa"
    assert "docker01_operator_qa_bundle.py" in doc["safe_next"]["command"]


def test_matching_deploy_missing_validation_needs_validation(tmp_path, monkeypatch):
    doc = _doc(tmp_path, monkeypatch, validation=False)
    assert doc["status"] == "needs_validation"
    assert "validation_status.py" in doc["safe_next"]["command"]
    assert "pytest" not in doc["safe_next"]["command"]


def test_source_mismatch_needs_deploy(tmp_path, monkeypatch):
    doc = _doc(tmp_path, monkeypatch, head="deadbeef")
    assert doc["status"] == "needs_deploy"
    assert "sfai_docker01_pr_lane.py" in doc["safe_next"]["command"]
    assert "docker compose" not in doc["safe_next"]["command"]


@pytest.mark.parametrize("kwargs", [{"health": "unhealthy"}, {"restart": 2}])
def test_container_unhealthy_or_restart_blocked(tmp_path, monkeypatch, kwargs):
    doc = _doc(tmp_path, monkeypatch, **kwargs)
    assert doc["status"] == "blocked"
    assert "restart" not in doc["safe_next"]["command"]


@pytest.mark.parametrize(
    "vstatus, classification", [("failed", "failed"), ("incomplete", "interrupted_or_incomplete")]
)
def test_validation_failed_or_interrupted_blocks_or_requires_rerun(
    tmp_path, monkeypatch, vstatus, classification
):
    doc = _doc(tmp_path, monkeypatch, validation_status=vstatus, classification=classification)
    assert doc["validation"]["rerun_required"] is True
    assert doc["status"] in {"blocked", "needs_validation"}


def test_evidence_discovery_exact_pr_commit_and_stale_ignored(tmp_path, monkeypatch):
    _write_validation(tmp_path, monkeypatch, pr=214, commit="1111111111112222", status="passed")
    _write_validation(tmp_path, monkeypatch, status="passed")
    _write_qa(tmp_path, monkeypatch, pr=214, commit="1111111111112222")
    bundle = _write_qa(tmp_path, monkeypatch)
    doc = lane.build_pr_lane_status(pr=PR, commit=COMMIT, runner=_runner())
    assert doc["validation"]["available"] is True
    assert doc["qa_bundle"]["bundle_path"] == str(bundle)


def test_tolerates_missing_qa_with_warning(tmp_path, monkeypatch):
    _write_validation(tmp_path, monkeypatch)
    doc = lane.build_pr_lane_status(pr=PR, commit=COMMIT, runner=_runner())
    assert doc["qa_bundle"]["status"] == "not_found"
    assert doc["warnings"]


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
