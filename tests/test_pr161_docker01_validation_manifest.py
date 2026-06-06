"""PR161 — Docker01 validation evidence manifest and run summary."""

from __future__ import annotations

import json
import subprocess
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "sfai_docker01_pr_lane.py"

if str(SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT.parent))

import sfai_docker01_pr_lane as lane  # noqa: E402


def sample_plan() -> dict:
    return lane.plan_docker01_lane(
        changed_files=["Dockerfile"],
        pr_number="161",
        full_validation=True,
        full_validation_reason="validation helper changed",
    )


def sample_manifest(
    tmp_path: Path, *, plan: dict | None = None, commands=None, phases=None
) -> dict:
    plan = plan or sample_plan()
    manifest_path = tmp_path / "manifest.json"
    summary_path = tmp_path / "summary.txt"
    return lane.build_validation_manifest(
        plan,
        pr_number="161",
        head_commit="abcdef1234567890",
        branch="pr161-manifest",
        repo="SeedOfEvil/ShellForgeAI",
        previous_image="lab/shellforgeai:previous",
        new_image="lab/shellforgeai:pr161-abcdef123456",
        image_id="sha256:image",
        compose_file=str(tmp_path / "compose.yml"),
        compose_backup=str(tmp_path / "compose.yml.pr161.bak"),
        compose_final_config="/tmp/compose-final.yml",
        snapshot="docker01-pr161-before-deploy",
        commands=commands
        or [
            {
                "name": "lint",
                "command": ["python", "-m", "ruff", "check", "."],
                "display": "ruff check .",
                "status": "passed",
                "duration_seconds": 1.2,
                "log_path": str(tmp_path / "validation.log"),
            },
            {
                "name": "compile",
                "command": ["python", "-m", "compileall", "-q", "src", "tests"],
                "display": "python -m compileall -q src tests",
                "status": "passed",
                "duration_seconds": 2.3,
                "log_path": str(tmp_path / "validation.log"),
            },
            {
                "name": "pytest_targeted",
                "command": ["python", "-m", "pytest", "-q", "tests/test_pr161_*"],
                "display": "pytest -q tests/test_pr161_*",
                "status": "passed",
                "duration_seconds": 3.4,
                "log_path": str(tmp_path / "validation.log"),
            },
            {
                "name": "pytest_full_runner",
                "command": ["python", "scripts/run_full_pytest.py"],
                "display": "python scripts/run_full_pytest.py",
                "status": "passed",
                "duration_seconds": 4.5,
                "log_path": str(tmp_path / "runner.log"),
            },
        ],
        phases=phases
        or [
            {"name": "preflight", "status": "passed", "duration_seconds": 0.1},
            {"name": "snapshot", "status": "passed", "duration_seconds": 0.2},
            {"name": "compose_update", "status": "passed", "duration_seconds": 0.3},
            {"name": "build", "status": "passed", "duration_seconds": 0.4},
            {"name": "validation", "status": "passed", "duration_seconds": 0.5},
        ],
        logs={
            "qa": str(tmp_path / "qa.log"),
            "validation": str(tmp_path / "validation.log"),
            "deploy": str(tmp_path / "deploy.log"),
            "runner": str(tmp_path / "runner.log"),
        },
        final_container={
            "name": "shellforgeai",
            "image": "lab/shellforgeai:pr161-abcdef123456",
            "image_id": "sha256:image",
            "status": "running",
            "health": "healthy",
            "restart_count": 0,
        },
        disk={"root_used": "10G", "root_available": "90G", "root_percent": "10%"},
        non_blockers=["historical metadata hygiene advisory"],
        manifest_path=str(manifest_path),
        human_summary_path=str(summary_path),
        created_at="2026-06-06T00:00:00Z",
    )


def test_manifest_schema_mode_pr_lane_and_full_validation_metadata(tmp_path):
    manifest = sample_manifest(tmp_path)
    assert manifest["schema_version"] == 1
    assert manifest["mode"] == "docker01_pr_validation_manifest"
    assert manifest["pr"]["number"] == 161
    assert manifest["pr"]["head_commit"] == "abcdef1234567890"
    assert manifest["lane"]["selected"] == "full"
    assert manifest["lane"]["reason"]
    assert manifest["lane"]["full_validation_required"] is True
    assert manifest["lane"]["runner"] == "python scripts/run_full_pytest.py"


def test_manifest_includes_commands_phases_deployment_snapshot_container_safety_logs(tmp_path):
    manifest = sample_manifest(tmp_path)
    assert manifest["commands"][0]["status"] == "passed"
    assert manifest["commands"][0]["duration_seconds"] == 1.2
    assert manifest["commands"][0]["log_path"].endswith("validation.log")
    assert manifest["phases"][1] == {
        "name": "snapshot",
        "status": "passed",
        "duration_seconds": 0.2,
    }
    assert manifest["deployment"]["compose_backup"].endswith("compose.yml.pr161.bak")
    assert manifest["deployment"]["snapshot"] == "docker01-pr161-before-deploy"
    assert manifest["final_container"]["status"] == "running"
    assert manifest["final_container"]["health"] == "healthy"
    assert manifest["final_container"]["restart_count"] == 0
    assert manifest["logs"]["qa"].endswith("qa.log")
    assert manifest["non_blockers"] == ["historical metadata hygiene advisory"]

    safety = manifest["safety"]
    assert safety["snapshot_before_mutation"] is True
    assert safety["compose_atomic_update"] is True
    assert safety["cleanup_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False
    assert safety["docker_prune"] is False
    assert safety["volume_prune"] is False
    assert safety["docker_compose_mutation_beyond_deploy"] is False
    assert safety["production_restart_beyond_deploy"] is False
    assert safety["shell_true"] is False
    assert safety["arbitrary_command_execution"] is False
    assert safety["natural_language_mutation"] is False


def test_manifest_writes_valid_json_and_summary_is_copy_paste_friendly(tmp_path):
    manifest = sample_manifest(tmp_path)
    manifest_path = Path(manifest["artifacts"]["manifest_path"])
    summary_path = Path(manifest["artifacts"]["human_summary_path"])
    lane.write_manifest(manifest, manifest_path)
    summary = lane.render_human_summary(manifest)
    lane.write_human_summary(summary, summary_path)

    loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert loaded["mode"] == "docker01_pr_validation_manifest"
    text = summary_path.read_text(encoding="utf-8")
    assert "Docker01 PR validation summary" in text
    assert "PR: #161" in text
    assert "Commit: abcdef1234567890" in text
    assert "Lane: full" in text
    assert "Result: PASS" in text
    assert "Container: running / healthy / restart=0" in text
    assert "* ruff: passed" in text
    assert "* compileall: passed" in text
    assert "* targeted tests: passed" in text
    assert "* full pytest: passed" in text
    assert "Safety:" in text
    assert "cleanup/remediation/rollback: not executed" in text
    assert "Docker/Compose mutation beyond deploy: no" in text
    assert "production restart beyond deploy: no" in text
    assert "* QA:" in text
    assert "* validation:" in text
    assert "* manifest:" in text


def test_failure_manifest_records_failed_phase_and_failed_status(tmp_path):
    commands = [
        {
            "name": "lint",
            "command": ["python", "-m", "ruff", "check", "."],
            "display": "ruff check .",
            "status": "failed",
            "duration_seconds": 1.0,
            "log_path": str(tmp_path / "validation.log"),
        }
    ]
    phases = [{"name": "validation", "status": "failed", "duration_seconds": 1.0}]
    manifest = lane.build_validation_manifest(
        sample_plan(),
        pr_number="161",
        head_commit="abcdef1234567890",
        commands=commands,
        phases=phases,
        manifest_path=str(tmp_path / "manifest.json"),
        human_summary_path=str(tmp_path / "summary.txt"),
        error_summary="ruff failed",
    )
    assert manifest["status"] == "failed"
    assert manifest["verdict"] == "fail"
    assert manifest["failed_phase"] == "validation"
    assert manifest["error_summary"] == "ruff failed"


def test_missing_optional_data_uses_null_or_unknown_without_crashing(tmp_path, monkeypatch):
    monkeypatch.setattr(lane, "_git_value", lambda _args: None)
    manifest = lane.build_validation_manifest(
        lane.plan_docker01_lane(changed_files=["docs/cli.md"]),
        manifest_path=str(tmp_path / "manifest.json"),
        human_summary_path=str(tmp_path / "summary.txt"),
    )
    assert manifest["pr"]["head_commit"] is None
    assert manifest["pr"]["short_commit"] is None
    assert manifest["pr"]["branch"] == "unknown"
    assert manifest["deployment"]["compose_backup"] is None
    assert manifest["deployment"]["snapshot"] is None
    assert manifest["final_container"]["health"] == "unknown"


def test_print_manifest_json_emits_strict_json_only(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--changed-files",
            "docs/cli.md",
            "--pr",
            "161",
            "--head-commit",
            "abcdef1234567890",
            "--branch",
            "pr161-manifest",
            "--manifest-output",
            str(tmp_path / "manifest.json"),
            "--summary-output",
            str(tmp_path / "summary.txt"),
            "--print-manifest-json",
            "--dry-run",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    data = json.loads(result.stdout)
    assert data["mode"] == "docker01_pr_validation_manifest"
    assert data["pr"]["number"] == 161
    assert "ShellForgeAI Docker01 PR lane" not in result.stdout


def test_existing_cli_options_still_parse_and_tests_do_not_use_docker_or_real_data(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--changed-files",
            "Dockerfile",
            "--pr",
            "161",
            "--profile",
            "auto",
            "--full-validation",
            "--full-validation-reason",
            "validation helper changed",
            "--dry-run",
            "--manifest-output",
            str(tmp_path / "manifest.json"),
            "--summary-output",
            str(tmp_path / "summary.txt"),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "ShellForgeAI Docker01 PR lane" in result.stdout
    assert (tmp_path / "manifest.json").is_file()
    assert (tmp_path / "summary.txt").is_file()

    text = Path(__file__).read_text(encoding="utf-8").lower()
    forbidden = [
        "docker" + ".from_env",
        "docker" + " compose",
        " /" + "data",
        "run_full_pytest.py" + " --execute",
    ]
    for needle in forbidden:
        assert needle not in text


def test_run_validation_records_command_duration_without_real_pytest():
    plan = lane.plan_docker01_lane(changed_files=["Dockerfile"])

    def fake_run(_argv, **_kwargs):
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    rc, records = lane.run_validation(plan, runner=fake_run, return_records=True)
    assert rc == 0
    assert records
    assert all(record["status"] == "passed" for record in records)
    assert all(record["duration_seconds"] is not None for record in records)
