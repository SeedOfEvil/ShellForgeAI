from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_mainline_validation.py"
spec = importlib.util.spec_from_file_location("run_mainline_validation", MODULE_PATH)
mainline = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mainline
assert spec.loader is not None
spec.loader.exec_module(mainline)


def command_texts(plan):
    return [" ".join(command.command) for command in plan.commands]


def test_dry_run_prints_planned_commands(capsys, tmp_path):
    rc = mainline.main(["--dry-run", "--output-dir", str(tmp_path)])
    out = capsys.readouterr().out

    assert rc == 0
    assert "ShellForgeAI mainline validation baseline dry-run" in out
    assert "Planned commands:" in out
    assert "ruff check ." in out
    assert "scripts/run_full_pytest.py" in out
    assert str(tmp_path) in out


def test_dry_run_does_not_execute_subprocesses(monkeypatch, tmp_path):
    def fail_run(*_args, **_kwargs):
        raise AssertionError("dry-run must not execute subprocesses")

    monkeypatch.setattr(subprocess, "run", fail_run)

    assert mainline.main(["--dry-run", "--output-dir", str(tmp_path)]) == 0


def test_dry_run_json_is_strict_parseable_json(capsys, tmp_path):
    rc = mainline.main(["--dry-run", "--json", "--output-dir", str(tmp_path)])
    out = capsys.readouterr().out

    assert rc == 0
    payload = json.loads(out)
    assert payload["mode"] == "mainline_validation_plan"
    assert payload["output_dir"] == str(tmp_path)


def test_default_planned_commands_include_ruff_compileall_v1_and_full_pytest():
    plan = mainline.build_plan(created_at="2026-06-06T00:00:00Z")
    texts = command_texts(plan)

    assert any(text == "ruff check ." for text in texts)
    assert any("-m compileall -q src tests" in text for text in texts)
    assert any("scripts/v1_validate.sh --quick" in text for text in texts)
    assert any("scripts/run_full_pytest.py" in text for text in texts)


def test_no_full_pytest_removes_runner_and_marks_skipped(tmp_path):
    plan = mainline.build_plan(output_dir=tmp_path, full_pytest=False)
    payload = mainline.plan_to_dict(plan)
    manifest = mainline.initial_manifest(
        plan,
        created_at="2026-06-06T00:00:00Z",
        git_metadata={
            "source": "local_checkout",
            "git_commit": "abc",
            "branch": "main",
            "dirty": False,
        },
    )

    assert not any("run_full_pytest.py" in text for text in command_texts(plan))
    assert payload["full_pytest_status"] == "skipped_by_operator"
    assert manifest["validation"]["full_pytest"] == "skipped_by_operator"


def test_no_xdist_passes_through_to_full_pytest_runner(tmp_path):
    plan = mainline.build_plan(output_dir=tmp_path, no_xdist=True)
    full = next(command for command in plan.commands if command.name == "full_pytest")

    assert "--no-xdist" in full.command


def test_durations_10_passes_duration_setting_through(tmp_path):
    plan = mainline.build_plan(output_dir=tmp_path, durations=10)
    full = next(command for command in plan.commands if command.name == "full_pytest")

    assert full.command[full.command.index("--durations") + 1] == "10"
    assert plan.durations == 10


def test_output_dir_and_baseline_name_are_configurable(tmp_path):
    plan = mainline.build_plan(
        output_dir=tmp_path / "custom", baseline_name="main", created_at="2026-06-06T00:00:00Z"
    )

    assert plan.output_dir == tmp_path / "custom"
    assert plan.baseline_name == "main"
    assert plan.manifest_path.parent == tmp_path / "custom"
    assert plan.manifest_path.name.startswith("main-")


def test_executed_successful_run_writes_manifest_json_and_human_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(
        mainline,
        "collect_git_metadata",
        lambda: {
            "source": "local_checkout",
            "git_commit": "abc123",
            "branch": "main",
            "dirty": False,
        },
    )
    monkeypatch.setattr(mainline, "run_planned_command", lambda _command: (0, 0.01))
    monkeypatch.setattr(mainline, "run_duration_tracking", lambda _plan, _manifest: 0)

    plan = mainline.build_plan(
        output_dir=tmp_path, baseline_name="main", created_at="2026-06-06T00:00:00Z"
    )

    assert mainline.execute_plan(plan) == 0
    manifest = json.loads(plan.manifest_path.read_text(encoding="utf-8"))
    summary = plan.summary_path.read_text(encoding="utf-8")
    assert manifest["mode"] == "mainline_validation_manifest"
    assert manifest["status"] == "passed"
    assert manifest["verdict"] == "pass"
    assert "Mainline validation summary" in summary
    assert "Result: PASS" in summary


def test_failed_command_exits_nonzero_and_writes_failed_manifest(monkeypatch, tmp_path):
    monkeypatch.setattr(
        mainline,
        "collect_git_metadata",
        lambda: {
            "source": "local_checkout",
            "git_commit": "abc123",
            "branch": "main",
            "dirty": False,
        },
    )

    def fake_run(command):
        if command.name == "ruff":
            return 2, 0.02
        return 0, 0.01

    monkeypatch.setattr(mainline, "run_planned_command", fake_run)

    plan = mainline.build_plan(output_dir=tmp_path, created_at="2026-06-06T00:00:00Z")

    assert mainline.execute_plan(plan) == 2
    manifest = json.loads(plan.manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["verdict"] == "fail"
    assert manifest["validation"]["ruff"] == "failed"


def test_duration_tracking_runs_after_full_pytest_success_if_tracker_exists(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        mainline,
        "collect_git_metadata",
        lambda: {
            "source": "local_checkout",
            "git_commit": "abc123",
            "branch": "main",
            "dirty": False,
        },
    )
    monkeypatch.setattr(mainline, "run_planned_command", lambda _command: (0, 0.01))

    def fake_duration(plan, manifest):
        calls.append((plan.run_id, manifest["validation"]["full_pytest"]))
        manifest["duration_tracking"]["status"] = "passed"
        manifest["duration_tracking"]["regressions"] = 0
        return 0

    monkeypatch.setattr(mainline, "run_duration_tracking", fake_duration)
    plan = mainline.build_plan(output_dir=tmp_path, created_at="2026-06-06T00:00:00Z")

    assert mainline.execute_plan(plan) == 0
    assert calls == [(plan.run_id, "passed")]


def test_duration_tracking_warning_does_not_hide_pytest_pass_status(monkeypatch, tmp_path):
    monkeypatch.setattr(
        mainline,
        "collect_git_metadata",
        lambda: {
            "source": "local_checkout",
            "git_commit": "abc123",
            "branch": "main",
            "dirty": False,
        },
    )
    monkeypatch.setattr(mainline, "run_planned_command", lambda _command: (0, 0.01))

    def fake_duration(_plan, manifest):
        manifest["duration_tracking"]["status"] = "failed"
        manifest["duration_tracking"]["regressions"] = 0
        manifest["non_blockers"].append("duration tracking warning: failed")
        return 1

    monkeypatch.setattr(mainline, "run_duration_tracking", fake_duration)
    plan = mainline.build_plan(output_dir=tmp_path, created_at="2026-06-06T00:00:00Z")

    assert mainline.execute_plan(plan) == 0
    manifest = json.loads(plan.manifest_path.read_text(encoding="utf-8"))
    assert manifest["validation"]["full_pytest"] == "passed"
    assert manifest["status"] == "partial"
    assert "duration tracking warning: failed" in manifest["non_blockers"]


def test_manifest_safety_flags_are_false_for_mutating_actions(tmp_path):
    plan = mainline.build_plan(output_dir=tmp_path, full_pytest=False)
    manifest = mainline.initial_manifest(
        plan,
        created_at="2026-06-06T00:00:00Z",
        git_metadata={
            "source": "local_checkout",
            "git_commit": "abc",
            "branch": "main",
            "dirty": False,
        },
    )
    safety = manifest["safety"]

    assert safety["deploy_performed"] is False
    assert safety["compose_modified"] is False
    assert safety["cleanup_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False


def test_no_shell_true_in_runner_source():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "shell":
            assert not (isinstance(node.value, ast.Constant) and node.value.value is True)


def test_no_docker_compose_prune_restart_remediation_cleanup_in_planned_commands(tmp_path):
    plan = mainline.build_plan(output_dir=tmp_path)
    forbidden = ("docker", "compose", "prune", "restart", "remediation", "cleanup", "rollback")

    for text in command_texts(plan):
        lowered = text.lower()
        assert not any(token in lowered for token in forbidden)


def test_no_real_data_or_docker_daemon_required_for_tests(monkeypatch, tmp_path):
    monkeypatch.setattr(
        mainline,
        "collect_git_metadata",
        lambda: {
            "source": "local_checkout",
            "git_commit": "abc123",
            "branch": "main",
            "dirty": False,
        },
    )
    monkeypatch.setattr(mainline, "run_planned_command", lambda _command: (0, 0.01))
    plan = mainline.build_plan(output_dir=tmp_path, full_pytest=False)

    assert mainline.execute_plan(plan) == 0
    assert str(plan.manifest_path).startswith(str(tmp_path))
    assert "/data" not in str(plan.manifest_path)
