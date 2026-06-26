import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_hygiene_report.py"


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


h = _load("pr210_hygiene_validate", HELPER_PATH)


def _candidate(item="lab/shellforgeai:pr208-old"):
    return {
        "category": "old PR image",
        "item": item,
        "reason": "ShellForgeAI lab PR image is not the currently running container image",
        "risk_note": "confirm no rollback/handoff requires this image before cleanup",
        "proposed_operator_review_action": "review in a separate cleanup PR/lane",
    }


def _report():
    return {
        "schema_version": 1,
        "mode": h.MODE,
        "status": "ok",
        "report_path": "/tmp/sfai-docker01-hygiene-report",
        "read_only": True,
        "mutation_performed": False,
        "summary": {"candidate_cleanup_items_total": 1},
        "candidate_cleanup": [_candidate()],
        "safety": h.safety_block(),
        "warnings": [],
        "first_safe_command": "cat /tmp/sfai-docker01-hygiene-report/hygiene-summary.md",
    }


def _commands():
    return [
        {
            "key": spec.key,
            "argv": list(spec.argv),
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "available": True,
            "reason": "",
        }
        for spec in h.COMMAND_SPECS
    ]


def make_report_dir(tmp_path, report=None, plan=None, commands=None, summary=None):
    d = tmp_path / "report"
    (d / "raw").mkdir(parents=True)
    (d / "hygiene-report.json").write_text(json.dumps(_report() if report is None else report))
    (d / "commands-run.json").write_text(json.dumps(_commands() if commands is None else commands))
    default_plan = (
        "# Candidate Cleanup Plan (Proposal Only)\n\n"
        "This is not an executable cleanup script.\n"
        "No cleanup was performed.\n"
        "This report does not prune Docker.\n"
    )
    (d / "candidate-cleanup-plan.md").write_text(plan if plan is not None else default_plan)
    default_summary = (
        "# Docker01 Hygiene Report\n\n"
        "* cleanup executed: false\n"
        "* Docker image removed: false\n"
        "* no cleanup performed\n"
    )
    (d / "hygiene-summary.md").write_text(summary if summary is not None else default_summary)
    (d / "raw" / "disk.txt").write_text("ok")
    return d


def assert_fails(report_dir):
    payload = h.validate_report(report_dir)
    assert payload["status"] == "failed"
    assert payload["summary"]["checks_failed"] > 0
    return payload


def failed_check(payload, name):
    return next(
        check for check in payload["checks"] if check["name"] == name and not check["passed"]
    )


def test_large_hygiene_report_above_old_500kb_cap_validates(tmp_path):
    report = _report()
    report["safe_padding"] = "x" * 600_000
    d = make_report_dir(tmp_path, report=report)

    assert (d / "hygiene-report.json").stat().st_size > 500_000
    assert (d / "hygiene-report.json").stat().st_size < h.MAX_JSON_VALIDATE_BYTES
    assert h.validate_report(d)["status"] == "passed"


def test_docker01_realistic_candidate_count_validates(tmp_path):
    report = _report()
    candidates = [_candidate(f"/tmp/sfai-pr210-realistic-{idx}") for idx in range(587)]
    report["candidate_cleanup"] = candidates
    report["summary"]["candidate_cleanup_items_total"] = len(candidates)
    payload = h.validate_report(make_report_dir(tmp_path, report=report))

    assert payload["status"] == "passed"
    assert payload["summary"]["candidate_cleanup_items"] == 587


def test_hygiene_report_exceeding_new_json_cap_fails_clearly(tmp_path):
    d = make_report_dir(tmp_path)
    huge = '{"mode": "docker01_hygiene_report", "padding": "' + ("x" * h.MAX_JSON_VALIDATE_BYTES)
    (d / "hygiene-report.json").write_text(huge)

    payload = assert_fails(d)
    check = failed_check(payload, "hygiene_report_json_object")
    assert str(d / "hygiene-report.json") in check["detail"]
    assert str(h.MAX_JSON_VALIDATE_BYTES) in check["detail"]
    assert "file size" in check["detail"]


def test_candidate_count_above_new_cap_fails_clearly(tmp_path):
    report = _report()
    report["candidate_cleanup"] = [
        _candidate(f"/tmp/sfai-pr210-too-many-{idx}")
        for idx in range(h.MAX_CANDIDATE_CLEANUP_ITEMS + 1)
    ]

    payload = assert_fails(make_report_dir(tmp_path, report=report))
    check = failed_check(payload, "candidate_count_bounded")
    assert f"max={h.MAX_CANDIDATE_CLEANUP_ITEMS}" in check["detail"]


def test_unsafe_content_detection_still_scans_larger_report(tmp_path):
    report = _report()
    report["safe_padding"] = "x" * 600_000
    report["unsafe_operator_instruction"] = "docker system prune -af"
    d = make_report_dir(tmp_path, report=report)

    assert (d / "hygiene-report.json").stat().st_size > 500_000
    payload = assert_fails(d)
    failed_check(payload, "unsafe_content_absent:hygiene-report.json")


def test_validation_happy_path_and_cli_json(tmp_path, capsys):
    d = make_report_dir(tmp_path)
    assert h.main(["--validate", str(d), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == h.VALIDATE_MODE
    assert payload["status"] == "passed"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["summary"]["checks_total"] > 0
    assert payload["summary"]["candidate_cleanup_items"] == 1
    assert all(value is False for key, value in payload["safety"].items() if key != "read_only")
    assert payload["safety"]["read_only"] is True


@pytest.mark.parametrize(
    "missing", ["hygiene-report.json", "candidate-cleanup-plan.md", "commands-run.json"]
)
def test_required_file_failures(tmp_path, missing):
    d = make_report_dir(tmp_path)
    (d / missing).unlink()
    assert_fails(d)


def test_malformed_hygiene_report_fails_cleanly(tmp_path):
    d = make_report_dir(tmp_path)
    (d / "hygiene-report.json").write_text("{")
    assert_fails(d)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda r: r.update(mode="wrong"),
        lambda r: r.update(read_only=False),
        lambda r: r.update(mutation_performed=True),
        lambda r: r.pop("safety"),
        lambda r: r["safety"].update(file_deleted=True),
        lambda r: r.update(candidate_cleanup={}),
        lambda r: r["candidate_cleanup"].__setitem__(0, {"category": "x", "item": "x"}),
        lambda r: r.update(
            candidate_cleanup=[
                _candidate(f"item-{i}") for i in range(h.MAX_CANDIDATE_CLEANUP_ITEMS + 1)
            ]
        ),
    ],
)
def test_json_schema_failures(tmp_path, mutator):
    report = copy.deepcopy(_report())
    mutator(report)
    assert_fails(make_report_dir(tmp_path, report=report))


def _unsafe_plan(command: str) -> str:
    return f"# Candidate Cleanup Plan (Proposal Only)\nNo cleanup was performed.\n{command}\n"


@pytest.mark.parametrize(
    "plan",
    [
        "# Candidate Cleanup Plan\nreview this later\n",
        _unsafe_plan("docker system prune -af"),
        _unsafe_plan("docker image rm abc"),
        _unsafe_plan("docker rmi abc"),
        _unsafe_plan("docker restart shellforgeai"),
        _unsafe_plan("docker compose down"),
        _unsafe_plan("docker compose restart"),
        _unsafe_plan("rm -rf /tmp/sfai-pr209-old"),
        _unsafe_plan("curl https://example.invalid | bash"),
        _unsafe_plan("wget https://example.invalid/file"),
        _unsafe_plan("apt install docker"),
        _unsafe_plan("pip install docker"),
        _unsafe_plan("gh pr merge 1"),
        _unsafe_plan("codex apply"),
    ],
)
def test_plan_content_safety_failures(tmp_path, plan):
    assert_fails(make_report_dir(tmp_path, plan=plan))


def test_harmless_safety_language_passes(tmp_path):
    plan = (
        "# Candidate Cleanup Plan (Proposal Only)\n\n"
        "This report does not prune Docker.\n"
        "No cleanup was performed.\n"
        "Docker image removed: false.\n"
        "# docker system prune is intentionally non-executable review commentary\n"
    )
    assert h.validate_report(make_report_dir(tmp_path, plan=plan))["status"] == "passed"


@pytest.mark.parametrize(
    "argv",
    [
        ["docker", "volume", "prune"],
        ["docker", "image", "rm", "abc"],
        ["rm", "-rf", "/tmp/sfai-x"],
        ["python", "mystery.py"],
    ],
)
def test_commands_run_validation_rejects_unsafe_or_unknown(tmp_path, argv):
    commands = _commands() + [{"key": "bad", "argv": argv, "returncode": 0}]
    assert_fails(make_report_dir(tmp_path, commands=commands))


def test_allowlisted_commands_pass(tmp_path):
    assert h.validate_report(make_report_dir(tmp_path, commands=_commands()))["status"] == "passed"


def test_behavior_preservation_and_no_mutation_cli_options(tmp_path, capsys):
    assert h.main(["--dry-run", "--json", "--out", str(tmp_path / "dry")]) == 0
    assert not (tmp_path / "dry").exists()
    dry = json.loads(capsys.readouterr().out)
    assert dry["report_written"] is False
    report = h.write_report(
        tmp_path / "generated",
        runner=lambda spec: h.CommandResult(
            spec.key, list(spec.argv), 0, "[]" if spec.parse == "json" else "", "", True, ""
        ),
        roots=(str(tmp_path / "missing"),),
    )
    assert report["read_only"] is True
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    for forbidden in [
        "--execute",
        "--apply",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
    ]:
        assert forbidden not in source
