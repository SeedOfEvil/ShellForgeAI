"""PR213 Docker01 QA bundle hygiene evidence integration tests."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_operator_qa_bundle.py"

spec = importlib.util.spec_from_file_location("pr213_qa_bundle", HELPER_PATH)
qa = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules["pr213_qa_bundle"] = qa
spec.loader.exec_module(qa)

PR = 213
COMMIT = "abcdef0123456789abcdef0123456789abcdef01"


def _safety(**overrides):
    data = {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "file_deleted": False,
        "container_restarted": False,
        "docker_compose_executed": False,
    }
    data.update(overrides)
    return data


def _json(data):
    return json.dumps(data)


def _core_stdout(key):
    if key in {"v1_quick", "v1_standard", "remediation_self_test"}:
        return _json(
            {
                "status": "ok",
                "summary": {"passed": 1, "failed": 0},
                "skipped": ["live disposable"],
                "safety": _safety(live_disposable_execute=False),
            }
        )
    if key == "ops_report":
        return _json({"read_only": True, "mutation_performed": False, "safety": _safety()})
    if key in {"status", "triage_docker", "propose", "apply_preview", "verify", "handoff"}:
        return _json({"status": "ok", "read_only": True, "safety": _safety()})
    if key == "docker_inspect":
        return _json(
            [
                {
                    "RestartCount": 0,
                    "State": {"Status": "running", "Health": {"Status": "healthy"}},
                    "Config": {"Image": "shellforgeai:test", "Labels": {}},
                }
            ]
        )
    if key == "disk":
        return "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 10G 2G 8G 20% /\n"
    if key == "validation_status":
        return _json(
            {
                "status": "passed",
                "classification": "passed",
                "pass_eligible": True,
                "rerun_required": False,
                "source": {"kind": "test"},
            }
        )
    if key == "ask_mutation":
        return "Refusing to execute; no cleanup, restart, Docker, or Compose command was executed."
    return "ok\n"


def _history(status="ok", safety=None):
    return {
        "status": status,
        "reports": [
            {
                "report_dir": "/tmp/h1",
                "valid_shape": True,
                "disk_use_percent": "75%",
                "candidate_cleanup_items_total": 7,
                "candidate_cleanup_bytes_estimated": 1234,
                "docker_images_total": 9,
                "shellforgeai_images_total": 2,
                "compose_backups_total": 3,
                "qa_bundles_total": 4,
                "validation_artifacts_total": 5,
                "receipt_artifacts_total": 6,
            }
        ],
        "summary": {"latest_report_dir": "/tmp/h1"},
        "safety": safety or _safety(),
        "warnings": [],
    }


def _compare(safety=None):
    return {
        "status": "ok",
        "new": _history()["reports"][0],
        "notable_changes": ["disk use increased"],
        "safety": safety or _safety(),
        "warnings": [],
    }


def _review():
    return {"status": "ok", "bundle_path": "/tmp/review", "safety": _safety(), "warnings": []}


class Runner:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        key = tuple(argv)
        if key in self.outputs:
            rc, out, err = self.outputs[key]
            return SimpleNamespace(returncode=rc, stdout=out, stderr=err)
        for spec in qa.build_command_specs(PR, COMMIT):
            if tuple(spec.argv) == key:
                return SimpleNamespace(returncode=0, stdout=_core_stdout(spec.key), stderr="")
        return SimpleNamespace(returncode=127, stdout="", stderr="unexpected")


def _outputs(include_review=False, history=None, compare=None):
    outputs = {}
    for spec in qa.hygiene_command_specs(include_review):
        if spec.key == "hygiene_history":
            outputs[tuple(spec.argv)] = (0, _json(history or _history()), "")
        elif spec.key == "hygiene_compare_latest":
            outputs[tuple(spec.argv)] = (0, _json(compare or _compare()), "")
        else:
            outputs[tuple(spec.argv)] = (0, _json(_review()), "")
    return outputs


def test_happy_path_writes_hygiene_outputs_and_summary(tmp_path):
    runner = Runner(_outputs())
    result = qa.generate_bundle(PR, COMMIT, tmp_path / "bundle", runner=runner)
    assert result["hygiene"]["history_status"] == "ok"
    assert result["hygiene"]["compare_latest_status"] == "ok"
    assert result["hygiene"]["review_bundle_status"] == "skipped"
    assert result["hygiene"]["latest_report_dir"] == "/tmp/h1"
    assert result["hygiene"]["disk_use_percent"] == "75%"
    assert result["hygiene"]["candidate_cleanup_items_total"] == 7
    assert result["hygiene"]["notable_changes"] == ["disk use increased"]
    assert (tmp_path / "bundle/raw/hygiene-history.json").is_file()
    assert (tmp_path / "bundle/raw/hygiene-compare-latest.json").is_file()
    summary = (tmp_path / "bundle/qa-summary.md").read_text()
    assert "## Docker01 hygiene evidence" in summary
    commands = json.loads((tmp_path / "bundle/commands-run.json").read_text())["commands"]
    hygiene = [c for c in commands if c["key"].startswith("hygiene_")]
    assert hygiene and all(c["critical"] is False for c in hygiene)


def test_missing_hygiene_is_non_blocking_warning(tmp_path):
    runner = Runner({tuple(qa.hygiene_command_specs()[0].argv): (1, "", "missing")})
    result = qa.generate_bundle(PR, COMMIT, tmp_path / "bundle", runner=runner)
    assert result["hygiene"]["history_status"] in {"not_available", "failed"}
    assert result["status"] in {"passed", "partial"}
    assert result["hygiene"]["warnings"]


def test_review_bundle_opt_in_only(tmp_path):
    runner = Runner(_outputs())
    qa.generate_bundle(PR, COMMIT, tmp_path / "default", runner=runner)
    assert not any("--review-bundle-latest" in call for call in runner.calls for call in call)
    runner = Runner(_outputs(include_review=True))
    result = qa.generate_bundle(
        PR, COMMIT, tmp_path / "review", runner=runner, include_hygiene_review_bundle=True
    )
    assert any("--review-bundle-latest" in call for call in runner.calls for call in call)
    assert result["hygiene"]["review_bundle_status"] == "ok"
    assert result["hygiene"]["latest_review_bundle"] == "/tmp/review"
    assert (tmp_path / "review/raw/hygiene-review-bundle.json").is_file()


def test_dry_run_lists_hygiene_and_writes_nothing(tmp_path):
    out = tmp_path / "dry"
    result = qa.generate_bundle(PR, COMMIT, out, dry_run=True)
    argv = [c["argv"] for c in result["planned_commands"]]
    assert any("--history" in a for a in argv)
    assert any("--compare-latest" in a for a in argv)
    assert not out.exists()


def test_hygiene_allowlist_is_narrow():
    py = sys.executable
    assert qa.is_command_allowed(
        [py, "scripts/docker01_hygiene_report.py", "--history", "--root", "/tmp", "--json"]
    )
    assert qa.is_command_allowed(
        [py, "scripts/docker01_hygiene_report.py", "--compare-latest", "--root", "/tmp", "--json"]
    )
    assert qa.is_command_allowed(
        [
            py,
            "scripts/docker01_hygiene_report.py",
            "--review-bundle-latest",
            "--root",
            "/tmp",
            "--json",
        ]
    )
    for bad in (
        "--out",
        "--validate",
        "--review-bundle",
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
        assert not qa.is_command_allowed([py, "scripts/docker01_hygiene_report.py", bad])
    assert not qa.is_command_allowed([py, "scripts/unknown.py", "--history"])


def test_hygiene_safety_flags_fail_safety(tmp_path):
    for flag in (
        "docker_prune_executed",
        "file_deleted",
        "container_restarted",
        "docker_compose_executed",
    ):
        runner = Runner(
            _outputs(
                history=_history(safety=_safety(**{flag: True})),
                compare=_compare(safety=_safety(**{flag: True})),
            )
        )
        result = qa.generate_bundle(PR, COMMIT, tmp_path / flag, runner=runner)
        assert result["status"] == "failed"
        assert result["safety"].get(flag) is True


def test_no_shell_true_and_no_executable_prune_strings():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    for argv in [s.argv for s in qa.hygiene_command_specs(True)]:
        joined = " ".join(argv)
        assert "prune" not in joined
        assert " rmi" not in joined
        assert " restart" not in joined
        assert "--delete" not in joined
