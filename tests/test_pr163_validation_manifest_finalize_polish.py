from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "finalize_validation_manifest.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("finalize_validation_manifest", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["finalize_validation_manifest"] = module
    spec.loader.exec_module(module)
    return module


helper = load_helper()


def base_manifest() -> dict:
    return {
        "schema_version": 1,
        "mode": "docker01_pr_validation_manifest",
        "status": "partial",
        "verdict": "hold",
        "commands": [
            {"name": "lint", "status": "not_run"},
            {"name": "compile", "status": "unknown"},
            {"name": "pytest_targeted", "status": "not_run"},
            {"name": "pytest_full_runner", "status": "not_run"},
        ],
        "phases": [{"name": "validation", "status": "unknown", "duration_seconds": None}],
        "logs": {},
        "validation": {
            "ruff": "unknown",
            "compileall": "unknown",
            "targeted_tests": "unknown",
            "full_pytest": "unknown",
        },
        "safety": {
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "docker_compose_mutation_beyond_deploy": False,
            "docker_prune": False,
            "volume_prune": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_mutation": False,
        },
        "non_blockers": [],
    }


def write_manifest(tmp_path: Path, manifest: dict | None = None) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest or base_manifest()), encoding="utf-8")
    return path


def invoke(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HELPER_PATH), *args],
        cwd=str(REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )


def read_finalized(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "manifest.finalized.json").read_text(encoding="utf-8"))


def finalize_with_log(
    tmp_path: Path, text: str, *extra_args: str, log_arg: str = "--validation-log"
) -> dict:
    manifest_path = write_manifest(tmp_path)
    log = tmp_path / "validation.log"
    log.write_text(text, encoding="utf-8")

    result = invoke(str(manifest_path), log_arg, str(log), *extra_args)

    assert result.returncode == 0, result.stderr
    return read_finalized(tmp_path)


def warning_text(manifest: dict) -> str:
    return "\n".join(manifest["evidence_import"]["warnings"])


@pytest.mark.parametrize(
    "summary",
    [
        "failed: 0",
        "0 failed",
        "failed=0",
        '"failed": 0',
        "20 passed / 0 failed",
    ],
)
def test_zero_failure_summaries_do_not_create_conflict_warning(tmp_path, summary):
    finalized = finalize_with_log(tmp_path, f"ruff: passed\n{summary}\n")

    warnings = warning_text(finalized)
    assert "conflicting" not in warnings
    assert "imported evidence contains failure/conflict" not in warnings
    assert finalized["evidence_import"]["logs"][0]["has_fail"] is False


@pytest.mark.parametrize(
    "summary",
    [
        "full pytest reached 100%",
        "ci_status=passed",
    ],
)
def test_success_evidence_is_treated_as_pass_without_conflict_warning(tmp_path, summary):
    finalized = finalize_with_log(tmp_path, summary)

    warnings = warning_text(finalized)
    assert "conflicting" not in warnings
    assert "imported evidence contains failure/conflict" not in warnings
    assert finalized["evidence_import"]["logs"][0]["has_pass"] is True


def test_full_pytest_100_percent_marks_full_pytest_passed(tmp_path):
    finalized = finalize_with_log(tmp_path, "full pytest reached 100%")

    assert finalized["validation"]["full_pytest"] == "passed"


@pytest.mark.parametrize(
    "failure",
    [
        "failed: 1",
        "1 failed",
        "exit code 1",
        "Traceback (most recent call last):",
    ],
)
def test_real_failures_create_failure_warning(tmp_path, failure):
    finalized = finalize_with_log(tmp_path, failure)

    warnings = warning_text(finalized)
    assert "imported evidence contains failure/conflict" in warnings
    assert finalized["evidence_import"]["logs"][0]["has_fail"] is True
    assert finalized["status"] == "failed"


def test_mixed_pass_and_real_failure_evidence_remains_conservative(tmp_path):
    finalized = finalize_with_log(tmp_path, "ruff: passed\nfailed: 1\n")

    warnings = warning_text(finalized)
    assert "conflicting pass/fail evidence" in warnings
    assert "imported evidence contains failure/conflict" in warnings
    assert finalized["status"] != "passed"
    assert finalized["verdict"] != "pass"


def test_explicit_pass_and_verdict_override_still_work_with_failure_warning(tmp_path):
    finalized = finalize_with_log(
        tmp_path,
        "failed: 1\n",
        "--status",
        "passed",
        "--verdict",
        "pass",
    )

    assert finalized["status"] == "passed"
    assert finalized["verdict"] == "pass"
    assert "imported evidence contains failure/conflict" in warning_text(finalized)


def test_duplicate_non_blockers_are_deduped_and_trimmed(tmp_path):
    manifest = base_manifest()
    manifest["non_blockers"] = [
        "historical metadata hygiene advisory",
        "expected disposable execute skip",
        " historical metadata hygiene advisory ",
    ]
    manifest_path = write_manifest(tmp_path, manifest)

    result = invoke(
        str(manifest_path),
        "--non-blocker",
        "expected disposable execute skip",
        "--non-blocker",
        "new advisory",
        "--non-blocker",
        "new advisory ",
    )

    assert result.returncode == 0, result.stderr
    finalized = read_finalized(tmp_path)
    assert finalized["non_blockers"] == [
        "historical metadata hygiene advisory",
        "expected disposable execute skip",
        "new advisory",
    ]


def test_finalized_manifest_remains_valid_json_with_unchanged_schema_and_mode(tmp_path):
    manifest_path = write_manifest(tmp_path)

    result = invoke(str(manifest_path), "--status", "passed", "--verdict", "pass")

    assert result.returncode == 0, result.stderr
    finalized = read_finalized(tmp_path)
    assert finalized["schema_version"] == 1
    assert finalized["mode"] == "docker01_pr_validation_manifest"


def test_helper_source_does_not_introduce_shell_true_or_execution_imports():
    source = HELPER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                assert not (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                )
    assert "import subprocess" not in source
    assert "from subprocess" not in source


def test_direct_finalize_keeps_status_and_verdict_conservative_for_ambiguous_evidence(tmp_path):
    manifest = base_manifest()
    args = SimpleNamespace(
        validation_log=None,
        qa_log=None,
        runner_log=None,
        targeted_log=None,
        full_pytest_log=None,
        status=None,
        verdict=None,
        non_blocker=[],
    )

    finalized = helper.finalize_manifest(manifest, args)

    assert finalized["status"] == "partial"
    assert finalized["verdict"] == "hold"
