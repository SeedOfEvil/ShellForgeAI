from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

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


def base_manifest(tmp_path: Path) -> dict:
    return {
        "schema_version": 1,
        "mode": "docker01_pr_validation_manifest",
        "status": "partial",
        "verdict": "hold",
        "pr": {"number": 162, "head_commit": "abc123", "short_commit": "abc123"},
        "host": {"name": "lab-docker01"},
        "deployment": {"snapshot": "docker01-pr162-before-deploy"},
        "lane": {"selected": "full", "full_validation_required": True},
        "commands": [
            {"name": "lint", "status": "not_run"},
            {"name": "compile", "status": "unknown"},
            {"name": "pytest_targeted", "status": "not_run"},
            {"name": "pytest_full_runner", "status": "not_run"},
        ],
        "phases": [{"name": "validation", "status": "unknown", "duration_seconds": None}],
        "logs": {},
        "final_container": {
            "status": "running",
            "health": "healthy",
            "restart_count": 0,
        },
        "disk": {"root_available": "90G"},
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
        "unknown_future_field": {"preserve": True},
    }


def write_manifest(tmp_path: Path, manifest: dict | None = None) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest or base_manifest(tmp_path)), encoding="utf-8")
    return path


def invoke(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HELPER_PATH), *args],
        cwd=str(REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_finalize_reads_existing_manifest_and_writes_copy_by_default(tmp_path):
    manifest_path = write_manifest(tmp_path)
    log = tmp_path / "validation.log"
    log.write_text(
        "ruff: passed\ncompileall: passed\ntargeted tests passed\nfull pytest: passed\n",
        encoding="utf-8",
    )

    result = invoke(str(manifest_path), "--validation-log", str(log))

    assert result.returncode == 0, result.stderr
    finalized_path = tmp_path / "manifest.finalized.json"
    assert finalized_path.is_file()
    assert read_json(manifest_path)["status"] == "partial"
    finalized = read_json(finalized_path)
    assert finalized["finalized"] is True
    assert finalized["finalized_by"] == "manifest_finalize_helper"


def test_in_place_updates_original_manifest(tmp_path):
    manifest_path = write_manifest(tmp_path)
    log = tmp_path / "validation.log"
    log.write_text("ruff check .: passed\n", encoding="utf-8")

    result = invoke(str(manifest_path), "--validation-log", str(log), "--in-place")

    assert result.returncode == 0, result.stderr
    assert read_json(manifest_path)["finalized"] is True


def test_finalized_manifest_preserves_unknown_fields_records_time_and_evidence(tmp_path):
    manifest_path = write_manifest(tmp_path)
    log = tmp_path / "validation.log"
    log.write_text("All checks passed\n", encoding="utf-8")

    result = invoke(str(manifest_path), "--validation-log", str(log))

    assert result.returncode == 0, result.stderr
    finalized = read_json(tmp_path / "manifest.finalized.json")
    assert finalized["unknown_future_field"] == {"preserve": True}
    assert finalized["finalized_at"].endswith("Z")
    assert finalized["evidence_import"]["enabled"] is True
    assert finalized["evidence_import"]["logs"][0]["type"] == "validation"
    assert finalized["evidence_import"]["logs"][0]["exists"] is True
    assert finalized["evidence_import"]["logs"][0]["parsed"] is True


@pytest.mark.parametrize(
    ("log_text", "key"),
    [
        ("ruff check .: passed", "ruff"),
        ("compileall passed", "compileall"),
        ("PR162 targeted tests passed", "targeted_tests"),
        ("full pytest reached 100%", "full_pytest"),
        ("pytest tests/test_example.py [100%]", "full_pytest"),
    ],
)
def test_imported_validation_log_can_mark_known_commands_passed(tmp_path, log_text, key):
    manifest_path = write_manifest(tmp_path)
    log = tmp_path / "validation.log"
    log.write_text(log_text, encoding="utf-8")

    result = invoke(str(manifest_path), "--validation-log", str(log))

    assert result.returncode == 0, result.stderr
    finalized = read_json(tmp_path / "manifest.finalized.json")
    assert finalized["validation"][key] == "passed"
    command = next(
        record for record in finalized["commands"] if helper._command_validation_key(record) == key
    )
    assert command["evidence_source"] == "imported_log"
    assert command["imported"] is True
    assert command["executed_by_helper"] is False


def test_imported_fail_marker_marks_failed_and_warns(tmp_path):
    manifest_path = write_manifest(tmp_path)
    log = tmp_path / "full.log"
    log.write_text("helper exit 1\nFAILED tests/test_bad.py\n", encoding="utf-8")

    result = invoke(str(manifest_path), "--full-pytest-log", str(log))

    assert result.returncode == 0, result.stderr
    finalized = read_json(tmp_path / "manifest.finalized.json")
    assert finalized["status"] == "failed"
    assert finalized["validation"]["full_pytest"] == "failed"
    assert finalized["evidence_import"]["warnings"]


def test_ambiguous_log_does_not_mark_pass_automatically(tmp_path):
    manifest_path = write_manifest(tmp_path)
    log = tmp_path / "validation.log"
    log.write_text("starting validation\ncollected tests\n", encoding="utf-8")

    result = invoke(str(manifest_path), "--validation-log", str(log))

    assert result.returncode == 0, result.stderr
    finalized = read_json(tmp_path / "manifest.finalized.json")
    assert finalized["validation"]["ruff"] == "unknown"
    assert any(
        "ambiguous validation log" in warning
        for warning in finalized["evidence_import"]["warnings"]
    )


def test_explicit_status_and_verdict_overrides_are_recorded(tmp_path):
    manifest_path = write_manifest(tmp_path)

    result = invoke(str(manifest_path), "--status", "passed", "--verdict", "pass")

    assert result.returncode == 0, result.stderr
    finalized = read_json(tmp_path / "manifest.finalized.json")
    assert finalized["status"] == "passed"
    assert finalized["verdict"] == "pass"
    assert finalized["evidence_import"]["operator_status_override"] == "passed"
    assert finalized["evidence_import"]["operator_verdict_override"] == "pass"


def test_missing_log_records_warning_and_does_not_crash(tmp_path):
    manifest_path = write_manifest(tmp_path)

    result = invoke(str(manifest_path), "--validation-log", str(tmp_path / "missing.log"))

    assert result.returncode == 0, result.stderr
    finalized = read_json(tmp_path / "manifest.finalized.json")
    assert finalized["evidence_import"]["logs"][0]["exists"] is False
    assert "missing validation log" in finalized["evidence_import"]["warnings"][0]


def test_invalid_manifest_fails_cleanly_with_no_traceback_and_no_overwrite(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{not-json", encoding="utf-8")

    result = invoke(str(manifest_path))

    assert result.returncode == 2
    assert "status=failed" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "manifest.finalized.json").exists()


def test_conflicting_pass_fail_evidence_does_not_silently_pass(tmp_path):
    manifest_path = write_manifest(tmp_path)
    log = tmp_path / "validation.log"
    log.write_text("ruff: passed\nFAILED tests/test_bad.py\n", encoding="utf-8")

    result = invoke(str(manifest_path), "--validation-log", str(log))

    assert result.returncode == 0, result.stderr
    finalized = read_json(tmp_path / "manifest.finalized.json")
    assert finalized["status"] in {"partial", "failed"}
    assert finalized["verdict"] != "pass"
    assert any("conflicting" in warning for warning in finalized["evidence_import"]["warnings"])


def test_human_summary_includes_imported_log_and_no_rerun_wording(tmp_path):
    manifest_path = write_manifest(tmp_path)
    log = tmp_path / "validation.log"
    log.write_text("full pytest: passed\ntargeted tests passed\n", encoding="utf-8")
    summary_path = tmp_path / "summary.txt"

    result = invoke(
        str(manifest_path), "--validation-log", str(log), "--summary-output", str(summary_path)
    )

    assert result.returncode == 0, result.stderr
    text = summary_path.read_text(encoding="utf-8")
    assert "Docker01 PR validation finalized summary" in text
    assert "Evidence source: imported logs" in text
    assert "tests were not rerun by the finalizer" in text


def test_json_emits_strict_json_only(tmp_path):
    manifest_path = write_manifest(tmp_path)

    result = invoke(str(manifest_path), "--status", "passed", "--json")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed"
    assert result.stderr == ""


def test_unsafe_output_path_is_rejected(tmp_path):
    manifest_path = write_manifest(tmp_path)

    result = invoke(str(manifest_path), "--output", "../escape.json")

    assert result.returncode == 2
    assert "unsafe output path rejected" in result.stderr
    assert not (tmp_path.parent / "escape.json").exists()


def test_helper_source_does_not_call_pytest_docker_compose_or_shell_true():
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
    forbidden_execution_imports = ["import subprocess", "from subprocess"]
    for text in forbidden_execution_imports:
        assert text not in source
    forbidden_mutation_phrases = ["docker compose up", "docker compose restart", "docker restart"]
    for text in forbidden_mutation_phrases:
        assert text not in source.lower()


def test_helper_does_not_mutate_real_data_and_preserves_safety_flags(tmp_path):
    manifest = base_manifest(tmp_path)
    manifest["safety"].update(
        {
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "docker_prune": False,
            "volume_prune": False,
        }
    )
    manifest_path = write_manifest(tmp_path, manifest)

    result = invoke(str(manifest_path), "--status", "passed")

    assert result.returncode == 0, result.stderr
    finalized = read_json(tmp_path / "manifest.finalized.json")
    assert not Path("/data/pr162-finalizer-test-sentinel").exists()
    for key in [
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "docker_prune",
        "volume_prune",
    ]:
        assert finalized["safety"][key] is False


def test_helper_can_add_non_blockers(tmp_path):
    manifest_path = write_manifest(tmp_path)

    result = invoke(str(manifest_path), "--non-blocker", "historical metadata warning")

    assert result.returncode == 0, result.stderr
    finalized = read_json(tmp_path / "manifest.finalized.json")
    assert "historical metadata warning" in finalized["non_blockers"]
