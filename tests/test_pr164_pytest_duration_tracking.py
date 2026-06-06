"""PR164 — full-validation duration history and regression tracking."""

from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "track_pytest_durations.py"


def load_tracker():
    spec = importlib.util.spec_from_file_location("track_pytest_durations", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["track_pytest_durations"] = module
    spec.loader.exec_module(module)
    return module


tracker = load_tracker()


STANDARD_LOG = """
=========================== slowest 25 durations ===========================
114.37s call     tests/test_pr111_v1_readiness_check.py::test_v1_check_profiles_json
91.22s call      tests/test_pr116_v1_packet_history_compare.py::test_packet_compare_latest
0.42s setup      tests/test_example.py::test_case
0.15s teardown   tests/test_example.py::test_case
=========================== 20 passed in 120.00s ===========================
"""


def write_log(tmp_path: Path, text: str = STANDARD_LOG) -> Path:
    path = tmp_path / "pytest.log"
    path.write_text(text, encoding="utf-8")
    return path


def invoke(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=str(REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )


def test_parse_standard_pytest_slowest_durations_section(tmp_path):
    parsed = tracker.parse_log(write_log(tmp_path))

    assert parsed["status"] == "ok"
    assert parsed["durations_found"] is True
    assert parsed["count"] == 4
    assert parsed["top"][0]["seconds"] == 114.37
    assert parsed["top"][0]["nodeid"] == (
        "tests/test_pr111_v1_readiness_check.py::test_v1_check_profiles_json"
    )


def test_parse_call_setup_and_teardown_phases(tmp_path):
    parsed = tracker.parse_log(write_log(tmp_path))

    assert [record["phase"] for record in parsed["top"]] == [
        "call",
        "call",
        "setup",
        "teardown",
    ]


def test_extract_file_and_test_name_from_nodeid(tmp_path):
    parsed = tracker.parse_log(write_log(tmp_path))

    record = parsed["top"][0]
    assert record["file"] == "tests/test_pr111_v1_readiness_check.py"
    assert record["test"] == "test_v1_check_profiles_json"


def test_no_durations_section_returns_controlled_status(tmp_path):
    log = write_log(tmp_path, "10 passed in 3.00s\n")

    parsed = tracker.parse_log(log)

    assert parsed["status"] == "no_durations_found"
    assert parsed["durations_found"] is False
    assert "no pytest slowest durations section found" in parsed["warnings"]


def test_missing_log_returns_controlled_not_found(tmp_path):
    missing = tmp_path / "missing.log"

    parsed = tracker.parse_log(missing)
    result = invoke("--log", str(missing), "--json")

    assert parsed["status"] == "not_found"
    assert result.returncode != 0
    data = json.loads(result.stdout)
    assert data["status"] == "not_found"
    assert "Traceback" not in result.stderr


def test_malformed_duration_line_is_warned_without_crashing(tmp_path):
    log = write_log(
        tmp_path,
        """
=========================== slowest 25 durations ===========================
not-a-duration line
1.00s call tests/test_ok.py::test_ok
=========================== 1 passed in 1.00s ===========================
""",
    )

    parsed = tracker.parse_log(log)

    assert parsed["status"] == "ok"
    assert parsed["count"] == 1
    assert any("malformed" in warning for warning in parsed["warnings"])


def test_json_mode_emits_strict_json(tmp_path):
    result = invoke("--log", str(write_log(tmp_path)), "--json")

    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["schema_version"] == 1
    assert data["mode"] == "pytest_duration_tracking"
    assert data["safety"]["shell_true"] is False


def test_baseline_with_same_nodeid_and_slower_current_flags_regression(tmp_path):
    baseline = {
        "schema_version": 1,
        "mode": "pytest_duration_history",
        "runs": [{"top": [{"nodeid": "tests/test_slow.py::test_case", "seconds": 80.0}]}],
    }
    current = [{"nodeid": "tests/test_slow.py::test_case", "seconds": 110.0}]

    regressions = tracker.detect_regressions(current, baseline)

    assert regressions == [
        {
            "nodeid": "tests/test_slow.py::test_case",
            "previous_seconds": 80.0,
            "current_seconds": 110.0,
            "delta_seconds": 30.0,
            "delta_percent": 37.5,
            "severity": "warning",
        }
    ]


def test_small_increase_below_threshold_does_not_flag_regression():
    baseline = {"runs": [{"top": [{"nodeid": "tests/test.py::test_case", "seconds": 80.0}]}]}
    current = [{"nodeid": "tests/test.py::test_case", "seconds": 85.0}]

    assert tracker.detect_regressions(current, baseline) == []


def test_new_nodeid_has_no_regression():
    baseline = {"runs": [{"top": [{"nodeid": "tests/old.py::test_case", "seconds": 80.0}]}]}
    current = [{"nodeid": "tests/new.py::test_case", "seconds": 200.0}]

    assert tracker.detect_regressions(current, baseline) == []


def test_missing_baseline_does_not_fail(tmp_path):
    log = write_log(tmp_path)
    missing = tmp_path / "missing-history.json"

    result = invoke("--log", str(log), "--baseline", str(missing), "--json")

    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "ok"
    assert data["regressions"] == []
    assert any("baseline/history not found" in warning for warning in data["warnings"])


def test_history_update_appends_a_run(tmp_path):
    log = write_log(tmp_path)
    history_path = tmp_path / "history.json"

    result = invoke("--log", str(log), "--history", str(history_path), "--update-history")

    assert result.returncode == 0, result.stderr
    history = json.loads(history_path.read_text(encoding="utf-8"))
    assert history["mode"] == "pytest_duration_history"
    assert len(history["runs"]) == 1
    assert history["runs"][0]["top"][0]["seconds"] == 114.37


def test_history_update_preserves_previous_runs(tmp_path):
    log = write_log(tmp_path)
    history_path = tmp_path / "history.json"
    history_path.write_text(
        json.dumps({"schema_version": 1, "mode": "pytest_duration_history", "runs": [{"top": []}]}),
        encoding="utf-8",
    )

    result = invoke("--log", str(log), "--history", str(history_path), "--update-history")

    assert result.returncode == 0, result.stderr
    history = json.loads(history_path.read_text(encoding="utf-8"))
    assert len(history["runs"]) == 2


def test_history_max_runs_prunes_oldest_when_documented_and_explicit(tmp_path):
    log = write_log(tmp_path)
    history_path = tmp_path / "history.json"
    history_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "mode": "pytest_duration_history",
                "runs": [{"created_at": "old-1", "top": []}, {"created_at": "old-2", "top": []}],
            }
        ),
        encoding="utf-8",
    )

    result = invoke(
        "--log",
        str(log),
        "--history",
        str(history_path),
        "--update-history",
        "--max-runs",
        "2",
    )

    assert result.returncode == 0, result.stderr
    history = json.loads(history_path.read_text(encoding="utf-8"))
    assert len(history["runs"]) == 2
    assert history["runs"][0]["created_at"] == "old-2"


def test_no_history_write_without_explicit_update_history(tmp_path):
    log = write_log(tmp_path)
    history_path = tmp_path / "history.json"

    result = invoke("--log", str(log), "--history", str(history_path), "--json")

    assert result.returncode == 0, result.stderr
    assert not history_path.exists()


def test_duration_report_can_be_added_to_manifest_without_breaking_existing_fields(tmp_path):
    log = write_log(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"schema_version": 1, "mode": "docker01_pr_validation_manifest", "keep": True}),
        encoding="utf-8",
    )

    result = invoke("--log", str(log), "--manifest", str(manifest_path), "--json")

    assert result.returncode == 0, result.stderr
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["keep"] is True
    assert manifest["duration_report"]["count"] == 4
    assert manifest["duration_report"]["top"][0]["nodeid"].startswith("tests/")


def test_manifest_backup_is_created_for_in_place_update(tmp_path):
    log = write_log(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    original = {"schema_version": 1, "mode": "docker01_pr_validation_manifest"}
    manifest_path.write_text(json.dumps(original), encoding="utf-8")

    result = invoke("--log", str(log), "--manifest", str(manifest_path))

    assert result.returncode == 0, result.stderr
    backup_path = manifest_path.with_name("manifest.json.bak")
    assert backup_path.is_file()
    assert json.loads(backup_path.read_text(encoding="utf-8")) == original


def test_duration_parsing_failure_becomes_non_blocking_warning_in_manifest(tmp_path):
    log = write_log(tmp_path, "no duration section here\n")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"non_blockers": []}), encoding="utf-8")

    result = invoke("--log", str(log), "--manifest", str(manifest_path), "--json")

    assert result.returncode == 0, result.stderr
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["duration_report"]["status"] == "no_durations_found"
    assert "duration tracking warning: no_durations_found" in manifest["non_blockers"]


def test_script_does_not_use_shell_true_or_subprocess_calls_for_execution():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                assert not (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                )
            if isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"run", "Popen", "call", "check_call", "check_output"}


def test_script_does_not_call_docker_compose_or_cleanup_remediation_rollback():
    text = SCRIPT.read_text(encoding="utf-8").lower()

    assert "docker compose up" not in text
    assert "docker compose down" not in text
    assert "docker compose restart" not in text
    assert "cleanup execute" not in text
    assert "remediation execute" not in text
    assert "rollback execute" not in text
    assert "cleanup_executed" in text
    assert "remediation_executed" in text
    assert "rollback_executed" in text


def test_script_does_not_mutate_real_data_in_tests(tmp_path):
    log = write_log(tmp_path)
    result = invoke("--log", str(log), "--json")

    assert result.returncode == 0, result.stderr
    assert not Path("/data/pr164-duration-history.json").exists()


def test_script_writes_only_explicit_temp_history_and_manifest_paths(tmp_path):
    log = write_log(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    history_path = tmp_path / "history.json"
    manifest_path.write_text(json.dumps({}), encoding="utf-8")

    result = invoke(
        "--log",
        str(log),
        "--manifest",
        str(manifest_path),
        "--history",
        str(history_path),
        "--update-history",
        "--json",
    )

    assert result.returncode == 0, result.stderr
    assert manifest_path.exists()
    assert manifest_path.with_name("manifest.json.bak").exists()
    assert history_path.exists()
    assert {path.name for path in tmp_path.iterdir()} == {
        "pytest.log",
        "manifest.json",
        "manifest.json.bak",
        "history.json",
    }
