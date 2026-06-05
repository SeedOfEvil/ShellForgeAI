"""PR157 — validation lane optimizer and test impact map.

These tests exercise the read-only lane-selection logic in
``scripts/validate_pr.py`` plus the impact map in
``scripts/validation_matrix.json``. The helper is loaded directly (not as part
of the shellforgeai runtime package) because it is dev-validation tooling, not
product runtime behavior.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "validate_pr.py"
MATRIX = REPO_ROOT / "scripts" / "validation_matrix.json"


def _load_helper():
    spec = importlib.util.spec_from_file_location("validate_pr_helper", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vp = _load_helper()


def plan(changed, **kwargs):
    return vp.plan_validation(list(changed), **kwargs)


def commands(p):
    return p["recommended_commands"]


def has_full_pytest(p) -> bool:
    """A 'full pytest' run is a whole-suite pytest invocation (no test paths)."""
    for cmd in p["recommended_commands"]:
        if cmd.strip() == "pytest -q --durations=25":
            return True
        if cmd.strip() in {"pytest -q", "pytest -q tests", "pytest -q tests/"}:
            return True
    return False


# --------------------------------------------------------------------------- #
# Lane selection (required tests 1-13)
# --------------------------------------------------------------------------- #
def test_01_docs_only_selects_fast_lane():
    p = plan(["docs/cli.md"])
    assert p["selected_lane"] == "fast"
    assert p["estimated_runtime_class"] == "short"


def test_02_readme_and_ops_only_select_fast_lane():
    assert plan(["README.md"])["selected_lane"] == "fast"
    assert plan(["OPS.md"])["selected_lane"] == "fast"
    assert plan(["docs/roadmap.md"])["selected_lane"] == "fast"


def test_03_ask_routing_selects_targeted_runtime():
    p = plan(["src/shellforgeai/core/ask_routing.py"])
    assert p["selected_lane"] == "targeted_runtime"
    assert p["full_pytest_required"] is False


def test_04_interactive_command_file_selects_targeted_runtime():
    p = plan(["src/shellforgeai/interactive/commands.py"])
    assert p["selected_lane"] == "targeted_runtime"


def test_05_recipe_preflight_selects_targeted_runtime():
    # recipe_preflight.py legitimately contains 'docker restart' preview text;
    # it must NOT be force-escalated to full by path classification alone.
    p = plan(["src/shellforgeai/core/recipe_preflight.py"])
    assert p["selected_lane"] == "targeted_runtime"
    assert p["safety_escalations"] == []


def test_06_remediation_execution_file_selects_full():
    p = plan(["src/shellforgeai/core/disposable_remediation.py"])
    assert p["selected_lane"] == "full"
    assert p["full_pytest_required"] is True


def test_07_rollback_execution_file_selects_full():
    p = plan(["src/shellforgeai/core/rollback_preview.py"])
    assert p["selected_lane"] == "full"


def test_08_dockerfile_selects_full():
    assert plan(["Dockerfile"])["selected_lane"] == "full"


def test_09_pyproject_selects_full():
    assert plan(["pyproject.toml"])["selected_lane"] == "full"


def test_10_v1_validate_script_selects_full():
    assert plan(["scripts/v1_validate.sh"])["selected_lane"] == "full"


def test_11_shell_true_keyword_escalates_to_full():
    # A normally-targeted source path, but the changed content adds shell=True.
    p = plan(
        ["src/shellforgeai/core/some_new_helper.py"],
        contents={"src/shellforgeai/core/some_new_helper.py": "subprocess.run(cmd, shell=True)\n"},
    )
    assert p["selected_lane"] == "full"
    assert any(h["keyword"] == "shell=True" for h in p["safety_escalations"])


def test_12_docker_compose_keyword_escalates_to_full():
    p = plan(
        ["src/shellforgeai/core/some_new_helper.py"],
        contents={"src/shellforgeai/core/some_new_helper.py": "run docker compose up -d\n"},
    )
    assert p["selected_lane"] == "full"
    assert any(h["keyword"] == "docker compose" for h in p["safety_escalations"])


def test_13_unknown_source_file_targeted_with_warning():
    p = plan(["src/shellforgeai/util/brandnew_unmapped_module.py"])
    assert p["selected_lane"] == "targeted_runtime"
    assert p["warnings"], "unmapped source module should warn"


# --------------------------------------------------------------------------- #
# Commands and tests (required tests 14-20)
# --------------------------------------------------------------------------- #
def test_14_commands_include_ruff_check():
    assert "ruff check ." in commands(plan(["docs/cli.md"]))


def test_15_commands_include_compileall():
    assert "python -m compileall -q src tests" in commands(plan(["docs/cli.md"]))


def test_16_commands_include_pr_specific_tests_when_pr_supplied():
    p = plan(["src/shellforgeai/core/ask_routing.py"], pr_number=156)
    assert any(t.startswith("tests/test_pr156_") for t in p["recommended_tests"])
    pytest_cmd = [c for c in commands(p) if c.startswith("pytest -q ")]
    assert pytest_cmd and "tests/test_pr156_" in pytest_cmd[0]


def test_17_commands_include_related_tests_from_matrix():
    p = plan(["src/shellforgeai/core/ask_routing.py"])
    assert "tests/test_pr105_ask_ops_report_routing.py" in p["recommended_tests"]


def test_18_full_lane_includes_durations():
    p = plan(["Dockerfile"])
    assert "pytest -q --durations=25" in commands(p)


def test_19_fast_lane_excludes_full_pytest():
    p = plan(["docs/cli.md"])
    assert p["full_pytest_required"] is False
    assert not has_full_pytest(p)


def test_20_targeted_lane_excludes_full_pytest_by_default():
    p = plan(["src/shellforgeai/core/ask_routing.py"])
    assert p["full_pytest_required"] is False
    assert not has_full_pytest(p)


# --------------------------------------------------------------------------- #
# Output / JSON / execution modes (required tests 21-25)
# --------------------------------------------------------------------------- #
def test_21_json_output_is_strict_parseable():
    # Programmatic public-plan serialization.
    p = plan(["src/shellforgeai/core/ask_routing.py"], pr_number=156)
    data = json.loads(json.dumps(vp._public_plan(p)))
    assert data["selected_lane"] == "targeted_runtime"
    assert "_commands" not in data  # internal argv stripped from JSON

    # End-to-end CLI --json.
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--changed-files", "Dockerfile", "--json"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stderr
    cli_data = json.loads(result.stdout)
    assert cli_data["selected_lane"] == "full"
    assert cli_data["full_pytest_required"] is True


def test_22_dry_run_does_not_execute(monkeypatch):
    def boom(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("dry-run must not execute any subprocess")

    monkeypatch.setattr(vp.subprocess, "run", boom)
    rc = vp.main(["--changed-files", "docs/cli.md"])
    assert rc == 0


def test_23_execute_mode_runs_only_recommended_commands():
    p = plan(["docs/cli.md"])
    calls: list[list[str]] = []

    def recording_runner(argv):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0)

    results = vp.execute_plan(p, runner=recording_runner)
    expected = [c["argv"] for c in p["_commands"]]
    assert calls == expected
    assert [r["display"] for r in results] == p["recommended_commands"]


def test_24_output_states_why_full_pytest_required_or_not():
    full = plan(["Dockerfile"])
    assert full["full_pytest_reason"]
    assert "required" in full["full_pytest_reason"].lower()
    assert "Full pytest reason:" in vp.render_human(full)

    targeted = plan(["src/shellforgeai/core/ask_routing.py"])
    assert targeted["full_pytest_reason"]
    assert "not required" in targeted["full_pytest_reason"].lower()


def test_25_output_includes_estimated_runtime_class():
    for files, expected in [
        (["docs/cli.md"], "short"),
        (["src/shellforgeai/core/ask_routing.py"], "medium"),
        (["Dockerfile"], "long"),
    ]:
        p = plan(files)
        assert p["estimated_runtime_class"] == expected
        assert "Estimated runtime:" in vp.render_human(p)


# --------------------------------------------------------------------------- #
# Safety-gate integrity and design invariants
# --------------------------------------------------------------------------- #
def test_full_validation_remains_available_via_profile():
    p = plan(["docs/cli.md"], profile="full")
    assert p["selected_lane"] == "full"
    assert "pytest -q --durations=25" in commands(p)


def test_full_validation_flag_forces_full_via_cli():
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--changed-files",
            "docs/cli.md",
            "--full-validation",
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["selected_lane"] == "full"


def test_profile_cannot_weaken_safety_escalation():
    # Even when the operator asks for 'fast', a safety keyword keeps it full.
    p = plan(
        ["src/shellforgeai/core/some_new_helper.py"],
        contents={"src/shellforgeai/core/some_new_helper.py": "os.system('rm -rf /tmp/x')\n"},
        profile="fast",
    )
    assert p["selected_lane"] == "full"
    assert any("cannot weaken safety gate" in w for w in p["warnings"])


def test_documentation_describing_keywords_does_not_escalate():
    # docs/safety.md mentions shell=True etc.; editing docs must stay fast.
    p = plan(
        ["docs/safety.md"],
        contents={"docs/safety.md": "We never use shell=True or docker compose mutation.\n"},
    )
    assert p["selected_lane"] == "fast"
    assert p["safety_escalations"] == []


def test_multiple_files_take_max_lane():
    p = plan(["docs/cli.md", "src/shellforgeai/core/ask_routing.py", "Dockerfile"])
    assert p["selected_lane"] == "full"


def test_changed_test_file_is_added_to_recommended_tests():
    target = "tests/test_pr156_recipe_preflight_ask_target_extraction.py"
    p = plan([target])
    assert p["selected_lane"] == "fast"  # tests-only change
    assert target in p["recommended_tests"]


def test_dotfiles_and_path_prefix_normalization():
    # Leading "./" is stripped, but dotfiles/dotdirs keep their leading dot.
    assert vp._norm("./docs/cli.md") == "docs/cli.md"
    assert vp._norm(".github/workflows/ci.yml") == ".github/workflows/ci.yml"
    assert plan(["./docs/cli.md"])["selected_lane"] == "fast"
    assert plan([".github/workflows/ci.yml"])["selected_lane"] == "full"
    assert plan([".gitignore"])["selected_lane"] == "fast"


def test_glob_matcher_handles_double_star():
    assert vp._glob_match("docs/**", "docs/a/b.md")
    assert vp._glob_match("src/**/*.py", "src/shellforgeai/core/foo.py")
    assert vp._glob_match("src/shellforgeai/interactive/**", "src/shellforgeai/interactive/repl.py")
    assert not vp._glob_match("*.md", "docs/x.md")
    assert vp._glob_match("*.md", "README.md")
    assert vp._glob_match(
        "src/shellforgeai/core/*remediation*", "src/shellforgeai/core/disposable_remediation.py"
    )


# --------------------------------------------------------------------------- #
# Matrix and docs presence
# --------------------------------------------------------------------------- #
def test_matrix_json_is_valid_and_complete():
    data = json.loads(MATRIX.read_text(encoding="utf-8"))
    assert data["lane_order"] == ["fast", "targeted_runtime", "full"]
    assert {"fast", "targeted_runtime", "full"} <= set(data["runtime_class"])
    assert data["rules"], "matrix must define rules"
    for rule in data["rules"]:
        assert rule["lane"] in {"fast", "targeted_runtime", "full"}
        assert "pattern" in rule and "reason" in rule
    assert data["safety_escalation"]["lane"] == "full"
    for kw in ("shell=True", "docker compose", "subprocess", "os.system"):
        assert kw in data["safety_escalation"]["keywords"]


def test_validation_docs_exist_with_lane_definitions():
    lanes = REPO_ROOT / "docs" / "VALIDATION_LANES.md"
    matrix_doc = REPO_ROOT / "docs" / "VALIDATION_MATRIX.md"
    assert lanes.exists(), "docs/VALIDATION_LANES.md must exist"
    assert matrix_doc.exists(), "docs/VALIDATION_MATRIX.md must exist"
    lanes_text = lanes.read_text(encoding="utf-8").lower()
    for needle in ("lane a", "lane b", "lane c", "fast", "targeted", "full validation", "pytest"):
        assert needle in lanes_text, f"VALIDATION_LANES.md missing: {needle}"
    matrix_text = matrix_doc.read_text(encoding="utf-8").lower()
    for needle in ("docs/**", "ask_routing", "remediation", "dockerfile", "safety"):
        assert needle in matrix_text, f"VALIDATION_MATRIX.md missing: {needle}"


def test_helper_has_no_shell_true_or_os_system():
    src = SCRIPT.read_text(encoding="utf-8")
    assert "shell=True" not in src
    assert "os.system(" not in src


def test_ops_and_roadmap_reference_validation_lanes():
    ops = (REPO_ROOT / "OPS.md").read_text(encoding="utf-8").lower()
    roadmap = (REPO_ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8").lower()
    assert "validation lane" in ops
    assert "validation_lanes.md" in ops or "validation-lanes" in ops
    assert "pr157" in roadmap


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
