"""PR291 fix: deterministic Windows targeted pytest selection tests.

Fake runner fixtures only: no network, no real pytest child, no shell. The
maintained Windows lane launches processes without a shell
(ProcessStartInfo), so a literal ``tests/test_pr291_*.py`` wildcard reached
pytest unexpanded and pytest exited 4 — a selection failure, not a product
test failure. Selection is now resolved with Python filesystem APIs into a
sorted explicit file list before pytest starts.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "windows_authenticated_model_acceptance.py"
)
TESTS_DIR = Path(__file__).resolve().parent

EXPECTED_FILES = (
    "test_pr291_codex_cli_argument_ordering.py",
    "test_pr291_codex_deterministic_output_capture.py",
    "test_pr291_model_doctor_probe_timeout_classification.py",
    "test_pr291_windows_codex_failure_reporting.py",
    "test_pr291_windows_codex_invocation_scope.py",
    "test_pr291_windows_codex_trust_bypass.py",
    "test_codex_provider.py",
)


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "windows_authenticated_model_acceptance_pr291_selection", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


wama = _load_module()


# --- resolution -------------------------------------------------------------------


def test_resolution_is_sorted_explicit_and_complete() -> None:
    resolved = wama.resolve_targeted_test_files(TESTS_DIR)
    assert resolved, "targeted test resolution must not be empty"
    assert resolved == sorted(resolved)
    assert len(resolved) == len(set(resolved))
    names = {Path(path).name for path in resolved}
    for expected in EXPECTED_FILES:
        assert expected in names, f"{expected} missing from targeted selection"
    # Explicit file paths only: no wildcard may reach pytest.
    assert not any("*" in path for path in resolved)
    # Discovery is name-driven, so any future test_pr291_*.py joins the set.
    assert all(
        Path(path).name.startswith("test_pr291_") or Path(path).name == "test_codex_provider.py"
        for path in resolved
    )


def test_resolution_discovers_new_pr291_files(tmp_path: Path) -> None:
    (tmp_path / "test_pr291_alpha.py").write_text("", encoding="utf-8")
    (tmp_path / "test_pr291_beta.py").write_text("", encoding="utf-8")
    (tmp_path / "test_codex_provider.py").write_text("", encoding="utf-8")
    (tmp_path / "test_unrelated.py").write_text("", encoding="utf-8")
    resolved = wama.resolve_targeted_test_files(tmp_path)
    names = [Path(path).name for path in resolved]
    assert names == sorted(names)
    assert set(names) == {
        "test_codex_provider.py",
        "test_pr291_alpha.py",
        "test_pr291_beta.py",
    }


def test_empty_resolution_is_a_clear_selection_error(tmp_path: Path) -> None:
    empty = tmp_path / "empty-tests"
    empty.mkdir()
    assert wama.resolve_targeted_test_files(empty) == []
    result = wama.run_targeted_tests(empty, runner=_fail_if_called)
    assert result["targeted_test_file_count"] == 0
    assert result["targeted_test_files_resolved"] == []
    assert result["targeted_pytest_exit_code"] is None
    assert result["targeted_tests_ok"] is False  # never silently passed
    assert "no targeted test files resolved" in result["targeted_test_selection_error"]


def _fail_if_called(argv, env):
    raise AssertionError("pytest must not be launched for an empty selection")


# --- runner -----------------------------------------------------------------------


class _RecordingRunner:
    def __init__(self, exit_code: int, stdout: str, stderr: str = "") -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.argv: list[str] | None = None
        self.env: dict | None = None

    def __call__(self, argv, env):
        self.argv = list(argv)
        self.env = dict(env)
        return wama.CommandResult(exit_code=self.exit_code, stdout=self.stdout, stderr=self.stderr)


def test_successful_run_reports_ok_with_completion_evidence(tmp_path: Path) -> None:
    (tmp_path / "test_pr291_alpha.py").write_text("", encoding="utf-8")
    (tmp_path / "test_codex_provider.py").write_text("", encoding="utf-8")
    runner = _RecordingRunner(0, "........ [100%]\n")  # no literal "passed" required
    result = wama.run_targeted_tests(tmp_path, runner=runner)
    assert result["targeted_pytest_exit_code"] == 0
    assert result["targeted_tests_ok"] is True
    assert result["targeted_test_selection_error"] is None
    assert result["targeted_test_file_count"] == 2
    # pytest is launched with explicit resolved file paths (argv list).
    assert runner.argv is not None
    assert runner.argv[1:4] == ["-m", "pytest", "-q"]
    assert runner.argv[4:] == result["targeted_test_files_resolved"]
    assert not any("*" in token for token in runner.argv)


def test_failed_run_reports_not_ok_with_bounded_excerpt(tmp_path: Path) -> None:
    (tmp_path / "test_pr291_alpha.py").write_text("", encoding="utf-8")
    runner = _RecordingRunner(1, "F" + ("x" * 10_000) + "\n1 failed in 2.0s\n", "boom\x07")
    result = wama.run_targeted_tests(tmp_path, runner=runner)
    assert result["targeted_pytest_exit_code"] == 1
    assert result["targeted_tests_ok"] is False
    excerpt = result["targeted_pytest_output_excerpt"]
    assert len(excerpt) <= wama.TARGETED_TEST_OUTPUT_EXCERPT_MAX_CHARS
    assert "\x07" not in excerpt
    assert "1 failed" in excerpt


def test_runner_never_uses_shell() -> None:
    import ast

    source = SCRIPT.read_text(encoding="utf-8")
    assert "shell=True" not in source
    tree = ast.parse(source)
    top_level_imports = [
        alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names
    ]
    top_level_imports += [
        node.module or "" for node in tree.body if isinstance(node, ast.ImportFrom)
    ]
    assert "subprocess" not in top_level_imports


# --- summary integration ----------------------------------------------------------


PACKET = {
    "platform": "windows",
    "processes": {"available": True, "total_count": 74, "returned_count": 10, "entries": []},
    "services": {
        "available": True,
        "total_count": 131,
        "running_count": 53,
        "stopped_count": 78,
        "entries": [],
    },
}

GROUNDED_ANSWER = (
    "This Windows host has 74 processes visible (10 shown) and 131 services: "
    "53 running and 78 stopped."
)


def _summary(**overrides):
    kwargs = {
        "codex_login_checked": True,
        "codex_logged_in": True,
        "codex_home_configured": True,
        "same_process_context": True,
        "packet": PACKET,
        "answer": GROUNDED_ANSWER,
        "model_assisted_answer_ran": True,
        "targeted_tests_exit_code": 0,
        "targeted_tests_output": "........ [100%]\n",
        "ask_exit_code": 0,
    }
    kwargs.update(overrides)
    return wama.build_summary(**kwargs)


def test_summary_reports_resolved_selection_fields() -> None:
    selection = {
        "targeted_test_files_resolved": ["tests/test_pr291_alpha.py"],
        "targeted_test_file_count": 1,
        "targeted_pytest_exit_code": 0,
        "targeted_test_selection_error": None,
    }
    summary = _summary(targeted_selection=selection)
    assert summary["targeted_test_files_resolved"] == ["tests/test_pr291_alpha.py"]
    assert summary["targeted_test_file_count"] == 1
    assert summary["targeted_pytest_exit_code"] == 0
    assert summary["targeted_test_selection_error"] is None
    assert summary["targeted_tests_ok"] is True
    assert summary["validation_status"] == "PASS"


def test_unexpanded_wildcard_output_is_classified_as_selection_error() -> None:
    wildcard_output = "ERROR: file or directory not found: tests/test_pr291_*.py\n"
    summary = _summary(targeted_tests_exit_code=4, targeted_tests_output=wildcard_output)
    # The cause is made explicit; targeted_tests_ok stays honest (the tests
    # never ran), and the lane switches to the deterministic resolver.
    assert "wildcard" in summary["targeted_test_selection_error"]
    assert summary["targeted_tests_ok"] is False
    assert summary["validation_status"] == "HOLD"


def test_empty_selection_keeps_acceptance_hold() -> None:
    selection = {
        "targeted_test_files_resolved": [],
        "targeted_test_file_count": 0,
        "targeted_pytest_exit_code": None,
        "targeted_test_selection_error": "no targeted test files resolved",
    }
    summary = _summary(
        targeted_selection=selection,
        targeted_tests_exit_code=None,
        targeted_tests_output="",
    )
    assert summary["targeted_tests_ok"] is False
    assert summary["validation_status"] == "HOLD"


def test_print_targeted_tests_cli_lists_files(capsys) -> None:
    exit_code = wama.main(["--print-targeted-tests", "--tests-dir", str(TESTS_DIR)])
    out = capsys.readouterr().out.strip().splitlines()
    assert exit_code == 0
    assert out == sorted(out)
    names = {Path(line).name for line in out}
    for expected in EXPECTED_FILES:
        assert expected in names


def test_print_targeted_tests_cli_empty_dir_exits_4(tmp_path: Path, capsys) -> None:
    empty = tmp_path / "none"
    empty.mkdir()
    exit_code = wama.main(["--print-targeted-tests", "--tests-dir", str(empty)])
    captured = capsys.readouterr()
    assert exit_code == 4
    assert captured.out.strip() == ""
    assert "targeted_test_selection_error" in captured.err
