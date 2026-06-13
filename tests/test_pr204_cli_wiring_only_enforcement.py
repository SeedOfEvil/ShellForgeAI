"""PR204 — CLI wiring-only enforcement guardrail.

This closes the CLI command-module split by making ``src/shellforgeai/cli.py``
explicitly wiring-only: Typer app/group creation, command-module registration,
shared app metadata, and a tiny, reasoned allowlist of intentional root/bootstrap
callables. The enforcement lives in ``scripts/cli_refactor_inventory.py --check``.

The check sorts every inline Typer callable in ``cli.py`` into exactly one of
three buckets: explicitly allowlisted wiring/bootstrap, documented
remaining-extraction candidates (classified debt, tracked not silently allowed),
and unapproved inline handlers (unclassified handlers or non-allowlisted
callbacks). An unapproved handler fails the check.

These tests run the standalone inventory script as a subprocess (it parses source
with ``ast`` and never imports the ShellForgeAI runtime app) and, for pure data
rules, import the helper module directly (it has no import-time side effects).
The check and these tests perform no Docker/Compose call, no container/production
restart, no cleanup/remediation/rollback/recovery execution, no shell execution,
no arbitrary/natural-language execution, and no model/Codex call. All writes use
``tmp_path``; real ``/data`` and source files are never mutated.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "cli_refactor_inventory.py"
DOC = REPO / "docs" / "CLI_REFACTOR_MAP.md"
CLI_PATH = REPO / "src" / "shellforgeai" / "cli.py"
COMMANDS_DIR = REPO / "src" / "shellforgeai" / "commands"

EXPECTED_COMMAND_MODULES = {
    "apply_preview",
    "ask",
    "doctor",
    "handoff",
    "interactive",
    "model",
    "ops",
    "propose",
    "receipt_audit",
    "receipt_recovery_execute",
    "receipt_recovery_readonly",
    "receipt_safety",
    "recipes",
    "remediation",
    "status",
    "triage",
    "v1",
    "verify",
}


def _run_script(
    *args: str, cwd: Path = REPO, check: bool = False
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(  # noqa: S603 - test executes the local inventory script only.
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"inventory script failed with {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result


def _check_json(*args: str, cwd: Path = REPO) -> tuple[dict[str, Any], int]:
    result = _run_script("--check", "--json", *args, cwd=cwd)
    payload = json.loads(result.stdout)
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    return payload, result.returncode


def _load_helper_module() -> Any:
    spec = importlib.util.spec_from_file_location("cli_refactor_inventory_pr204", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Register before exec so dataclass decorators can resolve the module namespace.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _hash_tree(paths: list[Path]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in paths:
        if path.is_dir():
            candidates = sorted(p for p in path.rglob("*.py") if "__pycache__" not in p.parts)
        else:
            candidates = [path]
        for candidate in candidates:
            rel = candidate.relative_to(REPO).as_posix()
            hashes[rel] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return hashes


def _make_synthetic_repo(tmp_path: Path, cli_source: str, *, with_modules: bool = True) -> Path:
    repo = tmp_path / "repo"
    cli_dir = repo / "src" / "shellforgeai"
    commands_dir = cli_dir / "commands"
    commands_dir.mkdir(parents=True)
    if with_modules:
        for module in EXPECTED_COMMAND_MODULES:
            (commands_dir / f"{module}.py").write_text("\n", encoding="utf-8")
    (cli_dir / "cli.py").write_text(cli_source, encoding="utf-8")
    return repo


# --------------------------------------------------------------------------
# 1–9: --check passes on the current tree and emits the strict contract
# --------------------------------------------------------------------------


def test_01_check_exits_zero_on_current_tree() -> None:
    result = _run_script("--check")
    assert result.returncode == 0, result.stdout + result.stderr


def test_02_check_json_emits_strict_json() -> None:
    result = _run_script("--check", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    assert payload["schema_version"] == 1
    assert payload["mode"] == "cli_refactor_inventory_check"


def test_03_check_json_status_passed() -> None:
    payload, code = _check_json()
    assert code == 0
    assert payload["status"] == "passed"


def test_04_check_json_is_read_only_and_non_mutating() -> None:
    payload, _ = _check_json()
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False


def test_05_check_json_includes_allowlist_with_reasons() -> None:
    payload, _ = _check_json()
    allowlist = payload["allowlist"]
    assert isinstance(allowlist, list) and allowlist
    for entry in allowlist:
        assert isinstance(entry["name"], str) and entry["name"].strip()
        assert isinstance(entry["reason"], str) and entry["reason"].strip()
    names = {entry["name"] for entry in allowlist}
    # The intentional root/bootstrap callables are present and reasoned.
    assert {"main", "version_cmd"} <= names


def test_06_check_json_allowlist_is_small() -> None:
    payload, _ = _check_json()
    # The allowlist is the closure boundary; it must stay tiny and reasoned.
    assert len(payload["allowlist"]) <= 6
    assert payload["allowlist_errors"] == []


def test_07_check_json_includes_unapproved_inline_handlers_list_empty() -> None:
    payload, _ = _check_json()
    assert isinstance(payload["unapproved_inline_handlers"], list)
    assert payload["unapproved_inline_handlers"] == []
    assert payload["summary"]["unapproved_inline_count"] == 0


def test_08_check_human_output_describes_wiring_only_role() -> None:
    result = _run_script("--check")
    assert result.returncode == 0
    text = result.stdout
    assert "CLI refactor inventory check: passed" in text
    assert "cli.py role:" in text
    assert "Typer app wiring" in text
    assert "command module registration" in text
    assert "No unapproved inline command handlers found." in text


def test_09_check_first_safe_command_is_non_mutating() -> None:
    payload, _ = _check_json()
    first = payload["first_safe_command"]
    assert "--check" not in first or "--json" in first  # advisory, never a mutation flag
    assert "--write-doc" not in first
    assert first.startswith("python scripts/cli_refactor_inventory.py")
    # The advertised next-safe command is a read-only render mode.
    assert "--markdown" in first


def test_09b_check_reports_tracked_remaining_extraction_candidates() -> None:
    # cli.py is not yet literally wiring-only: classified handlers remain. They are
    # reported as the tracked extraction map, NOT silently folded into the allowlist.
    payload, _ = _check_json()
    candidates = payload["remaining_extraction_candidates"]
    assert isinstance(candidates, list)
    allow_names = {entry["name"] for entry in payload["allowlist"]}
    assert not (set(candidates) & allow_names)
    if candidates:
        assert payload["cli_py_role"] == "wiring_with_tracked_remaining"
    else:
        assert payload["cli_py_role"] == "wiring_only"


# --------------------------------------------------------------------------
# 10–14: failure-mode behavior with synthetic repos
# --------------------------------------------------------------------------


def test_10_fake_cli_with_unapproved_inline_command_fails(tmp_path: Path) -> None:
    repo = _make_synthetic_repo(
        tmp_path,
        "from __future__ import annotations\n"
        "@app.command('surprise')\n"
        "def totally_new_handler():\n"
        "    pass\n",
    )
    payload, code = _check_json("--repo-root", str(repo))
    assert payload["status"] == "failed"
    assert code == 1
    assert "totally_new_handler" in payload["unapproved_inline_handlers"]


def test_11_failed_check_returns_nonzero(tmp_path: Path) -> None:
    repo = _make_synthetic_repo(
        tmp_path,
        "from __future__ import annotations\n"
        "@app.command('surprise')\n"
        "def evil_handler():\n"
        "    pass\n",
    )
    result = _run_script("--check", "--repo-root", str(repo))
    assert result.returncode == 1


def test_12_failed_check_reports_handler_name(tmp_path: Path) -> None:
    repo = _make_synthetic_repo(
        tmp_path,
        "from __future__ import annotations\n"
        "@app.command('surprise')\n"
        "def sneaky_inline_handler():\n"
        "    pass\n",
    )
    result = _run_script("--check", "--repo-root", str(repo))
    assert result.returncode == 1
    assert "Unapproved inline handlers:" in result.stdout
    assert "sneaky_inline_handler" in result.stdout
    assert "src/shellforgeai/commands/" in result.stdout


def test_13_fake_cli_with_only_allowed_version_and_bootstrap_passes(tmp_path: Path) -> None:
    repo = _make_synthetic_repo(
        tmp_path,
        "from __future__ import annotations\n"
        "@app.callback(invoke_without_command=True)\n"
        "def main():\n"
        "    pass\n"
        "@app.command('version')\n"
        "def version_cmd():\n"
        "    pass\n",
    )
    payload, code = _check_json("--repo-root", str(repo))
    assert payload["status"] == "passed"
    assert code == 0
    assert payload["unapproved_inline_handlers"] == []
    # With nothing but allowlisted wiring/bootstrap, cli.py is literally wiring-only.
    assert payload["remaining_extraction_candidates"] == []
    assert payload["cli_py_role"] == "wiring_only"


def test_14_allowlist_entry_without_reason_is_rejected() -> None:
    module = _load_helper_module()
    # A well-formed allowlist yields no errors.
    assert module.validate_allowlist([{"name": "main", "reason": "bootstrap"}]) == []
    # An entry missing a reason is rejected rather than silently honored.
    missing_reason = module.validate_allowlist([{"name": "main"}])
    assert missing_reason
    assert any("reason" in err for err in missing_reason)
    # An entry with an empty reason is likewise rejected.
    empty_reason = module.validate_allowlist([{"name": "main", "reason": "   "}])
    assert empty_reason
    # The shipped allowlist itself is well-formed.
    assert module.validate_allowlist(module.INLINE_ALLOWLIST) == []


def test_14b_check_fails_when_allowlist_is_malformed() -> None:
    module = _load_helper_module()
    payload = module.build_check(REPO, allowlist=[{"name": "main"}])
    assert payload["status"] == "failed"
    assert payload["allowlist_errors"]
    assert payload["cli_py_role"] == "needs_attention"


# --------------------------------------------------------------------------
# 15–20: the check itself stays strictly read-only / non-executing
# --------------------------------------------------------------------------


def _script_tree() -> ast.AST:
    return ast.parse(SCRIPT.read_text(encoding="utf-8"))


def _imported_top_level() -> set[str]:
    imported: set[str] = set()
    for node in ast.walk(_script_tree()):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    return imported


def test_15_check_does_not_modify_files() -> None:
    before = _hash_tree([CLI_PATH, COMMANDS_DIR, SCRIPT])
    assert _run_script("--check").returncode == 0
    assert _run_script("--check", "--json").returncode == 0
    after = _hash_tree([CLI_PATH, COMMANDS_DIR, SCRIPT])
    assert after == before
    payload, _ = _check_json()
    assert payload["safety"]["artifact_repaired"] is False
    assert payload["safety"]["artifact_deleted"] is False


def test_16_check_does_not_call_docker_or_compose() -> None:
    imported = _imported_top_level()
    assert "docker" not in imported
    assert "compose" not in imported
    payload, _ = _check_json()
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["container_restarted"] is False


def test_17_check_does_not_run_pytest_or_validation() -> None:
    imported = _imported_top_level()
    for forbidden in ("pytest", "ruff", "subprocess", "shellforgeai"):
        assert forbidden not in imported, forbidden
    payload, _ = _check_json()
    assert payload["safety"]["pytest_executed"] is False
    assert payload["safety"]["validation_executed"] is False


def test_18_check_does_not_call_model_or_codex() -> None:
    imported = _imported_top_level()
    for forbidden in ("openai", "anthropic", "codex", "litellm"):
        assert forbidden not in imported
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "build_provider" not in source
    payload, _ = _check_json()
    assert payload["safety"]["model_called"] is False


def test_19_check_does_not_use_shell_true() -> None:
    assert "shell=True" not in SCRIPT.read_text(encoding="utf-8")
    payload, _ = _check_json()
    assert payload["safety"]["shell_true"] is False


def test_20_check_has_no_command_or_artifact_mutation_primitives() -> None:
    forbidden_calls = {
        "eval",
        "exec",
        "system",
        "popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "spawn",
    }
    for node in ast.walk(_script_tree()):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            assert name not in forbidden_calls, name
    payload, _ = _check_json()
    safety = payload["safety"]
    for key in (
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "arbitrary_command_execution",
        "natural_language_execution",
        "artifact_repaired",
        "artifact_deleted",
    ):
        assert safety[key] is False, key


# --------------------------------------------------------------------------
# 21–25: regression — prior guardrails still present and green
# --------------------------------------------------------------------------


def test_21_pr198_inventory_tests_present() -> None:
    assert (REPO / "tests" / "test_pr198_cli_refactor_inventory.py").exists()


def test_22_pr202_inventory_enforcement_tests_present() -> None:
    assert (REPO / "tests" / "test_pr202_cli_refactor_inventory_enforcement.py").exists()


def test_23_pr203_closure_tests_present() -> None:
    assert (REPO / "tests" / "test_pr203_cli_refactor_closure.py").exists()


def test_24_pr184_command_surface_golden_present() -> None:
    assert (REPO / "tests" / "test_pr184_cli_command_surface_golden.py").exists()
    assert (REPO / "tests" / "golden" / "cli_command_surface_pr184.json").exists()
    assert (REPO / "tests" / "helpers" / "cli_surface.py").exists()


def test_25_representative_module_split_tests_present() -> None:
    base = REPO / "tests"
    for name in (
        "test_pr182_cli_module_scaffold_status_doctor.py",
        "test_pr199_cli_module_split_remediation.py",
        "test_pr200_cli_module_split_interactive.py",
    ):
        assert (base / name).exists(), name


# --------------------------------------------------------------------------
# 26–28: docs document the wiring-only closure and how to run the check
# --------------------------------------------------------------------------


def test_26_doc_documents_wiring_only_enforcement() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "## CLI wiring-only enforcement (`--check`)" in text
    assert "python scripts/cli_refactor_inventory.py --check" in text
    assert "wiring-only" in text


def test_27_doc_documents_allowlist_must_have_reasons() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "### Allowlist (intentional remaining inline callables)" in text
    assert "with a reason" in text
    # Allowlisted symbols are surfaced in the doc.
    assert "`main`" in text
    assert "`version_cmd`" in text


def test_28_doc_says_new_handlers_belong_in_command_modules() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "new command handlers belong in a command module" in text
    assert "PR184 golden command-surface guardrail remains required" in text
