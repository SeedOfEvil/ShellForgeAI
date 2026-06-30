"""PR202 — CLI refactor inventory enforcement guardrail.

This is process/test tooling, not a product command. It turns the PR198 CLI
refactor inventory (``scripts/cli_refactor_inventory.py``) into a regression
guardrail so future command-module work cannot silently reintroduce large
inline command handlers into ``src/shellforgeai/cli.py``.

The tests run the standalone inventory script as a subprocess (it parses source
with ``ast`` and never imports the ShellForgeAI runtime app) and assert:

* the JSON/Markdown/``--write-doc`` contract is stable and parseable,
* the command modules extracted in PR182–PR201 are represented,
* ``cli.py`` stays at/below the documented inline-handler debt threshold,
* remaining inline handlers are explicitly inventoried,
* the inventory helper itself stays strictly read-only and non-mutating.

The guardrail performs no Docker/Compose call, no container/production restart,
no cleanup/remediation/rollback/recovery execution, no shell execution, no
arbitrary/natural-language execution, and no model/Codex call. It uses
``tmp_path`` for any write and never mutates real ``/data`` or source files.
"""

from __future__ import annotations

import ast
import hashlib
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
COMMANDS_INIT = COMMANDS_DIR / "__init__.py"

# Command modules expected to exist after the PR182–PR201 extraction waves. Each
# entry is a module file under ``src/shellforgeai/commands/`` that cli.py imports
# and registers rather than owning the handler body inline.
EXPECTED_COMMAND_MODULES = {
    "apply_preview",
    "ask",
    "doctor",
    "handoff",
    "interactive",
    "model",
    "ops",
    "platform",
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
    "windows",
}


def _run_script(
    *args: str, cwd: Path = REPO, check: bool = True
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


def _json_payload(*args: str, cwd: Path = REPO, check: bool = True) -> dict[str, Any]:
    result = _run_script("--json", *args, cwd=cwd, check=check)
    payload = json.loads(result.stdout)
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    return payload


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


# --------------------------------------------------------------------------
# 1–8: inventory output contract
# --------------------------------------------------------------------------


def test_01_json_mode_emits_strict_json() -> None:
    result = _run_script("--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    # Strict JSON only: nothing but the object on stdout.
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")


def test_02_json_mode_is_cli_refactor_inventory() -> None:
    payload = _json_payload()
    assert payload["schema_version"] == 1
    assert payload["mode"] == "cli_refactor_inventory"
    assert payload["status"] == "ok"


def test_03_json_includes_cli_py_summary() -> None:
    payload = _json_payload()
    cli_py = payload["cli_py"]
    assert cli_py["path"] == "src/shellforgeai/cli.py"
    assert isinstance(cli_py["line_count"], int) and cli_py["line_count"] > 0
    assert isinstance(cli_py["inline_handler_count"], int) and cli_py["inline_handler_count"] > 0
    assert isinstance(cli_py["line_count_threshold"], int)
    assert isinstance(cli_py["inline_handler_threshold"], int)
    assert cli_py["allowed_inline_wiring"] is True
    assert isinstance(cli_py["remaining_inline_handler_functions"], list)
    # Summary mirrors the cli_py block for convenience.
    assert payload["summary"]["cli_line_count"] == cli_py["line_count"]
    assert payload["summary"]["cli_inline_handler_count"] == cli_py["inline_handler_count"]


def test_04_json_includes_command_module_list() -> None:
    payload = _json_payload()
    modules = payload["extracted_modules"]
    assert isinstance(modules, list) and modules
    for row in modules:
        assert set(row) >= {"name", "path", "category", "known_pr"}
        assert row["path"].startswith("src/shellforgeai/commands/")


def test_05_json_includes_extracted_handlers_equivalent() -> None:
    payload = _json_payload()
    names = {row["name"] for row in payload["extracted_modules"]}
    # Representative extracted handlers from PR182–PR201 are present by name.
    assert {"status", "doctor", "ops", "triage", "verify", "ask", "v1", "model"} <= names


def test_06_json_includes_remaining_handlers_debt_list() -> None:
    payload = _json_payload()
    remaining = payload["remaining_inline_handlers"]
    assert isinstance(remaining, list) and remaining
    for row in remaining:
        assert set(row) >= {"name", "function", "line", "category", "risk"}
    # The cli_py block also lists the raw remaining handler functions.
    funcs = payload["cli_py"]["remaining_inline_handler_functions"]
    assert len(funcs) == len(remaining)


def test_07_json_safety_block_is_read_only_and_non_mutating() -> None:
    payload = _json_payload()
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    safety = payload["safety"]
    for key in (
        "read_only",
        "mutation_performed",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "docker_compose_executed",
        "container_restarted",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
        "artifact_repaired",
        "artifact_deleted",
    ):
        expected = key == "read_only"
        assert safety[key] is expected, key


def test_08_markdown_emits_non_empty_markdown() -> None:
    result = _run_script("--markdown")
    assert result.returncode == 0
    assert result.stdout.startswith("# ShellForgeAI CLI Refactor Map")
    assert "## cli.py inline-handler debt" in result.stdout
    assert "## Safety summary" in result.stdout
    assert len(result.stdout.strip()) > 200


def test_09_write_doc_writes_only_explicit_target_and_matches_markdown(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "MAP.md"
    markdown = _run_script("--markdown").stdout
    result = _run_script("--write-doc", str(target))
    assert result.returncode == 0
    assert target.exists()
    assert target.read_text(encoding="utf-8") == markdown
    # No hidden/default artifacts: only the explicit target (and its parents) exist.
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert written == [target]


# --------------------------------------------------------------------------
# 10–14: extracted module coverage and inline-handler debt enforcement
# --------------------------------------------------------------------------


def test_10_expected_command_modules_from_pr182_through_pr201_exist() -> None:
    present = {p.stem for p in COMMANDS_DIR.glob("*.py") if p.name != "__init__.py"}
    missing = EXPECTED_COMMAND_MODULES - present
    assert not missing, f"missing extracted command modules: {sorted(missing)}"


def test_11_commands_package_all_entries_map_to_existing_modules() -> None:
    # Parse __all__ from the package init without importing the runtime app.
    tree = ast.parse(COMMANDS_INIT.read_text(encoding="utf-8"))
    exported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if "__all__" in targets and isinstance(node.value, (ast.List, ast.Tuple)):
                exported = [el.value for el in node.value.elts if isinstance(el, ast.Constant)]
    assert exported, "commands/__init__.py must declare __all__"
    present = {p.stem for p in COMMANDS_DIR.glob("*.py") if p.name != "__init__.py"}
    for name in exported:
        assert name in present, f"__all__ exports missing module: {name}"


def test_12_cli_py_imports_and_registers_extracted_modules_rather_than_owning_them() -> None:
    source = CLI_PATH.read_text(encoding="utf-8")
    for module in sorted(EXPECTED_COMMAND_MODULES):
        alias = f"{module}_commands"
        assert f"from shellforgeai.commands import {module} as {alias}" in source, (
            f"cli.py must import extracted module {module}"
        )
        assert f"{alias}.register(" in source, f"cli.py must register extracted module {module}"


def test_13_cli_py_line_count_within_documented_threshold() -> None:
    payload = _json_payload()
    cli_py = payload["cli_py"]
    assert cli_py["line_count"] <= cli_py["line_count_threshold"]
    assert cli_py["line_count_within_threshold"] is True
    assert cli_py["inline_handler_count"] <= cli_py["inline_handler_threshold"]
    assert cli_py["inline_handler_within_threshold"] is True
    assert cli_py["within_threshold"] is True
    assert payload["summary"]["cli_within_threshold"] is True


def test_14_remaining_inline_handlers_are_explicitly_listed() -> None:
    payload = _json_payload()
    remaining = payload["remaining_inline_handlers"]
    # Each remaining inline handler is explicitly classified (no silent debt) and
    # carries a category/risk/validation lane so future extraction is deliberate.
    assert payload["summary"]["remaining_inline_handlers"] == len(remaining)
    for row in remaining:
        assert row["category"] in {
            "read_only",
            "artifact_only",
            "preview_only",
            "confirm_gated_mutation",
            "unknown",
        }
        assert row["risk"] in {"low", "medium", "high"}
        assert "recommended_validation_lane" in row
    # No unknown/unclassified handlers in the live tree.
    assert payload["summary"]["unknown_handlers"] == 0


def test_15_enforcement_fails_clearly_when_thresholds_exceeded(tmp_path: Path) -> None:
    # Build a synthetic repo whose cli.py reintroduces a huge inline handler and
    # too many inline @app.command handlers; the inventory must report failure.
    repo = tmp_path / "repo"
    cli_dir = repo / "src" / "shellforgeai"
    commands_dir = cli_dir / "commands"
    commands_dir.mkdir(parents=True)
    for module in EXPECTED_COMMAND_MODULES:
        (commands_dir / f"{module}.py").write_text("\n", encoding="utf-8")

    # 200 inline handlers, each with a large body, far past both thresholds.
    big_body = "\n".join(f"    x{i} = {i}" for i in range(120))
    blocks = []
    for i in range(200):
        blocks.append(f"@app.command('cmd{i}')\ndef handler{i}():\n{big_body}\n")
    (cli_dir / "cli.py").write_text(
        "from __future__ import annotations\n" + "\n".join(blocks), encoding="utf-8"
    )

    result = _run_script("--json", "--repo-root", str(repo), check=False)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert payload["cli_py"]["within_threshold"] is False
    assert payload["cli_py"]["line_count_within_threshold"] is False
    assert payload["cli_py"]["inline_handler_within_threshold"] is False
    assert any("exceeds documented threshold" in w for w in payload["warnings"])


# --------------------------------------------------------------------------
# 16–18: regression guardrails (prior guardrail/test presence)
# --------------------------------------------------------------------------


def test_16_pr198_inventory_test_present() -> None:
    assert (REPO / "tests" / "test_pr198_cli_refactor_inventory.py").exists()


def test_17_pr184_command_surface_golden_present() -> None:
    assert (REPO / "tests" / "test_pr184_cli_command_surface_golden.py").exists()
    assert (REPO / "tests" / "golden" / "cli_command_surface_pr184.json").exists()
    assert (REPO / "tests" / "helpers" / "cli_surface.py").exists()


def test_18_prior_module_split_and_refusal_tests_present() -> None:
    base = REPO / "tests"
    for name in (
        "test_pr182_cli_module_scaffold_status_doctor.py",
        "test_pr183_cli_module_split_ops_triage.py",
    ):
        assert (base / name).exists(), name


# --------------------------------------------------------------------------
# 19–29: the inventory helper itself stays strictly read-only / non-executing
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


def test_19_to_22_helper_does_not_import_execution_runtime() -> None:
    imported = _imported_top_level()
    # No runtime/product import means no cleanup/remediation/rollback/recovery
    # execution path can be reached from the inventory helper.
    for forbidden in ("shellforgeai", "subprocess", "pytest", "ruff"):
        assert forbidden not in imported, forbidden


def test_23_helper_does_not_import_docker_or_compose() -> None:
    imported = _imported_top_level()
    assert "docker" not in imported
    assert "compose" not in imported


def test_24_helper_does_not_restart_containers() -> None:
    # The helper classifies restart-shaped handlers by descriptive name, but it
    # has no way to *execute* a restart: no subprocess/exec primitive exists and
    # the JSON safety contract reports container_restarted as false.
    imported = _imported_top_level()
    assert "subprocess" not in imported
    payload = _json_payload()
    assert payload["safety"]["container_restarted"] is False
    assert payload["safety"]["docker_compose_executed"] is False


def test_25_helper_does_not_use_shell_true() -> None:
    assert "shell=True" not in SCRIPT.read_text(encoding="utf-8")


def test_26_27_helper_has_no_command_or_nl_execution_primitives() -> None:
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


def test_28_helper_does_not_call_model_or_codex() -> None:
    imported = _imported_top_level()
    for forbidden in ("openai", "anthropic", "codex", "litellm"):
        assert forbidden not in imported
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "build_provider" not in source


def test_29_helper_does_not_mutate_source_files() -> None:
    before = _hash_tree([CLI_PATH, COMMANDS_DIR])
    _run_script()
    _json_payload()
    assert _run_script("--markdown").returncode == 0
    after = _hash_tree([CLI_PATH, COMMANDS_DIR])
    assert after == before
