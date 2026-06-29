"""PR203 — CLI refactor closure map and remaining-inline guardrail review.

This is a closure/verification step for the CLI command-module split, not a new
extraction. It locks in the closure view exposed by the PR198/PR202 inventory
helper (``scripts/cli_refactor_inventory.py``):

* the ``docs/CLI_REFACTOR_MAP.md`` closure map documents cli.py's intended Typer
  wiring role, the extracted command modules, the intentional inline glue, what
  is *not* allowed inline, and the remaining-candidate / closure status;
* the inventory helper emits a strict JSON/Markdown closure block that
  distinguishes intentional Typer wiring/glue (``@*.callback()``) from
  business-logic command handlers and never claims a false OK when an
  unexpected (unclassified) inline handler appears;
* cli.py still imports and registers the extracted modules and stays within the
  documented inline-handler debt thresholds;
* the PR184 command-surface and PR202 inline-handler guardrails remain present.

The tests run the standalone inventory script as a subprocess (it parses source
with ``ast`` and never imports the ShellForgeAI runtime app). The helper and
these tests perform no Docker/Compose call, no container/production restart, no
cleanup/remediation/rollback/recovery execution, no shell execution, no
arbitrary/natural-language execution, and no model/Codex call. All writes use
``tmp_path``; real ``/data`` and source files are never mutated.
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

# Command modules expected after the PR182–PR201 extraction waves. cli.py must
# import and register each of these rather than owning the handler body inline.
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


def _make_synthetic_repo(tmp_path: Path, cli_source: str) -> Path:
    """Build a minimal repo tree the inventory helper can parse in isolation."""

    repo = tmp_path / "repo"
    cli_dir = repo / "src" / "shellforgeai"
    commands_dir = cli_dir / "commands"
    commands_dir.mkdir(parents=True)
    for module in EXPECTED_COMMAND_MODULES:
        (commands_dir / f"{module}.py").write_text("\n", encoding="utf-8")
    (cli_dir / "cli.py").write_text(cli_source, encoding="utf-8")
    return repo


# --------------------------------------------------------------------------
# 1–6: CLI refactor closure map document
# --------------------------------------------------------------------------


def test_01_cli_refactor_map_doc_exists() -> None:
    assert DOC.exists()
    assert DOC.read_text(encoding="utf-8").startswith("# ShellForgeAI CLI Refactor Map")


def test_02_map_mentions_cli_py_as_typer_wiring() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "`cli.py` role: `typer_wiring`" in text
    assert "Typer app entrypoint and registration glue" in text


def test_03_map_lists_extracted_modules_that_exist() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "## Extracted command modules" in text
    present = {p.stem for p in COMMANDS_DIR.glob("*.py") if p.name != "__init__.py"}
    # Each expected module must be referenced in the map and exist on disk.
    for module in EXPECTED_COMMAND_MODULES:
        assert f"src/shellforgeai/commands/{module}.py" in text, module
        assert module in present, module


def test_04_map_documents_intentional_cli_py_responsibilities() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "## Intentional `cli.py` responsibilities (allowed Typer wiring/glue)" in text
    assert "Typer `app`/group creation" in text
    assert "`<module>_commands.register(...)` registration calls" in text


def test_05_map_documents_what_is_not_allowed_in_cli_py() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "## Not allowed in `cli.py`" in text
    assert "Large command handler bodies" in text
    assert "Docker/Compose mutation or restart logic." in text
    assert "Interactive REPL loop internals." in text


def test_06_map_has_remaining_candidates_and_closure_status_section() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "## CLI refactor closure status" in text
    assert "Closure status: `ok`" in text
    assert "future-extraction candidates" in text
    assert "## Recommended next extraction order" in text


# --------------------------------------------------------------------------
# 7–12: inventory helper output contract
# --------------------------------------------------------------------------


def test_07_json_emits_strict_json() -> None:
    result = _run_script("--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    assert payload["mode"] == "cli_refactor_inventory"


def test_08_json_includes_command_module_list() -> None:
    payload = _json_payload()
    closure = payload["closure"]
    modules = set(closure["command_modules"])
    assert modules >= EXPECTED_COMMAND_MODULES
    assert set(closure["expected_modules"]) == EXPECTED_COMMAND_MODULES
    # The detailed extracted-module rows are also present and point under commands/.
    for row in payload["extracted_modules"]:
        assert row["path"].startswith("src/shellforgeai/commands/")


def test_09_json_includes_remaining_and_unexpected_handler_info() -> None:
    payload = _json_payload()
    closure = payload["closure"]
    assert isinstance(closure["allowed_inline_glue"], list)
    assert isinstance(closure["unexpected_inline_handlers"], list)
    assert isinstance(closure["remaining_command_handlers"], int)
    # Glue (callbacks) and command handlers together account for every inline
    # handler the cli_py block reports.
    total = closure["remaining_command_handlers"] + len(closure["allowed_inline_glue"])
    assert total == payload["cli_py"]["inline_handler_count"]
    # The root callback is intentional Typer wiring/glue.
    assert "main" in closure["allowed_inline_glue"]


def test_10_json_does_not_claim_false_ok_when_unexpected_handler_present(tmp_path: Path) -> None:
    repo = _make_synthetic_repo(
        tmp_path,
        "from __future__ import annotations\n"
        "@mystery_app.command('surprise')\n"
        "def totally_new_handler():\n"
        "    pass\n",
    )
    payload = _json_payload("--repo-root", str(repo))
    closure = payload["closure"]
    assert "totally_new_handler" in closure["unexpected_inline_handlers"]
    # An unexpected inline handler must not be reported as closed/OK.
    assert closure["closure_status"] == "needs_attention"
    assert any("unexpected" in w for w in payload["warnings"])


def test_11_markdown_emits_non_empty_markdown() -> None:
    result = _run_script("--markdown")
    assert result.returncode == 0
    assert result.stdout.startswith("# ShellForgeAI CLI Refactor Map")
    assert "## CLI refactor closure status" in result.stdout
    assert "## Not allowed in `cli.py`" in result.stdout
    assert len(result.stdout.strip()) > 200


def test_12_write_doc_writes_only_explicit_target_and_matches_markdown(tmp_path: Path) -> None:
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
# 13–16: closure guardrail for the live repo
# --------------------------------------------------------------------------


def test_13_no_unexpected_inline_handlers_in_current_repo() -> None:
    payload = _json_payload()
    closure = payload["closure"]
    assert closure["unexpected_inline_handlers"] == []
    assert payload["summary"]["unknown_handlers"] == 0
    assert closure["closure_status"] == "ok"
    assert closure["command_surface_guardrail"] == "present"


def test_14_cli_py_still_imports_and_registers_command_modules() -> None:
    source = CLI_PATH.read_text(encoding="utf-8")
    for module in sorted(EXPECTED_COMMAND_MODULES):
        alias = f"{module}_commands"
        assert f"from shellforgeai.commands import {module} as {alias}" in source, module
        assert f"{alias}.register(" in source, module


def test_15_command_modules_referenced_by_inventory_exist() -> None:
    payload = _json_payload()
    assert payload["closure"]["missing_expected_modules"] == []
    present = {p.stem for p in COMMANDS_DIR.glob("*.py") if p.name != "__init__.py"}
    for module in payload["closure"]["command_modules"]:
        assert module in present, module


def test_16_no_broad_handler_bodies_reintroduced_per_pr202_thresholds() -> None:
    payload = _json_payload()
    cli_py = payload["cli_py"]
    assert cli_py["line_count"] <= cli_py["line_count_threshold"]
    assert cli_py["inline_handler_count"] <= cli_py["inline_handler_threshold"]
    assert cli_py["within_threshold"] is True


def test_16b_enforcement_still_fails_on_reintroduced_broad_handlers(tmp_path: Path) -> None:
    # A regression that dumps many large inline handlers back into cli.py must be
    # caught: status failed and closure status downgraded.
    big_body = "\n".join(f"    x{i} = {i}" for i in range(120))
    blocks = "\n".join(
        f"@app.command('cmd{i}')\ndef handler{i}():\n{big_body}\n" for i in range(200)
    )
    repo = _make_synthetic_repo(tmp_path, "from __future__ import annotations\n" + blocks)
    result = _run_script("--json", "--repo-root", str(repo), check=False)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert payload["closure"]["closure_status"] == "needs_attention"


# --------------------------------------------------------------------------
# 17–20: command-surface and prior-guardrail regression presence
# --------------------------------------------------------------------------


def test_17_pr184_command_surface_golden_present() -> None:
    assert (REPO / "tests" / "test_pr184_cli_command_surface_golden.py").exists()
    assert (REPO / "tests" / "golden" / "cli_command_surface_pr184.json").exists()
    assert (REPO / "tests" / "helpers" / "cli_surface.py").exists()


def test_18_pr202_inline_handler_guardrail_present() -> None:
    assert (REPO / "tests" / "test_pr202_cli_refactor_inventory_enforcement.py").exists()


def test_19_pr198_inventory_tests_present() -> None:
    assert (REPO / "tests" / "test_pr198_cli_refactor_inventory.py").exists()


def test_20_recent_module_split_tests_present() -> None:
    base = REPO / "tests"
    for name in (
        "test_pr182_cli_module_scaffold_status_doctor.py",
        "test_pr183_cli_module_split_ops_triage.py",
        "test_pr199_cli_module_split_remediation.py",
        "test_pr200_cli_module_split_interactive.py",
    ):
        assert (base / name).exists(), name


# --------------------------------------------------------------------------
# 21–30: the inventory helper itself stays strictly read-only / non-executing
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


def test_21_to_24_helper_does_not_execute_cleanup_remediation_rollback_recovery() -> None:
    # No runtime/product import means no cleanup/remediation/rollback/recovery
    # execution path can be reached from the inventory helper.
    imported = _imported_top_level()
    for forbidden in ("shellforgeai", "subprocess", "pytest", "ruff"):
        assert forbidden not in imported, forbidden
    payload = _json_payload()
    safety = payload["safety"]
    for key in (
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
    ):
        assert safety[key] is False, key


def test_25_helper_does_not_call_docker_or_compose() -> None:
    imported = _imported_top_level()
    assert "docker" not in imported
    assert "compose" not in imported
    payload = _json_payload()
    assert payload["safety"]["docker_compose_executed"] is False


def test_26_helper_does_not_restart_containers() -> None:
    payload = _json_payload()
    assert payload["safety"]["container_restarted"] is False
    assert "subprocess" not in _imported_top_level()


def test_27_helper_does_not_call_model_or_codex() -> None:
    imported = _imported_top_level()
    for forbidden in ("openai", "anthropic", "codex", "litellm"):
        assert forbidden not in imported
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "build_provider" not in source
    assert _json_payload()["safety"]["model_called"] is False


def test_28_helper_does_not_use_shell_true() -> None:
    assert "shell=True" not in SCRIPT.read_text(encoding="utf-8")


def test_29_helper_has_no_command_or_nl_execution_primitives() -> None:
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
    safety = _json_payload()["safety"]
    assert safety["arbitrary_command_execution"] is False
    assert safety["natural_language_execution"] is False


def test_30_helper_does_not_mutate_source_files_or_repair_delete_artifacts() -> None:
    before = _hash_tree([CLI_PATH, COMMANDS_DIR])
    _run_script()
    _json_payload()
    assert _run_script("--markdown").returncode == 0
    after = _hash_tree([CLI_PATH, COMMANDS_DIR])
    assert after == before
    safety = _json_payload()["safety"]
    assert safety["artifact_repaired"] is False
    assert safety["artifact_deleted"] is False
