"""PR198 — CLI refactor inventory and remaining-handler extraction map.

The inventory helper is process/documentation tooling only. These tests avoid
running ShellForgeAI runtime commands and instead execute the standalone script,
which parses source files without importing the Typer app.
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

KNOWN_EXTRACTED = {
    "status",
    "doctor",
    "ops",
    "triage",
    "verify",
    "handoff",
    "propose",
    "apply-preview",
    "ask",
    "recipes/preflight",
    "receipt audit",
    "receipt safety",
    "receipt recovery readonly",
    "receipt recovery execute",
    "v1",
    "model",
    "interactive",
    "windows doctor",
    "windows status",
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
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
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


def test_script_exists_and_help_exits_zero() -> None:
    assert SCRIPT.exists()
    result = _run_script("--help")
    assert result.returncode == 0
    assert "Inventory ShellForgeAI CLI refactor status" in result.stdout


def test_default_human_output_exits_zero() -> None:
    result = _run_script()
    assert result.returncode == 0
    assert "ShellForgeAI CLI refactor inventory" in result.stdout
    assert "Extracted command modules" in result.stdout
    assert "Remaining inline handlers in cli.py" in result.stdout


def test_json_mode_emits_strict_contract_and_safety_block() -> None:
    payload = _json_payload()
    assert payload["schema_version"] == 1
    assert payload["mode"] == "cli_refactor_inventory"
    assert payload["status"] == "ok"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["source"] == {
        "cli_path": "src/shellforgeai/cli.py",
        "commands_dir": "src/shellforgeai/commands",
    }
    assert isinstance(payload["extracted_modules"], list)
    assert isinstance(payload["remaining_inline_handlers"], list)
    assert isinstance(payload["recommended_next_extractions"], list)
    safety = payload["safety"]
    assert safety["read_only"] is True
    assert safety["mutation_performed"] is False
    assert safety["validation_executed"] is False
    assert safety["pytest_executed"] is False
    assert safety["ruff_executed"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["model_called"] is False


def test_extracted_modules_include_pr182_through_pr197_known_modules() -> None:
    payload = _json_payload()
    names = {row["name"] for row in payload["extracted_modules"]}
    assert names >= KNOWN_EXTRACTED
    for row in payload["extracted_modules"]:
        assert row["path"].startswith("src/shellforgeai/commands/")
        assert row["category"] in {
            "read_only",
            "artifact_only",
            "preview_only",
            "confirm_gated_mutation",
            "unknown",
        }


def test_remaining_handlers_are_listed_with_conservative_categories() -> None:
    payload = _json_payload()
    handlers = payload["remaining_inline_handlers"]
    assert handlers
    by_function = {row["function"]: row for row in handlers}
    # ``interactive`` was extracted to commands/interactive.py in PR200, so it is
    # no longer an inline handler; the root callback's interactive fallback stays.
    assert "interactive" not in by_function
    assert by_function["main"]["category"] == "read_only"
    assert by_function["apply"]["risk"] == "high"
    assert by_function["recipes_execute"]["category"] == "confirm_gated_mutation"
    assert by_function["remediation_rollback_execute"]["recommended_validation_lane"] == "Lane C"


def test_unknown_unclassified_handlers_warn_instead_of_claiming_certainty(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cli_dir = repo / "src" / "shellforgeai"
    commands_dir = cli_dir / "commands"
    commands_dir.mkdir(parents=True)
    for module in [
        "apply_preview.py",
        "ask.py",
        "doctor.py",
        "handoff.py",
        "interactive.py",
        "model.py",
        "ops.py",
        "platform.py",
        "propose.py",
        "receipt_audit.py",
        "receipt_recovery_execute.py",
        "receipt_recovery_readonly.py",
        "receipt_safety.py",
        "recipes.py",
        "remediation.py",
        "status.py",
        "triage.py",
        "v1.py",
        "verify.py",
        "windows.py",
    ]:
        (commands_dir / module).write_text("\n", encoding="utf-8")
    (cli_dir / "cli.py").write_text(
        "from __future__ import annotations\n"
        "@mystery_app.command('surprise')\n"
        "def totally_new_handler():\n"
        "    pass\n",
        encoding="utf-8",
    )

    payload = _json_payload("--repo-root", str(repo))
    assert payload["summary"]["unknown_handlers"] == 1
    assert payload["remaining_inline_handlers"][0]["category"] == "unknown"
    assert "unclassified inline handler" in payload["warnings"][0]


def test_script_does_not_import_docker_compose_or_validation_runners() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "docker" not in imported
    assert "compose" not in imported
    assert "pytest" not in imported
    assert "ruff" not in imported
    assert "subprocess" not in imported
    assert "shellforgeai" not in imported


def test_script_has_no_command_execution_primitives_or_shell_true() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "shell=True" not in source
    tree = ast.parse(source)
    forbidden_calls = {
        "eval",
        "exec",
        "system",
        "popen",
        "run",
        "call",
        "check_call",
        "check_output",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = ""
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            assert name not in forbidden_calls


def test_script_does_not_mutate_runtime_source_files() -> None:
    before = _hash_tree([CLI_PATH, COMMANDS_DIR])
    _run_script()
    _json_payload()
    result = _run_script("--markdown")
    assert result.returncode == 0
    after = _hash_tree([CLI_PATH, COMMANDS_DIR])
    assert after == before


def test_markdown_mode_exits_zero_and_includes_title_and_safety_summary() -> None:
    result = _run_script("--markdown")
    assert result.returncode == 0
    assert result.stdout.startswith("# ShellForgeAI CLI Refactor Map")
    assert "## Safety summary" in result.stdout
    assert "No Docker/Compose operation or mutation" in result.stdout


def test_docs_cli_refactor_map_exists_and_records_guardrails() -> None:
    assert DOC.exists()
    text = DOC.read_text(encoding="utf-8")
    assert "# ShellForgeAI CLI Refactor Map" in text
    assert "PR184 golden command-surface guardrail" in text
    assert "Lane C / full validation for safety-sensitive or broad command-surface moves" in text
    assert "Mutation-capable governed execution handlers move last" in text


def test_inventory_safety_contract_for_no_execution_or_artifact_repair_delete() -> None:
    payload = _json_payload()
    safety = payload["safety"]
    for key in (
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
        assert safety[key] is False
