"""PR188 governed receipt audit/report command-module extraction guardrails.

These tests prove the read-only/artifact-only ``recipes receipt`` audit,
audit-bundle, audit-bundle-validate, integrity, and explain handlers are wired
from ``shellforgeai.commands.receipt_audit`` while preserving command surfaces,
strict JSON behavior, bounded owned artifacts, and no-execution safety fields.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core.recipe_execution import RECEIPT_MODE, SCHEMA_VERSION

runner = CliRunner()

MODULE_PATH = Path("src/shellforgeai/commands/receipt_audit.py")
CLI_PATH = Path("src/shellforgeai/cli.py")
PROHIBITED_SAFE_COMMAND_TOKENS = (
    " docker restart ",
    " compose ",
    " cleanup",
    " recovery-execute",
    " rollback-execute",
    " repair",
    " delete",
    " sh -c",
    " bash -c",
)
SAFETY_FALSE_FLAGS = (
    "mutation_performed",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "docker_compose_executed",
    "container_restarted",
    "production_restart_executed",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "model_called",
)


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _receipt(
    data_dir: Path,
    receipt_id: str,
    *,
    target: str = "sfai-pr188-one",
    recipe_id: str = "docker.disposable_restart",
) -> Path:
    receipt_dir = data_dir / "recipe_receipts" / receipt_id
    receipt_dir.mkdir(parents=True)
    safety = {
        "read_only": False,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "production_restart_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
        "artifact_repaired": False,
        "artifact_deleted": False,
        "exact_target_only": True,
    }
    payload = {
        "schema_version": SCHEMA_VERSION,
        "mode": RECEIPT_MODE,
        "receipt_id": receipt_id,
        "recipe_id": recipe_id,
        "target": target,
        "status": "executed",
        "created_at": "2026-06-09T00:00:00Z",
        "verification": {"status": "passed"},
        "safety": safety,
    }
    _write_json(receipt_dir / "recipe-receipt.json", payload)
    (receipt_dir / "recipe-receipt.md").write_text(f"# {receipt_id}\n", encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "v2_recipe_execution_receipt",
        "recipe_id": recipe_id,
        "target": target,
        "files": ["recipe-receipt.json", "recipe-receipt.md", "manifest.json"],
        "checksums": {
            "recipe-receipt.json": _sha(receipt_dir / "recipe-receipt.json"),
            "recipe-receipt.md": _sha(receipt_dir / "recipe-receipt.md"),
        },
        "safety": safety,
    }
    _write_json(receipt_dir / "manifest.json", manifest)
    return receipt_dir


def _invoke_json(monkeypatch, tmp_path: Path, args: list[str], *, expect_code: int = 0) -> dict:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, args)
    assert result.exit_code == expect_code, result.output
    assert result.stdout.strip().startswith("{") and result.stdout.strip().endswith("}")
    return json.loads(result.stdout)


def _assert_read_only_safety(payload: dict) -> None:
    safety_raw = payload.get("safety")
    safety: dict = safety_raw if isinstance(safety_raw, dict) else {}
    assert payload.get("read_only", safety.get("read_only")) is True
    for flag in SAFETY_FALSE_FLAGS:
        if flag in payload or flag in safety:
            assert payload.get(flag, safety.get(flag)) is False, flag
    for flag in ("artifact_repaired", "artifact_deleted"):
        if flag in payload or flag in safety:
            assert payload.get(flag, safety.get(flag)) is False, flag


def _forbid_execution(monkeypatch) -> None:
    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"receipt audit/report command must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("receipt audit/report command must not call a model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)


# ---------------------------------------------------------------------------
# Module split / registration
# ---------------------------------------------------------------------------


def test_receipt_audit_module_exists_and_cli_wires_registration() -> None:
    module_source = MODULE_PATH.read_text(encoding="utf-8")
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert MODULE_PATH.exists()
    assert "def register(recipes_receipt_app: typer.Typer)" in module_source
    for command in (
        'command("audit")',
        'command("audit-bundle")',
        'command("audit-bundle-validate")',
        'command("integrity")',
        'command("explain")',
    ):
        assert command in module_source
    assert "from shellforgeai.commands import receipt_audit as receipt_audit_commands" in cli_source
    assert "receipt_audit_commands.register(recipes_receipt_app)" in cli_source


def test_cli_no_longer_owns_large_inline_receipt_audit_handler_bodies() -> None:
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "recipes_receipt_audit" not in function_names
    assert "recipes_receipt_audit_bundle" not in function_names
    assert "recipes_receipt_audit_bundle_validate" not in function_names
    assert "recipes_receipt_integrity" not in function_names
    assert "recipes_receipt_explain" not in function_names


def test_help_surfaces_exit_zero_and_preserve_existing_options() -> None:
    expectations = {
        ("audit",): ("--json", "--target", "--recipe", "--limit"),
        ("audit-bundle",): ("--json", "--target", "--recipe", "--limit"),
        ("audit-bundle-validate",): ("--json", "BUNDLE_REF"),
        ("integrity",): (
            "--json",
            "--target",
            "--recipe",
            "--limit",
            "--include-exports",
            "--include-audit-bundl",
        ),
        ("explain",): ("--json", "--source", "--finding", "--target", "--recipe", "--limit"),
    }
    for command, options in expectations.items():
        result = runner.invoke(app, ["recipes", "receipt", *command, "--help"])
        assert result.exit_code == 0, result.output
        for option in options:
            assert option in result.stdout


# ---------------------------------------------------------------------------
# Receipt audit behavior
# ---------------------------------------------------------------------------


def test_receipt_audit_json_filters_and_safety_are_preserved(monkeypatch, tmp_path: Path) -> None:
    _forbid_execution(monkeypatch)
    _receipt(tmp_path, "receipt_pr188_one", target="sfai-pr188-one")
    _receipt(tmp_path, "receipt_pr188_two", target="sfai-pr188-two", recipe_id="custom.recipe")

    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    empty_human = runner.invoke(app, ["recipes", "receipt", "audit"])
    assert empty_human.exit_code == 0

    payload = _invoke_json(
        monkeypatch,
        tmp_path,
        ["recipes", "receipt", "audit", "--target", "sfai-pr188-one", "--json"],
    )
    assert payload["filters"]["target"] == "sfai-pr188-one"
    assert payload["summary"]["receipts_found"] == 1
    _assert_read_only_safety(payload)

    recipe_payload = _invoke_json(
        monkeypatch,
        tmp_path,
        ["recipes", "receipt", "audit", "--recipe", "custom.recipe", "--limit", "1", "--json"],
    )
    assert recipe_payload["filters"]["recipe_id"] == "custom.recipe"
    assert recipe_payload["filters"]["limit"] == 1
    assert recipe_payload["summary"]["receipts_found"] == 1
    _assert_read_only_safety(recipe_payload)


# ---------------------------------------------------------------------------
# Audit-bundle behavior
# ---------------------------------------------------------------------------


def test_audit_bundle_create_validate_missing_and_non_owned_rejection(
    monkeypatch, tmp_path: Path
) -> None:
    _forbid_execution(monkeypatch)
    _receipt(tmp_path, "receipt_pr188_bundle")
    payload = _invoke_json(monkeypatch, tmp_path, ["recipes", "receipt", "audit-bundle", "--json"])
    assert payload["status"] == "created"
    assert payload["artifact_export_only"] is True
    _assert_read_only_safety(payload)
    bundle_path = Path(payload["path"])
    assert tmp_path in bundle_path.parents
    for name in (
        "audit-bundle.json",
        "audit-bundle.md",
        "receipt-audit.json",
        "receipt-history.json",
        "manifest.json",
        "checksums.json",
    ):
        assert (bundle_path / name).exists()

    validate = _invoke_json(
        monkeypatch,
        tmp_path,
        ["recipes", "receipt", "audit-bundle-validate", payload["bundle_id"], "--json"],
    )
    assert validate["status"] == "ok"
    _assert_read_only_safety(validate)

    missing = _invoke_json(
        monkeypatch,
        tmp_path,
        ["recipes", "receipt", "audit-bundle-validate", "audit_bundle_missing", "--json"],
        expect_code=1,
    )
    assert missing["status"] in {"not_found", "failed"}
    _assert_read_only_safety(missing)

    non_owned = _invoke_json(
        monkeypatch,
        tmp_path,
        ["recipes", "receipt", "audit-bundle-validate", "../../etc/passwd", "--json"],
        expect_code=1,
    )
    assert non_owned["status"] in {"not_found", "failed"}
    _assert_read_only_safety(non_owned)


# ---------------------------------------------------------------------------
# Integrity behavior
# ---------------------------------------------------------------------------


def test_integrity_json_include_flags_do_not_create_artifacts_and_report_corrupt(
    monkeypatch, tmp_path: Path
) -> None:
    _forbid_execution(monkeypatch)
    _receipt(tmp_path, "receipt_pr188_integrity")
    bad = tmp_path / "recipe_receipts" / "bad_json"
    bad.mkdir(parents=True)
    (bad / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    before_exports = (
        set((tmp_path / "exports").rglob("*")) if (tmp_path / "exports").exists() else set()
    )

    payload = _invoke_json(
        monkeypatch,
        tmp_path,
        [
            "recipes",
            "receipt",
            "integrity",
            "--include-exports",
            "--include-audit-bundles",
            "--json",
        ],
    )
    _assert_read_only_safety(payload)
    assert payload["filters"]["include_exports"] is True
    assert payload["filters"]["include_audit_bundles"] is True
    assert payload["summary"]["malformed_json"] >= 1
    after_exports = (
        set((tmp_path / "exports").rglob("*")) if (tmp_path / "exports").exists() else set()
    )
    assert after_exports == before_exports


# ---------------------------------------------------------------------------
# Explain behavior
# ---------------------------------------------------------------------------


def test_explain_known_unknown_findings_and_safe_next_commands(monkeypatch, tmp_path: Path) -> None:
    _forbid_execution(monkeypatch)
    known = _invoke_json(
        monkeypatch,
        tmp_path,
        ["recipes", "receipt", "explain", "--finding", "checksum_mismatch", "--json"],
    )
    assert known["status"] == "ok"
    assert known["explanations"][0]["code"] == "checksum_mismatch"
    _assert_read_only_safety(known)

    unknown = _invoke_json(
        monkeypatch,
        tmp_path,
        ["recipes", "receipt", "explain", "--finding", "totally_unknown_pr188", "--json"],
    )
    assert unknown["status"] == "unknown_finding"
    _assert_read_only_safety(unknown)

    commands = "\n".join(str(command).lower() for command in known.get("safe_next_commands", []))
    for explanation in known.get("explanations", []):
        if isinstance(explanation, dict):
            commands += "\n" + "\n".join(
                str(command).lower() for command in explanation.get("safe_next_commands", [])
            )
    padded = f" {commands} "
    for token in PROHIBITED_SAFE_COMMAND_TOKENS:
        assert token not in padded


def test_receipt_audit_module_does_not_import_execution_surfaces() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    forbidden = (
        "execute_disposable_restart",
        "execute_receipt_recovery",
        "subprocess",
        "build_provider",
        "shell=True",
        "docker compose",
        "docker restart",
        "artifact_repaired = True",
        "artifact_deleted = True",
    )
    for token in forbidden:
        assert token not in source
