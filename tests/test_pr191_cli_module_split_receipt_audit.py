"""PR191 receipt audit/history/export/compare command-module extraction guardrails.

These tests prove the read-only/artifact-only receipt history, inspect, export,
export-validate, compare, audit, audit-bundle, integrity, explain, and
rollback-preview handlers are registered from ``shellforgeai.commands.receipt_audit``
while governed execution/recovery handlers remain in ``cli.py``.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core.recipe_execution import (
    CommandResult,
    DockerContainerState,
    execute_disposable_restart,
)
from shellforgeai.core.recipe_preflight import build_preflight_packet, save_preflight_packet

runner = CliRunner()

MODULE_PATH = Path("src/shellforgeai/commands/receipt_audit.py")
CLI_PATH = Path("src/shellforgeai/cli.py")
READ_ONLY_COMMANDS = (
    "history",
    "inspect",
    "export",
    "export-validate",
    "compare",
    "compare-latest",
    "audit",
    "audit-bundle",
    "audit-bundle-validate",
    "integrity",
    "explain",
    "rollback-preview",
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
    "artifact_repaired",
    "artifact_deleted",
)


class FakeDocker:
    def __init__(self, *, after: str = "2026-06-11T00:00:05Z") -> None:
        self.after = after
        self.inspect_calls = 0
        self.restart_calls: list[list[str]] = []

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        return DockerContainerState(
            found=True,
            name=target,
            container_id="abc123",
            started_at="2026-06-11T00:00:00Z" if self.inspect_calls == 1 else self.after,
            labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
        )

    def restart(self, target: str) -> CommandResult:
        argv = ["docker", "restart", target]
        self.restart_calls.append(argv)
        return CommandResult(argv=argv, return_code=0, stdout=f"{target}\n", stderr="")


def _receipt(data_dir: Path, target: str, *, after: str = "2026-06-11T00:00:05Z") -> dict:
    scene = {
        "containers": [
            {
                "name": target,
                "labels": {"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
                "state": "running",
            }
        ]
    }
    packet = build_preflight_packet("docker.disposable_restart", target, scene=scene)
    saved = save_preflight_packet(packet, data_dir)
    fake = FakeDocker(after=after)
    result = execute_disposable_restart(saved["preflight_id"], data_dir, confirm=True, docker=fake)
    assert result["status"] == "executed"
    assert fake.restart_calls == [["docker", "restart", target]]
    return result


def _invoke(args: list[str], monkeypatch, tmp_path: Path, *, expect_code: int = 0):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, args)
    assert result.exit_code == expect_code, result.output
    return result


def _invoke_json(args: list[str], monkeypatch, tmp_path: Path, *, expect_code: int = 0) -> dict:
    result = _invoke(args, monkeypatch, tmp_path, expect_code=expect_code)
    assert result.stdout.strip().startswith("{"), result.stdout
    assert result.stdout.strip().endswith("}"), result.stdout
    return json.loads(result.stdout)


def _assert_non_mutating(payload: dict) -> None:
    raw_safety = payload.get("safety")
    safety: dict = raw_safety if isinstance(raw_safety, dict) else {}
    if ("read_only" in payload or "read_only" in safety) and payload.get("read_only") is not False:
        assert payload.get("read_only", safety.get("read_only")) is True
    for flag in SAFETY_FALSE_FLAGS:
        if flag in payload or flag in safety:
            assert payload.get(flag, safety.get(flag)) is False, flag


def _forbid_command_execution(monkeypatch) -> None:
    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"read-only receipt command must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("read-only receipt command must not call a model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)


# ---------------------------------------------------------------------------
# Module split / registration
# ---------------------------------------------------------------------------


def test_receipt_audit_module_owns_read_only_receipt_commands_and_cli_wires_it() -> None:
    assert MODULE_PATH.exists()
    module_source = MODULE_PATH.read_text(encoding="utf-8")
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert "def register(" in module_source
    for command in READ_ONLY_COMMANDS:
        assert f'command("{command}")' in module_source
    assert "from shellforgeai.commands import receipt_audit as receipt_audit_commands" in cli_source
    assert "receipt_audit_commands.register(recipes_receipt_app, app)" in cli_source
    assert '@recipes_receipt_app.command("recovery-execute")' in cli_source
    assert "execute_receipt_recovery(" in cli_source


def test_cli_no_longer_owns_large_read_only_receipt_handler_bodies() -> None:
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    for name in (
        "recipes_receipt_history",
        "recipes_receipt_inspect",
        "recipes_receipt_export",
        "recipes_receipt_export_validate",
        "recipes_receipt_compare",
        "recipes_receipt_compare_latest",
        "recipes_receipt_audit",
        "recipes_receipt_audit_bundle",
        "recipes_receipt_audit_bundle_validate",
        "recipes_receipt_integrity",
        "recipes_receipt_explain",
        "recipes_receipt_rollback_preview",
        "rollback_preview_receipt",
    ):
        assert name not in function_names
    assert "build_receipt_history(" not in CLI_PATH.read_text(encoding="utf-8")
    assert "preview_receipt_rollback(" not in CLI_PATH.read_text(encoding="utf-8")


def test_receipt_help_surfaces_exit_zero_and_preserve_existing_options(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt_help = runner.invoke(app, ["recipes", "receipt", "--help"])
    assert receipt_help.exit_code == 0
    for command in READ_ONLY_COMMANDS + (
        "recovery-execute",
        "recovery-status",
        "recovery-validate",
    ):
        assert command in receipt_help.stdout
    expectations = {
        ("history",): ("--json", "--limit"),
        ("inspect",): ("--json", "RECEIPT_REF"),
        ("export",): ("--json", "RECEIPT_REF"),
        ("export-validate",): ("--json", "EXPORT_REF"),
        ("compare",): ("--json", "--only-changed", "BEFORE_RECEIPT_REF", "AFTER_RECEIPT_REF"),
        ("audit",): ("--json", "--target", "--recipe", "--limit"),
        ("audit-bundle",): ("--json", "--target", "--recipe", "--limit"),
        ("audit-bundle-validate",): ("--json", "BUNDLE_REF"),
        ("integrity",): ("--json", "--include-exports"),
        ("explain",): ("--json", "--source", "--finding"),
        ("rollback-preview",): ("--json", "RECEIPT_REF"),
    }
    for suffix, tokens in expectations.items():
        result = runner.invoke(app, ["recipes", "receipt", *suffix, "--help"])
        assert result.exit_code == 0, result.output
        for token in tokens:
            assert token in result.stdout


# ---------------------------------------------------------------------------
# Behavior preservation for read-only/artifact-only surfaces
# ---------------------------------------------------------------------------


def test_history_inspect_export_validate_and_compare_json_contracts(monkeypatch, tmp_path: Path):
    one = _receipt(tmp_path, "sfai-pr191-one", after="2026-06-11T00:00:05Z")
    two = _receipt(tmp_path, "sfai-pr191-two", after="2026-06-11T00:01:05Z")
    _forbid_command_execution(monkeypatch)

    human = _invoke(["recipes", "receipt", "history"], monkeypatch, tmp_path)
    assert "Recipe receipt history" in human.stdout
    history = _invoke_json(["recipes", "receipt", "history", "--json"], monkeypatch, tmp_path)
    assert history["count"] == 2
    _assert_non_mutating(history)

    missing = _invoke_json(
        ["recipes", "receipt", "inspect", "missing", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert missing["status"] == "not_found"
    assert "Traceback" not in json.dumps(missing)
    _assert_non_mutating(missing)

    inspect_payload = _invoke_json(
        ["recipes", "receipt", "inspect", one["receipt_id"], "--json"], monkeypatch, tmp_path
    )
    assert inspect_payload["status"] == "ok"
    _assert_non_mutating(inspect_payload)

    exported = _invoke_json(
        ["recipes", "receipt", "export", one["receipt_id"], "--json"], monkeypatch, tmp_path
    )
    assert exported["status"] == "ok"
    assert Path(exported["export_path"]).is_relative_to(tmp_path / "exports" / "receipt_exports")
    _assert_non_mutating(exported)

    validate = _invoke_json(
        ["recipes", "receipt", "export-validate", exported["export_id"], "--json"],
        monkeypatch,
        tmp_path,
    )
    assert validate["status"] == "ok"
    _assert_non_mutating(validate)

    compare = _invoke_json(
        ["recipes", "receipt", "compare", one["receipt_id"], two["receipt_id"], "--json"],
        monkeypatch,
        tmp_path,
    )
    assert compare["status"] == "ok"
    assert "target" in compare["changed"]
    _assert_non_mutating(compare)


def test_audit_bundle_integrity_explain_and_rollback_preview_remain_non_mutating(
    monkeypatch, tmp_path: Path
):
    receipt = _receipt(tmp_path, "sfai-pr191-audit")
    _forbid_command_execution(monkeypatch)

    audit = _invoke_json(["recipes", "receipt", "audit", "--json"], monkeypatch, tmp_path)
    assert audit["mode"] == "v2_recipe_receipt_audit"
    _assert_non_mutating(audit)

    bundle = _invoke_json(["recipes", "receipt", "audit-bundle", "--json"], monkeypatch, tmp_path)
    assert bundle["status"] == "created"
    assert bundle["artifact_export_only"] is True
    assert Path(bundle["path"]).is_relative_to(tmp_path / "exports" / "receipt-audit-bundles")
    for required in ("audit-bundle.json", "audit-bundle.md", "manifest.json", "checksums.json"):
        assert (Path(bundle["path"]) / required).exists()
    _assert_non_mutating(bundle)

    bundle_validate = _invoke_json(
        ["recipes", "receipt", "audit-bundle-validate", bundle["bundle_id"], "--json"],
        monkeypatch,
        tmp_path,
    )
    assert bundle_validate["status"] == "ok"
    _assert_non_mutating(bundle_validate)

    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    integrity = _invoke_json(["recipes", "receipt", "integrity", "--json"], monkeypatch, tmp_path)
    after = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    assert after == before
    _assert_non_mutating(integrity)

    explain = _invoke_json(
        ["recipes", "receipt", "explain", "--finding", "checksum_mismatch", "--json"],
        monkeypatch,
        tmp_path,
    )
    assert explain["status"] == "ok"
    assert explain["explanations"][0]["code"] == "checksum_mismatch"
    _assert_non_mutating(explain)

    rollback = _invoke_json(
        ["recipes", "receipt", "rollback-preview", receipt["receipt_id"], "--json"],
        monkeypatch,
        tmp_path,
    )
    assert rollback["mode"] == "v2_receipt_rollback_preview"
    assert rollback["read_only"] is True
    assert rollback["rollback"]["execution_available"] is False
    assert rollback["safety"].get("rollback_executed", False) is False
    assert rollback["safety"].get("recovery_executed", False) is False
    assert rollback["safety"].get("container_restarted", False) is False
    _assert_non_mutating(rollback)


# ---------------------------------------------------------------------------
# Execution boundary / static safety assertions
# ---------------------------------------------------------------------------


def test_receipt_audit_module_does_not_import_or_define_execution_behavior() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    forbidden = (
        "execute_disposable_restart",
        "execute_receipt_recovery",
        "subprocess",
        "build_provider",
        "shell=True",
        "docker compose",
        "docker restart",
        "cleanup execute",
        "remediation execute",
        "rollback execute",
        "recovery execute",
        "artifact_repaired = True",
        "artifact_deleted = True",
    )
    for token in forbidden:
        assert token not in source


def test_moved_read_only_receipt_commands_do_not_execute_forbidden_runtime_paths(
    monkeypatch, tmp_path: Path
):
    receipt = _receipt(tmp_path, "sfai-pr191-boundary")
    _forbid_command_execution(monkeypatch)
    commands = [
        ["recipes", "receipt", "history", "--json"],
        ["recipes", "receipt", "inspect", receipt["receipt_id"], "--json"],
        ["recipes", "receipt", "export", receipt["receipt_id"], "--json"],
        ["recipes", "receipt", "compare", receipt["receipt_id"], receipt["receipt_id"], "--json"],
        ["recipes", "receipt", "audit", "--json"],
        ["recipes", "receipt", "integrity", "--json"],
        ["recipes", "receipt", "explain", "--finding", "checksum_mismatch", "--json"],
        ["recipes", "receipt", "rollback-preview", receipt["receipt_id"], "--json"],
    ]
    for command in commands:
        payload = _invoke_json(command, monkeypatch, tmp_path)
        _assert_non_mutating(payload)
