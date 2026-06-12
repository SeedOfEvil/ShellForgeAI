"""PR192 receipt verify/validate/rollback-preview command-module extraction guardrails.

These tests prove the read-only governed receipt verify, validate, and
rollback-preview handlers (plus the existing top-level ``rollback-preview``
alias) are registered from ``shellforgeai.commands.receipt_safety`` while the
mutation-capable governed recovery execution handlers remain in ``cli.py``.
The extraction is behavior-preserving: surfaces, JSON contracts, exit codes,
read-only safety fields, and the execution boundary are unchanged.
"""

from __future__ import annotations

import ast
import hashlib
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
from shellforgeai.core.recipe_receipt_recovery import execute_receipt_recovery

runner = CliRunner()

MODULE_PATH = Path("src/shellforgeai/commands/receipt_safety.py")
CLI_PATH = Path("src/shellforgeai/cli.py")
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
    def __init__(
        self,
        *,
        before_started: str = "2026-06-12T00:00:00Z",
        after_started: str = "2026-06-12T00:00:05Z",
    ) -> None:
        self.before_started = before_started
        self.after_started = after_started
        self.restart_calls: list[list[str]] = []
        self.inspect_calls = 0

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        return DockerContainerState(
            found=True,
            name=target,
            container_id="abc123",
            started_at=self.before_started if self.inspect_calls == 1 else self.after_started,
            labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
        )

    def restart(self, target: str) -> CommandResult:
        argv = ["docker", "restart", target]
        self.restart_calls.append(argv)
        return CommandResult(argv=argv, return_code=0, stdout=f"{target}\n", stderr="")


def _receipt(data_dir: Path, target: str = "sfai-pr192-user-sim") -> dict:
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
    fake = FakeDocker()
    result = execute_disposable_restart(saved["preflight_id"], data_dir, confirm=True, docker=fake)
    assert result["status"] == "executed"
    assert fake.restart_calls == [["docker", "restart", target]]
    return result


def _recovery_receipt(data_dir: Path, target: str = "sfai-pr192-user-sim") -> str:
    receipt = _receipt(data_dir, target)
    fake = FakeDocker(before_started="2026-06-12T00:10:00Z", after_started="2026-06-12T00:10:05Z")
    payload = execute_receipt_recovery(receipt["receipt_id"], data_dir, confirm=True, docker=fake)
    assert payload["status"] == "executed"
    return payload["recovery_receipt_id"]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resign_receipt(receipt_dir: Path) -> None:
    manifest_path = receipt_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for rel in ("recipe-receipt.json", "recipe-receipt.md"):
        manifest["checksums"][rel] = _sha(receipt_dir / rel)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest["checksums"]["manifest.json"] = _sha(manifest_path)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _mutate_receipt(receipt: dict, mutate, *, resign: bool = True) -> None:  # noqa: ANN001
    receipt_dir = Path(receipt["receipt"]["path"])
    receipt_path = receipt_dir / "recipe-receipt.json"
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    mutate(payload)
    receipt_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path = receipt_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["recipe_id"] = payload.get("recipe_id")
    manifest["target"] = payload.get("target")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if resign:
        _resign_receipt(receipt_dir)


def _invoke(args: list[str], monkeypatch, tmp_path: Path, *, expect_code: int = 0):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, args)
    assert result.exit_code == expect_code, result.output
    assert "Traceback" not in (result.stdout + (result.stderr or ""))
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


def _assert_validate_read_only(payload: dict) -> None:
    """Validate echoes the receipt's recorded execution safety block, so only the
    command's own top-level flags prove the validate run itself was read-only."""
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def _forbid_command_execution(monkeypatch) -> None:
    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"read-only receipt command must not run subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("read-only receipt command must not call a model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)


def _tree(root: Path) -> list[tuple[str, str | None]]:
    entries: list[tuple[str, str | None]] = []
    for p in sorted(root.rglob("*")):
        entries.append((str(p.relative_to(root)), _sha(p) if p.is_file() else None))
    return entries


# ---------------------------------------------------------------------------
# Module split / registration
# ---------------------------------------------------------------------------


def test_receipt_safety_module_owns_verify_validate_rollback_preview() -> None:
    assert MODULE_PATH.exists()
    module_source = MODULE_PATH.read_text(encoding="utf-8")
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert "def register(" in module_source
    for command in ("verify", "validate", "rollback-preview"):
        assert f'command("{command}")' in module_source
    # Top-level alias stays registered from the module against the root app.
    assert '@app.command("rollback-preview")' in module_source
    assert (
        "from shellforgeai.commands import receipt_safety as receipt_safety_commands" in cli_source
    )
    assert "receipt_safety_commands.register(recipes_receipt_app, app)" in cli_source
    # Mutation-capable governed recovery execution stays out of receipt_safety;
    # PR194 moved it to its own command module, wired from cli.py untouched.
    assert "receipt_recovery_execute_commands.register(recipes_receipt_app)" in cli_source
    assert "execute_receipt_recovery" not in module_source


def test_cli_no_longer_owns_receipt_safety_handler_bodies() -> None:
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    tree = ast.parse(cli_source)
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    for name in (
        "recipes_receipt_verify",
        "recipes_receipt_validate",
        "recipes_receipt_rollback_preview",
        "rollback_preview_receipt",
    ):
        assert name not in function_names
    assert "preview_receipt_rollback(" not in cli_source


def test_receipt_safety_help_surfaces_exit_zero_and_preserve_existing_options(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt_help = runner.invoke(app, ["recipes", "receipt", "--help"])
    assert receipt_help.exit_code == 0
    for command in ("verify", "validate", "rollback-preview"):
        assert command in receipt_help.stdout
    expectations = {
        ("recipes", "receipt", "verify"): ("--json", "RECEIPT_REF", "Read-only"),
        ("recipes", "receipt", "validate"): ("--json", "RECEIPT_REF", "Read-only"),
        ("recipes", "receipt", "rollback-preview"): ("--json", "RECEIPT_REF", "Read-only"),
        ("rollback-preview",): ("--json", "--receipt", "Read-only"),
    }
    for prefix, tokens in expectations.items():
        result = runner.invoke(app, [*prefix, "--help"])
        assert result.exit_code == 0, result.output
        for token in tokens:
            assert token in result.stdout


# ---------------------------------------------------------------------------
# Receipt verify behavior preservation
# ---------------------------------------------------------------------------


def test_verify_valid_execution_receipt_unchanged(monkeypatch, tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    _forbid_command_execution(monkeypatch)
    human = _invoke(["recipes", "receipt", "verify", receipt["receipt_id"]], monkeypatch, tmp_path)
    assert "Verify: passed" in human.stdout
    assert "Read-only receipt verification." in human.stdout
    payload = _invoke_json(
        ["recipes", "receipt", "verify", receipt["receipt_id"], "--json"], monkeypatch, tmp_path
    )
    assert payload["status"] == "passed"
    assert payload["recipe"]["recipe_id"] == "docker.disposable_restart"
    assert payload["safety"]["container_restarted_by_verify"] is False
    _assert_non_mutating(payload)


def test_verify_valid_recovery_receipt_unchanged(monkeypatch, tmp_path: Path) -> None:
    recovery_receipt_id = _recovery_receipt(tmp_path)
    _forbid_command_execution(monkeypatch)
    payload = _invoke_json(
        ["recipes", "receipt", "verify", recovery_receipt_id, "--json"], monkeypatch, tmp_path
    )
    assert payload["status"] == "passed"
    assert payload["safety"]["container_restarted_by_verify"] is False
    _assert_non_mutating(payload)


def test_verify_missing_and_malformed_receipts_fail_cleanly(monkeypatch, tmp_path: Path) -> None:
    _forbid_command_execution(monkeypatch)
    missing = _invoke_json(
        ["recipes", "receipt", "verify", "missing", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert missing["status"] == "not_found"
    _assert_non_mutating(missing)

    bad_dir = tmp_path / "recipe_receipts" / "bad"
    bad_dir.mkdir(parents=True)
    (bad_dir / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    malformed = _invoke_json(
        ["recipes", "receipt", "verify", "bad", "--json"], monkeypatch, tmp_path, expect_code=1
    )
    assert malformed["status"] == "failed"
    _assert_non_mutating(malformed)


# ---------------------------------------------------------------------------
# Receipt validate behavior preservation
# ---------------------------------------------------------------------------


def test_validate_valid_receipt_unchanged(monkeypatch, tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    _forbid_command_execution(monkeypatch)
    human = _invoke(
        ["recipes", "receipt", "validate", receipt["receipt_id"]], monkeypatch, tmp_path
    )
    assert "Recipe receipt validation: ok" in human.stdout
    assert "No action was taken by receipt validation." in human.stdout
    payload = _invoke_json(
        ["recipes", "receipt", "validate", receipt["receipt_id"], "--json"], monkeypatch, tmp_path
    )
    assert payload["status"] == "ok"
    assert all(payload["checks"].values()), payload["checks"]
    _assert_validate_read_only(payload)


def test_validate_missing_malformed_and_checksum_failures(monkeypatch, tmp_path: Path) -> None:
    _forbid_command_execution(monkeypatch)
    missing = _invoke_json(
        ["recipes", "receipt", "validate", "missing", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert missing["status"] == "not_found"
    _assert_non_mutating(missing)

    bad_dir = tmp_path / "recipe_receipts" / "bad"
    bad_dir.mkdir(parents=True)
    (bad_dir / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    malformed = _invoke_json(
        ["recipes", "receipt", "validate", "bad", "--json"], monkeypatch, tmp_path, expect_code=1
    )
    assert malformed["status"] == "failed"
    _assert_non_mutating(malformed)


def test_validate_checksum_drift_fails_and_does_not_repair_or_delete(
    monkeypatch, tmp_path: Path
) -> None:
    receipt = _receipt(tmp_path)
    # Tamper the receipt body without resigning the manifest: checksum drift.
    _mutate_receipt(receipt, lambda p: p.update({"target": "tampered"}), resign=False)
    _forbid_command_execution(monkeypatch)
    before = _tree(tmp_path)
    payload = _invoke_json(
        ["recipes", "receipt", "validate", receipt["receipt_id"], "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert payload["status"] == "failed"
    assert payload["checks"]["checksums"] is False
    assert "checksums check failed" in payload["warnings"]
    _assert_validate_read_only(payload)
    assert _tree(tmp_path) == before, "validate must not repair, rewrite, or delete artifacts"


# ---------------------------------------------------------------------------
# Rollback-preview behavior preservation
# ---------------------------------------------------------------------------


def test_rollback_preview_valid_receipt_reports_no_true_rollback(
    monkeypatch, tmp_path: Path
) -> None:
    receipt = _receipt(tmp_path)
    _forbid_command_execution(monkeypatch)
    human = _invoke(
        ["recipes", "receipt", "rollback-preview", receipt["receipt_id"]], monkeypatch, tmp_path
    )
    assert "Rollback preview: gated / limited" in human.stdout
    assert "No true state rollback is available for a container restart" in human.stdout
    assert "No rollback was executed" in human.stdout
    payload = _invoke_json(
        ["recipes", "receipt", "rollback-preview", receipt["receipt_id"], "--json"],
        monkeypatch,
        tmp_path,
    )
    assert payload["mode"] == "v2_receipt_rollback_preview"
    assert payload["status"] == "limited"
    assert payload["rollback"]["true_rollback_available"] is False
    assert payload["rollback"]["execution_available"] is False
    assert (
        payload["first_safe_command"]
        == f"shellforgeai verify --receipt {receipt['receipt_id']} --json"
    )
    _assert_non_mutating(payload)


def test_rollback_preview_top_level_alias_unchanged(monkeypatch, tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    _forbid_command_execution(monkeypatch)
    payload = _invoke_json(
        ["rollback-preview", "--receipt", receipt["receipt_id"], "--json"], monkeypatch, tmp_path
    )
    assert payload["mode"] == "v2_receipt_rollback_preview"
    assert payload["status"] == "limited"
    assert payload["rollback"]["true_rollback_available"] is False
    _assert_non_mutating(payload)


def test_rollback_preview_missing_unsupported_and_production_statuses(
    monkeypatch, tmp_path: Path
) -> None:
    _forbid_command_execution(monkeypatch)
    missing = _invoke_json(
        ["recipes", "receipt", "rollback-preview", "missing", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert missing["status"] == "not_found"
    _assert_non_mutating(missing)

    unsupported = _receipt(tmp_path, target="sfai-pr192-unsupported-sim")
    _mutate_receipt(
        unsupported, lambda payload: payload.update({"recipe_id": "example.unsupported"})
    )
    unsupported_payload = _invoke_json(
        ["recipes", "receipt", "rollback-preview", unsupported["receipt_id"], "--json"],
        monkeypatch,
        tmp_path,
    )
    assert unsupported_payload["status"] == "unsupported_recipe"
    assert unsupported_payload["first_safe_command"].startswith(
        "shellforgeai recipes receipt verify"
    )
    _assert_non_mutating(unsupported_payload)

    prod = _receipt(tmp_path, target="sfai-pr192-prod-sim")
    _mutate_receipt(prod, lambda payload: payload["post_state"].update({"production_target": True}))
    prod_payload = _invoke_json(
        ["recipes", "receipt", "rollback-preview", prod["receipt_id"], "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert prod_payload["status"] == "blocked"
    assert prod_payload["reason"] == "production target refused for rollback/recovery"
    _assert_non_mutating(prod_payload)


# ---------------------------------------------------------------------------
# Execution boundary / static safety assertions
# ---------------------------------------------------------------------------


def test_receipt_safety_module_does_not_import_or_define_execution_behavior() -> None:
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


def test_moved_receipt_safety_commands_do_not_execute_forbidden_runtime_paths(
    monkeypatch, tmp_path: Path
) -> None:
    receipt = _receipt(tmp_path, target="sfai-pr192-boundary-sim")
    _forbid_command_execution(monkeypatch)
    before = _tree(tmp_path)
    commands = [
        ["recipes", "receipt", "verify", receipt["receipt_id"], "--json"],
        ["recipes", "receipt", "rollback-preview", receipt["receipt_id"], "--json"],
        ["rollback-preview", "--receipt", receipt["receipt_id"], "--json"],
    ]
    for command in commands:
        payload = _invoke_json(command, monkeypatch, tmp_path)
        _assert_non_mutating(payload)
    validate_payload = _invoke_json(
        ["recipes", "receipt", "validate", receipt["receipt_id"], "--json"], monkeypatch, tmp_path
    )
    _assert_validate_read_only(validate_payload)
    assert _tree(tmp_path) == before, (
        "read-only receipt safety commands must not write, repair, or delete artifacts"
    )
