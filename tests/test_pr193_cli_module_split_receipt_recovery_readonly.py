"""PR193 read-only recovery receipt status/validate command-module extraction.

These tests prove ``recipes receipt recovery-status`` and
``recipes receipt recovery-validate`` are registered from
``shellforgeai.commands.receipt_recovery_readonly`` while mutation-capable
``recipes receipt recovery-execute`` remains in ``cli.py``. The extraction is
behavior-preserving: help surfaces, JSON contracts, read-only safety fields,
missing/malformed failures, artifact immutability, and the execution boundary
are unchanged.
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

MODULE_PATH = Path("src/shellforgeai/commands/receipt_recovery_readonly.py")
CLI_PATH = Path("src/shellforgeai/cli.py")
GOLDEN_PATH = Path("tests/golden/cli_command_surface_pr184.json")
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


def _recovery_receipt(data_dir: Path, target: str = "sfai-pr193-user-sim") -> str:
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
    executed = execute_disposable_restart(
        saved["preflight_id"], data_dir, confirm=True, docker=FakeDocker()
    )
    assert executed["status"] == "executed"
    recovery = execute_receipt_recovery(
        executed["receipt_id"],
        data_dir,
        confirm=True,
        docker=FakeDocker(
            before_started="2026-06-12T00:10:00Z", after_started="2026-06-12T00:10:05Z"
        ),
    )
    assert recovery["status"] == "executed"
    return recovery["recovery_receipt_id"]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(root: Path) -> list[tuple[str, str | None]]:
    return [
        (str(p.relative_to(root)), _sha(p) if p.is_file() else None)
        for p in sorted(root.rglob("*"))
    ]


def _invoke(args: list[str], monkeypatch, tmp_path: Path, *, expect_code: int = 0):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, args)
    assert result.exit_code == expect_code, result.output
    assert "Traceback" not in (result.stdout + (result.stderr or ""))
    return result


def _invoke_json(args: list[str], monkeypatch, tmp_path: Path, *, expect_code: int = 0) -> dict:
    result = _invoke(args, monkeypatch, tmp_path, expect_code=expect_code)
    stdout = result.stdout.strip()
    assert stdout.startswith("{"), result.stdout
    assert stdout.endswith("}"), result.stdout
    return json.loads(stdout)


def _assert_non_mutating(payload: dict) -> None:
    safety = payload.get("safety") if isinstance(payload.get("safety"), dict) else {}
    if "read_only" in payload or "read_only" in safety:
        assert payload.get("read_only", safety.get("read_only")) is True
    for flag in SAFETY_FALSE_FLAGS:
        if flag in payload or flag in safety:
            assert payload.get(flag, safety.get(flag)) is False, flag


def _assert_validate_read_only(payload: dict) -> None:
    # Validation echoes recorded receipt execution safety; top-level flags prove
    # the validation command itself stayed read-only and non-mutating.
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def _forbid_readonly_runtime_execution(monkeypatch) -> None:
    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"read-only recovery receipt command ran subprocesses: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("read-only recovery receipt command called a model provider")

    def fail_recovery_execute(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("status/validate must not rerun governed recovery execution")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)
    monkeypatch.setattr(cli_mod, "execute_receipt_recovery", fail_recovery_execute)


# ---------------------------------------------------------------------------
# Module split / registration
# ---------------------------------------------------------------------------


def test_recovery_readonly_module_owns_status_and_validate_wiring() -> None:
    assert MODULE_PATH.exists()
    module_source = MODULE_PATH.read_text(encoding="utf-8")
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert "def register(" in module_source
    assert '@recipes_receipt_app.command("recovery-status")' in module_source
    assert '@recipes_receipt_app.command("recovery-validate")' in module_source
    assert (
        "from shellforgeai.commands import receipt_recovery_readonly as "
        "receipt_recovery_readonly_commands"
    ) in cli_source
    assert "receipt_recovery_readonly_commands.register(recipes_receipt_app)" in cli_source
    assert '@recipes_receipt_app.command("recovery-execute")' in cli_source
    assert "execute_receipt_recovery(" in cli_source
    assert "execute_receipt_recovery" not in module_source


def test_cli_no_longer_owns_large_recovery_status_validate_handler_bodies() -> None:
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    tree = ast.parse(cli_source)
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "recipes_receipt_recovery_status" not in function_names
    assert "recipes_receipt_recovery_validate" not in function_names
    assert "verify_recipe_receipt(" not in cli_source
    assert "validate_recipe_receipt(" not in cli_source


def test_recovery_readonly_help_surfaces_exit_zero_and_preserve_options(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt_help = runner.invoke(app, ["recipes", "receipt", "--help"])
    assert receipt_help.exit_code == 0
    for command in ("recovery-status", "recovery-validate", "recovery-execute"):
        assert command in receipt_help.stdout

    for command in ("recovery-status", "recovery-validate"):
        result = runner.invoke(app, ["recipes", "receipt", command, "--help"])
        assert result.exit_code == 0, result.output
        assert "RECOVERY_RECEIPT_REF" in result.stdout
        assert "--json" in result.stdout
        assert "Read-only" in result.stdout


# ---------------------------------------------------------------------------
# Recovery-status behavior preservation
# ---------------------------------------------------------------------------


def test_recovery_status_valid_human_and_json_are_read_only(monkeypatch, tmp_path: Path) -> None:
    recovery_receipt_id = _recovery_receipt(tmp_path)
    before = _tree(tmp_path)
    _forbid_readonly_runtime_execution(monkeypatch)

    human = _invoke(
        ["recipes", "receipt", "recovery-status", recovery_receipt_id], monkeypatch, tmp_path
    )
    assert "Verify: passed" in human.stdout
    assert "Read-only receipt verification." in human.stdout
    assert "No container was restarted by verify." in human.stdout

    payload = _invoke_json(
        ["recipes", "receipt", "recovery-status", recovery_receipt_id, "--json"],
        monkeypatch,
        tmp_path,
    )
    assert payload["status"] == "passed"
    assert payload["receipt"]["recovery_receipt_id"] == recovery_receipt_id
    assert payload["safety"]["container_restarted_by_verify"] is False
    _assert_non_mutating(payload)
    assert _tree(tmp_path) == before, "status must not create a receipt or mutate artifacts"


def test_recovery_status_missing_and_malformed_fail_cleanly(monkeypatch, tmp_path: Path) -> None:
    _forbid_readonly_runtime_execution(monkeypatch)
    missing = _invoke_json(
        ["recipes", "receipt", "recovery-status", "missing", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert missing["status"] == "not_found"
    _assert_non_mutating(missing)

    bad_dir = tmp_path / "recipe_receipts" / "bad-recovery"
    bad_dir.mkdir(parents=True)
    (bad_dir / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    malformed = _invoke_json(
        ["recipes", "receipt", "recovery-status", "bad-recovery", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert malformed["status"] == "failed"
    _assert_non_mutating(malformed)


# ---------------------------------------------------------------------------
# Recovery-validate behavior preservation
# ---------------------------------------------------------------------------


def test_recovery_validate_valid_human_and_json_are_read_only(monkeypatch, tmp_path: Path) -> None:
    recovery_receipt_id = _recovery_receipt(tmp_path)
    before = _tree(tmp_path)
    _forbid_readonly_runtime_execution(monkeypatch)

    human = _invoke(
        ["recipes", "receipt", "recovery-validate", recovery_receipt_id], monkeypatch, tmp_path
    )
    assert "Recipe receipt validation: ok" in human.stdout
    assert "No action was taken by receipt validation." in human.stdout

    payload = _invoke_json(
        ["recipes", "receipt", "recovery-validate", recovery_receipt_id, "--json"],
        monkeypatch,
        tmp_path,
    )
    assert payload["status"] == "ok"
    assert payload["receipt_mode"] == "v2_recipe_recovery_receipt"
    assert payload["recovery_receipt_id"] == recovery_receipt_id
    assert all(payload["checks"].values()), payload["checks"]
    _assert_validate_read_only(payload)
    assert _tree(tmp_path) == before, "validate must not repair, delete, or mutate artifacts"


def test_recovery_validate_missing_malformed_and_checksum_drift_fail_cleanly(
    monkeypatch, tmp_path: Path
) -> None:
    _forbid_readonly_runtime_execution(monkeypatch)
    missing = _invoke_json(
        ["recipes", "receipt", "recovery-validate", "missing", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert missing["status"] == "not_found"
    _assert_non_mutating(missing)

    bad_dir = tmp_path / "recipe_receipts" / "bad-recovery"
    bad_dir.mkdir(parents=True)
    (bad_dir / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    malformed = _invoke_json(
        ["recipes", "receipt", "recovery-validate", "bad-recovery", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert malformed["status"] == "failed"
    _assert_non_mutating(malformed)

    recovery_receipt_id = _recovery_receipt(tmp_path, target="sfai-pr193-drift-sim")
    receipt_path = tmp_path / "recipe_receipts" / recovery_receipt_id / "recipe-receipt.json"
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["target"] = "tampered"
    receipt_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    before = _tree(tmp_path)
    drift = _invoke_json(
        ["recipes", "receipt", "recovery-validate", recovery_receipt_id, "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert drift["status"] == "failed"
    assert drift["checks"]["checksums"] is False
    _assert_validate_read_only(drift)
    assert _tree(tmp_path) == before, "validation must not repair or delete drifted artifacts"


# ---------------------------------------------------------------------------
# Execution boundary / command-surface guardrail hooks
# ---------------------------------------------------------------------------


def test_recovery_readonly_module_has_no_execution_imports_or_shell_paths() -> None:
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


def test_pr184_golden_guardrail_still_covers_recovery_receipt_surfaces() -> None:
    fixture = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    commands = {entry["name"]: entry for entry in fixture["commands"]}
    for name in (
        "recipes_receipt_recovery_status_help",
        "recipes_receipt_recovery_validate_help",
        "recipes_receipt_recovery_execute_help",
        "recipes_receipt_rollback_preview_help",
        "recipes_receipt_verify_help",
        "recipes_receipt_validate_help",
    ):
        assert name in commands
    execute_help = commands["recipes_receipt_recovery_execute_help"]
    assert "--confirm" in execute_help["required_substrings"]
