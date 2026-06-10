from __future__ import annotations

import json
import subprocess
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


class FakeDocker:
    def __init__(
        self,
        *,
        target: str = "sfai-pr185-user-sim",
        return_code: int = 0,
        before_started: str = "2026-06-10T00:00:00Z",
        after_started: str = "2026-06-10T00:00:05Z",
    ) -> None:
        self.target = target
        self.return_code = return_code
        self.before_started = before_started
        self.after_started = after_started
        self.inspect_calls = 0
        self.restart_calls: list[list[str]] = []

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        after = self.inspect_calls > 1
        return DockerContainerState(
            found=True,
            name=target,
            container_id="abc123",
            started_at=self.after_started if after else self.before_started,
            labels={
                "shellforgeai.disposable": "true",
                "shellforgeai.allow_restart": "true",
            },
        )

    def restart(self, target: str) -> CommandResult:
        argv = ["docker", "restart", target]
        self.restart_calls.append(argv)
        return CommandResult(
            argv=argv,
            return_code=self.return_code,
            stdout=f"{target}\n" if self.return_code == 0 else "",
            stderr="boom" if self.return_code else "",
        )


def _execution_receipt(tmp_path: Path, *, target: str = "sfai-pr185-user-sim") -> dict:
    scene = {
        "containers": [
            {
                "name": target,
                "labels": {
                    "shellforgeai.disposable": "true",
                    "shellforgeai.allow_restart": "true",
                },
                "state": "running",
            }
        ]
    }
    packet = build_preflight_packet("docker.disposable_restart", target, scene=scene)
    saved = save_preflight_packet(packet, tmp_path)
    result = execute_disposable_restart(
        saved["preflight_id"], tmp_path, confirm=True, docker=FakeDocker(target=target)
    )
    assert result["receipt_id"]
    return result


def _receipt_dirs(tmp_path: Path) -> set[str]:
    root = tmp_path / "recipe_receipts"
    if not root.exists():
        return set()
    return {path.name for path in root.iterdir() if path.is_dir()}


def _assert_verify_safety(payload: dict) -> None:
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    safety = payload["safety"]
    for key in (
        "read_only",
        "mutation_performed",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "docker_compose_executed",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
    ):
        assert safety[key] is (key == "read_only")
    for optional_key in (
        "verify_executed_command",
        "container_restarted_by_verify",
        "container_restarted",
        "apply_executed",
    ):
        if optional_key in safety:
            assert safety[optional_key] is False


def _block_model_calls(monkeypatch) -> None:  # noqa: ANN001
    def fail(*_args, **_kwargs):  # noqa: ANN001
        raise AssertionError("verify must not call the model/provider")

    monkeypatch.setattr(cli_mod, "build_provider", fail, raising=False)


def test_module_split_and_verify_registration_are_preserved() -> None:
    module_path = Path("src/shellforgeai/commands/verify.py")
    cli_path = Path("src/shellforgeai/cli.py")
    assert module_path.exists()
    module_source = module_path.read_text(encoding="utf-8")
    cli_source = cli_path.read_text(encoding="utf-8")
    assert "def register(app: typer.Typer)" in module_source
    assert '@app.command("verify")' in module_source
    assert "from shellforgeai.commands import verify as verify_commands" in cli_source
    assert "verify_commands.register(app)" in cli_source
    assert "def verify(" not in cli_source
    assert '@app.command("verify")' not in cli_source

    result = runner.invoke(app, ["verify", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.stdout
    assert "--brief" in result.stdout
    assert "--receipt" in result.stdout
    assert "read-only" in result.stdout.lower()


def test_current_state_verify_json_and_human_stay_read_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _block_model_calls(monkeypatch)

    result = runner.invoke(app, ["verify", "--json"])
    assert result.exit_code == 0
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    payload = json.loads(result.stdout)
    assert payload["mode"] == "v2_verify"
    assert payload["verification_type"] == "current_state"
    _assert_verify_safety(payload)

    human = runner.invoke(app, ["verify"])
    assert human.exit_code == 0
    assert "Traceback" not in human.stdout + human.stderr
    assert "read-only" in human.stdout.lower()


def test_missing_receipt_verify_is_controlled_json_not_found(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _block_model_calls(monkeypatch)

    result = runner.invoke(app, ["verify", "--receipt", "missing", "--json"])
    assert result.exit_code == 1
    assert "Traceback" not in result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "not_found"
    assert payload["verification_type"] == "receipt"
    _assert_verify_safety(payload)


def test_execution_receipt_verify_uses_recorded_evidence_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _execution_receipt(tmp_path)
    before_dirs = _receipt_dirs(tmp_path)
    _block_model_calls(monkeypatch)

    def fail_subprocess(*_args, **_kwargs):  # noqa: ANN001
        raise AssertionError("receipt verify must not call shell/Docker/Compose")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    monkeypatch.setattr(subprocess, "Popen", fail_subprocess)

    result = runner.invoke(app, ["verify", "--receipt", receipt["receipt_id"], "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed"
    assert payload["verification_type"] == "receipt"
    assert payload["execution"]["recorded_action"] == "docker restart sfai-pr185-user-sim"
    assert payload["post_check"]["verification_status"] == "passed"
    _assert_verify_safety(payload)
    assert _receipt_dirs(tmp_path) == before_dirs


def test_recovery_receipt_verify_uses_recorded_evidence_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _execution_receipt(tmp_path)
    recovery = execute_receipt_recovery(
        receipt["receipt_id"],
        tmp_path,
        confirm=True,
        docker=FakeDocker(target="sfai-pr185-user-sim"),
    )
    assert recovery["status"] == "executed"
    before_dirs = _receipt_dirs(tmp_path)
    _block_model_calls(monkeypatch)

    def fail_subprocess(*_args, **_kwargs):  # noqa: ANN001
        raise AssertionError("recovery receipt verify must not call shell/Docker/Compose")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    monkeypatch.setattr(subprocess, "Popen", fail_subprocess)

    result = runner.invoke(app, ["verify", "--receipt", recovery["recovery_receipt_id"], "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "passed"
    assert payload["receipt"]["recovery_receipt_id"] == recovery["recovery_receipt_id"]
    assert payload["receipt"]["original_receipt_id"] == receipt["receipt_id"]
    _assert_verify_safety(payload)
    assert _receipt_dirs(tmp_path) == before_dirs
