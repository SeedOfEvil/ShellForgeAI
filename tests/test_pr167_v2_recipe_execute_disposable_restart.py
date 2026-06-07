from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.recipe_execution import (
    CommandResult,
    DockerContainerState,
    execute_disposable_restart,
    validate_receipt,
)
from shellforgeai.core.recipe_preflight import build_preflight_packet, save_preflight_packet
from shellforgeai.interactive.commands import route_input


class FakeDocker:
    def __init__(
        self,
        *,
        target: str = "sfai-pr167-user-sim",
        labels: dict[str, str] | None = None,
        before_started: str = "2026-06-07T00:00:00Z",
        after_started: str = "2026-06-07T00:00:03Z",
        return_code: int = 0,
        after_found: bool = True,
    ) -> None:
        self.target = target
        self.labels = labels or {
            "shellforgeai.disposable": "true",
            "shellforgeai.allow_restart": "true",
        }
        self.before_started = before_started
        self.after_started = after_started
        self.return_code = return_code
        self.after_found = after_found
        self.restart_calls: list[list[str]] = []
        self.inspect_calls = 0

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        after = self.inspect_calls > 1
        return DockerContainerState(
            found=(self.after_found if after else True),
            name=target,
            container_id="abc123",
            started_at=self.after_started if after else self.before_started,
            labels=dict(self.labels),
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


def _saved_ready_preflight(tmp_path: Path, target: str = "sfai-pr167-user-sim") -> dict:
    scene = {
        "containers": [
            {
                "name": target,
                "labels": {
                    "shellforgeai.disposable": "true",
                    "shellforgeai.allow_restart": "true",
                },
                "state": "running",
                "status": "Up",
            }
        ]
    }
    packet = build_preflight_packet("docker.disposable_restart", target, scene=scene)
    assert packet["status"] == "preflight_ready"
    return save_preflight_packet(packet, tmp_path)


def _saved_blocked_preflight(tmp_path: Path, target: str = "shellforgeai") -> dict:
    scene = {"containers": [{"name": target, "labels": {}, "state": "running"}]}
    packet = build_preflight_packet("docker.disposable_restart", target, scene=scene)
    assert packet["status"] == "blocked"
    return save_preflight_packet(packet, tmp_path)


def test_execute_without_confirm_blocks_and_does_not_restart(tmp_path: Path) -> None:
    preflight = _saved_ready_preflight(tmp_path)
    fake = FakeDocker()
    result = execute_disposable_restart(
        preflight["preflight_id"], tmp_path, confirm=False, docker=fake
    )
    assert result["status"] == "blocked"
    assert result["reason"] == "explicit confirmation required"
    assert result["action"]["command_executed"] is False
    assert result["safety"]["container_restarted"] is False
    assert fake.restart_calls == []


def test_missing_preflight_blocks_without_traceback(tmp_path: Path) -> None:
    result = execute_disposable_restart(
        "does-not-exist", tmp_path, confirm=True, docker=FakeDocker()
    )
    assert result["status"] == "not_found"
    assert result["safety"]["mutation_performed"] is False


def test_malformed_preflight_blocks(tmp_path: Path) -> None:
    d = tmp_path / "recipe_preflights" / "bad"
    d.mkdir(parents=True)
    (d / "recipe-preflight.json").write_text("{not-json", encoding="utf-8")
    result = execute_disposable_restart("bad", tmp_path, confirm=True, docker=FakeDocker())
    assert result["status"] == "blocked"
    assert result["action"]["command_executed"] is False


def test_blocked_and_production_preflight_blocks(tmp_path: Path) -> None:
    preflight = _saved_blocked_preflight(tmp_path, "shellforgeai")
    fake = FakeDocker(target="shellforgeai")
    result = execute_disposable_restart(
        preflight["preflight_id"], tmp_path, confirm=True, docker=fake
    )
    assert result["status"] == "blocked"
    assert "preflight" in result["reason"]
    assert fake.restart_calls == []


def test_target_label_drift_blocks(tmp_path: Path) -> None:
    preflight = _saved_ready_preflight(tmp_path)
    fake = FakeDocker(labels={"shellforgeai.disposable": "true"})
    result = execute_disposable_restart(
        preflight["preflight_id"], tmp_path, confirm=True, docker=fake
    )
    assert result["status"] == "blocked"
    assert result["reason"] == "current target labels no longer satisfy gates"
    assert fake.restart_calls == []


def test_broad_target_blocks(tmp_path: Path) -> None:
    scene = {"containers": [{"name": "all", "labels": {}}]}
    packet = build_preflight_packet("docker.disposable_restart", "all", scene=scene)
    saved = save_preflight_packet(packet, tmp_path)
    result = execute_disposable_restart(
        saved["preflight_id"], tmp_path, confirm=True, docker=FakeDocker()
    )
    assert result["status"] == "blocked"
    assert result["action"]["command_executed"] is False


def test_successful_fake_executor_exact_argv_no_shell_receipt_and_verification(
    tmp_path: Path,
) -> None:
    preflight = _saved_ready_preflight(tmp_path)
    fake = FakeDocker()
    result = execute_disposable_restart(
        preflight["preflight_id"], tmp_path, confirm=True, docker=fake
    )
    assert result["status"] == "executed"
    assert fake.restart_calls == [["docker", "restart", "sfai-pr167-user-sim"]]
    assert result["action"]["argv"] == ["docker", "restart", "sfai-pr167-user-sim"]
    assert result["action"]["command_executed"] is True
    assert result["verification"]["status"] == "passed"
    assert result["verification"]["started_at_before"] != result["verification"]["started_at_after"]
    safety = result["safety"]
    assert safety["container_restarted"] is True
    assert safety["docker_compose_executed"] is False
    assert safety["shell_true"] is False
    assert safety["arbitrary_command_execution"] is False
    assert safety["natural_language_execution"] is False
    receipt_dir = Path(result["receipt"]["path"])
    assert (receipt_dir / "recipe-receipt.json").exists()
    assert (receipt_dir / "recipe-receipt.md").exists()
    assert (receipt_dir / "manifest.json").exists()


def test_receipt_manifest_checksums_validate(tmp_path: Path) -> None:
    preflight = _saved_ready_preflight(tmp_path)
    result = execute_disposable_restart(
        preflight["preflight_id"], tmp_path, confirm=True, docker=FakeDocker()
    )
    validation = validate_receipt(result["receipt_id"], tmp_path)
    assert validation["status"] == "ok"
    assert validation["checks"]["checksums"] is True
    assert validation["checks"]["safety"] is True


def test_failed_docker_return_code_writes_failed_receipt(tmp_path: Path) -> None:
    preflight = _saved_ready_preflight(tmp_path)
    result = execute_disposable_restart(
        preflight["preflight_id"], tmp_path, confirm=True, docker=FakeDocker(return_code=1)
    )
    assert result["status"] == "failed"
    assert result["action"]["command_executed"] is True
    assert result["action"]["return_code"] == 1
    assert result["safety"]["container_restarted"] is False
    assert Path(result["receipt"]["path"]).exists()


def test_command_success_verification_failure_writes_warning_no_extra_restart(
    tmp_path: Path,
) -> None:
    preflight = _saved_ready_preflight(tmp_path)
    fake = FakeDocker(after_started="2026-06-07T00:00:00Z")
    result = execute_disposable_restart(
        preflight["preflight_id"], tmp_path, confirm=True, docker=fake
    )
    assert result["status"] == "verification_failed"
    assert result["warnings"]
    assert fake.restart_calls == [["docker", "restart", "sfai-pr167-user-sim"]]
    assert Path(result["receipt"]["path"]).exists()


def test_invalid_receipt_validate_controlled_not_found(tmp_path: Path) -> None:
    result = validate_receipt("missing", tmp_path)
    assert result["status"] == "not_found"
    assert result["mutation_performed"] is False


def test_json_blocked_shape_has_non_mutating_safety(tmp_path: Path) -> None:
    result = execute_disposable_restart("missing", tmp_path, confirm=True, docker=FakeDocker())
    json.dumps(result)
    assert result["safety"]["mutation_performed"] is False
    assert result["action"]["command_executed"] is False
    assert result["safety"]["docker_compose_executed"] is False


def test_ask_routing_refuses_natural_language_execution() -> None:
    runner = CliRunner()
    for prompt in ["execute the restart recipe", "run that"]:
        res = runner.invoke(app, ["ask", prompt])
        assert res.exit_code == 0
        assert "Refused" in res.output
        assert "recipes execute <preflight_id> --confirm" in res.output
        assert "docker restart" not in res.output


def test_command_help_prompt_shows_governed_workflow_no_raw_docker() -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["ask", "what command would execute the disposable restart recipe?"])
    assert res.exit_code == 0
    assert "recipes execute <preflight_id> --confirm" in res.output
    assert "No action was taken" in res.output
    assert "docker restart" not in res.output


def test_interactive_explicit_execute_and_receipt_validate_routes() -> None:
    routed = route_input("recipes execute preflight_abc --confirm --json")
    assert routed.name == "cli_dispatch"
    assert routed.argv == ("recipes", "execute", "preflight_abc", "--confirm", "--json")
    receipt = route_input("recipes receipt validate receipt_abc --json")
    assert receipt.name == "cli_dispatch"
    assert receipt.argv == ("recipes", "receipt", "validate", "receipt_abc", "--json")


def test_interactive_natural_language_execute_refuses() -> None:
    routed = route_input("restart it now")
    assert routed.name == "mutation_refused"
    routed = route_input("run that")
    assert routed.name == "mutation_refused"


def test_no_cleanup_remediation_rollback_or_compose_safety_flags(tmp_path: Path) -> None:
    preflight = _saved_ready_preflight(tmp_path)
    result = execute_disposable_restart(
        preflight["preflight_id"], tmp_path, confirm=True, docker=FakeDocker()
    )
    safety = result["safety"]
    assert safety["cleanup_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["production_restart_executed"] is False
