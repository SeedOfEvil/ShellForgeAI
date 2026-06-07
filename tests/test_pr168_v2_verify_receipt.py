from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.recipe_execution import (
    CommandResult,
    DockerContainerState,
    execute_disposable_restart,
)
from shellforgeai.core.recipe_preflight import build_preflight_packet, save_preflight_packet
from shellforgeai.core.recipe_receipt_verify import verify_recipe_receipt
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input

runner = CliRunner()


class FakeDocker:
    def __init__(
        self, *, return_code: int = 0, after_started: str = "2026-06-07T00:00:03Z"
    ) -> None:
        self.return_code = return_code
        self.after_started = after_started
        self.restart_calls: list[list[str]] = []
        self.inspect_calls = 0

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        after = self.inspect_calls > 1
        return DockerContainerState(
            found=True,
            name=target,
            container_id="abc123",
            started_at=self.after_started if after else "2026-06-07T00:00:00Z",
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


def _receipt(tmp_path: Path, *, fake: FakeDocker | None = None) -> dict:
    target = "sfai-pr168-user-sim"
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
        saved["preflight_id"], tmp_path, confirm=True, docker=fake or FakeDocker()
    )
    assert result["receipt_id"]
    return result


def _rewrite_receipt(receipt_dir: Path, mutate) -> None:  # noqa: ANN001
    path = receipt_dir / "recipe-receipt.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_verify_receipt_valid_json_contract_read_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _receipt(tmp_path)
    result = runner.invoke(app, ["verify", "--receipt", receipt["receipt_id"], "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert result.stdout.strip().startswith("{") and result.stdout.strip().endswith("}")
    assert payload["schema_version"] == 1
    assert payload["mode"] == "v2_verify"
    assert payload["verification_type"] == "receipt"
    assert payload["status"] == "passed"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    safety = payload["safety"]
    for key in (
        "verify_executed_command",
        "container_restarted_by_verify",
        "shell_true",
        "arbitrary_command_execution",
        "model_called",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "docker_compose_executed",
        "natural_language_execution",
    ):
        assert safety[key] is False
        assert payload[key] is False
    assert payload["recipe"]["recipe_id"] == "docker.disposable_restart"
    assert payload["target"]["name"] == "sfai-pr168-user-sim"
    assert payload["execution"]["exact_target_only"] is True
    assert payload["execution"]["recorded_action"] == "docker restart sfai-pr168-user-sim"
    assert payload["execution"]["action_result"] == "executed"
    assert payload["post_check"]["verification_status"] == "passed"


def test_verify_receipt_human_and_brief(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _receipt(tmp_path)
    human = runner.invoke(app, ["verify", "--receipt", receipt["receipt_id"]])
    assert human.exit_code == 0
    assert "Verify: passed" in human.stdout
    assert "Verification type: receipt" in human.stdout
    assert "Recorded action:" in human.stdout
    assert "No container was restarted by verify" in human.stdout
    brief = runner.invoke(app, ["verify", "--receipt", receipt["receipt_id"], "--brief"])
    assert brief.exit_code == 0
    assert "Type: receipt" in brief.stdout


def test_receipt_resolution_failures_and_statuses(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    missing = runner.invoke(app, ["verify", "--receipt", "does-not-exist", "--json"])
    assert missing.exit_code != 0
    assert json.loads(missing.stdout)["status"] == "not_found"
    traversal = runner.invoke(app, ["verify", "--receipt", "../outside", "--json"])
    assert traversal.exit_code != 0
    assert json.loads(traversal.stdout)["status"] == "not_found"

    bad_dir = tmp_path / "recipe_receipts" / "bad"
    bad_dir.mkdir(parents=True)
    (bad_dir / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    malformed = runner.invoke(app, ["verify", "--receipt", "bad", "--json"])
    assert malformed.exit_code != 0
    assert json.loads(malformed.stdout)["status"] == "failed"


def test_unsupported_failed_and_safety_drift_receipts(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    receipt_dir = Path(receipt["receipt"]["path"])

    _rewrite_receipt(receipt_dir, lambda p: p.__setitem__("recipe_id", "unsupported.recipe"))
    unsupported = verify_recipe_receipt(receipt["receipt_id"], tmp_path)
    assert unsupported["status"] == "unsupported"
    assert unsupported["first_safe_command"] == "shellforgeai recipes list --json"

    receipt2 = _receipt(tmp_path, fake=FakeDocker(return_code=1))
    failed = verify_recipe_receipt(receipt2["receipt_id"], tmp_path)
    assert failed["status"] == "failed"
    assert failed["execution"]["action_result"] == "failed"

    receipt3 = _receipt(tmp_path)
    drift_dir = Path(receipt3["receipt"]["path"])
    _rewrite_receipt(drift_dir, lambda p: p["safety"].__setitem__("shell_true", True))
    drift = verify_recipe_receipt(receipt3["receipt_id"], tmp_path)
    assert drift["status"] == "safety_drift"


def test_verify_receipt_no_mutation_no_new_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _receipt(tmp_path)
    before = {p.relative_to(tmp_path): p.stat().st_mtime_ns for p in tmp_path.rglob("*")}

    def fail_run(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("receipt verify must not run subprocess")

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", fail_run)
    result = runner.invoke(app, ["verify", "--receipt", receipt["receipt_id"], "--json"])
    after = {p.relative_to(tmp_path): p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    assert result.exit_code == 0
    assert before == after
    payload = json.loads(result.stdout)
    assert payload["safety"]["container_restarted_by_verify"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    assert len(list((tmp_path / "recipe_receipts").iterdir())) == 1


def test_ask_receipt_verify_and_mutation_refusals() -> None:
    res = runner.invoke(app, ["ask", "verify receipt receipt_123"])
    assert res.exit_code == 0
    assert "shellforgeai verify --receipt receipt_123" in res.stdout
    assert "No action was taken" in res.stdout
    missing = runner.invoke(app, ["ask", "verify the execution receipt"])
    assert missing.exit_code == 0
    assert "Receipt id required" in missing.stdout
    for prompt in (
        "verify and restart again",
        "if failed retry it",
        "verify receipt receipt_123 and retry it",
    ):
        refused = runner.invoke(app, ["ask", prompt])
        assert refused.exit_code == 0
        assert "Refused" in refused.stdout
        assert "No action was taken" in refused.stdout


def test_interactive_receipt_verify_routes_and_mutation_refusal(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _receipt(tmp_path)
    assert route_input(f"verify --receipt {receipt['receipt_id']}").argv == (
        "verify",
        "--receipt",
        receipt["receipt_id"],
    )
    assert route_input(f"verify --receipt {receipt['receipt_id']} --json").argv == (
        "verify",
        "--receipt",
        receipt["receipt_id"],
        "--json",
    )
    assert route_input(f"recipes receipt verify {receipt['receipt_id']} --json").argv == (
        "recipes",
        "receipt",
        "verify",
        receipt["receipt_id"],
        "--json",
    )
    buf = StringIO()
    raw = repl._run_interactive_cli_dispatch(
        Console(file=buf), ("verify", "--receipt", receipt["receipt_id"], "--json")
    )
    assert json.loads(raw)["verification_type"] == "receipt"
    assert route_input("retry the receipt").name == "mutation_refused"
    assert route_input("rollback it").name == "mutation_refused"
