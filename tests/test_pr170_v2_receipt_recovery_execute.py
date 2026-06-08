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
from shellforgeai.core.recipe_receipt_recovery import execute_receipt_recovery
from shellforgeai.core.recipe_receipt_verify import verify_recipe_receipt
from shellforgeai.interactive.commands import route_input

runner = CliRunner()


class FakeDocker:
    def __init__(
        self,
        *,
        labels: dict[str, str] | None = None,
        before_started: str = "2026-06-08T00:00:00Z",
        after_started: str = "2026-06-08T00:00:04Z",
        return_code: int = 0,
        found: bool = True,
        name: str | None = None,
    ) -> None:
        self.labels = labels or {
            "shellforgeai.disposable": "true",
            "shellforgeai.allow_restart": "true",
        }
        self.before_started = before_started
        self.after_started = after_started
        self.return_code = return_code
        self.found = found
        self.name = name
        self.restart_calls: list[list[str]] = []
        self.inspect_calls = 0

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        after = self.inspect_calls > 1
        return DockerContainerState(
            found=self.found,
            name=self.name or target,
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
            stdout=f"{target}\n",
            stderr="boom" if self.return_code else "",
        )


def _receipt(tmp_path: Path, target: str = "sfai-pr170-user-sim") -> dict:
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
    saved = save_preflight_packet(packet, tmp_path)
    result = execute_disposable_restart(
        saved["preflight_id"], tmp_path, confirm=True, docker=FakeDocker()
    )
    assert result["status"] == "executed"
    return result


def _rewrite_receipt(receipt: dict, mutate) -> None:  # noqa: ANN001
    d = Path(receipt["receipt"]["path"])
    p = d / "recipe-receipt.json"
    payload = json.loads(p.read_text(encoding="utf-8"))
    mutate(payload)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    manifest["recipe_id"] = payload.get("recipe_id")
    manifest["target"] = payload.get("target")
    import hashlib

    manifest["checksums"]["recipe-receipt.json"] = hashlib.sha256(p.read_bytes()).hexdigest()
    (d / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_no_confirm_blocks_json_no_mutation(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    fake = FakeDocker()
    payload = execute_receipt_recovery(receipt["receipt_id"], tmp_path, confirm=False, docker=fake)
    assert payload["status"] == "blocked"
    assert payload["reason"] == "explicit --confirm required"
    assert payload["mutation_performed"] is False
    assert payload["action"]["docker_restart_attempted"] is False
    assert payload["safety"]["container_restarted"] is False
    assert fake.restart_calls == []


def test_missing_malformed_and_unsupported_receipts_fail_cleanly(tmp_path: Path) -> None:
    assert execute_receipt_recovery("missing", tmp_path, confirm=True)["status"] == "not_found"
    bad = tmp_path / "recipe_receipts" / "bad"
    bad.mkdir(parents=True)
    (bad / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    assert execute_receipt_recovery("bad", tmp_path, confirm=True)["status"] == "failed"
    receipt = _receipt(tmp_path)
    _rewrite_receipt(receipt, lambda p: p.update({"recipe_id": "other.recipe"}))
    payload = execute_receipt_recovery(receipt["receipt_id"], tmp_path, confirm=True)
    assert payload["status"] == "unsupported_recipe"
    assert payload["mutation_performed"] is False


def test_production_missing_label_drift_and_broad_targets_block(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    assert (
        execute_receipt_recovery(
            receipt["receipt_id"], tmp_path, confirm=True, docker=FakeDocker(name="shellforgeai")
        )["reason"]
        == "production target refused"
    )
    assert (
        execute_receipt_recovery(
            receipt["receipt_id"], tmp_path, confirm=True, docker=FakeDocker(found=False)
        )["reason"]
        == "target not found"
    )
    assert (
        execute_receipt_recovery(
            receipt["receipt_id"],
            tmp_path,
            confirm=True,
            docker=FakeDocker(labels={"shellforgeai.allow_restart": "true"}),
        )["reason"]
        == "current target labels no longer satisfy gates"
    )
    assert (
        execute_receipt_recovery(
            receipt["receipt_id"],
            tmp_path,
            confirm=True,
            docker=FakeDocker(labels={"shellforgeai.disposable": "true"}),
        )["reason"]
        == "current target labels no longer satisfy gates"
    )
    broad = _receipt(tmp_path, target="sfai-pr170-broad-sim")
    _rewrite_receipt(broad, lambda p: p.update({"target": "all"}))
    assert (
        execute_receipt_recovery(broad["receipt_id"], tmp_path, confirm=True)["reason"]
        == "broad or invalid target refused"
    )


def test_successful_recovery_writes_valid_receipt_and_verify_works(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    fake = FakeDocker(before_started="2026-06-08T00:10:00Z", after_started="2026-06-08T00:10:05Z")
    payload = execute_receipt_recovery(receipt["receipt_id"], tmp_path, confirm=True, docker=fake)
    assert payload["mode"] == "v2_receipt_recovery_execute"
    assert payload["status"] == "executed"
    assert fake.restart_calls == [["docker", "restart", "sfai-pr170-user-sim"]]
    assert payload["action"]["argv"] == ["docker", "restart", "sfai-pr170-user-sim"]
    assert payload["action"]["docker_restart_attempted"] is True
    assert payload["action"]["docker_restart_succeeded"] is True
    assert payload["verification"]["started_at_changed"] is True
    for key, expected in {
        "mutation_performed": True,
        "recovery_executed": True,
        "container_restarted": True,
        "docker_compose_executed": False,
        "production_restart_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
    }.items():
        assert payload["safety"][key] is expected
    rid = payload["recovery_receipt_id"]
    assert (tmp_path / "recipe_receipts" / rid / "receipt.json").exists()
    assert validate_receipt(rid, tmp_path)["status"] == "ok"
    verify = verify_recipe_receipt(rid, tmp_path)
    assert verify["status"] == "passed"
    assert verify["safety"]["container_restarted_by_verify"] is False


def test_failed_docker_command_writes_controlled_failed_recovery_receipt(tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    payload = execute_receipt_recovery(
        receipt["receipt_id"], tmp_path, confirm=True, docker=FakeDocker(return_code=1)
    )
    assert payload["status"] == "failed"
    assert payload["action"]["docker_restart_attempted"] is True
    assert payload["action"]["docker_restart_succeeded"] is False
    assert payload["verification"]["status"] == "failed"
    assert payload["safety"]["container_restarted"] is False
    assert payload["recovery_receipt_id"]


def test_cli_json_and_human_contracts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _receipt(tmp_path)
    no_confirm = runner.invoke(
        app, ["recipes", "receipt", "recovery-execute", receipt["receipt_id"], "--json"]
    )
    assert no_confirm.exit_code != 0
    no_confirm_payload = json.loads(no_confirm.stdout)
    assert no_confirm_payload["status"] == "blocked"
    assert no_confirm_payload["mutation_performed"] is False
    assert no_confirm_payload["safety"]["container_restarted"] is False

    # CLI uses the real Docker client; a missing daemon is a controlled failure, not traceback.
    failed = runner.invoke(
        app,
        ["recipes", "receipt", "recovery-execute", receipt["receipt_id"], "--confirm", "--json"],
    )
    assert "Traceback" not in failed.stdout + failed.stderr
    assert failed.stdout.strip().startswith("{")


def test_ask_routing_recovery_help_and_refusals(tmp_path: Path) -> None:
    rid = "receipt_abc"
    help_res = runner.invoke(app, ["ask", f"how would I recover receipt {rid}?"])
    assert help_res.exit_code == 0
    assert f"shellforgeai recipes receipt recovery-execute {rid} --confirm" in help_res.stdout
    assert "No action was taken" in help_res.stdout
    for prompt in ("run recovery", "rollback now", "show recovery command and run it"):
        res = runner.invoke(app, ["ask", prompt])
        assert res.exit_code == 0
        assert "Refused" in res.stdout
        assert "recovery-execute <receipt_id> --confirm" in res.stdout
        assert "No action was taken" in res.stdout


def test_interactive_routing_exact_command_and_natural_language_refusals() -> None:
    routed = route_input("recipes receipt recovery-execute receipt_abc --confirm --json")
    assert routed.name == "cli_dispatch"
    assert routed.argv == (
        "recipes",
        "receipt",
        "recovery-execute",
        "receipt_abc",
        "--confirm",
        "--json",
    )
    no_confirm = route_input("recipes receipt recovery-execute receipt_abc")
    assert no_confirm.name == "cli_dispatch"
    assert route_input("restart it again").name == "mutation_refused"
    assert route_input("run recovery").name == "mutation_refused"
