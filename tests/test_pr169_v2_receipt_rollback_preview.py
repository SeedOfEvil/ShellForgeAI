from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.recipe_execution import (
    CommandResult,
    DockerContainerState,
    execute_disposable_restart,
)
from shellforgeai.core.recipe_preflight import build_preflight_packet, save_preflight_packet
from shellforgeai.core.recipe_receipt_rollback_preview import preview_receipt_rollback
from shellforgeai.interactive.commands import route_input

runner = CliRunner()


class FakeDocker:
    def __init__(self) -> None:
        self.restart_calls: list[list[str]] = []
        self.inspect_calls = 0

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        return DockerContainerState(
            found=True,
            name=target,
            container_id="abc123",
            started_at="2026-06-07T00:00:03Z" if self.inspect_calls > 1 else "2026-06-07T00:00:00Z",
            labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
        )

    def restart(self, target: str) -> CommandResult:
        argv = ["docker", "restart", target]
        self.restart_calls.append(argv)
        return CommandResult(argv=argv, return_code=0, stdout=f"{target}\n", stderr="")


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


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


def _receipt(tmp_path: Path, monkeypatch, target: str = "sfai-pr169-user-sim") -> dict:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
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
    fake = FakeDocker()
    result = execute_disposable_restart(saved["preflight_id"], tmp_path, confirm=True, docker=fake)
    assert result["status"] == "executed"
    assert fake.restart_calls == [["docker", "restart", target]]
    return result


def _mutate_receipt(receipt: dict, mutate) -> None:  # noqa: ANN001
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
    _resign_receipt(receipt_dir)


def test_cli_human_valid_disposable_receipt_limited_no_true_rollback(
    tmp_path: Path, monkeypatch
) -> None:
    receipt = _receipt(tmp_path, monkeypatch)
    result = runner.invoke(app, ["recipes", "receipt", "rollback-preview", receipt["receipt_id"]])
    assert result.exit_code == 0
    assert "Rollback preview: gated / limited" in result.stdout
    assert "Recipe: docker.disposable_restart" in result.stdout
    assert "Target: sfai-pr169-user-sim" in result.stdout
    assert "No true state rollback is available for a container restart" in result.stdout
    assert "No rollback was executed" in result.stdout
    assert f"shellforgeai verify --receipt {receipt['receipt_id']} --json" in result.stdout
    assert (
        "No Docker, Compose, remediation, cleanup, shell, or arbitrary command was executed"
        in result.stdout
    )


def test_missing_and_malformed_receipts_fail_cleanly(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    missing = runner.invoke(app, ["recipes", "receipt", "rollback-preview", "missing", "--json"])
    assert missing.exit_code != 0
    assert "Traceback" not in missing.stdout + missing.stderr
    assert json.loads(missing.stdout)["status"] == "not_found"

    bad_dir = tmp_path / "recipe_receipts" / "bad"
    bad_dir.mkdir(parents=True)
    (bad_dir / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    malformed = runner.invoke(app, ["recipes", "receipt", "rollback-preview", "bad", "--json"])
    assert malformed.exit_code != 0
    assert "Traceback" not in malformed.stdout + malformed.stderr
    assert json.loads(malformed.stdout)["status"] == "failed"


def test_unsupported_recipe_and_production_target_statuses(tmp_path: Path, monkeypatch) -> None:
    unsupported = _receipt(tmp_path, monkeypatch)
    _mutate_receipt(
        unsupported, lambda payload: payload.update({"recipe_id": "example.unsupported"})
    )
    unsupported_res = runner.invoke(
        app, ["recipes", "receipt", "rollback-preview", unsupported["receipt_id"], "--json"]
    )
    assert unsupported_res.exit_code == 0
    unsupported_payload = json.loads(unsupported_res.stdout)
    assert unsupported_payload["status"] == "unsupported_recipe"
    assert unsupported_payload["first_safe_command"].startswith(
        "shellforgeai recipes receipt verify"
    )
    assert unsupported_payload["safety"]["mutation_performed"] is False

    prod = _receipt(tmp_path, monkeypatch, target="sfai-pr169-prod-sim")
    _mutate_receipt(
        prod,
        lambda payload: payload["post_state"].update({"production_target": True}),
    )
    prod_res = runner.invoke(
        app, ["recipes", "receipt", "rollback-preview", prod["receipt_id"], "--json"]
    )
    assert prod_res.exit_code != 0
    prod_payload = json.loads(prod_res.stdout)
    assert prod_payload["status"] == "blocked"
    assert prod_payload["reason"] == "production target refused for rollback/recovery"
    assert prod_payload["safety"]["container_restarted"] is False


def test_json_contract_strict_and_safety_complete(tmp_path: Path, monkeypatch) -> None:
    receipt = _receipt(tmp_path, monkeypatch)
    result = runner.invoke(
        app, ["recipes", "receipt", "rollback-preview", receipt["receipt_id"], "--json"]
    )
    assert result.exit_code == 0
    assert result.stdout.strip().startswith("{") and result.stdout.strip().endswith("}")
    payload = json.loads(result.stdout)
    assert payload["mode"] == "v2_receipt_rollback_preview"
    assert payload["status"] == "limited"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["recipe_id"] == "docker.disposable_restart"
    assert payload["rollback"]["true_rollback_available"] is False
    assert payload["rollback"]["execution_available"] is False
    for key in (
        "rollback_executed",
        "remediation_executed",
        "cleanup_executed",
        "docker_compose_executed",
        "container_restarted",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
    ):
        assert payload["safety"][key] is False
        assert payload[key] is False
    assert (
        payload["first_safe_command"]
        == f"shellforgeai verify --receipt {receipt['receipt_id']} --json"
    )


def test_core_preview_does_not_call_docker_or_shell(tmp_path: Path, monkeypatch) -> None:
    receipt = _receipt(tmp_path, monkeypatch)
    payload = preview_receipt_rollback(receipt["receipt_id"], tmp_path)
    assert payload["read_only"] is True
    assert payload["safety"]["rollback_executed"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["shell_true"] is False


def test_ask_routing_preview_and_mutation_refusal(tmp_path: Path, monkeypatch) -> None:
    receipt = _receipt(tmp_path, monkeypatch)
    rid = receipt["receipt_id"]
    preview = runner.invoke(app, ["ask", f"show rollback preview for receipt {rid}"])
    assert preview.exit_code == 0
    assert f"shellforgeai recipes receipt rollback-preview {rid}" in preview.stdout
    assert "No action was taken" in preview.stdout

    missing_ref = runner.invoke(app, ["ask", "can this receipt be rolled back?"])
    assert missing_ref.exit_code == 0
    assert "Receipt id/ref required" in missing_ref.stdout

    for prompt in ("rollback now", "execute rollback"):
        refused = runner.invoke(app, ["ask", prompt])
        assert refused.exit_code == 0
        assert "Refused" in refused.stdout
        assert "No action was taken" in refused.stdout

    mixed = runner.invoke(
        app, ["ask", f"show rollback preview for receipt {rid} and then rollback"]
    )
    assert mixed.exit_code == 0
    assert f"shellforgeai recipes receipt rollback-preview {rid}" in mixed.stdout
    assert "Refused rollback execution" in mixed.stdout
    assert "No action was taken" in mixed.stdout


def test_interactive_routing_and_help_mentions_rollback_preview() -> None:
    routed = route_input("recipes receipt rollback-preview receipt_abc --json")
    assert routed.name == "cli_dispatch"
    assert routed.argv == ("recipes", "receipt", "rollback-preview", "receipt_abc", "--json")
    optional = route_input("rollback-preview --receipt receipt_abc --json")
    assert optional.name == "cli_dispatch"
    assert optional.argv == ("rollback-preview", "--receipt", "receipt_abc", "--json")
    assert route_input("rollback now").name == "mutation_refused"
    from shellforgeai.interactive.repl import INTERACTIVE_HELP_TEXT

    assert "rollback-preview" in INTERACTIVE_HELP_TEXT
