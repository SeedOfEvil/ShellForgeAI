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
from shellforgeai.core.recipe_receipt_audit import (
    receipt_compare,
    receipt_compare_latest,
    receipt_export_validate,
    receipt_history,
    receipt_inspect,
)
from shellforgeai.core.recipe_receipt_recovery import execute_receipt_recovery
from shellforgeai.interactive.commands import route_input

runner = CliRunner()


class FakeDocker:
    def __init__(
        self, *, before: str = "2026-06-08T00:00:00Z", after: str = "2026-06-08T00:00:04Z"
    ) -> None:
        self.before = before
        self.after = after
        self.inspect_calls = 0
        self.restart_calls: list[list[str]] = []

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        return DockerContainerState(
            found=True,
            name=target,
            container_id="abc123",
            started_at=self.before if self.inspect_calls == 1 else self.after,
            labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
        )

    def restart(self, target: str) -> CommandResult:
        argv = ["docker", "restart", target]
        self.restart_calls.append(argv)
        return CommandResult(argv=argv, return_code=0, stdout=f"{target}\n", stderr="")


def _execution_receipt(
    data_dir: Path, target: str = "sfai-pr171-user-sim", *, after: str = "2026-06-08T00:00:04Z"
) -> dict:
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
    result = execute_disposable_restart(
        saved["preflight_id"], data_dir, confirm=True, docker=FakeDocker(after=after)
    )
    assert result["status"] == "executed"
    return result


def _rewrite_receipt(receipt_dir: Path, mutate) -> None:  # noqa: ANN001
    p = receipt_dir / "recipe-receipt.json"
    payload = json.loads(p.read_text(encoding="utf-8"))
    mutate(payload)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = json.loads((receipt_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["checksums"]["recipe-receipt.json"] = hashlib.sha256(p.read_bytes()).hexdigest()
    manifest["recipe_id"] = payload.get("recipe_id")
    manifest["target"] = payload.get("target")
    (receipt_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_history_empty_json_is_clean(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["recipes", "receipt", "history", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "empty"
    assert payload["count"] == 0
    assert payload["safety"]["model_called"] is False
    assert payload["safety"]["container_restarted"] is False


def test_history_lists_execution_and_recovery_newest_first_and_limit(tmp_path: Path) -> None:
    first = _execution_receipt(tmp_path)
    recovery = execute_receipt_recovery(
        first["receipt_id"], tmp_path, confirm=True, docker=FakeDocker(after="2026-06-08T00:01:00Z")
    )
    assert recovery["status"] == "executed"
    payload = receipt_history(tmp_path, limit=1)
    assert payload["count"] == 1
    assert payload["receipts"][0]["receipt_id"] == recovery["recovery_receipt_id"]
    assert payload["receipts"][0]["original_receipt_id"] == first["receipt_id"]
    assert payload["safety"]["recovery_executed"] is False


def test_inspect_execution_and_recovery_receipts(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    first = _execution_receipt(tmp_path)
    recovery = execute_receipt_recovery(
        first["receipt_id"], tmp_path, confirm=True, docker=FakeDocker(after="2026-06-08T00:02:00Z")
    )
    human = runner.invoke(app, ["recipes", "receipt", "inspect", first["receipt_id"]])
    assert human.exit_code == 0
    assert "Recipe receipt audit inspect" in human.stdout
    assert "Action as recorded" in human.stdout
    payload = receipt_inspect(recovery["recovery_receipt_id"], tmp_path)
    assert payload["status"] == "ok"
    assert payload["lineage"]["original_receipt_id"] == first["receipt_id"]
    assert payload["lineage"]["recovery_receipt_id"] == recovery["recovery_receipt_id"]
    assert payload["safety"]["rollback_executed"] is False


def test_inspect_missing_malformed_and_unsupported_fail_cleanly(tmp_path: Path) -> None:
    assert receipt_inspect("missing", tmp_path)["status"] == "not_found"
    bad = tmp_path / "recipe_receipts" / "bad"
    bad.mkdir(parents=True)
    (bad / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    (bad / "recipe-receipt.md").write_text("bad", encoding="utf-8")
    (bad / "manifest.json").write_text("{}", encoding="utf-8")
    assert receipt_inspect("bad", tmp_path)["status"] == "failed"
    unsupported = _execution_receipt(tmp_path, target="sfai-pr171-other")
    d = Path(unsupported["receipt"]["path"])
    _rewrite_receipt(d, lambda p: p.__setitem__("mode", "v2_unknown"))
    assert receipt_inspect(unsupported["receipt_id"], tmp_path)["status"] == "unsupported"


def test_export_and_export_validate_owned_bundle(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _execution_receipt(tmp_path)
    result = runner.invoke(app, ["recipes", "receipt", "export", receipt["receipt_id"], "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert Path(payload["export_path"]).is_relative_to(tmp_path / "exports" / "receipt_exports")
    assert payload["safety"]["docker_compose_executed"] is False
    validation = receipt_export_validate(payload["export_id"], tmp_path)
    assert validation["status"] == "ok"


def test_export_missing_malformed_and_path_traversal_refused(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    missing = runner.invoke(app, ["recipes", "receipt", "export", "../../etc/passwd", "--json"])
    assert missing.exit_code != 0
    payload = json.loads(missing.stdout)
    assert payload["status"] in {"not_found", "failed"}
    assert not (tmp_path / "exports" / "receipt_exports").exists()
    bad_export = tmp_path / "exports" / "receipt_exports" / "bad"
    bad_export.mkdir(parents=True)
    (bad_export / "export-manifest.json").write_text("{bad", encoding="utf-8")
    assert receipt_export_validate("bad", tmp_path)["status"] == "failed"


def test_compare_and_compare_latest(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    assert receipt_compare_latest(tmp_path)["status"] == "not_enough_history"
    one = _execution_receipt(tmp_path, target="sfai-pr171-one", after="2026-06-08T00:00:04Z")
    two = _execution_receipt(tmp_path, target="sfai-pr171-two", after="2026-06-08T00:00:08Z")
    payload = receipt_compare(one["receipt_id"], two["receipt_id"], tmp_path)
    assert payload["status"] == "ok"
    assert "target" in payload["changed"]
    assert "recipe_id" in payload["stable"]
    json_result = runner.invoke(
        app, ["recipes", "receipt", "compare", one["receipt_id"], two["receipt_id"], "--json"]
    )
    assert json.loads(json_result.stdout)["changed"]
    human = runner.invoke(
        app,
        ["recipes", "receipt", "compare", one["receipt_id"], two["receipt_id"], "--only-changed"],
    )
    assert "Stable fields:" not in human.stdout
    latest = runner.invoke(app, ["recipes", "receipt", "compare-latest", "--json"])
    assert json.loads(latest.stdout)["status"] == "ok"


def test_ask_routing_and_mutation_refusals(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _execution_receipt(tmp_path)
    for question, expected in [
        ("show recipe receipt history", "recipes receipt history"),
        (f"inspect receipt {receipt['receipt_id']}", "recipes receipt inspect"),
        ("compare latest receipts", "recipes receipt compare-latest"),
    ]:
        result = runner.invoke(app, ["ask", question])
        assert result.exit_code == 0
        assert expected in result.stdout
        assert "No action was taken" in result.stdout
    for question in [
        "recover latest receipt now",
        "rollback latest receipt",
        "cleanup old receipts",
        "restart it again",
        "rerun the receipt",
        "apply the receipt",
    ]:
        result = runner.invoke(app, ["ask", question])
        assert result.exit_code == 0
        assert "Refused" in result.stdout
        assert "No action was taken" in result.stdout


def test_interactive_exact_safe_dispatch_and_recovery_refusal() -> None:
    assert route_input("recipes receipt history").argv == ("recipes", "receipt", "history")
    assert route_input("recipes receipt inspect receipt_abc123 --json").argv == (
        "recipes",
        "receipt",
        "inspect",
        "receipt_abc123",
        "--json",
    )
    assert route_input("recipes receipt compare receipt_a receipt_b --only-changed").argv == (
        "recipes",
        "receipt",
        "compare",
        "receipt_a",
        "receipt_b",
        "--only-changed",
    )
    assert route_input("recover latest receipt now").name == "mutation_refused"
