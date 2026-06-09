from __future__ import annotations

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
    receipt_audit_bundle,
    receipt_audit_bundle_validate,
)
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import _dispatch_label

runner = CliRunner()


class FakeDocker:
    def __init__(self, *, after: str = "2026-06-08T00:00:04Z") -> None:
        self.after = after
        self.restart_calls: list[list[str]] = []
        self.inspect_calls = 0

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        return DockerContainerState(
            found=True,
            name=target,
            container_id="abc123",
            started_at="2026-06-08T00:00:00Z" if self.inspect_calls == 1 else self.after,
            labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
        )

    def restart(self, target: str) -> CommandResult:
        argv = ["docker", "restart", target]
        self.restart_calls.append(argv)
        return CommandResult(argv=argv, return_code=0, stdout=f"{target}\n", stderr="")


def _make_receipt(data_dir: Path, target: str = "sfai-pr173-one") -> str:
    packet = build_preflight_packet(
        "docker.disposable_restart",
        target,
        scene={
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
        },
    )
    saved = save_preflight_packet(packet, data_dir)
    result = execute_disposable_restart(
        saved["preflight_id"], data_dir, confirm=True, docker=FakeDocker()
    )
    return str(result["receipt_id"])


def _json(result) -> dict:  # noqa: ANN001
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    return json.loads(result.stdout)


def test_bundle_creation_writes_required_files_and_human_first_safe(
    tmp_path: Path, monkeypatch
) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _make_receipt(tmp_path)
    result = runner.invoke(app, ["recipes", "receipt", "audit-bundle"])
    assert result.exit_code == 0, result.stdout
    assert "Governed recipe audit bundle: created" in result.stdout
    assert "First safe command:" in result.stdout
    bundle_line = next(line for line in result.stdout.splitlines() if line.startswith("Path: "))
    bundle_dir = Path(bundle_line.removeprefix("Path: "))
    assert bundle_dir.is_relative_to(tmp_path / "exports" / "receipt-audit-bundles")
    for name in (
        "audit-bundle.json",
        "audit-bundle.md",
        "receipt-audit.json",
        "receipt-history.json",
        "manifest.json",
        "checksums.json",
    ):
        assert (bundle_dir / name).is_file()
    payload = json.loads((bundle_dir / "audit-bundle.json").read_text(encoding="utf-8"))
    assert payload["artifact_export_only"] is True
    assert payload["mutation_performed"] is False


def test_bundle_json_empty_history_and_safety_flags(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["recipes", "receipt", "audit-bundle", "--json"])
    assert result.exit_code == 0
    payload = _json(result)
    assert payload["status"] == "created"
    assert payload["summary"]["receipts_summarized"] == 0
    assert payload["safety"]["cleanup_executed"] is False
    assert payload["safety"]["remediation_executed"] is False
    assert payload["safety"]["rollback_executed"] is False
    assert payload["safety"]["recovery_executed"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["container_restarted"] is False
    assert payload["safety"]["production_restart_executed"] is False
    assert payload["safety"]["shell_true"] is False
    assert payload["safety"]["arbitrary_command_execution"] is False
    assert payload["safety"]["natural_language_execution"] is False
    assert payload["safety"]["model_called"] is False
    assert Path(payload["bundle"]["path"]).is_dir()


def test_bundle_filters_limit_and_optional_files(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _make_receipt(tmp_path, "sfai-pr173-target")
    _make_receipt(tmp_path, "sfai-pr173-other")
    result = runner.invoke(
        app,
        [
            "recipes",
            "receipt",
            "audit-bundle",
            "--target",
            "sfai-pr173-target",
            "--json",
        ],
    )
    payload = _json(result)
    assert payload["filters"]["target"] == "sfai-pr173-target"
    assert payload["summary"]["receipts_summarized"] == 1
    result = runner.invoke(
        app,
        ["recipes", "receipt", "audit-bundle", "--recipe", "docker.disposable_restart", "--json"],
    )
    assert _json(result)["filters"]["recipe_id"] == "docker.disposable_restart"
    result = runner.invoke(app, ["recipes", "receipt", "audit-bundle", "--limit", "1", "--json"])
    payload = _json(result)
    assert payload["filters"]["limit"] == 1
    assert payload["summary"]["receipts_summarized"] == 1
    result = runner.invoke(
        app,
        [
            "recipes",
            "receipt",
            "audit-bundle",
            "--include-exports",
            "--include-compare-summary",
            "--json",
        ],
    )
    payload = _json(result)
    assert "receipt-export-index.json" in payload["bundle"]["files"]
    assert "receipt-compare-summary.json" in payload["bundle"]["files"]


def test_invalid_limit_fails_cleanly(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["recipes", "receipt", "audit-bundle", "--limit", "0", "--json"])
    assert result.exit_code != 0
    assert "Traceback" not in result.stdout


def test_bundle_validate_ok_json_missing_corrupt_and_traversal(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    created = receipt_audit_bundle(tmp_path)
    bundle_id = created["bundle_id"]
    ok = runner.invoke(app, ["recipes", "receipt", "audit-bundle-validate", bundle_id, "--json"])
    assert ok.exit_code == 0
    assert _json(ok)["status"] == "ok"
    human = runner.invoke(app, ["recipes", "receipt", "audit-bundle-validate", bundle_id])
    assert human.exit_code == 0
    assert "Checksum status: ok" in human.stdout
    missing = runner.invoke(
        app, ["recipes", "receipt", "audit-bundle-validate", "missing-bundle", "--json"]
    )
    assert missing.exit_code != 0
    assert _json(missing)["status"] == "not_found"
    bundle_dir = Path(created["bundle"]["path"])
    (bundle_dir / "audit-bundle.md").unlink()
    failed = receipt_audit_bundle_validate(bundle_id, tmp_path)
    assert failed["status"] == "failed"
    assert any(
        item["name"] == "audit-bundle.md" and item["status"] == "missing"
        for item in failed["required_files"]
    )
    (bundle_dir / "audit-bundle.md").write_text("changed", encoding="utf-8")
    failed = receipt_audit_bundle_validate(bundle_id, tmp_path)
    assert failed["status"] == "failed"
    assert failed["checksum_status"] == "failed"
    traversal = runner.invoke(
        app, ["recipes", "receipt", "audit-bundle-validate", "../x", "--json"]
    )
    assert traversal.exit_code != 0
    assert _json(traversal)["status"] == "not_found"


def test_ask_routing_bundle_guidance_and_mutation_refusals() -> None:
    for prompt in (
        "create receipt audit bundle",
        "create recipe audit support packet",
        "validate audit bundle audit_bundle_20260608_203015_ab12cd",
        "show command to create audit bundle",
    ):
        result = runner.invoke(app, ["ask", prompt])
        assert result.exit_code == 0
        assert "audit-bundle" in result.stdout
        assert "No action was taken" in result.stdout
    for prompt in ("bundle audit then restart it", "export and recover now"):
        result = runner.invoke(app, ["ask", prompt])
        assert result.exit_code == 0
        assert "Refused" in result.stdout
        assert "No action was taken" in result.stdout


def test_interactive_routes_bundle_validate_and_polished_audit_label() -> None:
    assert route_input("recipes receipt audit-bundle").argv == (
        "recipes",
        "receipt",
        "audit-bundle",
    )
    assert route_input("recipes receipt audit-bundle --json").argv == (
        "recipes",
        "receipt",
        "audit-bundle",
        "--json",
    )
    assert route_input("recipes receipt audit-bundle --target sfai-pr173").argv == (
        "recipes",
        "receipt",
        "audit-bundle",
        "--target",
        "sfai-pr173",
    )
    assert route_input("recipes receipt audit-bundle-validate audit_bundle_abc --json").argv == (
        "recipes",
        "receipt",
        "audit-bundle-validate",
        "audit_bundle_abc",
        "--json",
    )
    assert route_input("restart from receipt").name == "mutation_refused"
    assert (
        _dispatch_label(("recipes", "receipt", "audit", "--target", "x"))
        == "Running read-only receipt audit..."
    )
    assert "recipe registry" not in _dispatch_label(
        ("recipes", "receipt", "audit", "--target", "x")
    )
