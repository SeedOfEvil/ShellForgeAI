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
from shellforgeai.core.recipe_receipt_audit import receipt_audit
from shellforgeai.core.recipe_receipt_recovery import execute_receipt_recovery
from shellforgeai.interactive.commands import route_input

runner = CliRunner()


class FakeDocker:
    def __init__(
        self,
        *,
        before: str = "2026-06-08T00:00:00Z",
        after: str = "2026-06-08T00:00:04Z",
        return_code: int = 0,
    ) -> None:
        self.before = before
        self.after = after
        self.return_code = return_code
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
        return CommandResult(
            argv=argv, return_code=self.return_code, stdout=f"{target}\n", stderr=""
        )


def _execution_receipt(
    data_dir: Path,
    target: str = "sfai-pr172-user-sim",
    *,
    recipe_id: str = "docker.disposable_restart",
    fake: FakeDocker | None = None,
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
        saved["preflight_id"], data_dir, confirm=True, docker=fake or FakeDocker()
    )
    assert result["receipt_id"]
    if recipe_id != "docker.disposable_restart":
        _rewrite_receipt(
            Path(result["receipt"]["path"]), lambda p: p.__setitem__("recipe_id", recipe_id)
        )
    return result


def _rewrite_receipt(receipt_dir: Path, mutate) -> dict:  # noqa: ANN001
    p = receipt_dir / "recipe-receipt.json"
    payload = json.loads(p.read_text(encoding="utf-8"))
    mutate(payload)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path = receipt_dir / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.setdefault("checksums", {})["recipe-receipt.json"] = hashlib.sha256(
            p.read_bytes()
        ).hexdigest()
        manifest["recipe_id"] = payload.get("recipe_id")
        manifest["target"] = payload.get("target")
        manifest["safety"] = payload.get("safety", {})
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return payload


def test_audit_empty_history_returns_strict_json(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["recipes", "receipt", "audit", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert result.stdout.strip().startswith("{") and result.stdout.strip().endswith("}")
    assert payload["status"] == "empty"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["summary"]["receipts_found"] == 0
    assert payload["first_safe_command"] == "shellforgeai recipes receipt history --json"


def test_audit_execution_and_human_first_safe_command(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt = _execution_receipt(tmp_path)
    payload = receipt_audit(tmp_path)
    assert payload["status"] == "ok"
    assert payload["summary"]["execution_receipts"] == 1
    assert payload["chains"][0]["original_receipt_id"] == receipt["receipt_id"]
    assert payload["chains"][0]["receipts"][0]["verification_status"] == "passed"
    human = runner.invoke(app, ["recipes", "receipt", "audit"])
    assert human.exit_code == 0
    assert "Governed recipe audit" in human.stdout
    assert "First safe command:" in human.stdout
    assert "Read-only audit." in human.stdout


def test_audit_recovery_links_to_original(tmp_path: Path) -> None:
    first = _execution_receipt(tmp_path)
    recovery = execute_receipt_recovery(
        first["receipt_id"], tmp_path, confirm=True, docker=FakeDocker(after="2026-06-08T00:01:00Z")
    )
    payload = receipt_audit(tmp_path)
    assert payload["summary"]["recovery_receipts"] == 1
    chain = payload["chains"][0]
    assert chain["original_receipt_id"] == first["receipt_id"]
    assert recovery["recovery_receipt_id"] in [r["receipt_id"] for r in chain["receipts"]]
    assert any(f["kind"] == "recovery_links_original" for f in payload["findings"])


def test_audit_filters_and_limit(tmp_path: Path) -> None:
    one = _execution_receipt(tmp_path, target="sfai-pr172-one")
    _execution_receipt(tmp_path, target="sfai-pr172-two", recipe_id="custom.recipe")
    assert receipt_audit(tmp_path, target="sfai-pr172-one")["summary"]["receipts_found"] == 1
    assert (
        receipt_audit(tmp_path, recipe_id="custom.recipe")["chains"][0]["recipe_id"]
        == "custom.recipe"
    )
    limited = receipt_audit(tmp_path, limit=1)
    assert limited["summary"]["receipts_found"] == 1
    no_match = receipt_audit(tmp_path, target="missing")
    assert no_match["status"] == "no_matches"
    assert one["receipt_id"]


def test_invalid_limit_fails_cleanly(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["recipes", "receipt", "audit", "--limit", "0"])
    assert result.exit_code != 0
    assert "Invalid value" in result.output or "must be" in result.output


def test_audit_missing_original_and_malformed_do_not_crash(tmp_path: Path) -> None:
    first = _execution_receipt(tmp_path)
    recovery = execute_receipt_recovery(
        first["receipt_id"], tmp_path, confirm=True, docker=FakeDocker(after="2026-06-08T00:02:00Z")
    )
    original_dir = Path(first["receipt"]["path"])
    for child in original_dir.iterdir():
        child.unlink()
    original_dir.rmdir()
    bad = tmp_path / "recipe_receipts" / "bad"
    bad.mkdir(parents=True)
    (bad / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    payload = receipt_audit(tmp_path)
    assert payload["status"] == "ok"
    assert payload["summary"]["missing_original_receipts"] == 1
    assert any(f["kind"] == "malformed_receipt" for f in payload["findings"])
    assert recovery["recovery_receipt_id"]


def test_audit_counts_verification_failed_and_safety_flags(tmp_path: Path) -> None:
    failed = _execution_receipt(
        tmp_path, target="sfai-pr172-failed", fake=FakeDocker(return_code=1)
    )
    flagged = _execution_receipt(tmp_path, target="sfai-pr172-flagged")
    flag_dir = Path(flagged["receipt"]["path"])
    _rewrite_receipt(
        flag_dir,
        lambda p: [
            p["safety"].__setitem__("production_restart_executed", True),
            p["safety"].__setitem__("docker_compose_executed", True),
            p["safety"].__setitem__("shell_true", True),
            p["safety"].__setitem__("arbitrary_command_execution", True),
            p["safety"].__setitem__("natural_language_execution", True),
        ],
    )
    payload = receipt_audit(tmp_path)
    assert payload["summary"]["verification_failed"] == 1
    assert payload["summary"]["failed_receipts"] == 1
    assert payload["summary"]["production_restart_recorded"] == 1
    assert payload["summary"]["safety_drift"] == 1
    warnings = "\n".join(payload["warnings"])
    for key in (
        "production_restart_executed",
        "docker_compose_executed",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
    ):
        assert key in warnings
    assert failed["receipt_id"]


def test_include_flags_are_read_only_metadata_summary(tmp_path: Path) -> None:
    _execution_receipt(tmp_path)
    payload = receipt_audit(tmp_path, include_exports=True, include_compare_summary=True)
    assert payload["filters"]["include_exports"] is True
    assert payload["filters"]["include_compare_summary"] is True
    assert "exports" in payload["chains"][0]["receipts"][0]
    assert payload["compare_summary"]["command"].startswith("shellforgeai recipes receipt compare")
    assert payload["safety"]["container_restarted"] is False


def test_ask_routing_audit_and_mutation_refusals() -> None:
    for prompt in (
        "audit recipe receipts",
        "what happened with the restart recipe?",
        "what happened in the last recovery?",
    ):
        result = runner.invoke(app, ["ask", prompt])
        assert result.exit_code == 0
        assert "recipes receipt audit" in result.stdout
        assert "No action was taken" in result.stdout
    for prompt in ("rerun the last receipt", "restart from the receipt"):
        refused = runner.invoke(app, ["ask", prompt])
        assert refused.exit_code == 0
        assert "Refused" in refused.stdout
        assert "No action was taken" in refused.stdout


def test_interactive_routes_audit_and_refuses_mutation() -> None:
    assert route_input("recipes receipt audit").argv == ("recipes", "receipt", "audit")
    assert route_input("recipes receipt audit --json").argv == (
        "recipes",
        "receipt",
        "audit",
        "--json",
    )
    assert route_input("recipes receipt audit --target sfai-pr172-one").argv == (
        "recipes",
        "receipt",
        "audit",
        "--target",
        "sfai-pr172-one",
    )
    assert route_input("audit governed actions").argv == ("recipes", "receipt", "audit")
    assert route_input("rerun receipt").name == "mutation_refused"


def test_audit_safety_contract(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _execution_receipt(tmp_path)

    def fail_run(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("receipt audit must not run subprocess")

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", fail_run)
    before = {p.relative_to(tmp_path): p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    result = runner.invoke(app, ["recipes", "receipt", "audit", "--json"])
    after = {p.relative_to(tmp_path): p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    assert result.exit_code == 0
    assert before == after
    payload = json.loads(result.stdout)
    safety = payload["safety"]
    for key in (
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
    ):
        assert safety[key] is False
