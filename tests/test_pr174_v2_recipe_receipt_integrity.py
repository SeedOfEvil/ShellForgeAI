from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.recipe_execution import RECEIPT_MODE, RECOVERY_RECEIPT_MODE, SCHEMA_VERSION
from shellforgeai.core.recipe_receipt_audit import receipt_integrity
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import _dispatch_label

runner = CliRunner()


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _receipt(
    data: Path,
    rid: str,
    *,
    mode: str = RECEIPT_MODE,
    target: str = "sfai-pr174-one",
    recipe_id: str = "docker.disposable_restart",
    safety: dict | None = None,
    original: str | None = None,
    created: str = "2026-06-09T00:00:00Z",
) -> Path:
    d = data / "recipe_receipts" / rid
    d.mkdir(parents=True)
    safety_payload = {
        "read_only": False,
        "mutation_performed": False,
        "docker_compose_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "production_restart_executed": False,
        "exact_target_only": True,
    }
    if safety:
        safety_payload.update(safety)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "receipt_id": rid,
        "recipe_id": recipe_id,
        "target": target,
        "status": "executed",
        "created_at": created,
        "verification": {"status": "passed"},
        "safety": safety_payload,
    }
    if original:
        payload["original_receipt_id"] = original
    _write_json(d / "recipe-receipt.json", payload)
    (d / "recipe-receipt.md").write_text(f"# {rid}\n", encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "v2_recipe_execution_receipt",
        "recipe_id": recipe_id,
        "target": target,
        "files": ["recipe-receipt.json", "recipe-receipt.md", "manifest.json"],
        "checksums": {
            "recipe-receipt.json": _sha(d / "recipe-receipt.json"),
            "recipe-receipt.md": _sha(d / "recipe-receipt.md"),
        },
        "safety": safety_payload,
    }
    _write_json(d / "manifest.json", manifest)
    return d


def _export(data: Path, source_id: str, *, corrupt: bool = False) -> Path:
    d = data / "exports" / "receipt_exports" / f"export_{source_id}"
    d.mkdir(parents=True)
    (d / "recipe-receipt.json").write_text('{"ok": true}\n', encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "v2_recipe_receipt_export",
        "source_receipt_id": source_id,
        "recipe_id": "docker.disposable_restart",
        "target": "sfai-pr174-one",
        "files": ["recipe-receipt.json", "export-manifest.json"],
        "checksums": {"recipe-receipt.json": "bad" if corrupt else _sha(d / "recipe-receipt.json")},
        "safety": {
            "docker_compose_executed": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
        },
    }
    _write_json(d / "export-manifest.json", manifest)
    return d


def _bundle(data: Path, *, missing: bool = False) -> Path:
    d = data / "exports" / "receipt-audit-bundles" / "audit_bundle_pr174"
    d.mkdir(parents=True)
    required = [
        "audit-bundle.json",
        "audit-bundle.md",
        "receipt-audit.json",
        "receipt-history.json",
        "manifest.json",
        "checksums.json",
    ]
    for name in required:
        if name == "manifest.json" or name == "checksums.json":
            continue
        if missing and name == "receipt-history.json":
            continue
        if name.endswith(".json"):
            _write_json(d / name, {"name": name})
        else:
            (d / name).write_text("bundle\n", encoding="utf-8")
    files = [name for name in required if not (missing and name == "receipt-history.json")]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "v2_recipe_receipt_audit_bundle",
        "bundle_id": "audit_bundle_pr174",
        "files": required,
        "filters": {},
        "checksums": {
            "stored_in": "checksums.json",
            "covers": [f for f in files if f != "checksums.json"],
        },
    }
    _write_json(d / "manifest.json", manifest)
    checks = {
        name: _sha(d / name) for name in files if name != "checksums.json" and (d / name).exists()
    }
    _write_json(d / "checksums.json", {"algorithm": "sha256", "checksums": checks})
    return d


def _json_result(args: list[str], tmp_path: Path, monkeypatch) -> dict:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert result.stdout.strip().startswith("{") and result.stdout.strip().endswith("}")
    return json.loads(result.stdout)


def test_integrity_empty_history_returns_strict_json_and_safety(
    tmp_path: Path, monkeypatch
) -> None:  # noqa: ANN001
    payload = _json_result(["recipes", "receipt", "integrity", "--json"], tmp_path, monkeypatch)
    assert payload["status"] == "empty"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["first_safe_command"] == "shellforgeai recipes receipt history --json"
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
        assert payload["safety"][key] is False


def test_integrity_valid_execution_recovery_and_human_first_safe(
    tmp_path: Path, monkeypatch
) -> None:  # noqa: ANN001
    _receipt(tmp_path, "receipt_one")
    _receipt(tmp_path, "recovery_receipt_one", mode=RECOVERY_RECEIPT_MODE, original="receipt_one")
    payload = receipt_integrity(tmp_path)
    assert payload["status"] == "ok"
    assert payload["summary"]["receipts_scanned"] == 2
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["recipes", "receipt", "integrity"])
    assert result.exit_code == 0
    assert "Governed receipt artifact integrity scan" in result.stdout
    assert "First safe command:" in result.stdout
    assert "Read-only integrity scan." in result.stdout


def test_integrity_findings_do_not_crash(tmp_path: Path) -> None:
    _receipt(tmp_path, "receipt_good")
    bad = tmp_path / "recipe_receipts" / "bad_json"
    bad.mkdir(parents=True)
    (bad / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    missing = tmp_path / "recipe_receipts" / "missing_file"
    missing.mkdir(parents=True)
    _receipt(tmp_path, "recovery_missing", mode=RECOVERY_RECEIPT_MODE, original="missing_original")
    unsupported = _receipt(tmp_path, "unsupported")
    payload = json.loads((unsupported / "recipe-receipt.json").read_text(encoding="utf-8"))
    payload["mode"] = "surprise"
    _write_json(unsupported / "recipe-receipt.json", payload)
    drift = _receipt(tmp_path, "drift")
    (drift / "recipe-receipt.md").write_text("changed\n", encoding="utf-8")
    result = receipt_integrity(tmp_path, limit=20)
    assert result["status"] == "ok_with_warnings"
    assert result["summary"]["malformed_json"] >= 1
    assert result["summary"]["missing_required_files"] >= 1
    assert result["summary"]["missing_original_receipts"] >= 1
    assert result["summary"]["unsupported_artifacts"] >= 1
    assert result["summary"]["checksum_failures"] >= 1
    assert result["findings"]


def test_integrity_safety_flags_are_flagged(tmp_path: Path) -> None:
    for key in (
        "production_restart_executed",
        "docker_compose_executed",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
    ):
        _receipt(
            tmp_path,
            f"receipt_{key}",
            safety={key: True},
            created=f"2026-06-09T00:00:0{len(key) % 10}Z",
        )
    payload = receipt_integrity(tmp_path, limit=20)
    messages = "\n".join(f["message"] for f in payload["findings"])
    for key in (
        "production_restart_executed",
        "docker_compose_executed",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
    ):
        assert key in messages
    assert payload["summary"]["production_restart_recorded"] == 1
    assert payload["summary"]["safety_drift"] >= 5


def test_integrity_filters_limit_and_invalid_limit(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    _receipt(tmp_path, "one", target="one", created="2026-06-09T00:00:01Z")
    _receipt(
        tmp_path, "two", target="two", recipe_id="custom.recipe", created="2026-06-09T00:00:02Z"
    )
    assert receipt_integrity(tmp_path, target="one")["summary"]["receipts_scanned"] == 1
    assert (
        receipt_integrity(tmp_path, recipe_id="custom.recipe")["summary"]["receipts_scanned"] == 1
    )
    assert receipt_integrity(tmp_path, limit=1)["summary"]["receipts_scanned"] == 1
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, ["recipes", "receipt", "integrity", "--limit", "0"])
    assert result.exit_code != 0
    assert "Invalid value" in result.output or "must be" in result.output


def test_integrity_include_exports_and_audit_bundles(tmp_path: Path) -> None:
    _receipt(tmp_path, "receipt_one")
    _export(tmp_path, "receipt_one")
    _bundle(tmp_path)
    payload = receipt_integrity(tmp_path, include_exports=True, include_audit_bundles=True)
    assert payload["summary"]["exports_scanned"] == 1
    assert payload["summary"]["audit_bundles_scanned"] == 1
    before = sorted(str(p) for p in (tmp_path / "exports").rglob("*"))
    receipt_integrity(tmp_path, include_exports=True, include_audit_bundles=True)
    after = sorted(str(p) for p in (tmp_path / "exports").rglob("*"))
    assert before == after


def test_integrity_include_exports_and_bundles_detect_corruption(tmp_path: Path) -> None:
    _receipt(tmp_path, "receipt_one")
    _export(tmp_path, "receipt_one", corrupt=True)
    _bundle(tmp_path, missing=True)
    payload = receipt_integrity(tmp_path, include_exports=True, include_audit_bundles=True)
    assert payload["summary"]["checksum_failures"] >= 1
    assert payload["summary"]["missing_required_files"] >= 1
    assert any(f["artifact_type"] == "receipt_export" for f in payload["findings"])
    assert any(f["artifact_type"] == "audit_bundle" for f in payload["findings"])


def test_ask_integrity_and_support_handoff_routes_are_deterministic(
    tmp_path: Path, monkeypatch
) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    for phrase in (
        "check receipt integrity",
        "scan receipt artifacts",
        "check audit bundle integrity",
        "create receipt audit bundle for support handoff",
        "make a support packet for receipt audit",
    ):
        result = runner.invoke(app, ["ask", phrase])
        assert result.exit_code == 0
        assert "deterministic ask routing" in result.stdout
        assert "No action was taken." in result.stdout
        assert "recipes receipt" in result.stdout


def test_ask_mutation_phrasing_refuses_but_offers_safe_read_only_guidance(
    tmp_path: Path, monkeypatch
) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    for phrase in (
        "check integrity and rerun receipt",
        "fix corrupt receipts",
        "create support packet and restart the receipt",
    ):
        result = runner.invoke(app, ["ask", phrase])
        assert result.exit_code == 0
        assert "Refused" in result.stdout
        assert "No action was taken." in result.stdout
        assert (
            "restart" in result.stdout or "integrity" in result.stdout or "bundle" in result.stdout
        )


def test_interactive_integrity_dispatch_and_wording() -> None:
    assert route_input("recipes receipt integrity").argv == ("recipes", "receipt", "integrity")
    assert route_input("recipes receipt integrity --json").argv == (
        "recipes",
        "receipt",
        "integrity",
        "--json",
    )
    assert route_input("recipes receipt integrity --include-audit-bundles").argv == (
        "recipes",
        "receipt",
        "integrity",
        "--include-audit-bundles",
    )
    assert (
        _dispatch_label(("recipes", "receipt", "integrity"))
        == "Running read-only receipt integrity scan..."
    )
    assert (
        _dispatch_label(("recipes", "receipt", "audit-bundle"))
        == "Running read-only receipt audit bundle..."
    )
    assert "recipe registry" not in _dispatch_label(("recipes", "receipt", "audit"))


def test_interactive_mutation_phrases_refuse() -> None:
    for phrase in ("rerun receipt", "cleanup old receipts", "delete bad artifacts"):
        routed = route_input(phrase)
        assert routed.name in {"quick_mutation_refusal", "mutation_refused", "unknown"}
