from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.recipe_execution import RECEIPT_MODE, RECOVERY_RECEIPT_MODE, SCHEMA_VERSION
from shellforgeai.core.recipe_receipt_explain import receipt_explain
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
    target: str = "sfai-pr175-one",
    recipe_id: str = "docker.disposable_restart",
    mode: str = RECEIPT_MODE,
    original: str | None = None,
    safety: dict | None = None,
    verification: str = "passed",
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
        "container_restarted": False,
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
        "created_at": "2026-06-09T00:00:00Z",
        "verification": {"status": verification},
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


def _bundle(data: Path) -> None:
    d = data / "exports" / "receipt-audit-bundles" / "audit_bundle_pr175"
    d.mkdir(parents=True)
    _write_json(d / "audit-bundle.json", {"bundle_id": "audit_bundle_pr175"})
    (d / "audit-bundle.md").write_text("bundle\n", encoding="utf-8")
    _write_json(d / "receipt-audit.json", {})
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "v2_recipe_receipt_audit_bundle",
        "bundle_id": "audit_bundle_pr175",
        "files": [
            "audit-bundle.json",
            "audit-bundle.md",
            "receipt-audit.json",
            "receipt-history.json",
            "manifest.json",
            "checksums.json",
        ],
        "checksums": {},
    }
    _write_json(d / "manifest.json", manifest)
    _write_json(d / "checksums.json", {"audit-bundle.json": "bad"})


def _invoke(tmp_path: Path, monkeypatch, args: list[str]):  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    return runner.invoke(app, args)


def test_explain_no_findings_and_json_contract(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    result = _invoke(tmp_path, monkeypatch, ["recipes", "receipt", "explain"])
    assert result.exit_code == 0
    assert "Governed receipt finding explanation" in result.stdout
    assert "Findings: none" in result.stdout
    assert "First safe command:" in result.stdout
    assert (
        "No repair, cleanup, recovery, rollback, Docker, or Compose command was executed."
        in result.stdout
    )

    json_result = _invoke(tmp_path, monkeypatch, ["recipes", "receipt", "explain", "--json"])
    assert json_result.exit_code == 0
    payload = json.loads(json_result.stdout)
    assert payload["mode"] == "v2_recipe_receipt_finding_explain"
    assert payload["status"] in {"no_findings", "ok"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["repair_attempted"] is False
    assert payload["safety"]["artifact_deleted"] is False
    assert payload["safe_next_commands"]


def test_specific_known_and_unknown_findings_are_deterministic(tmp_path: Path) -> None:
    for code in (
        "checksum_mismatch",
        "missing_original_receipt",
        "production_restart_recorded",
        "safety_drift",
    ):
        payload = receipt_explain(tmp_path, finding=code)
        assert payload["status"] == "ok"
        assert payload["explanations"][0]["code"] == code
        assert payload["explanations"][0]["safe_next_commands"]
        assert payload["explanations"][0]["not_performed"]

    unknown = receipt_explain(tmp_path, finding="totally_unknown")
    assert unknown["status"] == "unknown_finding"
    assert unknown["explanations"][0]["title"] == "Unknown finding"
    assert unknown["explanations"][0]["severity"] == "warning"


def test_source_filters_and_limit_behavior(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    _receipt(tmp_path, "receipt_pr175_a", target="sfai-pr175-one")
    _receipt(tmp_path, "receipt_pr175_b", target="other", recipe_id="other.recipe")
    _bundle(tmp_path)
    for source in ("integrity", "audit", "audit-bundle", "compare"):
        result = _invoke(
            tmp_path,
            monkeypatch,
            ["recipes", "receipt", "explain", "--source", source, "--json"],
        )
        assert result.exit_code == 0, result.stdout
        payload = json.loads(result.stdout)
        assert payload["source"] == source
        assert payload["read_only"] is True
    result = _invoke(
        tmp_path,
        monkeypatch,
        ["recipes", "receipt", "explain", "--target", "sfai-pr175-one", "--json"],
    )
    assert json.loads(result.stdout)["filters"]["target"] == "sfai-pr175-one"
    result = _invoke(
        tmp_path,
        monkeypatch,
        ["recipes", "receipt", "explain", "--recipe", "docker.disposable_restart", "--json"],
    )
    assert json.loads(result.stdout)["filters"]["recipe_id"] == "docker.disposable_restart"
    result = _invoke(
        tmp_path, monkeypatch, ["recipes", "receipt", "explain", "--limit", "1", "--json"]
    )
    assert json.loads(result.stdout)["filters"]["limit"] == 1
    bad = _invoke(tmp_path, monkeypatch, ["recipes", "receipt", "explain", "--limit", "0"])
    assert bad.exit_code != 0
    assert "Invalid value" in bad.stdout or "Error" in bad.output


def test_explain_sources_detect_local_findings(tmp_path: Path) -> None:
    d = _receipt(tmp_path, "receipt_pr175_corrupt")
    (d / "recipe-receipt.md").write_text("changed\n", encoding="utf-8")
    integrity = receipt_explain(tmp_path, source="integrity")
    codes = {item["code"] for item in integrity["explanations"]}
    assert "checksum_mismatch" in codes

    _receipt(
        tmp_path,
        "recovery_receipt_pr175_missing",
        mode=RECOVERY_RECEIPT_MODE,
        original="receipt_missing_original",
    )
    audit = receipt_explain(tmp_path, source="audit")
    audit_codes = {item["code"] for item in audit["explanations"]}
    assert "missing_original_receipt" in audit_codes or "verification_failed" in audit_codes


def test_safe_guidance_does_not_suggest_mutating_commands(tmp_path: Path) -> None:
    for code in ("checksum_mismatch", "safety_drift", "production_restart_recorded"):
        payload = receipt_explain(tmp_path, finding=code)
        text = json.dumps(payload).lower()
        forbidden = (
            "docker restart",
            "docker compose",
            "cleanup execute",
            "recovery execute",
            "rollback execute",
            "rm ",
            "delete artifact",
        )
        assert not any(item in text for item in forbidden)


def test_ask_explain_routes_and_mutation_refusals(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    deterministic = (
        "explain receipt integrity findings",
        "what does checksum_mismatch mean?",
        "what should I do about safety drift?",
        "explain compare result",
        "create receipt audit bundle for support handoff",
        "make a support packet for receipt audit",
    )
    for phrase in deterministic:
        result = runner.invoke(app, ["ask", phrase])
        assert result.exit_code == 0
        assert "deterministic ask routing" in result.stdout
        assert "No action was taken." in result.stdout
    for phrase in (
        "explain and fix corrupt receipts",
        "explain then delete bad artifacts",
        "explain safety drift and recover now",
    ):
        result = runner.invoke(app, ["ask", phrase])
        assert result.exit_code == 0
        assert "Refused" in result.stdout
        assert "No action was taken." in result.stdout
        assert "recipes receipt explain" in result.stdout


def test_interactive_explain_dispatch_and_mutation_refusal() -> None:
    assert route_input("recipes receipt explain").argv == ("recipes", "receipt", "explain")
    assert route_input("recipes receipt explain --json").argv == (
        "recipes",
        "receipt",
        "explain",
        "--json",
    )
    assert route_input("recipes receipt explain --finding checksum_mismatch").argv == (
        "recipes",
        "receipt",
        "explain",
        "--finding",
        "checksum_mismatch",
    )
    assert (
        _dispatch_label(("recipes", "receipt", "explain"))
        == "Running read-only receipt finding explanation..."
    )
    assert "recipe registry" not in _dispatch_label(("recipes", "receipt", "explain"))
    for phrase in ("fix corrupt receipts", "delete bad artifacts", "recover now", "rollback now"):
        routed = route_input(phrase)
        assert routed.name in {"quick_mutation_refusal", "mutation_refused", "unknown"}


def test_explain_safety_invariants(tmp_path: Path) -> None:
    payload = receipt_explain(tmp_path, finding="checksum_mismatch")
    safety = payload["safety"]
    assert safety["cleanup_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False
    assert safety["recovery_executed"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["container_restarted"] is False
    assert safety["production_restart_executed"] is False
    assert safety["shell_true"] is False
    assert safety["arbitrary_command_execution"] is False
    assert safety["natural_language_execution"] is False
    assert safety["model_called"] is False
    assert safety["repair_attempted"] is False
    assert safety["artifact_deleted"] is False
