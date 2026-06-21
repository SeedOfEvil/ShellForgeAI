from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _write_receipt(
    root: Path,
    name: str,
    *,
    probe_status: str = "passed",
    auth_readiness: str = "verified",
    latency_ms: int = 100,
    timeout_seconds: int = 10,
    provider: str = "codex",
    model: str = "gpt-5.5",
    created_at: str = "2026-06-21T00:00:00Z",
) -> Path:
    receipt = root / name
    receipt.mkdir()
    payload = {
        "schema_version": 1,
        "mode": "model_doctor",
        "created_at": created_at,
        "read_only": True,
        "mutation_performed": False,
        "provider": provider,
        "model": model,
        "auth_readiness": auth_readiness,
        "live_probe_requested": True,
        "live_probe_performed": True,
        "model_called": True,
        "probe": {
            "status": probe_status,
            "provider": provider,
            "model": model,
            "timeout_seconds": timeout_seconds,
            "request_id": "req_1",
            "latency_ms": latency_ms,
            "error_class": None,
            "error_message": None,
        },
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "cleanup_executed": False,
            "docker_prune_executed": False,
            "docker_image_removed": False,
            "file_deleted": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "recovery_executed": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
        },
    }
    (receipt / "model-doctor-live-probe.json").write_text(json.dumps(payload), encoding="utf-8")
    (receipt / "model-doctor-live-probe-summary.md").write_text("# summary\n", encoding="utf-8")
    files = ["model-doctor-live-probe.json", "model-doctor-live-probe-summary.md"]
    sums = {}
    for file in files:
        data = (receipt / file).read_bytes()
        sums[file] = {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    manifest = {
        "schema_version": 1,
        "mode": "model_doctor",
        "files": files + ["manifest.json", "checksums.json"],
        "read_only": True,
        "mutation_performed": False,
        "checksums": sums,
    }
    (receipt / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    data = (receipt / "manifest.json").read_bytes()
    sums["manifest.json"] = {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    (receipt / "checksums.json").write_text(
        json.dumps({"schema_version": 1, "algorithm": "sha256", "files": sums}), encoding="utf-8"
    )
    return receipt


def _json(result):
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_history_happy_path_strict_json_latest_and_safety(tmp_path):
    _write_receipt(
        tmp_path,
        "sfai-pr228-live-probe-receipt-a",
        created_at="2026-06-21T00:00:00Z",
        latency_ms=10,
    )
    latest = _write_receipt(
        tmp_path,
        "sfai-pr228-live-probe-receipt-b",
        created_at="2026-06-21T01:00:00Z",
        latency_ms=20,
    )
    (tmp_path / "unrelated").mkdir()
    data = _json(
        runner.invoke(app, ["model", "receipt", "history", "--root", str(tmp_path), "--json"])
    )
    assert data["mode"] == "model_doctor_receipt_history"
    assert data["status"] == "ok"
    assert data["summary"]["valid_receipts"] == 2
    assert data["summary"]["ignored_candidates"] == 1
    assert data["summary"]["latest_valid_receipt"] == str(latest)
    assert data["summary"]["latest_probe_status"] == "passed"
    assert data["summary"]["latest_auth_readiness"] == "verified"
    assert data["summary"]["latest_model_called"] is True
    assert data["safety"]["model_called"] is False
    assert data["safety"]["live_probe_performed"] is False
    assert data["safety"]["history_only"] is True


def test_history_human_output_is_concise(tmp_path):
    _write_receipt(tmp_path, "sfai-pr228-live-probe-receipt-a")
    result = runner.invoke(app, ["model", "receipt", "history", "--root", str(tmp_path)])
    assert result.exit_code == 0
    assert "# Model Doctor Receipt History" in result.output
    assert "no live probe performed" in result.output
    assert "no model call performed" in result.output


def test_history_empty_invalid_checksum_secret_and_bounds(tmp_path):
    empty = _json(
        runner.invoke(app, ["model", "receipt", "history", "--root", str(tmp_path), "--json"])
    )
    assert empty["status"] == "empty"
    bad = _write_receipt(tmp_path, "sfai-pr228-live-probe-receipt-bad")
    (bad / "model-doctor-live-probe-summary.md").write_text("changed", encoding="utf-8")
    secret = _write_receipt(tmp_path, "sfai-pr228-live-probe-receipt-secret")
    (secret / "model-doctor-live-probe-summary.md").write_text(
        "Authorization: Bearer sk-test", encoding="utf-8"
    )
    for idx in range(18):
        (tmp_path / f"model-doctor-receipt-incomplete-{idx}").mkdir()
    data = _json(
        runner.invoke(app, ["model", "receipt", "history", "--root", str(tmp_path), "--json"])
    )
    reasons = {item["reason"] for item in data["invalid_candidates"]}
    assert "checksum_mismatch" in reasons
    assert "secret_marker_detected" in reasons
    assert "missing_required_files" in reasons
    assert len(data["invalid_candidates"]) == 20


def test_history_stale_different_naming_does_not_crash(tmp_path):
    _write_receipt(tmp_path, "custom-model-doctor-receipt-old")
    data = _json(
        runner.invoke(app, ["model", "receipt", "history", "--root", str(tmp_path), "--json"])
    )
    assert data["summary"]["valid_receipts"] == 1


def test_compare_happy_path_deltas_json_human_and_safety(tmp_path):
    old = _write_receipt(
        tmp_path, "sfai-pr228-live-probe-receipt-old", latency_ms=100, timeout_seconds=10
    )
    new = _write_receipt(
        tmp_path,
        "sfai-pr228-live-probe-receipt-new",
        probe_status="failed",
        auth_readiness="failed",
        latency_ms=175,
        timeout_seconds=12,
        model="gpt-new",
    )
    data = _json(runner.invoke(app, ["model", "receipt", "compare", str(old), str(new), "--json"]))
    assert data["mode"] == "model_doctor_receipt_compare"
    assert data["status"] == "ok"
    assert data["delta"]["probe_status_changed"] is True
    assert data["delta"]["auth_readiness_changed"] is True
    assert data["delta"]["latency_ms_delta"] == 75
    assert data["delta"]["timeout_seconds_delta"] == 2
    assert data["delta"]["model_changed"] is True
    assert data["safety"]["model_called"] is False
    assert data["safety"]["live_probe_performed"] is False
    human = runner.invoke(app, ["model", "receipt", "compare", str(old), str(new)])
    assert human.exit_code == 0
    assert "# Model Doctor Receipt Compare" in human.output
    assert "no model call performed" in human.output


def test_compare_missing_invalid_json_checksum_and_secret_fail_cleanly(tmp_path):
    good = _write_receipt(tmp_path, "sfai-pr228-live-probe-receipt-good")
    missing = tmp_path / "sfai-pr228-live-probe-receipt-missing"
    assert (
        _json(
            runner.invoke(app, ["model", "receipt", "compare", str(missing), str(good), "--json"])
        )["status"]
        == "failed"
    )
    assert (
        _json(
            runner.invoke(app, ["model", "receipt", "compare", str(good), str(missing), "--json"])
        )["status"]
        == "failed"
    )
    invalid_json = _write_receipt(tmp_path, "sfai-pr228-live-probe-receipt-invalid-json")
    (invalid_json / "model-doctor-live-probe.json").write_text("{", encoding="utf-8")
    checksum = _write_receipt(tmp_path, "sfai-pr228-live-probe-receipt-checksum")
    (checksum / "model-doctor-live-probe-summary.md").write_text("changed", encoding="utf-8")
    secret = _write_receipt(tmp_path, "sfai-pr228-live-probe-receipt-secret")
    (secret / "model-doctor-live-probe-summary.md").write_text("ghp_secret", encoding="utf-8")
    for path in (invalid_json, checksum, secret):
        data = _json(
            runner.invoke(app, ["model", "receipt", "compare", str(good), str(path), "--json"])
        )
        assert data["status"] == "failed"


def test_commands_do_not_use_live_probe_model_network_or_docker(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise AssertionError("forbidden runtime call")

    import shellforgeai.commands.model as model_module

    monkeypatch.setattr(model_module, "_run_live_probe", fail)
    data = _json(
        runner.invoke(app, ["model", "receipt", "history", "--root", str(tmp_path), "--json"])
    )
    assert data["safety"]["model_called"] is False
    src = Path("src/shellforgeai/core/model_receipt_history.py").read_text(encoding="utf-8").lower()
    assert "shell=true" not in src
    assert "subprocess" not in src
    assert "docker" not in src
