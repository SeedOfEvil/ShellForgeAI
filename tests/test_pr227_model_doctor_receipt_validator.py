from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

import shellforgeai.cli as cli
from shellforgeai.cli import app
from shellforgeai.llm.schemas import ModelResponse

runner = CliRunner()


class FakeProvider:
    def __init__(self):
        self.calls = []

    def doctor(self):
        return {
            "provider": "fake",
            "model": "fake-model",
            "auth_cache_present": True,
            "auth_readiness": "not_verified",
            "auth_reason": "auth_cache_present_live_probe_not_run",
        }

    def complete(self, request):
        self.calls.append(request)
        return ModelResponse(provider="fake", model="fake-model", text="ready", ok=True)


def _install(monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(cli, "build_provider", lambda _settings: provider)
    return provider


def _write_receipt(root: Path, *, mutation: bool = False, probe_meta: bool = True) -> dict:
    root.mkdir()
    payload = {
        "schema_version": 1,
        "mode": "model_doctor",
        "status": "ok",
        "read_only": True,
        "mutation_performed": mutation,
        "live_probe_requested": True,
        "live_probe_performed": bool(probe_meta),
        "model_called": bool(probe_meta),
        "probe": {"status": "passed", "timeout_seconds": 10} if probe_meta else {},
        "safety": {
            "read_only": True,
            "mutation_performed": mutation,
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
    (root / "model-doctor-live-probe.json").write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n"
    )
    (root / "model-doctor-live-probe-summary.md").write_text(
        "# Model Doctor live probe receipt\n\n- No mutation was performed.\n"
    )
    files = ["model-doctor-live-probe.json", "model-doctor-live-probe-summary.md"]
    metas = {}
    for name in files:
        data = (root / name).read_bytes()
        metas[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    manifest = {
        "schema_version": 1,
        "mode": "model_doctor",
        "files": files + ["manifest.json", "checksums.json"],
        "read_only": True,
        "mutation_performed": False,
        "checksums": metas,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    data = (root / "manifest.json").read_bytes()
    metas["manifest.json"] = {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    (root / "checksums.json").write_text(
        json.dumps(
            {"schema_version": 1, "algorithm": "sha256", "files": metas}, sort_keys=True, indent=2
        )
        + "\n"
    )
    return payload


def _validate(path: Path, *extra: str):
    return runner.invoke(app, ["model", "doctor", "--validate-receipt", str(path), *extra])


def test_valid_receipt_json_is_strict_and_accepts_historical_model_call(
    tmp_path: Path, monkeypatch
):
    provider = _install(monkeypatch)
    receipt = tmp_path / "receipt"
    _write_receipt(receipt)
    result = _validate(receipt, "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["mode"] == "model_doctor_receipt_validation"
    assert payload["status"] == "passed"
    assert payload["summary"]["required_files_present"] is True
    assert payload["summary"]["json_parse_ok"] is True
    assert payload["summary"]["manifest_ok"] is True
    assert payload["summary"]["checksums_ok"] is True
    assert payload["summary"]["secret_scan_ok"] is True
    assert payload["summary"]["safety_ok"] is True
    assert payload["summary"]["probe_status"] == "passed"
    assert payload["summary"]["live_probe_requested"] is True
    assert payload["summary"]["live_probe_performed"] is True
    assert payload["summary"]["model_called"] is True
    assert payload["safety"]["model_called"] is False
    assert payload["safety"]["model_call_performed"] is False
    assert payload["safety"]["live_probe_performed"] is False
    assert payload["safety"]["validation_only"] is True
    assert provider.calls == []


def test_human_output_is_concise(tmp_path: Path, monkeypatch):
    _install(monkeypatch)
    receipt = tmp_path / "receipt"
    _write_receipt(receipt)
    result = _validate(receipt)
    assert result.exit_code == 0, result.output
    assert "# Model Doctor Receipt Validation" in result.stdout
    assert "## Checks" in result.stdout
    assert "* no model call performed" in result.stdout
    assert "* no live probe performed" in result.stdout


def test_validation_out_writes_artifacts_and_preserves_source(tmp_path: Path, monkeypatch):
    _install(monkeypatch)
    receipt = tmp_path / "receipt"
    _write_receipt(receipt)
    before = {p.name: p.read_bytes() for p in receipt.iterdir()}
    out = tmp_path / "validation"
    result = _validate(receipt, "--validation-out", str(out), "--json")
    assert result.exit_code == 0, result.output
    for name in [
        "model-doctor-receipt-validation.json",
        "model-doctor-receipt-validation-summary.md",
        "manifest.json",
        "checksums.json",
    ]:
        assert (out / name).exists()
    manifest = json.loads((out / "manifest.json").read_text())
    checksums = json.loads((out / "checksums.json").read_text())
    assert set(manifest["files"]) - {"checksums.json"} == set(checksums["files"])
    for name, meta in checksums["files"].items():
        data = (out / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == meta["sha256"]
        assert len(data) == meta["size_bytes"]
    after = {p.name: p.read_bytes() for p in receipt.iterdir()}
    assert before == after


def test_missing_required_file_fails(tmp_path: Path, monkeypatch):
    _install(monkeypatch)
    receipt = tmp_path / "receipt"
    _write_receipt(receipt)
    (receipt / "manifest.json").unlink()
    payload = json.loads(_validate(receipt, "--json").stdout)
    assert payload["status"] == "failed"
    assert payload["summary"]["required_files_present"] is False


def test_invalid_json_fails(tmp_path: Path, monkeypatch):
    _install(monkeypatch)
    receipt = tmp_path / "receipt"
    _write_receipt(receipt)
    (receipt / "checksums.json").write_text("{")
    payload = json.loads(_validate(receipt, "--json").stdout)
    assert payload["status"] == "failed"
    assert payload["summary"]["json_parse_ok"] is False


def test_checksum_mismatch_fails(tmp_path: Path, monkeypatch):
    _install(monkeypatch)
    receipt = tmp_path / "receipt"
    _write_receipt(receipt)
    (receipt / "model-doctor-live-probe-summary.md").write_text("changed\n")
    payload = json.loads(_validate(receipt, "--json").stdout)
    assert payload["status"] == "failed"
    assert payload["summary"]["checksums_ok"] is False


def test_manifest_missing_file_fails(tmp_path: Path, monkeypatch):
    _install(monkeypatch)
    receipt = tmp_path / "receipt"
    _write_receipt(receipt)
    manifest = json.loads((receipt / "manifest.json").read_text())
    manifest["files"].remove("checksums.json")
    (receipt / "manifest.json").write_text(json.dumps(manifest))
    payload = json.loads(_validate(receipt, "--json").stdout)
    assert payload["status"] == "failed"
    assert payload["summary"]["manifest_ok"] is False


def test_secret_marker_fails_without_echoing_secret(tmp_path: Path, monkeypatch):
    _install(monkeypatch)
    receipt = tmp_path / "receipt"
    _write_receipt(receipt)
    (receipt / "model-doctor-live-probe-summary.md").write_text("Authorization: Bearer sk-test\n")
    result = _validate(receipt, "--json")
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert payload["summary"]["secret_scan_ok"] is False
    assert "sk-test" not in result.stdout


def test_oversized_receipt_file_safely_fails(tmp_path: Path, monkeypatch):
    _install(monkeypatch)
    receipt = tmp_path / "receipt"
    _write_receipt(receipt)
    (receipt / "model-doctor-live-probe.json").write_text(" " * (300 * 1024))
    payload = json.loads(_validate(receipt, "--json").stdout)
    assert payload["status"] == "failed"
    assert any(c["name"] == "bounded_files" and c["status"] == "failed" for c in payload["checks"])


def test_mutation_flag_and_missing_probe_metadata_fail(tmp_path: Path, monkeypatch):
    _install(monkeypatch)
    receipt = tmp_path / "mutation"
    _write_receipt(receipt, mutation=True)
    payload = json.loads(_validate(receipt, "--json").stdout)
    assert payload["status"] == "failed"
    assert payload["summary"]["safety_ok"] is False

    missing = tmp_path / "missing_probe"
    _write_receipt(missing, probe_meta=False)
    payload = json.loads(_validate(missing, "--json").stdout)
    assert payload["status"] == "failed"
    assert payload["summary"]["live_probe_performed"] is False


def test_validator_does_not_add_live_probe_or_mutation_surface(monkeypatch):
    provider = _install(monkeypatch)
    help_text = runner.invoke(app, ["model", "doctor", "--help"]).stdout
    assert "--validate-receipt" in help_text
    assert "--validation-out" in help_text
    for forbidden in [
        "--execute",
        "--apply",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
        "--post-comment",
        "--approve",
        "--merge",
    ]:
        assert forbidden not in help_text
    default = runner.invoke(app, ["model", "doctor", "--json"])
    assert json.loads(default.stdout)["model_called"] is False
    assert provider.calls == []


def test_source_static_guardrails():
    source = Path("src/shellforgeai/commands/model.py").read_text()
    assert "shell=True" not in source
