"""PR229 Docker01 QA bundle model receipt evidence integration tests.

These exercise the read-only Model Doctor receipt evidence section added to the
Docker01 operator QA bundle. The bundle collects receipt evidence only via the
existing read-only ``shellforgeai model receipt history --root /tmp --json``
command (run through the same narrow ``docker exec`` allowlist as the other
product smoke commands). It never calls the model, never runs a live probe,
never touches the network, and performs no Docker *mutation* for receipts.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_operator_qa_bundle.py"

spec = importlib.util.spec_from_file_location("pr229_qa_bundle", HELPER_PATH)
qa = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules["pr229_qa_bundle"] = qa
spec.loader.exec_module(qa)

PR = 229
COMMIT = "abcdef0123456789abcdef0123456789abcdef01"

MR_ARGV = tuple(qa.model_receipt_command_specs()[0].argv)


# ---------------------------------------------------------------------------
# Smoke-command runner (mirrors the other QA bundle integration tests)
# ---------------------------------------------------------------------------


def _safety(**overrides):
    data = {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "docker_prune_executed": False,
        "file_deleted": False,
        "container_restarted": False,
        "docker_compose_executed": False,
    }
    data.update(overrides)
    return data


def _json(data):
    return json.dumps(data)


def _core_stdout(key):
    if key in {"v1_quick", "v1_standard", "remediation_self_test"}:
        return _json(
            {
                "status": "ok",
                "summary": {"passed": 1, "failed": 0},
                "skipped": ["live disposable"],
                "safety": _safety(live_disposable_execute=False),
            }
        )
    if key == "ops_report":
        return _json({"read_only": True, "mutation_performed": False, "safety": _safety()})
    if key in {"status", "triage_docker", "propose", "apply_preview", "verify", "handoff"}:
        return _json({"status": "ok", "read_only": True, "safety": _safety()})
    if key == "docker_inspect":
        return _json(
            [
                {
                    "RestartCount": 0,
                    "State": {"Status": "running", "Health": {"Status": "healthy"}},
                    "Config": {"Image": "shellforgeai:test", "Labels": {}},
                }
            ]
        )
    if key == "disk":
        return "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 10G 2G 8G 20% /\n"
    if key == "validation_status":
        return _json(
            {
                "status": "passed",
                "classification": "passed",
                "pass_eligible": True,
                "rerun_required": False,
                "source": {"kind": "test"},
            }
        )
    if key == "ask_mutation":
        return "Refusing to execute; no cleanup, restart, Docker, or Compose command was executed."
    if key.startswith("hygiene_"):
        return _json({"status": "empty", "reports": [], "warnings": [], "safety": _safety()})
    return "ok\n"


class Runner:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        key = tuple(argv)
        if key in self.outputs:
            rc, out, err = self.outputs[key]
            return SimpleNamespace(returncode=rc, stdout=out, stderr=err)
        for group in (qa.build_command_specs(PR, COMMIT), qa.hygiene_command_specs(True)):
            for s in group:
                if tuple(s.argv) == key:
                    return SimpleNamespace(returncode=0, stdout=_core_stdout(s.key), stderr="")
        return SimpleNamespace(returncode=127, stdout="", stderr="unexpected")


# ---------------------------------------------------------------------------
# Fake model receipt history outputs (shape of build_model_receipt_history)
# ---------------------------------------------------------------------------


def _receipt_meta(
    path="/tmp/sfai-pr229-live-probe-receipt-a",
    *,
    probe="passed",
    auth="verified",
    model_called=True,
    live=True,
    validation="passed",
):
    return {
        "path": path,
        "status": "valid",
        "created_at": "2026-06-21T00:00:00Z",
        "probe_status": probe,
        "auth_readiness": auth,
        "model_called": model_called,
        "live_probe_performed": live,
        "validation_status": validation,
    }


def _hist_safety(**overrides):
    safety = {
        "read_only": True,
        "mutation_performed": False,
        "model_called": False,
        "live_probe_performed": False,
        "history_only": True,
    }
    safety.update(overrides)
    return safety


def _history(status="ok", receipts=None, invalid=None, ignored=0, warnings=None, safety=None):
    receipts = receipts if receipts is not None else [_receipt_meta()]
    invalid = invalid or []
    latest = receipts[0] if receipts else {}
    return {
        "schema_version": 1,
        "mode": "model_doctor_receipt_history",
        "status": status,
        "root": "/tmp",
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "candidates_scanned": len(receipts) + len(invalid),
            "valid_receipts": len(receipts),
            "invalid_receipts": len(invalid),
            "ignored_candidates": ignored,
            "latest_valid_receipt": latest.get("path"),
            "latest_probe_status": latest.get("probe_status", "unknown"),
            "latest_auth_readiness": latest.get("auth_readiness", "unknown"),
            "latest_model_called": latest.get("model_called"),
            "latest_live_probe_performed": latest.get("live_probe_performed"),
        },
        "receipts": receipts,
        "invalid_candidates": invalid,
        "warnings": warnings or [],
        "safety": safety or _hist_safety(),
    }


def _gen(tmp_path, name="bundle", mr_output=None, **kwargs):
    """Generate a bundle. ``mr_output`` is the (rc, stdout, stderr) for the
    model receipt history command; omit it to simulate an unavailable command."""
    outputs = {}
    if mr_output is not None:
        outputs[MR_ARGV] = mr_output
    runner = Runner(outputs)
    result = qa.generate_bundle(PR, COMMIT, tmp_path / name, runner=runner, **kwargs)
    return result, runner


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_qa_results_includes_model_receipts_block(tmp_path):
    result, _ = _gen(tmp_path, mr_output=(0, _json(_history()), ""))
    mr = result["model_receipts"]
    assert mr["enabled"] is True
    assert mr["status"] == "ok"
    assert mr["history_status"] == "ok"
    on_disk = json.loads((tmp_path / "bundle/qa-results.json").read_text())
    assert "model_receipts" in on_disk


def test_summary_includes_model_receipt_section(tmp_path):
    _gen(tmp_path, mr_output=(0, _json(_history()), ""))
    summary = (tmp_path / "bundle/qa-summary.md").read_text()
    assert "## Model receipt evidence" in summary
    assert "QA bundle did not perform a live probe or model call." in summary


def test_raw_model_receipt_history_written(tmp_path):
    _gen(tmp_path, mr_output=(0, _json(_history()), ""))
    assert (tmp_path / "bundle/raw/model-receipt-history.json").is_file()
    assert (tmp_path / "bundle/raw/model-receipt-evidence.json").is_file()
    raw = json.loads((tmp_path / "bundle/raw/model-receipt-history.json").read_text())
    assert raw["mode"] == "model_doctor_receipt_history"


def test_latest_valid_receipt_metadata_summarized(tmp_path):
    history = _history(receipts=[_receipt_meta(path="/tmp/sfai-pr229-live-probe-receipt-latest")])
    result, _ = _gen(tmp_path, mr_output=(0, _json(history), ""))
    mr = result["model_receipts"]
    assert mr["latest_receipt_path"] == "/tmp/sfai-pr229-live-probe-receipt-latest"
    assert mr["latest_receipt_validation_status"] == "passed"
    assert mr["latest_probe_status"] == "passed"
    assert mr["latest_auth_readiness"] == "verified"


def test_valid_invalid_counts_included(tmp_path):
    history = _history(
        status="partial",
        receipts=[_receipt_meta()],
        invalid=[{"path": "/tmp/bad", "reason": "checksum_mismatch"}],
    )
    result, _ = _gen(tmp_path, mr_output=(0, _json(history), ""))
    mr = result["model_receipts"]
    assert mr["receipts_valid"] == 1
    assert mr["receipts_invalid"] == 1


def test_safe_next_command_included(tmp_path):
    result, _ = _gen(tmp_path, mr_output=(0, _json(_history()), ""))
    assert (
        result["model_receipts"]["safe_next_command"]
        == "shellforgeai model receipt history --root /tmp --json"
    )


def test_collection_safety_reports_no_model_call_or_live_probe(tmp_path):
    result, _ = _gen(tmp_path, mr_output=(0, _json(_history()), ""))
    safety = result["model_receipts"]["safety"]
    assert safety["model_called"] is False
    assert safety["live_probe_performed"] is False
    assert safety["receipt_history_only"] is True
    assert safety["read_only"] is True


def test_historical_model_called_true_is_accepted(tmp_path):
    history = _history(receipts=[_receipt_meta(model_called=True, live=True)])
    result, _ = _gen(tmp_path, mr_output=(0, _json(history), ""))
    mr = result["model_receipts"]
    # Historical receipt recorded a model call (earlier explicit live probe)...
    assert mr["latest_model_called"] is True
    assert mr["latest_live_probe_performed"] is True
    # ...but the QA collection itself did not, and the bundle is not failed.
    assert mr["safety"]["model_called"] is False
    assert result["status"] in {"passed", "partial"}


def test_parses_real_history_helper_shape(tmp_path):
    # Feed the bundle the real ``build_model_receipt_history`` output shape, built
    # from a real on-disk receipt, to confirm the summary parses it (no model
    # call: the helper only reads + validates existing receipt directories).
    from shellforgeai.core.model_receipt_history import build_model_receipt_history

    receipts_root = tmp_path / "receipts"
    receipts_root.mkdir()
    _write_real_receipt(receipts_root, "sfai-pr229-live-probe-receipt-a")
    real = build_model_receipt_history(receipts_root)
    result, _ = _gen(tmp_path, mr_output=(0, json.dumps(real), ""))
    mr = result["model_receipts"]
    assert mr["status"] == "ok"
    assert mr["receipts_valid"] == 1
    assert mr["latest_model_called"] is True
    assert mr["safety"]["model_called"] is False


# ---------------------------------------------------------------------------
# Empty / missing
# ---------------------------------------------------------------------------


def test_empty_history_does_not_fail_bundle(tmp_path):
    history = _history(status="empty", receipts=[])
    result, _ = _gen(tmp_path, mr_output=(0, _json(history), ""))
    mr = result["model_receipts"]
    assert mr["status"] == "empty"
    assert result["status"] in {"passed", "partial"}
    assert mr["warnings"]


def test_unavailable_command_reports_not_available(tmp_path):
    # No mr_output supplied -> the runner returns a non-zero exit for the command.
    result, _ = _gen(tmp_path)
    mr = result["model_receipts"]
    assert mr["status"] == "not_available"
    assert any("unavailable" in w for w in mr["warnings"])
    assert result["status"] in {"passed", "partial"}


def test_missing_raw_history_is_deterministic(tmp_path):
    _gen(tmp_path)  # unavailable command
    raw = json.loads((tmp_path / "bundle/raw/model-receipt-history.json").read_text())
    assert raw["status"] == "not_available"
    assert raw["read_only"] is True


def test_skip_model_receipts_flag(tmp_path):
    result, runner = _gen(tmp_path, include_model_receipts=False)
    mr = result["model_receipts"]
    assert mr["enabled"] is False
    assert mr["status"] == "not_available"
    assert result["status"] in {"passed", "partial"}
    # The receipt history command was not even planned/executed.
    assert MR_ARGV not in [tuple(c) for c in runner.calls]


# ---------------------------------------------------------------------------
# Failure / safety
# ---------------------------------------------------------------------------


def test_secret_marker_fails_safety_assertions(tmp_path):
    history = _history(
        status="partial",
        receipts=[],
        invalid=[{"path": "/tmp/secret", "reason": "secret_marker_detected"}],
    )
    result, _ = _gen(tmp_path, mr_output=(0, _json(history), ""))
    mr = result["model_receipts"]
    assert mr["status"] == "failed"
    assert mr["secret_scan_ok"] is False
    assert result["status"] == "failed"
    sa = json.loads((tmp_path / "bundle/safety-assertions.json").read_text())
    assertion = next(a for a in sa["assertions"] if a["name"] == "model_receipt_evidence_safe")
    assert assertion["passed"] is False


def test_historical_safety_drift_fails_safety(tmp_path):
    history = _history(safety=_hist_safety(mutation_performed=True))
    result, _ = _gen(tmp_path, mr_output=(0, _json(history), ""))
    assert result["model_receipts"]["status"] == "failed"
    assert result["status"] == "failed"


def test_checksum_mismatch_is_surfaced_not_fatal(tmp_path):
    history = _history(
        status="partial",
        receipts=[_receipt_meta()],
        invalid=[{"path": "/tmp/cs", "reason": "checksum_mismatch"}],
    )
    result, _ = _gen(tmp_path, mr_output=(0, _json(history), ""))
    mr = result["model_receipts"]
    assert mr["status"] == "partial"
    assert mr["secret_scan_ok"] is True
    assert any("invalid receipt" in w for w in mr["warnings"])
    # Not a safety failure: bundle is not failed solely due to an invalid receipt.
    assert result["status"] in {"passed", "partial"}


def test_qa_bundle_does_not_run_live_probe_model_or_network(tmp_path):
    result, runner = _gen(tmp_path, mr_output=(0, _json(_history()), ""))
    for call in runner.calls:
        joined = " ".join(call)
        assert "--live-probe" not in joined
        assert "doctor" not in joined or "model receipt" not in joined
    # The only model-related command issued for receipts is the read-only
    # ``model receipt history`` form (no live probe / no model doctor probe).
    model_calls = [c for c in runner.calls if "model" in c]
    for call in model_calls:
        if "receipt" in call:
            assert call[-3:] == ["--root", "/tmp", "--json"]
            assert "history" in call
    assert result["model_receipts"]["safety"]["live_probe_performed"] is False


def test_receipt_command_runs_no_docker_mutation(tmp_path):
    # Receipt evidence uses only the narrow read-only ``docker exec ... model
    # receipt history`` form; no docker prune/rm/rmi/restart/compose/volume.
    argv = list(MR_ARGV)
    assert qa.is_command_allowed(argv)
    joined = " ".join(argv)
    for token in ("prune", " rm ", " rmi", "restart", "compose", "volume", "--live-probe"):
        assert token not in joined
    # Mutation variants of the receipt command are rejected by the allowlist.
    for bad in ("rm", "delete", "prune", "live-probe"):
        assert not qa.is_command_allowed(
            ["docker", "exec", "shellforgeai", "shellforgeai", "model", "receipt", bad]
        )


def test_source_has_no_shell_true_and_no_live_probe_invocation():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    assert "--live-probe" not in source
    assert "model doctor --live-probe" not in source
    # The standalone helper introduces no hard product-runtime import (PR206/205).
    assert "import shellforgeai" not in source
    assert "from shellforgeai" not in source


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_real_receipt(root: Path, name: str, *, model_called=True) -> Path:
    import hashlib

    receipt = root / name
    receipt.mkdir()
    payload = {
        "schema_version": 1,
        "mode": "model_doctor",
        "created_at": "2026-06-21T00:00:00Z",
        "read_only": True,
        "mutation_performed": False,
        "provider": "codex",
        "model": "gpt-5.5",
        "auth_readiness": "verified",
        "live_probe_requested": True,
        "live_probe_performed": True,
        "model_called": model_called,
        "probe": {
            "status": "passed",
            "provider": "codex",
            "model": "gpt-5.5",
            "timeout_seconds": 10,
            "request_id": "req_1",
            "latency_ms": 100,
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
