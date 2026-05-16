"""PR54: mission post-execution report and export pack tests.

Self-contained, fixture-based. tmp_path is the data dir. No live Docker, no
root, no journalctl, no internet. Lab restart executor + inspector are faked
exactly the way PR53 tests fake them.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.audit.storage import AuditStorage
from shellforgeai.cli import app
from shellforgeai.core import lab_restart as lab_restart_mod
from shellforgeai.core.lab_restart import (
    ENV_ALLOW_LAB_RESTART,
    ENV_MUTATION_MODE,
    FakeCommandExecutor,
    write_default_allowlist,
)
from shellforgeai.core.mission import (
    prepare_mission,
)
from shellforgeai.core.mission_export import (
    export_mission,
    validate_mission_export,
)
from shellforgeai.core.mission_report import build_mission_report
from shellforgeai.core.rollback_preview import write_preview

runner = CliRunner()

CONTAINER = "sfai-pr54-target"

FAKE_SECRETS = {
    "openai_key": "sk-test-AbCDeFGhiJklmnoPQR1234567890zzz",
    "github_token": "ghp_AbCDeFGhiJklmnoPQR1234567890zzz",
    "slack_token": "xoxb-1111-2222-aaaaaaaaaaaaaaaaaaaaaaaaa",
    "aws_key": "AKIAABCDEFGHIJ234567",
    "auth_header": "Authorization: Bearer abc.def.ghi-very-secret-1234",
    "webhook": "https://hooks.slack.com/services/T0/B0/abcdefghijklmnopqrstuvwx",
    "password_kv": "password=hunter2-very-secret",
}


def _enable_mutation_env(monkeypatch) -> None:
    monkeypatch.setenv(ENV_MUTATION_MODE, "lab")
    monkeypatch.setenv(ENV_ALLOW_LAB_RESTART, "1")


def _patch_fake_executor(monkeypatch, fake: FakeCommandExecutor) -> FakeCommandExecutor:
    monkeypatch.setattr(cli_mod, "_lab_restart_executor_factory", lambda: fake)
    before_payload = lab_restart_mod.make_inspect_payload(
        started_at="2026-05-14T12:00:00.000000000Z"
    )
    after_payload = lab_restart_mod.make_inspect_payload(
        started_at="2026-05-14T12:00:05.000000000Z"
    )
    fake_inspector = lab_restart_mod.FakeContainerInspector(
        results=[
            lab_restart_mod.InspectResult(ok=True, exists=True, raw=before_payload),
            lab_restart_mod.InspectResult(ok=True, exists=True, raw=after_payload),
        ]
    )
    monkeypatch.setattr(cli_mod, "_lab_restart_inspector_factory", lambda: fake_inspector)
    monkeypatch.setattr(
        cli_mod,
        "_lab_restart_verification_config",
        lambda: lab_restart_mod.VerificationConfig(
            post_restart_wait_seconds=0,
            health_wait_seconds=0,
            health_poll_interval_seconds=0,
        ),
    )
    monkeypatch.setattr(cli_mod, "_lab_restart_verification_sleep", lambda _s: None)
    return fake


def _write_evidence(dst: Path, name: str = CONTAINER, with_secrets: bool = False) -> Path:
    payload = {
        "session_id": "sf_pr54",
        "items": [
            {
                "source": "docker.containers",
                "content": json.dumps(
                    {
                        "containers": [
                            {
                                "name": name,
                                "id": "abc",
                                "image": "lab:v1",
                                "state": "running",
                                "status": "Up 1m",
                                "health": "healthy",
                                "labels": {"shellforgeai.allow_restart": "true"},
                            }
                        ]
                    }
                ),
            }
        ],
    }
    if with_secrets:
        # Each secret in its own item so JSON-encoded newlines don't bleed
        # into the next token (the redactor relies on word boundaries).
        for k, v in FAKE_SECRETS.items():
            payload["items"].append({"source": f"fake.{k}", "content": v})
    p = dst / "evidence.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _write_summary(dst: Path, *, with_secrets: bool = False) -> Path:
    text = "# Summary\n- ok\n"
    if with_secrets:
        text = text + "\n".join([f"- probe: {v}" for v in FAKE_SECRETS.values()]) + "\n"
    p = dst / "summary.md"
    p.write_text(text, encoding="utf-8")
    return p


def _setup_mission(
    tmp_path: Path,
    monkeypatch,
    *,
    approve: bool = False,
    rollback: bool = False,
    with_secrets: bool = False,
) -> tuple[Path, str, str]:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    sess = tmp_path / "artifacts" / "sf_pr54"
    sess.mkdir(parents=True, exist_ok=True)
    ev = _write_evidence(sess, with_secrets=with_secrets)
    _write_summary(sess, with_secrets=with_secrets)
    write_default_allowlist(tmp_path, containers=[CONTAINER], enabled=True)
    res = prepare_mission(tmp_path, container=CONTAINER, evidence_path=ev, session_id="sf_pr54")
    assert res.ok, res.refusal
    assert res.payload is not None
    pid = res.payload["proposal_id"]
    if approve:
        from shellforgeai.core.approvals import approve_proposal

        proposal = approve_proposal(tmp_path, pid, reason="ok")
        if rollback:
            write_preview(tmp_path, proposal)
    elif rollback:
        from shellforgeai.core.approvals import find_proposal_path, load_proposal_from_path

        path, _ = find_proposal_path(tmp_path, pid)
        if path is not None:
            write_preview(tmp_path, load_proposal_from_path(path))
    return tmp_path, res.mission_id, pid


def _execute_mission(tmp_path: Path, monkeypatch) -> tuple[Path, str, str]:
    _enable_mutation_env(monkeypatch)
    data_dir, mid, pid = _setup_mission(
        tmp_path, monkeypatch, approve=True, rollback=True, with_secrets=True
    )
    _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 0, r.output
    return data_dir, mid, pid


def _read_events(tmp_path: Path) -> list[dict]:
    return AuditStorage(tmp_path).read_events()


# ---------------------------------------------------------------------------
# Report tests


def test_report_for_executed_mission_includes_receipt(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "report", mid])
    assert r.exit_code == 0, r.output
    assert "Mission restart report" in r.output
    assert mid in r.output
    assert "Verification" in r.output
    assert "Arbitrary command execution: false" in r.output
    assert "execution_path: apply_gate" not in r.output  # only in human report
    # Report files written to data dir
    json_path = data_dir / "mission_reports" / mid / "mission-report.json"
    md_path = data_dir / "mission_reports" / mid / "mission-report.md"
    assert json_path.exists() and md_path.exists()
    payload = json.loads(json_path.read_text())
    assert payload["mission_id"] == mid
    assert payload["status"] == "executed"
    assert payload["execution"]["status"] == "executed"
    assert payload["execution"]["path"] == "apply_gate"
    assert payload["execution"]["receipt_present"] is True
    assert payload["execution"]["arbitrary_command_execution"] is False
    assert payload["verification"]["status"] == "passed"
    assert payload["safety"]["arbitrary_command_execution"] is False
    assert payload["safety"]["natural_language_execution"] is False


def test_report_json_is_strict_json_only(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "report", mid, "--json"])
    assert r.exit_code == 0, r.output
    # First non-blank char must be '{'
    out = r.output.lstrip()
    assert out.startswith("{"), repr(out[:80])
    payload = json.loads(out)
    assert payload["schema_version"] == "1"
    assert payload["mission_id"] == mid
    assert payload["execution"]["arbitrary_command_execution"] is False
    assert payload["safety"]["arbitrary_command_execution"] is False
    assert payload["safety"]["rollback_execution"] is False


def test_report_for_ready_mission_has_not_executed_state(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    r = runner.invoke(app, ["mission", "restart", "report", mid, "--json"])
    assert r.exit_code == 0, r.output
    payload = json.loads(r.output)
    assert payload["status"] == "ready"
    assert payload["execution"]["status"] == "not_executed"
    assert payload["execution"]["receipt"] == ""
    assert payload["verification"]["status"] == "not_run"


def test_report_for_blocked_mission_lists_safe_state(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "report", mid, "--json"])
    assert r.exit_code == 0, r.output
    payload = json.loads(r.output)
    # Mission blocked because no approval/rollback yet.
    assert payload["status"] in ("waiting_approval", "blocked")
    assert payload["execution"]["status"] == "not_executed"
    assert payload["safety"]["arbitrary_command_execution"] is False


def test_report_does_not_reset_mission_status(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    runner.invoke(app, ["mission", "restart", "report", mid])
    runner.invoke(app, ["mission", "restart", "report", mid])
    mp = data_dir / "missions" / "restart" / mid / "mission.json"
    payload = json.loads(mp.read_text())
    assert payload["status"] == "executed"
    assert payload["phases"]["execution"]["status"] == "executed"


def test_report_does_not_call_apply_or_restart(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "report", mid])
    assert r.exit_code == 0, r.output
    # No execution receipts should be created by report.
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    assert receipts == []
    assert fake.calls == []


def test_report_is_idempotent(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r1 = runner.invoke(app, ["mission", "restart", "report", mid, "--json"])
    r2 = runner.invoke(app, ["mission", "restart", "report", mid, "--json"])
    assert r1.exit_code == 0 and r2.exit_code == 0
    p1 = json.loads(r1.output)
    p2 = json.loads(r2.output)
    # Fields that shouldn't change between back-to-back calls.
    for key in (
        "mission_id",
        "mission_type",
        "target",
        "status",
        "session_id",
        "proposal_id",
    ):
        assert p1[key] == p2[key], key
    assert p1["execution"]["status"] == p2["execution"]["status"]


def test_report_records_audit_event(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "report", mid])
    assert r.exit_code == 0
    events = _read_events(data_dir)
    rep_events = [e for e in events if e["kind"] == "mission_report"]
    assert rep_events, events
    last = rep_events[-1]
    assert last["status"] == "success"
    assert last["details"]["mission_id"] == mid
    assert last["details"]["arbitrary_command_execution"] is False
    assert last["safety"]["execution_allowed"] is False
    assert last["safety"]["mutation_performed"] is False


# ---------------------------------------------------------------------------
# Export tests


def test_export_creates_manifest_summary_checksums_and_report(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "export", mid])
    assert r.exit_code == 0, r.output
    # Default export directory is keyed by mission_id (PR52 layout).
    export_dir = data_dir / "mission_exports" / mid
    assert export_dir.is_dir()
    for required in (
        "export-manifest.json",
        "export-summary.md",
        "checksums.sha256",
        "mission-report.json",
        "mission-report.md",
        "mission.json",
        "proposal.json",
        "rollback-preview.json",
        "apply-receipt.json",
        "before-inspect.json",
        "after-inspect.json",
        "audit-events.json",
    ):
        assert (export_dir / required).exists(), required
    manifest = json.loads((export_dir / "export-manifest.json").read_text())
    assert manifest["mission_id"] == mid
    assert manifest["source_type"] == "mission_restart"
    assert manifest["safety"]["execution_allowed"] is False
    assert manifest["safety"]["mutation_performed_by_export"] is False
    assert manifest["safety"]["arbitrary_command_execution"] is False
    assert manifest["redaction_applied"] is False


def test_export_lists_missing_optional_files_when_absent(tmp_path: Path, monkeypatch):
    """For a not-yet-executed mission, optional files like apply-receipt are missing."""
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    out = tmp_path / "out_mission_export"
    result = export_mission(data_dir, mid, output=out, redact=False)
    assert result.export_dir == out
    manifest = json.loads(result.manifest_path.read_text())
    assert "apply-receipt.json" in manifest["missing_optional_files"]
    assert "before-inspect.json" in manifest["missing_optional_files"]
    assert (out / "mission-report.json").exists()


def test_validate_mission_export_passes_on_fresh_export(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    out = tmp_path / "valid_export"
    export_mission(data_dir, mid, output=out)
    r = runner.invoke(app, ["mission", "restart", "validate-export", str(out)])
    assert r.exit_code == 0, r.output
    assert "Mission export validation passed" in r.output


def test_validate_mission_export_fails_on_checksum_mismatch(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    out = tmp_path / "tamper_export"
    export_mission(data_dir, mid, output=out)
    # Tamper with mission-report.json so its checksum no longer matches.
    p = out / "mission-report.json"
    p.write_text(p.read_text() + "\n", encoding="utf-8")
    r = runner.invoke(app, ["mission", "restart", "validate-export", str(out)])
    assert r.exit_code == 1
    assert "checksum mismatch" in r.output


def test_validate_mission_export_fails_when_manifest_missing(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    out = tmp_path / "no_manifest_export"
    export_mission(data_dir, mid, output=out)
    (out / "export-manifest.json").unlink()
    r = runner.invoke(app, ["mission", "restart", "validate-export", str(out)])
    assert r.exit_code == 1
    assert "export-manifest.json not found" in r.output


def test_validate_mission_export_fails_when_report_missing(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    out = tmp_path / "no_report_export"
    export_mission(data_dir, mid, output=out)
    (out / "mission-report.json").unlink()
    r = runner.invoke(app, ["mission", "restart", "validate-export", str(out)])
    assert r.exit_code == 1
    assert "mission-report.json" in r.output


def test_export_records_audit_event(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "export", mid])
    assert r.exit_code == 0
    events = _read_events(data_dir)
    exp_events = [e for e in events if e["kind"] == "mission_export"]
    assert exp_events
    assert exp_events[-1]["status"] == "success"
    assert exp_events[-1]["details"]["arbitrary_command_execution"] is False
    assert exp_events[-1]["details"]["mutation_performed_by_export"] is False


def test_export_validate_records_audit_event(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    out = tmp_path / "audit_validate"
    export_mission(data_dir, mid, output=out)
    r = runner.invoke(app, ["mission", "restart", "validate-export", str(out)])
    assert r.exit_code == 0
    events = _read_events(data_dir)
    val_events = [e for e in events if e["kind"] == "mission_export_validate"]
    assert val_events
    assert val_events[-1]["status"] == "success"


def test_export_does_not_call_apply_or_restart(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "export", mid])
    assert r.exit_code == 0
    # No execution receipts should be created by export.
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    assert receipts == []
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Redaction tests


def test_redacted_export_removes_secret_probes_from_text_files(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    out = tmp_path / "redacted_export"
    result = export_mission(data_dir, mid, output=out, redact=True)
    assert result.redaction_applied is True
    # Probes should not appear in any exported text file.
    for rel in result.included_files:
        text = (out / rel).read_text(encoding="utf-8", errors="replace")
        for probe in FAKE_SECRETS.values():
            assert probe not in text, f"secret leak in {rel}: {probe}"
    # Source files must remain unchanged.
    src_ev = data_dir / "artifacts" / "sf_pr54" / "evidence.json"
    src_summary = data_dir / "artifacts" / "sf_pr54" / "summary.md"
    src_text = src_ev.read_text() + "\n" + src_summary.read_text()
    assert any(probe in src_text for probe in FAKE_SECRETS.values())


def test_redacted_export_includes_redaction_report_and_validates(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    out = tmp_path / "redacted_export_validate"
    export_mission(data_dir, mid, output=out, redact=True)
    assert (out / "redaction-report.json").exists()
    rpayload = json.loads((out / "redaction-report.json").read_text())
    assert rpayload["redaction_applied"] is True
    r = runner.invoke(app, ["mission", "restart", "validate-export", str(out)])
    assert r.exit_code == 0, r.output
    assert "redaction: on" in r.output


def test_export_redact_cli_flag_emits_redaction(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    out = tmp_path / "cli_redact"
    r = runner.invoke(
        app,
        ["mission", "restart", "export", mid, "--redact", "--output", str(out)],
    )
    assert r.exit_code == 0, r.output
    manifest = json.loads((out / "export-manifest.json").read_text())
    assert manifest["redaction_applied"] is True


# ---------------------------------------------------------------------------
# Ask routing tests


def test_ask_show_mission_report_returns_report(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["ask", "show mission report"])
    assert r.exit_code == 0, r.output
    assert "Mission restart report" in r.output
    assert mid in r.output
    assert "Arbitrary command execution: false" in r.output
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    # Only the one already-existing executed receipt; ask must not create more.
    assert len(receipts) == 1


def test_ask_make_redacted_mission_pack_creates_export(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["ask", "make a redacted mission pack"])
    assert r.exit_code == 0, r.output
    assert "Mission export written" in r.output
    assert "redaction: on" in r.output
    # Verify the created export exists and contains no secret probes.
    export_dir = data_dir / "mission_exports" / mid
    assert export_dir.is_dir()
    for p in export_dir.iterdir():
        if p.is_file() and p.suffix in (".md", ".json"):
            text = p.read_text(encoding="utf-8", errors="replace")
            for probe in FAKE_SECRETS.values():
                assert probe not in text, f"secret leak in {p}: {probe}"


def test_ask_did_mission_execute_safely_reports(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["ask", "did the mission execute safely"])
    assert r.exit_code == 0, r.output
    assert "Mission restart report" in r.output
    assert "Verification" in r.output


def test_ask_run_mission_and_export_refuses(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["ask", "run mission and export"])
    assert r.exit_code == 0, r.output
    assert "Refusing to execute" in r.output
    assert fake.calls == []
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    assert receipts == []


def test_ask_does_not_call_apply_or_restart(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    # Track new restarts after execute. We need to create a fresh fake here.
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    fake.calls.clear()
    runner.invoke(app, ["ask", "show mission report"])
    runner.invoke(app, ["ask", "make a redacted mission pack"])
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Audit validate must still pass


def test_audit_validate_passes_after_report_and_export(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    runner.invoke(app, ["mission", "restart", "report", mid])
    out = tmp_path / "audit_pass_export"
    runner.invoke(app, ["mission", "restart", "export", mid, "--output", str(out)])
    runner.invoke(app, ["mission", "restart", "validate-export", str(out)])
    r = runner.invoke(app, ["audit", "validate"])
    assert r.exit_code == 0, r.output


def test_validate_export_module_function(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    out = tmp_path / "module_validate"
    export_mission(data_dir, mid, output=out)
    result = validate_mission_export(out)
    assert result.ok, result.errors


# ---------------------------------------------------------------------------
# Audit-event collection


def test_report_collects_audit_events_for_mission(tmp_path: Path, monkeypatch):
    data_dir, mid, pid = _execute_mission(tmp_path, monkeypatch)
    report = build_mission_report(data_dir, mid)
    assert isinstance(report["audit_events"], list)
    assert report["audit_events"], "expected to find at least one audit event"
    kinds = {e["kind"] for e in report["audit_events"]}
    # The execute path emits restart_mission delegated + the actual execution.
    assert "restart_mission" in kinds or "execution" in kinds


# ---------------------------------------------------------------------------
# Report shape: command_argv + safety semantics


def test_executed_report_records_command_argv(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "report", mid, "--json"])
    payload = json.loads(r.output)
    assert payload["execution"]["command_argv"] == ["docker", "restart", CONTAINER]
    assert payload["execution"]["docker_mutation"] is True
    assert payload["execution"]["service_impacting"] is True
