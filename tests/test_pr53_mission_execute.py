"""PR53: mission execute handoff to the existing apply gate.

Tests are deterministic and self-contained. ``tmp_path`` is used as
``SHELLFORGEAI_DATA_DIR``; the executor and inspector are faked. No live
Docker, no root, no journalctl, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.audit.storage import AuditStorage
from shellforgeai.cli import app
from shellforgeai.core import lab_restart as lab_restart_mod
from shellforgeai.core.approvals import (
    approve_proposal,
    cancel_proposal,
    reject_proposal,
)
from shellforgeai.core.lab_restart import (
    ENV_ALLOW_LAB_RESTART,
    ENV_MUTATION_MODE,
    FakeCommandExecutor,
    write_default_allowlist,
)
from shellforgeai.core.mission import (
    prepare_mission,
)
from shellforgeai.core.rollback_preview import write_preview

runner = CliRunner()

CONTAINER = "sfai-pr53-target"


def _enable_mutation_env(monkeypatch) -> None:
    monkeypatch.setenv(ENV_MUTATION_MODE, "lab")
    monkeypatch.setenv(ENV_ALLOW_LAB_RESTART, "1")


def _disable_mutation_env(monkeypatch) -> None:
    monkeypatch.delenv(ENV_MUTATION_MODE, raising=False)
    monkeypatch.delenv(ENV_ALLOW_LAB_RESTART, raising=False)


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


def _write_evidence(dst: Path, name: str = CONTAINER) -> Path:
    payload = {
        "session_id": "sf_pr53",
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
    p = dst / "evidence.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _setup_mission(
    tmp_path: Path,
    monkeypatch,
    *,
    approve: bool = False,
    rollback: bool = False,
    allowlist: bool = True,
) -> tuple[Path, str, str]:
    """Prepare a mission. Returns (data_dir, mission_id, proposal_id)."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    sess = tmp_path / "artifacts" / "sf_pr53"
    sess.mkdir(parents=True, exist_ok=True)
    ev = _write_evidence(sess)
    if allowlist:
        write_default_allowlist(tmp_path, containers=[CONTAINER], enabled=True)
    res = prepare_mission(tmp_path, container=CONTAINER, evidence_path=ev, session_id="sf_pr53")
    assert res.ok, res.refusal
    assert res.payload is not None
    pid = res.payload["proposal_id"]
    if approve:
        proposal = approve_proposal(tmp_path, pid, reason="ok")
        if rollback:
            write_preview(tmp_path, proposal)
    elif rollback:
        from shellforgeai.core.approvals import find_proposal_path, load_proposal_from_path

        path, _ = find_proposal_path(tmp_path, pid)
        if path is not None:
            write_preview(tmp_path, load_proposal_from_path(path))
    return tmp_path, res.mission_id, pid


def _read_events(tmp_path: Path) -> list[dict]:
    return AuditStorage(tmp_path).read_events()


# ---------------------------------------------------------------------------
# Dry-run / readiness preview


def test_mission_execute_dry_run_shows_blockers_when_not_ready(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--dry-run"])
    assert r.exit_code == 1, r.output
    assert "dry-run / no execution" in r.output
    assert "readiness: blocked" in r.output
    assert "shellforgeai apply" in r.output and "--execute --confirm" in r.output
    assert "arbitrary_command_execution: false" in r.output
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    assert receipts == []


def test_mission_execute_dry_run_ready_shows_delegation_command(tmp_path: Path, monkeypatch):
    data_dir, mid, pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "readiness: ready" in r.output
    # Rich console may soft-wrap long lines; check the parts independently.
    assert f"shellforgeai apply {pid}" in r.output
    assert "--execute --confirm" in r.output


def test_mission_execute_without_execute_is_dry_run(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid])
    assert r.exit_code == 0, r.output
    assert "dry-run / no execution" in r.output
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Confirmation gate


def test_mission_execute_requires_confirm(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute"])
    assert r.exit_code == 1, r.output
    assert "confirm" in r.output.lower()
    assert "no commands executed" in r.output
    assert fake.calls == []
    events = _read_events(data_dir)
    assert any(e["kind"] == "restart_mission" and e["status"] == "refused" for e in events)


# ---------------------------------------------------------------------------
# Readiness refusal matrix


def test_mission_execute_refuses_pending_proposal(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "Mission execution refused" in r.output
    assert fake.calls == []


def test_mission_execute_refuses_rejected_proposal(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, pid = _setup_mission(tmp_path, monkeypatch)
    reject_proposal(data_dir, pid, reason="no")
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert fake.calls == []


def test_mission_execute_refuses_canceled_proposal(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, pid = _setup_mission(tmp_path, monkeypatch)
    cancel_proposal(data_dir, pid, reason="no")
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert fake.calls == []


def test_mission_execute_refuses_missing_rollback_preview(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "rollback" in r.output.lower()
    assert fake.calls == []


def test_mission_execute_refuses_invalid_rollback_preview(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    # Corrupt the rollback preview to make it invalid.
    preview = data_dir / "rollback_previews" / pid / "rollback-preview.json"
    payload = json.loads(preview.read_text())
    payload["rollback_executable_by_shellforgeai"] = True
    preview.write_text(json.dumps(payload), encoding="utf-8")
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert fake.calls == []


def test_mission_execute_refuses_unknown_mission(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    write_default_allowlist(tmp_path, containers=[CONTAINER], enabled=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(
        app,
        [
            "mission",
            "restart",
            "execute",
            "mission_restart_does_not_exist",
            "--execute",
            "--confirm",
        ],
    )
    assert r.exit_code == 1
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Successful delegation


def test_mission_execute_delegates_to_apply_gate(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 0, r.output
    assert "Mission execution completed through apply gate" in r.output
    assert "execution_path: apply_gate" in r.output
    # The lab-restart fake executor was invoked exactly once.
    assert fake.calls == [["docker", "restart", CONTAINER]]

    # Mission record reflects executed/verified state and references the receipt.
    mp = data_dir / "missions" / "restart" / mid / "mission.json"
    payload = json.loads(mp.read_text())
    assert payload["status"] == "executed"
    assert payload["phases"]["execution"]["status"] == "executed"
    receipt_ref = payload["phases"]["execution"]["receipt"]
    assert receipt_ref and Path(receipt_ref).exists()
    assert payload["phases"]["verification"]["status"] == "passed"
    assert payload["safety"]["arbitrary_command_execution"] is False
    assert payload["safety"]["execution_status"] == "executed"

    # An execution receipt exists and matches the mission reference.
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    assert len(receipts) == 1
    assert str(receipts[0]) == receipt_ref

    # Audit event emitted for delegated execute.
    events = _read_events(data_dir)
    delegated = [
        e for e in events if e["kind"] == "restart_mission" and e["action"] == "execute_delegated"
    ]
    assert delegated, events
    assert delegated[-1]["status"] == "success"
    assert delegated[-1]["details"]["execution_path"] == "apply_gate"
    assert delegated[-1]["details"]["arbitrary_command_execution"] is False


def test_mission_execute_failure_records_failed_status(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = FakeCommandExecutor()
    fake.result = lab_restart_mod.ExecResult(ok=False, exit_code=1, stdout="", stderr="boom")
    _patch_fake_executor(monkeypatch, fake)
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 1
    mp = data_dir / "missions" / "restart" / mid / "mission.json"
    payload = json.loads(mp.read_text())
    assert payload["status"] == "failed"
    assert payload["phases"]["execution"]["status"] == "executed"  # receipt exists
    assert payload["phases"]["execution"].get("result") == "failed"
    assert payload["safety"]["arbitrary_command_execution"] is False
    assert payload["safety"]["execution_status"] != "executed"


# ---------------------------------------------------------------------------
# Audit validate still passes


def test_mission_execute_audit_validate_passes(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 0
    r2 = runner.invoke(app, ["audit", "validate"])
    assert r2.exit_code == 0, r2.output


# ---------------------------------------------------------------------------
# Mission export integrates receipt


def test_mission_export_after_execution_includes_receipt(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 0
    out_dir = tmp_path / "export_out"
    r2 = runner.invoke(app, ["mission", "restart", "export", mid, "--output", str(out_dir)])
    assert r2.exit_code == 0, r2.output
    manifest = json.loads((out_dir / "manifest.json").read_text())
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    assert receipts
    receipt_name = receipts[0].name
    assert receipt_name in manifest["included_files"]
    assert (out_dir / receipt_name).exists()
    assert manifest["execution_receipt"] == str(receipts[0])


# ---------------------------------------------------------------------------
# Mission validate still passes after execution


def test_mission_validate_after_execution_passes(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 0
    r2 = runner.invoke(app, ["mission", "restart", "validate", mid])
    assert r2.exit_code == 0, r2.output


# ---------------------------------------------------------------------------
# Ask refusal regression: ask never calls the apply gate


def test_ask_run_mission_refuses_and_does_not_execute(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["ask", "run the restart mission"])
    assert r.exit_code == 0, r.output
    assert "Refusing to execute" in r.output
    assert "apply" in r.output and "--execute --confirm" in r.output
    assert fake.calls == []
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    assert receipts == []


def test_ask_is_mission_ready_is_read_only(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["ask", "is the restart mission ready"])
    assert r.exit_code == 0, r.output
    assert fake.calls == []
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    assert receipts == []


# ---------------------------------------------------------------------------
# Status refresh preserves terminal execution state (regression: see PR53
# follow-up — `mission restart status` was rewriting executed missions back to
# status=ready / execution=not_executed / verification=not_run).


def _execute_and_return_mid(tmp_path: Path, monkeypatch) -> tuple[Path, str]:
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 0, r.output
    return data_dir, mid


def test_mission_status_preserves_executed_state(tmp_path: Path, monkeypatch):
    data_dir, mid = _execute_and_return_mid(tmp_path, monkeypatch)
    mp = data_dir / "missions" / "restart" / mid / "mission.json"
    before = json.loads(mp.read_text())
    assert before["status"] == "executed"
    receipt_ref = before["phases"]["execution"]["receipt"]
    assert receipt_ref and Path(receipt_ref).exists()

    r = runner.invoke(app, ["mission", "restart", "status", mid])
    assert r.exit_code == 0, r.output

    after = json.loads(mp.read_text())
    assert after["status"] == "executed"
    assert after["phases"]["execution"]["status"] == "executed"
    assert after["phases"]["execution"]["receipt"] == receipt_ref
    assert after["phases"]["verification"]["status"] == "passed"
    assert after["phases"]["verification"]["receipt"] == receipt_ref
    assert after["safety"]["arbitrary_command_execution"] is False
    assert after["safety"]["execution_status"] == "executed"
    assert after["safety"]["mutation_performed"] is True


def test_mission_status_json_preserves_executed_state(tmp_path: Path, monkeypatch):
    data_dir, mid = _execute_and_return_mid(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "status", mid, "--json"])
    assert r.exit_code == 0, r.output
    payload = json.loads(r.output)
    assert payload["status"] == "executed"
    assert payload["phases"]["execution"]["status"] == "executed"
    assert payload["phases"]["execution"]["receipt"]
    assert payload["phases"]["verification"]["status"] == "passed"
    assert payload["phases"]["verification"]["receipt"]
    assert payload["safety"]["arbitrary_command_execution"] is False


def test_mission_checklist_after_execution_does_not_suggest_apply(tmp_path: Path, monkeypatch):
    data_dir, mid = _execute_and_return_mid(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "checklist", mid])
    assert r.exit_code == 0, r.output
    out = r.output
    assert "[OK] Execution" in out
    assert "[OK] Verification" in out
    # Post-execution next_commands must not suggest the apply gate.
    assert "shellforgeai apply" not in out
    assert "audit timeline" in out


def test_mission_validate_executed_passes(tmp_path: Path, monkeypatch):
    data_dir, mid = _execute_and_return_mid(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "validate", mid])
    assert r.exit_code == 0, r.output


def test_mission_validate_executed_without_receipt_fails(tmp_path: Path, monkeypatch):
    data_dir, mid = _execute_and_return_mid(tmp_path, monkeypatch)
    mp = data_dir / "missions" / "restart" / mid / "mission.json"
    payload = json.loads(mp.read_text())
    payload["phases"]["execution"]["receipt"] = None
    mp.write_text(json.dumps(payload), encoding="utf-8")
    r = runner.invoke(app, ["mission", "restart", "validate", mid])
    assert r.exit_code == 1
    assert "receipt" in r.output.lower()


def test_mission_validate_arbitrary_exec_after_executed_fails(tmp_path: Path, monkeypatch):
    data_dir, mid = _execute_and_return_mid(tmp_path, monkeypatch)
    mp = data_dir / "missions" / "restart" / mid / "mission.json"
    payload = json.loads(mp.read_text())
    payload["safety"]["arbitrary_command_execution"] = True
    mp.write_text(json.dumps(payload), encoding="utf-8")
    r = runner.invoke(app, ["mission", "restart", "validate", mid])
    assert r.exit_code == 1
    assert "arbitrary_command_execution" in r.output


def test_status_refresh_still_marks_ready_pre_execution(tmp_path: Path, monkeypatch):
    """Regression guard: pre-execution refresh must still compute readiness."""
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    r = runner.invoke(app, ["mission", "restart", "status", mid, "--json"])
    assert r.exit_code == 0
    payload = json.loads(r.output)
    assert payload["status"] == "ready"
    assert payload["phases"]["execution"]["status"] == "not_executed"
    assert payload["phases"]["verification"]["status"] == "not_run"


def test_status_refresh_preserves_refusal_record(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch)
    _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 1
    mp = data_dir / "missions" / "restart" / mid / "mission.json"
    refused = json.loads(mp.read_text())
    assert refused["phases"]["execution"]["status"] == "refused"
    assert refused["status"] == "blocked"

    r2 = runner.invoke(app, ["mission", "restart", "status", mid, "--json"])
    assert r2.exit_code == 0
    payload = json.loads(r2.output)
    assert payload["phases"]["execution"]["status"] == "refused"
    assert payload["status"] == "blocked"


def test_failed_mission_status_does_not_reset_to_ready(tmp_path: Path, monkeypatch):
    _enable_mutation_env(monkeypatch)
    data_dir, mid, _pid = _setup_mission(tmp_path, monkeypatch, approve=True, rollback=True)
    fake = FakeCommandExecutor()
    fake.result = lab_restart_mod.ExecResult(ok=False, exit_code=1, stdout="", stderr="boom")
    _patch_fake_executor(monkeypatch, fake)
    r = runner.invoke(app, ["mission", "restart", "execute", mid, "--execute", "--confirm"])
    assert r.exit_code == 1

    r2 = runner.invoke(app, ["mission", "restart", "status", mid, "--json"])
    assert r2.exit_code == 0
    payload = json.loads(r2.output)
    assert payload["status"] == "failed"
    assert payload["phases"]["execution"]["status"] == "executed"
