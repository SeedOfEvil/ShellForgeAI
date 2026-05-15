"""PR48: post-mutation verification gate for lab container restart.

Tests are deterministic and self-contained. They use ``tmp_path`` as the data
dir, fake the executor and the inspector, and never touch live Docker, root,
journalctl, systemd, or the network. There is no real ``time.sleep``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.cli import app
from shellforgeai.core import lab_restart as lab_restart_mod
from shellforgeai.core.approvals import (
    STATUS_APPROVED,
    Proposal,
    ProposalApproval,
    ProposalExecution,
    ProposalSource,
    compute_proposal_fingerprint_payload,
    write_proposal,
)
from shellforgeai.core.ask_routing import (
    is_lab_restart_ask_intent,
    is_lab_restart_verification_ask_intent,
)
from shellforgeai.core.lab_restart import (
    ENV_ALLOW_LAB_RESTART,
    ENV_MUTATION_MODE,
    HEALTH_HEALTHY,
    HEALTH_NONE,
    HEALTH_STARTING,
    HEALTH_UNHEALTHY,
    MUTATION_SCOPE,
    VERIFICATION_STATUS_FAILED,
    VERIFICATION_STATUS_PASSED,
    VERIFICATION_STATUS_SKIPPED,
    VERIFICATION_STATUS_WARNING,
    ContainerState,
    ExecResult,
    FakeCommandExecutor,
    FakeContainerInspector,
    InspectResult,
    VerificationConfig,
    capture_container_state_from,
    make_inspect_payload,
    parse_inspect_payload,
    run_post_restart_verification,
    write_default_allowlist,
)
from shellforgeai.core.rollback_preview import write_preview

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures


def _enable_mutation_env(monkeypatch) -> None:
    monkeypatch.setenv(ENV_MUTATION_MODE, "lab")
    monkeypatch.setenv(ENV_ALLOW_LAB_RESTART, "1")


def _mk_restart_proposal(
    *,
    proposal_id: str = "prop_pr48_001",
    container: str = "sfai-healthy-web",
) -> Proposal:
    steps = [f"OPERATOR-RUN: docker restart {container}   # SERVICE-IMPACTING"]
    rollback = [f"docker logs --tail 50 {container}"]
    verification = [f"docker inspect {container}"]
    fp = compute_proposal_fingerprint_payload(
        session_id="sf_test_pr48",
        option_id="opt_pr48_001",
        component=container,
        kind="container_restart",
        title=f"Restart {container} after config change",
        risk="medium",
        steps=steps,
        rollback=rollback,
        verification=verification,
    )
    return Proposal(
        proposal_id=proposal_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        status=STATUS_APPROVED,
        source=ProposalSource(session_id="sf_test_pr48"),
        target="docker",
        component=container,
        kind="container_restart",
        title=f"Restart {container} after config change",
        risk="medium",
        confidence="medium",
        impact=f"Recreates {container} container after lab config change.",
        safety_labels=["OPERATOR-RUN", "REQUIRES APPROVAL", "SERVICE-IMPACTING"],
        preconditions=["Lab container is healthy enough to restart."],
        proposed_steps=steps,
        rollback=rollback,
        verification=verification,
        notes="",
        execution=ProposalExecution(allowed=False, status="not_executed"),
        fingerprint=fp,
        approval=ProposalApproval(
            reason="lab restart approved for test",
            approved_at="2026-05-14T00:00:01+00:00",
            approved_by="op",
        ),
    )


def _seed_lab(
    tmp_path: Path,
    *,
    container: str = "sfai-healthy-web",
    proposal_id: str = "prop_pr48_001",
    with_rollback_preview: bool = True,
) -> Proposal:
    proposal = _mk_restart_proposal(proposal_id=proposal_id, container=container)
    write_proposal(tmp_path, proposal)
    write_default_allowlist(tmp_path, containers=[container], enabled=True)
    if with_rollback_preview:
        write_preview(tmp_path, proposal)
    return proposal


def _patch(monkeypatch, *, executor: FakeCommandExecutor, inspector: FakeContainerInspector):
    from shellforgeai import cli as cli_mod

    monkeypatch.setattr(cli_mod, "_lab_restart_executor_factory", lambda: executor)
    monkeypatch.setattr(cli_mod, "_lab_restart_inspector_factory", lambda: inspector)
    monkeypatch.setattr(
        cli_mod,
        "_lab_restart_verification_config",
        lambda: VerificationConfig(
            post_restart_wait_seconds=0,
            health_wait_seconds=0,
            health_poll_interval_seconds=0,
        ),
    )
    monkeypatch.setattr(cli_mod, "_lab_restart_verification_sleep", lambda _s: None)


def _read_events(tmp_path: Path) -> list[dict]:
    return AuditStorage(tmp_path).read_events()


def _make_inspector(*payloads_or_results) -> FakeContainerInspector:
    """Helper: convert payload dicts (or raw InspectResults) to a queue."""
    queued: list[InspectResult] = []
    for item in payloads_or_results:
        if isinstance(item, InspectResult):
            queued.append(item)
        elif item is None:
            queued.append(InspectResult(ok=True, exists=False, raw=None, error="not found"))
        else:
            queued.append(InspectResult(ok=True, exists=True, raw=item))
    return FakeContainerInspector(results=queued)


# ---------------------------------------------------------------------------
# Pure-function tests for the verification core


def test_parse_inspect_payload_normalizes_running_container():
    raw = make_inspect_payload(
        container_id="abc",
        running=True,
        status="running",
        started_at="2026-05-14T12:00:00.000Z",
        exit_code=0,
        restart_count=3,
    )
    state = parse_inspect_payload(raw)
    assert state.exists is True
    assert state.container_id == "abc"
    assert state.running is True
    assert state.status == "running"
    assert state.started_at == "2026-05-14T12:00:00.000Z"
    assert state.exit_code == 0
    assert state.restart_count == 3
    assert state.has_healthcheck is False
    assert state.health == HEALTH_NONE


def test_parse_inspect_payload_handles_list_form():
    raw = make_inspect_payload()
    state = parse_inspect_payload([raw])
    assert state.exists is True


def test_parse_inspect_payload_handles_healthcheck():
    raw = make_inspect_payload(health="healthy")
    state = parse_inspect_payload(raw)
    assert state.has_healthcheck is True
    assert state.health == HEALTH_HEALTHY


def test_parse_inspect_payload_normalizes_unknown_health():
    raw = make_inspect_payload(health="weird")
    state = parse_inspect_payload(raw)
    assert state.health == "unknown"


def test_parse_inspect_payload_missing_container():
    state = parse_inspect_payload([])
    assert state.exists is False


def test_capture_container_state_from_handles_failed_inspect():
    res = InspectResult(ok=False, exists=False, raw=None, error="not found")
    state = capture_container_state_from(res)
    assert state.exists is False


# ---------------------------------------------------------------------------
# run_post_restart_verification


def _before_state(started_at="A", health=HEALTH_NONE, has_health=False, restart_count=0):
    return ContainerState(
        exists=True,
        container_id="abc",
        running=True,
        status="running",
        started_at=started_at,
        exit_code=0,
        health=health,
        restart_count=restart_count,
        has_healthcheck=has_health,
    )


def test_verification_pass_when_started_at_changes_and_running():
    inspector = _make_inspector(
        make_inspect_payload(started_at="B", running=True, restart_count=0),
    )
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A"),
        restart_ok=True,
        config=VerificationConfig(0, 0, 0),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_PASSED
    assert outcome.summary["started_at_changed"] is True
    assert outcome.summary["running_after"] is True
    assert outcome.after_raw is not None


def test_verification_warning_when_started_at_unchanged():
    inspector = _make_inspector(
        make_inspect_payload(started_at="A", running=True, restart_count=0),
    )
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A"),
        restart_ok=True,
        config=VerificationConfig(0, 0, 0),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_WARNING
    assert outcome.summary["started_at_changed"] is False
    assert outcome.summary["running_after"] is True


def test_verification_warning_when_restart_count_unchanged_but_started_changed():
    # StartedAt did change, RestartCount did not — note added but still passing.
    inspector = _make_inspector(
        make_inspect_payload(started_at="B", running=True, restart_count=0),
    )
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A", restart_count=0),
        restart_ok=True,
        config=VerificationConfig(0, 0, 0),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_PASSED
    assert any("RestartCount" in n for n in outcome.summary["notes"])


def test_verification_failed_when_container_not_running_after():
    inspector = _make_inspector(
        make_inspect_payload(started_at="B", running=False, status="exited"),
    )
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A"),
        restart_ok=True,
        config=VerificationConfig(0, 0, 0),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_FAILED
    assert outcome.summary["running_after"] is False


def test_verification_failed_when_container_missing_after():
    inspector = _make_inspector(None)
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A"),
        restart_ok=True,
        config=VerificationConfig(0, 0, 0),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_FAILED
    assert "missing" in " ".join(outcome.summary["notes"]).lower()


def test_verification_failed_when_inspect_fails():
    inspector = FakeContainerInspector(
        results=[InspectResult(ok=False, exists=False, raw=None, error="boom")]
    )
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A"),
        restart_ok=True,
        config=VerificationConfig(0, 0, 0),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_FAILED


def test_verification_skipped_when_restart_failed():
    inspector = FakeContainerInspector(results=[])
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A"),
        restart_ok=False,
        config=VerificationConfig(0, 0, 0),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_SKIPPED
    # Inspector is never called when restart fails.
    assert inspector.calls == []


def test_verification_pass_with_healthy_healthcheck():
    inspector = _make_inspector(
        make_inspect_payload(started_at="B", running=True, health="healthy"),
    )
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A", has_health=True, health=HEALTH_HEALTHY),
        restart_ok=True,
        config=VerificationConfig(0, 0, 0),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_PASSED
    assert outcome.summary["health_after"] == HEALTH_HEALTHY


def test_verification_warning_when_starting_after_timeout():
    # First inspect returns starting; with health_wait_seconds=0, no extra polls,
    # so the verification status is WARNING with the starting-after-timeout note.
    inspector = _make_inspector(
        make_inspect_payload(started_at="B", running=True, health="starting"),
    )
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A", has_health=True, health=HEALTH_STARTING),
        restart_ok=True,
        config=VerificationConfig(
            post_restart_wait_seconds=0, health_wait_seconds=0, health_poll_interval_seconds=0
        ),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_WARNING
    assert outcome.summary["health_after"] == HEALTH_STARTING


def test_verification_pass_when_starting_then_healthy():
    inspector = _make_inspector(
        make_inspect_payload(started_at="B", running=True, health="starting"),
        make_inspect_payload(started_at="B", running=True, health="healthy"),
    )
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A", has_health=True, health=HEALTH_STARTING),
        restart_ok=True,
        config=VerificationConfig(
            post_restart_wait_seconds=0,
            health_wait_seconds=5,
            health_poll_interval_seconds=1,
        ),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_PASSED
    assert outcome.summary["health_after"] == HEALTH_HEALTHY


def test_verification_failed_when_unhealthy():
    inspector = _make_inspector(
        make_inspect_payload(started_at="B", running=True, health="unhealthy"),
    )
    outcome = run_post_restart_verification(
        inspector=inspector,
        container="sfai-healthy-web",
        before_state=_before_state(started_at="A", has_health=True, health=HEALTH_HEALTHY),
        restart_ok=True,
        config=VerificationConfig(0, 0, 0),
        sleep_fn=lambda _s: None,
    )
    assert outcome.summary["status"] == VERIFICATION_STATUS_FAILED
    assert outcome.summary["health_after"] == HEALTH_UNHEALTHY


# ---------------------------------------------------------------------------
# CLI end-to-end (apply --execute --confirm) with verification


def test_apply_execute_confirm_records_verification_pass(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake_executor = FakeCommandExecutor()
    inspector = _make_inspector(
        make_inspect_payload(started_at="A", running=True, restart_count=0),
        make_inspect_payload(started_at="B", running=True, restart_count=0),
    )
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)
    proposal = _seed_lab(tmp_path)

    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    assert "Guarded lab container restart executed:" in r.stdout
    assert "verification: passed" in r.stdout
    assert "running_after: True" in r.stdout
    assert "started_at_changed: True" in r.stdout

    # Receipt JSON includes verification + evidence files.
    receipts = list((tmp_path / "execution_receipts").glob("exec_*.json"))
    assert len(receipts) == 1
    payload = json.loads(receipts[0].read_text())
    v = payload["verification"]
    assert v["status"] == VERIFICATION_STATUS_PASSED
    assert v["running_after"] is True
    assert v["started_at_changed"] is True
    assert v["started_at_before"] == "A"
    assert v["started_at_after"] == "B"
    assert "evidence" in v
    assert Path(v["evidence"]["before_inspect_path"]).exists()
    assert Path(v["evidence"]["after_inspect_path"]).exists()
    md_path = receipts[0].with_suffix(".md")
    assert md_path.exists()
    md_text = md_path.read_text()
    assert "verification" in md_text.lower()

    events = _read_events(tmp_path)
    success = [
        e
        for e in events
        if e["kind"] == "execution"
        and e["action"] == "lab_container_restart"
        and e["status"] == "success"
    ]
    assert success
    ev = success[0]
    assert ev["details"]["verification_status"] == VERIFICATION_STATUS_PASSED
    assert ev["details"]["container_running_after"] is True
    assert ev["details"]["started_at_changed"] is True
    assert ev["safety"]["mutation_scope"] == MUTATION_SCOPE
    assert ev["safety"]["execution_allowed"] is True
    assert ev["safety"]["execution_status"] == "executed"
    assert ev["safety"]["mutation_performed"] is True

    # Mutation argv stayed exact and inspector saw inspect-only.
    assert fake_executor.calls == [["docker", "restart", "sfai-healthy-web"]]


def test_apply_execute_confirm_records_verification_warning(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake_executor = FakeCommandExecutor()
    # StartedAt unchanged -> warning.
    inspector = _make_inspector(
        make_inspect_payload(started_at="A", running=True),
        make_inspect_payload(started_at="A", running=True),
    )
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)
    proposal = _seed_lab(tmp_path)

    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    assert "verification warning" in r.stdout
    assert "verification: warning" in r.stdout

    payload = json.loads(
        next(iter((tmp_path / "execution_receipts").glob("exec_*.json"))).read_text()
    )
    assert payload["verification"]["status"] == VERIFICATION_STATUS_WARNING

    events = _read_events(tmp_path)
    warn = [
        e
        for e in events
        if e["kind"] == "execution"
        and e["action"] == "lab_container_restart"
        and e["status"] == "warning"
    ]
    assert warn
    assert warn[0]["details"]["verification_status"] == VERIFICATION_STATUS_WARNING


def test_apply_execute_confirm_records_verification_failed(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake_executor = FakeCommandExecutor()
    inspector = _make_inspector(
        make_inspect_payload(started_at="A", running=True),
        make_inspect_payload(started_at="B", running=False, status="exited"),
    )
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)
    proposal = _seed_lab(tmp_path)

    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "verification failed" in r.stdout
    assert "no additional restart attempted" in r.stdout
    # Restart was only attempted once.
    assert fake_executor.calls == [["docker", "restart", "sfai-healthy-web"]]

    payload = json.loads(
        next(iter((tmp_path / "execution_receipts").glob("exec_*.json"))).read_text()
    )
    assert payload["verification"]["status"] == VERIFICATION_STATUS_FAILED
    assert payload["verification"]["running_after"] is False

    events = _read_events(tmp_path)
    failed = [
        e
        for e in events
        if e["kind"] == "execution"
        and e["action"] == "lab_container_restart"
        and e["status"] == "failed"
    ]
    assert failed
    assert failed[0]["details"]["verification_status"] == VERIFICATION_STATUS_FAILED


def test_apply_execute_confirm_restart_failure_skips_verification(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake_executor = FakeCommandExecutor(
        result=ExecResult(ok=False, exit_code=1, stdout="", stderr="container not found")
    )
    # Only the before-inspect call should happen.
    inspector = _make_inspector(
        make_inspect_payload(started_at="A", running=True),
    )
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)
    proposal = _seed_lab(tmp_path)

    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "Guarded lab container restart failed" in r.stdout

    payload = json.loads(
        next(iter((tmp_path / "execution_receipts").glob("exec_*.json"))).read_text()
    )
    assert payload["verification"]["status"] == VERIFICATION_STATUS_SKIPPED
    assert payload["result"]["status"] == "failed"
    # Inspector was only called once (the pre-restart capture).
    assert inspector.calls == ["sfai-healthy-web"]


def test_apply_execute_confirm_audit_validate_passes_with_verification(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake_executor = FakeCommandExecutor()
    inspector = _make_inspector(
        make_inspect_payload(started_at="A", running=True),
        make_inspect_payload(started_at="B", running=True),
    )
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)
    proposal = _seed_lab(tmp_path)

    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    storage = AuditStorage(tmp_path)
    vr = storage.validate_events()
    assert vr.ok, vr.errors


# ---------------------------------------------------------------------------
# Safety: no docker exec, no shell=True, no second restart


def test_inspector_uses_argv_only_no_shell():
    """The DockerCliInspector must call subprocess with shell=False on argv list."""
    import subprocess

    captured = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        result = subprocess.CompletedProcess(args=args[0], returncode=0, stdout="[]", stderr="")
        return result

    insp = lab_restart_mod.DockerCliInspector()
    import shellforgeai.core.lab_restart as mod

    orig = mod.subprocess.run
    try:
        mod.subprocess.run = fake_run  # type: ignore[assignment]
        insp.inspect("sfai-healthy-web")
    finally:
        mod.subprocess.run = orig  # type: ignore[assignment]
    assert captured["kwargs"].get("shell") is False
    assert captured["args"][0] == ["docker", "inspect", "sfai-healthy-web"]


def test_inspector_refuses_unsafe_container_name():
    insp = lab_restart_mod.DockerCliInspector()
    res = insp.inspect("; rm -rf /")
    assert not res.ok
    assert "unsafe" in res.error.lower()


def test_unsafe_container_name_refused_before_verification(tmp_path: Path, monkeypatch):
    """Even unsafe names compiled into actions are refused at the gate."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake_executor = FakeCommandExecutor()
    inspector = FakeContainerInspector(results=[])
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)

    # Seed an allowlist that does NOT include the unsafe name.
    write_default_allowlist(tmp_path, containers=["sfai-healthy-web"], enabled=True)
    proposal = _mk_restart_proposal(container="sfai-healthy-web")
    write_proposal(tmp_path, proposal)

    # Even though gates pass for the safe name, the inspector must never see
    # an unsafe name. Independently verify the inspector rejects unsafe argv.
    res = inspector.inspect("bad;name")
    assert not res.ok


# ---------------------------------------------------------------------------
# Ask integration: read-only verification queries; mutation refusal preserved


def test_ask_show_verification_intent_matches_verification_phrasings():
    assert is_lab_restart_verification_ask_intent("did the restart work?").matched
    assert is_lab_restart_verification_ask_intent("show restart verification").matched
    assert is_lab_restart_verification_ask_intent("show post-mutation verification").matched
    assert is_lab_restart_verification_ask_intent("show last execution receipt").matched
    assert is_lab_restart_verification_ask_intent(
        "was the container running after restart?"
    ).matched
    # Mutation phrasings are NOT a verification-only ask.
    assert not is_lab_restart_verification_ask_intent("restart it and verify").matched
    assert not is_lab_restart_verification_ask_intent("restart sfai-healthy-web").matched


def test_ask_restart_and_verify_is_refused_as_mutation():
    intent = is_lab_restart_ask_intent("restart it and verify")
    assert intent.matched is True
    # And the verification-only intent must NOT match this mutation phrasing.
    assert not is_lab_restart_verification_ask_intent("restart it and verify").matched


def test_ask_restart_it_and_verify_does_not_execute(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake_executor = FakeCommandExecutor()
    inspector = FakeContainerInspector(results=[])
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)
    _seed_lab(tmp_path)

    r = runner.invoke(app, ["ask", "restart it and verify"])
    assert r.exit_code == 0, r.stdout
    assert "Refusing to execute" in r.stdout
    assert "post-mutation verification runs automatically" in r.stdout
    assert fake_executor.calls == []
    assert inspector.calls == []


def test_ask_show_verification_with_no_receipt_explains_path(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    fake_executor = FakeCommandExecutor()
    inspector = FakeContainerInspector(results=[])
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)

    r = runner.invoke(app, ["ask", "show restart verification"])
    assert r.exit_code == 0, r.stdout
    assert "no execution receipt found" in r.stdout
    assert "apply" in r.stdout
    assert fake_executor.calls == []
    assert inspector.calls == []


def test_ask_show_verification_summarizes_existing_receipt(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    # First execute a real (faked) restart so a verification block exists.
    fake_executor = FakeCommandExecutor()
    inspector = _make_inspector(
        make_inspect_payload(started_at="A", running=True),
        make_inspect_payload(started_at="B", running=True),
    )
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)
    proposal = _seed_lab(tmp_path)

    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout

    # Now use ask to summarize verification — must be read-only.
    fake_executor2 = FakeCommandExecutor()
    inspector2 = FakeContainerInspector(results=[])
    _patch(monkeypatch, executor=fake_executor2, inspector=inspector2)

    r2 = runner.invoke(app, ["ask", "did the restart work?"])
    assert r2.exit_code == 0, r2.stdout
    assert "verification: passed" in r2.stdout
    assert fake_executor2.calls == []
    assert inspector2.calls == []


def test_ask_verification_does_not_fire_on_unrelated_question(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    assert not is_lab_restart_verification_ask_intent("what is the weather?").matched


# ---------------------------------------------------------------------------
# Receipt format compatibility


def test_receipt_filename_pattern_unchanged(tmp_path: Path, monkeypatch):
    """PR47-shape glob (``exec_*.json`` at top level) still finds exactly one."""
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake_executor = FakeCommandExecutor()
    inspector = _make_inspector(
        make_inspect_payload(started_at="A", running=True),
        make_inspect_payload(started_at="B", running=True),
    )
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)
    proposal = _seed_lab(tmp_path)

    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    receipts = list((tmp_path / "execution_receipts").glob("exec_*.json"))
    assert len(receipts) == 1
    # Evidence directory is a sibling.
    evidence_dir = receipts[0].with_suffix("")
    assert evidence_dir.is_dir()
    assert (evidence_dir / "before-inspect.json").exists()
    assert (evidence_dir / "after-inspect.json").exists()


# ---------------------------------------------------------------------------
# Audit timeline / search regressions


def test_audit_timeline_shows_verification_status(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake_executor = FakeCommandExecutor()
    inspector = _make_inspector(
        make_inspect_payload(started_at="A", running=True),
        make_inspect_payload(started_at="B", running=True),
    )
    _patch(monkeypatch, executor=fake_executor, inspector=inspector)
    proposal = _seed_lab(tmp_path)

    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    tl = runner.invoke(app, ["audit", "timeline"])
    assert tl.exit_code == 0, tl.stdout
    assert "lab_container_restart" in tl.stdout
