"""PR32: approval queue / mutation proposal objects.

Deterministic, no Docker/systemd/journalctl/internet/root required.
Every test uses ``tmp_path`` as the data dir.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.approvals import (
    APPROVAL_STATUSES,
    PROPOSAL_SCHEMA_VERSION,
    STATUS_APPROVED,
    STATUS_ARCHIVED,
    STATUS_CANCELED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Proposal,
    approve_proposal,
    archive_proposal,
    cancel_proposal,
    create_proposals_for_session,
    find_proposal_path,
    list_proposals,
    proposal_filename,
    proposals_from_runbook_payload,
    reject_proposal,
    validate_proposal_payload,
)
from shellforgeai.core.ask_routing import (
    is_create_proposals_intent,
    is_immediate_fix_intent,
)

# ---------------------------------------------------------------------------
# Fixtures


def _docker_lab_runbook(session_id: str, session_dir: Path) -> dict:
    """Synthesize a Docker01-lab-shaped runbook.json payload.

    Mirrors what `build_runbook` produces from a fully-populated lab
    evidence bundle (missing-env / bad-volume-perms / restart-loop /
    bad-network / noisy-logs).
    """
    evidence_path = str(session_dir / "evidence.json")
    return {
        "schema_version": "1",
        "session_id": session_id,
        "target": "docker",
        "generated_at": "2026-05-11T00:00:00+00:00",
        "source_evidence": evidence_path,
        "safety_mode": "read-only / operator-run only",
        "overall_risk": "medium",
        "problems": [
            {
                "id": "problem:sfai-missing-env:missing-env",
                "component": "sfai-missing-env",
                "kind": "missing-env",
                "severity": "warning",
                "confidence": "high",
                "likely_cause": "Required env variable missing.",
                "evidence": ["state=exited", "exit_code=42"],
            },
            {
                "id": "problem:sfai-bad-volume-perms:bad-volume-perms",
                "component": "sfai-bad-volume-perms",
                "kind": "bad-volume-perms",
                "severity": "warning",
                "confidence": "high",
                "likely_cause": "Mount permission denied.",
                "evidence": ["log_themes=read_only_fs"],
            },
            {
                "id": "problem:sfai-restart-loop:restart-loop",
                "component": "sfai-restart-loop",
                "kind": "restart-loop",
                "severity": "critical",
                "confidence": "high",
                "likely_cause": "Simulated crash, restart loop.",
                "evidence": ["state=restarting"],
            },
            {
                "id": "problem:sfai-bad-network:bad-network",
                "component": "sfai-bad-network",
                "kind": "bad-network",
                "severity": "warning",
                "confidence": "medium",
                "likely_cause": "Upstream unreachable.",
                "evidence": ["log_themes=dns_failure,upstream_unreachable"],
            },
            {
                "id": "problem:sfai-noisy-logs:noisy-logs",
                "component": "sfai-noisy-logs",
                "kind": "noisy-logs",
                "severity": "info",
                "confidence": "medium",
                "likely_cause": "Verbose WARN/ERROR but app is running.",
                "evidence": ["log_themes=warn_line"],
            },
        ],
        "remediation_options": [
            {
                "id": "option:sfai-missing-env:missing-env",
                "title": "Provide REQUIRED_SETTING for sfai-missing-env",
                "applies_to": [
                    "problem:sfai-missing-env:missing-env",
                    "sfai-missing-env",
                ],
                "risk": "medium",
                "impact": "Recreates sfai-missing-env after config change.",
                "preconditions": ["Confirm required variable name."],
                "steps": [
                    "OPERATOR-RUN: edit compose env file and add REQUIRED_SETTING.",
                    "OPERATOR-RUN: docker compose up -d sfai-missing-env   # SERVICE-IMPACTING",
                ],
                "rollback": [
                    "Revert compose/env file change.",
                    "OPERATOR-RUN: docker compose up -d sfai-missing-env",
                ],
                "verification": ["docker logs --tail 50 sfai-missing-env"],
                "safety_label": "OPERATOR-RUN",
            },
            {
                "id": "option:sfai-bad-volume-perms:bad-volume-perms",
                "title": "Fix volume permissions / writable mount for sfai-bad-volume-perms",
                "applies_to": [
                    "problem:sfai-bad-volume-perms:bad-volume-perms",
                    "sfai-bad-volume-perms",
                ],
                "risk": "medium",
                "impact": "Changes mount flags or host directory ownership.",
                "preconditions": ["Inspect mounts."],
                "steps": [
                    "OPERATOR-RUN: edit compose volume entry to remove ':ro'.",
                    "OPERATOR-RUN: chown host path to UID/GID # REQUIRES APPROVAL",
                    "OPERATOR-RUN: docker compose up -d sfai-bad-volume-perms # SERVICE-IMPACTING",
                ],
                "rollback": ["Restore previous compose volume flags."],
                "verification": ["docker logs --tail 50 sfai-bad-volume-perms"],
                "safety_label": "OPERATOR-RUN",
            },
            {
                "id": "option:sfai-restart-loop:restart-loop",
                "title": "Stabilize restart loop for sfai-restart-loop",
                "applies_to": [
                    "problem:sfai-restart-loop:restart-loop",
                    "sfai-restart-loop",
                ],
                "risk": "medium",
                "impact": "Modifies sfai-restart-loop startup.",
                "preconditions": ["Read logs."],
                "steps": [
                    "OPERATOR-RUN: fix entrypoint / Cmd.",
                    "OPERATOR-RUN: docker compose up -d sfai-restart-loop   # SERVICE-IMPACTING",
                ],
                "rollback": ["Revert startup config."],
                "verification": ["docker inspect -f '{{.RestartCount}}' sfai-restart-loop"],
                "safety_label": "OPERATOR-RUN",
            },
            {
                "id": "option:sfai-bad-network:bad-network",
                "title": "Correct upstream / DNS configuration for sfai-bad-network",
                "applies_to": [
                    "problem:sfai-bad-network:bad-network",
                    "sfai-bad-network",
                ],
                "risk": "medium",
                "impact": "Recreates sfai-bad-network after dependency config change.",
                "preconditions": ["Inspect env."],
                "steps": [
                    "OPERATOR-RUN: correct the upstream hostname / URL.",
                    "OPERATOR-RUN: docker compose up -d sfai-bad-network   # SERVICE-IMPACTING",
                ],
                "rollback": ["Restore previous upstream config."],
                "verification": ["docker logs --tail 50 sfai-bad-network"],
                "safety_label": "OPERATOR-RUN",
            },
            {
                "id": "option:sfai-noisy-logs:noisy-logs",
                "title": "Investigate (do not mutate) noisy logs for sfai-noisy-logs",
                "applies_to": [
                    "problem:sfai-noisy-logs:noisy-logs",
                    "sfai-noisy-logs",
                ],
                "risk": "low",
                "impact": "No mutation recommended yet. Read-only investigation only.",
                "preconditions": ["Read logs."],
                "steps": [
                    "Decide whether the WARN/ERROR lines correlate with user-visible impact.",
                    "If they are expected app chatter, no action is required.",
                ],
                "rollback": [],
                "verification": ["docker logs --tail 50 sfai-noisy-logs"],
                "safety_label": "OPERATOR-RUN",
            },
        ],
        "recommended_order": [],
        "post_fix_validation": ["docker compose ps"],
        "rollback_notes": ["Each option above includes a per-option rollback."],
        "safety_notes": ["ShellForgeAI did not execute these steps. This is an operator-run plan."],
        "executive_summary": "Identified problems across the Docker lab.",
    }


def _write_runbook(tmp_path: Path, session_id: str = "sf_lab_session") -> Path:
    sess = tmp_path / "artifacts" / session_id
    sess.mkdir(parents=True)
    rb = _docker_lab_runbook(session_id, sess)
    rb_path = sess / "runbook.json"
    rb_path.write_text(json.dumps(rb), encoding="utf-8")
    # Synthetic evidence file so source.evidence resolves
    (sess / "evidence.json").write_text("{}", encoding="utf-8")
    return rb_path


@pytest.fixture()
def _data_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path / "sfdata"))
    monkeypatch.setenv("HOME", str(tmp_path))
    data_dir = tmp_path / "sfdata"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


# ---------------------------------------------------------------------------
# Schema / id


def test_proposal_id_format_uses_time_stamp_prefix():
    payload = _docker_lab_runbook("sf_test", Path("/tmp"))
    proposals = proposals_from_runbook_payload(payload, source_runbook="rb.json")
    for p in proposals:
        assert p.proposal_id.startswith("prop_")
        assert " " not in p.proposal_id


def test_proposal_schema_version_field():
    payload = _docker_lab_runbook("sf_test", Path("/tmp"))
    proposals = proposals_from_runbook_payload(payload, source_runbook="rb.json")
    assert proposals
    assert all(p.schema_version == PROPOSAL_SCHEMA_VERSION for p in proposals)


def test_proposal_status_default_pending():
    payload = _docker_lab_runbook("sf_test", Path("/tmp"))
    proposals = proposals_from_runbook_payload(payload, source_runbook="rb.json")
    assert all(p.status == STATUS_PENDING for p in proposals)


def test_proposal_execution_always_disabled():
    payload = _docker_lab_runbook("sf_test", Path("/tmp"))
    proposals = proposals_from_runbook_payload(payload, source_runbook="rb.json")
    for p in proposals:
        assert p.execution.allowed is False
        assert p.execution.status == "not_executed"
        assert p.execution.reason


def test_archived_status_recognized():
    assert STATUS_ARCHIVED in APPROVAL_STATUSES


# ---------------------------------------------------------------------------
# Storage


def test_storage_respects_data_dir_no_slash_data_hardcode(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    data_dir.mkdir()
    proposals = create_proposals_for_session(data_dir, rb)
    assert proposals
    for status_dir in ("pending", "approved", "rejected", "canceled", "archived"):
        d = data_dir / "approvals" / status_dir
        assert d.exists(), f"missing approvals/{status_dir}"
    for p in proposals:
        path, status = find_proposal_path(data_dir, p.proposal_id)
        assert status == STATUS_PENDING
        assert path is not None
        assert str(path).startswith(str(data_dir))
        assert "/data/approvals" not in str(path)


def test_proposal_ids_unique(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    ids = {p.proposal_id for p in proposals}
    assert len(ids) == len(proposals)


# ---------------------------------------------------------------------------
# Creation from runbook


def test_create_proposals_skips_healthy_web_and_noisy_logs_by_default(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    components = {p.component for p in proposals}
    expected = {
        "sfai-missing-env",
        "sfai-bad-volume-perms",
        "sfai-restart-loop",
        "sfai-bad-network",
    }
    assert expected.issubset(components)
    # noisy-logs is read-only / low-risk and skipped by default.
    assert "sfai-noisy-logs" not in components
    # healthy-web has no remediation option in the runbook -> not present.
    assert "sfai-healthy-web" not in components


def test_create_proposals_include_low_keeps_noisy_logs(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb, include_low=True)
    components = {p.component for p in proposals}
    assert "sfai-noisy-logs" in components


def test_create_proposals_assigns_expected_kinds(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    by_component = {p.component: p for p in proposals}
    assert by_component["sfai-missing-env"].kind == "container_env_config_change"
    assert by_component["sfai-bad-volume-perms"].kind == "container_mount_permission_change"
    assert by_component["sfai-restart-loop"].kind == "container_startup_config_change"
    assert by_component["sfai-bad-network"].kind == "container_upstream_config_change"


def test_create_proposals_safety_labels(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    for p in proposals:
        assert "OPERATOR-RUN" in p.safety_labels
        assert "REQUIRES APPROVAL" in p.safety_labels
        # All four lab options are service-impacting (compose up -d).
        assert "SERVICE-IMPACTING" in p.safety_labels


def test_create_proposals_high_risk_for_broad_destructive(tmp_path):
    rb = _docker_lab_runbook("sf_test", tmp_path)
    # Mutate restart-loop to include a broad destructive step.
    for opt in rb["remediation_options"]:
        if "restart-loop" in opt.get("id", ""):
            opt["steps"].append("OPERATOR-RUN: chmod 777 /etc/   # REQUIRES APPROVAL")
            break
    proposals = proposals_from_runbook_payload(rb, source_runbook="rb.json")
    target = next(p for p in proposals if p.component == "sfai-restart-loop")
    assert target.risk == "high"
    assert "HIGH-RISK" in target.safety_labels
    assert "BACKUP-REQUIRED" in target.safety_labels


def test_create_proposals_source_references(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    for p in proposals:
        assert p.source.runbook == str(rb)
        assert p.source.session_id == "sf_lab_session"
        # evidence.json sibling exists in our fixture.
        assert p.source.evidence.endswith("evidence.json")


def test_create_proposals_json_files_validate(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    for p in proposals:
        path, _status = find_proposal_path(data_dir, p.proposal_id)
        payload = json.loads(path.read_text(encoding="utf-8"))
        errors, _warnings = validate_proposal_payload(payload)
        assert errors == [], f"{p.proposal_id}: {errors}"


# ---------------------------------------------------------------------------
# Validation


def test_validate_passes_for_well_formed(tmp_path):
    rb = _write_runbook(tmp_path)
    proposals = create_proposals_for_session(tmp_path / "sfdata", rb)
    for p in proposals:
        errors, _warnings = validate_proposal_payload(json.loads(p.model_dump_json()))
        assert errors == []


def test_validate_fails_when_missing_required_fields():
    errors, _warnings = validate_proposal_payload({"proposal_id": "prop_x"})
    assert any("schema_version" in e for e in errors)


def test_validate_fails_for_invalid_risk():
    p = Proposal(
        proposal_id="prop_x",
        status=STATUS_PENDING,
        risk="catastrophic",
        title="t",
        proposed_steps=["OPERATOR-RUN: restart"],
    )
    errors, _ = validate_proposal_payload(json.loads(p.model_dump_json()))
    assert any("risk" in e for e in errors)


def test_validate_fails_when_execution_allowed_true():
    p = Proposal(
        proposal_id="prop_x",
        status=STATUS_PENDING,
        risk="medium",
        title="t",
        proposed_steps=["OPERATOR-RUN: restart"],
        rollback=["revert"],
        safety_labels=["OPERATOR-RUN", "REQUIRES APPROVAL"],
    )
    payload = json.loads(p.model_dump_json())
    payload["execution"]["allowed"] = True
    errors, _ = validate_proposal_payload(payload)
    assert any("execution.allowed" in e for e in errors)


def test_validate_fails_when_medium_high_missing_rollback():
    p = Proposal(
        proposal_id="prop_x",
        status=STATUS_PENDING,
        risk="medium",
        title="t",
        proposed_steps=["OPERATOR-RUN: restart"],
        rollback=[],
        safety_labels=["OPERATOR-RUN", "REQUIRES APPROVAL"],
    )
    errors, _ = validate_proposal_payload(json.loads(p.model_dump_json()))
    assert any("rollback" in e for e in errors)


def test_validate_fails_for_mutating_without_required_labels():
    p = Proposal(
        proposal_id="prop_x",
        status=STATUS_PENDING,
        risk="medium",
        title="t",
        proposed_steps=["OPERATOR-RUN: docker restart sfai"],
        rollback=["revert"],
        safety_labels=[],
    )
    errors, _ = validate_proposal_payload(json.loads(p.model_dump_json()))
    assert any("OPERATOR-RUN" in e for e in errors)
    assert any("REQUIRES APPROVAL" in e for e in errors)


# ---------------------------------------------------------------------------
# Transitions


def test_approve_does_not_execute(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    target = proposals[0]
    approved = approve_proposal(data_dir, target.proposal_id, reason="approved in change window")
    assert approved.status == STATUS_APPROVED
    assert approved.execution.allowed is False
    assert approved.execution.status == "not_executed"
    assert approved.approval.approved_by
    assert approved.approval.approved_at
    assert approved.approval.reason == "approved in change window"
    # File physically moved between pending and approved.
    pending_path = data_dir / "approvals" / "pending" / proposal_filename(target.proposal_id)
    approved_path = data_dir / "approvals" / "approved" / proposal_filename(target.proposal_id)
    assert not pending_path.exists()
    assert approved_path.exists()


def test_reject_records_reason(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    target = proposals[0]
    rejected = reject_proposal(data_dir, target.proposal_id, reason="not safe yet")
    assert rejected.status == STATUS_REJECTED
    assert rejected.execution.allowed is False
    assert rejected.approval.rejected_by
    assert rejected.approval.reason == "not safe yet"


def test_cancel_records_reason(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    target = proposals[0]
    canceled = cancel_proposal(data_dir, target.proposal_id, reason="superseded by another change")
    assert canceled.status == STATUS_CANCELED
    assert canceled.execution.allowed is False
    assert canceled.approval.canceled_by
    assert canceled.approval.reason == "superseded by another change"


def test_archive_records_reason(tmp_path):
    rb = _write_runbook(tmp_path)
    data_dir = tmp_path / "sfdata"
    proposals = create_proposals_for_session(data_dir, rb)
    target = proposals[0]
    approve_proposal(data_dir, target.proposal_id, reason="ok")
    archived = archive_proposal(data_dir, target.proposal_id, reason="completed offline")
    assert archived.status == STATUS_ARCHIVED
    assert archived.execution.allowed is False
    assert archived.approval.archived_by


# ---------------------------------------------------------------------------
# CLI flows


def test_cli_approvals_create_from_runbook(_data_env, tmp_path):
    rb = _write_runbook(tmp_path)
    runner = CliRunner()
    result = runner.invoke(app, ["approvals", "create", "--from-runbook", str(rb)])
    assert result.exit_code == 0, result.output
    assert "Created approval proposals from runbook" in result.output
    assert "pending queue" in result.output
    assert "execution: disabled" in result.output
    pending_dir = _data_env / "approvals" / "pending"
    assert any(pending_dir.glob("*.proposal.json"))


def test_cli_approvals_create_latest(_data_env, tmp_path, monkeypatch):
    # Latest runbook discovery walks <data_dir>/artifacts/sf_*/runbook.json.
    # Override SHELLFORGEAI_DATA_DIR so the rb fixture lives in the same root.
    rb = _data_env / "artifacts" / "sf_latest_001" / "runbook.json"
    rb.parent.mkdir(parents=True)
    payload = _docker_lab_runbook("sf_latest_001", rb.parent)
    rb.write_text(json.dumps(payload), encoding="utf-8")
    (rb.parent / "evidence.json").write_text("{}", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["approvals", "create", "--latest"])
    assert result.exit_code == 0, result.output
    assert "Created approval proposals" in result.output
    pending_dir = _data_env / "approvals" / "pending"
    assert any(pending_dir.glob("*.proposal.json"))


def test_cli_approvals_create_no_args_clean_error(_data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["approvals", "create"])
    assert result.exit_code != 0
    assert "Provide a session" in result.output or "Missing" in result.output


def test_cli_approvals_list_empty(_data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["approvals", "list"])
    assert result.exit_code == 0, result.output
    assert "No pending approval proposals" in result.output


def test_cli_approvals_list_after_create(_data_env, tmp_path):
    rb = _write_runbook(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["approvals", "create", "--from-runbook", str(rb)])
    listed = runner.invoke(app, ["approvals", "list"])
    assert listed.exit_code == 0, listed.output
    assert "Pending approval proposals" in listed.output
    assert "sfai-missing-env" in listed.output


def test_cli_approvals_show_displays_details(_data_env, tmp_path):
    rb = _write_runbook(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["approvals", "create", "--from-runbook", str(rb)])
    entries = list_proposals(_data_env)
    target = entries[0][1]
    result = runner.invoke(app, ["approvals", "show", target.proposal_id])
    assert result.exit_code == 0, result.output
    assert target.proposal_id in result.output
    assert "proposed_steps" in result.output.lower() or "preconditions" in result.output.lower()
    assert "Not executed by ShellForgeAI" in result.output


def test_cli_approvals_show_missing_clean_error(_data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["approvals", "show", "prop_does_not_exist"])
    assert result.exit_code != 0
    assert "not found" in result.output.lower()
    assert "Traceback" not in result.output


def test_cli_approvals_approve_records_status_only(_data_env, tmp_path):
    rb = _write_runbook(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["approvals", "create", "--from-runbook", str(rb)])
    target = list_proposals(_data_env)[0][1]
    result = runner.invoke(
        app,
        [
            "approvals",
            "approve",
            target.proposal_id,
            "--reason",
            "Reviewed in change window",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "approved but not executed" in result.output
    assert "execution: disabled" in result.output


def test_cli_approvals_reject_then_cancel(_data_env, tmp_path):
    rb = _write_runbook(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["approvals", "create", "--from-runbook", str(rb)])
    entries = list_proposals(_data_env)
    first = entries[0][1].proposal_id
    second = entries[1][1].proposal_id
    rejected = runner.invoke(app, ["approvals", "reject", first, "--reason", "wrong window"])
    assert rejected.exit_code == 0
    assert "rejected" in rejected.output.lower()
    canceled = runner.invoke(app, ["approvals", "cancel", second, "--reason", "superseded"])
    assert canceled.exit_code == 0
    assert "canceled" in canceled.output.lower()


def test_cli_approvals_archive(_data_env, tmp_path):
    rb = _write_runbook(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["approvals", "create", "--from-runbook", str(rb)])
    target = list_proposals(_data_env)[0][1].proposal_id
    approved = runner.invoke(app, ["approvals", "approve", target, "--reason", "ok"])
    assert approved.exit_code == 0
    archived = runner.invoke(app, ["approvals", "archive", target, "--reason", "done offline"])
    assert archived.exit_code == 0
    assert "archived" in archived.output.lower()


def test_cli_approvals_validate_passes(_data_env, tmp_path):
    rb = _write_runbook(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["approvals", "create", "--from-runbook", str(rb)])
    target = list_proposals(_data_env)[0][1].proposal_id
    result = runner.invoke(app, ["approvals", "validate", target])
    assert result.exit_code == 0, result.output
    assert "Proposal validation passed" in result.output
    assert "execution: disabled" in result.output
    assert "schema: ok" in result.output
    assert "safety: ok" in result.output


def test_cli_approvals_validate_accepts_json_path(_data_env, tmp_path):
    rb = _write_runbook(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["approvals", "create", "--from-runbook", str(rb)])
    proposal = list_proposals(_data_env)[0][1]
    path, _ = find_proposal_path(_data_env, proposal.proposal_id)
    assert path is not None
    result = runner.invoke(app, ["approvals", "validate", str(path)])
    assert result.exit_code == 0, result.output
    assert "Proposal validation passed" in result.output


def test_cli_approvals_validate_fails_clean(_data_env, tmp_path):
    bad = tmp_path / "broken.proposal.json"
    bad.write_text("{}", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["approvals", "validate", str(bad)])
    assert result.exit_code != 0
    assert "Proposal validation failed" in result.output
    assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# Ask integration


def test_ask_immediate_fix_intent_detected():
    assert is_immediate_fix_intent("approve and run the fix") is True
    assert is_immediate_fix_intent("fix everything now") is True
    assert is_immediate_fix_intent("just fix it") is True
    assert is_immediate_fix_intent("hello world") is False


def test_ask_create_proposals_intent_detected():
    assert is_create_proposals_intent("queue the safe fixes for approval").matched
    assert is_create_proposals_intent("create approval proposals from latest runbook").matched
    assert is_create_proposals_intent("put those fixes in the approval queue").matched
    assert is_create_proposals_intent("how is the weather").matched is False


def test_ask_immediate_fix_refuses_execution(_data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["ask", "fix everything now"])
    assert result.exit_code == 0, result.output
    assert "Refusing to execute" in result.output
    assert "validation-only" in result.output


def test_ask_immediate_fix_offers_runbook_when_missing(_data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["ask", "approve and run the fix"])
    assert result.exit_code == 0, result.output
    assert "Refusing to execute" in result.output
    assert "No runbook artifact available" in result.output


def test_ask_queue_safe_fixes_creates_proposals(_data_env, tmp_path):
    # Latest runbook lives under data_dir/artifacts/sf_*/runbook.json.
    rb = _data_env / "artifacts" / "sf_qsafe_001" / "runbook.json"
    rb.parent.mkdir(parents=True)
    payload = _docker_lab_runbook("sf_qsafe_001", rb.parent)
    rb.write_text(json.dumps(payload), encoding="utf-8")
    (rb.parent / "evidence.json").write_text("{}", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["ask", "queue the safe fixes for approval"])
    assert result.exit_code == 0, result.output
    assert "Staged approval proposals" in result.output
    assert "execution: disabled" in result.output
    pending_dir = _data_env / "approvals" / "pending"
    assert any(pending_dir.glob("*.proposal.json"))


def test_ask_queue_safe_fixes_without_runbook_gives_next_step(_data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["ask", "queue the safe fixes for approval"])
    assert result.exit_code == 0, result.output
    assert "No runbook artifact available" in result.output
    assert "diagnose" in result.output.lower()


# ---------------------------------------------------------------------------
# Apply integration


def test_apply_validation_only_on_approved_proposal(_data_env, tmp_path):
    rb = _write_runbook(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["approvals", "create", "--from-runbook", str(rb)])
    target = list_proposals(_data_env)[0][1].proposal_id
    runner.invoke(app, ["approvals", "approve", target, "--reason", "ok"])
    result = runner.invoke(app, ["apply", target])
    assert result.exit_code == 0, result.output
    # PR33 reuse: bundle is generated, but no commands executed.
    assert "execution: not_executed" in result.output
    assert "No commands were executed" in result.output
