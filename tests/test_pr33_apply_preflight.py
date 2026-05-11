"""PR33: apply preflight + operator execution bundle export.

Tests are deterministic and self-contained. They do not require Docker,
systemd, journalctl, network access, or root. Every test uses ``tmp_path``
as the data dir so nothing escapes the test sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import approvals as approvals_mod
from shellforgeai.core.apply_bundle import (
    PREFIGHT_FILES,
    BundleResult,
    generate_bundle,
    run_preflight,
)
from shellforgeai.core.approvals import (
    STATUS_APPROVED,
    STATUS_CANCELED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Proposal,
    ProposalApproval,
    ProposalExecution,
    ProposalSource,
    approve_proposal,
    compute_proposal_fingerprint_payload,
    find_proposal_path,
    proposal_filename,
    write_proposal,
)


def _mk_proposal(
    proposal_id: str = "prop_test_001",
    *,
    status: str = STATUS_APPROVED,
    risk: str = "medium",
    safety_labels: list[str] | None = None,
    steps: list[str] | None = None,
    rollback: list[str] | None = None,
    verification: list[str] | None = None,
    execution_allowed: bool = False,
    execution_status: str = "not_executed",
) -> Proposal:
    component = "sfai-missing-env"
    kind = "container_env_config_change"
    title = "Provide REQUIRED_SETTING for sfai-missing-env"
    resolved_steps = (
        steps
        if steps is not None
        else [
            "OPERATOR-RUN: edit compose env file and add REQUIRED_SETTING.",
            "OPERATOR-RUN: docker compose up -d sfai-missing-env   # SERVICE-IMPACTING",
        ]
    )
    resolved_rollback = (
        rollback
        if rollback is not None
        else [
            "Revert compose/env file change.",
            "OPERATOR-RUN: docker compose up -d sfai-missing-env",
        ]
    )
    resolved_verification = (
        verification if verification is not None else ["docker logs --tail 50 sfai-missing-env"]
    )
    fingerprint = compute_proposal_fingerprint_payload(
        session_id="sf_test_001",
        option_id="opt_test_001",
        component=component,
        kind=kind,
        title=title,
        risk=risk,
        steps=resolved_steps,
        rollback=resolved_rollback,
        verification=resolved_verification,
    )
    return Proposal(
        proposal_id=proposal_id,
        created_at="2026-05-11T00:00:00+00:00",
        status=status,
        source=ProposalSource(session_id="sf_test"),
        target="docker",
        component=component,
        kind=kind,
        title=title,
        risk=risk,
        confidence="medium",
        impact="Recreates sfai-missing-env after config change.",
        safety_labels=safety_labels
        if safety_labels is not None
        else ["OPERATOR-RUN", "REQUIRES APPROVAL", "SERVICE-IMPACTING"],
        preconditions=["Confirm required variable name."],
        proposed_steps=resolved_steps,
        rollback=resolved_rollback,
        verification=resolved_verification,
        notes="",
        execution=ProposalExecution(allowed=execution_allowed, status=execution_status),
        fingerprint=fingerprint,
        approval=ProposalApproval(
            reason="approved for test",
            approved_at="2026-05-11T00:00:01+00:00",
            approved_by="op",
        )
        if status == STATUS_APPROVED
        else ProposalApproval(),
    )


def _write_proposal(data_dir: Path, proposal: Proposal) -> Path:
    return write_proposal(data_dir, proposal)


# ---------------------------------------------------------------------------
# Preflight unit tests


def test_preflight_passes_for_approved_proposal():
    proposal = _mk_proposal(status=STATUS_APPROVED)
    result = run_preflight(proposal)
    assert result.passed
    assert result.status == "passed"
    assert any(c.name == "proposal_schema" and c.status == "passed" for c in result.checks)
    assert any(c.name == "status_approved" and c.status == "passed" for c in result.checks)


def test_preflight_fails_for_pending_proposal():
    proposal = _mk_proposal(status=STATUS_PENDING)
    result = run_preflight(proposal)
    assert not result.passed
    assert any("pending" in e for e in result.errors)


def test_preflight_fails_for_rejected_proposal():
    proposal = _mk_proposal(status=STATUS_REJECTED)
    result = run_preflight(proposal)
    assert not result.passed
    assert any("rejected" in e for e in result.errors)


def test_preflight_fails_for_canceled_proposal():
    proposal = _mk_proposal(status=STATUS_CANCELED)
    result = run_preflight(proposal)
    assert not result.passed
    assert any("canceled" in e for e in result.errors)


def test_preflight_fails_when_execution_allowed_true():
    proposal = _mk_proposal(execution_allowed=True)
    result = run_preflight(proposal)
    assert not result.passed
    assert any("execution.allowed" in e for e in result.errors)


def test_preflight_fails_when_execution_status_executed():
    proposal = _mk_proposal(execution_status="executed")
    result = run_preflight(proposal)
    assert not result.passed
    assert any("execution.status" in e for e in result.errors)


def test_preflight_fails_when_medium_risk_has_no_rollback():
    proposal = _mk_proposal(risk="medium", rollback=[])
    result = run_preflight(proposal)
    assert not result.passed
    assert any("rollback" in e for e in result.errors)


def test_preflight_fails_when_high_risk_has_no_rollback():
    proposal = _mk_proposal(risk="high", rollback=[])
    result = run_preflight(proposal)
    assert not result.passed
    assert any("rollback" in e for e in result.errors)


def test_preflight_fails_when_mutating_missing_operator_run_label():
    proposal = _mk_proposal(safety_labels=["REQUIRES APPROVAL"])
    result = run_preflight(proposal)
    assert not result.passed
    assert any("OPERATOR-RUN" in e for e in result.errors)


def test_preflight_fails_when_mutating_missing_requires_approval_label():
    proposal = _mk_proposal(safety_labels=["OPERATOR-RUN"])
    result = run_preflight(proposal)
    assert not result.passed
    assert any("REQUIRES APPROVAL" in e for e in result.errors)


def test_preflight_fails_for_none_proposal():
    result = run_preflight(None)
    assert not result.passed
    assert any("missing" in e for e in result.errors)


def test_preflight_warns_on_broad_destructive_words():
    proposal = _mk_proposal(
        steps=[
            "OPERATOR-RUN: chmod 777 /etc/   # REQUIRES APPROVAL",
            "OPERATOR-RUN: docker compose up -d   # SERVICE-IMPACTING",
        ],
        risk="high",
        rollback=["restore backup"],
    )
    result = run_preflight(proposal)
    # Risk-high triggers a warning even when preflight passes everything else.
    assert any("destructive" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# Bundle generation tests


def test_generate_bundle_writes_all_five_files(tmp_path):
    proposal = _mk_proposal()
    res = generate_bundle(proposal, data_dir=tmp_path)
    assert isinstance(res, BundleResult)
    expected = {p.name for p in res.files}
    assert expected == set(PREFIGHT_FILES)
    for f in res.files:
        assert f.exists() and f.stat().st_size > 0


def test_bundle_dir_respects_configured_data_dir_not_slash_data(tmp_path):
    proposal = _mk_proposal(proposal_id="prop_local_path_test")
    res = generate_bundle(proposal, data_dir=tmp_path)
    assert str(res.bundle_dir).startswith(str(tmp_path))
    for f in res.files:
        assert str(f).startswith(str(tmp_path))
        # No leakage to a hardcoded /data prefix.
        assert "/data/apply_bundles" not in str(f)


def test_operator_commands_script_has_early_exit_before_commands(tmp_path):
    proposal = _mk_proposal()
    res = generate_bundle(proposal, data_dir=tmp_path)
    cmds = (res.bundle_dir / "operator-commands.sh").read_text(encoding="utf-8")
    assert "#!/usr/bin/env bash" in cmds
    assert "set -euo pipefail" in cmds
    # The exit line must precede any OPERATOR-RUN command.
    exit_idx = cmds.find("exit 2")
    assert exit_idx != -1
    operator_idx = cmds.find("OPERATOR-RUN")
    assert operator_idx > exit_idx, "exit 2 must come before any operator-run command"
    assert "ShellForgeAI did not execute" in cmds


def test_rollback_script_has_early_exit_before_commands(tmp_path):
    proposal = _mk_proposal()
    res = generate_bundle(proposal, data_dir=tmp_path)
    rb = (res.bundle_dir / "rollback.sh").read_text(encoding="utf-8")
    assert "exit 2" in rb
    exit_idx = rb.find("exit 2")
    rollback_idx = rb.find("ROLLBACK:")
    assert rollback_idx == -1 or rollback_idx > exit_idx
    assert "ShellForgeAI did not execute" in rb


def test_apply_preflight_json_marks_execution_not_executed(tmp_path):
    proposal = _mk_proposal()
    res = generate_bundle(proposal, data_dir=tmp_path)
    payload = json.loads((res.bundle_dir / "apply-preflight.json").read_text(encoding="utf-8"))
    assert payload["execution_allowed"] is False
    assert payload["execution_status"] == "not_executed"
    assert payload["proposal_id"] == proposal.proposal_id
    assert payload["proposal_status"] == STATUS_APPROVED
    assert payload["preflight_status"] == "passed"
    assert payload["schema_version"] == "1"
    assert isinstance(payload["checks"], list)
    assert any(c["name"] == "proposal_schema" for c in payload["checks"])


def test_apply_preview_md_lists_safety_metadata(tmp_path):
    proposal = _mk_proposal()
    res = generate_bundle(proposal, data_dir=tmp_path)
    md = (res.bundle_dir / "apply-preview.md").read_text(encoding="utf-8")
    assert proposal.proposal_id in md
    assert "approved" in md.lower()
    assert "execution: not_executed" in md.lower()
    assert "ShellForgeAI generated this bundle but did not execute it." in md


def test_validation_md_lists_verification_or_safety(tmp_path):
    proposal = _mk_proposal()
    res = generate_bundle(proposal, data_dir=tmp_path)
    md = (res.bundle_dir / "validation.md").read_text(encoding="utf-8")
    assert "docker logs --tail 50 sfai-missing-env" in md
    assert "ShellForgeAI generated this bundle but did not execute it." in md


# ---------------------------------------------------------------------------
# CLI integration


@pytest.fixture()
def _data_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path / "sfdata"))
    monkeypatch.setenv("HOME", str(tmp_path))
    data_dir = tmp_path / "sfdata"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def test_apply_cli_approved_proposal_id_generates_bundle(_data_env):
    proposal = _mk_proposal()
    write_proposal(_data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["apply", proposal.proposal_id])
    assert result.exit_code == 0, result.output
    assert "Apply preflight passed" in result.output
    assert "execution: not_executed" in result.output
    assert "No commands were executed" in result.output
    bundle_dir = _data_env / "apply_bundles" / proposal.proposal_id
    for name in PREFIGHT_FILES:
        assert (bundle_dir / name).exists(), f"missing {name}"


def test_apply_cli_pending_proposal_fails_no_bundle(_data_env):
    proposal = _mk_proposal(proposal_id="prop_pending_001", status=STATUS_PENDING)
    write_proposal(_data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["apply", proposal.proposal_id])
    assert result.exit_code != 0
    assert "Apply preflight failed" in result.output
    assert "pending" in result.output.lower()
    # No operator-run scripts written for pending; only diagnostic preflight.
    bundle_dir = _data_env / "apply_bundles" / proposal.proposal_id
    assert not (bundle_dir / "operator-commands.sh").exists()
    assert not (bundle_dir / "rollback.sh").exists()


def test_apply_cli_rejected_proposal_refuses(_data_env):
    proposal = _mk_proposal(proposal_id="prop_rejected_001", status=STATUS_REJECTED)
    write_proposal(_data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["apply", proposal.proposal_id])
    assert result.exit_code != 0
    assert "Apply preflight failed" in result.output
    bundle_dir = _data_env / "apply_bundles" / proposal.proposal_id
    assert not (bundle_dir / "operator-commands.sh").exists()


def test_apply_cli_canceled_proposal_refuses(_data_env):
    proposal = _mk_proposal(proposal_id="prop_canceled_001", status=STATUS_CANCELED)
    write_proposal(_data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["apply", proposal.proposal_id])
    assert result.exit_code != 0
    assert "Apply preflight failed" in result.output


def test_apply_cli_missing_proposal_clean_error(_data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["apply", "prop_does_not_exist"])
    assert result.exit_code != 0
    assert "not found" in result.output.lower()
    assert "no commands executed" in result.output.lower()


def test_apply_cli_malformed_proposal_json_clean_error(_data_env, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["apply", str(bad)])
    assert result.exit_code != 0
    assert "not found" in result.output.lower() or "preflight failed" in result.output.lower()


def test_apply_cli_proposal_path_directly(_data_env, tmp_path):
    proposal = _mk_proposal(proposal_id="prop_direct_path_001")
    proposal_path = tmp_path / proposal_filename(proposal.proposal_id)
    proposal_path.write_text(proposal.model_dump_json(indent=2), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["apply", str(proposal_path)])
    assert result.exit_code == 0, result.output
    assert "Apply preflight passed" in result.output
    bundle_dir = _data_env / "apply_bundles" / proposal.proposal_id
    assert (bundle_dir / "apply-preflight.json").exists()


def test_apply_cli_latest_approved_flag(_data_env):
    p1 = _mk_proposal(proposal_id="prop_first_001")
    p2 = _mk_proposal(proposal_id="prop_second_002")
    write_proposal(_data_env, p1)
    # mtime ordering: ensure second is newer.
    import time

    time.sleep(0.05)
    write_proposal(_data_env, p2)
    runner = CliRunner()
    result = runner.invoke(app, ["apply", "--latest-approved"])
    assert result.exit_code == 0, result.output
    assert p2.proposal_id in result.output


def test_apply_cli_latest_approved_when_none(_data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["apply", "--latest-approved"])
    assert result.exit_code != 0
    assert "no approved proposals" in result.output.lower()


def test_apply_cli_dry_run_does_not_write_bundle(_data_env):
    proposal = _mk_proposal(proposal_id="prop_dryrun_001")
    write_proposal(_data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["apply", "--dry-run", proposal.proposal_id])
    assert result.exit_code == 0, result.output
    assert "dry-run" in result.output.lower()
    assert "no commands executed" in result.output.lower()
    bundle_dir = _data_env / "apply_bundles" / proposal.proposal_id
    assert not bundle_dir.exists()


def test_apply_cli_preserves_plan_json_validation(_data_env, tmp_path):
    from shellforgeai.core.plans import Plan, PlanStep

    p = Plan(
        plan_id="p",
        goal="g",
        session_id="s",
        steps=[PlanStep(step_id="1", title="t", description="d")],
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(p.model_dump_json(), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["apply", str(plan_path)])
    assert result.exit_code == 0, result.output
    assert "Apply execution is intentionally disabled" in result.output


# ---------------------------------------------------------------------------
# Approvals CLI smoke (PR32 scaffolding) -- exercised here so that
# regression coverage stays tight for PR33's apply path.


def test_approvals_create_from_runbook_session(_data_env, tmp_path):
    session_id = "sf_test_session_001"
    sess_dir = _data_env / "artifacts" / session_id
    sess_dir.mkdir(parents=True, exist_ok=True)
    runbook = {
        "schema_version": "1",
        "session_id": session_id,
        "target": "docker",
        "generated_at": "2026-05-11T00:00:00+00:00",
        "source_evidence": str(sess_dir / "evidence.json"),
        "safety_mode": "read-only / operator-run only",
        "overall_risk": "medium",
        "problems": [],
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
                "preconditions": ["Confirm required variable."],
                "steps": [
                    "OPERATOR-RUN: edit compose env file and add REQUIRED_SETTING.",
                    "OPERATOR-RUN: docker compose up -d sfai-missing-env   # SERVICE-IMPACTING",
                ],
                "rollback": ["Revert compose change."],
                "verification": ["docker logs --tail 50 sfai-missing-env"],
                "safety_label": "OPERATOR-RUN",
            }
        ],
        "recommended_order": [],
        "post_fix_validation": ["docker compose ps"],
        "safety_notes": ["ShellForgeAI did not execute these steps. This is an operator-run plan."],
    }
    (sess_dir / "runbook.json").write_text(json.dumps(runbook), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(app, ["approvals", "create", session_id])
    assert result.exit_code == 0, result.output
    assert "created: 1" in result.output
    assert "execution: disabled" in result.output

    listed = runner.invoke(app, ["approvals", "list"])
    assert listed.exit_code == 0, listed.output
    assert "Pending approval proposals" in listed.output
    assert "sfai-missing-env" in listed.output


def test_approvals_approve_then_apply_creates_bundle(_data_env):
    proposal = _mk_proposal(proposal_id="prop_flow_001", status=STATUS_PENDING)
    write_proposal(_data_env, proposal)
    runner = CliRunner()
    # Pending apply must fail.
    pending = runner.invoke(app, ["apply", proposal.proposal_id])
    assert pending.exit_code != 0

    approved = runner.invoke(
        app,
        [
            "approvals",
            "approve",
            proposal.proposal_id,
            "--reason",
            "approved for PR33 flow test",
        ],
    )
    assert approved.exit_code == 0, approved.output
    assert "status: approved" in approved.output

    after = runner.invoke(app, ["apply", proposal.proposal_id])
    assert after.exit_code == 0, after.output
    bundle_dir = _data_env / "apply_bundles" / proposal.proposal_id
    for name in PREFIGHT_FILES:
        assert (bundle_dir / name).exists()
    payload = json.loads((bundle_dir / "apply-preflight.json").read_text(encoding="utf-8"))
    assert payload["execution_allowed"] is False
    assert payload["execution_status"] == "not_executed"


def test_approvals_validate_passes_for_well_formed_proposal(_data_env):
    proposal = _mk_proposal(proposal_id="prop_validate_001")
    write_proposal(_data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["approvals", "validate", proposal.proposal_id])
    assert result.exit_code == 0, result.output
    assert "Proposal validation passed" in result.output


def test_approvals_approve_moves_file_between_directories(_data_env):
    proposal = _mk_proposal(proposal_id="prop_move_001", status=STATUS_PENDING)
    write_proposal(_data_env, proposal)
    pending_path = _data_env / "approvals" / "pending" / proposal_filename(proposal.proposal_id)
    assert pending_path.exists()
    approve_proposal(_data_env, proposal.proposal_id, reason="ok")
    approved_path, status = find_proposal_path(_data_env, proposal.proposal_id)
    assert status == STATUS_APPROVED
    assert approved_path is not None
    assert "approved" in str(approved_path)
    assert not pending_path.exists()


# ---------------------------------------------------------------------------
# Ask integration


def test_ask_apply_approved_intent_refuses_execute(_data_env, monkeypatch):
    proposal = _mk_proposal(proposal_id="prop_ask_refuse_001")
    write_proposal(_data_env, proposal)

    runner = CliRunner()
    result = runner.invoke(app, ["ask", "can you run the approved fix?"])
    assert result.exit_code == 0, result.output
    assert "Refusing to execute" in result.output
    # Must NOT generate a bundle on an execute-style request.
    bundle_dir = _data_env / "apply_bundles" / proposal.proposal_id
    assert not bundle_dir.exists()


def test_ask_apply_approved_intent_prepare_generates_bundle(_data_env, monkeypatch):
    proposal = _mk_proposal(proposal_id="prop_ask_prepare_001")
    write_proposal(_data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["ask", "prepare the approved fix bundle"])
    assert result.exit_code == 0, result.output
    assert "Prepared operator preflight bundle" in result.output
    bundle_dir = _data_env / "apply_bundles" / proposal.proposal_id
    for name in PREFIGHT_FILES:
        assert (bundle_dir / name).exists()


def test_ask_apply_approved_intent_with_no_approved_proposal(_data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["ask", "apply the approved proposal"])
    # Execute-style: refuses cleanly; no proposal known so explains workflow.
    assert result.exit_code == 0, result.output
    assert "Refusing to execute" in result.output
    assert "no approved proposal" in result.output.lower()


# ---------------------------------------------------------------------------
# Module-level invariants


def test_module_constants_unchanged():
    assert approvals_mod.STATUS_PENDING == "pending"
    assert approvals_mod.STATUS_APPROVED == "approved"
    assert approvals_mod.STATUS_REJECTED == "rejected"
    assert approvals_mod.STATUS_CANCELED == "canceled"
