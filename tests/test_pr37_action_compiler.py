"""PR37: policy-gated action compiler tests.

Deterministic, fixture-based. No Docker, no systemd, no network, no root.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.actions import (
    ACTIONS_SCHEMA_VERSION,
    DECISION_BLOCKED,
    DECISION_MANUAL_ONLY,
    DECISION_READ_ONLY,
    actions_dir_for,
    classify_step,
    compile_actions,
    compile_and_write,
    find_actions_for_proposal,
    is_actions_ask_intent,
    load_actions_file,
    validate_actions_payload,
)
from shellforgeai.core.approvals import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Proposal,
    ProposalApproval,
    ProposalExecution,
    ProposalSource,
    compute_proposal_fingerprint_payload,
    write_proposal,
)


def _mk_proposal(
    proposal_id: str = "prop_pr37_001",
    *,
    status: str = STATUS_APPROVED,
    steps: list[str] | None = None,
    rollback: list[str] | None = None,
    verification: list[str] | None = None,
    preconditions: list[str] | None = None,
) -> Proposal:
    component = "sfai-bad-network"
    kind = "container_recreate"
    title = "Recreate sfai-bad-network with corrected upstream"
    resolved_steps = (
        steps
        if steps is not None
        else [
            "OPERATOR-RUN: edit compose env file and correct upstream hostname.",
            "OPERATOR-RUN: docker compose up -d sfai-bad-network # SERVICE-IMPACTING",
        ]
    )
    resolved_rollback = rollback if rollback is not None else ["Revert compose change."]
    resolved_verification = (
        verification if verification is not None else ["docker logs --tail 50 sfai-bad-network"]
    )
    resolved_pre = preconditions if preconditions is not None else ["Confirm intended hostname."]
    fp = compute_proposal_fingerprint_payload(
        session_id="sf_pr37_test",
        option_id="opt_pr37_001",
        component=component,
        kind=kind,
        title=title,
        risk="medium",
        steps=resolved_steps,
        rollback=resolved_rollback,
        verification=resolved_verification,
    )
    return Proposal(
        proposal_id=proposal_id,
        created_at="2026-05-12T00:00:00+00:00",
        status=status,
        source=ProposalSource(session_id="sf_pr37_test"),
        target="docker",
        component=component,
        kind=kind,
        title=title,
        risk="medium",
        confidence="medium",
        impact="Reload corrected upstream config.",
        safety_labels=["OPERATOR-RUN", "REQUIRES APPROVAL", "SERVICE-IMPACTING"],
        preconditions=resolved_pre,
        proposed_steps=resolved_steps,
        rollback=resolved_rollback,
        verification=resolved_verification,
        execution=ProposalExecution(),
        fingerprint=fp,
        approval=ProposalApproval(
            reason="approved for PR37 test",
            approved_at="2026-05-12T00:00:01+00:00",
            approved_by="op",
        )
        if status == STATUS_APPROVED
        else ProposalApproval(),
    )


# ---------------------------------------------------------------------------
# Policy classification


@pytest.mark.parametrize(
    "text,decision",
    [
        ("docker inspect sfai-bad-network", DECISION_READ_ONLY),
        ("docker logs --tail 50 sfai-bad-network", DECISION_READ_ONLY),
        ("docker ps", DECISION_READ_ONLY),
        ("systemctl status nginx", DECISION_READ_ONLY),
        ("journalctl -u nginx -n 50", DECISION_READ_ONLY),
        ("cat /etc/hosts", DECISION_READ_ONLY),
    ],
)
def test_classify_read_only(text, decision):
    cls = classify_step(text)
    assert cls.decision == decision


@pytest.mark.parametrize(
    "text",
    [
        "docker compose up -d sfai-bad-network",
        "docker compose down",
        "docker restart sfai-bad-network",
        "systemctl restart nginx",
        "systemctl reload nginx",
        "service nginx restart",
    ],
)
def test_classify_service_impacting_blocked(text):
    cls = classify_step(text)
    assert cls.decision == DECISION_BLOCKED
    assert "SERVICE-IMPACTING" in cls.safety_labels


@pytest.mark.parametrize(
    "text",
    [
        "chmod 644 /etc/nginx/nginx.conf",
        "chown root:root /etc/nginx/nginx.conf",
        "rm -rf /var/log/nginx/old",
        "mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak",
    ],
)
def test_classify_filesystem_blocked(text):
    cls = classify_step(text)
    assert cls.decision == DECISION_BLOCKED
    assert "FILESYSTEM-MUTATION" in cls.safety_labels


@pytest.mark.parametrize(
    "text",
    [
        "apt install nginx",
        "apt-get remove nginx",
        "yum install nginx",
        "dnf install nginx",
        "apk add nginx",
        "pip install requests",
    ],
)
def test_classify_package_blocked(text):
    cls = classify_step(text)
    assert cls.decision == DECISION_BLOCKED
    assert "PACKAGE-MUTATION" in cls.safety_labels


@pytest.mark.parametrize(
    "text",
    [
        "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
        "ufw allow 22",
        "nft add rule inet filter input tcp dport 22 accept",
        "firewall-cmd --add-port=22/tcp",
    ],
)
def test_classify_firewall_blocked(text):
    cls = classify_step(text)
    assert cls.decision == DECISION_BLOCKED
    assert "FIREWALL-MUTATION" in cls.safety_labels


@pytest.mark.parametrize(
    "text",
    [
        "ip route add default via 10.0.0.1",
        "ip route delete default",
        "resolvectl dns eth0 1.1.1.1",
    ],
)
def test_classify_network_blocked(text):
    cls = classify_step(text)
    assert cls.decision == DECISION_BLOCKED
    assert "NETWORK-MUTATION" in cls.safety_labels


def test_classify_manual_edit():
    cls = classify_step("edit compose env file and correct upstream hostname.")
    assert cls.decision == DECISION_MANUAL_ONLY


def test_classify_unknown_defaults_to_manual_only():
    cls = classify_step("zzzfoobar quux not a command at all")
    assert cls.decision == DECISION_MANUAL_ONLY


# ---------------------------------------------------------------------------
# Compile


def test_compile_actions_preserves_raw_text_and_normalizes(tmp_path):
    proposal = _mk_proposal()
    compiled = compile_actions(proposal)
    raws = [a.raw_text for a in compiled.actions]
    normalizeds = [a.normalized_text for a in compiled.actions]
    assert "OPERATOR-RUN: docker compose up -d sfai-bad-network # SERVICE-IMPACTING" in raws
    assert "docker compose up -d sfai-bad-network" in normalizeds


def test_compile_actions_dedups_duplicate_leading_labels():
    proposal = _mk_proposal(
        steps=[
            "OPERATOR-RUN: OPERATOR-RUN: docker compose up -d sfai-bad-network # SERVICE-IMPACTING"
        ]
    )
    compiled = compile_actions(proposal)
    step_actions = [a for a in compiled.actions if a.source_section == "proposed_step"]
    assert step_actions
    a = step_actions[0]
    assert a.normalized_text == "docker compose up -d sfai-bad-network"
    assert a.decision == DECISION_BLOCKED
    assert "SERVICE-IMPACTING" in a.safety_labels
    assert a.execution_allowed is False


def test_compile_and_write_outputs_under_data_dir(tmp_path):
    proposal = _mk_proposal()
    result = compile_and_write(proposal, data_dir=tmp_path)
    assert result.actions_dir == actions_dir_for(tmp_path, proposal.proposal_id)
    assert result.actions_json.exists()
    assert result.actions_md.exists()
    payload = json.loads(result.actions_json.read_text(encoding="utf-8"))
    assert payload["schema_version"] == ACTIONS_SCHEMA_VERSION
    assert payload["execution_allowed"] is False
    assert payload["execution_status"] == "not_executed"
    assert payload["proposal_id"] == proposal.proposal_id
    assert payload["policy"]["mode"] == "review_only"
    # Every action carries execution_allowed=false
    assert all(a["execution_allowed"] is False for a in payload["actions"])


def test_compile_summary_counts_match_actions(tmp_path):
    proposal = _mk_proposal()
    result = compile_and_write(proposal, data_dir=tmp_path)
    payload = json.loads(result.actions_json.read_text(encoding="utf-8"))
    summary = payload["summary"]
    actions = payload["actions"]
    assert summary["total_actions"] == len(actions)
    assert summary["blocked"] == sum(1 for a in actions if a["decision"] == DECISION_BLOCKED)
    assert summary["manual_only"] == sum(
        1 for a in actions if a["decision"] == DECISION_MANUAL_ONLY
    )
    assert summary["read_only"] == sum(1 for a in actions if a["decision"] == DECISION_READ_ONLY)
    assert summary["allowed_for_future_execution"] == 0


# ---------------------------------------------------------------------------
# Validation


def test_validate_accepts_compiled(tmp_path):
    proposal = _mk_proposal()
    result = compile_and_write(proposal, data_dir=tmp_path)
    payload = json.loads(result.actions_json.read_text(encoding="utf-8"))
    res = validate_actions_payload(payload)
    assert res.ok, res.errors


def test_validate_rejects_execution_allowed_true(tmp_path):
    proposal = _mk_proposal()
    result = compile_and_write(proposal, data_dir=tmp_path)
    payload = json.loads(result.actions_json.read_text(encoding="utf-8"))
    payload["actions"][0]["execution_allowed"] = True
    res = validate_actions_payload(payload)
    assert not res.ok
    assert any("execution_allowed must be false" in e for e in res.errors)


def test_validate_rejects_missing_field(tmp_path):
    proposal = _mk_proposal()
    result = compile_and_write(proposal, data_dir=tmp_path)
    payload = json.loads(result.actions_json.read_text(encoding="utf-8"))
    payload["actions"][0].pop("reason")
    res = validate_actions_payload(payload)
    assert not res.ok
    assert any("missing required field" in e for e in res.errors)


def test_validate_rejects_summary_mismatch(tmp_path):
    proposal = _mk_proposal()
    result = compile_and_write(proposal, data_dir=tmp_path)
    payload = json.loads(result.actions_json.read_text(encoding="utf-8"))
    payload["summary"]["blocked"] = payload["summary"]["blocked"] + 5
    res = validate_actions_payload(payload)
    assert not res.ok
    assert any("summary.blocked mismatch" in e for e in res.errors)


def test_validate_rejects_blocked_marked_read_only(tmp_path):
    proposal = _mk_proposal()
    result = compile_and_write(proposal, data_dir=tmp_path)
    payload = json.loads(result.actions_json.read_text(encoding="utf-8"))
    # Find the docker compose up -d action and downgrade decision
    for a in payload["actions"]:
        if "SERVICE-IMPACTING" in a.get("safety_labels", []):
            a["decision"] = "read_only_review"
            break
    res = validate_actions_payload(payload)
    assert not res.ok
    assert any("marked read_only_review" in e for e in res.errors)


def test_validate_rejects_malformed_payload():
    res = validate_actions_payload("not a json object")
    assert not res.ok


def test_load_actions_file_missing(tmp_path):
    payload, err = load_actions_file(tmp_path / "nope.json")
    assert payload is None
    assert err is not None


# ---------------------------------------------------------------------------
# CLI smoke tests


runner = CliRunner()


@pytest.fixture()
def data_env(tmp_path, monkeypatch):
    data = tmp_path / "sfdata"
    data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(data))
    monkeypatch.setenv("HOME", str(tmp_path))
    return data


def _run(*args: str):
    return runner.invoke(app, list(args))


def test_cli_actions_compile_latest_approved(data_env):
    tmp_path = data_env
    proposal = _mk_proposal()
    write_proposal(tmp_path, proposal)
    res = _run("actions", "compile", "--latest-approved")
    assert res.exit_code == 0, res.output
    out = tmp_path / "actions" / proposal.proposal_id / "actions.json"
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["execution_allowed"] is False
    assert payload["execution_status"] == "not_executed"


def test_cli_actions_compile_refuses_missing(data_env):
    res = _run("actions", "compile", "prop_nope")
    assert res.exit_code == 1
    assert "no commands executed" in res.output


def test_cli_actions_compile_refuses_rejected_by_default(data_env):
    proposal = _mk_proposal(status=STATUS_REJECTED)
    write_proposal(data_env, proposal)
    res = _run("actions", "compile", proposal.proposal_id)
    assert res.exit_code == 1


def test_cli_actions_compile_pending_with_flag(data_env):
    proposal = _mk_proposal(status=STATUS_PENDING)
    write_proposal(data_env, proposal)
    res = _run("actions", "compile", proposal.proposal_id, "--allow-pending")
    assert res.exit_code == 0, res.output


def test_cli_actions_validate(data_env):
    proposal = _mk_proposal()
    write_proposal(data_env, proposal)
    _run("actions", "compile", "--latest-approved")
    actions_json = data_env / "actions" / proposal.proposal_id / "actions.json"
    res = _run("actions", "validate", str(actions_json))
    assert res.exit_code == 0, res.output
    assert "Action validation passed" in res.output


def test_cli_actions_validate_missing(data_env):
    res = _run("actions", "validate", str(data_env / "nope.json"))
    assert res.exit_code == 1
    assert "Action validation failed" in res.output


def test_cli_actions_show_by_id(data_env):
    proposal = _mk_proposal()
    write_proposal(data_env, proposal)
    _run("actions", "compile", "--latest-approved")
    res = _run("actions", "show", proposal.proposal_id)
    assert res.exit_code == 0, res.output
    assert proposal.proposal_id in res.output


# ---------------------------------------------------------------------------
# Apply integration: bundle now includes actions, original behavior preserved


def test_apply_integration_adds_actions_files(data_env):
    proposal = _mk_proposal()
    write_proposal(data_env, proposal)
    res = _run("apply", proposal.proposal_id)
    assert res.exit_code == 0, res.output
    # Bundle dir still has the original 5 files
    bdir = data_env / "apply_bundles" / proposal.proposal_id
    for name in (
        "apply-preview.md",
        "operator-commands.sh",
        "rollback.sh",
        "validation.md",
        "apply-preflight.json",
    ):
        assert (bdir / name).exists()
    # Actions written separately
    adir = data_env / "actions" / proposal.proposal_id
    assert (adir / "actions.json").exists()
    assert (adir / "actions.md").exists()
    # Preflight payload mentions actions_compiled
    preflight = json.loads((bdir / "apply-preflight.json").read_text(encoding="utf-8"))
    assert preflight.get("actions_compiled") is True
    assert preflight.get("execution_allowed") is False


# ---------------------------------------------------------------------------
# Ask intent


def test_is_actions_ask_intent_compile():
    res = is_actions_ask_intent("can you compile actions for approved proposal?")
    assert res.matched and res.compile


def test_is_actions_ask_intent_show():
    res = is_actions_ask_intent("show me what would be executed")
    assert res.matched and res.show


def test_is_actions_ask_intent_run_refuses():
    res = is_actions_ask_intent("run the actions")
    assert res.matched and res.run


def test_is_actions_ask_intent_unrelated():
    assert is_actions_ask_intent("how are you").matched is False


# ---------------------------------------------------------------------------
# Helpers


def test_find_actions_for_proposal(tmp_path):
    proposal = _mk_proposal()
    compile_and_write(proposal, data_dir=tmp_path)
    p = find_actions_for_proposal(tmp_path, proposal.proposal_id)
    assert p is not None and p.exists()
    assert find_actions_for_proposal(tmp_path, "prop_unknown") is None
