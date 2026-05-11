"""PR34: audit/export pack tests.

Fixtures/mocks only. No Docker, no systemd/journal, no network, no root,
no host mutation.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.apply_bundle import generate_bundle
from shellforgeai.core.approvals import (
    STATUS_APPROVED,
    Proposal,
    ProposalApproval,
    ProposalExecution,
    ProposalSource,
    compute_proposal_fingerprint_payload,
    write_proposal,
)
from shellforgeai.core.export_pack import (
    SESSION_OPTIONAL_FILES,
    export_from_proposal,
    export_from_session,
    export_latest_approved,
    export_latest_session,
    is_export_intent,
    redact_text,
    validate_export,
)

# ---------------------------------------------------------------------------
# Fixtures


@pytest.fixture()
def data_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path / "sfdata"))
    monkeypatch.setenv("HOME", str(tmp_path))
    data_dir = tmp_path / "sfdata"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def _make_session(data_dir: Path, session_id: str, *, with_runbook: bool = True) -> Path:
    sess = data_dir / "artifacts" / session_id
    sess.mkdir(parents=True, exist_ok=True)
    (sess / "evidence.json").write_text(
        json.dumps({"session_id": session_id, "items": []}, indent=2), encoding="utf-8"
    )
    (sess / "summary.md").write_text(
        f"# Summary for {session_id}\n\npassword=hunter2\n", encoding="utf-8"
    )
    (sess / "plan.json").write_text(
        json.dumps({"plan_id": "p", "session_id": session_id}, indent=2), encoding="utf-8"
    )
    if with_runbook:
        (sess / "runbook.md").write_text("# Runbook\n- step\n", encoding="utf-8")
        (sess / "runbook.json").write_text(
            json.dumps({"session_id": session_id, "remediation_options": []}, indent=2),
            encoding="utf-8",
        )
    return sess


def _make_proposal(
    proposal_id: str = "prop_test_pr34_001",
    *,
    status: str = STATUS_APPROVED,
    session_id: str = "sf_test_001",
    runbook_path: str = "",
    evidence_path: str = "",
) -> Proposal:
    component = "sfai-missing-env"
    kind = "container_env_config_change"
    title = "Provide REQUIRED_SETTING for sfai-missing-env"
    steps = [
        "OPERATOR-RUN: edit compose env file and add REQUIRED_SETTING.",
        "OPERATOR-RUN: docker compose up -d sfai-missing-env   # SERVICE-IMPACTING",
    ]
    rollback = ["Revert compose change.", "OPERATOR-RUN: docker compose up -d sfai-missing-env"]
    verification = ["docker logs --tail 50 sfai-missing-env"]
    fingerprint = compute_proposal_fingerprint_payload(
        session_id=session_id,
        option_id="opt_pr34_001",
        component=component,
        kind=kind,
        title=title,
        risk="medium",
        steps=steps,
        rollback=rollback,
        verification=verification,
    )
    return Proposal(
        proposal_id=proposal_id,
        created_at="2026-05-11T00:00:00+00:00",
        status=status,
        source=ProposalSource(
            session_id=session_id,
            runbook=runbook_path,
            evidence=evidence_path,
        ),
        target="docker",
        component=component,
        kind=kind,
        title=title,
        risk="medium",
        impact="Recreates sfai-missing-env after config change.",
        confidence="medium",
        safety_labels=["OPERATOR-RUN", "REQUIRES APPROVAL", "SERVICE-IMPACTING"],
        preconditions=["Confirm required variable name."],
        proposed_steps=steps,
        rollback=rollback,
        verification=verification,
        execution=ProposalExecution(),
        fingerprint=fingerprint,
        approval=ProposalApproval(
            reason="approved for PR34 test",
            approved_at="2026-05-11T00:00:01+00:00",
            approved_by="op",
        ),
    )


# ---------------------------------------------------------------------------
# Source resolution


def test_export_from_session_includes_artifacts(data_env):
    sess = _make_session(data_env, "sf_pr34_session_001")
    res = export_from_session(data_env, sess)
    for name in SESSION_OPTIONAL_FILES:
        assert (res.export_dir / name).exists(), f"missing {name}"
    assert "evidence.json" in res.included_files
    assert res.missing_optional == []


def test_export_from_session_records_missing_optional(data_env):
    sess = _make_session(data_env, "sf_pr34_session_002", with_runbook=False)
    res = export_from_session(data_env, sess)
    assert "runbook.md" in res.missing_optional
    assert "runbook.json" in res.missing_optional
    assert "evidence.json" in res.included_files


def test_export_from_proposal_includes_proposal_and_source(data_env):
    sess = _make_session(data_env, "sf_pr34_proposal_001")
    proposal = _make_proposal(
        proposal_id="prop_pr34_proposal_001",
        session_id="sf_pr34_proposal_001",
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
    )
    write_proposal(data_env, proposal)
    res = export_from_proposal(data_env, proposal.proposal_id)
    assert "proposal.json" in res.included_files
    assert "evidence.json" in res.included_files
    assert "runbook.json" in res.included_files


def test_export_proposal_includes_bundle_when_present(data_env):
    sess = _make_session(data_env, "sf_pr34_bundle_001")
    proposal = _make_proposal(
        proposal_id="prop_pr34_bundle_001",
        session_id="sf_pr34_bundle_001",
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
    )
    write_proposal(data_env, proposal)
    generate_bundle(proposal, data_dir=data_env)
    res = export_from_proposal(data_env, proposal.proposal_id)
    assert "apply-preflight.json" in res.included_files
    assert "operator-commands.sh" in res.included_files
    assert "rollback.sh" in res.included_files


def test_export_latest_session_picks_newest(data_env):
    _make_session(data_env, "sf_pr34_old_001")
    time.sleep(0.05)
    newest = _make_session(data_env, "sf_pr34_new_001")
    res = export_latest_session(data_env)
    assert res.source_type == "latest"
    assert res.source_session_id == newest.name


def test_export_latest_approved_resolves_newest(data_env):
    p1 = _make_proposal(proposal_id="prop_pr34_first_001")
    p2 = _make_proposal(proposal_id="prop_pr34_second_001")
    write_proposal(data_env, p1)
    time.sleep(0.05)
    write_proposal(data_env, p2)
    res = export_latest_approved(data_env)
    assert res.source_proposal_id == p2.proposal_id


# ---------------------------------------------------------------------------
# Manifest / checksums


def test_manifest_has_required_fields(data_env):
    sess = _make_session(data_env, "sf_pr34_manifest_001")
    res = export_from_session(data_env, sess)
    manifest = json.loads(res.manifest_path.read_text(encoding="utf-8"))
    for key in (
        "export_id",
        "created_at",
        "source_type",
        "source_session_id",
        "included_files",
        "missing_optional_files",
        "checksums",
        "safety_note",
        "raw_evidence_warning",
        "shellforgeai_version",
    ):
        assert key in manifest, f"missing {key}"
    assert "did not execute" in manifest["safety_note"].lower()
    assert "review before sharing" in manifest["raw_evidence_warning"].lower()
    assert manifest["execution_allowed"] is False
    assert manifest["execution_status"] == "not_executed"
    for rel in manifest["included_files"]:
        assert "/" not in rel or rel.startswith("./") is False  # relative


def test_checksums_file_created_and_matches(data_env):
    sess = _make_session(data_env, "sf_pr34_checksum_001")
    res = export_from_session(data_env, sess)
    assert res.checksums_path.exists()
    contents = res.checksums_path.read_text(encoding="utf-8")
    assert "evidence.json" in contents
    # Each line: <sha256>  <path>
    for line in contents.strip().splitlines():
        parts = line.split(None, 1)
        assert len(parts) == 2
        assert len(parts[0]) == 64


# ---------------------------------------------------------------------------
# Validation


def test_validate_export_passes_for_fresh_pack(data_env):
    sess = _make_session(data_env, "sf_pr34_validate_001")
    res = export_from_session(data_env, sess)
    v = validate_export(res.export_dir)
    assert v.ok, v.errors


def test_validate_fails_on_missing_manifest(tmp_path):
    v = validate_export(tmp_path / "nonexistent")
    assert not v.ok
    assert any("manifest" in e.lower() for e in v.errors)


def test_validate_fails_on_missing_included_file(data_env):
    sess = _make_session(data_env, "sf_pr34_validate_002")
    res = export_from_session(data_env, sess)
    (res.export_dir / "evidence.json").unlink()
    v = validate_export(res.export_dir)
    assert not v.ok
    assert any("missing included file: evidence.json" in e for e in v.errors)


def test_validate_fails_on_checksum_mismatch(data_env):
    sess = _make_session(data_env, "sf_pr34_validate_003")
    res = export_from_session(data_env, sess)
    target = res.export_dir / "evidence.json"
    target.write_text("tampered", encoding="utf-8")
    v = validate_export(res.export_dir)
    assert not v.ok
    assert any("checksum mismatch: evidence.json" in e for e in v.errors)


def test_validate_fails_on_malformed_manifest(data_env):
    sess = _make_session(data_env, "sf_pr34_validate_004")
    res = export_from_session(data_env, sess)
    res.manifest_path.write_text("{not json", encoding="utf-8")
    v = validate_export(res.export_dir)
    assert not v.ok
    assert any("malformed manifest" in e for e in v.errors)


def test_validate_fails_when_redaction_report_missing(data_env):
    sess = _make_session(data_env, "sf_pr35_validate_redact_001")
    res = export_from_session(data_env, sess, redact=True)
    (res.export_dir / "redaction-report.json").unlink()
    v = validate_export(res.export_dir)
    assert not v.ok
    assert any("redaction-report.json missing" in e for e in v.errors)


def test_validate_fails_on_apply_preflight_execution_allowed(data_env):
    sess = _make_session(data_env, "sf_pr34_validate_005")
    proposal = _make_proposal(
        proposal_id="prop_pr34_validate_005",
        session_id="sf_pr34_validate_005",
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
    )
    write_proposal(data_env, proposal)
    generate_bundle(proposal, data_dir=data_env)
    res = export_from_proposal(data_env, proposal.proposal_id)
    # Tamper with preflight to claim execution allowed.
    preflight_path = res.export_dir / "apply-preflight.json"
    payload = json.loads(preflight_path.read_text(encoding="utf-8"))
    payload["execution_allowed"] = True
    preflight_path.write_text(json.dumps(payload), encoding="utf-8")
    v = validate_export(res.export_dir)
    assert not v.ok
    assert any("execution_allowed" in e for e in v.errors)


# ---------------------------------------------------------------------------
# Redaction


def test_redact_text_masks_common_secrets():
    txt = "password=hunter2\ntoken: abc123\nAPI_KEY=xyz789\nAuthorization: Bearer eyJ\nDATABASE_URL=postgres://u:p@h/db\n"
    out = redact_text(txt)
    assert "hunter2" not in out
    assert "abc123" not in out
    assert "xyz789" not in out
    assert "eyJ" not in out
    assert "[REDACTED]" in out
    assert "postgres://u:p@h/db" not in out


def test_redact_text_private_key_block_and_preserve_normal_text():
    txt = "missing REQUIRED_SETTING\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
    out = redact_text(txt)
    assert "REQUIRED_SETTING" in out
    assert "[REDACTED_PRIVATE_KEY_BLOCK]" in out


def test_redact_flag_redacts_copied_summary(data_env):
    sess = _make_session(data_env, "sf_pr34_redact_001")
    res = export_from_session(data_env, sess, redact=True)
    summary_copy = (res.export_dir / "summary.md").read_text(encoding="utf-8")
    assert "hunter2" not in summary_copy
    assert "[REDACTED]" in summary_copy
    manifest = json.loads((res.export_dir / "export-manifest.json").read_text(encoding="utf-8"))
    assert manifest["redaction_applied"] is True
    assert (res.export_dir / "redaction-report.json").exists()
    report = json.loads((res.export_dir / "redaction-report.json").read_text(encoding="utf-8"))
    assert report["redaction_applied"] is True
    assert "hunter2" not in json.dumps(report)


# ---------------------------------------------------------------------------
# CLI


def test_cli_export_session_dir(data_env):
    sess = _make_session(data_env, "sf_pr34_cli_001")
    runner = CliRunner()
    result = runner.invoke(app, ["export", str(sess)])
    assert result.exit_code == 0, result.output
    assert "Audit/export pack written" in result.output
    assert "execution: not_executed" in result.output


def test_cli_export_session_id(data_env):
    _make_session(data_env, "sf_pr34_cli_id_001")
    runner = CliRunner()
    result = runner.invoke(app, ["export", "sf_pr34_cli_id_001"])
    assert result.exit_code == 0, result.output
    assert "sf_pr34_cli_id_001" in result.output


def test_cli_export_latest(data_env):
    _make_session(data_env, "sf_pr34_cli_latest_001")
    runner = CliRunner()
    result = runner.invoke(app, ["export", "--latest"])
    assert result.exit_code == 0, result.output
    assert "sf_pr34_cli_latest_001" in result.output


def test_cli_export_proposal(data_env):
    proposal = _make_proposal(proposal_id="prop_pr34_cli_001")
    write_proposal(data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["export", "--proposal", proposal.proposal_id])
    assert result.exit_code == 0, result.output
    assert proposal.proposal_id in result.output
    assert "proposal.json" in result.output


def test_cli_export_latest_approved(data_env):
    proposal = _make_proposal(proposal_id="prop_pr34_cli_la_001")
    write_proposal(data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["export", "--latest-approved"])
    assert result.exit_code == 0, result.output
    assert "prop_pr34_cli_la_001" in result.output


def test_cli_export_approved_flag_refused(data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["export", "--approved"])
    assert result.exit_code != 0
    assert "too broad" in result.output.lower() or "refused" in result.output.lower()


def test_cli_export_missing_session(data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["export", "sf_does_not_exist"])
    assert result.exit_code != 0
    assert "not found" in result.output.lower()


def test_cli_validate_export_valid(data_env):
    sess = _make_session(data_env, "sf_pr34_validate_cli_001")
    runner = CliRunner()
    result = runner.invoke(app, ["export", str(sess)])
    assert result.exit_code == 0, result.output
    # Find export dir from output (printed via export id heading).
    export_root = data_env / "exports"
    export_dirs = list(export_root.glob("export_*"))
    assert export_dirs
    validate_result = runner.invoke(app, ["validate-export", str(export_dirs[0])])
    assert validate_result.exit_code == 0, validate_result.output
    assert "Export validation passed" in validate_result.output


def test_cli_validate_export_missing(data_env, tmp_path):
    runner = CliRunner()
    result = runner.invoke(app, ["validate-export", str(tmp_path / "no_such")])
    assert result.exit_code != 0
    assert "Export validation failed" in result.output


# ---------------------------------------------------------------------------
# Ask integration


def test_is_export_intent_matches_audit_pack():
    out = is_export_intent("create an audit pack")
    assert out.matched
    assert not out.prefer_approved


def test_is_export_intent_prefers_approved():
    out = is_export_intent("export the approved proposal")
    assert out.matched
    assert out.prefer_approved


def test_is_export_intent_redaction_phrase():
    out = is_export_intent("package this for external sharing")
    assert out.matched
    assert out.use_redaction


def test_ask_create_audit_pack_creates_export(data_env):
    _make_session(data_env, "sf_pr34_ask_001")
    runner = CliRunner()
    result = runner.invoke(app, ["ask", "create an audit pack"])
    assert result.exit_code == 0, result.output
    assert "Audit/export pack written" in result.output
    export_dirs = list((data_env / "exports").glob("export_*"))
    assert export_dirs


def test_ask_export_approved_proposal_creates_export(data_env):
    proposal = _make_proposal(proposal_id="prop_pr34_ask_002")
    write_proposal(data_env, proposal)
    runner = CliRunner()
    result = runner.invoke(app, ["ask", "export the approved proposal"])
    assert result.exit_code == 0, result.output
    assert "Audit/export pack written" in result.output
    assert proposal.proposal_id in result.output


def test_ask_export_when_no_session_or_proposal(data_env):
    runner = CliRunner()
    result = runner.invoke(app, ["ask", "create an audit pack"])
    assert result.exit_code == 0, result.output
    assert "no session artifacts" in result.output.lower()
    assert "no commands were executed" in result.output.lower()
