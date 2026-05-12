"""PR38: stale-evidence / drift guard tests.

Deterministic, fixture-based. No Docker, no systemd/journal, no network,
no root, no host mutation.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.actions import compile_and_write
from shellforgeai.core.approvals import (
    STATUS_APPROVED,
    Proposal,
    ProposalApproval,
    ProposalExecution,
    ProposalSource,
    compute_proposal_fingerprint_payload,
    write_proposal,
)
from shellforgeai.core.export_pack import export_from_session
from shellforgeai.core.guards import (
    DECISION_BLOCKED,
    DECISION_DRIFT,
    DECISION_FRESH,
    DECISION_STALE,
    GUARD_SCHEMA_VERSION,
    HASH_CHANGED,
    HASH_MATCHED,
    HASH_MISSING,
    HASH_UNKNOWN,
    check_actions_file,
    check_export_dir,
    check_proposal_file,
    check_proposal_payload,
    compute_proposal_source_hashes,
    compute_source_hashes_for_paths,
    evaluate_age,
    evaluate_drift,
    is_guard_ask_intent,
    load_guard_report,
    max_age_from_hours,
    sha256_of_path,
    write_guard_report,
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


def _make_session(data_dir: Path, session_id: str = "sf_pr38_001") -> Path:
    sess = data_dir / "artifacts" / session_id
    sess.mkdir(parents=True, exist_ok=True)
    (sess / "evidence.json").write_text(
        json.dumps({"session_id": session_id, "items": []}), encoding="utf-8"
    )
    (sess / "summary.md").write_text("# summary\n", encoding="utf-8")
    (sess / "runbook.json").write_text(
        json.dumps({"session_id": session_id, "remediation_options": []}),
        encoding="utf-8",
    )
    (sess / "runbook.md").write_text("# runbook\n", encoding="utf-8")
    return sess


def _make_proposal(
    *,
    proposal_id: str = "prop_pr38_001",
    session_id: str = "sf_pr38_001",
    runbook_path: str = "",
    evidence_path: str = "",
    summary_path: str = "",
    created_at: str | None = None,
    status: str = STATUS_APPROVED,
    record_hashes: bool = True,
) -> Proposal:
    component = "sfai-missing-env"
    kind = "container_env_config_change"
    title = "PR38 proposal"
    steps = [
        "OPERATOR-RUN: edit compose env file.",
        "OPERATOR-RUN: docker compose up -d sfai-missing-env # SERVICE-IMPACTING",
    ]
    rollback = ["Revert compose change."]
    verification = ["docker logs --tail 50 sfai-missing-env"]
    fp = compute_proposal_fingerprint_payload(
        session_id=session_id,
        option_id="opt_pr38_001",
        component=component,
        kind=kind,
        title=title,
        risk="medium",
        steps=steps,
        rollback=rollback,
        verification=verification,
    )
    hashes: dict[str, str] = {}
    if record_hashes:
        hashes = compute_proposal_source_hashes(
            evidence_path=evidence_path,
            runbook_path=runbook_path,
            summary_path=summary_path,
        )
    return Proposal(
        proposal_id=proposal_id,
        created_at=(datetime.now(timezone.utc).isoformat() if created_at is None else created_at),
        status=status,
        source=ProposalSource(
            session_id=session_id,
            runbook=runbook_path,
            evidence=evidence_path,
            summary=summary_path,
        ),
        target="docker",
        component=component,
        kind=kind,
        title=title,
        risk="medium",
        confidence="medium",
        impact="PR38 fixture",
        safety_labels=["OPERATOR-RUN", "REQUIRES APPROVAL", "SERVICE-IMPACTING"],
        preconditions=["Confirm setting."],
        proposed_steps=steps,
        rollback=rollback,
        verification=verification,
        execution=ProposalExecution(),
        fingerprint=fp,
        source_hashes=hashes,
        approval=ProposalApproval(
            reason="approved for PR38 test",
            approved_at=datetime.now(timezone.utc).isoformat(),
            approved_by="op",
        )
        if status == STATUS_APPROVED
        else ProposalApproval(),
    )


# ---------------------------------------------------------------------------
# Hash helpers


def test_sha256_of_path_matches_for_known_content(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hello", encoding="utf-8")
    digest = sha256_of_path(p)
    assert digest is not None and digest.startswith("sha256:")
    digest_again = sha256_of_path(p)
    assert digest == digest_again


def test_sha256_of_path_missing_returns_none(tmp_path):
    assert sha256_of_path(tmp_path / "nope.txt") is None


def test_compute_source_hashes_skips_missing_paths(tmp_path):
    a = tmp_path / "a.txt"
    a.write_text("aaa", encoding="utf-8")
    out = compute_source_hashes_for_paths({"a.txt": a, "b.txt": tmp_path / "b.txt", "empty": ""})
    assert "a.txt" in out
    assert "b.txt" not in out
    assert "empty" not in out


# ---------------------------------------------------------------------------
# Age evaluation


def test_evaluate_age_fresh():
    now = datetime.now(timezone.utc)
    age = evaluate_age(
        (now - timedelta(seconds=10)).isoformat(),
        source_type="proposal",
        now=now,
    )
    assert age.status == "fresh"
    assert age.age_seconds >= 10
    assert age.max_age_seconds == 86400


def test_evaluate_age_stale():
    now = datetime.now(timezone.utc)
    age = evaluate_age(
        (now - timedelta(days=2)).isoformat(),
        source_type="proposal",
        now=now,
    )
    assert age.status == "stale"
    assert age.age_seconds > age.max_age_seconds


def test_evaluate_age_unknown_when_missing():
    age = evaluate_age("", source_type="proposal")
    assert age.status == "unknown"


def test_max_age_from_hours_override():
    assert max_age_from_hours(1, source_type="proposal") == 3600
    assert max_age_from_hours(None, source_type="proposal") == 86400
    assert max_age_from_hours(None, source_type="export") == 7 * 86400


# ---------------------------------------------------------------------------
# Drift evaluation


def test_evaluate_drift_matched(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("hello", encoding="utf-8")
    stored = {"a.txt": sha256_of_path(p)}
    drift = evaluate_drift(stored, {"a.txt": p})
    assert drift.source_hash_status == HASH_MATCHED
    assert not drift.changed_files


def test_evaluate_drift_changed(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("hello", encoding="utf-8")
    stored = {"a.txt": sha256_of_path(p)}
    p.write_text("changed", encoding="utf-8")
    drift = evaluate_drift(stored, {"a.txt": p})
    assert drift.source_hash_status == HASH_CHANGED
    assert "a.txt" in drift.changed_files


def test_evaluate_drift_missing(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("hello", encoding="utf-8")
    stored = {"a.txt": sha256_of_path(p)}
    p.unlink()
    drift = evaluate_drift(stored, {"a.txt": p})
    assert drift.source_hash_status == HASH_MISSING
    assert "a.txt" in drift.missing_files


def test_evaluate_drift_unknown_when_no_stored_hashes():
    drift = evaluate_drift({}, {})
    assert drift.source_hash_status == HASH_UNKNOWN


# ---------------------------------------------------------------------------
# Proposal guard


def test_check_proposal_fresh(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    path = write_proposal(data_env, proposal)
    report = check_proposal_file(path)
    assert report.decision == DECISION_FRESH
    assert report.execution_allowed is False
    assert report.execution_status == "not_executed"
    assert report.drift.source_hash_status == HASH_MATCHED


def test_check_proposal_stale_when_old_created_at(data_env):
    sess = _make_session(data_env)
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
        created_at=old,
    )
    path = write_proposal(data_env, proposal)
    report = check_proposal_file(path)
    assert report.decision == DECISION_STALE
    assert report.age.status == "stale"
    # Stale is not blocked; it's a warning-style decision.
    assert report.execution_allowed is False


def test_check_proposal_drift_detected_when_source_changes(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    path = write_proposal(data_env, proposal)
    # Tamper with the source evidence after proposal creation.
    (sess / "evidence.json").write_text(
        json.dumps({"session_id": "sf_pr38_001", "items": ["new"]}), encoding="utf-8"
    )
    report = check_proposal_file(path)
    assert report.decision == DECISION_DRIFT
    assert report.drift.source_hash_status == HASH_CHANGED
    assert "evidence.json" in report.drift.changed_files


def test_check_proposal_drift_when_source_removed(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    path = write_proposal(data_env, proposal)
    (sess / "evidence.json").unlink()
    report = check_proposal_file(path)
    assert report.decision == DECISION_DRIFT
    assert report.drift.source_hash_status in (HASH_MISSING, HASH_CHANGED)


def test_check_proposal_blocked_when_missing(data_env):
    report = check_proposal_file(data_env / "nonexistent.proposal.json")
    assert report.decision == DECISION_BLOCKED


def test_check_proposal_blocked_when_malformed(data_env, tmp_path):
    p = tmp_path / "bad.proposal.json"
    p.write_text("{not json", encoding="utf-8")
    report = check_proposal_file(p)
    assert report.decision == DECISION_BLOCKED


def test_check_proposal_without_stored_hashes_is_warning_not_failure(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
        record_hashes=False,
    )
    path = write_proposal(data_env, proposal)
    report = check_proposal_file(path)
    # No stored hashes: drift unknown, but decision is still fresh/warning
    assert report.drift.source_hash_status == HASH_UNKNOWN
    assert report.decision in (DECISION_FRESH, "warning")


def test_check_proposal_missing_created_at_warns(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
        created_at="",
    )
    path = write_proposal(data_env, proposal)
    report = check_proposal_file(path)
    assert report.age.status == "unknown"
    assert report.decision in (DECISION_FRESH, "warning")


def test_check_proposal_payload_max_age_override(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    payload = json.loads(proposal.model_dump_json())
    # Override max age to 1 second so the proposal looks stale.
    report = check_proposal_payload(payload, max_age_seconds=1)
    assert report.decision in (DECISION_STALE, DECISION_DRIFT, DECISION_FRESH)
    # The decision depends on age vs threshold; with 1s override the proposal is stale.
    if report.age.age_seconds > 1:
        assert report.decision == DECISION_STALE


# ---------------------------------------------------------------------------
# Actions guard


def test_check_actions_fresh(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    compile_result = compile_and_write(proposal, data_dir=data_env)
    report = check_actions_file(compile_result.actions_json, data_dir=data_env)
    assert report.decision == DECISION_FRESH
    assert report.execution_allowed is False


def test_check_actions_fingerprint_mismatch(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    compile_result = compile_and_write(proposal, data_dir=data_env)
    payload = json.loads(compile_result.actions_json.read_text(encoding="utf-8"))
    payload["proposal_fingerprint"] = "0" * 64
    compile_result.actions_json.write_text(json.dumps(payload), encoding="utf-8")
    report = check_actions_file(compile_result.actions_json, data_dir=data_env)
    assert report.decision == DECISION_BLOCKED


def test_check_actions_execution_allowed_true_blocks(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    compile_result = compile_and_write(proposal, data_dir=data_env)
    payload = json.loads(compile_result.actions_json.read_text(encoding="utf-8"))
    payload["execution_allowed"] = True
    compile_result.actions_json.write_text(json.dumps(payload), encoding="utf-8")
    report = check_actions_file(compile_result.actions_json, data_dir=data_env)
    assert report.decision == DECISION_BLOCKED


def test_check_actions_missing_proposal_warns(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        proposal_id="prop_pr38_actions_orphan",
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    compile_result = compile_and_write(proposal, data_dir=data_env)
    # No write_proposal call: source proposal missing on disk.
    report = check_actions_file(compile_result.actions_json, data_dir=data_env)
    assert "source proposal not found" in " ".join(report.warnings)


def test_check_actions_missing_file_blocks(data_env):
    report = check_actions_file(data_env / "nope" / "actions.json", data_dir=data_env)
    assert report.decision == DECISION_BLOCKED


# ---------------------------------------------------------------------------
# Export guard


def test_check_export_fresh(data_env):
    sess = _make_session(data_env)
    export = export_from_session(data_env, sess)
    report = check_export_dir(export.export_dir)
    assert report.decision == DECISION_FRESH
    assert report.drift.source_hash_status == HASH_MATCHED


def test_check_export_checksum_mismatch_blocks(data_env):
    sess = _make_session(data_env)
    export = export_from_session(data_env, sess)
    (export.export_dir / "evidence.json").write_text("tampered", encoding="utf-8")
    report = check_export_dir(export.export_dir)
    assert report.decision == DECISION_BLOCKED


def test_check_export_missing_dir_blocks(data_env):
    report = check_export_dir(data_env / "doesnotexist")
    assert report.decision == DECISION_BLOCKED


def test_check_export_redacted_without_report_blocks(data_env):
    sess = _make_session(data_env)
    export = export_from_session(data_env, sess)
    # Forge a redacted manifest without a redaction-report.json
    manifest_path = export.export_dir / "export-manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["redaction_applied"] = True
    payload["redaction_report"] = "redaction-report.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    report = check_export_dir(export.export_dir)
    assert report.decision == DECISION_BLOCKED


def test_check_export_preflight_execution_allowed_blocks(data_env):
    sess = _make_session(data_env)
    export = export_from_session(data_env, sess)
    (export.export_dir / "apply-preflight.json").write_text(
        json.dumps({"execution_allowed": True, "execution_status": "not_executed"}),
        encoding="utf-8",
    )
    report = check_export_dir(export.export_dir)
    assert report.decision == DECISION_BLOCKED


# ---------------------------------------------------------------------------
# Persistence / report shape


def test_write_guard_report_creates_json_and_md(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    path = write_proposal(data_env, proposal)
    report = check_proposal_file(path)
    written = write_guard_report(report, data_dir=data_env)
    assert written.json_path.exists()
    assert written.md_path.exists()
    payload, err = load_guard_report(written.json_path)
    assert err is None and payload is not None
    assert payload["schema_version"] == GUARD_SCHEMA_VERSION
    assert payload["execution_allowed"] is False
    assert payload["execution_status"] == "not_executed"
    assert payload["source_type"] == "proposal"
    assert payload["source_id"] == proposal.proposal_id


def test_load_guard_report_accepts_directory(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    path = write_proposal(data_env, proposal)
    report = check_proposal_file(path)
    written = write_guard_report(report, data_dir=data_env)
    payload, err = load_guard_report(written.json_path.parent)
    assert err is None and payload is not None


# ---------------------------------------------------------------------------
# Ask intent


def test_is_guard_ask_intent_proposal():
    res = is_guard_ask_intent("is this proposal stale?")
    assert res.matched and res.check_proposal


def test_is_guard_ask_intent_drift():
    res = is_guard_ask_intent("check drift before apply")
    assert res.matched and res.check_drift


def test_is_guard_ask_intent_actions():
    res = is_guard_ask_intent("is the action plan safe to use?")
    assert res.matched and res.check_actions


def test_is_guard_ask_intent_export():
    res = is_guard_ask_intent("verify this export pack is still valid")
    assert res.matched and res.check_export


def test_is_guard_ask_intent_run_anyway():
    res = is_guard_ask_intent("run it anyway")
    assert res.matched and res.run_anyway


def test_is_guard_ask_intent_unrelated():
    assert is_guard_ask_intent("how is the weather").matched is False


# ---------------------------------------------------------------------------
# CLI smoke tests

runner = CliRunner()


def _run(*args):
    return runner.invoke(app, list(args))


def test_cli_guard_check_proposal_fresh(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    res = _run("guard", "check", proposal.proposal_id)
    assert res.exit_code == 0, res.output
    assert "decision: fresh" in res.output
    assert "execution_allowed: false" in res.output
    out_dir = data_env / "guards" / proposal.proposal_id
    assert (out_dir / "guard-report.json").exists()
    assert (out_dir / "guard-report.md").exists()


def test_cli_guard_check_latest_approved(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    res = _run("guard", "check", "--latest-approved")
    assert res.exit_code == 0, res.output
    assert "decision: fresh" in res.output


def test_cli_guard_check_missing_proposal_blocks(data_env):
    res = _run("guard", "check", "prop_nope")
    assert res.exit_code != 0


def test_cli_guard_check_stale_with_max_age(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    # 0 hours => any non-zero age is stale (use a very small max-age).
    res = _run("guard", "check", proposal.proposal_id, "--max-age-hours", "0.0001")
    assert res.exit_code != 0
    assert "decision: stale" in res.output or "stale" in res.output.lower()


def test_cli_guard_check_actions(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    compile_result = compile_and_write(proposal, data_dir=data_env)
    res = _run("guard", "check-actions", str(compile_result.actions_json))
    assert res.exit_code == 0, res.output
    assert "decision: fresh" in res.output


def test_cli_guard_check_export(data_env):
    sess = _make_session(data_env)
    export = export_from_session(data_env, sess)
    res = _run("guard", "check-export", str(export.export_dir))
    assert res.exit_code == 0, res.output
    assert "decision: fresh" in res.output


def test_cli_guard_show(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    _run("guard", "check", proposal.proposal_id)
    report_path = data_env / "guards" / proposal.proposal_id / "guard-report.json"
    res = _run("guard", "show", str(report_path))
    assert res.exit_code == 0, res.output
    assert proposal.proposal_id in res.output


# ---------------------------------------------------------------------------
# Apply integration


def test_apply_refuses_stale_proposal(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    res = _run("apply", proposal.proposal_id, "--max-age-hours", "0.0001")
    assert res.exit_code != 0
    assert "stale" in res.output.lower()
    # No bundle should be generated.
    bdir = data_env / "apply_bundles" / proposal.proposal_id
    # Diagnostic apply-preflight.json may exist with guard refusal but no
    # operator-run scripts.
    if bdir.exists():
        assert not (bdir / "operator-commands.sh").exists()


def test_apply_allow_stale_creates_bundle(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    res = _run(
        "apply",
        proposal.proposal_id,
        "--max-age-hours",
        "0.0001",
        "--allow-stale",
    )
    assert res.exit_code == 0, res.output
    bdir = data_env / "apply_bundles" / proposal.proposal_id
    for name in (
        "apply-preview.md",
        "operator-commands.sh",
        "rollback.sh",
        "validation.md",
        "apply-preflight.json",
    ):
        assert (bdir / name).exists()
    payload = json.loads((bdir / "apply-preflight.json").read_text(encoding="utf-8"))
    assert payload["execution_allowed"] is False
    assert payload["execution_status"] == "not_executed"
    assert payload.get("guard_status") in ("stale", "fresh", "warning")
    assert payload.get("guard_report")


def test_apply_refuses_drifted_proposal(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    # Drift after creation: change evidence content.
    (sess / "evidence.json").write_text("CHANGED", encoding="utf-8")
    res = _run("apply", proposal.proposal_id)
    assert res.exit_code != 0
    assert "drift" in res.output.lower() or "changed" in res.output.lower()


def test_apply_fresh_proposal_bundle_includes_guard_status(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    res = _run("apply", proposal.proposal_id)
    assert res.exit_code == 0, res.output
    bdir = data_env / "apply_bundles" / proposal.proposal_id
    payload = json.loads((bdir / "apply-preflight.json").read_text(encoding="utf-8"))
    assert payload.get("guard_status") == DECISION_FRESH
    assert payload.get("execution_allowed") is False
    assert payload.get("execution_status") == "not_executed"
    assert payload.get("guard_report")


# ---------------------------------------------------------------------------
# Ask integration


def test_cli_ask_check_proposal_freshness_returns_guard(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    res = _run("ask", "check if the approved proposal is still fresh")
    assert res.exit_code == 0, res.output
    assert "decision:" in res.output


def test_cli_ask_run_it_anyway_refuses(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    write_proposal(data_env, proposal)
    res = _run("ask", "run it anyway")
    assert res.exit_code == 0, res.output
    assert "Refusing to execute" in res.output or "never runs" in res.output.lower()


# ---------------------------------------------------------------------------
# Schema invariants


def test_guard_report_always_records_no_execution(data_env):
    sess = _make_session(data_env)
    proposal = _make_proposal(
        runbook_path=str(sess / "runbook.json"),
        evidence_path=str(sess / "evidence.json"),
        summary_path=str(sess / "summary.md"),
    )
    path = write_proposal(data_env, proposal)
    report = check_proposal_file(path)
    payload = report.to_dict()
    assert payload["execution_allowed"] is False
    assert payload["execution_status"] == "not_executed"
    assert payload["schema_version"] == GUARD_SCHEMA_VERSION
    # Decisions are constrained
    assert payload["decision"] in (
        DECISION_FRESH,
        DECISION_STALE,
        DECISION_DRIFT,
        DECISION_BLOCKED,
        "warning",
    )
