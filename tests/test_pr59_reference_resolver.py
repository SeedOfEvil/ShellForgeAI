from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from shellforgeai.core.approvals import (
    Proposal,
    ProposalApproval,
    ProposalExecution,
    ProposalSource,
    write_proposal,
)
from shellforgeai.core.reference_resolver import ReferenceFilters, resolve_reference


def _proposal(
    pid: str, status: str, created_at: datetime, component: str = "shellforgeai"
) -> Proposal:
    return Proposal(
        proposal_id=pid,
        created_at=created_at.isoformat(),
        status=status,
        source=ProposalSource(session_id="sf_test"),
        component=component,
        target=component,
        kind="docker_restart",
        title="restart",
        risk="medium",
        proposed_steps=[f"docker restart {component}"],
        execution=ProposalExecution(allowed=False, status="not_executed"),
        approval=ProposalApproval(),
    )


def test_resolve_latest_restart_proposal_prefers_newest_active(tmp_path: Path):
    now = datetime.now(UTC)
    write_proposal(tmp_path, _proposal("prop_old", "rejected", now - timedelta(days=2)))
    write_proposal(tmp_path, _proposal("prop_new", "pending", now - timedelta(minutes=5)))
    res = resolve_reference(
        "proposal",
        "show compose context for this restart proposal",
        ReferenceFilters(restart_only=True),
        tmp_path,
    )
    assert res.status == "resolved"
    assert res.id == "prop_new"


def test_resolve_explicit_old_id_still_wins(tmp_path: Path):
    now = datetime.now(UTC)
    write_proposal(tmp_path, _proposal("prop_explicit", "pending", now - timedelta(days=5)))
    res = resolve_reference(
        "proposal",
        "show compose context for prop_explicit",
        ReferenceFilters(restart_only=True),
        tmp_path,
    )
    assert res.status == "resolved"
    assert res.id == "prop_explicit"
    assert res.stale is False


def test_stale_is_flagged_for_latest_phrase(tmp_path: Path):
    now = datetime.now(UTC)
    write_proposal(tmp_path, _proposal("prop_stale", "pending", now - timedelta(days=3)))
    res = resolve_reference(
        "proposal",
        "latest restart proposal",
        ReferenceFilters(restart_only=True, stale_after_hours=24),
        tmp_path,
    )
    assert res.status == "resolved"
    assert res.stale is True


def test_ambiguous_when_scores_equal(tmp_path: Path):
    now = datetime.now(UTC)
    p1 = _proposal("prop_a", "pending", now, component="web")
    p2 = _proposal("prop_b", "pending", now, component="web")
    write_proposal(tmp_path, p1)
    write_proposal(tmp_path, p2)
    res = resolve_reference(
        "proposal", "this restart proposal", ReferenceFilters(restart_only=True), tmp_path
    )
    assert res.status == "ambiguous"
    assert len(res.candidates) >= 2
