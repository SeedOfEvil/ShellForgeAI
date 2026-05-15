from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.approvals import approve_proposal
from shellforgeai.core.rollback_preview import write_preview

runner = CliRunner()


def _write_evidence(tmp_path: Path, name: str) -> Path:
    payload = {
        "session_id": "sf_pr51",
        "items": [
            {
                "source": "docker.containers",
                "content": json.dumps(
                    {
                        "containers": [
                            {"name": name, "labels": {"shellforgeai.allow_restart": "true"}}
                        ]
                    }
                ),
            }
        ],
    }
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _make_proposal(tmp_path: Path, monkeypatch, name: str = "sfai-pr51-test") -> str:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _write_evidence(tmp_path, name)
    r = runner.invoke(app, ["approvals", "propose-restart", name, "--from-evidence", str(ev)])
    assert r.exit_code == 0, r.output
    pending = next((tmp_path / "approvals" / "pending").glob("*.proposal.json"))
    return pending.stem.replace(".proposal", "")


def test_restart_plan_pending_blocked(tmp_path: Path, monkeypatch):
    pid = _make_proposal(tmp_path, monkeypatch)
    r = runner.invoke(app, ["approvals", "restart-plan", pid])
    assert r.exit_code == 0
    assert "Apply readiness: blocked" in r.output
    assert "[WAIT] Proposal is pending approval" in r.output


def test_restart_plan_ready_when_approved_and_rollback_present(tmp_path: Path, monkeypatch):
    pid = _make_proposal(tmp_path, monkeypatch)
    proposal = approve_proposal(tmp_path, pid, reason="ok")
    write_preview(tmp_path, proposal)
    r = runner.invoke(app, ["approvals", "restart-plan", pid, "--json"])
    assert r.exit_code == 0
    payload = json.loads(r.output)
    assert payload["apply_readiness"]["status"] == "ready"
    assert payload["safety"]["execution_allowed"] is False


def test_restart_plan_from_evidence_missing_proposal(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _write_evidence(tmp_path, "sfai-pr51-missing")
    r = runner.invoke(
        app,
        [
            "approvals",
            "restart-plan",
            "--from-evidence",
            str(ev),
            "--container",
            "sfai-pr51-missing",
            "--json",
        ],
    )
    assert r.exit_code == 0
    payload = json.loads(r.output)
    assert payload["proposal_status"] == "missing"
    assert payload["apply_readiness"]["status"] == "blocked"


def test_restart_plan_ask_path(tmp_path: Path, monkeypatch):
    pid = _make_proposal(tmp_path, monkeypatch)
    _ = pid
    r = runner.invoke(app, ["ask", "show restart checklist"])
    assert r.exit_code == 0
    assert "Restart proposal plan" in r.output
