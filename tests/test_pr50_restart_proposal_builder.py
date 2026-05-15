from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.approvals import load_proposal_from_path

runner = CliRunner()


def _write_evidence(tmp_path: Path, *, name: str, labels: dict[str, str]) -> Path:
    payload = {
        "session_id": "sf_test_pr50",
        "items": [
            {
                "source": "docker.containers",
                "content": json.dumps(
                    {
                        "containers": [
                            {
                                "name": name,
                                "id": "abc123",
                                "image": "lab:v1",
                                "state": "running",
                                "status": "Up 1m",
                                "health": "healthy",
                                "labels": labels,
                            }
                        ]
                    }
                ),
            }
        ],
    }
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_approvals_propose_restart_creates_pending(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _write_evidence(
        tmp_path, name="sfai-pr50-web", labels={"shellforgeai.allow_restart": "true"}
    )
    result = runner.invoke(
        app,
        ["approvals", "propose-restart", "sfai-pr50-web", "--from-evidence", str(ev)],
    )
    assert result.exit_code == 0, result.output
    assert "Restart proposal created" in result.output
    entries = list((tmp_path / "approvals" / "pending").glob("*.proposal.json"))
    assert len(entries) == 1
    proposal = load_proposal_from_path(entries[0])
    assert proposal.execution.allowed is False
    assert proposal.execution.status == "not_executed"
    assert proposal.proposed_steps == ["docker restart sfai-pr50-web"]
    assert "DOCKER-MUTATION" in proposal.safety_labels


def test_approvals_propose_restart_refuses_non_allowlisted(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _write_evidence(tmp_path, name="prod-nginx", labels={})
    result = runner.invoke(
        app,
        ["approvals", "propose-restart", "prod-nginx", "--from-evidence", str(ev)],
    )
    assert result.exit_code == 1
    assert "Restart proposal refused" in result.output
    assert not (tmp_path / "approvals").exists()


def test_approvals_propose_restart_dedupes(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _write_evidence(tmp_path, name="sfai-test-api", labels={"shellforgeai.disposable": "true"})
    cmd = ["approvals", "propose-restart", "sfai-test-api", "--from-evidence", str(ev)]
    first = runner.invoke(app, cmd)
    second = runner.invoke(app, cmd)
    assert first.exit_code == 0
    assert second.exit_code == 0
    assert "deduped" in second.output.lower()
    entries = list((tmp_path / "approvals" / "pending").glob("*.proposal.json"))
    assert len(entries) == 1
