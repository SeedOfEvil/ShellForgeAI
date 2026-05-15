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


def _mk_session_with_evidence(
    data_dir: Path, session_id: str, *, name: str, labels: dict[str, str]
) -> Path:
    sess = data_dir / "artifacts" / session_id
    sess.mkdir(parents=True, exist_ok=True)
    evidence = _write_evidence(sess, name=name, labels=labels)
    (sess / "summary.md").write_text("# summary\n", encoding="utf-8")
    (sess / "plan.json").write_text('{"plan_id":"p1"}\n', encoding="utf-8")
    return evidence


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


def test_approvals_propose_restart_latest_works_without_runbook(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _mk_session_with_evidence(
        tmp_path,
        "sf_20260515_000001_aaaaaa",
        name="sfai-pr50-latest",
        labels={"shellforgeai.allow_restart": "true"},
    )
    result = runner.invoke(
        app,
        [
            "approvals",
            "propose-restart",
            "--latest",
            "--container",
            "sfai-pr50-latest",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Restart proposal created" in result.output


def test_from_evidence_and_from_session_dedupe_with_same_canonical_session(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _mk_session_with_evidence(
        tmp_path,
        "sf_20260515_000002_bbbbbb",
        name="sfai-pr50-dedupe",
        labels={"shellforgeai.allow_restart": "true"},
    )
    a = runner.invoke(
        app,
        [
            "approvals",
            "propose-restart",
            "--from-evidence",
            str(ev),
            "--container",
            "sfai-pr50-dedupe",
        ],
    )
    b = runner.invoke(
        app,
        [
            "approvals",
            "propose-restart",
            "--from-session",
            "sf_20260515_000002_bbbbbb",
            "--container",
            "sfai-pr50-dedupe",
        ],
    )
    assert a.exit_code == 0, a.output
    assert b.exit_code == 0, b.output
    assert "deduped" in b.output.lower()
    entries = list((tmp_path / "approvals" / "pending").glob("*.proposal.json"))
    assert len(entries) == 1


def test_container_option_and_positional_both_supported(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _write_evidence(
        tmp_path, name="sfai-pr50-container-opt", labels={"shellforgeai.allow_restart": "true"}
    )
    via_opt = runner.invoke(
        app,
        [
            "approvals",
            "propose-restart",
            "--from-evidence",
            str(ev),
            "--container",
            "sfai-pr50-container-opt",
        ],
    )
    via_positional = runner.invoke(
        app,
        [
            "approvals",
            "propose-restart",
            "sfai-pr50-container-opt",
            "--from-evidence",
            str(ev),
        ],
    )
    assert via_opt.exit_code == 0, via_opt.output
    assert via_positional.exit_code == 0, via_positional.output


def test_approvals_propose_restart_refuses_missing_target(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _write_evidence(
        tmp_path, name="sfai-pr50-real", labels={"shellforgeai.allow_restart": "true"}
    )
    result = runner.invoke(
        app,
        ["approvals", "propose-restart", "sfai-pr50-missing", "--from-evidence", str(ev)],
    )
    assert result.exit_code == 1
    assert "target not found in evidence" in result.output


def test_approvals_propose_restart_refuses_shellforgeai_target(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _write_evidence(
        tmp_path, name="shellforgeai", labels={"shellforgeai.allow_restart": "true"}
    )
    result = runner.invoke(
        app,
        ["approvals", "propose-restart", "shellforgeai", "--from-evidence", str(ev)],
    )
    assert result.exit_code == 1
    assert "target is shellforgeai itself" in result.output


def test_approvals_propose_restart_refuses_shell_metachar_target(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    ev = _write_evidence(
        tmp_path, name="sfai-pr50-meta", labels={"shellforgeai.allow_restart": "true"}
    )
    result = runner.invoke(
        app,
        ["approvals", "propose-restart", "sfai-pr50-meta;rm", "--from-evidence", str(ev)],
    )
    assert result.exit_code == 1
    assert "unsafe container name" in result.output
