from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.approvals import approve_proposal, reject_proposal
from shellforgeai.core.mission import (
    KNOWN_PHASE_STATUSES,
    SCHEMA_VERSION,
    mission_json_path,
    prepare_mission,
    validate_mission_path,
)
from shellforgeai.core.rollback_preview import write_preview

runner = CliRunner()


def _write_evidence(dst: Path, name: str, allowlisted: bool = True) -> Path:
    labels = {"shellforgeai.allow_restart": "true"} if allowlisted else {}
    payload = {
        "session_id": "sf_pr52",
        "items": [
            {
                "source": "docker.containers",
                "content": json.dumps(
                    {
                        "containers": [
                            {
                                "name": name,
                                "id": "abc",
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
    p = dst / "evidence.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _setup(tmp_path: Path, monkeypatch, name: str = "sfai-pr52-target") -> tuple[Path, Path]:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    sess = tmp_path / "artifacts" / "sf_pr52"
    sess.mkdir(parents=True, exist_ok=True)
    ev = _write_evidence(sess, name)
    return tmp_path, ev


def test_mission_prepare_creates_pending_mission(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    r = runner.invoke(
        app,
        [
            "mission",
            "restart",
            "prepare",
            "--container",
            "sfai-pr52-target",
            "--from-evidence",
            str(ev),
        ],
    )
    assert r.exit_code == 0, r.output
    assert "Restart mission prepared" in r.output
    missions = list((data_dir / "missions" / "restart").iterdir())
    assert len(missions) == 1
    payload = json.loads((missions[0] / "mission.json").read_text())
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["mission_type"] == "docker_restart"
    assert payload["target"] == "sfai-pr52-target"
    assert payload["status"] == "waiting_approval"
    assert payload["safety"]["execution_allowed"] is False
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["arbitrary_command_execution"] is False
    assert payload["command_preview"] == "docker restart sfai-pr52-target"
    assert (missions[0] / "mission.md").exists()


def test_mission_prepare_dedupes_on_repeat(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    r1 = runner.invoke(
        app,
        [
            "mission",
            "restart",
            "prepare",
            "--container",
            "sfai-pr52-target",
            "--from-evidence",
            str(ev),
        ],
    )
    assert r1.exit_code == 0
    r2 = runner.invoke(
        app,
        [
            "mission",
            "restart",
            "prepare",
            "--container",
            "sfai-pr52-target",
            "--from-evidence",
            str(ev),
        ],
    )
    assert r2.exit_code == 0
    assert "deduped" in r2.output.lower()
    missions = list((data_dir / "missions" / "restart").iterdir())
    assert len(missions) == 1


def test_mission_prepare_refuses_when_evidence_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    r = runner.invoke(
        app,
        ["mission", "restart", "prepare", "--container", "sfai-pr52-target"],
    )
    assert r.exit_code == 1
    assert "refused" in r.output.lower()
    assert "diagnose" in r.output.lower()
    assert not (tmp_path / "missions" / "restart").exists()


def test_mission_prepare_refuses_non_allowlisted(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    sess = tmp_path / "artifacts" / "sf_x"
    sess.mkdir(parents=True, exist_ok=True)
    ev = _write_evidence(sess, "production-web", allowlisted=False)
    r = runner.invoke(
        app,
        [
            "mission",
            "restart",
            "prepare",
            "--container",
            "production-web",
            "--from-evidence",
            str(ev),
        ],
    )
    assert r.exit_code == 1
    assert "refused" in r.output.lower()
    assert not (tmp_path / "missions" / "restart").exists()


def test_mission_status_after_approve_shows_waiting_rollback(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    assert res.ok
    assert res.payload is not None
    pid = res.payload["proposal_id"]
    approve_proposal(data_dir, pid, reason="ok")
    r = runner.invoke(app, ["mission", "restart", "status", res.mission_id, "--json"])
    assert r.exit_code == 0
    payload = json.loads(r.output)
    assert payload["status"] == "waiting_rollback"
    assert payload["phases"]["approval"]["status"] == "approved"
    assert payload["phases"]["rollback"]["status"] == "missing"


def test_mission_status_ready_when_rollback_present(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    assert res.payload is not None
    pid = res.payload["proposal_id"]
    proposal = approve_proposal(data_dir, pid, reason="ok")
    write_preview(data_dir, proposal)
    r = runner.invoke(app, ["mission", "restart", "status", res.mission_id, "--json"])
    payload = json.loads(r.output)
    assert payload["status"] == "ready"
    assert payload["phases"]["readiness"]["status"] == "ready"
    assert payload["safety"]["execution_status"] == "not_executed"


def test_mission_status_blocked_when_rejected(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    assert res.payload is not None
    pid = res.payload["proposal_id"]
    reject_proposal(data_dir, pid, reason="no")
    r = runner.invoke(app, ["mission", "restart", "status", res.mission_id, "--json"])
    payload = json.loads(r.output)
    assert payload["status"] == "blocked"
    assert payload["phases"]["approval"]["status"] == "rejected"


def test_mission_checklist_lists_next_commands(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    r = runner.invoke(app, ["mission", "restart", "checklist", res.mission_id])
    assert r.exit_code == 0
    out = r.output
    assert "Safe restart mission" in out
    assert "Next commands:" in out
    assert "approvals approve" in out
    assert "apply" in out and "--execute --confirm" in out
    assert "did not restart anything" in out


def test_mission_with_rollback_preview_flag(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir,
        container="sfai-pr52-target",
        evidence_path=ev,
        session_id="sf_pr52",
        with_rollback_preview=True,
    )
    assert res.ok
    assert res.payload is not None
    pid = res.payload["proposal_id"]
    preview = data_dir / "rollback_previews" / pid / "rollback-preview.json"
    assert preview.exists()


def test_mission_validate_passes_for_fresh_mission(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    r = runner.invoke(app, ["mission", "restart", "validate", res.mission_id])
    assert r.exit_code == 0, r.output
    assert "validation passed" in r.output


def test_mission_validate_fails_on_arbitrary_command_execution(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    p = mission_json_path(data_dir, res.mission_id)
    payload = json.loads(p.read_text())
    payload["safety"]["arbitrary_command_execution"] = True
    p.write_text(json.dumps(payload), encoding="utf-8")
    r = runner.invoke(app, ["mission", "restart", "validate", res.mission_id])
    assert r.exit_code == 1
    assert "arbitrary_command_execution must be false" in r.output


def test_mission_validate_fails_on_unsafe_next_command(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    p = mission_json_path(data_dir, res.mission_id)
    payload = json.loads(p.read_text())
    payload["next_commands"].append("docker restart sfai-pr52-target && rm -rf /")
    p.write_text(json.dumps(payload), encoding="utf-8")
    ok, errors, _ = validate_mission_path(p)
    assert not ok
    assert any("unsafe shell chain" in e for e in errors)


def test_mission_validate_fails_on_invalid_phase_status(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    p = mission_json_path(data_dir, res.mission_id)
    payload = json.loads(p.read_text())
    payload["phases"]["evidence"]["status"] = "weird"
    p.write_text(json.dumps(payload), encoding="utf-8")
    r = runner.invoke(app, ["mission", "restart", "validate", res.mission_id])
    assert r.exit_code == 1
    assert "invalid status" in r.output


def test_mission_validate_fails_on_unsafe_command_preview(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    p = mission_json_path(data_dir, res.mission_id)
    payload = json.loads(p.read_text())
    payload["command_preview"] = "docker restart sfai-pr52-target && echo bad"
    p.write_text(json.dumps(payload), encoding="utf-8")
    r = runner.invoke(app, ["mission", "restart", "validate", res.mission_id])
    assert r.exit_code == 1


def test_mission_validate_fails_on_malformed_json(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    p = mission_json_path(data_dir, res.mission_id)
    p.write_text("{not json", encoding="utf-8")
    r = runner.invoke(app, ["mission", "restart", "validate", res.mission_id])
    assert r.exit_code == 1
    assert "malformed" in r.output.lower() or "failed" in r.output.lower()


def test_mission_status_json_strict(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    r = runner.invoke(app, ["mission", "restart", "status", res.mission_id, "--json"])
    assert r.exit_code == 0
    json.loads(r.output)


def test_mission_audit_event_recorded(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    runner.invoke(
        app,
        [
            "mission",
            "restart",
            "prepare",
            "--container",
            "sfai-pr52-target",
            "--from-evidence",
            str(ev),
        ],
    )
    events_path = data_dir / "audit" / "events.jsonl"
    assert events_path.exists()
    rows = [json.loads(line) for line in events_path.read_text().splitlines() if line.strip()]
    kinds = [r["kind"] for r in rows]
    assert "restart_mission" in kinds
    mission_event = next(r for r in rows if r["kind"] == "restart_mission")
    assert mission_event["safety"]["execution_allowed"] is False
    assert mission_event["safety"]["mutation_performed"] is False


def test_mission_export_bundles_files(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    r = runner.invoke(app, ["mission", "restart", "export", res.mission_id])
    assert r.exit_code == 0, r.output
    out_dir = data_dir / "mission_exports" / res.mission_id
    assert (out_dir / "mission.json").exists()
    assert (out_dir / "mission.md").exists()
    assert (out_dir / "manifest.json").exists()


def test_ask_prepare_safe_restart_mission(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    sess_dir = ev.parent
    # Place evidence in a discoverable artifact session dir.
    artifacts_dir = data_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    # ev is already under artifacts/sf_pr52/evidence.json
    assert sess_dir.parent.name == "artifacts"
    r = runner.invoke(
        app,
        ["ask", "prepare safe restart mission for sfai-pr52-target"],
    )
    assert r.exit_code == 0, r.output
    assert "Restart mission prepared" in r.output or "Restart mission deduped" in r.output


def test_ask_show_restart_mission_checklist(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    res = prepare_mission(
        data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52"
    )
    _ = res
    r = runner.invoke(app, ["ask", "show restart mission checklist"])
    assert r.exit_code == 0
    assert "Safe restart mission" in r.output


def test_ask_restart_it_now_refuses(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch)
    prepare_mission(data_dir, container="sfai-pr52-target", evidence_path=ev, session_id="sf_pr52")
    r = runner.invoke(app, ["ask", "run the restart mission"])
    assert r.exit_code == 0
    assert "Refusing" in r.output
    assert "apply" in r.output
    # Ensure no mutation receipt was created.
    receipts = data_dir / "execution_receipts"
    assert not receipts.exists() or not list(receipts.glob("*.json"))


def test_known_phase_statuses_constants():
    assert "evidence" in KNOWN_PHASE_STATUSES
    assert "execution" in KNOWN_PHASE_STATUSES
