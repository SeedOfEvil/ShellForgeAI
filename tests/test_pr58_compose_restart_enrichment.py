"""PR58: Compose-aware restart proposal and mission enrichment tests.

Fixture-based. tmp_path is the data dir. No live Docker, no root, no journal,
no internet. PR58 is metadata enrichment only — no new mutation path, no
docker compose execution.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core import lab_restart as lab_restart_mod
from shellforgeai.core.approvals import (
    approve_proposal,
    build_restart_proposal_from_evidence,
    find_proposal_path,
    load_proposal_from_path,
)
from shellforgeai.core.ask_routing import (
    has_compose_artifact_reference_phrase,
    is_compose_service_mutation_proposal_request,
    is_mission_compose_context_query,
    is_restart_proposal_compose_context_query,
)
from shellforgeai.core.compose_context import compose_context_from_row
from shellforgeai.core.lab_restart import (
    ENV_ALLOW_LAB_RESTART,
    ENV_MUTATION_MODE,
    FakeCommandExecutor,
    write_default_allowlist,
)
from shellforgeai.core.mission import prepare_mission
from shellforgeai.core.mission_report import build_mission_report
from shellforgeai.core.rollback_preview import write_preview

runner = CliRunner()

CONTAINER = "sfai-pr58-target"

COMPOSE_LABELS = {
    "com.docker.compose.project": "shellforgeai",
    "com.docker.compose.service": "shellforgeai",
    "com.docker.compose.container-number": "1",
    "com.docker.compose.project.working_dir": "/srv/compose/shellforgeai",
    "com.docker.compose.project.config_files": "/srv/compose/shellforgeai/compose.yml",
    "com.docker.compose.version": "2.40.3",
    "com.docker.compose.oneoff": "false",
    "com.docker.compose.config-hash": "abc123",
    "shellforgeai.allow_restart": "true",
}


def _write_evidence(
    dst: Path,
    *,
    name: str = CONTAINER,
    compose: bool = True,
) -> Path:
    labels = dict(COMPOSE_LABELS) if compose else {"shellforgeai.allow_restart": "true"}
    payload = {
        "session_id": "sf_pr58",
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


def _setup(
    tmp_path: Path,
    monkeypatch,
    *,
    compose: bool = True,
    name: str = CONTAINER,
) -> tuple[Path, Path]:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    sess = tmp_path / "artifacts" / "sf_pr58"
    sess.mkdir(parents=True, exist_ok=True)
    ev = _write_evidence(sess, name=name, compose=compose)
    return tmp_path, ev


# ---------------------------------------------------------------------------
# Helper unit


def test_compose_context_from_row_detected_from_labels() -> None:
    row = {"labels": COMPOSE_LABELS}
    cc = compose_context_from_row(row)
    assert cc["detected"] is True
    assert cc["project"] == "shellforgeai"
    assert cc["service"] == "shellforgeai"
    assert cc["working_dir"] == "/srv/compose/shellforgeai"
    assert cc["config_files"] == ["/srv/compose/shellforgeai/compose.yml"]
    assert cc["source"] == "docker_labels"


def test_compose_context_from_row_uses_preparsed() -> None:
    row = {
        "compose": {
            "detected": True,
            "project": "preparsed",
            "service": "preparsed",
        }
    }
    cc = compose_context_from_row(row)
    assert cc["project"] == "preparsed"
    assert cc["source"] == "docker_labels"


def test_compose_context_from_row_missing() -> None:
    cc = compose_context_from_row({"labels": {}})
    assert cc["detected"] is False
    assert cc["reason"] == "compose labels not present"


# ---------------------------------------------------------------------------
# Proposal enrichment


def test_restart_proposal_includes_compose_context(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    proposal, status = build_restart_proposal_from_evidence(
        data_dir, ev, container_name=CONTAINER, source_session_id="sf_pr58"
    )
    assert status == "created"
    assert proposal is not None
    cc = proposal.compose_context
    assert cc["detected"] is True
    assert cc["project"] == "shellforgeai"
    assert cc["service"] == "shellforgeai"
    assert cc["working_dir"] == "/srv/compose/shellforgeai"
    assert "/srv/compose/shellforgeai/compose.yml" in cc["config_files"]
    assert cc["source"] == "docker_labels"
    assert proposal.restart_scope == "container"
    assert proposal.compose_mutation is False
    # Command preview remains the exact container restart.
    assert proposal.proposed_steps == [f"docker restart {CONTAINER}"]


def test_restart_proposal_without_compose_labels(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=False)
    proposal, status = build_restart_proposal_from_evidence(data_dir, ev, container_name=CONTAINER)
    assert status == "created"
    assert proposal is not None
    cc = proposal.compose_context
    assert cc["detected"] is False
    assert cc["reason"] == "compose labels not present"
    assert proposal.restart_scope == "container"
    assert proposal.compose_mutation is False


def test_approvals_show_displays_compose_context(tmp_path: Path, monkeypatch):
    _setup(tmp_path, monkeypatch, compose=True)
    result = runner.invoke(
        app,
        [
            "approvals",
            "propose-restart",
            CONTAINER,
            "--from-evidence",
            str(tmp_path / "artifacts" / "sf_pr58" / "evidence.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    pending = next((tmp_path / "approvals" / "pending").glob("*.proposal.json"))
    pid = pending.stem.replace(".proposal", "")
    r = runner.invoke(app, ["approvals", "show", pid])
    assert r.exit_code == 0, r.output
    assert "Compose context:" in r.output
    assert "Compose-managed: yes" in r.output
    assert "Project: shellforgeai" in r.output
    assert "Service: shellforgeai" in r.output
    assert "/srv/compose/shellforgeai/compose.yml" in r.output
    assert "restart_scope: container" in r.output
    assert "compose_mutation: False" in r.output
    assert f"Command preview remains: docker restart {CONTAINER}" in r.output


def test_approvals_show_non_compose_target(tmp_path: Path, monkeypatch):
    _setup(tmp_path, monkeypatch, compose=False)
    result = runner.invoke(
        app,
        [
            "approvals",
            "propose-restart",
            CONTAINER,
            "--from-evidence",
            str(tmp_path / "artifacts" / "sf_pr58" / "evidence.json"),
        ],
    )
    assert result.exit_code == 0
    pending = next((tmp_path / "approvals" / "pending").glob("*.proposal.json"))
    pid = pending.stem.replace(".proposal", "")
    r = runner.invoke(app, ["approvals", "show", pid])
    assert r.exit_code == 0
    assert "Compose-managed: no" in r.output


# ---------------------------------------------------------------------------
# Restart-plan


def _make_proposal(tmp_path: Path, monkeypatch, *, compose: bool = True) -> str:
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=compose)
    r = runner.invoke(app, ["approvals", "propose-restart", CONTAINER, "--from-evidence", str(ev)])
    assert r.exit_code == 0, r.output
    pending = next((data_dir / "approvals" / "pending").glob("*.proposal.json"))
    return pending.stem.replace(".proposal", "")


def test_restart_plan_human_includes_compose_context(tmp_path: Path, monkeypatch):
    pid = _make_proposal(tmp_path, monkeypatch, compose=True)
    r = runner.invoke(app, ["approvals", "restart-plan", pid])
    assert r.exit_code == 0, r.output
    assert "Compose context:" in r.output
    assert "Compose-managed: yes" in r.output
    assert "Project: shellforgeai" in r.output
    assert "Service: shellforgeai" in r.output
    assert "Scope warning:" in r.output
    assert "container, not the Compose service" in r.output
    assert "No docker compose command will be executed" in r.output


def test_restart_plan_json_includes_compose_context_and_scope(tmp_path: Path, monkeypatch):
    pid = _make_proposal(tmp_path, monkeypatch, compose=True)
    r = runner.invoke(app, ["approvals", "restart-plan", pid, "--json"])
    assert r.exit_code == 0, r.output
    payload = json.loads(r.output)
    assert payload["compose_context"]["detected"] is True
    assert payload["compose_context"]["project"] == "shellforgeai"
    assert payload["compose_context"]["service"] == "shellforgeai"
    assert payload["restart_scope"] == "container"
    assert payload["compose_mutation"] is False
    assert payload["safety"]["compose_mutation"] is False


def test_restart_plan_readiness_ready_with_compose_context(tmp_path: Path, monkeypatch):
    pid = _make_proposal(tmp_path, monkeypatch, compose=True)
    proposal = approve_proposal(tmp_path, pid, reason="ok")
    write_preview(tmp_path, proposal)
    r = runner.invoke(app, ["approvals", "restart-plan", pid, "--json"])
    assert r.exit_code == 0
    payload = json.loads(r.output)
    assert payload["apply_readiness"]["status"] == "ready"
    assert payload["compose_context"]["detected"] is True
    assert payload["compose_mutation"] is False
    assert payload["restart_scope"] == "container"


def test_restart_plan_blocks_when_command_preview_uses_docker_compose(tmp_path: Path, monkeypatch):
    pid = _make_proposal(tmp_path, monkeypatch, compose=True)
    path, _ = find_proposal_path(tmp_path, pid)
    assert path is not None
    proposal = load_proposal_from_path(path)
    proposal.proposed_steps = [f"docker compose restart {CONTAINER}"]
    path.write_text(proposal.model_dump_json(indent=2), encoding="utf-8")
    r = runner.invoke(app, ["approvals", "restart-plan", pid, "--json"])
    assert r.exit_code == 0
    payload = json.loads(r.output)
    assert payload["apply_readiness"]["status"] == "blocked"
    assert any(
        "docker compose command preview" in b for b in payload["apply_readiness"]["blockers"]
    )


# ---------------------------------------------------------------------------
# Mission


def test_mission_prepare_carries_compose_context(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    res = prepare_mission(data_dir, container=CONTAINER, evidence_path=ev, session_id="sf_pr58")
    assert res.ok
    assert res.payload is not None
    cc = res.payload["compose_context"]
    assert cc["detected"] is True
    assert cc["project"] == "shellforgeai"
    assert cc["service"] == "shellforgeai"
    assert res.payload["restart_scope"] == "container"
    assert res.payload["compose_mutation"] is False
    assert res.payload["safety"]["compose_mutation"] is False


def test_mission_status_json_includes_compose_context(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    res = prepare_mission(data_dir, container=CONTAINER, evidence_path=ev, session_id="sf_pr58")
    assert res.ok
    r = runner.invoke(app, ["mission", "restart", "status", res.mission_id, "--json"])
    assert r.exit_code == 0
    payload = json.loads(r.output)
    assert payload["compose_context"]["detected"] is True
    assert payload["restart_scope"] == "container"
    assert payload["compose_mutation"] is False


def test_mission_checklist_displays_compose_context(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    res = prepare_mission(data_dir, container=CONTAINER, evidence_path=ev, session_id="sf_pr58")
    r = runner.invoke(app, ["mission", "restart", "checklist", res.mission_id])
    assert r.exit_code == 0, r.output
    assert "Compose context:" in r.output
    assert "Project: shellforgeai" in r.output
    assert "Service: shellforgeai" in r.output
    assert "Restart scope: container" in r.output
    assert "Compose service mutation is not enabled" in r.output


def test_mission_validate_still_passes_with_compose_context(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    res = prepare_mission(data_dir, container=CONTAINER, evidence_path=ev, session_id="sf_pr58")
    r = runner.invoke(app, ["mission", "restart", "validate", res.mission_id])
    assert r.exit_code == 0, r.output
    assert "validation passed" in r.output.lower()


# ---------------------------------------------------------------------------
# Apply gate receipt + mission report


def _enable_mutation_env(monkeypatch) -> None:
    monkeypatch.setenv(ENV_MUTATION_MODE, "lab")
    monkeypatch.setenv(ENV_ALLOW_LAB_RESTART, "1")


def _patch_fake_executor(monkeypatch, fake: FakeCommandExecutor) -> FakeCommandExecutor:
    monkeypatch.setattr(cli_mod, "_lab_restart_executor_factory", lambda: fake)
    before_payload = lab_restart_mod.make_inspect_payload(
        started_at="2026-05-14T12:00:00.000000000Z"
    )
    after_payload = lab_restart_mod.make_inspect_payload(
        started_at="2026-05-14T12:00:05.000000000Z"
    )
    fake_inspector = lab_restart_mod.FakeContainerInspector(
        results=[
            lab_restart_mod.InspectResult(ok=True, exists=True, raw=before_payload),
            lab_restart_mod.InspectResult(ok=True, exists=True, raw=after_payload),
        ]
    )
    monkeypatch.setattr(cli_mod, "_lab_restart_inspector_factory", lambda: fake_inspector)
    monkeypatch.setattr(
        cli_mod,
        "_lab_restart_verification_config",
        lambda: lab_restart_mod.VerificationConfig(
            post_restart_wait_seconds=0,
            health_wait_seconds=0,
            health_poll_interval_seconds=0,
        ),
    )
    monkeypatch.setattr(cli_mod, "_lab_restart_verification_sleep", lambda _s: None)
    return fake


def _execute_mission(tmp_path: Path, monkeypatch) -> tuple[Path, str, str]:
    _enable_mutation_env(monkeypatch)
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    write_default_allowlist(data_dir, containers=[CONTAINER], enabled=True)
    res = prepare_mission(data_dir, container=CONTAINER, evidence_path=ev, session_id="sf_pr58")
    assert res.ok
    assert res.payload is not None
    pid = res.payload["proposal_id"]
    proposal = approve_proposal(data_dir, pid, reason="ok")
    write_preview(data_dir, proposal)
    _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    r = runner.invoke(
        app, ["mission", "restart", "execute", res.mission_id, "--execute", "--confirm"]
    )
    assert r.exit_code == 0, r.output
    return data_dir, res.mission_id, pid


def test_apply_receipt_records_compose_context(tmp_path: Path, monkeypatch):
    data_dir, _mid, _pid = _execute_mission(tmp_path, monkeypatch)
    receipts = list((data_dir / "execution_receipts").glob("exec_*.json"))
    assert receipts
    payload = json.loads(receipts[-1].read_text())
    cc = payload.get("compose_context") or {}
    assert cc.get("detected") is True
    assert cc.get("project") == "shellforgeai"
    assert cc.get("service") == "shellforgeai"
    assert payload["safety"]["compose_mutation"] is False
    assert payload["safety"]["restart_scope"] == "container"
    # Exact container restart argv preserved.
    assert payload["command_argv"] == ["docker", "restart", CONTAINER]


def test_mission_report_includes_compose_context(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    report = build_mission_report(data_dir, mid)
    cc = report.get("compose_context") or {}
    assert cc.get("detected") is True
    assert cc.get("project") == "shellforgeai"
    assert report["restart_scope"] == "container"
    assert report["compose_mutation"] is False
    assert report["safety"]["compose_mutation"] is False


def test_mission_report_md_renders_compose_context_and_safety(tmp_path: Path, monkeypatch):
    data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "report", mid])
    assert r.exit_code == 0, r.output
    md_path = data_dir / "mission_reports" / mid / "mission-report.md"
    assert md_path.exists()
    body = md_path.read_text()
    assert "Compose context" in body
    assert "Compose-managed: yes" in body
    assert "Compose context was advisory/read-only" in body
    assert "No docker compose command was executed" in body
    assert "Restart was exact-container scoped" in body


def test_validate_executed_mission_still_passes(tmp_path: Path, monkeypatch):
    _data_dir, mid, _pid = _execute_mission(tmp_path, monkeypatch)
    r = runner.invoke(app, ["mission", "restart", "validate", mid])
    assert r.exit_code == 0, r.output


# ---------------------------------------------------------------------------
# Refusal of compose service mutation


def test_compose_service_mutation_detector() -> None:
    assert is_compose_service_mutation_proposal_request(
        "propose restart for compose service shellforgeai"
    )
    assert is_compose_service_mutation_proposal_request(
        "create compose restart proposal for shellforgeai"
    )
    assert is_compose_service_mutation_proposal_request("docker compose restart shellforgeai")
    assert is_compose_service_mutation_proposal_request("compose up shellforgeai")
    assert is_compose_service_mutation_proposal_request("recreate compose service shellforgeai")
    assert not is_compose_service_mutation_proposal_request("compose context for shellforgeai")


def test_ask_propose_restart_for_compose_service_refuses(tmp_path: Path, monkeypatch):
    _setup(tmp_path, monkeypatch, compose=True)
    r = runner.invoke(app, ["ask", "propose restart for compose service shellforgeai"])
    assert r.exit_code == 0
    assert ("Restart proposal refused" in r.output) or (
        "Refusing natural-language Compose mutation" in r.output
    )
    assert "compose inspect" in r.output
    assert not (tmp_path / "approvals").exists() or not list(
        (tmp_path / "approvals" / "pending").glob("*.proposal.json")
    )


def test_ask_docker_compose_restart_refuses(tmp_path: Path, monkeypatch):
    _setup(tmp_path, monkeypatch, compose=True)
    r = runner.invoke(app, ["ask", "docker compose restart shellforgeai"])
    assert r.exit_code == 0
    assert "Refusing natural-language Compose mutation" in r.output
    assert "compose inspect" in r.output
    receipts = tmp_path / "execution_receipts"
    assert not receipts.exists() or not list(receipts.glob("*.json"))


def test_ask_compose_up_refuses(tmp_path: Path, monkeypatch):
    _setup(tmp_path, monkeypatch, compose=True)
    r = runner.invoke(app, ["ask", "compose up shellforgeai"])
    assert r.exit_code == 0
    assert "Refusing natural-language Compose mutation" in r.output


def test_ask_create_compose_restart_proposal_refuses(tmp_path: Path, monkeypatch):
    _setup(tmp_path, monkeypatch, compose=True)
    r = runner.invoke(app, ["ask", "create compose restart proposal for shellforgeai"])
    assert r.exit_code == 0
    assert "Refusing natural-language Compose mutation" in r.output
    assert not (tmp_path / "approvals").exists() or not list(
        (tmp_path / "approvals" / "pending").glob("*.proposal.json")
    )


def test_ask_restart_compose_service_now_refuses(tmp_path: Path, monkeypatch):
    _setup(tmp_path, monkeypatch, compose=True)
    r = runner.invoke(app, ["ask", "restart the compose service now"])
    assert r.exit_code == 0
    assert "Refusing natural-language Compose mutation" in r.output


# ---------------------------------------------------------------------------
# Read-only compose context asks on proposal / mission


def test_query_detectors() -> None:
    assert is_restart_proposal_compose_context_query(
        "show compose context for this restart proposal"
    )
    assert is_restart_proposal_compose_context_query("is this restart proposal compose-managed")
    assert is_mission_compose_context_query("is this mission targeting a compose service")
    assert is_mission_compose_context_query("show compose context for this restart mission")
    assert is_mission_compose_context_query("show compose context for latest restart mission")
    assert not is_mission_compose_context_query("show compose context for shellforgeai")
    assert has_compose_artifact_reference_phrase("show compose context for this restart mission")
    assert has_compose_artifact_reference_phrase("show compose context for this restart proposal")
    assert not has_compose_artifact_reference_phrase("compose context for shellforgeai")


def test_ask_show_compose_context_for_restart_proposal(tmp_path: Path, monkeypatch):
    pid = _make_proposal(tmp_path, monkeypatch, compose=True)
    approve_proposal(tmp_path, pid, reason="ok")
    r = runner.invoke(app, ["ask", "show compose context for this restart proposal"])
    assert r.exit_code == 0, r.output
    assert f"Restart proposal compose context ({pid})" in r.output
    assert "Compose-managed: yes" in r.output
    assert "restart_scope: container" in r.output
    assert "compose_mutation: False" in r.output


def test_ask_mission_compose_context(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    res = prepare_mission(data_dir, container=CONTAINER, evidence_path=ev, session_id="sf_pr58")
    assert res.ok
    r = runner.invoke(app, ["ask", "is this mission targeting a compose service?"])
    assert r.exit_code == 0, r.output
    assert "Mission compose context" in r.output
    assert "restart_scope: container" in r.output
    assert "compose_mutation: False" in r.output
    assert "Compose service mutation is not enabled" in r.output


def test_ask_show_compose_context_for_this_restart_mission(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    res = prepare_mission(data_dir, container=CONTAINER, evidence_path=ev, session_id="sf_pr59")
    assert res.ok
    r = runner.invoke(app, ["ask", "show compose context for this restart mission"])
    assert r.exit_code == 0, r.output
    assert "Mission compose context" in r.output
    assert str((res.payload or {}).get("mission_id")) in r.output


def test_ask_show_compose_context_for_latest_restart_mission(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    res = prepare_mission(data_dir, container=CONTAINER, evidence_path=ev, session_id="sf_pr59")
    assert res.ok
    r = runner.invoke(app, ["ask", "show compose context for latest restart mission"])
    assert r.exit_code == 0, r.output
    assert "Mission compose context" in r.output
    assert str((res.payload or {}).get("mission_id")) in r.output


def test_ask_compose_context_no_mutation_executed(tmp_path: Path, monkeypatch):
    data_dir, ev = _setup(tmp_path, monkeypatch, compose=True)
    res = prepare_mission(data_dir, container=CONTAINER, evidence_path=ev, session_id="sf_pr58")
    assert res.ok
    runner.invoke(app, ["ask", "is this mission targeting a compose service?"])
    receipts = data_dir / "execution_receipts"
    assert not receipts.exists() or not list(receipts.glob("*.json"))


def test_ask_compose_context_prefers_fresh_proposal_over_old_long_lived(
    tmp_path: Path, monkeypatch
):
    pid_new = _make_proposal(tmp_path, monkeypatch, compose=True)
    approve_proposal(tmp_path, pid_new, reason="ok")
    old_dir = tmp_path / "approvals" / "approved"
    old_dir.mkdir(parents=True, exist_ok=True)
    old_src = json.loads((old_dir / f"{pid_new}.proposal.json").read_text(encoding="utf-8"))
    old_src["proposal_id"] = "prop_pr58_old"
    old_src["created_at"] = "2020-01-01T00:00:00+00:00"
    old_path = old_dir / "prop_pr58_old.proposal.json"
    old_path.write_text(json.dumps(old_src), encoding="utf-8")
    r = runner.invoke(app, ["ask", "show compose context for this restart proposal"])
    assert r.exit_code == 0, r.output
    assert f"Restart proposal compose context ({pid_new})" in r.output
