"""PR47: first non-metadata mutation gate — lab-allowlisted Docker container restart.

Tests are deterministic and self-contained. They use ``tmp_path`` as the data
dir, mock the executor, and never touch live Docker, root, journalctl,
systemd, or the network.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.cli import app
from shellforgeai.core import lab_restart as lab_restart_mod
from shellforgeai.core.actions import classify_step
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
from shellforgeai.core.lab_restart import (
    ENV_ALLOW_LAB_RESTART,
    ENV_MUTATION_MODE,
    MUTATION_SCOPE,
    Allowlist,
    ExecResult,
    FakeCommandExecutor,
    SubprocessExecutor,
    evaluate_gates,
    find_restart_candidates,
    is_safe_container_name,
    is_valid_restart_argv,
    load_allowlist,
    parse_restart_command,
    policy_path,
    write_default_allowlist,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures


def _enable_mutation_env(monkeypatch) -> None:
    monkeypatch.setenv(ENV_MUTATION_MODE, "lab")
    monkeypatch.setenv(ENV_ALLOW_LAB_RESTART, "1")


def _disable_mutation_env(monkeypatch) -> None:
    monkeypatch.delenv(ENV_MUTATION_MODE, raising=False)
    monkeypatch.delenv(ENV_ALLOW_LAB_RESTART, raising=False)


def _mk_restart_proposal(
    *,
    proposal_id: str = "prop_lab_restart_001",
    container: str = "sfai-healthy-web",
    status: str = STATUS_APPROVED,
    extra_steps: list[str] | None = None,
) -> Proposal:
    steps = [
        f"OPERATOR-RUN: docker restart {container}   # SERVICE-IMPACTING",
    ]
    if extra_steps:
        steps.extend(extra_steps)
    rollback = [f"docker logs --tail 50 {container}"]
    verification = [f"docker inspect {container}"]
    fp = compute_proposal_fingerprint_payload(
        session_id="sf_test_pr47",
        option_id="opt_pr47_001",
        component=container,
        kind="container_restart",
        title=f"Restart {container} after config change",
        risk="medium",
        steps=steps,
        rollback=rollback,
        verification=verification,
    )
    return Proposal(
        proposal_id=proposal_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        status=status,
        source=ProposalSource(session_id="sf_test_pr47"),
        target="docker",
        component=container,
        kind="container_restart",
        title=f"Restart {container} after config change",
        risk="medium",
        confidence="medium",
        impact=f"Recreates {container} container after lab config change.",
        safety_labels=["OPERATOR-RUN", "REQUIRES APPROVAL", "SERVICE-IMPACTING"],
        preconditions=["Lab container is healthy enough to restart."],
        proposed_steps=steps,
        rollback=rollback,
        verification=verification,
        notes="",
        execution=ProposalExecution(allowed=False, status="not_executed"),
        fingerprint=fp,
        approval=ProposalApproval(
            reason="lab restart approved for test",
            approved_at="2026-05-14T00:00:01+00:00",
            approved_by="op",
        )
        if status == STATUS_APPROVED
        else ProposalApproval(),
    )


def _seed_proposal(data_dir: Path, proposal: Proposal) -> Path:
    return write_proposal(data_dir, proposal)


def _seed_allowlist(
    data_dir: Path,
    *,
    enabled: bool = True,
    containers: list[str] | None = None,
) -> Path:
    return write_default_allowlist(
        data_dir,
        containers=containers if containers is not None else ["sfai-healthy-web"],
        enabled=enabled,
    )


def _patch_fake_executor(monkeypatch, fake: FakeCommandExecutor) -> FakeCommandExecutor:
    from shellforgeai import cli as cli_mod

    monkeypatch.setattr(cli_mod, "_lab_restart_executor_factory", lambda: fake)
    return fake


def _read_events(tmp_path: Path) -> list[dict]:
    return AuditStorage(tmp_path).read_events()


# ---------------------------------------------------------------------------
# Pure-function tests (allowlist, executor argv validation, parser)


def test_is_safe_container_name_accepts_normal_names():
    assert is_safe_container_name("sfai-healthy-web")
    assert is_safe_container_name("a")
    assert is_safe_container_name("A1.b_c-d")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "-bad",
        ".bad",
        "bad name",
        "bad;rm -rf /",
        "bad|name",
        "bad&name",
        "$evil",
        "`whoami`",
        "name'quote",
        'name"quote',
        "name/slash",
        "name\\back",
        "../escape",
        "name\nnewline",
        "*wild",
        "name;",
    ],
)
def test_is_safe_container_name_rejects_unsafe(bad: str) -> None:
    assert not is_safe_container_name(bad)


def test_parse_restart_command_only_accepts_canonical_form():
    assert parse_restart_command("docker restart sfai-healthy-web") == "sfai-healthy-web"
    assert parse_restart_command("  docker   restart   sfai-healthy-web  ") == "sfai-healthy-web"
    assert parse_restart_command("docker compose restart sfai-healthy-web") is None
    assert parse_restart_command("docker stop sfai-healthy-web") is None
    assert parse_restart_command("docker restart -f sfai-healthy-web") is None
    assert parse_restart_command("docker restart sfai-healthy-web; rm -rf /") is None
    assert parse_restart_command("docker restart 'sfai-healthy-web'") is None


def test_is_valid_restart_argv():
    ok, _ = is_valid_restart_argv(["docker", "restart", "sfai-healthy-web"])
    assert ok
    bad_cases = [
        [],
        ["docker", "restart"],
        ["docker", "restart", "sfai-healthy-web", "extra"],
        ["docker", "stop", "sfai-healthy-web"],
        ["bash", "-c", "docker restart sfai-healthy-web"],
        ["docker", "restart", "; rm -rf /"],
        ["docker", "restart", ""],
    ]
    for argv in bad_cases:
        ok, reason = is_valid_restart_argv(argv)
        assert not ok, f"expected refusal for {argv!r}"
        assert reason


def test_load_allowlist_missing_returns_none(tmp_path: Path):
    assert load_allowlist(tmp_path) is None


def test_load_allowlist_round_trip(tmp_path: Path):
    write_default_allowlist(
        tmp_path, containers=["sfai-healthy-web", "sfai-restart-loop"], enabled=True
    )
    al = load_allowlist(tmp_path)
    assert isinstance(al, Allowlist)
    assert al.enabled is True
    assert "sfai-healthy-web" in al.containers
    assert "sfai-restart-loop" in al.containers


def test_load_allowlist_disabled_default(tmp_path: Path):
    write_default_allowlist(tmp_path, containers=["sfai-healthy-web"], enabled=False)
    al = load_allowlist(tmp_path)
    assert al is not None and al.enabled is False


def test_load_allowlist_strips_unsafe_names(tmp_path: Path):
    p = policy_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "enabled": True,
                "allowed_containers": ["sfai-healthy-web", "bad;name", "", None, 5],
            }
        ),
        encoding="utf-8",
    )
    al = load_allowlist(tmp_path)
    assert al is not None
    assert al.containers == ("sfai-healthy-web",)


def test_load_allowlist_malformed_disables(tmp_path: Path):
    p = policy_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{this is not json", encoding="utf-8")
    al = load_allowlist(tmp_path)
    assert al is not None
    assert al.enabled is False
    assert al.containers == ()


def test_mutation_mode_requires_both_envs(monkeypatch):
    monkeypatch.delenv(ENV_MUTATION_MODE, raising=False)
    monkeypatch.delenv(ENV_ALLOW_LAB_RESTART, raising=False)
    assert lab_restart_mod.mutation_mode_enabled() is False
    monkeypatch.setenv(ENV_MUTATION_MODE, "lab")
    assert lab_restart_mod.mutation_mode_enabled() is False
    monkeypatch.setenv(ENV_ALLOW_LAB_RESTART, "1")
    assert lab_restart_mod.mutation_mode_enabled() is True
    monkeypatch.setenv(ENV_MUTATION_MODE, "prod")
    assert lab_restart_mod.mutation_mode_enabled() is False


# ---------------------------------------------------------------------------
# Action classification: docker restart still classifies as service-impacting


def test_action_compiler_classifies_docker_restart_as_blocked_service_impacting():
    cls = classify_step("docker restart sfai-healthy-web")
    assert cls.kind == "docker"
    assert cls.operation == "restart"
    assert cls.decision == "blocked"
    assert "SERVICE-IMPACTING" in cls.safety_labels


def test_action_compiler_actions_json_still_execution_allowed_false(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    proposal = _mk_restart_proposal()
    _seed_proposal(tmp_path, proposal)
    r = runner.invoke(app, ["actions", "compile", proposal.proposal_id])
    assert r.exit_code == 0, r.stdout
    actions_path = tmp_path / "actions" / proposal.proposal_id / "actions.json"
    payload = json.loads(actions_path.read_text())
    assert payload["execution_allowed"] is False
    assert payload["execution_status"] == "not_executed"
    for action in payload["actions"]:
        assert action["execution_allowed"] is False


def test_find_restart_candidates_picks_docker_restart_only():
    payload = {
        "actions": [
            {"action_id": "act_001", "normalized_text": "docker logs sfai-healthy-web"},
            {"action_id": "act_002", "normalized_text": "docker restart sfai-healthy-web"},
            {"action_id": "act_003", "normalized_text": "docker compose up -d sfai-healthy-web"},
        ]
    }
    out = find_restart_candidates(payload)
    assert [c.action_id for c in out] == ["act_002"]
    assert out[0].container == "sfai-healthy-web"
    assert out[0].command_argv == ("docker", "restart", "sfai-healthy-web")


# ---------------------------------------------------------------------------
# CLI gate matrix


def _seed_for_apply(
    tmp_path: Path,
    *,
    container: str = "sfai-healthy-web",
    status: str = STATUS_APPROVED,
    allowlist_containers: list[str] | None = None,
    allowlist_enabled: bool = True,
    proposal_id: str = "prop_lab_restart_001",
    extra_steps: list[str] | None = None,
) -> Proposal:
    proposal = _mk_restart_proposal(
        proposal_id=proposal_id, container=container, status=status, extra_steps=extra_steps
    )
    _seed_proposal(tmp_path, proposal)
    _seed_allowlist(
        tmp_path,
        enabled=allowlist_enabled,
        containers=allowlist_containers if allowlist_containers is not None else [container],
    )
    return proposal


def test_apply_without_execute_runs_dry_run_only(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _disable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id])
    assert r.exit_code == 0, r.stdout
    assert "Apply preflight passed" in r.stdout
    assert fake.calls == []
    # No execution receipt and no execution audit event.
    receipts = list((tmp_path / "execution_receipts").glob("exec_*.json"))
    assert receipts == []
    events = _read_events(tmp_path)
    assert not any(e["kind"] == "execution" for e in events)


def test_apply_execute_without_confirm_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute"])
    assert r.exit_code == 1
    assert "Execution refused" in r.stdout
    assert "confirm_flag_missing" in r.stdout
    assert fake.calls == []
    events = _read_events(tmp_path)
    refused = [
        e
        for e in events
        if e["kind"] == "execution"
        and e["status"] == "refused"
        and e["details"].get("failed_gate") == "confirm_flag_missing"
    ]
    assert refused, events


def test_apply_confirm_without_execute_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--confirm"])
    assert r.exit_code == 1
    assert "execute_flag_missing" in r.stdout
    assert fake.calls == []


def test_apply_mutation_mode_disabled_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _disable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "mutation_mode_disabled" in r.stdout
    assert fake.calls == []


def test_apply_allowlist_missing_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _mk_restart_proposal()
    _seed_proposal(tmp_path, proposal)
    # Note: no allowlist file written.
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "allowlist_missing" in r.stdout
    assert fake.calls == []


def test_apply_allowlist_disabled_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path, allowlist_enabled=False)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "allowlist_disabled" in r.stdout
    assert fake.calls == []


def test_apply_allowlist_empty_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path, allowlist_containers=[])
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "allowlist_empty" in r.stdout
    assert fake.calls == []


def test_apply_container_not_in_allowlist_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(
        tmp_path, container="sfai-healthy-web", allowlist_containers=["something-else"]
    )
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "container_not_allowlisted" in r.stdout
    assert fake.calls == []


def test_apply_pending_proposal_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _mk_restart_proposal(status=STATUS_PENDING)
    _seed_proposal(tmp_path, proposal)
    _seed_allowlist(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    # The bundle preflight refuses pending before the PR47 gate runs.
    assert fake.calls == []


def test_apply_rejected_proposal_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _mk_restart_proposal(status=STATUS_REJECTED)
    _seed_proposal(tmp_path, proposal)
    _seed_allowlist(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert fake.calls == []


def test_apply_no_restart_action_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    # Use docker compose up -d (not allowed) instead of restart.
    proposal = Proposal(
        proposal_id="prop_no_restart_001",
        created_at=datetime.now(timezone.utc).isoformat(),
        status=STATUS_APPROVED,
        source=ProposalSource(session_id="sf_test_pr47"),
        target="docker",
        component="sfai-healthy-web",
        kind="container_recreate",
        title="Recreate sfai-healthy-web",
        risk="medium",
        confidence="medium",
        impact="recreate",
        safety_labels=["OPERATOR-RUN", "REQUIRES APPROVAL", "SERVICE-IMPACTING"],
        preconditions=["x"],
        proposed_steps=[
            "OPERATOR-RUN: docker compose up -d sfai-healthy-web   # SERVICE-IMPACTING"
        ],
        rollback=["docker compose stop sfai-healthy-web"],
        verification=["docker inspect sfai-healthy-web"],
        execution=ProposalExecution(allowed=False, status="not_executed"),
        fingerprint=compute_proposal_fingerprint_payload(
            session_id="sf_test_pr47",
            option_id="opt_no_restart_001",
            component="sfai-healthy-web",
            kind="container_recreate",
            title="Recreate sfai-healthy-web",
            risk="medium",
            steps=["OPERATOR-RUN: docker compose up -d sfai-healthy-web   # SERVICE-IMPACTING"],
            rollback=["docker compose stop sfai-healthy-web"],
            verification=["docker inspect sfai-healthy-web"],
        ),
        approval=ProposalApproval(
            reason="for test", approved_at="2026-05-14T00:00:01+00:00", approved_by="op"
        ),
    )
    _seed_proposal(tmp_path, proposal)
    _seed_allowlist(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "no_restart_action_found" in r.stdout
    assert fake.calls == []


def test_apply_multiple_restart_actions_requires_action_id(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(
        tmp_path,
        extra_steps=[
            "OPERATOR-RUN: docker restart sfai-restart-loop   # SERVICE-IMPACTING",
        ],
        allowlist_containers=["sfai-healthy-web", "sfai-restart-loop"],
    )
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "multiple_restart_actions_require_action_id" in r.stdout
    assert fake.calls == []


def test_apply_action_not_found_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path)
    r = runner.invoke(
        app,
        [
            "apply",
            proposal.proposal_id,
            "--execute",
            "--confirm",
            "--action-id",
            "act_bogus",
        ],
    )
    assert r.exit_code == 1
    assert "action_not_found" in r.stdout
    assert fake.calls == []


def test_apply_action_not_restart_refuses(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(
        tmp_path,
        extra_steps=[
            "OPERATOR-RUN: docker logs --tail 50 sfai-healthy-web",
        ],
    )
    # The verification step "docker inspect ..." is generally classified read_only;
    # we want to point at a non-restart action. Find the logs action id, which the
    # compiler will emit. There are 5 actions: 1 precondition (manual), 1 restart,
    # 1 logs (proposed), 1 rollback, 1 verification. act_002 is the restart.
    r = runner.invoke(
        app,
        [
            "apply",
            proposal.proposal_id,
            "--execute",
            "--confirm",
            "--action-id",
            "act_001",  # precondition, not a restart
        ],
    )
    assert r.exit_code == 1
    assert "action_not_lab_container_restart" in r.stdout
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Success path


def test_apply_execute_confirm_runs_restart_with_fake_executor(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    assert "Guarded lab container restart executed" in r.stdout
    assert "container: sfai-healthy-web" in r.stdout
    assert "command: docker restart sfai-healthy-web" in r.stdout
    assert f"mutation_scope: {MUTATION_SCOPE}" in r.stdout
    assert fake.calls == [["docker", "restart", "sfai-healthy-web"]]
    assert fake.last_timeout == 30

    receipts = list((tmp_path / "execution_receipts").glob("exec_*.json"))
    assert len(receipts) == 1
    payload = json.loads(receipts[0].read_text())
    assert payload["kind"] == "lab_container_restart"
    assert payload["container"] == "sfai-healthy-web"
    assert payload["command_argv"] == ["docker", "restart", "sfai-healthy-web"]
    assert payload["result"]["status"] == "success"
    assert payload["safety"]["scope"] == MUTATION_SCOPE
    assert payload["safety"]["docker_mutation"] is True
    assert payload["safety"]["package_mutation"] is False
    assert payload["safety"]["filesystem_mutation"] is False
    assert payload["safety"]["firewall_mutation"] is False
    assert payload["safety"]["arbitrary_command_execution"] is False

    events = _read_events(tmp_path)
    success = [
        e
        for e in events
        if e["kind"] == "execution"
        and e["action"] == "lab_container_restart"
        and e["status"] == "success"
    ]
    assert success, events
    ev = success[0]
    assert ev["safety"]["mutation_scope"] == MUTATION_SCOPE
    assert ev["safety"]["execution_allowed"] is True
    assert ev["safety"]["execution_status"] == "executed"
    assert ev["safety"]["mutation_performed"] is True
    assert ev["details"]["remediation_execution"] is True
    assert ev["details"]["command_argv"] == ["docker", "restart", "sfai-healthy-web"]
    assert ev["details"]["arbitrary_command_execution"] is False


def test_apply_execute_confirm_failed_executor_returns_nonzero(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(
        monkeypatch,
        FakeCommandExecutor(
            result=ExecResult(ok=False, exit_code=1, stdout="", stderr="container not found")
        ),
    )
    proposal = _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 1
    assert "Guarded lab container restart failed" in r.stdout
    receipts = list((tmp_path / "execution_receipts").glob("exec_*.json"))
    assert len(receipts) == 1
    payload = json.loads(receipts[0].read_text())
    assert payload["result"]["status"] == "failed"
    assert payload["result"]["exit_code"] == 1
    events = _read_events(tmp_path)
    failed = [
        e
        for e in events
        if e["kind"] == "execution"
        and e["action"] == "lab_container_restart"
        and e["status"] == "failed"
    ]
    assert failed
    assert fake.calls == [["docker", "restart", "sfai-healthy-web"]]


def test_apply_with_action_id_selects_specific_restart(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(
        tmp_path,
        extra_steps=[
            "OPERATOR-RUN: docker restart sfai-restart-loop   # SERVICE-IMPACTING",
        ],
        allowlist_containers=["sfai-healthy-web", "sfai-restart-loop"],
    )
    # Compile actions first so we know the assigned action_ids.
    r = runner.invoke(app, ["actions", "compile", proposal.proposal_id])
    assert r.exit_code == 0
    actions_path = tmp_path / "actions" / proposal.proposal_id / "actions.json"
    payload = json.loads(actions_path.read_text())
    restart_ids = [
        a["action_id"]
        for a in payload["actions"]
        if a.get("normalized_text", "").startswith("docker restart")
    ]
    assert len(restart_ids) == 2
    # Select the second one explicitly.
    r = runner.invoke(
        app,
        [
            "apply",
            proposal.proposal_id,
            "--execute",
            "--confirm",
            "--action-id",
            restart_ids[1],
        ],
    )
    assert r.exit_code == 0, r.stdout
    assert fake.calls == [["docker", "restart", "sfai-restart-loop"]]


# ---------------------------------------------------------------------------
# Executor abstraction tests


def test_subprocess_executor_refuses_unsafe_argv():
    ex = SubprocessExecutor()
    res = ex.run(["docker", "restart", "; rm -rf /"], timeout_seconds=5)
    assert not res.ok
    assert res.exit_code == 2
    assert "safe container name" in res.stderr


def test_subprocess_executor_refuses_wrong_verb():
    ex = SubprocessExecutor()
    res = ex.run(["docker", "stop", "sfai-healthy-web"], timeout_seconds=5)
    assert not res.ok
    assert res.exit_code == 2


def test_fake_executor_records_argv_and_timeout():
    fake = FakeCommandExecutor()
    res = fake.run(["docker", "restart", "sfai-healthy-web"], timeout_seconds=42)
    assert res.ok
    assert fake.calls == [["docker", "restart", "sfai-healthy-web"]]
    assert fake.last_timeout == 42


def test_fake_executor_refuses_invalid_argv():
    fake = FakeCommandExecutor()
    res = fake.run(["bash", "-c", "docker restart x"], timeout_seconds=5)
    assert not res.ok


# ---------------------------------------------------------------------------
# Ask must not execute


def test_ask_restart_container_does_not_execute(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["ask", "restart sfai-healthy-web"])
    assert r.exit_code == 0, r.stdout
    assert "Refusing to execute" in r.stdout
    assert "--execute --confirm" in r.stdout
    assert fake.calls == []


def test_ask_run_the_approved_restart_does_not_execute(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["ask", "run the approved restart"])
    assert r.exit_code == 0, r.stdout
    assert "Refusing to execute" in r.stdout
    assert "--execute --confirm" in r.stdout
    assert fake.calls == []


def test_ask_perform_the_restart_does_not_execute(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    fake = _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["ask", "perform the restart on sfai-healthy-web"])
    assert r.exit_code == 0, r.stdout
    assert "Refusing to execute" in r.stdout
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Audit validation


def test_audit_validate_accepts_scoped_execution_event(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    storage = AuditStorage(tmp_path)
    vr = storage.validate_events()
    assert vr.ok, vr.errors
    assert vr.event_count > 0
    # And the execution event exists with the right safety scope
    events = storage.read_events()
    exec_events = [
        e for e in events if e["kind"] == "execution" and e["action"] == "lab_container_restart"
    ]
    assert exec_events
    assert exec_events[0]["safety"]["mutation_scope"] == MUTATION_SCOPE


def test_audit_validate_rejects_arbitrary_mutation_event(tmp_path: Path):
    storage = AuditStorage(tmp_path)
    # Write a fake "I executed something else" event by going through write_event
    # with a non-allowed action; validation must reject.
    storage.write_event(
        kind="execution",
        action="package_install",  # NOT allowed
        status="success",
        session_id="sf_x",
        proposal_id="prop_x",
        proposal_fingerprint="",
        target="apt",
        risk="high",
        summary="naughty",
        safety={
            "execution_allowed": True,
            "execution_status": "executed",
            "mutation_performed": True,
            "mutation_scope": "package_install",
        },
        details={},
    )
    vr = storage.validate_events()
    assert not vr.ok
    assert any("execution_allowed must be false" in e for e in vr.errors)


def test_audit_timeline_shows_executed_event(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _enable_mutation_env(monkeypatch)
    _patch_fake_executor(monkeypatch, FakeCommandExecutor())
    proposal = _seed_for_apply(tmp_path)
    r = runner.invoke(app, ["apply", proposal.proposal_id, "--execute", "--confirm"])
    assert r.exit_code == 0, r.stdout
    tl = runner.invoke(app, ["audit", "timeline"])
    assert tl.exit_code == 0, tl.stdout
    assert "lab_container_restart" in tl.stdout


# ---------------------------------------------------------------------------
# Pure gate evaluator unit tests (no CLI)


def test_evaluate_gates_full_success_path():
    al = Allowlist(enabled=True, containers=("sfai-healthy-web",), source_path=None)
    payload = {
        "actions": [{"action_id": "act_001", "normalized_text": "docker restart sfai-healthy-web"}]
    }
    gate = evaluate_gates(
        execute=True,
        confirm=True,
        proposal_status="approved",
        guard_decision="fresh",
        actions_payload=payload,
        allowlist=al,
        action_id=None,
        env={ENV_MUTATION_MODE: "lab", ENV_ALLOW_LAB_RESTART: "1"},
    )
    assert gate.allowed is True
    assert gate.container == "sfai-healthy-web"


def test_evaluate_gates_blocks_when_guard_drift():
    al = Allowlist(enabled=True, containers=("sfai-healthy-web",), source_path=None)
    payload = {
        "actions": [{"action_id": "act_001", "normalized_text": "docker restart sfai-healthy-web"}]
    }
    gate = evaluate_gates(
        execute=True,
        confirm=True,
        proposal_status="approved",
        guard_decision="drift",
        actions_payload=payload,
        allowlist=al,
        action_id=None,
        env={ENV_MUTATION_MODE: "lab", ENV_ALLOW_LAB_RESTART: "1"},
    )
    assert gate.allowed is False
    assert gate.failed_gate == "guard_failed"


def test_evaluate_gates_rejects_unsafe_container_name():
    al = Allowlist(enabled=True, containers=("ok-name",), source_path=None)
    payload = {"actions": [{"action_id": "act_001", "normalized_text": "docker restart bad;name"}]}
    gate = evaluate_gates(
        execute=True,
        confirm=True,
        proposal_status="approved",
        guard_decision="fresh",
        actions_payload=payload,
        allowlist=al,
        action_id=None,
        env={ENV_MUTATION_MODE: "lab", ENV_ALLOW_LAB_RESTART: "1"},
    )
    # parse_restart_command should reject the unsafe name upstream, so no
    # candidate at all is found.
    assert gate.allowed is False
    assert gate.failed_gate == "no_restart_action_found"
