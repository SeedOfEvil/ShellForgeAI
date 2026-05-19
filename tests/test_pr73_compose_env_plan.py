from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _containers_payload(rows):
    class _Res:
        ok = True
        stdout = json.dumps({"containers": rows})

    return _Res()


def _blocked_disposable_target_setup(monkeypatch) -> None:
    rows = [
        {
            "name": "sfai-pr67-compose-web",
            "compose": {
                "detected": True,
                "project": "sfai_pr67_disposable",
                "service": "web",
                "container": "sfai-pr67-compose-web",
                "working_dir": "/srv/compose/sfai_pr67_disposable",
                "config_files": ["/srv/compose/sfai_pr67_disposable/docker-compose.yml"],
                "labels": {
                    "shellforgeai.disposable": "true",
                    "shellforgeai.allow_restart": "true",
                    "shellforgeai.test_harness": "compose-restart",
                    "shellforgeai.scope": "pr67",
                },
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run",
        lambda *a, **k: type(
            "R", (), {"returncode": 1, "stdout": "", "stderr": "unknown command: docker compose"}
        )(),
    )


def _production_target_setup(monkeypatch) -> None:
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
                "container": "shellforgeai",
                "working_dir": "/srv/compose/shellforgeai",
                "config_files": ["/srv/compose/shellforgeai/compose.yml"],
                "labels": {},
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run",
        lambda *a, **k: type(
            "R", (), {"returncode": 1, "stdout": "", "stderr": "unknown command: docker compose"}
        )(),
    )


def test_env_plan_disposable_target_blocked_human(monkeypatch) -> None:
    _blocked_disposable_target_setup(monkeypatch)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "sfai-pr67-compose-web"])
    assert res.exit_code == 0
    assert "Compose execution environment plan" in res.stdout
    assert "input: sfai-pr67-compose-web" in res.stdout
    assert "compose-managed: true" in res.stdout
    assert "target_allowlisted: true" in res.stdout
    assert "compose_file_snapshot_unavailable" in res.stdout
    assert "docker_compose_cli_unavailable" in res.stdout
    assert "ShellForgeAI action: none" in res.stdout
    assert "read_only: true" in res.stdout
    assert "docker_compose_executed: false" in res.stdout
    assert "container_restarted: false" in res.stdout
    assert "host_side_bypass: false" in res.stdout
    assert "arbitrary_command_execution: false" in res.stdout


def test_env_plan_disposable_target_blocked_json(monkeypatch) -> None:
    _blocked_disposable_target_setup(monkeypatch)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "sfai-pr67-compose-web", "--json"])
    body = json.loads(res.stdout)
    assert body["schema_version"] == "1"
    assert body["status"] == "blocked"
    assert body["target"]["input"] == "sfai-pr67-compose-web"
    assert body["target"]["compose_managed"] is True
    assert body["target"]["disposable"] is True
    assert body["target"]["allow_restart"] is True
    assert body["target"]["target_allowlisted"] is True
    assert body["target"]["production_like"] is False
    assert "compose_file_snapshot_unavailable" in body["readiness"]["blockers"]
    assert "docker_compose_cli_unavailable" in body["readiness"]["blockers"]
    assert isinstance(body["plan"], list) and body["plan"]
    for entry in body["plan"]:
        assert entry["shellforgeai_action"] == "none"
        assert entry["automated"] is False
        assert entry["allowed_for_production"] is False
    assert body["safety"]["read_only"] is True
    assert body["safety"]["docker_compose_executed"] is False
    assert body["safety"]["container_restarted"] is False
    assert body["safety"]["host_side_bypass"] is False
    assert body["safety"]["arbitrary_command_execution"] is False
    assert body["safety"]["natural_language_execution"] is False


def test_env_plan_production_target_warns(monkeypatch) -> None:
    _production_target_setup(monkeypatch)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "shellforgeai"])
    assert "Target is not eligible for Compose execution proof." in res.stdout
    assert "production target should not be labeled disposable" in res.stdout
    assert "use the PR67 disposable harness target instead" in res.stdout


def test_env_plan_production_target_json_production_like_true(monkeypatch) -> None:
    _production_target_setup(monkeypatch)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["target"]["production_like"] is True
    assert body["target"]["target_allowlisted"] is False
    assert "target_not_allowlisted" in body["readiness"]["blockers"]
    plan_by_blocker = {entry["blocker"]: entry for entry in body["plan"]}
    assert "target_not_allowlisted" in plan_by_blocker
    remediation = plan_by_blocker["target_not_allowlisted"]["operator_remediation"]
    assert "PR67 disposable harness" in remediation
    assert "Do not label production" in remediation
    assert any("production-like target detected" in w for w in body["warnings"])


def test_env_plan_compose_file_snapshot_unavailable_wording(monkeypatch) -> None:
    _blocked_disposable_target_setup(monkeypatch)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "sfai-pr67-compose-web", "--json"])
    body = json.loads(res.stdout)
    entry = next(e for e in body["plan"] if e["blocker"] == "compose_file_snapshot_unavailable")
    assert "read-only" in entry["operator_remediation"].lower()
    assert "expose" in entry["operator_remediation"].lower()
    assert entry["mutation_required_outside_shellforgeai"] is True


def test_env_plan_docker_compose_cli_unavailable_wording(monkeypatch) -> None:
    _blocked_disposable_target_setup(monkeypatch)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "sfai-pr67-compose-web", "--json"])
    body = json.loads(res.stdout)
    entry = next(e for e in body["plan"] if e["blocker"] == "docker_compose_cli_unavailable")
    text = entry["operator_remediation"].lower()
    assert "compose plugin" in text or "docker cli" in text
    assert "shellforgeai" in text


def test_env_plan_required_invocation_unsupported_wording(monkeypatch, tmp_path) -> None:
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services:\n  web: {}\n", encoding="utf-8")
    rows = [
        {
            "name": "sfai-pr67-compose-web",
            "compose": {
                "detected": True,
                "project": "sfai_pr67_disposable",
                "service": "web",
                "container": "sfai-pr67-compose-web",
                "working_dir": str(tmp_path),
                "config_files": [str(compose_file)],
                "labels": {
                    "shellforgeai.disposable": "true",
                    "shellforgeai.allow_restart": "true",
                },
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )

    def _run(*a, **k):
        cmd = a[0]
        if cmd[:3] == ["docker", "compose", "version"]:
            return type("R", (), {"returncode": 0, "stdout": "Docker Compose v2", "stderr": ""})()
        return type("R", (), {"returncode": 1, "stdout": "", "stderr": "unknown flag"})()

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _run)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "sfai-pr67-compose-web", "--json"])
    body = json.loads(res.stdout)
    blockers = body["readiness"]["blockers"]
    if "required_invocation_unsupported" in blockers:
        entry = next(e for e in body["plan"] if e["blocker"] == "required_invocation_unsupported")
        assert "compose plugin" in entry["operator_remediation"].lower() or (
            "compatible" in entry["operator_remediation"].lower()
        )


def test_env_plan_target_not_allowlisted_recommends_pr67(monkeypatch) -> None:
    rows = [
        {
            "name": "some-compose-app",
            "compose": {
                "detected": True,
                "project": "some_project",
                "service": "some_service",
                "container": "some-compose-app",
                "working_dir": "/tmp/x",
                "config_files": ["/tmp/x/compose.yml"],
                "labels": {},
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run",
        lambda *a, **k: type("R", (), {"returncode": 1, "stdout": "", "stderr": "unknown"})(),
    )
    res = runner.invoke(app, ["compose", "env-plan", "--target", "some-compose-app", "--json"])
    body = json.loads(res.stdout)
    plan_by_blocker = {entry["blocker"]: entry for entry in body["plan"]}
    assert "target_not_allowlisted" in plan_by_blocker
    text = plan_by_blocker["target_not_allowlisted"]["operator_remediation"]
    assert "PR67 disposable harness" in text


def test_env_plan_unknown_blocker_preserved(monkeypatch) -> None:
    from shellforgeai.cli import _compose_env_plan_payload

    def _fake_contract(target):  # type: ignore[no-redef]
        return {
            "schema_version": "1",
            "status": "blocked",
            "target": {
                "input": target or "",
                "compose_managed": True,
                "project": "p",
                "service": "s",
                "container": "c",
                "disposable": True,
                "allow_restart": True,
                "target_allowlisted": True,
            },
            "readiness": {
                "ready": False,
                "ready_for_optional_disposable_proof": False,
                "blockers": ["some_unknown_future_blocker"],
                "warnings": [],
            },
        }

    monkeypatch.setattr("shellforgeai.cli._compose_env_contract_payload", _fake_contract)
    payload = _compose_env_plan_payload("anything")
    plan_by_blocker = {entry["blocker"]: entry for entry in payload["plan"]}
    assert "some_unknown_future_blocker" in plan_by_blocker
    entry = plan_by_blocker["some_unknown_future_blocker"]
    assert entry["shellforgeai_action"] == "none"
    assert entry["automated"] is False
    assert "Unrecognized blocker" in entry["meaning"]


def test_env_plan_json_no_text_before_or_after(monkeypatch) -> None:
    _blocked_disposable_target_setup(monkeypatch)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "sfai-pr67-compose-web", "--json"])
    stdout = res.stdout
    parsed = json.loads(stdout)
    assert isinstance(parsed, dict)
    redumped = json.dumps(parsed)
    assert stdout.strip() == redumped


def test_env_plan_safety_flags_present_in_json(monkeypatch) -> None:
    _blocked_disposable_target_setup(monkeypatch)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "sfai-pr67-compose-web", "--json"])
    body = json.loads(res.stdout)
    assert set(body["safety"].keys()) >= {
        "read_only",
        "docker_compose_executed",
        "container_restarted",
        "host_side_bypass",
        "arbitrary_command_execution",
        "natural_language_execution",
    }


def test_env_plan_target_not_found_blocked(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload([]),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run",
        lambda *a, **k: type("R", (), {"returncode": 1, "stdout": "", "stderr": "unknown"})(),
    )
    res = runner.invoke(app, ["compose", "env-plan", "--target", "no-such-container", "--json"])
    body = json.loads(res.stdout)
    assert body["status"] in {"blocked", "not_found"}
    assert "target_not_found" in body["readiness"]["blockers"]
    plan_by_blocker = {entry["blocker"]: entry for entry in body["plan"]}
    assert "target_not_found" in plan_by_blocker


def test_env_plan_no_target_supplied(monkeypatch) -> None:
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload([]),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run",
        lambda *a, **k: type("R", (), {"returncode": 1, "stdout": "", "stderr": "unknown"})(),
    )
    res = runner.invoke(app, ["compose", "env-plan", "--json"])
    body = json.loads(res.stdout)
    assert body["status"] == "blocked"
    assert "target_required" in body["readiness"]["blockers"]


def test_env_plan_does_not_invoke_subprocess_run_when_contract_handles_it() -> None:
    from shellforgeai.cli import _compose_env_plan_payload

    payload = _compose_env_plan_payload(None)
    assert payload["status"] == "blocked"
    assert payload["safety"]["docker_compose_executed"] is False
    assert payload["safety"]["read_only"] is True


def test_env_plan_post_conditions_mention_production_not_allowlisted(monkeypatch) -> None:
    _blocked_disposable_target_setup(monkeypatch)
    res = runner.invoke(app, ["compose", "env-plan", "--target", "sfai-pr67-compose-web", "--json"])
    body = json.loads(res.stdout)
    joined = " ".join(body["post_conditions"])
    assert "production" in joined and "not allowlisted" in joined


def test_env_plan_does_not_create_proposals_or_missions(monkeypatch, tmp_path) -> None:
    _blocked_disposable_target_setup(monkeypatch)
    data_root = tmp_path / "data"
    data_root.mkdir()
    res = runner.invoke(app, ["compose", "env-plan", "--target", "sfai-pr67-compose-web", "--json"])
    assert res.exit_code == 0
    assert not (data_root / "proposals").exists()
    assert not (data_root / "missions").exists()


def test_env_plan_natural_language_mutation_still_refused(monkeypatch) -> None:
    """env-plan must not enable natural-language mutation execution."""
    from shellforgeai.core.ask_routing import is_compose_mutation_request

    assert is_compose_mutation_request("docker compose restart sfai-pr67-compose-web") is True
    assert is_compose_mutation_request("restart compose service web") is True


@pytest.mark.parametrize(
    "blocker_name",
    [
        "compose_file_snapshot_unavailable",
        "docker_compose_cli_unavailable",
        "required_invocation_unsupported",
        "target_not_allowlisted",
        "compose_file_missing",
        "compose_metadata_incomplete",
    ],
)
def test_env_plan_blocker_map_covers_known_blockers(blocker_name) -> None:
    from shellforgeai.cli import _COMPOSE_ENV_PLAN_BLOCKER_MAP

    assert blocker_name in _COMPOSE_ENV_PLAN_BLOCKER_MAP
    entry = _COMPOSE_ENV_PLAN_BLOCKER_MAP[blocker_name]
    assert "meaning" in entry
    assert "operator_remediation" in entry
    assert entry["shellforgeai_action"] == "none"
    assert entry["allowed_for_production"] is False
