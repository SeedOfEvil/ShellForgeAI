"""PR67 follow-up: env-check label normalization + mission not_found.

Two fixes:

1. env-check / readiness must recognize disposable/allow_restart labels
   from Docker label sources (row["labels"], Docker inspect Config.Labels,
   container_labels/docker_labels variants), not just from the
   compose-context block.

2. `mission compose-restart {status,checklist,validate,execute}
   <fake-mission>` must not traceback. Human output is a clean
   "not found" line; --json emits strict JSON with status=not_found.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()

DISPOSABLE_PROJECT = "sfai_pr67_disposable"
DISPOSABLE_SERVICE = "web"
DISPOSABLE_CONTAINER = "sfai-pr67-compose-web"


def _ok_compose(*_a, **_k):
    return type("R", (), {"returncode": 0, "stdout": "Docker Compose v2", "stderr": ""})()


def _bad_compose(*_a, **_k):
    return type(
        "R", (), {"returncode": 1, "stdout": "", "stderr": "unknown command: docker compose"}
    )()


def _containers_payload(rows):
    class _Res:
        ok = True
        stdout = json.dumps({"containers": rows})

    return _Res()


def _disposable_row(*, labels_on_row=None, labels_on_compose=None, extra=None):
    row = {
        "name": DISPOSABLE_CONTAINER,
        "compose": {
            "detected": True,
            "project": DISPOSABLE_PROJECT,
            "service": DISPOSABLE_SERVICE,
            "container": DISPOSABLE_CONTAINER,
            "working_dir": "/srv/x",
            "config_files": ["/srv/x/docker-compose.yml"],
        },
    }
    if labels_on_row is not None:
        row["labels"] = labels_on_row
    if labels_on_compose is not None:
        row["compose"]["labels"] = labels_on_compose
    if extra:
        row.update(extra)
    return row


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path / "data"))


# ---------------------------------------------------------------------------
# label normalization (Blocker 1)
# ---------------------------------------------------------------------------


def test_env_check_recognizes_labels_on_row(monkeypatch) -> None:
    rows = [
        _disposable_row(
            labels_on_row={
                "shellforgeai.disposable": "true",
                "shellforgeai.allow_restart": "true",
            }
        )
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _ok_compose)
    r = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(r.stdout)
    assert body["allowlist"]["disposable"] is True
    assert body["allowlist"]["allow_restart"] is True
    assert body["allowlist"]["target_allowlisted"] is True
    assert "target_not_allowlisted" not in body["readiness"]["blockers"]


def test_env_check_recognizes_labels_on_compose_block(monkeypatch) -> None:
    rows = [
        _disposable_row(
            labels_on_compose={
                "shellforgeai.disposable": "true",
                "shellforgeai.allow_restart": "true",
            }
        )
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _ok_compose)
    r = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(r.stdout)
    assert body["allowlist"]["target_allowlisted"] is True


def test_env_check_recognizes_docker_inspect_config_labels(monkeypatch) -> None:
    rows = [
        _disposable_row(
            extra={
                "Config": {
                    "Labels": {
                        "shellforgeai.disposable": "true",
                        "shellforgeai.allow_restart": "true",
                    }
                }
            }
        )
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _ok_compose)
    r = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(r.stdout)
    assert body["allowlist"]["target_allowlisted"] is True


def test_env_check_recognizes_container_labels_shape(monkeypatch) -> None:
    rows = [
        _disposable_row(
            extra={
                "container_labels": {
                    "shellforgeai.disposable": "true",
                    "shellforgeai.allow_restart": "true",
                }
            }
        )
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _ok_compose)
    r = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(r.stdout)
    assert body["allowlist"]["target_allowlisted"] is True


def test_env_check_label_value_variants_accepted(monkeypatch) -> None:
    for value in ("true", "True", "1", "yes"):
        rows = [_disposable_row(labels_on_row={"shellforgeai.disposable": value})]
        monkeypatch.setattr(
            "shellforgeai.cli.containers.containers",
            lambda all_containers=True, _rows=rows: _containers_payload(_rows),
        )
        monkeypatch.setattr("shellforgeai.cli.subprocess.run", _ok_compose)
        r = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
        body = json.loads(r.stdout)
        assert body["allowlist"]["disposable"] is True, f"value={value!r}"
        assert body["allowlist"]["target_allowlisted"] is True


def test_env_check_real_shellforgeai_target_remains_not_allowlisted(monkeypatch) -> None:
    rows = [
        {
            "name": "shellforgeai",
            "labels": {},
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
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
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _bad_compose)
    r = runner.invoke(app, ["compose", "env-check", "--target", "shellforgeai", "--json"])
    body = json.loads(r.stdout)
    assert body["allowlist"]["disposable"] is False
    assert body["allowlist"]["allow_restart"] is False
    assert body["allowlist"]["target_allowlisted"] is False
    assert "target_not_allowlisted" in body["readiness"]["blockers"]


def test_env_check_disposable_blockers_keep_compose_cli_blockers(monkeypatch) -> None:
    """target_allowlisted=true must still report the real environmental
    blockers (Docker01 reality)."""
    rows = [
        _disposable_row(
            labels_on_row={
                "shellforgeai.disposable": "true",
                "shellforgeai.allow_restart": "true",
            }
        )
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _bad_compose)
    r = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(r.stdout)
    assert body["allowlist"]["target_allowlisted"] is True
    assert "target_not_allowlisted" not in body["readiness"]["blockers"]
    assert "docker_compose_cli_unavailable" in body["readiness"]["blockers"]
    assert "compose_file_snapshot_unavailable" in body["readiness"]["blockers"]


def test_env_check_human_output_shows_allowlist_block(monkeypatch) -> None:
    rows = [
        _disposable_row(
            labels_on_row={
                "shellforgeai.disposable": "true",
                "shellforgeai.allow_restart": "true",
            }
        )
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _bad_compose)
    r = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER])
    assert "Allowlist:" in r.stdout
    assert "disposable: true" in r.stdout
    assert "allow_restart: true" in r.stdout
    assert "target_allowlisted: true" in r.stdout


# ---------------------------------------------------------------------------
# missing mission id (Blocker 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("subcmd", ["status", "checklist", "validate", "execute"])
def test_mission_missing_id_json_is_clean_not_found(subcmd) -> None:
    r = runner.invoke(app, ["mission", "compose-restart", subcmd, "fake-mission-id", "--json"])
    assert r.exit_code != 0
    body = json.loads(r.stdout)
    assert body["status"] == "not_found"
    assert body["mission_id"] == "fake-mission-id"
    assert body["error"] == "mission_not_found"
    assert body["executed"] is False
    assert body["docker_compose_executed"] is False
    assert body["container_restarted"] is False
    assert "warnings" in body
    assert "Traceback" not in r.stdout
    assert "FileNotFoundError" not in r.stdout


@pytest.mark.parametrize("subcmd", ["status", "checklist", "validate", "execute"])
def test_mission_missing_id_human_is_clean_not_found(subcmd) -> None:
    r = runner.invoke(app, ["mission", "compose-restart", subcmd, "fake-mission-id"])
    assert r.exit_code != 0
    assert "Compose restart mission not found: fake-mission-id" in r.stdout
    assert "Traceback" not in r.stdout
    assert "FileNotFoundError" not in r.stdout


def test_mission_missing_id_does_not_invoke_subprocess(monkeypatch) -> None:
    called: dict = {"n": 0}

    def _block(*a, **kw):
        called["n"] += 1
        raise AssertionError("subprocess.run must not be called for missing mission")

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _block)
    r = runner.invoke(
        app,
        [
            "mission",
            "compose-restart",
            "execute",
            "fake-mission-id",
            "--execute",
            "--confirm",
            "--json",
        ],
    )
    assert r.exit_code != 0
    assert called["n"] == 0
    body = json.loads(r.stdout)
    assert body["status"] == "not_found"


# ---------------------------------------------------------------------------
# safety regression
# ---------------------------------------------------------------------------


def test_env_check_remains_read_only_after_label_fix(monkeypatch) -> None:
    rows = [
        _disposable_row(
            labels_on_row={
                "shellforgeai.disposable": "true",
                "shellforgeai.allow_restart": "true",
            }
        )
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _ok_compose)
    r = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(r.stdout)
    assert body["safety"]["read_only"] is True
    assert body["safety"]["docker_compose_executed"] is False
    assert body["safety"]["container_restarted"] is False
    assert body["safety"]["proposal_created"] is False
    assert body["safety"]["mission_created"] is False
    assert body["safety"]["apply_executed"] is False
    assert body["safety"]["arbitrary_command_execution"] is False
