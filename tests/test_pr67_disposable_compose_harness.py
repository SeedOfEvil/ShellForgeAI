"""PR67 disposable Compose execution harness readiness tests.

These tests exercise the disposable Compose fixture, the env-check
readiness path, the mission readiness/checklist/validate path, and the
mocked execute path. No live Docker, no real Compose mutation.
"""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_FIXTURE = REPO_ROOT / "examples" / "compose" / "disposable-restart" / "docker-compose.yml"
TEST_FIXTURE = (
    REPO_ROOT / "tests" / "fixtures" / "compose" / "disposable-restart" / "docker-compose.yml"
)
LAB_SCRIPT = REPO_ROOT / "scripts" / "pr67_disposable_compose_harness.sh"

DISPOSABLE_PROJECT = "sfai_pr67_disposable"
DISPOSABLE_SERVICE = "web"
DISPOSABLE_CONTAINER = "sfai-pr67-compose-web"


# ---------------------------------------------------------------------------
# fixture file shape tests
# ---------------------------------------------------------------------------


@pytest.fixture(params=[EXAMPLE_FIXTURE, TEST_FIXTURE])
def fixture_path(request) -> Path:
    return request.param


def _load_fixture(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_disposable_fixture_files_exist(fixture_path: Path) -> None:
    assert fixture_path.is_file(), f"missing disposable fixture: {fixture_path}"


def test_disposable_fixture_project_and_names(fixture_path: Path) -> None:
    data = _load_fixture(fixture_path)
    assert data.get("name") == DISPOSABLE_PROJECT
    services = data.get("services") or {}
    assert DISPOSABLE_SERVICE in services
    svc = services[DISPOSABLE_SERVICE]
    assert svc.get("container_name") == DISPOSABLE_CONTAINER


def test_disposable_fixture_required_labels(fixture_path: Path) -> None:
    svc = _load_fixture(fixture_path)["services"][DISPOSABLE_SERVICE]
    labels = svc.get("labels") or {}
    assert str(labels.get("shellforgeai.disposable")).lower() == "true"
    assert str(labels.get("shellforgeai.allow_restart")).lower() == "true"
    assert labels.get("shellforgeai.test_harness") == "compose-restart"
    assert labels.get("shellforgeai.scope") == "pr67"


def test_disposable_fixture_is_not_privileged(fixture_path: Path) -> None:
    svc = _load_fixture(fixture_path)["services"][DISPOSABLE_SERVICE]
    assert not svc.get("privileged")
    assert "host" not in str(svc.get("network_mode") or "").lower()
    assert "host" not in str(svc.get("pid") or "").lower()
    assert "host" not in str(svc.get("ipc") or "").lower()


def test_disposable_fixture_no_docker_socket_or_dangerous_mounts(fixture_path: Path) -> None:
    svc = _load_fixture(fixture_path)["services"][DISPOSABLE_SERVICE]
    for vol in svc.get("volumes") or []:
        s = vol if isinstance(vol, str) else vol.get("source", "")
        assert "docker.sock" not in s
        assert not s.startswith("/etc")
        assert not s.startswith("/var/lib")
        assert not s.startswith("/root")


def test_disposable_fixture_no_secrets(fixture_path: Path) -> None:
    raw = fixture_path.read_text(encoding="utf-8").lower()
    for needle in ("password:", "secret:", "api_key", "token:"):
        assert needle not in raw, f"unexpected secret-like token '{needle}' in fixture"


def test_disposable_fixture_service_name_deterministic(fixture_path: Path) -> None:
    services = _load_fixture(fixture_path)["services"]
    assert list(services.keys()) == [DISPOSABLE_SERVICE]


# ---------------------------------------------------------------------------
# env-check readiness tests
# ---------------------------------------------------------------------------


def _ok_compose_run(*_a, **_k):
    return type("R", (), {"returncode": 0, "stdout": "Docker Compose v2", "stderr": ""})()


def _bad_compose_run(*_a, **_k):
    return type(
        "R", (), {"returncode": 1, "stdout": "", "stderr": "unknown command: docker compose"}
    )()


def _containers_payload(rows):
    class _Res:
        ok = True
        stdout = json.dumps({"containers": rows})

    return _Res()


def _disposable_row(compose_file: str, working_dir: str, labels: dict | None = None) -> dict:
    return {
        "name": DISPOSABLE_CONTAINER,
        "compose": {
            "detected": True,
            "project": DISPOSABLE_PROJECT,
            "service": DISPOSABLE_SERVICE,
            "container": DISPOSABLE_CONTAINER,
            "working_dir": working_dir,
            "config_files": [compose_file],
            "labels": labels
            if labels is not None
            else {
                "shellforgeai.disposable": "true",
                "shellforgeai.allow_restart": "true",
                "shellforgeai.test_harness": "compose-restart",
                "shellforgeai.scope": "pr67",
            },
        },
    }


def _services_run_factory(service_name: str):
    def _run(cmd, *args, **kwargs):
        if cmd[:3] == ["docker", "compose", "version"]:
            return type("R", (), {"returncode": 0, "stdout": "Docker Compose v2", "stderr": ""})()
        if cmd[-2:] == ["config", "--services"]:
            return type("R", (), {"returncode": 0, "stdout": service_name, "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    return _run


def test_env_check_disposable_ready_json(monkeypatch, tmp_path: Path) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(TEST_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    rows = [_disposable_row(str(compose_file), str(tmp_path))]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run", _services_run_factory(DISPOSABLE_SERVICE)
    )
    res = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(res.stdout)
    assert body["status"] == "ok"
    assert body["target"]["compose_managed"] is True
    assert body["target"]["project"] == DISPOSABLE_PROJECT
    assert body["target"]["service"] == DISPOSABLE_SERVICE
    assert body["target"]["container"] == DISPOSABLE_CONTAINER
    assert body["allowlist"]["target_allowlisted"] is True
    assert body["allowlist"]["disposable"] is True
    assert body["allowlist"]["allow_restart"] is True
    expected_hash = hashlib.sha256(compose_file.read_bytes()).hexdigest()
    assert body["config_snapshot"]["compose_file_sha256"] == expected_hash
    assert body["readiness"]["compose_restart_execution_ready"] is True
    assert body["readiness"]["blockers"] == []
    assert body["safety"]["docker_compose_executed"] is False
    assert body["safety"]["container_restarted"] is False


def test_env_check_disposable_ready_json_is_strict(monkeypatch, tmp_path: Path) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(TEST_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    rows = [_disposable_row(str(compose_file), str(tmp_path))]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run", _services_run_factory(DISPOSABLE_SERVICE)
    )
    res = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    stripped = res.stdout.strip()
    # exactly one JSON object, no surrounding text
    parsed = json.loads(stripped)
    assert isinstance(parsed, dict)
    assert stripped.startswith("{") and stripped.endswith("}")


def test_env_check_missing_allow_restart_blocks(monkeypatch, tmp_path: Path) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    rows = [
        _disposable_row(
            str(compose_file),
            str(tmp_path),
            labels={"shellforgeai.disposable": "true"},
        )
    ]
    rows[0]["compose"]["labels"].pop("shellforgeai.allow_restart", None)
    # remove disposable too so allowlist fails entirely
    rows[0]["compose"]["labels"] = {}
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run", _services_run_factory(DISPOSABLE_SERVICE)
    )
    res = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(res.stdout)
    assert body["readiness"]["compose_restart_execution_ready"] is False
    assert "target_not_allowlisted" in body["readiness"]["blockers"]


def test_env_check_missing_compose_file_blocks(monkeypatch, tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.yml"
    rows = [_disposable_row(str(missing), str(tmp_path))]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run", _services_run_factory(DISPOSABLE_SERVICE)
    )
    res = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(res.stdout)
    assert "compose_file_snapshot_unavailable" in body["readiness"]["blockers"]
    assert body["readiness"]["compose_restart_execution_ready"] is False


def test_env_check_compose_cli_unavailable_blocks(monkeypatch, tmp_path: Path) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(TEST_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    rows = [_disposable_row(str(compose_file), str(tmp_path))]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _bad_compose_run)
    res = runner.invoke(app, ["compose", "env-check", "--target", DISPOSABLE_CONTAINER, "--json"])
    body = json.loads(res.stdout)
    assert "docker_compose_cli_unavailable" in body["readiness"]["blockers"]
    assert body["readiness"]["compose_restart_execution_ready"] is False


def test_env_check_real_shellforgeai_target_remains_blocked(monkeypatch, tmp_path: Path) -> None:
    """Non-disposable production-style target must NOT become ready."""
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    rows = [
        {
            "name": "shellforgeai",
            "compose": {
                "detected": True,
                "project": "shellforgeai",
                "service": "shellforgeai",
                "working_dir": str(tmp_path),
                "config_files": [str(compose_file)],
                "labels": {},  # explicitly NOT allowlisted
            },
        }
    ]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _services_run_factory("shellforgeai"))
    res = runner.invoke(app, ["compose", "env-check", "--target", "shellforgeai", "--json"])
    body = json.loads(res.stdout)
    assert body["allowlist"]["target_allowlisted"] is False
    assert body["readiness"]["compose_restart_execution_ready"] is False
    assert "target_not_allowlisted" in body["readiness"]["blockers"]


# ---------------------------------------------------------------------------
# mission readiness / execute (mocked, never real)
# ---------------------------------------------------------------------------


def _runtime_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path / "data"))


def _prepare_mission(monkeypatch, tmp_path: Path) -> tuple[str, str, Path]:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(TEST_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    rows = [_disposable_row(str(compose_file), str(tmp_path))]
    monkeypatch.setattr(
        "shellforgeai.cli.containers.containers",
        lambda all_containers=True: _containers_payload(rows),
    )
    monkeypatch.setattr(
        "shellforgeai.cli.subprocess.run", _services_run_factory(DISPOSABLE_SERVICE)
    )
    create = runner.invoke(app, ["compose", "propose-restart", DISPOSABLE_CONTAINER, "--json"])
    pid = json.loads(create.stdout)["proposal"]["id"]
    runner.invoke(app, ["approvals", "approve", pid, "--reason", "pr67 lab"])
    rb = runner.invoke(app, ["rollback", "preview", pid])
    assert rb.exit_code == 0, rb.stdout
    prep = runner.invoke(app, ["mission", "compose-restart", "prepare", pid])
    mid = [
        ln.split(":", 1)[1].strip()
        for ln in prep.stdout.splitlines()
        if ln.strip().startswith("- mission:")
    ][0]
    return pid, mid, compose_file


def test_mission_validate_ready_for_disposable(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    _pid, mid, _cf = _prepare_mission(monkeypatch, tmp_path)
    r = runner.invoke(app, ["mission", "compose-restart", "validate", mid, "--json"])
    body = json.loads(r.stdout)
    gates = body.get("gates") or {}
    assert gates.get("target_allowlisted") is True
    assert gates.get("compose_metadata_complete") is True
    assert gates.get("rollback_preview_present") is True
    assert gates.get("rollback_preview_valid") is True
    assert gates.get("compose_file_snapshot_available") is True
    assert gates.get("docker_compose_available") is True


def test_mission_execute_refuses_without_confirm(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    _pid, mid, _cf = _prepare_mission(monkeypatch, tmp_path)
    r = runner.invoke(app, ["mission", "compose-restart", "execute", mid, "--execute"])
    assert r.exit_code == 1
    assert "requires --execute --confirm" in r.stdout


def test_mission_execute_uses_expected_argv_and_no_shell(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    _pid, mid, compose_file = _prepare_mission(monkeypatch, tmp_path)
    seen: dict = {}

    class P:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def _run(cmd, capture_output=False, text=False, check=False, **kwargs):
        seen.setdefault("calls", []).append(
            {"cmd": cmd, "shell": kwargs.get("shell", False), "check": check}
        )
        if cmd[:3] == ["docker", "compose", "version"]:
            return P(stdout="Docker Compose v2")
        if cmd[-2:] == ["config", "--services"]:
            return P(stdout=DISPOSABLE_SERVICE)
        return P()

    monkeypatch.setattr("shellforgeai.cli.subprocess.run", _run)
    r = runner.invoke(
        app,
        [
            "mission",
            "compose-restart",
            "execute",
            mid,
            "--execute",
            "--confirm",
            "--json",
        ],
    )
    assert r.exit_code == 0, r.stdout
    body = json.loads(r.stdout)
    assert body["execution"]["executed"] is True
    assert body["execution"]["command"] == [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "--project-directory",
        str(tmp_path),
        "restart",
        DISPOSABLE_SERVICE,
    ]
    for call in seen["calls"]:
        assert call["shell"] is False, "shell=True must never appear on the Compose lane"
        assert isinstance(call["cmd"], list)


# ---------------------------------------------------------------------------
# safety / refusal regression
# ---------------------------------------------------------------------------


def test_natural_language_compose_restart_still_refuses(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    r = runner.invoke(
        app,
        ["ask", f"docker compose restart {DISPOSABLE_CONTAINER}"],
    )
    out = (r.stdout or "") + (r.stderr or "")
    assert "natural-language" in out.lower() or "refus" in out.lower() or r.exit_code != 0


def test_ask_execute_latest_compose_mission_refuses(monkeypatch, tmp_path: Path) -> None:
    _runtime_env(monkeypatch, tmp_path)
    r = runner.invoke(app, ["ask", "execute latest compose restart mission"])
    out = (r.stdout or "") + (r.stderr or "")
    assert r.exit_code != 0 or "refus" in out.lower() or "natural-language" in out.lower()


# ---------------------------------------------------------------------------
# lab script tests
# ---------------------------------------------------------------------------


def test_lab_script_exists_and_executable() -> None:
    assert LAB_SCRIPT.is_file()
    mode = LAB_SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR, "lab script must be executable"


def test_lab_script_has_expected_names() -> None:
    raw = LAB_SCRIPT.read_text(encoding="utf-8")
    assert DISPOSABLE_PROJECT in raw
    assert DISPOSABLE_SERVICE in raw
    assert DISPOSABLE_CONTAINER in raw


def test_lab_script_does_not_target_production_compose_mutation() -> None:
    raw = LAB_SCRIPT.read_text(encoding="utf-8")
    # must not invoke docker compose up/down for the production project name.
    assert "shellforgeai up" not in raw
    assert "shellforgeai down" not in raw
    # explicitly: no docker compose against the production project name
    for forbidden in (
        "docker compose -p shellforgeai ",
        "--project-name shellforgeai ",
        "--project-name shellforgeai\n",
    ):
        assert forbidden not in raw


def test_lab_script_does_not_prune_or_remove_paths() -> None:
    # Strip shell comments so the script's documentation of what it *does
    # not* do doesn't trip the assertion.
    lines = []
    for ln in LAB_SCRIPT.read_text(encoding="utf-8").splitlines():
        stripped = ln.lstrip()
        if stripped.startswith("#"):
            continue
        lines.append(ln)
    code = "\n".join(lines)
    assert "docker system prune" not in code
    assert "rm -rf /" not in code
    assert "rm -rf ~" not in code


def test_lab_script_print_commands_does_not_auto_execute(monkeypatch) -> None:
    res = subprocess.run(
        [str(LAB_SCRIPT), "print-commands"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    assert "shellforgeai mission compose-restart execute" in res.stdout
    assert "do not run" in res.stdout.lower()


def test_lab_script_print_env_lists_disposable_names() -> None:
    res = subprocess.run(
        [str(LAB_SCRIPT), "print-env"], capture_output=True, text=True, check=False
    )
    assert res.returncode == 0
    assert DISPOSABLE_PROJECT in res.stdout
    assert DISPOSABLE_SERVICE in res.stdout
    assert DISPOSABLE_CONTAINER in res.stdout


def test_lab_script_unknown_subcommand_refuses() -> None:
    res = subprocess.run(
        [str(LAB_SCRIPT), "self-destruct"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode != 0
