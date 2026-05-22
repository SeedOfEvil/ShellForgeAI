import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app


def _env(tmp_path: Path) -> dict[str, str]:
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _write_scene(tmp_path: Path, name: str, labels: dict[str, str]) -> None:
    data = tmp_path / "data"
    ev = data / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    payload = {
        "containers": [{"name": name, "status": "running", "labels": labels}],
        "problem_summary": {"containers": []},
    }
    (ev / "docker.containers.json").write_text(json.dumps(payload), encoding="utf-8")


# triage_ranking collector may fall back; keep tests focused on refusals and artifact flow


def test_plan_refuses_missing_labels(tmp_path: Path) -> None:
    r = CliRunner().invoke(
        app,
        ["remediation", "plan", "--target", "foo", "--scenario", "sfai-noisy-errors"],
        env=_env(tmp_path),
    )
    assert r.exit_code == 1
    assert "Refused" in r.stdout


def test_plan_validate_execute_status_json(tmp_path: Path) -> None:
    from shellforgeai.core.disposable_remediation import write_plan

    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    p = write_plan(
        data_dir=data,
        target="sfai-noisy-errors",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    plan_id = p["plan_id"]

    rv = CliRunner().invoke(app, ["remediation", "validate", plan_id, "--json"], env=_env(tmp_path))
    assert rv.exit_code == 0
    assert json.loads(rv.stdout)["status"] == "ok"

    re = CliRunner().invoke(app, ["remediation", "execute", plan_id], env=_env(tmp_path))
    assert re.exit_code == 1
    assert "--execute --confirm" in re.stdout

    re2 = CliRunner().invoke(
        app,
        ["remediation", "execute", plan_id, "--execute", "--confirm", "--json"],
        env=_env(tmp_path),
    )
    assert re2.exit_code == 0
    payload = json.loads(re2.stdout)
    assert payload["status"] == "executed"
    rid = payload["receipt_id"]

    rs = CliRunner().invoke(app, ["remediation", "status", rid, "--json"], env=_env(tmp_path))
    assert rs.exit_code == 0
    sp = json.loads(rs.stdout)
    assert sp["status"] == "ok"
    assert sp["receipt"]["plan_id"] == plan_id
