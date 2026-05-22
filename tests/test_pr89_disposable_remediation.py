import json

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import triage_ranking
from shellforgeai.core.disposable_remediation import write_plan

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _scene(labels_by_name):
    return {"containers": [{"name": n, "labels": labels} for n, labels in labels_by_name.items()]}


def test_collect_scene_includes_container_labels(monkeypatch):
    class R:
        def __init__(self, ok, stdout=""):
            self.ok = ok
            self.stdout = stdout

    payload = {
        "containers": [
            {"name": "sfai-noisy-errors", "state": "running", "labels": {"sfai.battle": "true"}},
            {"name": "other", "state": "running", "labels": {"x": "y"}},
        ]
    }

    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking._collect_cpu_stats",
        lambda: {},
    )
    monkeypatch.setattr(
        "shellforgeai.tools.containers.containers",
        lambda all_containers=True: R(True, json.dumps(payload)),
    )
    monkeypatch.setattr("shellforgeai.tools.containers.inspect", lambda name: R(False, ""))
    monkeypatch.setattr(
        "shellforgeai.tools.containers.container_logs", lambda name, tail=200: R(False, "")
    )

    scene = triage_ranking.collect_scene()
    by = {c["name"]: c for c in scene["containers"]}
    assert by["sfai-noisy-errors"]["labels"]["sfai.battle"] == "true"
    assert by["other"]["labels"]["x"] == "y"


def test_cli_plan_success_and_json_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene(
            {
                "sfai-noisy-errors": {
                    "sfai.battle": "true",
                    "shellforgeai.disposable": "true",
                    "shellforgeai.allow_restart": "true",
                    "shellforgeai.test_harness": "battle-lab",
                }
            }
        ),
    )
    r = runner.invoke(
        app,
        [
            "remediation",
            "plan",
            "--target",
            "sfai-noisy-errors",
            "--scenario",
            "sfai-noisy-errors",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert r.exit_code == 0
    p = json.loads(r.stdout)
    assert p["status"] == "planned"
    plan = p["plan"]
    assert plan["disposable"] is True
    assert plan["target_allowlisted"] is True
    assert plan["production_target"] is False
    assert plan["execution_allowed"] is False
    assert plan["mutation_performed"] is False
    assert plan["safety"]["shell_true"] is False
    assert plan["safety"]["arbitrary_command_execution"] is False


def test_cli_plan_refusals(tmp_path, monkeypatch):
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _scene({"x": {}}))
    r_prod = runner.invoke(
        app,
        [
            "remediation",
            "plan",
            "--target",
            "shellforgeai",
            "--scenario",
            "sfai-noisy-errors",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert r_prod.exit_code == 1 and json.loads(r_prod.stdout)["status"] == "blocked"

    r_un = runner.invoke(
        app,
        ["remediation", "plan", "--target", "x", "--scenario", "sfai-noisy-errors", "--json"],
        env=_env(tmp_path),
    )
    assert r_un.exit_code == 1

    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene({"x": {"sfai.battle": "true"}}),
    )
    r_allow = runner.invoke(
        app,
        ["remediation", "plan", "--target", "x", "--scenario", "sfai-noisy-errors", "--json"],
        env=_env(tmp_path),
    )
    assert r_allow.exit_code == 1

    r_broad = runner.invoke(
        app,
        ["remediation", "plan", "--target", "*", "--scenario", "sfai-noisy-errors", "--json"],
        env=_env(tmp_path),
    )
    assert r_broad.exit_code == 1


def test_execute_gates_and_receipt(tmp_path):
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    p = write_plan(
        data_dir=data,
        target="sfai-noisy-errors",
        scenario="sfai-noisy-errors",
        labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
    )
    plan_id = p["plan_id"]

    r1 = runner.invoke(app, ["remediation", "execute", plan_id], env=_env(tmp_path))
    assert r1.exit_code == 1 and "--execute --confirm" in r1.stdout

    r2 = runner.invoke(app, ["remediation", "execute", plan_id, "--execute"], env=_env(tmp_path))
    assert r2.exit_code == 1

    r3 = runner.invoke(
        app,
        ["remediation", "execute", plan_id, "--execute", "--confirm", "--json"],
        env=_env(tmp_path),
    )
    assert r3.exit_code == 0
    ep = json.loads(r3.stdout)
    assert ep["status"] == "executed"
    rid = ep["receipt_id"]

    rs = runner.invoke(app, ["remediation", "status", rid, "--json"], env=_env(tmp_path))
    assert rs.exit_code == 0
    sp = json.loads(rs.stdout)
    rec = sp["receipt"]
    assert rec["plan_id"] == plan_id
    assert rec["plan_fingerprint"]
    assert "pre_state" in rec and "post_state" in rec and "verification" in rec
