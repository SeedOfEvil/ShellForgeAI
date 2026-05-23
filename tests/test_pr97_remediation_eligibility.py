import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _scene(containers):
    return {"containers": containers}


def _sus(name, severity="high", classes=None):
    return {"name": name, "severity": severity, "confidence": "high", "classes": classes or []}


def test_eligibility_json_targets_and_safety(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene(
            [
                {
                    "name": "sfai-noisy-errors",
                    "labels": {
                        "shellforgeai.disposable": "true",
                        "shellforgeai.allow_restart": "true",
                    },
                },
                {"name": "shellforgeai", "labels": {}},
            ]
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda _: {"suspects": [_sus("sfai-noisy-errors"), _sus("shellforgeai", "critical")]},
    )
    r = runner.invoke(app, ["remediation", "eligibility", "--json"], env=_env(tmp_path))
    assert r.exit_code == 0
    p = json.loads(r.stdout)
    assert p["mode"] == "remediation_eligibility"
    assert p["safety"]["plan_created"] is False
    by = {t["name"]: t for t in p["targets"]}
    assert by["sfai-noisy-errors"]["eligibility"] == "eligible_for_plan"
    assert by["sfai-noisy-errors"]["executors"]["proof"]["ready"] is True
    assert by["sfai-noisy-errors"]["executors"]["docker-disposable"]["ready"] is True
    assert by["shellforgeai"]["eligibility"] == "blocked"
    assert "production target refused" in by["shellforgeai"]["blocked_reasons"]


def test_eligibility_missing_allow_restart_blocks_docker_disposable(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene(
            [{"name": "sfai-noisy-errors", "labels": {"shellforgeai.disposable": "true"}}]
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda _: {"suspects": [_sus("sfai-noisy-errors")]},
    )
    r = runner.invoke(app, ["remediation", "eligibility", "--json"], env=_env(tmp_path))
    assert r.exit_code == 1
    t = json.loads(r.stdout)["targets"][0]
    assert t["executors"]["proof"]["ready"] is True
    assert t["executors"]["docker-disposable"]["ready"] is False
    assert "target missing allowlist labels" in t["blocked_reasons"]


def test_eligibility_target_specific_and_broad_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _scene([]))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", lambda _: {"suspects": []})
    broad = runner.invoke(
        app, ["remediation", "eligibility", "--target", "*", "--json"], env=_env(tmp_path)
    )
    assert broad.exit_code == 1
    bp = json.loads(broad.stdout)
    assert bp["status"] == "blocked"

    one = runner.invoke(
        app, ["remediation", "eligibility", "--target", "missing", "--json"], env=_env(tmp_path)
    )
    assert one.exit_code == 1
    op = json.loads(one.stdout)
    assert op["targets"][0]["name"] == "missing"
    assert "target not found" in op["targets"][0]["blocked_reasons"]


def test_eligibility_empty_and_human_output(tmp_path, monkeypatch):
    monkeypatch.setattr("shellforgeai.core.triage_ranking.collect_scene", lambda: _scene([]))
    monkeypatch.setattr("shellforgeai.core.triage_ranking.rank_scene", lambda _: {"suspects": []})
    rj = runner.invoke(app, ["remediation", "eligibility", "--json"], env=_env(tmp_path))
    assert rj.exit_code == 0
    assert json.loads(rj.stdout)["status"] == "empty"

    rh = runner.invoke(app, ["remediation", "eligibility"], env=_env(tmp_path))
    assert "Safety:" in rh.stdout
    assert "Eligible targets:" in rh.stdout
    assert "Blocked targets:" in rh.stdout
    assert "created no plan and executed nothing" in rh.stdout
    assert "execute --confirm" not in rh.stdout


def test_eligibility_explain_json_eligible(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene(
            [
                {
                    "name": "sfai-pr97-eligible",
                    "labels": {
                        "shellforgeai.disposable": "true",
                        "shellforgeai.allow_restart": "true",
                        "shellforgeai.scenario": "sfai-noisy-errors",
                    },
                }
            ]
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda _: {"suspects": [_sus("sfai-pr97-eligible")]},
    )
    r = runner.invoke(
        app,
        ["remediation", "eligibility", "--target", "sfai-pr97-eligible", "--explain", "--json"],
        env=_env(tmp_path),
    )
    assert r.exit_code == 0
    p = json.loads(r.stdout)
    assert p["mode"] == "remediation_eligibility_explain"
    assert p["eligibility"]["state"] == "eligible_for_plan"
    assert p["labels"]["found"]["shellforgeai.allow_restart"] == "true"
    assert p["suggested_plan_command"].startswith("shellforgeai remediation plan --target")
    assert "execute --confirm" not in r.stdout
    assert p["safety"]["plan_created"] is False


def test_eligibility_explain_blocked_and_human_safety(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene(
            [{"name": "sfai-noisy-errors", "labels": {"shellforgeai.disposable": "true"}}]
        ),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda _: {"suspects": [_sus("sfai-noisy-errors")]},
    )
    rj = runner.invoke(
        app,
        ["remediation", "eligibility", "--target", "sfai-noisy-errors", "--explain", "--json"],
        env=_env(tmp_path),
    )
    assert rj.exit_code == 1
    pj = json.loads(rj.stdout)
    assert pj["labels"]["missing"] == ["shellforgeai.allow_restart=true"]
    assert any(
        g["name"] == "docker_disposable_executor_ready" and g["status"] == "blocked"
        for g in pj["gates"]
    )
    assert "allow_restart=true" in pj["what_would_make_eligible"][0]
    rh = runner.invoke(
        app,
        ["remediation", "eligibility", "--target", "sfai-noisy-errors", "--explain"],
        env=_env(tmp_path),
    )
    assert "Safety:" in rh.stdout
    assert "Labels found:" in rh.stdout
    assert "Gates:" in rh.stdout
    assert "Blocking reasons:" in rh.stdout
    assert "What would make this eligible:" in rh.stdout
    assert "no plan was created" in rh.stdout
    assert "no remediation was executed" in rh.stdout
    assert "execute --confirm" not in rh.stdout


def test_eligibility_explain_production_guidance(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _scene([{"name": "shellforgeai", "labels": {}}]),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene",
        lambda _: {"suspects": [_sus("shellforgeai", "critical")]},
    )
    r = runner.invoke(
        app,
        ["remediation", "eligibility", "--target", "shellforgeai", "--explain", "--json"],
        env=_env(tmp_path),
    )
    p = json.loads(r.stdout)
    assert r.exit_code == 1
    assert "production target refused" in p["eligibility"]["blocked_reasons"]
    assert "allow_restart" not in " ".join(p["what_would_make_eligible"]).lower()
