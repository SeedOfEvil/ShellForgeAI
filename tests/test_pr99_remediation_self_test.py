import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def test_self_test_quick_and_json(tmp_path):
    r = runner.invoke(app, ["remediation", "self-test", "--profile", "quick"], env=_env(tmp_path))
    assert r.exit_code == 0
    assert "Disposable remediation lane self-test" in r.stdout

    rj = runner.invoke(
        app, ["remediation", "self-test", "--profile", "quick", "--json"], env=_env(tmp_path)
    )
    assert rj.exit_code == 0
    p = json.loads(rj.stdout)
    assert p["mode"] == "remediation_self_test"
    assert p["profile"] == "quick"
    assert p["safety"]["mutation_performed"] is False
    assert "execute --confirm" not in " ".join(p["next_safe_commands"])


def test_self_test_standard_and_full_profiles(tmp_path):
    r = runner.invoke(
        app, ["remediation", "self-test", "--profile", "standard", "--json"], env=_env(tmp_path)
    )
    assert r.exit_code == 0
    p = json.loads(r.stdout)
    assert p["summary"]["passed"] >= 2
    assert p["summary"]["skipped"] >= 1
    assert p["summary"]["passed"] + p["summary"]["failed"] == len(p["checks"])

    rf = runner.invoke(
        app,
        ["remediation", "self-test", "--profile", "full", "--json", "--fail-on-warn"],
        env=_env(tmp_path),
    )
    assert rf.exit_code == 0
    pf = json.loads(rf.stdout)
    assert pf["status"] == "ok"
    assert pf["warnings"] == []
    assert pf["ci_status"] == "passed"
    assert pf["safety"].get("proof_execution_performed") is True
    assert pf["safety"].get("docker_disposable_executed") is False


def test_self_test_invalid_profile(tmp_path):
    r = runner.invoke(app, ["remediation", "self-test", "--profile", "nope"], env=_env(tmp_path))
    assert r.exit_code != 0


def test_self_test_full_live_requires_target(tmp_path):
    r = runner.invoke(
        app,
        [
            "remediation",
            "self-test",
            "--profile",
            "full",
            "--include-live-disposable-execute",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert r.exit_code != 0
    p = json.loads(r.stdout)
    assert p["live_disposable_proof"]["requested"] is True
    assert p["safety"]["mutation_performed"] is False


def test_self_test_full_live_requires_confirm(tmp_path):
    r = runner.invoke(
        app,
        [
            "remediation",
            "self-test",
            "--profile",
            "full",
            "--include-live-disposable-execute",
            "--target",
            "sfai-pr103-user-sim",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert r.exit_code != 0
    p = json.loads(r.stdout)
    assert p["live_disposable_proof"]["requested"] is True
    assert p["live_disposable_proof"]["confirmed"] is False
    assert p["safety"]["mutation_performed"] is False


def test_self_test_full_live_disposable_success(tmp_path, monkeypatch):
    calls = {"count": 0}

    def _inspect(_target):
        calls["count"] += 1
        started_at = "2026-05-24T00:00:00Z" if calls["count"] == 1 else "2026-05-24T00:00:05Z"
        return {
            "name": "sfai-pr103-user-sim",
            "labels": {"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
            "StartedAt": started_at,
            "restart_count": 0 if calls["count"] == 1 else 1,
            "status": "running",
            "id": "abc",
        }

    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.inspect_exact_target_state", _inspect
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.run_exact_docker_restart",
        lambda target: (True, 0, target, ""),
    )
    r = runner.invoke(
        app,
        [
            "remediation",
            "self-test",
            "--profile",
            "full",
            "--include-live-disposable-execute",
            "--target",
            "sfai-pr103-user-sim",
            "--confirm-live-disposable",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert r.exit_code in {0, 1}
    p = json.loads(r.stdout)
    assert p["live_disposable_proof"]["requested"] is True
    assert p["live_disposable_proof"]["target"] == "sfai-pr103-user-sim"
    assert p["live_disposable_proof"]["docker_restart_attempted"] is True
    assert p["safety"]["docker_compose_executed"] is False
