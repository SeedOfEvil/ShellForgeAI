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


def test_self_test_standard_and_fail_on_warn(tmp_path):
    r = runner.invoke(
        app, ["remediation", "self-test", "--profile", "standard", "--json"], env=_env(tmp_path)
    )
    assert r.exit_code == 0
    p = json.loads(r.stdout)
    assert p["summary"]["passed"] >= 2
    assert p["summary"]["skipped"] >= 1
    assert p["summary"]["passed"] + p["summary"]["failed"] == len(p["checks"])

    rw = runner.invoke(
        app,
        ["remediation", "self-test", "--profile", "full", "--json", "--fail-on-warn"],
        env=_env(tmp_path),
    )
    assert rw.exit_code == 1
    pw = json.loads(rw.stdout)
    assert pw["warnings"]
    assert pw["ci_status"] == "failed_on_warn"


def test_self_test_invalid_profile(tmp_path):
    r = runner.invoke(app, ["remediation", "self-test", "--profile", "nope"], env=_env(tmp_path))
    assert r.exit_code != 0
