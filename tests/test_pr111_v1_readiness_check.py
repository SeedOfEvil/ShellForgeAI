import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def test_v1_check_profiles_json(tmp_path, monkeypatch):
    def _fast_readiness(_app, profile="standard"):
        return {
            "schema_version": 1,
            "mode": "v1_readiness_check",
            "profile": profile,
            "status": "ok",
            "ci_status": "passed",
            "summary": {"passed": 1, "failed": 0, "warned": 0, "skipped": 0},
            "checks": [
                {
                    "name": "command_surface_version",
                    "status": "passed",
                    "message": "version surface",
                    "mutation": False,
                }
            ],
            "warnings": [],
            "skipped": [],
            "safety": {"read_only": True, "mutation_performed": False},
            "next_safe_commands": ["shellforgeai doctor --json"],
        }

    monkeypatch.setattr("shellforgeai.core.v1_readiness.run_v1_readiness_check", _fast_readiness)

    for profile in ("quick", "standard", "full"):
        r = runner.invoke(app, ["v1", "check", "--profile", profile, "--json"], env=_env(tmp_path))
        assert r.exit_code in {0, 1}
        p = json.loads(r.stdout)
        assert p["schema_version"] == 1
        assert p["mode"] == "v1_readiness_check"
        assert p["profile"] == profile
        assert "summary" in p and "checks" in p and "safety" in p
        assert isinstance(p["checks"], list)
        for check in p["checks"]:
            assert {"name", "status", "message", "mutation"}.issubset(check.keys())
            assert check["mutation"] is False


def test_v1_check_quick_exit_zero(tmp_path):
    r = runner.invoke(app, ["v1", "check", "--profile", "quick"], env=_env(tmp_path))
    assert r.exit_code == 0


def test_v1_check_invalid_profile(tmp_path):
    r = runner.invoke(app, ["v1", "check", "--profile", "nope", "--json"], env=_env(tmp_path))
    assert r.exit_code == 1


def test_v1_check_fail_on_warn(tmp_path, monkeypatch):
    def _fake(_app, profile="standard"):
        return {
            "schema_version": 1,
            "mode": "v1_readiness_check",
            "profile": profile,
            "status": "warn",
            "ci_status": "failed_on_warn",
            "summary": {"passed": 1, "failed": 0, "warned": 1, "skipped": 0},
            "checks": [{"name": "x", "status": "warned", "message": "w", "mutation": False}],
            "warnings": ["w"],
            "skipped": [],
            "safety": {"mutation_performed": False},
            "next_safe_commands": ["shellforgeai doctor --json"],
        }

    monkeypatch.setattr("shellforgeai.core.v1_readiness.run_v1_readiness_check", _fake)
    r = runner.invoke(app, ["v1", "check", "--fail-on-warn", "--json"], env=_env(tmp_path))
    assert r.exit_code == 1


def test_v1_check_safe_commands_are_canonical(tmp_path):
    r = runner.invoke(app, ["v1", "check", "--profile", "quick", "--json"], env=_env(tmp_path))
    p = json.loads(r.stdout)
    allowed = {
        "shellforgeai doctor --json",
        "shellforgeai model doctor --json",
        "shellforgeai ops report --json",
        "shellforgeai remediation self-test --profile standard --json",
    }
    assert set(p["next_safe_commands"]).issubset(allowed)
