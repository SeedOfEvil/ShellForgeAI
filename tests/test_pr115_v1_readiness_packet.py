import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def test_v1_packet_json_and_content(tmp_path):
    r = runner.invoke(app, ["v1", "packet", "--json"], env=_env(tmp_path))
    assert r.exit_code in {0, 1}
    p = json.loads(r.stdout)
    assert p["mode"] == "v1_readiness_packet"
    assert "docs_contract" in p["checks"]
    assert "command_surface" in p["checks"]
    assert "v1_check" in p["checks"]
    assert "ops_report" in p["checks"]
    assert "ask_routes" in p["checks"]
    assert "mutation_refusal" in p["checks"]
    assert "remediation_self_test" in p["checks"]
    assert p["safety"]["read_only"] is True
    assert p["safety"]["mutation_performed"] is False
    for cmd in p["safe_next_commands"]:
        assert "restart" not in cmd.lower()


def test_v1_packet_save_validate_export_flow(tmp_path):
    env = _env(tmp_path)
    saved = runner.invoke(app, ["v1", "packet", "--save", "--json"], env=env)
    assert saved.exit_code in {0, 1}
    sp = json.loads(saved.stdout)
    assert "packet_id" in sp and "packet_path" in sp

    r1 = runner.invoke(app, ["v1", "packet", "validate", sp["packet_id"], "--json"], env=env)
    assert json.loads(r1.stdout)["mode"] == "v1_readiness_packet_validate"

    r2 = runner.invoke(app, ["v1", "packet", "validate", sp["packet_path"], "--json"], env=env)
    assert json.loads(r2.stdout)["mode"] == "v1_readiness_packet_validate"

    ex = runner.invoke(app, ["v1", "packet", "export", sp["packet_id"], "--json"], env=env)
    ep = json.loads(ex.stdout)
    assert ep["mode"] == "v1_readiness_packet_export"

    exv = runner.invoke(
        app, ["v1", "packet", "export-validate", ep["export"]["id"], "--json"], env=env
    )
    assert json.loads(exv.stdout)["mode"] == "v1_readiness_packet_export_validate"

    ex2 = runner.invoke(app, ["v1", "packet", "export", sp["packet_id"], "--json"], env=env)
    assert json.loads(ex2.stdout)["status"] in {"exported", "already_exists"}


def test_v1_packet_error_paths_controlled(tmp_path):
    env = _env(tmp_path)
    r = runner.invoke(app, ["v1", "packet", "validate", "missing", "--json"], env=env)
    p = json.loads(r.stdout)
    assert p["status"] == "not_found"
    assert "Traceback" not in r.stdout
