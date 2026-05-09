import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def test_diagnose_nginx_json_stdout_parses() -> None:
    res = runner.invoke(app, ["diagnose", "nginx", "--json"])
    assert res.exit_code == 0
    json.loads(res.stdout)


def test_diagnose_disk_json_stdout_parses() -> None:
    res = runner.invoke(app, ["diagnose", "disk", "--json"])
    assert res.exit_code == 0
    payload = json.loads(res.stdout)
    assert "evidence" in payload


def test_diagnose_performance_json_stdout_parses() -> None:
    res = runner.invoke(app, ["diagnose", "performance", "--json"])
    assert res.exit_code == 0
    json.loads(res.stdout)
