from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "docker01_ownership_fix_readiness.py"
spec = importlib.util.spec_from_file_location("docker01_ownership_fix_readiness_pr284", SCRIPT_PATH)
assert spec and spec.loader
readiness = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = readiness
spec.loader.exec_module(readiness)


def dockerfile(tmp_path: Path, text: str | None = None) -> Path:
    p = tmp_path / "Dockerfile"
    p.write_text(
        text if text is not None else f"FROM scratch\nRUN {readiness.BROAD_CHOWN_PATTERN}\n",
        encoding="utf-8",
    )
    return p


def recipe(tmp_path: Path, extra: str = "") -> Path:
    p = tmp_path / "recipe.py"
    p.write_text(
        "CONFIRMATION='CONFIRM'\n# --apply write gate\n# backup receipt\n" + extra,
        encoding="utf-8",
    )
    return p


def report(
    tmp_path: Path, df: Path | None = None, rp: Path | None = None, health: Path | None = None
):
    return readiness.build_report(
        df or dockerfile(tmp_path), health_json=health, recipe_script=rp or recipe(tmp_path)
    )


def test_json_output_emits_schema_mode_status_read_only_and_safety(tmp_path, capsys):
    df = dockerfile(tmp_path)
    rp = recipe(tmp_path)
    assert readiness.main(["--dockerfile", str(df), "--recipe-script", str(rp), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["mode"] == "docker01_ownership_fix_readiness"
    assert payload["status"] in {"attention", "blocked", "unknown"}
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert all(v is False for k, v in payload["safety"].items() if k != "read_only")


def test_markdown_output_is_deterministic_and_includes_readiness(tmp_path, capsys):
    df = dockerfile(tmp_path)
    rp = recipe(tmp_path)
    args = ["--dockerfile", str(df), "--recipe-script", str(rp), "--markdown"]
    assert readiness.main(args) == 0
    first = capsys.readouterr().out
    assert readiness.main(args) == 0
    assert capsys.readouterr().out == first
    assert "Readiness status" in first
    assert "This helper did not modify the Dockerfile and did not execute the recipe." in first


def test_out_json_and_out_markdown_write_only_when_requested(tmp_path, capsys):
    df = dockerfile(tmp_path)
    rp = recipe(tmp_path)
    out_json = tmp_path / "out.json"
    out_md = tmp_path / "out.md"
    assert (
        readiness.main(
            ["--dockerfile", str(df), "--recipe-script", str(rp), "--out-json", str(out_json)]
        )
        == 0
    )
    assert json.loads(out_json.read_text())["mode"] == readiness.MODE
    assert capsys.readouterr().out == ""
    assert not out_md.exists()
    assert (
        readiness.main(
            ["--dockerfile", str(df), "--recipe-script", str(rp), "--out-markdown", str(out_md)]
        )
        == 0
    )
    assert "Readiness status" in out_md.read_text()


def test_missing_output_mode_fails_cleanly(tmp_path, capsys):
    assert readiness.main(["--dockerfile", str(dockerfile(tmp_path))]) == 2
    assert "select at least one output mode" in capsys.readouterr().err


def test_broad_chown_detected_and_absent(tmp_path):
    assert report(tmp_path)["dockerfile"]["broad_recursive_ownership_layer"]["detected"] is True
    payload = report(
        tmp_path, df=dockerfile(tmp_path, "FROM scratch\nRUN chown appuser /opt/app\n")
    )
    assert payload["dockerfile"]["broad_recursive_ownership_layer"]["detected"] is False
    assert payload["readiness"]["status"] == "attention"
    assert "no_broad_chown_detected" in payload["readiness"]["reasons"]


def test_missing_and_unreadable_dockerfile_report_cleanly(tmp_path, monkeypatch):
    missing = tmp_path / "missing.Dockerfile"
    payload = report(tmp_path, df=missing)
    assert payload["readiness"]["status"] == "blocked"
    assert payload["dockerfile"]["status"] == "not_found"
    df = dockerfile(tmp_path)
    orig = Path.read_text

    def blocked(self, *a, **kw):
        if self == df:
            raise PermissionError("blocked")
        return orig(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", blocked)
    payload = report(tmp_path, df=df)
    assert payload["dockerfile"]["status"] == "unreadable"
    assert payload["readiness"]["status"] == "blocked"


def test_recipe_ready_missing_and_explicit_missing(tmp_path):
    assert report(tmp_path)["readiness"]["status"] == "ready"
    missing = tmp_path / "missing_recipe.py"
    payload = report(tmp_path, rp=missing)
    assert payload["recipe"]["status"] == "not_found"
    assert payload["recipe"]["explicit"] is True
    assert payload["readiness"]["status"] == "blocked"


def test_recipe_missing_static_markers_block(tmp_path):
    cases = {
        "confirmation_required": "# --apply\n# backup receipt\n",
        "apply_flag_present": "CONFIRMATION='CONFIRM'\n# backup receipt\n",
        "backup_or_receipt_present": "CONFIRMATION='CONFIRM'\n# --apply\n",
    }
    for check, text in cases.items():
        rp = tmp_path / f"{check}.py"
        rp.write_text(text, encoding="utf-8")
        payload = report(tmp_path, rp=rp)
        assert payload["readiness"]["status"] == "blocked"
        assert f"recipe_static_check_failed:{check}" in payload["readiness"]["reasons"]


def test_recipe_unsafe_command_markers_block(tmp_path):
    cases = {
        "docker_build_absent": 'subprocess.run(["docker", "build", "."])\n',
        "docker_compose_mutation_absent": 'subprocess.run(["docker", "compose", "up", "-d"])\n',
        "docker_prune_absent": 'subprocess.run(["docker", "system", "prune"])\n',
        "docker_remove_absent": 'subprocess.run(["docker", "rmi", "image"])\n',
        "service_restart_absent": 'subprocess.run(["systemctl", "restart", "nginx"])\n',
        "process_kill_absent": 'subprocess.run(["kill", "123"])\n',
        "shell_true_absent": "# shell=True",
    }
    for check, extra in cases.items():
        payload = report(tmp_path, rp=recipe(tmp_path, extra))
        assert payload["recipe"]["static_checks"][check] is False
        assert payload["readiness"]["status"] == "blocked"


def test_health_json_attention_and_broad_chown_reflected(tmp_path):
    h = tmp_path / "health.json"
    h.write_text(
        json.dumps(
            {
                "mode": "docker01_build_health_report",
                "readiness": {"status": "attention", "reasons": ["io"]},
                "known_risks": {"broad_recursive_ownership_layer": {"detected": True}},
                "dockerfile": {"selected_path": "/x/Dockerfile"},
            }
        ),
        encoding="utf-8",
    )
    payload = report(tmp_path, health=h)
    assert payload["health_report"]["status"] == "valid"
    assert payload["health_report"]["readiness_status"] == "attention"
    assert payload["health_report"]["broad_chown_risk"]["detected"] is True
    assert payload["readiness"]["status"] == "attention"


def test_invalid_health_json_is_deterministic(tmp_path):
    h = tmp_path / "health.json"
    h.write_text("{", encoding="utf-8")
    payload = report(tmp_path, health=h)
    assert payload["health_report"]["status"] == "invalid"
    assert "health_json_invalid" in payload["readiness"]["reasons"]


def test_source_safety_no_execution_or_forbidden_integrations():
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = [
        "subprocess",
        "docker build",
        "docker prune",
        "docker rm",
        "docker rmi",
        "volume rm",
        "docker compose up",
        "docker compose down",
        "restart",
        "kill",
        "cleanup",
        "remediation",
        "rollback",
        "recovery",
        "shell=True",
        "Proxmox",
        "QGA",
        "PowerShell",
        "WinRM",
        "eval(",
        "exec(",
    ]
    for token in forbidden:
        if token in source:
            assert token in {
                "subprocess",
                "docker prune",
                "docker rm",
                "docker rmi",
                "volume rm",
                "restart",
                "kill",
                "cleanup",
                "remediation",
                "rollback",
                "recovery",
            }
    for node in ast.walk(tree):
        assert not (
            isinstance(node, ast.Import) and any(alias.name == "subprocess" for alias in node.names)
        )
        assert not (isinstance(node, ast.ImportFrom) and node.module == "subprocess")
        assert not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec"}
        )
