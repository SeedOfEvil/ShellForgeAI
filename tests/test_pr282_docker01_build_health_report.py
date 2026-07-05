from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "docker01_build_health_report.py"
spec = importlib.util.spec_from_file_location("docker01_build_health_report", SCRIPT_PATH)
assert spec and spec.loader
report = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = report
spec.loader.exec_module(report)


def usage(total: int, free: int):
    return shutil._ntuple_diskusage(total, total - free, free)


def usage_fn(percent: float):
    def _usage(_path: Path):
        total = 1000
        free = int(total * (100 - percent) / 100)
        return usage(total, free)

    return _usage


def fake_docker():
    return {
        "docker_available": True,
        "docker_info_available": True,
        "system_df_available": True,
        "buildkit_indicators": [],
        "read_only_commands": [],
    }


def make_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    disk_percent: float = 10.0,
    dockerfile_text: str | None = "FROM scratch\n",
    proc: Path | None = None,
):
    monkeypatch.setattr(report, "run_read_only_docker_commands", fake_docker)
    dockerfile = tmp_path / "Dockerfile"
    if dockerfile_text is not None:
        dockerfile.write_text(dockerfile_text, encoding="utf-8")
    docker_root = tmp_path / "docker-root"
    workspace = tmp_path / "workspace"
    docker_root.mkdir()
    workspace.mkdir()
    return report.build_report(
        docker_root=docker_root,
        workspace=workspace,
        dockerfile=dockerfile,
        proc_root=proc or tmp_path / "missing-proc",
        usage_fn=usage_fn(disk_percent),
    )


def test_json_report_contract(tmp_path, monkeypatch):
    payload = make_report(tmp_path, monkeypatch)
    assert payload["schema_version"] == 1
    assert payload["mode"] == "docker01_build_health_report"
    assert payload["status"] == "ok"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_safety_flags_are_false_for_mutation_actions(tmp_path, monkeypatch):
    safety = make_report(tmp_path, monkeypatch)["safety"]
    assert safety["read_only"] is True
    false_flags = {key: value for key, value in safety.items() if key != "read_only"}
    assert false_flags
    assert all(value is False for value in false_flags.values())


def test_markdown_output_is_deterministic_and_includes_readiness(tmp_path, monkeypatch):
    payload = make_report(tmp_path, monkeypatch)
    first = report.render_markdown(payload)
    second = report.render_markdown(payload)
    assert first == second
    assert "Readiness status: `ok`" in first


def test_output_files_only_when_explicitly_requested(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    original_build_report = report.build_report

    def _stable_report():
        monkeypatch.setattr(report, "build_report", original_build_report)
        payload = make_report(tmp_path, monkeypatch)
        payload["host"] = {"hostname": "h", "platform": "p", "cwd": str(tmp_path)}
        return payload

    monkeypatch.setattr(report, "build_report", _stable_report)
    out_json = tmp_path / "health.json"
    out_md = tmp_path / "health.md"
    assert report.main(["--out-json", str(out_json), "--out-markdown", str(out_md)]) == 0
    assert json.loads(out_json.read_text(encoding="utf-8"))["mode"] == report.MODE
    assert "Docker01 build lane health report" in out_md.read_text(encoding="utf-8")
    assert capsys.readouterr().out == ""


def test_missing_output_mode_fails_cleanly():
    with pytest.raises(SystemExit) as exc:
        report.main([])
    assert exc.value.code == 2


def test_high_root_disk_usage_produces_attention(tmp_path, monkeypatch):
    payload = make_report(tmp_path, monkeypatch, disk_percent=90.0)
    assert payload["readiness"]["status"] == "attention"
    assert "root_disk_used_percent_high" in payload["readiness"]["reasons"]


def test_high_docker_root_usage_produces_attention(tmp_path, monkeypatch):
    calls = []

    def _usage(path: Path):
        calls.append(path)
        return usage(1000, 100) if "docker-root" in str(path) else usage(1000, 900)

    monkeypatch.setattr(report, "run_read_only_docker_commands", fake_docker)
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n")
    docker_root = tmp_path / "docker-root"
    docker_root.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = report.build_report(
        docker_root=docker_root,
        workspace=workspace,
        dockerfile=dockerfile,
        proc_root=tmp_path / "proc",
        usage_fn=_usage,
    )
    assert payload["readiness"]["status"] == "attention"
    assert "docker_root_disk_used_percent_high" in payload["readiness"]["reasons"]


def test_missing_docker_root_path_is_unknown_not_crash(tmp_path, monkeypatch):
    payload = make_report(tmp_path, monkeypatch)
    missing = tmp_path / "missing-docker-root"
    monkeypatch.setattr(report, "run_read_only_docker_commands", fake_docker)
    payload = report.build_report(
        docker_root=missing,
        workspace=tmp_path,
        dockerfile=tmp_path / "Dockerfile",
        proc_root=tmp_path / "proc",
        usage_fn=usage_fn(10),
    )
    assert payload["filesystem"]["docker_root"]["available"] is False
    assert payload["readiness"]["status"] in {"ok", "unknown"}


def test_dockerfile_chown_pattern_detection(tmp_path, monkeypatch):
    payload = make_report(
        tmp_path, monkeypatch, dockerfile_text=f"RUN {report.BROAD_CHOWN_PATTERN}\n"
    )
    assert payload["known_risks"]["broad_recursive_ownership_layer"]["detected"] is True
    assert payload["readiness"]["status"] == "attention"


def test_dockerfile_without_chown_pattern_not_flagged(tmp_path, monkeypatch):
    payload = make_report(tmp_path, monkeypatch, dockerfile_text="RUN chown appuser /opt/app\n")
    assert payload["known_risks"]["broad_recursive_ownership_layer"]["detected"] is False


def test_missing_dockerfile_unknown_not_crash(tmp_path, monkeypatch):
    payload = make_report(tmp_path, monkeypatch, dockerfile_text=None)
    assert payload["known_risks"]["dockerfile"]["available"] is False
    assert payload["readiness"]["status"] == "unknown"


def write_proc(root: Path, pid: str, name: str, state: str, cmdline: str):
    p = root / pid
    p.mkdir(parents=True)
    (p / "comm").write_text(name, encoding="utf-8")
    (p / "cmdline").write_text(cmdline.replace(" ", "\x00"), encoding="utf-8")
    (p / "status").write_text(f"Name:\t{name}\nState:\t{state}\n", encoding="utf-8")


def test_process_scan_detects_build_related_and_d_state(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    write_proc(proc, "123", "docker", "S (sleeping)", "docker buildx ls")
    write_proc(proc, "124", "chown", "D (disk sleep)", "chown -R appuser /data")
    payload = make_report(tmp_path, monkeypatch, proc=proc)
    assert payload["processes"]["count"] == 2
    assert len(payload["processes"]["possible_stuck_io"]) == 1
    assert payload["readiness"]["status"] == "blocked"


def test_docker_cli_failure_and_timeout_are_warnings(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/docker")

    def fake_run(argv, **kwargs):
        if argv[:2] == ["docker", "info"]:
            raise subprocess.TimeoutExpired(argv, 1, output="", stderr="slow")
        return SimpleNamespace(returncode=1, stdout="", stderr="failed")

    monkeypatch.setattr(subprocess, "run", fake_run)
    payload = report.run_read_only_docker_commands(timeout=1)
    assert any(item["reason"] == "timeout" for item in payload["read_only_commands"])
    assert payload["buildkit_indicators"]


def test_source_safety_invariants():
    source = Path(report.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
        ):
            for kw in node.keywords:
                if kw.arg == "shell":
                    assert isinstance(kw.value, ast.Constant) and kw.value.value is False
    forbidden = [
        "docker build",
        "docker compose",
        "docker prune",
        "docker rm",
        "docker rmi",
        "docker restart",
        "docker kill",
        "docker stop",
        "docker start",
        "pip install",
        "pytest",
        "powershell",
        "winrm",
        "proxmox",
        "qga",
        "model",
        "auth-cache",
        "secret",
        "cleanup_execute(",
        "remediation_execute(",
        "rollback_execute(",
        "recovery_execute(",
        "eval(",
        "exec(",
    ]
    lowered = source.lower()
    for token in forbidden:
        assert token not in lowered
    for spec in report.ALLOWED_DOCKER_COMMANDS:
        assert spec.argv[:1] == ("docker",)
        assert not any(
            part in {"build", "compose", "prune", "rm", "rmi", "restart", "up", "down", "kill"}
            for part in spec.argv
        )
