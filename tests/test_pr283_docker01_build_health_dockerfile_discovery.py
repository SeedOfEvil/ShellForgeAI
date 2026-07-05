from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "docker01_build_health_report.py"
spec = importlib.util.spec_from_file_location("docker01_build_health_report_pr283", SCRIPT_PATH)
assert spec and spec.loader
report = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = report
spec.loader.exec_module(report)


def usage_fn(_path: Path):
    return shutil._ntuple_diskusage(1000, 100, 900)


def fake_docker():
    return {
        "docker_available": True,
        "docker_info_available": True,
        "system_df_available": True,
        "buildkit_indicators": [],
        "read_only_commands": [],
    }


def build(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, dockerfile: Path | None = None):
    monkeypatch.setattr(report, "run_read_only_docker_commands", fake_docker)
    docker_root = tmp_path / "docker-root"
    docker_root.mkdir(exist_ok=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return report.build_report(
        docker_root=docker_root,
        workspace=workspace,
        dockerfile=dockerfile,
        proc_root=tmp_path / "proc",
        usage_fn=usage_fn,
    )


def isolate_candidates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    workspace = tmp_path / "workspace-src"
    workspace.mkdir()
    compose = tmp_path / "compose" / "Dockerfile"
    compose.parent.mkdir()
    monkeypatch.setattr(report, "REPO_ROOT", repo)
    monkeypatch.setattr(report, "DEFAULT_WORKSPACE", workspace)
    monkeypatch.setattr(report, "COMPOSE_PROJECT_DOCKERFILE", compose)
    return repo, workspace, compose


def test_explicit_dockerfile_path_is_selected_when_exists(tmp_path, monkeypatch):
    isolate_candidates(monkeypatch, tmp_path)
    explicit = tmp_path / "explicit.Dockerfile"
    explicit.write_text(f"FROM scratch\nRUN {report.BROAD_CHOWN_PATTERN}\n", encoding="utf-8")
    payload = build(monkeypatch, tmp_path, dockerfile=explicit)
    assert payload["dockerfile"]["status"] == "found"
    assert payload["dockerfile"]["selected_path"] == str(explicit)
    assert payload["dockerfile"]["source"] == "explicit"
    assert payload["known_risks"]["broad_recursive_ownership_layer"]["detected"] is True
    assert payload["known_risks"]["broad_recursive_ownership_layer"]["path"] == str(explicit)


def test_explicit_dockerfile_missing_reports_not_found(tmp_path, monkeypatch):
    isolate_candidates(monkeypatch, tmp_path)
    missing = tmp_path / "missing.Dockerfile"
    payload = build(monkeypatch, tmp_path, dockerfile=missing)
    assert payload["dockerfile"]["status"] == "not_found"
    assert payload["dockerfile"]["selected_path"] is None
    assert payload["dockerfile"]["candidates_checked"][0]["path"] == str(missing)


def test_explicit_dockerfile_unreadable_reports_unreadable(tmp_path, monkeypatch):
    isolate_candidates(monkeypatch, tmp_path)
    explicit = tmp_path / "unreadable.Dockerfile"
    explicit.write_text("FROM scratch\n", encoding="utf-8")
    original_open = Path.open

    def blocked(self, *args, **kwargs):
        if self == explicit:
            raise PermissionError("blocked")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", blocked)
    payload = build(monkeypatch, tmp_path, dockerfile=explicit)
    assert payload["dockerfile"]["status"] == "unreadable"
    assert payload["dockerfile"]["selected_path"] is None


def test_cwd_compose_and_workspace_priority_order(tmp_path, monkeypatch):
    repo, workspace, compose = isolate_candidates(monkeypatch, tmp_path)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    cwd_dockerfile = cwd / "Dockerfile"
    cwd_dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    compose.write_text("FROM scratch\n", encoding="utf-8")
    (repo / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (workspace / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    payload = build(monkeypatch, tmp_path)
    assert payload["dockerfile"]["status"] == "ambiguous"
    assert payload["dockerfile"]["selected_path"] == str(cwd_dockerfile)
    assert [c["source"] for c in payload["dockerfile"]["candidates_checked"]] == [
        "cwd",
        "compose_project",
        "repo_root",
        "workspace",
    ]
    cwd_dockerfile.unlink()
    assert build(monkeypatch, tmp_path)["dockerfile"]["selected_path"] == str(compose)
    compose.unlink()
    assert build(monkeypatch, tmp_path)["dockerfile"]["selected_path"] == str(repo / "Dockerfile")
    (repo / "Dockerfile").unlink()
    assert build(monkeypatch, tmp_path)["dockerfile"]["selected_path"] == str(
        workspace / "Dockerfile"
    )


def test_json_and_markdown_include_discovery_fields(tmp_path, monkeypatch, capsys):
    isolate_candidates(monkeypatch, tmp_path)
    explicit = tmp_path / "Dockerfile"
    explicit.write_text("FROM scratch\n", encoding="utf-8")
    assert report.main(["--dockerfile", str(explicit), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dockerfile"]["selected_path"] == str(explicit)
    assert payload["dockerfile"]["source"] == "explicit"
    assert payload["dockerfile"]["candidates_checked"]
    assert report.main(["--dockerfile", str(explicit), "--markdown"]) == 0
    md = capsys.readouterr().out
    assert "Selected Dockerfile path" in md
    assert str(explicit) in md
    assert "Candidates checked" in md


def test_broad_chown_pattern_detected_and_absent(tmp_path, monkeypatch):
    isolate_candidates(monkeypatch, tmp_path)
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(f"RUN {report.BROAD_CHOWN_PATTERN}\n", encoding="utf-8")
    assert (
        build(monkeypatch, tmp_path, dockerfile=dockerfile)["dockerfile"]["risk"][
            "broad_recursive_ownership_layer"
        ]["detected"]
        is True
    )
    dockerfile.write_text("RUN chown appuser /opt/app\n", encoding="utf-8")
    assert (
        build(monkeypatch, tmp_path, dockerfile=dockerfile)["dockerfile"]["risk"][
            "broad_recursive_ownership_layer"
        ]["detected"]
        is False
    )


def test_missing_all_candidates_not_found_no_crash(tmp_path, monkeypatch):
    isolate_candidates(monkeypatch, tmp_path)
    monkeypatch.chdir(tmp_path)
    payload = build(monkeypatch, tmp_path)
    assert payload["dockerfile"]["status"] == "not_found"
    assert payload["readiness"]["status"] == "unknown"


def test_source_safety_no_recursive_scan_shell_or_mutation_strings():
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert ".rglob(" not in source
    assert ".glob(" not in source
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
        ):
            assert any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                for kw in node.keywords
            )
    lowered = source.lower()
    forbidden = [
        "docker build ",
        "docker prune",
        "docker rm",
        "docker rmi",
        "volume rm",
        "docker restart",
        "docker compose up",
        "docker compose down",
        "docker kill",
        "cleanup_execute(",
        "remediation_execute(",
        "rollback_execute(",
        "recovery_execute(",
        "proxmox",
        "qga",
        "powershell",
        "winrm",
        "eval(",
        "exec(",
    ]
    for token in forbidden:
        assert token not in lowered
