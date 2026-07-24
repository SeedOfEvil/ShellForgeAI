from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import v1_resource_resolution as resolver
from shellforgeai.core.v1_resource_resolution import (
    REQUIRED_V1_CONTRACT_RESOURCES,
    resolve_v1_contract_resource_root,
)


def _make_contract(root: Path) -> None:
    for rel in REQUIRED_V1_CONTRACT_RESOURCES:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"contract {rel}\n", encoding="utf-8")


def _make_imported_package(root: Path) -> Path:
    package = root / "src" / "shellforgeai"
    package.mkdir(parents=True)
    return package


def _patch_package(monkeypatch: pytest.MonkeyPatch, package: Path) -> None:
    monkeypatch.setattr(resolver, "files", lambda _name: package)


def _docs_check(payload: dict[str, object]) -> dict[str, object]:
    return next(c for c in payload["checks"] if c["name"] == "docs_v1_contract_present")


def test_imported_source_root_wins_from_repo_unrelated_and_system32_shaped_cwds(
    tmp_path, monkeypatch
):
    imported_root = tmp_path / "source-a"
    _make_contract(imported_root)
    package = _make_imported_package(imported_root)
    _patch_package(monkeypatch, package)

    for cwd in (imported_root, tmp_path / "ordinary", tmp_path / "C" / "Windows" / "System32"):
        cwd.mkdir(parents=True, exist_ok=True)
        result = resolve_v1_contract_resource_root(cwd=cwd)
        assert result.resolved is True
        assert result.root == imported_root
        assert result.source == "imported_package_source_root"
        assert result.cwd_independent is True
        assert result.missing_resources == ()


def test_v1_quick_and_standard_are_cwd_independent(tmp_path, monkeypatch):
    imported_root = tmp_path / "source-a"
    _make_contract(imported_root)
    package = _make_imported_package(imported_root)
    _patch_package(monkeypatch, package)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)

    runner = CliRunner()
    for profile in ("quick", "standard"):
        result = runner.invoke(app, ["v1", "check", "--profile", profile, "--json"])
        assert result.exit_code == 0
        check = _docs_check(json.loads(result.stdout))
        assert check["status"] == "passed"
        assert check["evidence"]["source"] == "imported_package_source_root"
        assert check["evidence"]["cwd_independent"] is True


def test_fake_or_different_cwd_cannot_override_valid_imported_root(tmp_path, monkeypatch):
    imported_root = tmp_path / "source-a"
    _make_contract(imported_root)
    package = _make_imported_package(imported_root)
    _patch_package(monkeypatch, package)
    fake_cwd = tmp_path / "source-b"
    _make_contract(fake_cwd)
    (fake_cwd / "README.md").write_text("fake checkout\n", encoding="utf-8")

    result = resolve_v1_contract_resource_root(cwd=fake_cwd)

    assert result.resolved is True
    assert result.root == imported_root
    assert result.source == "imported_package_source_root"


def test_invalid_imported_candidate_can_fall_through_to_valid_cwd(tmp_path, monkeypatch):
    invalid_root = tmp_path / "invalid"
    package = _make_imported_package(invalid_root)
    _patch_package(monkeypatch, package)
    cwd = tmp_path / "valid-cwd"
    _make_contract(cwd)

    result = resolve_v1_contract_resource_root(cwd=cwd)

    assert result.resolved is True
    assert result.root == cwd.resolve()
    assert result.source == "current_working_directory"
    assert result.cwd_independent is False


def test_unresolved_reports_exact_missing_resources(tmp_path, monkeypatch):
    invalid_root = tmp_path / "invalid"
    package = _make_imported_package(invalid_root)
    _patch_package(monkeypatch, package)
    cwd = tmp_path / "partial"
    cwd.mkdir()
    (cwd / "README.md").write_text("partial\n", encoding="utf-8")
    (cwd / "docs").mkdir()

    result = resolve_v1_contract_resource_root(cwd=cwd)

    assert result.resolved is False
    assert result.source == "unresolved"
    assert result.error_class == "v1_contract_resources_not_resolved"
    assert result.missing_resources == tuple(
        r for r in REQUIRED_V1_CONTRACT_RESOURCES if r != "README.md"
    )
    assert result.checked_sources[-1] == "unresolved"


def test_checked_sources_are_deterministic(tmp_path, monkeypatch):
    package = _make_imported_package(tmp_path / "invalid")
    _patch_package(monkeypatch, package)
    cwd = tmp_path / "empty"
    cwd.mkdir()

    first = resolve_v1_contract_resource_root(cwd=cwd).evidence()
    second = resolve_v1_contract_resource_root(cwd=cwd).evidence()

    assert first == second
    assert first["checked_sources"] == [
        "imported_package_source_root",
        "imported_package_source_root",
        "imported_package_source_root",
        "python_executable_lineage",
        "python_executable_lineage",
        "current_working_directory",
        "unresolved",
    ]


def test_resolver_avoids_broad_search_and_side_effect_apis(monkeypatch, tmp_path):
    package = _make_imported_package(tmp_path / "invalid")
    _patch_package(monkeypatch, package)
    monkeypatch.setattr(os, "chdir", lambda *_args, **_kwargs: pytest.fail("os.chdir called"))
    monkeypatch.setattr(Path, "rglob", lambda *_args, **_kwargs: pytest.fail("Path.rglob called"))
    monkeypatch.setattr(Path, "glob", lambda *_args, **_kwargs: pytest.fail("Path.glob called"))
    monkeypatch.setattr(Path, "home", lambda *_args, **_kwargs: pytest.fail("Path.home called"))
    monkeypatch.setattr(
        "subprocess.run", lambda *_args, **_kwargs: pytest.fail("subprocess.run called")
    )
    writes = ("write_text", "write_bytes", "touch", "mkdir", "unlink", "rename", "replace")

    def _fail_write(method: str):
        return lambda *_args, **_kwargs: pytest.fail(f"Path.{method} called")

    for name in writes:
        monkeypatch.setattr(Path, name, _fail_write(name))

    result = resolve_v1_contract_resource_root(cwd=tmp_path / "empty")

    assert result.resolved is False


def test_public_v1_contract_shape_and_text_mode(tmp_path, monkeypatch):
    imported_root = tmp_path / "source-a"
    _make_contract(imported_root)
    _patch_package(monkeypatch, _make_imported_package(imported_root))
    runner = CliRunner()

    payload = json.loads(runner.invoke(app, ["v1", "check", "--profile", "quick", "--json"]).stdout)
    names = [c["name"] for c in payload["checks"]]
    assert names[5] == "docs_v1_contract_present"
    assert payload["profile"] == "quick"
    for key in ("read_only", "mutation_performed", "apply_executed", "arbitrary_command_execution"):
        assert key in payload["safety"]
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False

    text = runner.invoke(app, ["v1", "check", "--profile", "quick"])
    assert text.exit_code == 0
    assert "ShellForgeAI V1 readiness check" in text.stdout
    assert runner.invoke(app, ["v1", "check", "--profile", "nope", "--json"]).exit_code == 1
