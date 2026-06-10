"""PR180 — fallback packet non-execution contract + Lane B QA marker.

PR179 added the disposable validation-container fallback packet generator
(``scripts/validation_container_fallback.py``) and taught the PR177 status
viewer to surface ``fallback_packet_present``. PR180 locks that product/safety
contract down with durable regression coverage and makes targeted-only (Lane B)
validation explicit in the viewer's QA output:

1. A fallback packet may be generated when host validation tooling is missing.
2. The generated fallback command/packet is **inert data** — it is never
   executed automatically.
3. The status viewer clearly exposes ``fallback_packet_present=true``.
4. The viewer emits an explicit Lane A/B/C QA marker so reviewers know full
   ``pytest`` was intentionally not run on a targeted Lane B change.

These are process/evidence-tooling tests only. They never install packages,
never call the Docker daemon, never run Docker/Compose, never run a real
pytest/ruff, never restart/clean up/remediate/roll back anything, and never
mutate services/containers or real ``/data``. Fake evidence files, ``tmp_path``
fixtures, and monkeypatched execution boundaries are used throughout.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
FALLBACK_PATH = SCRIPTS / "validation_container_fallback.py"
VIEWER_PATH = SCRIPTS / "validation_status.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


fb = _load("pr180_validation_container_fallback", FALLBACK_PATH)
viewer = _load("pr180_validation_status", VIEWER_PATH)


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def _failed_preflight_doc(missing=("ruff", "pytest")) -> dict:
    return {
        "schema_version": 1,
        "mode": "validation_environment_preflight",
        "status": "failed",
        "classification": "setup_failure",
        "pass_eligible": False,
        "rerun_required": True,
        "failed_checks": list(missing),
        "warning_checks": [],
    }


def _setup_failure_run_dir(tmp_path: Path, *, missing=("ruff", "pytest")) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "validation-preflight.json").write_text(
        json.dumps(_failed_preflight_doc(missing)), encoding="utf-8"
    )
    return run_dir


def _fallback_source() -> str:
    return FALLBACK_PATH.read_text(encoding="utf-8")


def _viewer_args(run_dir: Path):
    return viewer.build_parser().parse_args(["--run-dir", str(run_dir), "--json"])


# --------------------------------------------------------------------------- #
# 1. Inert fallback packet on missing host tooling
# --------------------------------------------------------------------------- #
def test_setup_failure_missing_tools_creates_inert_fallback_packet(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path, missing=("ruff", "pytest"))
    report = fb.generate_packet(run_dir=run_dir)

    # setup_failure is reported, and the packet is created.
    assert report["status"] == "created"
    assert report["source"]["classification"] == "setup_failure"
    missing = report["source"]["missing_required_tools"]
    assert "ruff" in missing and "pytest" in missing
    assert report["packet"]["created"] is True
    for name in fb.PACKET_FILES:
        assert (run_dir / name).is_file(), name

    # The command lives only as inert data inside the packet object: an argv
    # list and a copy-paste string. It is never auto-executed.
    container = report["container_validation"]
    assert container["auto_execute"] is False
    assert container["operator_invoked"] is True
    assert container["host_package_install_required"] is False
    assert isinstance(container["command_argv"], list)
    assert container["command_argv"][0] == "docker"
    assert isinstance(container["command_preview"], str)

    # The on-disk argv file is pure JSON data (a list of strings), nothing more.
    argv = json.loads((run_dir / fb.FALLBACK_ARGV_NAME).read_text(encoding="utf-8"))
    assert argv == container["command_argv"]
    assert all(isinstance(token, str) for token in argv)


# --------------------------------------------------------------------------- #
# 2. The fallback command is never executed
# --------------------------------------------------------------------------- #
def _module_never_imports_execution(path: Path) -> None:
    """Assert the module imports no subprocess/os.system style execution path."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name != "subprocess" for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "subprocess"


def test_fallback_packet_generation_does_not_execute_command(tmp_path, monkeypatch):
    # Static guarantee: the generator has no subprocess capability at all.
    _module_never_imports_execution(FALLBACK_PATH)
    assert not hasattr(fb, "subprocess")

    # Runtime guarantee: trip every execution boundary so any accidental
    # subprocess/shell call during generation would fail loudly.
    def _boom(*_args, **_kwargs):  # pragma: no cover - must never be called
        raise AssertionError("fallback packet generation executed a command")

    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "call", _boom)
    monkeypatch.setattr(subprocess, "check_call", _boom)
    monkeypatch.setattr(subprocess, "check_output", _boom)
    monkeypatch.setattr(os, "system", _boom)
    monkeypatch.setattr(os, "popen", _boom)

    run_dir = _setup_failure_run_dir(tmp_path)
    report = fb.generate_packet(run_dir=run_dir)

    assert report["status"] == "created"
    assert report["safety"]["arbitrary_command_execution"] is False
    assert report["safety"]["docker_executed"] is False
    assert report["safety"]["pytest_executed"] is False
    assert report["safety"]["ruff_executed"] is False
    assert report["safety"]["validation_executed"] is False


def test_fallback_packet_generation_has_no_cleanup_or_mutation(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    safety = fb.generate_packet(run_dir=run_dir)["safety"]
    # No cleanup / remediation / rollback / recovery / restart / docker mutation.
    for flag in (
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "container_restarted",
        "docker_executed",
        "docker_compose_executed",
        "packages_installed",
        "mutation_performed",
        "shell_true",
        "natural_language_execution",
        "model_called",
    ):
        assert safety[flag] is False, flag

    # No artifact repair/delete, no model call, no shell=True in the source.
    source = _fallback_source()
    assert "shell=True" not in source
    for forbidden in ("os.remove", "os.unlink", ".unlink(", "rmtree", "shutil.rmtree"):
        assert forbidden not in source, forbidden
    for forbidden in ("import requests", "import httpx", "openai", "anthropic"):
        assert forbidden not in source, forbidden


def test_fallback_packet_writes_only_inside_run_dir(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    run_dir = _setup_failure_run_dir(tmp_path)
    before = {p.name for p in run_dir.iterdir()}
    fb.generate_packet(run_dir=run_dir)
    after = {p.name for p in run_dir.iterdir()}
    assert after - before == set(fb.PACKET_FILES)
    # Nothing was written, repaired, or deleted outside the run directory.
    assert list(outside.iterdir()) == []


# --------------------------------------------------------------------------- #
# 3. Status viewer exposes fallback_packet_present
# --------------------------------------------------------------------------- #
def test_status_viewer_exposes_fallback_packet_present(tmp_path):
    run_dir = _setup_failure_run_dir(tmp_path)
    args = _viewer_args(run_dir)

    # Before the packet exists, the viewer reports it absent (no invention).
    report = viewer.generate_report(args)
    assert report["fallback_packet_present"] is False
    assert report["fallback_packet_path"] is None
    assert report["qa_marker"]["fallback_packet_present"] is False

    # After generation, the viewer surfaces it in JSON, the QA marker, and human.
    fb.generate_packet(run_dir=run_dir)
    report = viewer.generate_report(args)
    assert report["fallback_packet_present"] is True
    assert report["fallback_packet_path"] == str(run_dir / fb.FALLBACK_JSON_NAME)
    assert report["qa_marker"]["fallback_packet_present"] is True
    human = viewer.render_human(report)
    assert "fallback packet" in human
    assert "fallback packet present: yes" in human
    # The viewer remains read-only while reporting the packet.
    assert report["safety"]["validation_executed"] is False
    assert report["safety"]["container_restarted"] is False
    assert report["safety"]["model_called"] is False


# --------------------------------------------------------------------------- #
# 4. Explicit Lane B targeted-only QA marker
# --------------------------------------------------------------------------- #
def _lane_b_manifest() -> dict:
    return {
        "schema_version": 1,
        "mode": "docker01_pr_validation_manifest",
        "lane": {
            "selected": "targeted_runtime",
            "reason": "Lane B read-only routing change",
            "full_validation_required": False,
            "full_validation_reason": None,
        },
    }


def test_lane_b_targeted_validation_marker_is_explicit():
    marker = viewer.lane_qa_marker(_lane_b_manifest(), fallback_packet_present=True)
    assert marker["validation_lane"] == "B"
    assert marker["validation_scope"] == "targeted"
    assert marker["full_pytest_run"] is False
    assert "Lane B" in marker["full_pytest_reason"]
    assert "targeted" in marker["full_pytest_reason"]
    assert marker["fallback_packet_present"] is True


def test_lane_c_full_validation_marker_is_explicit():
    manifest = {
        "schema_version": 1,
        "mode": "docker01_pr_validation_manifest",
        "lane": {
            "selected": "full",
            "reason": "Dockerfile changed",
            "full_validation_required": True,
            "full_validation_reason": "Dockerfile changed; safety boundary",
        },
    }
    marker = viewer.lane_qa_marker(manifest, fallback_packet_present=False)
    assert marker["validation_lane"] == "C"
    assert marker["validation_scope"] == "full"
    assert marker["full_pytest_run"] is True
    assert marker["full_pytest_reason"] == "Dockerfile changed; safety boundary"
    assert marker["fallback_packet_present"] is False


def test_lane_marker_without_manifest_defaults_to_targeted():
    marker = viewer.lane_qa_marker(None, fallback_packet_present=False)
    assert marker["validation_lane"] is None
    assert marker["validation_scope"] == "targeted"
    assert marker["full_pytest_run"] is False
    assert marker["full_pytest_reason"] == "Targeted validation"
    assert marker["fallback_packet_present"] is False


def test_viewer_report_includes_lane_b_marker_with_manifest(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "validation-manifest.json").write_text(
        json.dumps(_lane_b_manifest()), encoding="utf-8"
    )
    report = viewer.generate_report(_viewer_args(run_dir))
    marker = report["qa_marker"]
    assert marker["validation_lane"] == "B"
    assert marker["validation_scope"] == "targeted"
    assert marker["full_pytest_run"] is False

    human = viewer.render_human(report)
    assert "QA marker:" in human
    assert "validation lane: B" in human
    assert "full pytest run: no" in human
