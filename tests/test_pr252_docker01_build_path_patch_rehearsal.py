"""PR252 Docker01 build path ownership patch rehearsal tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

HELPER_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "docker01_build_path_patch_rehearsal.py"
)
_SPEC = importlib.util.spec_from_file_location("docker01_build_path_patch_rehearsal", HELPER_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)

CHOWN_LINE = "RUN chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai"
PREVIEW_TEXT = """FROM python:3.12
# ShellForgeAI PR251 preview: avoid broad recursive ownership on Docker/LXC build paths.
RUN install -d -o appuser -g appuser /data /home/appuser/.codex
# Prefer COPY --chown=appuser:appuser for application source ownership. /opt/shellforgeai
# Do not recursively chown /data during image build.
"""


def _dockerfile(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "compose" / "shellforgeai" / "Dockerfile"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    return path


def _preview_dir(tmp_path: Path) -> Path:
    out = tmp_path / "patch-preview"
    out.mkdir()
    files = {
        "dockerfile-ownership-preview.Dockerfile": PREVIEW_TEXT,
        "dockerfile-ownership-preview.diff": "--- Dockerfile\n+++ preview\n-" + CHOWN_LINE + "\n",
        "docker01-build-path-patch-preview.json": json.dumps({"status": "preview_ready"}) + "\n",
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8")
    artifacts = [
        "dockerfile-ownership-preview.Dockerfile",
        "dockerfile-ownership-preview.diff",
        "docker01-build-path-patch-preview.json",
        "manifest.json",
        "checksums.json",
    ]
    (out / "manifest.json").write_text(
        json.dumps({"artifacts": artifacts}) + "\n", encoding="utf-8"
    )
    checksums = {
        name: hashlib.sha256((out / name).read_bytes()).hexdigest()
        for name in artifacts
        if name != "checksums.json"
    }
    (out / "checksums.json").write_text(json.dumps({"sha256": checksums}) + "\n", encoding="utf-8")
    return out


def test_json_output_strict_rehearsal_passed_and_safety(tmp_path: Path) -> None:
    original = f"FROM python:3.12\n{CHOWN_LINE}\n"
    dockerfile = _dockerfile(tmp_path, original)
    report = helper._public_report(
        helper.build_report(dockerfile, _preview_dir(tmp_path), None, tmp_path / "out")
    )
    decoded = json.loads(json.dumps(report))

    assert decoded["schema_version"] == 1
    assert decoded["mode"] == "docker01_build_path_ownership_patch_rehearsal"
    assert decoded["status"] == "rehearsal_passed"
    assert (
        decoded["summary"]["original_sha256_before"]
        == hashlib.sha256(original.encode()).hexdigest()
    )
    assert (
        decoded["summary"]["original_sha256_before"] == decoded["summary"]["original_sha256_after"]
    )
    assert decoded["summary"]["original_unchanged"] is True
    assert decoded["summary"]["patch_preview_manifest_ok"] is True
    assert decoded["summary"]["patch_preview_checksums_ok"] is True
    assert decoded["summary"]["broad_recursive_ownership_detected_in_original"] is True
    assert decoded["summary"]["broad_recursive_ownership_absent_from_rehearsed_artifact"] is True
    assert (
        decoded["summary"]["known_risk_paths_removed_from_recursive_ownership"]
        == helper.KNOWN_PATHS
    )
    assert decoded["summary"]["static_verification_passed"] is True
    assert decoded["production_dockerfile_modified"] is False
    assert decoded["compose_modified"] is False
    assert decoded["docker_build_available"] is False
    assert decoded["safety"]["docker_build_executed"] is False
    assert decoded["safety"]["docker_compose_executed"] is False
    assert decoded["safety"]["chown_executed"] is False
    assert decoded["safety"]["chmod_executed"] is False


def test_human_output_is_concise_operator_facing(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, f"FROM scratch\n{CHOWN_LINE}\n")
    report = helper._public_report(
        helper.build_report(dockerfile, _preview_dir(tmp_path), None, tmp_path / "out")
    )

    human = helper.render_human(report)

    assert human.startswith("# Docker01 Build Path Ownership Patch Rehearsal")
    assert "Mutation performed: yes, artifact-only" in human
    assert "Production Dockerfile modified: no" in human
    assert "Compose modified: no" in human
    assert "Docker build available: no" in human
    assert "This is a patch rehearsal only." in human
    assert "* no shell=True" in human
    assert len(human.splitlines()) < 45


def test_out_writes_required_reports_manifest_checksums_and_rehearsed_files(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, f"FROM scratch\n{CHOWN_LINE}\n")
    out = tmp_path / "patch-rehearsal"

    report = helper.build_report(dockerfile, _preview_dir(tmp_path), None, out)
    helper.write_artifacts(out, report)

    for name in helper.ARTIFACTS:
        assert (out / name).is_file(), name
    rehearsed = (out / "dockerfile-ownership-rehearsed.Dockerfile").read_text(encoding="utf-8")
    diff = (out / "dockerfile-ownership-rehearsal.diff").read_text(encoding="utf-8")
    static = json.loads(
        (out / "dockerfile-ownership-rehearsal-static-verification.json").read_text()
    )
    assert CHOWN_LINE not in rehearsed
    assert "chown -R appuser:appuser /data" not in rehearsed
    assert "RUN install -d -o appuser -g appuser /data /home/appuser/.codex" in rehearsed
    assert "COPY --chown=appuser:appuser" in rehearsed
    assert "-" + CHOWN_LINE in diff
    assert static["rehearsed_contains_chown_r"] is False
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checksums = json.loads((out / "checksums.json").read_text(encoding="utf-8"))["sha256"]
    assert manifest["artifacts"] == helper.ARTIFACTS
    assert set(checksums) == set(helper.ARTIFACTS) - {"checksums.json"}
    for name, digest in checksums.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_non_empty_out_fails_safely(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, f"FROM scratch\n{CHOWN_LINE}\n")
    out = tmp_path / "patch-rehearsal"
    out.mkdir()
    (out / "existing.txt").write_text("keep", encoding="utf-8")

    try:
        helper.write_artifacts(
            out, helper.build_report(dockerfile, _preview_dir(tmp_path), None, out)
        )
    except SystemExit as exc:
        assert "non-empty" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected non-empty output directory to fail")
    assert (out / "existing.txt").read_text(encoding="utf-8") == "keep"


def test_missing_dockerfile_and_missing_preview_fail_safely(tmp_path: Path) -> None:
    report = helper.build_report(
        tmp_path / "missing.Dockerfile", _preview_dir(tmp_path), None, None
    )
    assert report["status"] == "rehearsal_failed"
    assert report["summary"]["original_dockerfile_found"] is False
    assert report["mutation_performed"] is False
    assert report["production_dockerfile_modified"] is False
    assert report["compose_modified"] is False

    dockerfile = _dockerfile(tmp_path, f"FROM scratch\n{CHOWN_LINE}\n")
    missing_preview = helper.build_report(
        dockerfile, None, tmp_path / "missing-preview.Dockerfile", None
    )
    assert missing_preview["status"] == "rehearsal_failed"
    assert missing_preview["summary"]["preview_dockerfile_found"] is False


def test_invalid_preview_manifest_or_checksum_fails_safely(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, f"FROM scratch\n{CHOWN_LINE}\n")
    preview = _preview_dir(tmp_path)
    (preview / "checksums.json").write_text(json.dumps({"sha256": {}}), encoding="utf-8")

    report = helper.build_report(dockerfile, preview, None, tmp_path / "out")

    assert report["status"] != "rehearsal_passed"
    assert report["summary"]["patch_preview_checksums_ok"] is False
    assert report["production_dockerfile_modified"] is False
    assert report["compose_modified"] is False


def test_helper_source_has_no_forbidden_execution_surface() -> None:
    source = HELPER_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "subprocess" not in source
    assert "subprocess." not in source
    assert "docker compose up" not in source.lower()
    assert "docker build ." not in source.lower()
    assert "pytest.main" not in source
    assert "pip install" not in source
