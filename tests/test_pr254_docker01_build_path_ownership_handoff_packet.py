"""PR254 Docker01 ownership handoff packet tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "docker01_build_path_ownership_handoff_packet.py"
_SPEC = importlib.util.spec_from_file_location(
    "docker01_build_path_ownership_handoff_packet", HELPER_PATH
)
assert _SPEC is not None
assert _SPEC.loader is not None
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)

RISKY = "RUN chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai\n"
CLEAN_CANDIDATE = """# ShellForgeAI Docker01 ownership candidate artifact.
# CANDIDATE ONLY: this is not the active Docker01 production Dockerfile.
# Future review is required before any production Dockerfile change.
FROM python:3.12-slim
RUN install -d -o appuser -g appuser /data /home/appuser/.codex /opt/shellforgeai
# COPY --chown=appuser:appuser . /opt/shellforgeai
"""


def _fixtures(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source.Dockerfile"
    candidate = tmp_path / "candidate.Dockerfile"
    source.write_text("FROM python:3.12-slim\n" + RISKY, encoding="utf-8")
    candidate.write_text(CLEAN_CANDIDATE, encoding="utf-8")
    return source, candidate


def test_json_output_strict_handoff_ready_sha_and_safety(tmp_path: Path) -> None:
    source, candidate = _fixtures(tmp_path)
    report = helper.build_report(source, candidate)
    decoded = json.loads(json.dumps({k: v for k, v in report.items() if k != "_diff"}))

    assert decoded["schema_version"] == 1
    assert decoded["mode"] == "docker01_build_path_ownership_handoff_packet"
    assert decoded["status"] == "handoff_ready"
    assert decoded["summary"]["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert (
        decoded["summary"]["candidate_sha256"] == hashlib.sha256(candidate.read_bytes()).hexdigest()
    )
    assert decoded["summary"]["known_risk_paths_in_source"] == helper.KNOWN_PATHS
    assert decoded["summary"]["candidate_removes_source_risk_pattern"] is True
    assert decoded["read_only"] is True
    assert decoded["mutation_performed"] is False
    assert decoded["apply_available"] is False
    assert decoded["production_dockerfile_modified"] is False
    assert decoded["compose_modified"] is False
    assert decoded["safety"]["shell_true"] is False


def test_human_output_is_concise_operator_facing(tmp_path: Path) -> None:
    source, candidate = _fixtures(tmp_path)
    human = helper.render_human(helper.build_report(source, candidate))

    assert human.startswith("# Docker01 Ownership Handoff Packet")
    assert "Read-only: yes" in human
    assert "Mutation performed: no" in human
    assert "Apply available: no" in human
    assert "This is not approval" in human
    assert "* no shell=True" in human
    assert len(human.splitlines()) < 55


def test_out_writes_required_files_manifest_checksums_and_review_notes(tmp_path: Path) -> None:
    source, candidate = _fixtures(tmp_path)
    out = tmp_path / "handoff"
    report = helper.build_report(source, candidate, out_dir=out)
    helper.write_artifacts(out, report)

    for name in helper.ARTIFACTS:
        assert (out / name).is_file(), name
    diff = (out / "source-vs-candidate.diff").read_text(encoding="utf-8")
    assert "chown -R appuser:appuser" in diff
    assert "COPY --chown=appuser:appuser" in diff
    assert "Review source SHA256" in (out / "operator-review-checklist.md").read_text(
        encoding="utf-8"
    )
    preflight = (out / "future-change-preflight.md").read_text(encoding="utf-8")
    assert "Confirm this PR did not perform the action" in preflight
    assert "> /srv/compose/shellforgeai/Dockerfile" not in preflight
    assert "cp " not in preflight
    assert "mv " not in preflight
    assert "planning-only" in (out / "rollback-notes.md").read_text(encoding="utf-8")

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checksums = json.loads((out / "checksums.json").read_text(encoding="utf-8"))["sha256"]
    assert manifest["artifacts"] == helper.ARTIFACTS
    assert set(checksums) == set(helper.ARTIFACTS) - {"checksums.json"}
    for name, digest in checksums.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_non_empty_out_fails_safely(tmp_path: Path) -> None:
    source, candidate = _fixtures(tmp_path)
    out = tmp_path / "handoff"
    out.mkdir()
    (out / "existing.txt").write_text("keep", encoding="utf-8")
    try:
        helper.write_artifacts(out, helper.build_report(source, candidate, out_dir=out))
    except SystemExit as exc:
        assert "non-empty" in str(exc)
    else:
        raise AssertionError("expected non-empty out failure")
    assert (out / "existing.txt").read_text(encoding="utf-8") == "keep"


def test_missing_source_dockerfile_fails_safely(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.Dockerfile"
    candidate.write_text(CLEAN_CANDIDATE, encoding="utf-8")
    report = helper.build_report(tmp_path / "missing.Dockerfile", candidate)
    assert report["status"] == "failed"
    assert report["summary"]["source_dockerfile_found"] is False
    assert report["read_only"] is True
    assert report["mutation_performed"] is False


def test_missing_candidate_fails_safely(tmp_path: Path) -> None:
    source = tmp_path / "source.Dockerfile"
    source.write_text("FROM scratch\n" + RISKY, encoding="utf-8")
    report = helper.build_report(source, tmp_path / "missing.Dockerfile")
    assert report["status"] == "failed"
    assert report["summary"]["candidate_found"] is False
    assert report["read_only"] is True
    assert report["mutation_performed"] is False


def test_risky_candidate_returns_not_ready(tmp_path: Path) -> None:
    source, candidate = _fixtures(tmp_path)
    candidate.write_text(CLEAN_CANDIDATE + RISKY, encoding="utf-8")
    report = helper.build_report(source, candidate)
    assert report["status"] == "not_ready"
    assert report["candidate"]["broad_recursive_ownership_detected"] is True
    assert report["summary"]["known_risk_paths_recursive_chown_in_candidate"] == helper.KNOWN_PATHS


def test_optional_candidate_verification_input_can_be_consumed(tmp_path: Path) -> None:
    source, candidate = _fixtures(tmp_path)
    verification = tmp_path / "verification"
    verification.mkdir()
    payload = {"summary": {"candidate_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest()}}
    (verification / "docker01-ownership-candidate-verification.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    report = helper.build_report(source, candidate, candidate_verification=verification)
    assert report["status"] == "handoff_ready"
    assert any(check["name"] == "candidate_verification_input" for check in report["checks"])


def test_helper_source_has_no_forbidden_execution_surface() -> None:
    source = HELPER_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "subprocess" not in source
    assert "docker compose up" not in source.lower()
    assert "docker build ." not in source.lower()
    assert "pytest.main" not in source
    assert "pip install" not in source
