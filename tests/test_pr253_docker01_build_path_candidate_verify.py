"""PR253 Docker01 ownership candidate verifier tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "docker01_build_path_candidate_verify.py"
_SPEC = importlib.util.spec_from_file_location("docker01_build_path_candidate_verify", HELPER_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)

CANDIDATE = ROOT / "ops" / "docker" / "Dockerfile.docker01.ownership-candidate"
README = ROOT / "ops" / "docker" / "README.docker01-ownership-candidate.md"
RISKY = "RUN chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai\n"


def test_candidate_and_readme_exist_and_are_review_only() -> None:
    assert CANDIDATE.is_file()
    assert README.is_file()
    readme = README.read_text(encoding="utf-8").lower()
    assert "not the active docker01 production dockerfile" in readme
    assert "separate pr or operator-reviewed change" in readme


def test_json_output_strict_candidate_verified_and_safety() -> None:
    report = helper.build_report(CANDIDATE)
    decoded = json.loads(json.dumps(report))

    assert decoded["schema_version"] == 1
    assert decoded["mode"] == "docker01_build_path_ownership_candidate_verification"
    assert decoded["status"] == "candidate_verified"
    assert decoded["summary"]["candidate_found"] is True
    assert (
        decoded["summary"]["candidate_sha256"] == hashlib.sha256(CANDIDATE.read_bytes()).hexdigest()
    )
    assert decoded["read_only"] is True
    assert decoded["mutation_performed"] is False
    assert decoded["apply_available"] is False
    assert decoded["production_dockerfile_modified"] is False
    assert decoded["compose_modified"] is False
    assert decoded["summary"]["broad_recursive_ownership_in_candidate"] is False
    assert decoded["candidate_checks"]["no_chown_r_data"] is True
    assert decoded["candidate_checks"]["no_chown_r_codex"] is True
    assert decoded["candidate_checks"]["no_chown_r_opt_shellforgeai"] is True
    assert decoded["summary"]["targeted_runtime_dir_pattern_detected"] is True
    assert decoded["summary"]["copy_chown_guidance_detected"] is True
    assert decoded["summary"]["candidate_marked_not_active"] is True


def test_human_output_is_concise_operator_facing() -> None:
    human = helper.render_human(helper.build_report(CANDIDATE))

    assert human.startswith("# Docker01 Ownership Candidate Verification")
    assert "Read-only: yes" in human
    assert "Mutation performed: no" in human
    assert "Apply available: no" in human
    assert "* no shell=True" in human
    assert len(human.splitlines()) < 45


def test_out_writes_required_files_manifest_and_checksums(tmp_path: Path) -> None:
    out = tmp_path / "candidate-verification"
    report = helper.build_report(CANDIDATE, None, out)
    helper.write_artifacts(out, report)

    for name in helper.ARTIFACTS:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checksums = json.loads((out / "checksums.json").read_text(encoding="utf-8"))["sha256"]
    assert manifest["artifacts"] == helper.ARTIFACTS
    assert set(checksums) == set(helper.ARTIFACTS) - {"checksums.json"}
    for name, digest in checksums.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_non_empty_out_fails_safely(tmp_path: Path) -> None:
    out = tmp_path / "candidate-verification"
    out.mkdir()
    (out / "existing.txt").write_text("keep", encoding="utf-8")
    try:
        helper.write_artifacts(out, helper.build_report(CANDIDATE, None, out))
    except SystemExit as exc:
        assert "non-empty" in str(exc)
    else:
        raise AssertionError("expected non-empty out failure")
    assert (out / "existing.txt").read_text(encoding="utf-8") == "keep"


def test_missing_candidate_fails_safely(tmp_path: Path) -> None:
    report = helper.build_report(tmp_path / "missing.Dockerfile")
    assert report["status"] == "candidate_failed"
    assert report["summary"]["candidate_found"] is False
    assert report["read_only"] is True
    assert report["mutation_performed"] is False


def test_risky_candidate_fails_verification(tmp_path: Path) -> None:
    candidate = tmp_path / "Dockerfile"
    candidate.write_text(
        "# candidate not the active production Dockerfile\n" + RISKY, encoding="utf-8"
    )
    report = helper.build_report(candidate)
    assert report["status"] == "candidate_failed"
    assert report["summary"]["broad_recursive_ownership_in_candidate"] is True
    assert report["candidate_checks"]["no_chown_r_data"] is False
    assert report["candidate_checks"]["no_chown_r_codex"] is False
    assert report["candidate_checks"]["no_chown_r_opt_shellforgeai"] is False


def test_source_comparison_detects_source_risk_and_candidate_removes_it(tmp_path: Path) -> None:
    source = tmp_path / "Dockerfile"
    source.write_text("FROM scratch\n" + RISKY, encoding="utf-8")
    report = helper.build_report(CANDIDATE, source)
    comparison = report["source_comparison"]
    assert report["status"] == "candidate_verified"
    assert comparison["requested"] is True
    assert comparison["source_contains_broad_recursive_ownership"] is True
    assert comparison["candidate_removes_source_risk_pattern"] is True
    assert comparison["source_risk_paths"] == helper.KNOWN_PATHS


def test_helper_source_has_no_forbidden_execution_surface() -> None:
    source = HELPER_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "subprocess" not in source
    assert "docker compose up" not in source.lower()
    assert "docker build ." not in source.lower()
    assert "pytest.main" not in source
    assert "pip install" not in source
