"""PR255 guarded Docker01 external Dockerfile ownership update recipe tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "docker01_external_dockerfile_ownership_update.py"
_SPEC = importlib.util.spec_from_file_location(
    "docker01_external_dockerfile_ownership_update", HELPER_PATH
)
assert _SPEC and _SPEC.loader
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)

RISK = "RUN chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai\n"
SOURCE = "FROM python:3.12-slim\n" + RISK
CANDIDATE = (
    "# CANDIDATE ONLY: this is not the active Docker01 production Dockerfile.\n"
    "FROM python:3.12-slim\n"
    "RUN install -d -o appuser -g appuser "
    "/data /home/appuser/.codex /opt/shellforgeai\n"
)
CONFIRM = helper.CONFIRMATION


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    root = tmp_path / "fixture-root"
    source = root / "compose" / "Dockerfile"
    cand = root / "repo" / "ops" / "docker" / "Dockerfile.docker01.ownership-candidate"
    backup = root / "backups"
    out = root / "receipt"
    source.parent.mkdir(parents=True)
    cand.parent.mkdir(parents=True)
    source.write_text(SOURCE, encoding="utf-8")
    cand.write_text(CANDIDATE, encoding="utf-8")
    return root, source, cand, backup, out


def args(root: Path, source: Path, cand: Path, backup: Path | None, out: Path | None, **kw):
    class A:
        pass

    a = A()
    a.source_dockerfile = source
    a.candidate = cand
    a.fixture_root = root
    a.expected_source_sha256 = kw.get("source_sha", sha(SOURCE))
    a.expected_candidate_sha256 = kw.get("candidate_sha", sha(CANDIDATE))
    a.backup_dir = backup
    a.out = out
    a.confirm = kw.get("confirm", CONFIRM)
    return a


def test_preflight_json_output_is_strict_and_passes_with_matching_shas(tmp_path: Path) -> None:
    root, source, cand, backup, out = fixture(tmp_path)
    report = helper._preflight(args(root, source, cand, backup, out))
    decoded = json.loads(json.dumps(helper._public(report)))
    assert decoded["schema_version"] == 1
    assert decoded["mode"] == "docker01_external_dockerfile_ownership_update_preflight"
    assert decoded["status"] == "preflight_passed"
    assert decoded["read_only"] is True
    assert decoded["mutation_performed"] is False
    assert decoded["summary"]["source_sha256_match"] is True
    assert decoded["summary"]["candidate_sha256_match"] is True
    assert decoded["summary"]["source_contains_broad_recursive_ownership"] is True
    assert decoded["summary"]["candidate_contains_broad_recursive_ownership"] is False
    assert decoded["summary"]["candidate_removes_source_risk_pattern"] is True
    assert decoded["safety"]["docker_build_executed"] is False
    assert decoded["safety"]["docker_compose_executed"] is False
    assert decoded["safety"]["chown_executed"] is False
    assert decoded["safety"]["chmod_executed"] is False


def test_preflight_human_output_is_concise(tmp_path: Path) -> None:
    root, source, cand, backup, out = fixture(tmp_path)
    human = helper.render_human(helper._preflight(args(root, source, cand, backup, out)))
    assert human.startswith("# Docker01 External Dockerfile Ownership Update")
    assert "Read-only: yes" in human
    assert "Docker build available: no" in human
    assert len(human.splitlines()) < 35


def test_preflight_failures_for_sha_and_missing_files(tmp_path: Path) -> None:
    root, source, cand, backup, out = fixture(tmp_path)
    assert (
        helper._preflight(args(root, source, cand, backup, out, source_sha="bad"))["status"]
        == "preflight_failed"
    )
    assert (
        helper._preflight(args(root, source, cand, backup, out, candidate_sha="bad"))["status"]
        == "preflight_failed"
    )
    source.unlink()
    assert (
        helper._preflight(args(root, source, cand, backup, out))["summary"]["source_found"] is False
    )
    source.write_text(SOURCE, encoding="utf-8")
    cand.unlink()
    assert (
        helper._preflight(args(root, source, cand, backup, out))["summary"]["candidate_found"]
        is False
    )


def test_write_fixture_receipt_backup_and_atomic_source_replacement(tmp_path: Path) -> None:
    root, source, cand, backup, out = fixture(tmp_path)
    report = helper._write(args(root, source, cand, backup, out))
    assert report["status"] == "update_written"
    assert report["mutation_performed"] is True
    assert report["docker_build_available"] is False
    assert report["compose_validation_available"] is False
    assert report["container_recreate_available"] is False
    assert source.read_text(encoding="utf-8") == CANDIDATE
    backups = list(backup.iterdir())
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == SOURCE
    assert report["summary"]["source_after_matches_candidate"] is True
    assert report["summary"]["source_before_matches_backup"] is True
    helper.write_artifacts(out, report)
    for name in helper.WRITE_ARTIFACTS:
        assert (out / name).is_file(), name


def test_write_refuses_confirmation_and_sha_mismatches_before_mutation(tmp_path: Path) -> None:
    for kw in (
        {"confirm": None},
        {"confirm": "wrong"},
        {"source_sha": "bad"},
        {"candidate_sha": "bad"},
    ):
        root, source, cand, backup, out = fixture(tmp_path / str(len(kw)) / str(kw))
        report = helper._write(args(root, source, cand, backup, out, **kw))
        assert report["status"] == "update_failed"
        assert source.read_text(encoding="utf-8") == SOURCE
        assert not backup.exists()


def test_write_refuses_risky_candidate_symlinks_unsafe_paths_and_non_empty_out(
    tmp_path: Path,
) -> None:
    root, source, cand, backup, out = fixture(tmp_path)
    cand.write_text("# candidate not the active production Dockerfile\n" + RISK, encoding="utf-8")
    assert (
        helper._write(args(root, source, cand, backup, out, candidate_sha=sha(cand.read_text())))[
            "status"
        ]
        == "update_failed"
    )

    root, source, cand, backup, out = fixture(tmp_path / "sym-source")
    source.unlink()
    target = root / "target"
    target.write_text(SOURCE, encoding="utf-8")
    source.symlink_to(target)
    assert helper._write(args(root, source, cand, backup, out))["status"] == "update_failed"

    root, source, cand, backup, out = fixture(tmp_path / "sym-cand")
    cand.unlink()
    target = root / "cand-target"
    target.write_text(CANDIDATE, encoding="utf-8")
    cand.symlink_to(target)
    assert helper._write(args(root, source, cand, backup, out))["status"] == "update_failed"

    root, source, cand, backup, out = fixture(tmp_path / "paths")
    outside = tmp_path / "outside" / "Dockerfile"
    outside.parent.mkdir()
    outside.write_text(SOURCE, encoding="utf-8")
    assert helper._write(args(root, outside, cand, backup, out))["status"] == "update_failed"
    assert (
        helper._write(args(root, source, cand, tmp_path / "outside-backup", out))["status"]
        == "update_failed"
    )
    out.mkdir(parents=True)
    (out / "existing").write_text("x")
    assert helper._write(args(root, source, cand, backup, out))["status"] == "update_failed"


def test_production_path_safety_logic_requires_exact_path(tmp_path: Path) -> None:
    root, source, cand, backup, out = fixture(tmp_path)
    a = args(None, source, cand, backup, out)
    report = helper._preflight(a)
    assert report["status"] == "preflight_failed"
    assert "production source Dockerfile must resolve exactly" in "\n".join(report["errors"])


def test_artifacts_manifest_checksums_and_preflight_files(tmp_path: Path) -> None:
    root, source, cand, backup, out = fixture(tmp_path)
    report = helper._preflight(args(root, source, cand, backup, out))
    helper.write_artifacts(out, report)
    for name in helper.PRE_ARTIFACTS:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checksums = json.loads((out / "checksums.json").read_text(encoding="utf-8"))["sha256"]
    assert manifest["artifacts"] == helper.PRE_ARTIFACTS
    assert set(checksums) == set(helper.PRE_ARTIFACTS) - {"checksums.json"}


def test_helper_source_has_no_forbidden_execution_surface() -> None:
    source = HELPER_PATH.read_text(encoding="utf-8").lower()
    assert "shell=true" not in source
    assert "subprocess" not in source
    assert "docker build ." not in source
    assert "docker compose up" not in source
    assert "pip install" not in source
    assert "pytest.main" not in source


def test_docs_mention_confirmation_and_stop_before_runtime_actions() -> None:
    docs = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in [
            "OPS.md",
            "docs/VALIDATION_LANES.md",
            "docs/VALIDATION_MATRIX.md",
            "docs/roadmap.md",
        ]
    )
    assert "CONFIRM_SHELLFORGEAI_DOCKER01_OWNERSHIP_DOCKERFILE_UPDATE" in docs
    assert "Codex/PR" in docs and "must not run production write mode" in docs
    assert "stops before Docker build" in docs or "stop before Docker build" in docs
    assert "recreate" in docs and "restart" in docs
