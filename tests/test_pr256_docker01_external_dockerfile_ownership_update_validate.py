"""PR256 read-only Docker01 external Dockerfile ownership update validator tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "docker01_external_dockerfile_ownership_update_validate.py"
_SPEC = importlib.util.spec_from_file_location("docker01_validate", HELPER_PATH)
assert _SPEC and _SPEC.loader
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)

RISK = "RUN chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai\n"
SAFE = (
    "FROM python:3.12-slim\n"
    "RUN install -d -o appuser -g appuser /data /home/appuser/.codex /opt/shellforgeai\n"
    "COPY --chown=appuser:appuser . /opt/shellforgeai\n"
)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def report_for(tmp_path: Path, text: str) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "Dockerfile"
    target.write_text(text, encoding="utf-8")
    return helper.build_report(target, None, None)


def test_json_output_is_strict_and_human_output_is_concise(tmp_path: Path) -> None:
    report = report_for(tmp_path, SAFE)
    decoded = json.loads(json.dumps(report))
    assert decoded["schema_version"] == 1
    assert decoded["status"] == "validated"
    human = helper.render_human(report)
    assert human.startswith("# Docker01 External Dockerfile Ownership Update Validation")
    assert "Read-only: yes" in human
    assert len(human.splitlines()) < 40


def test_target_safer_pattern_validated_and_sha_reported(tmp_path: Path) -> None:
    report = report_for(tmp_path, SAFE)
    assert report["status"] == "validated"
    assert report["summary"]["target_sha256"] == sha(SAFE)
    assert report["summary"]["broad_recursive_ownership_present"] is False
    assert report["summary"]["targeted_ownership_pattern_present"] is True


def test_target_with_exact_broad_risk_returns_not_updated(tmp_path: Path) -> None:
    report = report_for(tmp_path, "FROM base\n" + RISK)
    assert report["status"] == "not_updated"
    assert report["summary"]["broad_recursive_ownership_present"] is True


def test_missing_target_fails_safely(tmp_path: Path) -> None:
    report = helper.build_report(tmp_path / "missing.Dockerfile", None, None)
    assert report["status"] == "failed"
    assert report["summary"]["target_found"] is False
    assert report["read_only"] is True


def test_broad_recursive_risks_are_detected_by_path(tmp_path: Path) -> None:
    for risk_path in ["/data", "/home/appuser/.codex", "/opt/shellforgeai"]:
        report = report_for(
            tmp_path / risk_path.strip("/").replace("/", "_"),
            f"RUN chown -R appuser:appuser {risk_path}\n",
        )
        assert report["target_analysis"]["broad_chown_risk_detected"] is True
        assert (
            risk_path
            in report["target_analysis"]["known_risk_paths_detected_in_recursive_ownership"]
        )


def test_targeted_runtime_directory_pattern_is_detected(tmp_path: Path) -> None:
    report = report_for(tmp_path, "RUN install -d -o appuser -g appuser /data\n")
    assert report["target_analysis"]["targeted_install_dir_pattern_detected"] is True


def write_valid_receipt(
    receipt: Path, target: Path, backup: Path, *, override: dict | None = None
) -> None:
    receipt.mkdir(parents=True)
    backup.write_text("before", encoding="utf-8")
    data = {
        "schema_version": 1,
        "mode": "docker01_external_dockerfile_ownership_update",
        "source_dockerfile_path": str(target),
        "backup_path": str(backup),
        "write_external_dockerfile_only": True,
        "summary": {
            "source_sha256_before": sha("before"),
            "source_sha256_after": sha(SAFE),
            "backup_sha256": sha("before"),
            "source_replaced_with_candidate": True,
        },
        "safety": {
            "docker_build_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "recovery_executed": False,
        },
    }
    if override:
        data.update(override)
    (receipt / "docker01-external-dockerfile-update-receipt.json").write_text(
        json.dumps(data), encoding="utf-8"
    )
    (receipt / "manifest.json").write_text(
        json.dumps(
            {
                "artifacts": [
                    "docker01-external-dockerfile-update-receipt.json",
                    "manifest.json",
                    "checksums.json",
                ]
            }
        ),
        encoding="utf-8",
    )
    sums = {
        name: hashlib.sha256((receipt / name).read_bytes()).hexdigest()
        for name in ["docker01-external-dockerfile-update-receipt.json", "manifest.json"]
    }
    (receipt / "checksums.json").write_text(json.dumps({"sha256": sums}), encoding="utf-8")


def test_valid_receipt_manifest_checksums_and_backup_validate(tmp_path: Path) -> None:
    target = tmp_path / "Dockerfile"
    target.write_text(SAFE, encoding="utf-8")
    receipt = tmp_path / "receipt"
    backup = tmp_path / "backup.Dockerfile"
    write_valid_receipt(receipt, target, backup)
    report = helper.build_report(target, receipt, None)
    assert report["status"] == "validated"
    assert report["summary"]["receipt_manifest_ok"] is True
    assert report["summary"]["receipt_checksums_ok"] is True
    assert report["summary"]["backup_verified"] is True


def test_receipt_claiming_disallowed_actions_fails(tmp_path: Path) -> None:
    keys = [
        "docker_build_executed",
        "docker_compose_executed",
        "container_restarted",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
    ]
    for key in keys:
        case = tmp_path / key
        case.mkdir()
        target = case / "Dockerfile"
        target.write_text(SAFE, encoding="utf-8")
        receipt = case / "receipt"
        backup = case / "backup"
        write_valid_receipt(receipt, target, backup, override={"safety": {key: True}})
        report = helper.build_report(target, receipt, None)
        assert report["status"] == "failed"
        assert report["summary"]["safety_contract_ok"] is False


def test_receipt_checksum_mismatch_fails(tmp_path: Path) -> None:
    target = tmp_path / "Dockerfile"
    target.write_text(SAFE, encoding="utf-8")
    receipt = tmp_path / "receipt"
    backup = tmp_path / "backup"
    write_valid_receipt(receipt, target, backup)
    (receipt / "checksums.json").write_text(
        json.dumps({"sha256": {"manifest.json": "bad"}}), encoding="utf-8"
    )
    assert helper.build_report(target, receipt, None)["status"] == "failed"


def test_out_writes_required_files_and_checksums_and_non_empty_out_fails(tmp_path: Path) -> None:
    target = tmp_path / "Dockerfile"
    target.write_text(SAFE, encoding="utf-8")
    out = tmp_path / "out"
    report = helper.build_report(target, None, out)
    helper.write_artifacts(out, report)
    for name in helper.ARTIFACTS:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checksums = json.loads((out / "checksums.json").read_text(encoding="utf-8"))["sha256"]
    assert manifest["artifacts"] == helper.ARTIFACTS
    assert set(checksums) == set(helper.ARTIFACTS) - {"checksums.json"}
    assert helper.build_report(target, None, out)["status"] == "failed"


def test_safety_flags_and_source_have_no_execution_surface(tmp_path: Path) -> None:
    report = report_for(tmp_path, SAFE)
    safety = report["safety"]
    for key in ["read_only", "validation_only"]:
        assert safety[key] is True
    for key in [
        "mutation_performed",
        "update_executed_by_validator",
        "dockerfile_modified_by_validator",
        "compose_modified_by_validator",
        "docker_build_executed",
        "docker_compose_executed",
        "chown_executed",
        "chmod_executed",
    ]:
        assert safety[key] is False
    source = HELPER_PATH.read_text(encoding="utf-8").lower()
    assert "shell=true" not in source
    assert "subprocess" not in source
    assert "docker build ." not in source
    assert "docker compose up" not in source
    assert "pip install" not in source
    assert "pytest.main" not in source


def test_docs_mention_validator_is_read_only_and_not_remediation() -> None:
    docs = "\n".join(
        (ROOT / p).read_text(encoding="utf-8")
        for p in [
            "OPS.md",
            "docs/VALIDATION_LANES.md",
            "docs/VALIDATION_MATRIX.md",
            "docs/roadmap.md",
        ]
    )
    assert "docker01_external_dockerfile_ownership_update_validate.py" in docs
    assert "read-only" in docs
    assert "not remediation" in docs
    assert "Docker build/recreate validation" in docs
