import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr235_archive_readiness", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr235_archive_readiness"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def make_chain(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir(parents=True)
    source = root / "sfai-pr235-qa-bundle-20260623T000000Z.json"
    source.write_text("candidate-secret")
    (root / "sfai-pr235-storage-health-20260623T000000Z.json").write_text("storage")
    plan = h.build_plan(str(root))
    plan_dir = tmp_path / "plan"
    h.write_outputs(plan, str(plan_dir))
    receipt = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id=plan["plan_id"])
    receipt_dir = tmp_path / "receipt"
    h.write_dry_run_receipt_outputs(receipt, str(receipt_dir))
    validation = h.validate_dry_run_receipt(str(receipt_dir), plan_dir=str(plan_dir))
    validation_dir = tmp_path / "receipt-validation"
    h.write_dry_run_receipt_validation_outputs(validation, str(validation_dir))
    return plan_dir, receipt_dir, validation_dir, source, root


def snapshot_files(path: Path):
    return {p.name: (p.read_text(), p.stat().st_mtime_ns) for p in path.iterdir() if p.is_file()}


def test_valid_chain_returns_ready_strict_json_human_and_is_read_only(tmp_path):
    plan_dir, receipt_dir, _, source, root = make_chain(tmp_path)
    before_plan = snapshot_files(plan_dir)
    before_receipt = snapshot_files(receipt_dir)
    source_before = (source.read_text(), source.stat().st_mtime_ns)

    result = h.build_execution_readiness(str(plan_dir), str(receipt_dir))
    loaded = json.loads(json.dumps(result))
    assert loaded["mode"] == "docker01_artifact_archive_execution_readiness"
    assert loaded["status"] == "ready_for_execution_review"
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["execution_available"] is False
    assert loaded["future_execution_review_only"] is True
    assert loaded["summary"]["plan_validation_status"] == "passed"
    assert loaded["summary"]["dry_run_receipt_validation_status"] == "passed"
    assert loaded["summary"]["plan_id_match"] is True
    assert loaded["summary"]["candidate_manifest_match"] is True
    assert loaded["summary"]["exclusions_match"] is True
    assert loaded["summary"]["future_contract_match"] is True
    assert loaded["summary"]["safety_contract_ok"] is True
    assert loaded["summary"]["candidate_items"] == 2
    assert loaded["future_execution_requirements"]["separate_pr_required"] is True
    assert loaded["future_execution_requirements"]["source_delete_default"] is False
    assert loaded["future_execution_requirements"]["source_move_default"] is False
    assert loaded["safety"]["readiness_gate_only"] is True
    assert all(
        v is False
        for k, v in loaded["safety"].items()
        if k not in {"read_only", "readiness_gate_only"}
    )

    human = h.render_execution_readiness_summary(result)
    assert "# Docker01 Artifact Archive Execution Readiness" in human
    assert "Execution available: no" in human
    assert "readiness gate only" in human
    assert len(human.splitlines()) < 55

    assert snapshot_files(plan_dir) == before_plan
    assert snapshot_files(receipt_dir) == before_receipt
    assert source.exists() and source.read_text() == source_before[0]
    assert source.stat().st_mtime_ns == source_before[1]
    assert not any(p.suffix in {".tar", ".gz", ".zst", ".zip"} for p in root.iterdir())


def test_valid_chain_with_supplied_receipt_validation_returns_ready(tmp_path):
    plan_dir, receipt_dir, validation_dir, *_ = make_chain(tmp_path)
    result = h.build_execution_readiness(
        str(plan_dir), str(receipt_dir), receipt_validation_dir=str(validation_dir)
    )
    assert result["status"] == "ready_for_execution_review"
    assert result["receipt_validation_dir"] == str(validation_dir)
    assert any(
        c["name"] == "receipt_validation_supplied" and c["status"] == "passed"
        for c in result["checks"]
    )


def test_out_writes_required_readiness_files_and_valid_checksums(tmp_path):
    plan_dir, receipt_dir, *_ = make_chain(tmp_path)
    result = h.build_execution_readiness(str(plan_dir), str(receipt_dir))
    out = tmp_path / "readiness"
    h.write_execution_readiness_outputs(result, str(out))
    for name in h.EXECUTION_READINESS_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    checksums = json.loads((out / "checksums.json").read_text())
    assert manifest["archive_created"] is False
    assert manifest["candidate_contents_copied"] is False
    assert "manifest.json" in checksums["checksums"]
    assert "checksums.json" not in checksums["checksums"]
    for name, recorded in checksums["checksums"].items():
        assert recorded == "sha256:" + h.sha256_file(out / name)
    assert not any(p.suffix in {".tar", ".gz", ".zst", ".zip"} for p in out.iterdir())


def _mutate_json(path: Path, parts, value):
    data = json.loads(path.read_text())
    cur = data
    for part in parts[:-1]:
        cur = cur[part]
    cur[parts[-1]] = value
    path.write_text(json.dumps(data, sort_keys=True))


def _mutate_candidate(file_path: Path, **updates):
    data = json.loads(file_path.read_text())
    data["candidates"][0].update(updates)
    file_path.write_text(json.dumps(data, sort_keys=True))


@pytest.mark.parametrize(
    "name,mutate",
    [
        (
            "plan_id",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["plan_id"], "sha256:0000000000000000"
            ),
        ),
        ("count", lambda p, r, t: _drop_candidate(r / "candidate-manifest.json")),
        ("bytes", lambda p, r, t: _mutate_candidate(r / "candidate-manifest.json", size_bytes=999)),
        (
            "class",
            lambda p, r, t: _mutate_candidate(
                r / "candidate-manifest.json", **{"class": "storage_health_report_artifacts"}
            ),
        ),
        (
            "path",
            lambda p, r, t: _mutate_candidate(
                r / "candidate-manifest.json", path=str(t / "sfai-pr235-validation-other")
            ),
        ),
        (
            "confirmation",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json",
                ["future_execution_contract", "future_confirmation_phrase"],
                "NOPE",
            ),
        ),
        ("invalid_plan", lambda p, r, t: (p / "artifact-archive-plan.json").write_text("{")),
        (
            "invalid_receipt",
            lambda p, r, t: (r / "artifact-archive-dry-run-receipt.json").write_text("{"),
        ),
        (
            "execution_available",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["execution_available"], True
            ),
        ),
        (
            "mutation_performed",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["mutation_performed"], True
            ),
        ),
        (
            "archive_created",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["safety", "archive_created"], True
            ),
        ),
        (
            "source_copied",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["safety", "source_copied"], True
            ),
        ),
        (
            "source_moved",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["safety", "source_moved"], True
            ),
        ),
        (
            "source_deleted",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["safety", "source_deleted"], True
            ),
        ),
        (
            "source_modified",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["safety", "source_modified"], True
            ),
        ),
        (
            "cleanup",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["safety", "cleanup_executed"], True
            ),
        ),
        (
            "prune",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json",
                ["safety", "docker_prune_executed"],
                True,
            ),
        ),
        (
            "restart",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["safety", "container_restarted"], True
            ),
        ),
        (
            "remediation",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json",
                ["safety", "remediation_executed"],
                True,
            ),
        ),
        (
            "rollback",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["safety", "rollback_executed"], True
            ),
        ),
        (
            "recovery",
            lambda p, r, t: _mutate_json(
                r / "artifact-archive-dry-run-receipt.json", ["safety", "recovery_executed"], True
            ),
        ),
        (
            "unsafe_path",
            lambda p, r, t: _mutate_candidate(
                r / "candidate-manifest.json", path="/var/lib/docker/bad"
            ),
        ),
    ],
)
def test_readiness_blockers_return_not_ready_or_failed(tmp_path, name, mutate):
    plan_dir, receipt_dir, _, _, root = make_chain(tmp_path / name)
    mutate(plan_dir, receipt_dir, root)
    result = h.build_execution_readiness(str(plan_dir), str(receipt_dir))
    assert result["status"] in {"not_ready", "failed"}
    assert result["execution_available"] is False


def _drop_candidate(path: Path):
    data = json.loads(path.read_text())
    data["candidates"] = data["candidates"][:1]
    path.write_text(json.dumps(data, sort_keys=True))


def test_symlink_candidate_fails_and_is_not_followed(tmp_path):
    plan_dir, receipt_dir, _, _, root = make_chain(tmp_path)
    target = root / "target"
    target.write_text("secret")
    link = root / "sfai-pr235-qa-bundle-symlink"
    link.symlink_to(target)
    _mutate_candidate(receipt_dir / "candidate-manifest.json", path=str(link))
    result = h.build_execution_readiness(str(plan_dir), str(receipt_dir))
    assert result["status"] in {"not_ready", "failed"}
    assert target.read_text() == "secret"


def test_no_shell_true_or_mutation_cli_flags_are_introduced():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    assert "subprocess" not in source
    for flag in [
        "--execute",
        "--apply",
        "--archive-now",
        "--cleanup",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--rm",
        "--rmi",
        "--post-comment",
        "--approve",
        "--merge",
    ]:
        assert flag not in source
