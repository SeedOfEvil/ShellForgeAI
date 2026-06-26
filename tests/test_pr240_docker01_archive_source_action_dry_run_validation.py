import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr240_source_action_validation", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr240_source_action_validation"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def make_source_action_chain(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir(parents=True)
    candidate_dir = root / "sfai-pr240-qa-bundle-20260625T000000Z"
    candidate_dir.mkdir()
    source_file = candidate_dir / "evidence.txt"
    source_file.write_text("bundle-evidence")
    candidate_file = root / "sfai-pr240-storage-health-20260625T000000Z.json"
    candidate_file.write_text('{"ok": true}')

    plan = h.build_plan(str(root))
    plan_dir = tmp_path / "plan"
    h.write_outputs(plan, str(plan_dir))
    dry = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id=plan["plan_id"])
    dry_dir = tmp_path / "dry"
    h.write_dry_run_receipt_outputs(dry, str(dry_dir))
    bundle_dir = tmp_path / "bundle"
    created = h.build_archive_bundle(
        str(plan_dir),
        str(dry_dir),
        supplied_plan_id=plan["plan_id"],
        confirm=h.CONFIRMATION_PHRASE,
        archive_out=str(bundle_dir),
    )
    assert created["status"] == "archive_created"
    eligibility = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    eligibility_dir = tmp_path / "eligibility"
    h.write_archive_eligibility_review_outputs(eligibility, str(eligibility_dir))
    source_action = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    source_action_dir = tmp_path / "source-action-dry-run"
    h.write_archive_source_action_dry_run_outputs(source_action, str(source_action_dir))
    return {
        "root": root,
        "source_file": source_file,
        "candidate_dir": candidate_dir,
        "candidate_file": candidate_file,
        "plan": plan,
        "plan_dir": plan_dir,
        "dry_dir": dry_dir,
        "bundle_dir": bundle_dir,
        "eligibility_dir": eligibility_dir,
        "source_action_dir": source_action_dir,
    }


def test_standalone_validation_json_is_strict_and_human_is_concise(tmp_path):
    fx = make_source_action_chain(tmp_path)
    result = h.validate_archive_source_action_dry_run(str(fx["source_action_dir"]))
    loaded = json.loads(json.dumps(result))
    assert loaded["schema_version"] == 1
    assert loaded["mode"] == "docker01_artifact_archive_source_action_dry_run_validation"
    assert loaded["status"] == "partial"
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["source_action_available"] is False
    assert loaded["summary"]["required_files_present"] is True
    assert loaded["summary"]["json_parse_ok"] is True
    assert loaded["summary"]["manifest_ok"] is True
    assert loaded["summary"]["checksums_ok"] is True
    assert loaded["summary"]["source_action_contract_ok"] is True
    assert loaded["summary"]["safety_contract_ok"] is True
    assert loaded["summary"]["candidate_manifest_ok"] is True
    assert all(c["source_recheck_ok"] for c in loaded["candidate_validation"])
    human = h.render_archive_source_action_dry_run_validation_summary(result)
    assert human.startswith("# Docker01 Archive Source-Action Dry-Run Validation")
    assert "Source action available: no" in human
    assert "* no source copied" in human
    assert "* no cleanup/prune/delete/restart" in human


def test_full_cross_check_passes_and_out_writes_valid_artifacts_without_modifying_inputs(tmp_path):
    fx = make_source_action_chain(tmp_path)
    watched = [
        *fx["source_action_dir"].rglob("*"),
        *fx["bundle_dir"].rglob("*"),
        *fx["plan_dir"].rglob("*"),
        *fx["dry_dir"].rglob("*"),
        *fx["eligibility_dir"].rglob("*"),
        *fx["root"].rglob("*"),
    ]
    before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in watched if p.is_file()}
    result = h.validate_archive_source_action_dry_run(
        str(fx["source_action_dir"]),
        archive_bundle_dir=str(fx["bundle_dir"]),
        plan_dir=str(fx["plan_dir"]),
        dry_run_receipt_dir=str(fx["dry_dir"]),
        archive_eligibility_review_dir=str(fx["eligibility_dir"]),
    )
    assert result["status"] == "passed"
    assert result["summary"]["archive_bundle_cross_check_status"] == "passed"
    assert result["summary"]["plan_cross_check_status"] == "passed"
    assert result["summary"]["dry_run_receipt_cross_check_status"] == "passed"
    assert result["summary"]["archive_eligibility_cross_check_status"] == "passed"
    out = tmp_path / "validation-out"
    h.write_archive_source_action_dry_run_validation_outputs(result, str(out))
    for name in h.SOURCE_ACTION_DRY_RUN_VALIDATION_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["mode"] == "docker01_artifact_archive_source_action_dry_run_validation"
    checksums = json.loads((out / "checksums.json").read_text())["checksums"]
    for name, digest in checksums.items():
        assert digest == "sha256:" + h.sha256_file(out / name)
    after = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in watched if p.is_file()}
    assert after == before
    assert fx["source_file"].read_text() == "bundle-evidence"
    assert fx["candidate_file"].exists()
    assert not list(tmp_path.glob("*.tar*"))


@pytest.mark.parametrize(
    "filename",
    [
        "archive-source-action-dry-run.json",
        "candidate-source-action-manifest.json",
        "manifest.json",
        "checksums.json",
    ],
)
def test_missing_or_invalid_required_files_fail(tmp_path, filename):
    fx = make_source_action_chain(tmp_path)
    (fx["source_action_dir"] / filename).unlink()
    result = h.validate_archive_source_action_dry_run(str(fx["source_action_dir"]))
    assert result["status"] == "failed"

    fx = make_source_action_chain(tmp_path / "invalid")
    (fx["source_action_dir"] / filename).write_text("{")
    result = h.validate_archive_source_action_dry_run(str(fx["source_action_dir"]))
    assert result["status"] == "failed"


@pytest.mark.parametrize(
    "flag",
    [
        "source_action_available",
        "mutation_performed",
        "source_deleted",
        "source_moved",
        "source_modified",
        "source_copied",
        "archive_created",
        "cleanup_executed",
        "docker_prune_executed",
        "container_restarted",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
    ],
)
def test_unsafe_contract_flags_fail(tmp_path, flag):
    fx = make_source_action_chain(tmp_path)
    path = fx["source_action_dir"] / "archive-source-action-dry-run.json"
    data = json.loads(path.read_text())
    if flag in {"source_action_available", "mutation_performed"}:
        data[flag] = True
    else:
        data["safety"][flag] = True
    path.write_text(json.dumps(data))
    result = h.validate_archive_source_action_dry_run(str(fx["source_action_dir"]))
    assert result["status"] == "failed"


def test_checksum_candidate_plan_and_archive_cross_check_blockers(tmp_path):
    fx = make_source_action_chain(tmp_path)
    (fx["source_action_dir"] / "archive-source-action-dry-run-summary.md").write_text("tamper")
    result = h.validate_archive_source_action_dry_run(str(fx["source_action_dir"]))
    assert result["status"] == "failed"
    assert result["summary"]["checksums_ok"] is False

    fx = make_source_action_chain(tmp_path / "plan-mismatch")
    plan = json.loads((fx["plan_dir"] / "artifact-archive-plan.json").read_text())
    plan["plan_id"] = "sha256:0000000000000000"
    (fx["plan_dir"] / "artifact-archive-plan.json").write_text(json.dumps(plan))
    result = h.validate_archive_source_action_dry_run(
        str(fx["source_action_dir"]), plan_dir=str(fx["plan_dir"])
    )
    assert result["status"] == "failed"

    fx = make_source_action_chain(tmp_path / "archive-mismatch")
    next((fx["bundle_dir"] / "payload").rglob("*.txt")).write_text("tamper")
    result = h.validate_archive_source_action_dry_run(
        str(fx["source_action_dir"]), archive_bundle_dir=str(fx["bundle_dir"])
    )
    assert result["status"] == "failed"


def test_unsafe_symlink_runtime_and_missing_source_behaviors(tmp_path):
    fx = make_source_action_chain(tmp_path)
    path = fx["source_action_dir"] / "candidate-source-action-manifest.json"
    data = json.loads(path.read_text())
    data["candidates"][0]["source_path"] = "/var/lib/docker/containers/x"
    path.write_text(json.dumps(data))
    result = h.validate_archive_source_action_dry_run(str(fx["source_action_dir"]))
    assert result["status"] == "failed"

    fx = make_source_action_chain(tmp_path / "symlink")
    outside = tmp_path / "outside-secret"
    outside.write_text("secret")
    link = tmp_path / "sfai-pr240-qa-bundle-link"
    link.symlink_to(outside)
    path = fx["source_action_dir"] / "candidate-source-action-manifest.json"
    data = json.loads(path.read_text())
    data["candidates"][0]["source_path"] = str(link)
    path.write_text(json.dumps(data))
    result = h.validate_archive_source_action_dry_run(str(fx["source_action_dir"]))
    assert result["status"] == "failed"
    assert outside.read_text() == "secret"

    fx = make_source_action_chain(tmp_path / "missing")
    fx["source_file"].unlink()
    fx["candidate_dir"].rmdir()
    result = h.validate_archive_source_action_dry_run(str(fx["source_action_dir"]))
    assert result["status"] == "partial"
    assert any(c["validation_status"] == "warning" for c in result["candidate_validation"])


def test_cli_json_and_command_surface_guardrails(tmp_path):
    fx = make_source_action_chain(tmp_path)
    proc = subprocess.run(
        [
            sys.executable,
            str(HELPER_PATH),
            "--validate-archive-source-action-dry-run",
            str(fx["source_action_dir"]),
            "--archive-bundle",
            str(fx["bundle_dir"]),
            "--plan-dir",
            str(fx["plan_dir"]),
            "--dry-run-receipt",
            str(fx["dry_dir"]),
            "--archive-eligibility-review",
            str(fx["eligibility_dir"]),
            "--json",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    assert json.loads(proc.stdout)["status"] == "passed"
    source = HELPER_PATH.read_text()
    for forbidden in [
        "--cleanup",
        "--execute-cleanup",
        "--cleanup-now",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
    ]:
        assert forbidden not in source
    assert "shell=True" not in source
    assert "--validate-archive-source-action-dry-run" in source
