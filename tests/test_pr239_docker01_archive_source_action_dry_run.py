import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "pr239_archive_source_action_dry_run", HELPER_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr239_archive_source_action_dry_run"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def make_chain(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir(parents=True)
    candidate_dir = root / "sfai-pr239-qa-bundle-20260625T000000Z"
    candidate_dir.mkdir()
    (candidate_dir / "evidence.txt").write_text("bundle-evidence")
    candidate_file = root / "sfai-pr239-storage-health-20260625T000000Z.json"
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
    return root, candidate_dir, candidate_file, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir


def test_happy_path_json_human_and_source_recheck(tmp_path):
    _, _, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path)
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    loaded = json.loads(json.dumps(result))
    assert loaded["schema_version"] == 1
    assert loaded["mode"] == "docker01_artifact_archive_source_action_dry_run"
    assert loaded["status"] == "ready_for_source_action_review"
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["source_action_available"] is False
    assert loaded["future_source_action_review_only"] is True
    assert loaded["summary"]["archive_validation_status"] == "passed"
    assert loaded["summary"]["plan_validation_status"] == "passed"
    assert loaded["summary"]["dry_run_receipt_validation_status"] == "passed"
    assert loaded["summary"]["archive_eligibility_status"] == "eligible_for_review"
    assert loaded["summary"]["plan_id_match"] is True
    assert loaded["summary"]["candidate_manifest_match"] is True
    assert loaded["summary"]["archive_payload_verified"] is True
    assert loaded["summary"]["source_preservation_ok"] is True
    assert loaded["summary"]["would_review_candidates"] == 2
    assert all(
        c["status"] == "would_review_for_source_action"
        for c in loaded["candidate_source_action_manifest"]
    )
    assert all(c["source_recheck_ok"] is True for c in loaded["candidate_source_action_manifest"])
    human = h.render_archive_source_action_dry_run_summary(result)
    assert human.startswith("# Docker01 Archive-Backed Source Action Dry Run")
    assert "Source action available: no" in human
    assert "* no source deleted" in human
    assert "* no cleanup/prune/delete/restart" in human


def test_out_writes_artifacts_and_checksums_without_modifying_inputs(tmp_path):
    root, candidate_dir, candidate_file, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = (
        make_chain(tmp_path)
    )
    watched = [
        *bundle_dir.rglob("*"),
        *plan_dir.rglob("*"),
        *dry_dir.rglob("*"),
        *eligibility_dir.rglob("*"),
        *root.rglob("*"),
    ]
    before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in watched if p.is_file()}
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    out = tmp_path / "source-action-dry-run"
    h.write_archive_source_action_dry_run_outputs(result, str(out))
    for name in h.SOURCE_ACTION_DRY_RUN_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["mode"] == "docker01_artifact_archive_source_action_dry_run"
    assert manifest["archive_created"] is False
    assert manifest["candidate_contents_copied"] is False
    checksums = json.loads((out / "checksums.json").read_text())["checksums"]
    for name, digest in checksums.items():
        assert digest == "sha256:" + h.sha256_file(out / name)
    after = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in watched if p.is_file()}
    assert after == before
    assert (candidate_dir / "evidence.txt").read_text() == "bundle-evidence"
    assert candidate_file.read_text() == '{"ok": true}'
    assert not list(tmp_path.glob("*.tar*"))


@pytest.mark.parametrize(
    "target,filename",
    [
        ("bundle", "archive-receipt.json"),
        ("plan", "artifact-archive-plan.json"),
        ("dry", "artifact-archive-dry-run-receipt.json"),
        ("eligibility", "artifact-archive-eligibility-review.json"),
    ],
)
def test_invalid_required_evidence_not_ready_or_failed(tmp_path, target, filename):
    _, _, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path)
    dirs = {"bundle": bundle_dir, "plan": plan_dir, "dry": dry_dir, "eligibility": eligibility_dir}
    (dirs[target] / filename).write_text("{")
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    assert result["status"] in {"not_ready", "failed"}
    assert result["source_action_available"] is False


def test_plan_id_candidate_manifest_checksum_and_preservation_block(tmp_path):
    _, _, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path)
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id="sha256:0000000000000000",
    )
    assert result["status"] in {"not_ready", "failed"}
    assert result["summary"]["plan_id_match"] is False

    _, _, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path / "fresh1")
    manifest_path = bundle_dir / "source-candidate-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["candidates"].pop()
    manifest_path.write_text(json.dumps(manifest))
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    assert result["status"] in {"not_ready", "failed"}
    assert result["summary"]["candidate_manifest_match"] is False

    _, _, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path / "fresh2")
    next((bundle_dir / "payload").rglob("*.txt")).write_text("tampered")
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    assert result["status"] in {"not_ready", "failed"}
    assert result["summary"]["archive_payload_verified"] is False

    _, _, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path / "fresh3")
    preservation_path = bundle_dir / "source-preservation.json"
    preservation = json.loads(preservation_path.read_text())
    preservation["source_move_performed"] = True
    preservation_path.write_text(json.dumps(preservation))
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    assert result["status"] in {"not_ready", "failed"}
    assert result["summary"]["source_preservation_ok"] is False


@pytest.mark.parametrize(
    "flag",
    [
        "source_deleted",
        "source_moved",
        "source_modified",
        "cleanup_executed",
        "docker_prune_executed",
        "container_restarted",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
    ],
)
def test_unsafe_flags_block(tmp_path, flag):
    _, _, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path)
    receipt_path = bundle_dir / "archive-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["safety"][flag] = True
    receipt_path.write_text(json.dumps(receipt))
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    assert result["status"] in {"not_ready", "failed"}


@pytest.mark.parametrize("name", ["not-shellforge", "srv", "compose.yml"])
def test_unsafe_candidate_paths_block(tmp_path, name):
    _, _, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path)
    manifest_path = bundle_dir / "source-candidate-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["candidates"][0]["path"] = str(tmp_path / name)
    manifest_path.write_text(json.dumps(manifest))
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    assert result["status"] in {"not_ready", "failed"}


def test_symlink_blocks_and_is_not_followed(tmp_path):
    _, _, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path)
    outside = tmp_path / "outside-secret"
    outside.write_text("secret")
    link = tmp_path / "sfai-pr239-qa-bundle-symlink"
    link.symlink_to(outside)
    manifest_path = bundle_dir / "source-candidate-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["candidates"][0]["path"] = str(link)
    manifest["candidates"][0]["class"] = "qa_bundle_artifacts"
    manifest_path.write_text(json.dumps(manifest))
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    assert result["status"] in {"not_ready", "failed"}
    assert outside.read_text() == "secret"


def test_missing_source_can_be_partial_when_archive_and_preservation_clean(tmp_path):
    _, candidate_dir, _, plan, plan_dir, dry_dir, bundle_dir, eligibility_dir = make_chain(tmp_path)
    (candidate_dir / "evidence.txt").unlink()
    candidate_dir.rmdir()
    # Refresh eligibility so its own source recheck evidence is partial rather than stale.
    eligibility = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    h.write_archive_eligibility_review_outputs(eligibility, str(eligibility_dir))
    result = h.build_archive_source_action_dry_run(
        str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
        supplied_plan_id=plan["plan_id"],
    )
    assert result["status"] == "partial"
    assert any(c["status"] == "warning" for c in result["candidate_source_action_manifest"])


def test_command_surface_guard_and_no_shell_true_literal():
    source = HELPER_PATH.read_text()
    for forbidden in [
        "--cleanup",
        "--execute-cleanup",
        "--cleanup-now",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--rm",
        "--rmi",
    ]:
        assert forbidden not in source
    assert "shell=True" not in source
    assert "--archive-source-action-dry-run" in source
