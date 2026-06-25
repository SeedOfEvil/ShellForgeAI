import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr238_archive_eligibility_review", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr238_archive_eligibility_review"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def make_chain(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir(parents=True)
    candidate_dir = root / "sfai-pr238-qa-bundle-20260625T000000Z"
    candidate_dir.mkdir()
    (candidate_dir / "evidence.txt").write_text("bundle-evidence")
    candidate_file = root / "sfai-pr238-storage-health-20260625T000000Z.json"
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
    return root, candidate_dir, candidate_file, plan, plan_dir, dry_dir, bundle_dir


def test_happy_path_strict_json_and_human_output(tmp_path):
    _, _, _, plan, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    loaded = json.loads(json.dumps(result))
    assert loaded["schema_version"] == 1
    assert loaded["mode"] == "docker01_artifact_archive_eligibility_review"
    assert loaded["status"] == "eligible_for_review"
    assert loaded["plan_id"] == plan["plan_id"]
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["cleanup_available"] is False
    assert loaded["summary"]["archive_validation_status"] == "passed"
    assert loaded["summary"]["plan_validation_status"] == "passed"
    assert loaded["summary"]["dry_run_receipt_validation_status"] == "passed"
    assert loaded["summary"]["candidate_manifest_match"] is True
    assert loaded["summary"]["archive_payload_verified"] is True
    assert loaded["summary"]["source_preservation_ok"] is True
    assert loaded["summary"]["eligible_candidates"] == 2
    assert all(c["status"] == "eligible" and c["source_exists"] for c in loaded["candidate_review"])
    human = h.render_archive_eligibility_review_summary(result)
    assert human.startswith("# Docker01 Artifact Archive Eligibility Review")
    assert "Cleanup available: no" in human
    assert "* no source deleted" in human
    assert "* no cleanup/prune/delete/restart" in human


def test_out_writes_report_artifacts_and_checksums(tmp_path):
    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    out = tmp_path / "eligibility"
    h.write_archive_eligibility_review_outputs(result, str(out))
    for name in h.ARCHIVE_ELIGIBILITY_REVIEW_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["mode"] == "docker01_artifact_archive_eligibility_review"
    assert manifest["cleanup_available"] is False
    checksums = json.loads((out / "checksums.json").read_text())["checksums"]
    for name, digest in checksums.items():
        assert digest == "sha256:" + h.sha256_file(out / name)


def test_review_does_not_modify_inputs_or_sources(tmp_path):
    root, candidate_dir, candidate_file, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    watched = [*bundle_dir.rglob("*"), *plan_dir.rglob("*"), *dry_dir.rglob("*"), *root.rglob("*")]
    before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in watched if p.is_file()}
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] == "eligible_for_review"
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
    ],
)
def test_invalid_required_evidence_fails(tmp_path, target, filename):
    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    dirs = {"bundle": bundle_dir, "plan": plan_dir, "dry": dry_dir}
    (dirs[target] / filename).write_text("{")
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] in {"not_eligible", "failed"}
    assert result["cleanup_available"] is False


def test_plan_id_and_candidate_manifest_mismatch_block(tmp_path):
    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    receipt_path = dry_dir / "artifact-archive-dry-run-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["plan_id"] = "sha256:0000000000000000"
    receipt_path.write_text(json.dumps(receipt))
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] in {"not_eligible", "failed"}
    assert result["summary"]["plan_id_match"] is False

    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path / "fresh")
    manifest_path = bundle_dir / "source-candidate-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["candidates"].pop()
    manifest_path.write_text(json.dumps(manifest))
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] in {"not_eligible", "failed"}
    assert result["summary"]["candidate_manifest_match"] is False


def test_checksum_and_source_preservation_and_unsafe_flags_block(tmp_path):
    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    payload = next((bundle_dir / "payload").rglob("*.txt"))
    payload.write_text("tampered")
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] in {"not_eligible", "failed"}
    assert result["summary"]["archive_payload_verified"] is False

    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path / "fresh1")
    preservation_path = bundle_dir / "source-preservation.json"
    preservation = json.loads(preservation_path.read_text())
    preservation["source_delete_performed"] = True
    preservation_path.write_text(json.dumps(preservation))
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] in {"not_eligible", "failed"}
    assert result["summary"]["source_preservation_ok"] is False

    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path / "fresh2")
    receipt_path = bundle_dir / "archive-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["safety"]["container_restarted"] = True
    receipt_path.write_text(json.dumps(receipt))
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] in {"not_eligible", "failed"}


@pytest.mark.parametrize("name", ["not-shellforge", "srv", "compose.yml"])
def test_unsafe_candidate_paths_block(tmp_path, name):
    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    manifest_path = bundle_dir / "source-candidate-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["candidates"][0]["path"] = str(tmp_path / name)
    manifest_path.write_text(json.dumps(manifest))
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] in {"not_eligible", "failed"}


def test_symlink_candidate_blocks_and_is_not_followed(tmp_path):
    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    outside = tmp_path / "outside-secret"
    outside.write_text("secret")
    link = tmp_path / "sfai-pr238-qa-bundle-symlink"
    link.symlink_to(outside)
    manifest_path = bundle_dir / "source-candidate-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["candidates"][0]["path"] = str(link)
    manifest["candidates"][0]["class"] = "qa_bundle_artifacts"
    manifest_path.write_text(json.dumps(manifest))
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] in {"not_eligible", "failed"}
    assert outside.read_text() == "secret"


def test_missing_source_can_be_partial_when_archive_and_preservation_are_clean(tmp_path):
    _, candidate_dir, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    (candidate_dir / "evidence.txt").unlink()
    candidate_dir.rmdir()
    result = h.build_archive_eligibility_review(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] == "partial"
    assert any(c["status"] == "warning" for c in result["candidate_review"])


def test_no_cleanup_execution_flags_or_shell_true_literal_introduced():
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
