import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr237_archive_bundle_validation", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr237_archive_bundle_validation"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def make_chain(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir(parents=True)
    candidate_dir = root / "sfai-pr237-qa-bundle-20260625T000000Z"
    candidate_dir.mkdir()
    (candidate_dir / "evidence.txt").write_text("bundle-evidence")
    candidate_file = root / "sfai-pr237-storage-health-20260625T000000Z.json"
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


def test_valid_archive_bundle_validates_standalone_and_strict_json(tmp_path):
    _, _, _, plan, _, _, bundle_dir = make_chain(tmp_path)
    result = h.validate_archive_bundle(str(bundle_dir))
    loaded = json.loads(json.dumps(result))
    assert loaded["schema_version"] == 1
    assert loaded["mode"] == "docker01_artifact_archive_bundle_validation"
    assert loaded["status"] == "passed"
    assert loaded["plan_id"] == plan["plan_id"]
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["summary"]["plan_cross_check_status"] == "not_requested"
    assert loaded["summary"]["dry_run_cross_check_status"] == "not_requested"
    assert loaded["summary"]["candidate_items"] == 2
    assert loaded["summary"]["files_copied"] == 2
    assert loaded["safety"]["archive_created"] is False
    assert loaded["safety"]["source_copied"] is False
    assert loaded["safety"]["cleanup_executed"] is False
    assert loaded["future_cleanup_eligible_for_review"] is True
    assert loaded["future_cleanup_available"] is False


def test_valid_archive_bundle_with_matching_plan_and_dry_run_passes(tmp_path):
    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    result = h.validate_archive_bundle(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] == "passed"
    assert result["summary"]["plan_cross_check_status"] == "passed"
    assert result["summary"]["dry_run_cross_check_status"] == "passed"


def test_human_output_is_concise_and_pasteable(tmp_path):
    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    result = h.validate_archive_bundle(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    human = h.render_archive_bundle_validation_summary(result)
    assert human.startswith("# Docker01 Artifact Archive Bundle Validation")
    assert "## Checks" in human
    assert "* no archive created by validator" in human
    assert "* no source copied by validator" in human
    assert "* no cleanup/prune/delete/restart" in human


def test_out_writes_validation_artifacts_and_checksums(tmp_path):
    _, _, _, _, _, _, bundle_dir = make_chain(tmp_path)
    result = h.validate_archive_bundle(str(bundle_dir))
    out = tmp_path / "validation"
    h.write_archive_bundle_validation_outputs(result, str(out))
    for name in h.ARCHIVE_BUNDLE_VALIDATION_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    checksums = json.loads((out / "checksums.json").read_text())["checksums"]
    assert manifest["mode"] == "docker01_artifact_archive_bundle_validation"
    for name, digest in checksums.items():
        assert digest == "sha256:" + h.sha256_file(out / name)


def test_validator_does_not_modify_bundle_plan_dry_run_or_sources(tmp_path):
    root, candidate_dir, candidate_file, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    watched = [*bundle_dir.rglob("*"), *plan_dir.rglob("*"), *dry_dir.rglob("*"), *root.rglob("*")]
    before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in watched if p.is_file()}
    result = h.validate_archive_bundle(
        str(bundle_dir), plan_dir=str(plan_dir), dry_run_receipt_dir=str(dry_dir)
    )
    assert result["status"] == "passed"
    after = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in watched if p.is_file()}
    assert after == before
    assert (candidate_dir / "evidence.txt").read_text() == "bundle-evidence"
    assert candidate_file.read_text() == '{"ok": true}'
    assert not list(tmp_path.glob("*.tar*"))
    assert not list(tmp_path.glob("*.zip"))


@pytest.mark.parametrize(
    "filename",
    ["archive-receipt.json", "archive-manifest.json", "archive-checksums.json"],
)
def test_required_archive_files_missing_fail(tmp_path, filename):
    _, _, _, _, _, _, bundle_dir = make_chain(tmp_path)
    (bundle_dir / filename).unlink()
    result = h.validate_archive_bundle(str(bundle_dir))
    assert result["status"] == "failed"
    assert any(
        c["name"] == "required_files_present" and c["status"] == "failed" for c in result["checks"]
    )


def test_invalid_json_fails(tmp_path):
    _, _, _, _, _, _, bundle_dir = make_chain(tmp_path)
    (bundle_dir / "archive-receipt.json").write_text("{")
    result = h.validate_archive_bundle(str(bundle_dir))
    assert result["status"] == "failed"
    assert any(c["name"] == "json_parse_ok" and c["status"] == "failed" for c in result["checks"])


def test_manifest_missing_payload_entry_and_checksum_mismatch_fail(tmp_path):
    _, _, _, _, _, _, bundle_dir = make_chain(tmp_path)
    manifest_path = bundle_dir / "archive-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["entries"][0]["entries"] = []
    manifest_path.write_text(json.dumps(manifest))
    result = h.validate_archive_bundle(str(bundle_dir))
    assert result["status"] == "failed"
    assert any(c["name"] == "manifest_ok" and c["status"] == "failed" for c in result["checks"])

    _, _, _, _, _, _, bundle_dir = make_chain(tmp_path / "fresh")
    payload = next((bundle_dir / "payload").rglob("*.txt"))
    payload.write_text("tampered")
    result = h.validate_archive_bundle(str(bundle_dir))
    assert result["status"] == "failed"
    assert any(c["name"] == "checksums_ok" and c["status"] == "failed" for c in result["checks"])


@pytest.mark.parametrize("bad_rel", ["/abs/payload.txt", "payload/../evil", "not-payload/file"])
def test_unsafe_payload_paths_fail(tmp_path, bad_rel):
    _, _, _, _, _, _, bundle_dir = make_chain(tmp_path)
    checksums = json.loads((bundle_dir / "archive-checksums.json").read_text())
    checksums["checksums"] = {bad_rel: "sha256:bad"}
    (bundle_dir / "archive-checksums.json").write_text(json.dumps(checksums))
    result = h.validate_archive_bundle(str(bundle_dir))
    assert result["status"] == "failed"
    assert any(c["name"] == "checksums_ok" and c["status"] == "failed" for c in result["checks"])


def test_symlink_payload_fails_and_is_not_followed(tmp_path):
    _, _, _, _, _, _, bundle_dir = make_chain(tmp_path)
    payload = next((bundle_dir / "payload").rglob("*.txt"))
    payload.unlink()
    payload.symlink_to(tmp_path / "outside-secret")
    (tmp_path / "outside-secret").write_text("secret")
    result = h.validate_archive_bundle(str(bundle_dir))
    assert result["status"] == "failed"
    assert (tmp_path / "outside-secret").read_text() == "secret"


@pytest.mark.parametrize(
    "flag",
    [
        "source_deleted",
        "source_moved",
        "source_modified",
        "cleanup_executed",
        "docker_prune_executed",
        "docker_compose_executed",
        "container_restarted",
        "file_deleted",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
    ],
)
def test_unsafe_receipt_safety_flags_fail(tmp_path, flag):
    _, _, _, _, _, _, bundle_dir = make_chain(tmp_path)
    receipt_path = bundle_dir / "archive-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["safety"][flag] = True
    if flag.startswith("source_"):
        receipt["summary"][flag] = True
    receipt_path.write_text(json.dumps(receipt))
    result = h.validate_archive_bundle(str(bundle_dir))
    assert result["status"] == "failed"


def test_source_preservation_metadata_failure_and_missing_sources_partial(tmp_path):
    _, _, _, _, _, _, bundle_dir = make_chain(tmp_path)
    preservation_path = bundle_dir / "source-preservation.json"
    preservation = json.loads(preservation_path.read_text())
    preservation["source_delete_performed"] = True
    preservation_path.write_text(json.dumps(preservation))
    result = h.validate_archive_bundle(str(bundle_dir))
    assert result["status"] == "failed"

    root, _, _, _, _, _, bundle_dir = make_chain(tmp_path / "missing_sources")
    for item in root.iterdir():
        if item.is_file():
            item.unlink()
        else:
            for child in item.iterdir():
                child.unlink()
            item.rmdir()
    result = h.validate_archive_bundle(str(bundle_dir))
    assert result["status"] == "partial"
    assert result["summary"]["source_preservation_ok"] is True


def test_cross_check_mismatches_and_invalid_inputs_fail(tmp_path):
    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path)
    plan_json = json.loads((plan_dir / "artifact-archive-plan.json").read_text())
    plan_json["plan_id"] = "sha256:0000000000000000"
    (plan_dir / "artifact-archive-plan.json").write_text(json.dumps(plan_json))
    assert h.validate_archive_bundle(str(bundle_dir), plan_dir=str(plan_dir))["status"] == "failed"

    _, _, _, _, plan_dir, dry_dir, bundle_dir = make_chain(tmp_path / "drybad")
    cand = json.loads((dry_dir / "candidate-manifest.json").read_text())
    cand["candidates"][0]["path"] += "-different"
    (dry_dir / "candidate-manifest.json").write_text(json.dumps(cand))
    result = h.validate_archive_bundle(str(bundle_dir), dry_run_receipt_dir=str(dry_dir))
    assert result["status"] == "failed"
    assert result["summary"]["dry_run_cross_check_status"] == "failed"


def test_no_mutation_flags_or_shell_true_introduced():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    for forbidden in (
        "--cleanup",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--rm",
        "--rmi",
    ):
        assert forbidden not in source
