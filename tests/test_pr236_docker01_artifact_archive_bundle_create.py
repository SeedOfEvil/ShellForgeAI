import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr236_archive_bundle", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr236_archive_bundle"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def make_chain(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir(parents=True)
    candidate = root / "sfai-pr236-qa-bundle-20260624T000000Z"
    candidate.mkdir()
    (candidate / "evidence.txt").write_text("copy-only-evidence")
    source_file = root / "sfai-pr236-storage-health-20260624T000000Z.json"
    source_file.write_text('{"ok": true}')
    plan = h.build_plan(str(root))
    plan_dir = tmp_path / "plan"
    h.write_outputs(plan, str(plan_dir))
    receipt = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id=plan["plan_id"])
    receipt_dir = tmp_path / "receipt"
    h.write_dry_run_receipt_outputs(receipt, str(receipt_dir))
    return root, candidate, source_file, plan, plan_dir, receipt_dir


def test_happy_path_creates_copy_only_archive_bundle(tmp_path):
    _, candidate_dir, source_file, plan, plan_dir, receipt_dir = make_chain(tmp_path)
    before_dir = (candidate_dir / "evidence.txt").read_text()
    before_file = source_file.read_text()
    out = tmp_path / "bundle"

    result = h.build_archive_bundle(
        str(plan_dir),
        str(receipt_dir),
        supplied_plan_id=plan["plan_id"],
        confirm=h.CONFIRMATION_PHRASE,
        archive_out=str(out),
    )
    loaded = json.loads(json.dumps(result))
    assert loaded["mode"] == "docker01_artifact_archive_bundle_create"
    assert loaded["status"] == "archive_created"
    assert loaded["mutation_performed"] is True
    assert loaded["mutation_type"] == "copy_only_archive_bundle_create"
    assert loaded["confirmation_phrase_matched"] is True
    assert loaded["summary"]["candidate_items"] == 2
    assert loaded["summary"]["files_copied"] == 2
    assert loaded["summary"]["directories_copied"] == 1
    assert loaded["summary"]["source_deleted"] is False
    assert loaded["summary"]["source_moved"] is False
    assert loaded["summary"]["source_modified"] is False
    assert loaded["source_preservation"]["source_paths_verified_present_after_copy"] is True
    assert loaded["safety"]["source_deleted"] is False
    assert loaded["safety"]["source_moved"] is False
    assert loaded["safety"]["source_modified"] is False
    assert loaded["safety"]["cleanup_executed"] is False
    assert loaded["safety"]["docker_prune_executed"] is False
    assert loaded["safety"]["docker_volume_removed"] is False
    assert loaded["safety"]["container_restarted"] is False
    assert loaded["safety"]["remediation_executed"] is False
    assert loaded["safety"]["rollback_executed"] is False
    assert loaded["safety"]["recovery_executed"] is False
    assert loaded["safety"]["shell_true"] is False

    for name in h.ARCHIVE_BUNDLE_OUT_FILES:
        assert (out / name).is_file(), name
    assert (out / "payload").is_dir()
    copied_texts = [p.read_text() for p in (out / "payload").rglob("*") if p.is_file()]
    assert "copy-only-evidence" in copied_texts
    assert before_dir == (candidate_dir / "evidence.txt").read_text()
    assert before_file == source_file.read_text()
    manifest_text = (out / "archive-manifest.json").read_text()
    assert "copy-only-evidence" not in manifest_text
    checksums = json.loads((out / "archive-checksums.json").read_text())["checksums"]
    for rel, digest in checksums.items():
        assert digest == "sha256:" + h.sha256_file(out / rel)
    human = h.render_archive_bundle_summary(result)
    assert "# Docker01 Artifact Archive Bundle Created" in human
    assert "Mutation type: copy-only archive bundle creation" in human
    assert "* no source deletion" in human


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"supplied_plan_id": None}, "plan_id_supplied"),
        ({"supplied_plan_id": "sha256:0000000000000000"}, "plan_id_match"),
        ({"confirm": None}, "confirmation_phrase_matched"),
        ({"confirm": "WRONG"}, "confirmation_phrase_matched"),
        ({"archive_out": None}, "archive_out_safe"),
    ],
)
def test_required_gates_fail_before_copy(tmp_path, kwargs, error):
    _, _, _, plan, plan_dir, receipt_dir = make_chain(tmp_path)
    out = tmp_path / "bundle"
    params = {
        "supplied_plan_id": plan["plan_id"],
        "confirm": h.CONFIRMATION_PHRASE,
        "archive_out": str(out),
    }
    params.update(kwargs)
    result = h.build_archive_bundle(str(plan_dir), str(receipt_dir), **params)
    assert result["status"] == "failed"
    assert any(c["name"] == error and c["status"] == "failed" for c in result["checks"])
    assert result["source_preservation"]["source_delete_performed"] is False
    assert result["source_preservation"]["source_move_performed"] is False
    assert not (out / "payload").exists()


def test_unsafe_and_non_empty_archive_out_fail_before_copy(tmp_path):
    _, _, _, plan, plan_dir, receipt_dir = make_chain(tmp_path)
    non_empty = tmp_path / "non-empty"
    non_empty.mkdir()
    (non_empty / "existing").write_text("x")
    for archive_out in ("/tmp", str(non_empty)):
        result = h.build_archive_bundle(
            str(plan_dir),
            str(receipt_dir),
            supplied_plan_id=plan["plan_id"],
            confirm=h.CONFIRMATION_PHRASE,
            archive_out=archive_out,
        )
        assert result["status"] == "failed"
        assert any(
            c["name"] == "archive_out_safe" and c["status"] == "failed" for c in result["checks"]
        )


def test_invalid_plan_or_receipt_and_missing_candidate_fail_before_copy(tmp_path):
    _, _, source_file, plan, plan_dir, receipt_dir = make_chain(tmp_path)
    (plan_dir / "artifact-archive-plan.json").write_text("{")
    result = h.build_archive_bundle(
        str(plan_dir),
        str(receipt_dir),
        supplied_plan_id=plan["plan_id"],
        confirm=h.CONFIRMATION_PHRASE,
        archive_out=str(tmp_path / "bad-plan"),
    )
    assert result["status"] == "failed"
    assert any(
        c["name"] == "plan_validation_passed" and c["status"] == "failed" for c in result["checks"]
    )

    _, _, source_file, plan, plan_dir, receipt_dir = make_chain(tmp_path / "fresh")
    (receipt_dir / "artifact-archive-dry-run-receipt.json").write_text("{")
    result = h.build_archive_bundle(
        str(plan_dir),
        str(receipt_dir),
        supplied_plan_id=plan["plan_id"],
        confirm=h.CONFIRMATION_PHRASE,
        archive_out=str(tmp_path / "bad-receipt"),
    )
    assert result["status"] == "failed"
    assert any(
        c["name"] == "dry_run_receipt_validation_passed" and c["status"] == "failed"
        for c in result["checks"]
    )

    _, _, source_file, plan, plan_dir, receipt_dir = make_chain(tmp_path / "missing")
    source_file.unlink()
    result = h.build_archive_bundle(
        str(plan_dir),
        str(receipt_dir),
        supplied_plan_id=plan["plan_id"],
        confirm=h.CONFIRMATION_PHRASE,
        archive_out=str(tmp_path / "missing-bundle"),
    )
    assert result["status"] == "failed"
    assert any(
        c["name"] == "candidate_paths_present" and c["status"] == "failed" for c in result["checks"]
    )


def test_symlink_candidate_archive_out_nesting_and_runtime_candidate_refuse(tmp_path):
    root, _, _, plan, plan_dir, receipt_dir = make_chain(tmp_path)
    manifest = json.loads((plan_dir / "candidate-manifest.json").read_text())
    link = root / "sfai-pr236-qa-bundle-symlink"
    link.symlink_to(root / "sfai-pr236-qa-bundle-20260624T000000Z")
    manifest["candidates"].append(
        {
            "path": str(link),
            "class": "qa_bundle_artifacts",
            "type": "directory",
            "size_bytes": 0,
            "future_action": "archive_candidate_only",
        }
    )
    (plan_dir / "candidate-manifest.json").write_text(json.dumps(manifest))
    result = h.build_archive_bundle(
        str(plan_dir),
        str(receipt_dir),
        supplied_plan_id=plan["plan_id"],
        confirm=h.CONFIRMATION_PHRASE,
        archive_out=str(tmp_path / "symlink-bundle"),
    )
    assert result["status"] == "failed"

    root, candidate_dir, _, plan, plan_dir, receipt_dir = make_chain(tmp_path / "nest")
    result = h.build_archive_bundle(
        str(plan_dir),
        str(receipt_dir),
        supplied_plan_id=plan["plan_id"],
        confirm=h.CONFIRMATION_PHRASE,
        archive_out=str(candidate_dir / "archive"),
    )
    assert result["status"] == "failed"
    assert any(
        c["name"] == "archive_out_not_inside_candidate" and c["status"] == "failed"
        for c in result["checks"]
    )

    manifest = json.loads((plan_dir / "candidate-manifest.json").read_text())
    manifest["candidates"][0]["path"] = "/var/lib/docker/sfai-pr236-qa-bundle-x"
    (plan_dir / "candidate-manifest.json").write_text(json.dumps(manifest))
    result = h.build_archive_bundle(
        str(plan_dir),
        str(receipt_dir),
        supplied_plan_id=plan["plan_id"],
        confirm=h.CONFIRMATION_PHRASE,
        archive_out=str(tmp_path / "runtime-bundle"),
    )
    assert result["status"] == "failed"


def test_partial_copy_failure_leaves_inspectable_evidence_and_preserves_sources(
    tmp_path, monkeypatch
):
    _, candidate_dir, source_file, plan, plan_dir, receipt_dir = make_chain(tmp_path)
    original = source_file.read_text()
    calls = {"n": 0}
    real_copy2 = h.shutil.copy2

    def flaky_copy2(src, dst, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] > 1:
            raise OSError("simulated copy failure")
        return real_copy2(src, dst, *args, **kwargs)

    monkeypatch.setattr(h.shutil, "copy2", flaky_copy2)
    out = tmp_path / "partial"
    result = h.build_archive_bundle(
        str(plan_dir),
        str(receipt_dir),
        supplied_plan_id=plan["plan_id"],
        confirm=h.CONFIRMATION_PHRASE,
        archive_out=str(out),
    )
    assert result["status"] == "partial"
    assert "simulated copy failure" in " ".join(result["errors"])
    assert (out / "archive-receipt.json").is_file()
    assert (out / "payload").is_dir()
    assert source_file.exists() and source_file.read_text() == original
    assert (candidate_dir / "evidence.txt").exists()
    assert result["source_preservation"]["source_delete_performed"] is False
    assert result["source_preservation"]["source_move_performed"] is False
    assert result["source_preservation"]["source_modify_performed"] is False


def test_no_broad_mutation_flags_or_shell_true_options_introduced():
    parser_text = HELPER_PATH.read_text()
    for forbidden in (
        "--cleanup",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--rm",
        "--rmi",
    ):
        assert forbidden not in parser_text
    assert "shell=True" not in parser_text.replace("no shell=True", "")
    assert "subprocess" not in parser_text
