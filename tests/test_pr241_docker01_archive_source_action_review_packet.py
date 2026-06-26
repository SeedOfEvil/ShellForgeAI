import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr241_review_packet", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr241_review_packet"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def make_chain(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir(parents=True)
    candidate_dir = root / "sfai-pr241-qa-bundle-20260626T000000Z"
    candidate_dir.mkdir()
    source_file = candidate_dir / "evidence.txt"
    source_file.write_text("review-packet-evidence")
    candidate_file = root / "sfai-pr241-storage-health-20260626T000000Z.json"
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
    assert source_action["status"] == "ready_for_source_action_review"
    source_action_dir = tmp_path / "source-action"
    h.write_archive_source_action_dry_run_outputs(source_action, str(source_action_dir))
    validation = h.validate_archive_source_action_dry_run(
        str(source_action_dir),
        archive_bundle_dir=str(bundle_dir),
        plan_dir=str(plan_dir),
        dry_run_receipt_dir=str(dry_dir),
        archive_eligibility_review_dir=str(eligibility_dir),
    )
    assert validation["status"] == "passed"
    validation_dir = tmp_path / "validation"
    h.write_archive_source_action_dry_run_validation_outputs(validation, str(validation_dir))
    return locals()


def build_packet(fx):
    return h.build_archive_source_action_review_packet(
        str(fx["source_action_dir"]),
        source_action_validation_dir=str(fx["validation_dir"]),
        archive_bundle_dir=str(fx["bundle_dir"]),
        plan_dir=str(fx["plan_dir"]),
        dry_run_receipt_dir=str(fx["dry_dir"]),
        archive_eligibility_review_dir=str(fx["eligibility_dir"]),
        supplied_plan_id=fx["plan"]["plan_id"],
    )


def mtimes(paths):
    return {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in paths if p.is_file()}


def test_happy_path_strict_json_human_and_outputs_are_read_only(tmp_path):
    fx = make_chain(tmp_path)
    watched = [
        *fx["source_action_dir"].rglob("*"),
        *fx["validation_dir"].rglob("*"),
        *fx["bundle_dir"].rglob("*"),
        *fx["plan_dir"].rglob("*"),
        *fx["dry_dir"].rglob("*"),
        *fx["eligibility_dir"].rglob("*"),
        *fx["root"].rglob("*"),
    ]
    before = mtimes(watched)
    result = build_packet(fx)
    loaded = json.loads(json.dumps(result))
    assert loaded["mode"] == "docker01_artifact_archive_source_action_review_packet"
    assert loaded["status"] == "ready_for_human_review"
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["source_action_available"] is False
    assert loaded["human_review_packet_only"] is True
    assert loaded["summary"]["source_action_validation_status"] == "passed"
    assert loaded["summary"]["plan_id_match"] is True
    assert loaded["summary"]["candidate_manifest_match"] is True
    assert loaded["summary"]["archive_payload_verified"] is True
    assert loaded["summary"]["source_preservation_ok"] is True
    human = h.render_archive_source_action_review_packet(result)
    assert human.startswith("# Docker01 Archive Source-Action Human Review Packet")
    assert "* not approval" in human
    assert "* not execution" in human
    assert "Source action available: no" in human
    out = tmp_path / "packet"
    h.write_archive_source_action_review_packet_outputs(result, str(out))
    for name in h.SOURCE_ACTION_REVIEW_PACKET_OUT_FILES:
        assert (out / name).is_file(), name
    assert "not an approval" in (out / "future-source-action-signoff-template.md").read_text()
    assert "not execution" in (out / "future-source-action-signoff-template.md").read_text()
    assert "not authorization" in (out / "future-source-action-signoff-template.md").read_text()
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["mode"] == "docker01_artifact_archive_source_action_review_packet"
    checksums = json.loads((out / "checksums.json").read_text())["checksums"]
    for name, digest in checksums.items():
        assert digest == "sha256:" + h.sha256_file(out / name)
    assert mtimes(watched) == before
    assert fx["source_file"].read_text() == "review-packet-evidence"
    assert fx["candidate_file"].exists()
    assert not list(tmp_path.glob("*.tar*"))


@pytest.mark.parametrize(
    "filename", ["archive-source-action-dry-run-validation.json", "manifest.json", "checksums.json"]
)
def test_missing_or_invalid_validation_file_fails(tmp_path, filename):
    fx = make_chain(tmp_path)
    (fx["validation_dir"] / filename).unlink()
    assert build_packet(fx)["status"] == "failed"
    fx = make_chain(tmp_path / "invalid")
    (fx["validation_dir"] / filename).write_text("{")
    assert build_packet(fx)["status"] in {"failed", "not_ready"}


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
def test_blocking_unsafe_flags_fail(tmp_path, flag):
    fx = make_chain(tmp_path)
    path = fx["source_action_dir"] / "archive-source-action-dry-run.json"
    data = json.loads(path.read_text())
    if flag in {"source_action_available", "mutation_performed"}:
        data[flag] = True
    else:
        data["safety"][flag] = True
    path.write_text(json.dumps(data))
    assert build_packet(fx)["status"] in {"failed", "not_ready"}


def test_plan_candidate_checksum_unsafe_path_and_symlink_blockers(tmp_path):
    fx = make_chain(tmp_path)
    assert (
        h.build_archive_source_action_review_packet(
            str(fx["source_action_dir"]),
            source_action_validation_dir=str(fx["validation_dir"]),
            archive_bundle_dir=str(fx["bundle_dir"]),
            plan_dir=str(fx["plan_dir"]),
            dry_run_receipt_dir=str(fx["dry_dir"]),
            archive_eligibility_review_dir=str(fx["eligibility_dir"]),
            supplied_plan_id="sha256:0000000000000000",
        )["status"]
        == "not_ready"
    )

    fx = make_chain(tmp_path / "checksum")
    next((fx["bundle_dir"] / "payload").rglob("*.txt")).write_text("tamper")
    assert build_packet(fx)["status"] == "not_ready"

    fx = make_chain(tmp_path / "unsafe")
    path = fx["source_action_dir"] / "candidate-source-action-manifest.json"
    data = json.loads(path.read_text())
    data["candidates"][0]["source_path"] = "/var/lib/docker/containers/x"
    path.write_text(json.dumps(data))
    assert build_packet(fx)["status"] in {"failed", "not_ready"}

    fx = make_chain(tmp_path / "symlink")
    outside = tmp_path / "outside"
    outside.write_text("secret")
    link = tmp_path / "sfai-pr241-qa-bundle-link"
    link.symlink_to(outside)
    path = fx["source_action_dir"] / "candidate-source-action-manifest.json"
    data = json.loads(path.read_text())
    data["candidates"][0]["source_path"] = str(link)
    path.write_text(json.dumps(data))
    assert build_packet(fx)["status"] in {"failed", "not_ready"}
    assert outside.read_text() == "secret"


def test_partial_missing_source_and_cli_guardrails(tmp_path):
    fx = make_chain(tmp_path)
    fx["source_file"].unlink()
    fx["candidate_dir"].rmdir()
    result = build_packet(fx)
    assert result["status"] == "partial"
    assert any(c["status"] == "warning" for c in result["candidate_review"])

    fx = make_chain(tmp_path / "cli")
    proc = subprocess.run(
        [
            sys.executable,
            str(HELPER_PATH),
            "--archive-source-action-review-packet",
            str(fx["source_action_dir"]),
            "--source-action-validation",
            str(fx["validation_dir"]),
            "--archive-bundle",
            str(fx["bundle_dir"]),
            "--plan-dir",
            str(fx["plan_dir"]),
            "--dry-run-receipt",
            str(fx["dry_dir"]),
            "--archive-eligibility-review",
            str(fx["eligibility_dir"]),
            "--plan-id",
            fx["plan"]["plan_id"],
            "--json",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    assert json.loads(proc.stdout)["status"] == "ready_for_human_review"
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
        "--post-comment",
        "--approve",
        "--merge",
        "--apply",
        "--execute",
    ]:
        assert forbidden not in source
    assert "shell=True" not in source
