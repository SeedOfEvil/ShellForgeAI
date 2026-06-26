import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_pr241_docker01_archive_source_action_review_packet import (
    HELPER_PATH,
    build_packet,
    h,
    make_chain,
)


def make_review_packet(tmp_path: Path):
    fx = make_chain(tmp_path)
    packet = build_packet(fx)
    assert packet["status"] == "ready_for_human_review"
    packet_dir = tmp_path / "packet"
    h.write_archive_source_action_review_packet_outputs(packet, str(packet_dir))
    fx["packet"] = packet
    fx["packet_dir"] = packet_dir
    return fx


def mtimes(paths):
    return {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in paths if p.is_file()}


@pytest.mark.parametrize("decision", h.ALLOWED_SOURCE_ACTION_DECISIONS)
def test_decision_enum_records_receipt_json_and_human(tmp_path, decision):
    fx = make_review_packet(tmp_path)
    result = h.build_archive_source_action_decision_receipt(
        str(fx["packet_dir"]), supplied_plan_id=fx["plan"]["plan_id"], decision=decision
    )
    assert result["status"] in {"decision_recorded", "partial"}
    assert result["mode"] == h.SOURCE_ACTION_DECISION_RECEIPT_MODE
    assert result["decision"] == decision
    assert result["read_only"] is True
    assert result["mutation_performed"] is False
    assert result["source_action_available"] is False
    assert result["decision_receipt_only"] is True
    assert result["this_is_not_approval"] is True
    assert result["this_is_not_execution"] is True
    assert result["this_does_not_authorize_source_action"] is True
    assert result["summary"]["plan_id_match"] is True
    assert result["summary"]["candidate_manifest_match"] is True
    assert json.loads(json.dumps(result))["schema_version"] == 1
    human = h.render_archive_source_action_decision_receipt(result)
    assert human.startswith("# Docker01 Archive Source-Action Operator Decision Receipt")
    assert "not approval" in human
    assert "not execution" in human
    assert "does not authorize source action" in human


def test_out_writes_required_files_and_preserves_evidence_and_sources(tmp_path):
    fx = make_review_packet(tmp_path)
    watched = [
        *fx["packet_dir"].rglob("*"),
        *fx["source_action_dir"].rglob("*"),
        *fx["validation_dir"].rglob("*"),
        *fx["bundle_dir"].rglob("*"),
        *fx["plan_dir"].rglob("*"),
        *fx["dry_dir"].rglob("*"),
        *fx["eligibility_dir"].rglob("*"),
        *fx["root"].rglob("*"),
    ]
    before = mtimes(watched)
    out = tmp_path / "decision"
    result = h.build_archive_source_action_decision_receipt(
        str(fx["packet_dir"]),
        supplied_plan_id=fx["plan"]["plan_id"],
        decision="ready_for_future_pr_review",
        source_action_dry_run_dir=str(fx["source_action_dir"]),
        source_action_validation_dir=str(fx["validation_dir"]),
        archive_bundle_dir=str(fx["bundle_dir"]),
        plan_dir=str(fx["plan_dir"]),
        dry_run_receipt_dir=str(fx["dry_dir"]),
        archive_eligibility_review_dir=str(fx["eligibility_dir"]),
    )
    assert result["status"] == "decision_recorded"
    h.write_archive_source_action_decision_receipt_outputs(result, str(out))
    for name in h.SOURCE_ACTION_DECISION_RECEIPT_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["mode"] == h.SOURCE_ACTION_DECISION_RECEIPT_MODE
    checksums = json.loads((out / "checksums.json").read_text())["checksums"]
    for name, digest in checksums.items():
        assert digest == "sha256:" + h.sha256_file(out / name)
    assert "separate PR/lane required" in (out / "future-source-action-requirements.md").read_text()
    assert mtimes(watched) == before
    assert fx["source_file"].read_text() == "review-packet-evidence"
    assert fx["candidate_file"].exists()
    assert not list(tmp_path.glob("*.tar*"))


@pytest.mark.parametrize("field", ["source_action_available", "mutation_performed"])
def test_review_packet_executable_or_mutation_claim_not_ready(tmp_path, field):
    fx = make_review_packet(tmp_path)
    path = fx["packet_dir"] / "archive-source-action-review-packet.json"
    data = json.loads(path.read_text())
    data[field] = True
    path.write_text(json.dumps(data))
    result = h.build_archive_source_action_decision_receipt(
        str(fx["packet_dir"]), supplied_plan_id=fx["plan"]["plan_id"], decision="defer"
    )
    assert result["status"] in {"failed", "not_ready"}


def test_missing_invalid_mismatch_and_invalid_decision_block(tmp_path):
    fx = make_review_packet(tmp_path)
    assert (
        h.build_archive_source_action_decision_receipt(
            str(tmp_path / "missing"), supplied_plan_id=fx["plan"]["plan_id"], decision="defer"
        )["status"]
        == "failed"
    )
    assert h.build_archive_source_action_decision_receipt(
        str(fx["packet_dir"]), supplied_plan_id="sha256:0000000000000000", decision="defer"
    )["status"] in {"failed", "not_ready"}
    assert (
        h.build_archive_source_action_decision_receipt(
            str(fx["packet_dir"]), supplied_plan_id=fx["plan"]["plan_id"], decision="free form"
        )["status"]
        == "not_ready"
    )
    path = fx["packet_dir"] / "checksums.json"
    data = json.loads(path.read_text())
    data["checksums"]["archive-source-action-review-packet.json"] = "sha256:bad"
    path.write_text(json.dumps(data))
    assert (
        h.build_archive_source_action_decision_receipt(
            str(fx["packet_dir"]), supplied_plan_id=fx["plan"]["plan_id"], decision="defer"
        )["status"]
        == "failed"
    )


def test_not_ready_packet_cannot_be_marked_ready_for_future_review(tmp_path):
    fx = make_review_packet(tmp_path)
    path = fx["packet_dir"] / "archive-source-action-review-packet.json"
    data = json.loads(path.read_text())
    data["status"] = "not_ready"
    path.write_text(json.dumps(data))
    checks = json.loads((fx["packet_dir"] / "checksums.json").read_text())
    checks["checksums"]["archive-source-action-review-packet.json"] = "sha256:" + h.sha256_file(
        path
    )
    (fx["packet_dir"] / "checksums.json").write_text(json.dumps(checks))
    assert h.build_archive_source_action_decision_receipt(
        str(fx["packet_dir"]),
        supplied_plan_id=fx["plan"]["plan_id"],
        decision="ready_for_future_pr_review",
    )["status"] in {"failed", "not_ready"}
    assert h.build_archive_source_action_decision_receipt(
        str(fx["packet_dir"]), supplied_plan_id=fx["plan"]["plan_id"], decision="defer"
    )["status"] in {"failed", "partial", "decision_recorded"}


def test_cross_check_candidate_mismatch_archive_checksum_unsafe_path_and_symlink_block(tmp_path):
    fx = make_review_packet(tmp_path)
    cpath = fx["source_action_dir"] / "candidate-source-action-manifest.json"
    data = json.loads(cpath.read_text())
    data["candidates"] = []
    cpath.write_text(json.dumps(data))
    assert (
        h.build_archive_source_action_decision_receipt(
            str(fx["packet_dir"]),
            supplied_plan_id=fx["plan"]["plan_id"],
            decision="defer",
            source_action_dry_run_dir=str(fx["source_action_dir"]),
        )["status"]
        == "not_ready"
    )

    fx = make_review_packet(tmp_path / "checksum")
    next((fx["bundle_dir"] / "payload").rglob("*.txt")).write_text("tamper")
    assert (
        h.build_archive_source_action_decision_receipt(
            str(fx["packet_dir"]),
            supplied_plan_id=fx["plan"]["plan_id"],
            decision="defer",
            archive_bundle_dir=str(fx["bundle_dir"]),
            plan_dir=str(fx["plan_dir"]),
            dry_run_receipt_dir=str(fx["dry_dir"]),
        )["status"]
        == "not_ready"
    )

    fx = make_review_packet(tmp_path / "unsafe")
    path = fx["packet_dir"] / "candidate-review-summary.json"
    data = json.loads(path.read_text())
    data["candidates"][0]["source_path"] = "/var/lib/docker/containers/x"
    path.write_text(json.dumps(data))
    checks = json.loads((fx["packet_dir"] / "checksums.json").read_text())
    checks["checksums"]["candidate-review-summary.json"] = "sha256:" + h.sha256_file(path)
    (fx["packet_dir"] / "checksums.json").write_text(json.dumps(checks))
    assert h.build_archive_source_action_decision_receipt(
        str(fx["packet_dir"]), supplied_plan_id=fx["plan"]["plan_id"], decision="defer"
    )["status"] in {"failed", "not_ready"}

    fx = make_review_packet(tmp_path / "symlink")
    outside = tmp_path / "outside"
    outside.write_text("secret")
    link = tmp_path / "sfai-pr242-qa-bundle-link"
    link.symlink_to(outside)
    path = fx["packet_dir"] / "candidate-review-summary.json"
    data = json.loads(path.read_text())
    data["candidates"][0]["source_path"] = str(link)
    path.write_text(json.dumps(data))
    checks = json.loads((fx["packet_dir"] / "checksums.json").read_text())
    checks["checksums"]["candidate-review-summary.json"] = "sha256:" + h.sha256_file(path)
    (fx["packet_dir"] / "checksums.json").write_text(json.dumps(checks))
    assert h.build_archive_source_action_decision_receipt(
        str(fx["packet_dir"]), supplied_plan_id=fx["plan"]["plan_id"], decision="defer"
    )["status"] in {"failed", "not_ready"}
    assert outside.read_text() == "secret"


def test_cli_json_out_and_command_surface_guardrails(tmp_path):
    fx = make_review_packet(tmp_path)
    out = tmp_path / "out"
    cp = subprocess.run(
        [
            sys.executable,
            str(HELPER_PATH),
            "--archive-source-action-decision-receipt",
            str(fx["packet_dir"]),
            "--plan-id",
            fx["plan"]["plan_id"],
            "--decision",
            "ready_for_future_pr_review",
            "--out",
            str(out),
            "--json",
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    data = json.loads(cp.stdout)
    assert data["status"] in {"decision_recorded", "partial"}
    assert (out / "archive-source-action-decision-receipt.json").is_file()
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    for banned in [
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
        assert banned not in source
