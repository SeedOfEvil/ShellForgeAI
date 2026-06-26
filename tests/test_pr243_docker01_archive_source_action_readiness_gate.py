import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_pr241_docker01_archive_source_action_review_packet import HELPER_PATH, h
from test_pr242_docker01_archive_source_action_decision_receipt import make_review_packet, mtimes


def make_decision_receipt(tmp_path: Path, decision="ready_for_future_pr_review"):
    fx = make_review_packet(tmp_path)
    receipt = h.build_archive_source_action_decision_receipt(
        str(fx["packet_dir"]),
        supplied_plan_id=fx["plan"]["plan_id"],
        decision=decision,
        source_action_dry_run_dir=str(fx["source_action_dir"]),
        source_action_validation_dir=str(fx["validation_dir"]),
        archive_bundle_dir=str(fx["bundle_dir"]),
        plan_dir=str(fx["plan_dir"]),
        dry_run_receipt_dir=str(fx["dry_dir"]),
        archive_eligibility_review_dir=str(fx["eligibility_dir"]),
    )
    assert receipt["status"] == "decision_recorded"
    receipt_dir = tmp_path / "decision"
    h.write_archive_source_action_decision_receipt_outputs(receipt, str(receipt_dir))
    fx["receipt"] = receipt
    fx["receipt_dir"] = receipt_dir
    return fx


def build_gate(fx, plan_id=None):
    return h.build_archive_source_action_readiness_gate(
        str(fx["receipt_dir"]),
        review_packet_dir=str(fx["packet_dir"]),
        source_action_dry_run_dir=str(fx["source_action_dir"]),
        source_action_validation_dir=str(fx["validation_dir"]),
        archive_bundle_dir=str(fx["bundle_dir"]),
        plan_dir=str(fx["plan_dir"]),
        dry_run_receipt_dir=str(fx["dry_dir"]),
        archive_eligibility_review_dir=str(fx["eligibility_dir"]),
        supplied_plan_id=plan_id or fx["plan"]["plan_id"],
    )


def rewrite_checksum(directory: Path, name: str):
    checks = json.loads((directory / "checksums.json").read_text())
    checks["checksums"][name] = "sha256:" + h.sha256_file(directory / name)
    (directory / "checksums.json").write_text(json.dumps(checks))


def test_happy_path_json_human_out_and_read_only(tmp_path):
    fx = make_decision_receipt(tmp_path)
    watched = [
        *fx["receipt_dir"].rglob("*"),
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
    result = build_gate(fx)
    loaded = json.loads(json.dumps(result))
    assert loaded["mode"] == h.SOURCE_ACTION_READINESS_GATE_MODE
    assert loaded["status"] == "ready_for_future_pr_review"
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["source_action_available"] is False
    assert loaded["readiness_gate_only"] is True
    assert loaded["future_source_action_pr_required"] is True
    assert loaded["this_is_not_approval"] is True
    assert loaded["this_is_not_execution"] is True
    assert loaded["this_does_not_authorize_source_action"] is True
    assert loaded["summary"]["plan_id_match"] is True
    assert loaded["summary"]["candidate_manifest_match"] is True
    assert loaded["summary"]["archive_payload_verified"] is True
    assert loaded["summary"]["source_preservation_ok"] is True
    assert loaded["summary"]["source_action_contract_ok"] is True
    human = h.render_archive_source_action_readiness_gate(result)
    assert human.startswith("# Docker01 Archive Source-Action Readiness Gate")
    assert "* not approval" in human
    assert "* not execution" in human
    assert "* does not authorize source action" in human
    out = tmp_path / "readiness"
    h.write_archive_source_action_readiness_gate_outputs(result, str(out))
    for name in h.SOURCE_ACTION_READINESS_GATE_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["mode"] == h.SOURCE_ACTION_READINESS_GATE_MODE
    checksums = json.loads((out / "checksums.json").read_text())["checksums"]
    for name, digest in checksums.items():
        assert digest == "sha256:" + h.sha256_file(out / name)
    contract = (out / "non-execution-contract.md").read_text()
    assert "future action would require a separate PR/lane" in contract
    assert "source delete default is false" in contract
    assert "source move default is false" in contract
    assert mtimes(watched) == before
    assert fx["source_file"].read_text() == "review-packet-evidence"
    assert fx["candidate_file"].exists()
    assert not list(tmp_path.glob("*.tar*"))


@pytest.mark.parametrize("decision", ["defer", "reject", "needs_more_evidence"])
def test_non_ready_decisions_are_not_ready(tmp_path, decision):
    fx = make_decision_receipt(tmp_path, decision=decision)
    assert build_gate(fx)["status"] == "not_ready"


def test_missing_invalid_and_checksum_mismatch_decision_receipt_fail(tmp_path):
    fx = make_decision_receipt(tmp_path)
    fx["receipt_dir"] = tmp_path / "missing"
    assert build_gate(fx)["status"] == "failed"
    fx = make_decision_receipt(tmp_path / "invalid")
    (fx["receipt_dir"] / "archive-source-action-decision-receipt.json").write_text("{")
    assert build_gate(fx)["status"] == "failed"
    fx = make_decision_receipt(tmp_path / "checksum")
    data = json.loads((fx["receipt_dir"] / "checksums.json").read_text())
    data["checksums"]["archive-source-action-decision-receipt.json"] = "sha256:bad"
    (fx["receipt_dir"] / "checksums.json").write_text(json.dumps(data))
    assert build_gate(fx)["status"] == "failed"


@pytest.mark.parametrize(
    "target,filename,field,in_safety",
    [
        ("receipt_dir", "archive-source-action-decision-receipt.json", "mutation_performed", False),
        (
            "source_action_dir",
            "archive-source-action-dry-run.json",
            "source_action_available",
            False,
        ),
        ("source_action_dir", "archive-source-action-dry-run.json", "source_deleted", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "source_moved", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "source_modified", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "source_copied", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "archive_created", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "cleanup_executed", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "docker_prune_executed", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "container_restarted", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "remediation_executed", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "rollback_executed", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "recovery_executed", True),
        ("source_action_dir", "archive-source-action-dry-run.json", "shell_true", True),
    ],
)
def test_unsafe_flags_fail(target, filename, field, in_safety, tmp_path):
    fx = make_decision_receipt(tmp_path)
    path = fx[target] / filename
    data = json.loads(path.read_text())
    if in_safety:
        data.setdefault("safety", {})[field] = True
    else:
        data[field] = True
    path.write_text(json.dumps(data))
    if target in {"receipt_dir"}:
        rewrite_checksum(fx[target], filename)
    assert build_gate(fx)["status"] in {"failed", "not_ready"}


def test_plan_candidate_archive_checksum_unsafe_and_symlink_block(tmp_path):
    fx = make_decision_receipt(tmp_path)
    assert build_gate(fx, plan_id="sha256:0000000000000000")["status"] == "not_ready"

    fx = make_decision_receipt(tmp_path / "candidate")
    data = json.loads((fx["receipt_dir"] / "candidate-decision-summary.json").read_text())
    data["candidates"] = []
    (fx["receipt_dir"] / "candidate-decision-summary.json").write_text(json.dumps(data))
    rewrite_checksum(fx["receipt_dir"], "candidate-decision-summary.json")
    assert build_gate(fx)["status"] in {"failed", "not_ready"}

    fx = make_decision_receipt(tmp_path / "checksum")
    next((fx["bundle_dir"] / "payload").rglob("*.txt")).write_text("tamper")
    assert build_gate(fx)["status"] == "not_ready"

    fx = make_decision_receipt(tmp_path / "unsafe")
    data = json.loads((fx["receipt_dir"] / "candidate-decision-summary.json").read_text())
    data["candidates"][0]["source_path"] = "/var/lib/docker/containers/x"
    (fx["receipt_dir"] / "candidate-decision-summary.json").write_text(json.dumps(data))
    rewrite_checksum(fx["receipt_dir"], "candidate-decision-summary.json")
    assert build_gate(fx)["status"] in {"failed", "not_ready"}

    fx = make_decision_receipt(tmp_path / "symlink")
    outside = tmp_path / "outside"
    outside.write_text("secret")
    link = tmp_path / "sfai-pr243-qa-bundle-link"
    link.symlink_to(outside)
    data = json.loads((fx["receipt_dir"] / "candidate-decision-summary.json").read_text())
    data["candidates"][0]["source_path"] = str(link)
    (fx["receipt_dir"] / "candidate-decision-summary.json").write_text(json.dumps(data))
    rewrite_checksum(fx["receipt_dir"], "candidate-decision-summary.json")
    assert build_gate(fx)["status"] in {"failed", "not_ready"}
    assert outside.read_text() == "secret"


def test_optional_source_recheck_warning_can_be_partial(tmp_path):
    fx = make_decision_receipt(tmp_path)
    fx["candidate_file"].unlink()
    result = build_gate(fx)
    assert result["status"] == "partial"
    assert result["summary"]["warning_candidates"] >= 1


def test_cli_json_out_and_command_surface_guardrails(tmp_path):
    fx = make_decision_receipt(tmp_path)
    out = tmp_path / "out"
    cmd = [
        sys.executable,
        str(HELPER_PATH),
        "--archive-source-action-readiness-gate",
        str(fx["receipt_dir"]),
        "--review-packet",
        str(fx["packet_dir"]),
        "--source-action-dry-run",
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
        "--out",
        str(out),
        "--json",
    ]
    proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
    assert json.loads(proc.stdout)["status"] == "ready_for_future_pr_review"
    assert (out / "archive-source-action-readiness-gate.json").is_file()
    help_text = subprocess.run(
        [sys.executable, str(HELPER_PATH), "--help"], check=True, text=True, capture_output=True
    ).stdout
    assert "--archive-source-action-readiness-gate" in help_text
    banned = [
        "--execute-cleanup",
        "--cleanup-now",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
        "--apply",
        "--execute",
        "--approve",
        "--merge",
        "--post-comment",
    ]
    for flag in banned:
        assert flag not in help_text
    assert "shell=True" not in HELPER_PATH.read_text()
