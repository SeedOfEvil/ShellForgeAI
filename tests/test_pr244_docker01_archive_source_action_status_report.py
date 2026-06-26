import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_pr241_docker01_archive_source_action_review_packet import h
from test_pr243_docker01_archive_source_action_readiness_gate import (
    HELPER_PATH,
    build_gate,
    make_decision_receipt,
    mtimes,
    rewrite_checksum,
)


def make_readiness_gate(tmp_path: Path):
    fx = make_decision_receipt(tmp_path)
    gate = build_gate(fx)
    assert gate["status"] == "ready_for_future_pr_review"
    gate_dir = tmp_path / "readiness"
    h.write_archive_source_action_readiness_gate_outputs(gate, str(gate_dir))
    fx["gate"] = gate
    fx["gate_dir"] = gate_dir
    return fx


def build_status(fx, full=False, plan_id=None):
    kwargs = {"supplied_plan_id": plan_id or (fx["plan"]["plan_id"] if full else None)}
    if full:
        kwargs.update(
            decision_receipt_dir=str(fx["receipt_dir"]),
            review_packet_dir=str(fx["packet_dir"]),
            source_action_dry_run_dir=str(fx["source_action_dir"]),
            source_action_validation_dir=str(fx["validation_dir"]),
            archive_bundle_dir=str(fx["bundle_dir"]),
            plan_dir=str(fx["plan_dir"]),
            dry_run_receipt_dir=str(fx["dry_dir"]),
            archive_eligibility_review_dir=str(fx["eligibility_dir"]),
        )
    return h.build_archive_source_action_status_report(str(fx["gate_dir"]), **kwargs)


def test_standalone_readiness_gate_status_report_is_strict_json_and_partial(tmp_path):
    fx = make_readiness_gate(tmp_path)
    result = build_status(fx)
    loaded = json.loads(json.dumps(result))
    assert loaded["mode"] == h.SOURCE_ACTION_STATUS_REPORT_MODE
    assert loaded["status"] in {"partial", "ready_for_operator_review"}
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["source_action_available"] is False
    assert loaded["operator_status_report_only"] is True
    assert loaded["this_is_not_approval"] is True
    assert loaded["this_is_not_execution"] is True
    assert loaded["this_does_not_authorize_source_action"] is True
    human = h.render_archive_source_action_status_report(result)
    assert human.startswith("# Docker01 Archive Source-Action Operator Status")
    assert "* not approval" in human
    assert "* not execution" in human
    assert "* does not authorize source action" in human


def test_full_evidence_chain_out_files_checksums_and_no_mutation(tmp_path):
    fx = make_readiness_gate(tmp_path)
    watched = [
        *fx["gate_dir"].rglob("*"),
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
    out = tmp_path / "status-out"
    result = build_status(fx, full=True)
    assert result["status"] == "ready_for_operator_review"
    h.write_archive_source_action_status_report_outputs(result, str(out))
    for name in h.SOURCE_ACTION_STATUS_REPORT_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["mode"] == h.SOURCE_ACTION_STATUS_REPORT_MODE
    checksums = json.loads((out / "checksums.json").read_text())["checksums"]
    for name, digest in checksums.items():
        assert digest == "sha256:" + h.sha256_file(out / name)
    next_steps = (out / "operator-next-steps.md").read_text()
    assert "future action would require a separate PR/lane" in next_steps
    assert "source delete default is false" in next_steps
    assert "source move default is false" in next_steps
    assert mtimes(watched) == before
    assert fx["source_file"].read_text() == "review-packet-evidence"
    assert not list(tmp_path.glob("*.tar*"))


@pytest.mark.parametrize(
    "field,in_safety",
    [
        ("source_action_available", False),
        ("mutation_performed", False),
        ("this_is_approval", False),
        ("source_deleted", True),
        ("source_moved", True),
        ("source_modified", True),
        ("source_copied", True),
        ("archive_created", True),
        ("cleanup_executed", True),
        ("docker_prune_executed", True),
        ("container_restarted", True),
        ("remediation_executed", True),
        ("rollback_executed", True),
        ("recovery_executed", True),
    ],
)
def test_readiness_gate_unsafe_claims_are_not_ready_or_failed(tmp_path, field, in_safety):
    fx = make_readiness_gate(tmp_path)
    path = fx["gate_dir"] / "archive-source-action-readiness-gate.json"
    data = json.loads(path.read_text())
    if in_safety:
        data.setdefault("safety", {})[field] = True
    else:
        data[field] = True
    path.write_text(json.dumps(data))
    rewrite_checksum(fx["gate_dir"], "archive-source-action-readiness-gate.json")
    assert build_status(fx)["status"] in {"not_ready", "failed"}


def test_missing_invalid_checksum_mismatch_and_cross_check_failures(tmp_path):
    fx = make_readiness_gate(tmp_path)
    fx["gate_dir"] = tmp_path / "missing"
    assert build_status(fx)["status"] == "failed"

    fx = make_readiness_gate(tmp_path / "invalid")
    (fx["gate_dir"] / "archive-source-action-readiness-gate.json").write_text("{")
    assert build_status(fx)["status"] == "failed"

    fx = make_readiness_gate(tmp_path / "checksum")
    checks = json.loads((fx["gate_dir"] / "checksums.json").read_text())
    checks["checksums"]["archive-source-action-readiness-gate.json"] = "sha256:bad"
    (fx["gate_dir"] / "checksums.json").write_text(json.dumps(checks))
    assert build_status(fx)["status"] == "failed"

    fx = make_readiness_gate(tmp_path / "planid")
    assert build_status(fx, full=True, plan_id="sha256:0000000000000000")["status"] == "not_ready"

    fx = make_readiness_gate(tmp_path / "archive")
    next((fx["bundle_dir"] / "payload").rglob("*.txt")).write_text("tamper")
    assert build_status(fx, full=True)["status"] in {"not_ready", "failed"}


def test_unsafe_symlink_and_runtime_candidates_fail_without_following(tmp_path):
    fx = make_readiness_gate(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("secret")
    link = tmp_path / "sfai-pr244-qa-bundle-link"
    link.symlink_to(outside)
    data = json.loads((fx["gate_dir"] / "candidate-readiness-summary.json").read_text())
    data["candidates"][0]["source_path"] = str(link)
    (fx["gate_dir"] / "candidate-readiness-summary.json").write_text(json.dumps(data))
    rewrite_checksum(fx["gate_dir"], "candidate-readiness-summary.json")
    assert build_status(fx)["status"] in {"not_ready", "failed"}
    assert outside.read_text() == "secret"

    fx = make_readiness_gate(tmp_path / "runtime")
    data = json.loads((fx["gate_dir"] / "candidate-readiness-summary.json").read_text())
    data["candidates"][0]["source_path"] = "/var/lib/docker/containers/x"
    (fx["gate_dir"] / "candidate-readiness-summary.json").write_text(json.dumps(data))
    rewrite_checksum(fx["gate_dir"], "candidate-readiness-summary.json")
    assert build_status(fx)["status"] in {"not_ready", "failed"}


def test_cli_json_human_out_and_command_surface_guardrails(tmp_path):
    fx = make_readiness_gate(tmp_path)
    out = tmp_path / "out"
    cmd = [
        sys.executable,
        str(HELPER_PATH),
        "--archive-source-action-status-report",
        str(fx["gate_dir"]),
        "--decision-receipt",
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
    assert json.loads(proc.stdout)["status"] == "ready_for_operator_review"
    human = subprocess.run(
        [
            sys.executable,
            str(HELPER_PATH),
            "--archive-source-action-status-report",
            str(fx["gate_dir"]),
        ],
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    assert "not approval" in human and "not execution" in human and "does not authorize" in human
    help_text = subprocess.run(
        [sys.executable, str(HELPER_PATH), "--help"], check=True, text=True, capture_output=True
    ).stdout
    assert "--archive-source-action-status-report" in help_text
    for flag in [
        "--execute-cleanup",
        "--cleanup-now",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--rm",
        "--rmi",
        "--apply",
        "--execute",
        "--approve",
        "--merge",
        "--post-comment",
    ]:
        assert flag not in help_text
    assert "shell=True" not in HELPER_PATH.read_text()
