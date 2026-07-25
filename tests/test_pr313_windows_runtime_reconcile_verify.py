"""PR313 read-only post-change verification helper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_pr313_windows_runtime_reconcile_execute import (  # noqa: E402
    CANONICAL_INSPECT_PROFILE_BYTES,
    CANONICAL_WRAPPER_BYTES,
    MARKERLESS_WRAPPER_BYTES,
    SCRIPTS,
    THIRD_PROFILE_BYTES,
    build_pr304,
    force_linux,
    load_script,
    make_lab,
    run_execute,
    symlink_or_skip,
    write_exact,
)

from shellforgeai.core import windows_runtime_reconcile_execution as wrre

VERIFY_HELPER = SCRIPTS / "windows_runtime_reconcile_verify.py"
SYSTEM32 = "C:\\Windows\\System32"


def reconciled_lab(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_EXECUTED
    return lab, result


def fresh_artifacts(tmp_path, monkeypatch, lab, *, suffix="post"):
    staged = build_pr304(
        tmp_path,
        monkeypatch,
        lab.runtime,
        name=f"pr304-{suffix}-staged.json",
        cwd=str(lab.staged),
    )
    system32 = build_pr304(
        tmp_path, monkeypatch, lab.runtime, name=f"pr304-{suffix}-system32.json", cwd=SYSTEM32
    )
    return staged, system32


def run_verify(lab, result, staged, system32, **overrides):
    kwargs = {
        "staged_pr304": str(staged),
        "system32_pr304": str(system32),
        "staged_source_root": str(lab.staged),
        "durable_runtime_root": str(lab.runtime),
        "data_dir": str(lab.data_dir),
        "validators": wrre.load_validators(SCRIPTS),
    }
    kwargs.update(overrides)
    receipt_ref = kwargs.pop("receipt_ref", result["receipt_id"])
    return wrre.verify_windows_runtime_reconcile(receipt_ref, **kwargs)


def snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()
    }


# --------------------------------------------------------------------------- #
# Healthy verification
# --------------------------------------------------------------------------- #


def test_verifier_accepts_healthy_staged_and_system32_artifacts(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_VERIFIED, verification["failures"]
    assert verification["failures"] == []
    assert verification["receipt_id"] == result["receipt_id"]
    assert all(item["result"] == "verified" for item in verification["operations"])
    assert {item["relative_destination"] for item in verification["operations"]} == {
        destination for _, destination in wrre.ALLOWLIST
    }
    names = {check["name"] for check in verification["checks"]}
    assert "receipt.bundle_integrity" in names
    assert "pr304.stable_identity" in names
    assert "pr304.staged_source_context" in names
    assert "pr304.system32_context" in names
    assert "staged.runtime.profile_resolution" in names
    assert "system32.wrapper.semantic_markers" in names
    assert "system32.wrapper.canonical_match" in names
    assert "staged.import.exact_source_match" in names
    assert all(check["status"] == "passed" for check in verification["checks"])


def test_verifier_is_read_only_and_records_no_repair(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    before_runtime = snapshot(lab.runtime)
    before_receipt = snapshot(Path(result["receipt_path"]))
    verification = run_verify(lab, result, staged, system32)
    assert verification["read_only"] is True
    assert verification["mutation_performed"] is False
    assert verification["repair_executed"] is False
    assert verification["rollback_executed"] is False
    assert verification["safety"]["mutation_performed"] is False
    assert verification["safety"]["exact_two_file_allowlist"] is True
    for key in wrre.SAFETY_FALSE_KEYS:
        assert verification["safety"][key] is False, key
    assert snapshot(lab.runtime) == before_runtime
    assert snapshot(Path(result["receipt_path"])) == before_receipt


def test_verification_packet_uses_relative_paths_and_root_fingerprints(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    verification = run_verify(lab, result, staged, system32)
    serialized = json.dumps(verification)
    assert str(lab.staged) not in serialized
    assert str(lab.runtime) not in serialized
    assert wrre.is_plan_sha256(verification["roots"]["staged_source_root_fingerprint_sha256"])
    assert wrre.is_plan_sha256(verification["roots"]["durable_runtime_root_fingerprint_sha256"])
    for item in verification["operations"]:
        assert not item["relative_destination"].startswith("/")


def test_verifier_accepts_a_partial_execution_receipt(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="match")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_PARTIAL_EXECUTED
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_VERIFIED, verification["failures"]


# --------------------------------------------------------------------------- #
# Rejections
# --------------------------------------------------------------------------- #


def test_verifier_rejects_pr304_identity_mismatch(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    payload = json.loads(system32.read_bytes().decode("utf-8"))
    payload["wrapper"]["sha256"] = "f" * 64
    system32.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_BLOCKED
    assert any("stable identity" in failure for failure in verification["failures"])
    assert verification["operations"] == []


@pytest.mark.parametrize("body", ["[]", "{not json", '{"schema_version": 2}'])
def test_verifier_rejects_stale_or_malformed_pr304_artifacts(tmp_path, monkeypatch, body):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    staged.write_text(body, encoding="utf-8")
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_BLOCKED
    assert verification["failures"]
    assert verification["mutation_performed"] is False


def test_verifier_rejects_destination_hash_drift(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    write_exact(lab.profile_destination, THIRD_PROFILE_BYTES)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_FAILED
    assert any(
        "config/profiles/inspect.yaml" in failure and "does not match the receipt" in failure
        for failure in verification["failures"]
    )
    drifted = next(
        item
        for item in verification["operations"]
        if item["relative_destination"] == "config/profiles/inspect.yaml"
    )
    assert drifted["result"] == "failed"
    assert lab.profile_destination.read_bytes() == THIRD_PROFILE_BYTES


def test_verifier_rejects_a_missing_durable_destination(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    lab.wrapper_destination.unlink()
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_FAILED
    assert any("bin/sfai.cmd" in failure for failure in verification["failures"])


def test_verifier_rejects_a_wrong_staged_source_context(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged = build_pr304(
        tmp_path, monkeypatch, lab.runtime, name="pr304-wrong-cwd.json", cwd=SYSTEM32
    )
    _, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_FAILED
    assert any("staged source context" in failure for failure in verification["failures"])


def test_verifier_requires_a_system32_invocation_context(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, _ = fresh_artifacts(tmp_path, monkeypatch, lab)
    not_system32 = build_pr304(
        tmp_path, monkeypatch, lab.runtime, name="pr304-not-sys32.json", cwd="C:\\Temp"
    )
    verification = run_verify(lab, result, staged, not_system32)
    assert verification["status"] == wrre.VERIFY_STATUS_FAILED
    assert any("System32 invocation context" in failure for failure in verification["failures"])


def test_verifier_rejects_root_mismatch(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    other = tmp_path / "other-runtime"
    other.mkdir()
    verification = run_verify(lab, result, staged, system32, durable_runtime_root=str(other))
    assert verification["status"] == wrre.VERIFY_STATUS_BLOCKED
    assert any("root fingerprints" in failure for failure in verification["failures"])


def test_verifier_rejects_an_invalid_or_missing_receipt(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    missing = run_verify(lab, result, staged, system32, receipt_ref="wrr_missing")
    assert missing["status"] == wrre.VERIFY_STATUS_BLOCKED
    assert missing["operations"] == []

    directory = Path(result["receipt_path"])
    (directory / wrre.RECEIPT_MANIFEST).write_text("{}", encoding="utf-8")
    tampered = run_verify(lab, result, staged, system32)
    assert tampered["status"] == wrre.VERIFY_STATUS_BLOCKED


def test_verifier_rejects_a_wrapper_that_lost_its_semantic_markers(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    write_exact(lab.wrapper_destination, MARKERLESS_WRAPPER_BYTES)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_FAILED
    assert any("wrapper.semantic_markers" in failure for failure in verification["failures"])


def test_verifier_rejects_a_missing_durable_profile_resolution(tmp_path, monkeypatch):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    lab.profile_destination.unlink()
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_FAILED
    assert any("runtime.profile_context" in failure for failure in verification["failures"])


# --------------------------------------------------------------------------- #
# Direct verification helper
# --------------------------------------------------------------------------- #


def test_verify_helper_is_unsupported_on_linux(tmp_path, capsys, monkeypatch):
    force_linux(monkeypatch)
    helper = load_script(VERIFY_HELPER)
    code = helper.main(
        [
            "wrr_missing",
            "--staged-pr304",
            str(tmp_path / "a.json"),
            "--system32-pr304",
            str(tmp_path / "b.json"),
            "--staged-source-root",
            str(tmp_path / "staged"),
            "--durable-runtime-root",
            str(tmp_path / "runtime"),
            "--data-dir",
            str(tmp_path / "data"),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out.strip())
    assert code == 0
    assert payload["status"] == "unsupported"
    assert payload["platform"]["system"] == "linux"
    assert payload["repair_executed"] is False
    assert payload["rollback_executed"] is False
    assert payload["operations"] == []
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["subprocess_executed"] is False
    assert payload["safety"]["powershell_executed"] is False
    assert not (tmp_path / "data").exists()


def test_verify_helper_saves_only_with_explicit_option_and_refuses_overwrite(
    tmp_path, monkeypatch, capsys
):
    lab, result = reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    helper = load_script(VERIFY_HELPER)
    argv = [
        result["receipt_id"],
        "--staged-pr304",
        str(staged),
        "--system32-pr304",
        str(system32),
        "--staged-source-root",
        str(lab.staged),
        "--durable-runtime-root",
        str(lab.runtime),
        "--data-dir",
        str(lab.data_dir),
        "--json",
    ]
    assert helper.main(argv) == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "verified"

    out = tmp_path / "verification.json"
    assert helper.main([*argv, "--out-json", str(out)]) == 0
    capsys.readouterr()
    assert json.loads(out.read_bytes().decode("utf-8"))["status"] == "verified"
    with pytest.raises(SystemExit):
        helper.main([*argv, "--out-json", str(out)])


def test_verify_helper_rejects_arbitrary_paths_and_repair_flags(tmp_path):
    helper = load_script(VERIFY_HELPER)
    for argv in (
        ["r", "--repair"],
        ["r", "--rollback"],
        ["r", "--source", "x", "--destination", "y"],
    ):
        with pytest.raises(SystemExit):
            helper.main(argv)


def test_reconciled_profile_matches_the_staged_source(tmp_path, monkeypatch):
    lab, _ = reconciled_lab(tmp_path, monkeypatch)
    assert lab.profile_destination.read_bytes() == CANONICAL_INSPECT_PROFILE_BYTES
    assert lab.wrapper_destination.read_bytes() == CANONICAL_WRAPPER_BYTES


# --------------------------------------------------------------------------- #
# Destination-parent post-verification
# --------------------------------------------------------------------------- #


def parent_reconciled_lab(tmp_path, monkeypatch, profile_parent="missing_all"):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent=profile_parent,
    )
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_EXECUTED, result["blockers"]
    return lab, result


@pytest.mark.parametrize("profile_parent", ["missing_all", "missing_profiles"])
def test_verifier_accepts_created_parent_chain(tmp_path, monkeypatch, profile_parent):
    lab, result = parent_reconciled_lab(tmp_path, monkeypatch, profile_parent)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_VERIFIED, verification["failures"]
    names = {check["name"] for check in verification["checks"]}
    assert "parent.retained_directory.config/profiles" in names
    assert all(check["status"] == "passed" for check in verification["checks"])
    assert (lab.runtime / "config/profiles").is_dir()


def test_verifier_rejects_a_missing_retained_directory(tmp_path, monkeypatch):
    lab, result = parent_reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    lab.profile_destination.unlink()
    (lab.runtime / "config/profiles").rmdir()
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_FAILED
    assert any("retained execution-created directory" in f for f in verification["failures"])


def test_verifier_rejects_hostile_reparse_conversion(tmp_path, monkeypatch):
    lab, result = parent_reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    lab.profile_destination.unlink()
    (lab.runtime / "config/profiles").rmdir()
    elsewhere = tmp_path / "hostile-profiles"
    elsewhere.mkdir()
    symlink_or_skip(lab.runtime / "config/profiles", elsewhere, target_is_directory=True)
    verification = run_verify(lab, result, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_FAILED
    assert any("retained execution-created directory" in f for f in verification["failures"])


def test_verifier_rejects_bin_parent_creation_claim(tmp_path, monkeypatch):
    lab, result = parent_reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    directory = Path(result["receipt_path"])
    receipt = json.loads((directory / wrre.RECEIPT_JSON).read_bytes().decode("utf-8"))
    receipt["operations"][1]["destination_parent"]["creation_allowed"] = True
    (directory / wrre.RECEIPT_JSON).write_bytes(
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    verification = run_verify(lab, result, staged, system32)
    # Receipt-bundle integrity fails first: checksum plus parent-contract rejection.
    assert verification["status"] == wrre.VERIFY_STATUS_BLOCKED


def test_verifier_remains_read_only_over_created_directories(tmp_path, monkeypatch):
    lab, result = parent_reconciled_lab(tmp_path, monkeypatch)
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab)
    before = snapshot(lab.runtime)
    before_dirs = sorted(str(p.relative_to(lab.runtime)) for p in lab.runtime.rglob("*"))
    verification = run_verify(lab, result, staged, system32)
    assert verification["read_only"] is True
    assert verification["repair_executed"] is False
    assert snapshot(lab.runtime) == before
    assert sorted(str(p.relative_to(lab.runtime)) for p in lab.runtime.rglob("*")) == before_dirs


def test_fresh_confirmed_replay_after_parent_creation_is_a_no_op(tmp_path, monkeypatch):
    lab, first = parent_reconciled_lab(tmp_path, monkeypatch)
    created = [
        entry
        for op in first["operations"]
        for entry in (op.get("destination_parent") or {}).get("created_directories") or []
    ]
    assert created == ["config", "config/profiles"]

    fresh = [build_pr304(tmp_path, monkeypatch, lab.runtime, name="pr304-replay.json")]
    helper = load_script(SCRIPTS / "windows_runtime_reconcile_preflight.py")
    packet = helper.build_packet([str(a) for a in fresh], str(lab.staged), str(lab.runtime))
    assert packet["status"] == "no_change"
    assert packet["operations"][0]["destination_parent"]["state"] == "present"
    assert packet["operations"][1]["destination_parent"]["state"] == "present"

    replay_path = tmp_path / "pr305-replay.json"
    replay_path.write_text(json.dumps(packet, sort_keys=True), encoding="utf-8")
    replay = run_execute(
        lab,
        packet_path=replay_path,
        artifacts=fresh,
        confirm_plan_sha256=wrre.canonical_plan_sha256(packet),
    )
    assert replay["status"] == wrre.STATUS_NO_CHANGE
    assert replay["mutation_performed"] is False
    assert replay["safety"]["parent_directory_create_executed"] is False
    assert (lab.runtime / "config/profiles").is_dir()

    validation = wrre.validate_saved_receipt(replay["receipt_id"], str(lab.data_dir))
    assert validation["status"] == "ok", validation["failures"]
    staged, system32 = fresh_artifacts(tmp_path, monkeypatch, lab, suffix="replay")
    verification = run_verify(lab, replay, staged, system32)
    assert verification["status"] == wrre.VERIFY_STATUS_VERIFIED, verification["failures"]
