"""PR313 execution receipt bundle, validator, privacy, and preservation contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_pr313_windows_runtime_reconcile_execute import (  # noqa: E402
    CANONICAL_INSPECT_PROFILE_BYTES,
    CANONICAL_WRAPPER_BYTES,
    SCRIPTS,
    STALE_PROFILE_BYTES,
    THIRD_PROFILE_BYTES,
    load_script,
    make_lab,
    run_execute,
    write_exact,
)

from shellforgeai.core import recipe_execution, recipe_registry
from shellforgeai.core import windows_runtime_reconcile_execution as wrre

RECEIPT_HELPER = SCRIPTS / "windows_runtime_reconcile_receipt_acceptance.py"


def receipt_dir(result: dict) -> Path:
    return Path(result["receipt_path"])


def read_receipt(result: dict) -> dict:
    return json.loads((receipt_dir(result) / wrre.RECEIPT_JSON).read_bytes().decode("utf-8"))


def read_manifest(result: dict) -> dict:
    return json.loads((receipt_dir(result) / wrre.RECEIPT_MANIFEST).read_bytes().decode("utf-8"))


def rewrite(directory: Path, name: str, payload: dict) -> None:
    # Byte-exact: tamper fixtures feed manifest checksum validation.
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    (directory / name).write_bytes(text.encode("utf-8"))


def refresh_manifest(directory: Path) -> None:
    manifest = json.loads((directory / wrre.RECEIPT_MANIFEST).read_bytes().decode("utf-8"))
    manifest["checksums"] = {
        wrre.RECEIPT_JSON: wrre._sha256_file(directory / wrre.RECEIPT_JSON),
        wrre.RECEIPT_MD: wrre._sha256_file(directory / wrre.RECEIPT_MD),
    }
    rewrite(directory, wrre.RECEIPT_MANIFEST, manifest)


def validate(result: dict, lab) -> dict:
    return wrre.validate_saved_receipt(result["receipt_id"], str(lab.data_dir))


# --------------------------------------------------------------------------- #
# Bundle shape
# --------------------------------------------------------------------------- #


def test_receipt_bundle_files_and_manifest_are_written(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab)
    directory = receipt_dir(result)
    assert directory.parent.name == wrre.RECEIPT_ROOT_NAME
    assert directory.name.startswith("wrr_")
    for name in wrre.RECEIPT_REQUIRED_FILES:
        assert (directory / name).is_file()
    manifest = read_manifest(result)
    assert manifest["kind"] == wrre.MANIFEST_KIND
    assert manifest["mode"] == wrre.MANIFEST_MODE
    assert manifest["recipe_id"] == wrre.RECIPE_ID
    assert list(manifest["files"]) == list(wrre.RECEIPT_REQUIRED_FILES)


def test_receipt_directory_is_never_overwritten(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="match", wrapper_state="match")
    first = run_execute(lab)
    second = run_execute(lab)
    assert first["receipt_id"] != second["receipt_id"]
    assert receipt_dir(first).is_dir() and receipt_dir(second).is_dir()


def test_receipt_records_the_required_execution_facts(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="stale")
    result = run_execute(lab)
    receipt = read_receipt(result)
    assert receipt["mode"] == wrre.RECEIPT_MODE
    assert receipt["recipe_id"] == wrre.RECIPE_ID
    assert receipt["created_at"].endswith("Z")
    assert receipt["plan"]["canonical_packet_sha256"] == lab.confirm
    assert wrre.is_plan_sha256(receipt["plan"]["artifact_file_sha256"])
    assert receipt["plan"]["confirmation_matched"] is True
    assert receipt["plan"]["confirmation_scope"] == "recipe_specific_plan_hash_authorization_only"
    assert receipt["evidence"]["pr304_artifact_count"] == 1
    assert all(wrre.is_plan_sha256(v) for v in receipt["evidence"]["pr304_artifact_sha256"])
    assert receipt["allowlist"] == [{"source": a, "destination": b} for a, b in wrre.ALLOWLIST]
    assert receipt["transaction"]["all_prepared_before_commit"] is True
    assert receipt["recovery_posture"]["automatic_rollback_after_success"] is False
    assert receipt["recovery_posture"]["backups_retained"] is True
    for operation in receipt["operations"]:
        for key in (
            "saved_operation",
            "revalidated_operation",
            "mutation_required",
            "source_sha256",
            "saved_destination_sha256",
            "current_pre_change_sha256",
            "expected_post_change_sha256",
            "post_change_sha256",
            "backup_created",
            "backup_relative_path",
            "backup_sha256",
            "temporary_preparation",
            "commit_result",
            "hash_verification",
            "mutation_performed",
        ):
            assert key in operation


def test_receipt_safety_ledger_is_complete_and_never_overstates(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="match")
    result = run_execute(lab)
    safety = read_receipt(result)["safety"]
    for key in wrre.SAFETY_FALSE_KEYS:
        assert safety[key] is False, key
    assert safety["exact_two_file_allowlist"] is True
    assert safety["read_only"] is False
    assert safety["mutation_performed"] is True
    assert safety["file_create_executed"] is True
    assert safety["file_replace_executed"] is False
    assert safety["backup_created"] is False
    assert safety["atomic_replace_executed"] is True
    assert safety["compensation_executed"] is False


def test_no_op_receipt_states_read_only_and_no_mutation(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="match", wrapper_state="match")
    result = run_execute(lab)
    receipt = read_receipt(result)
    assert receipt["status"] == wrre.STATUS_NO_CHANGE
    assert receipt["read_only"] is True
    assert receipt["mutation_performed"] is False
    assert receipt["safety"]["read_only"] is True
    assert receipt["safety"]["mutation_performed"] is False
    assert receipt["safety"]["backup_created"] is False
    assert receipt["safety"]["atomic_replace_executed"] is False


# --------------------------------------------------------------------------- #
# Validator acceptance across every receipt-producing status
# --------------------------------------------------------------------------- #


def _fail_second_commit(phase, target):
    return "injected failure" if phase == "commit" and target == "bin/sfai.cmd" else None


def _fail_post_verify(phase, target):
    return "injected failure" if phase == "post_verify" else None


def _drift_then_fail(lab):
    def hook(phase, target):
        if phase == "commit" and target == "bin/sfai.cmd":
            write_exact(lab.profile_destination, THIRD_PROFILE_BYTES)
            return "injected failure"
        return None

    return hook


@pytest.mark.parametrize(
    "profile_state,wrapper_state,expected",
    [
        ("missing", "stale", wrre.STATUS_EXECUTED),
        ("stale", "match", wrre.STATUS_PARTIAL_EXECUTED),
        ("match", "match", wrre.STATUS_NO_CHANGE),
    ],
)
def test_receipts_validate_for_each_terminal_status(
    tmp_path, monkeypatch, profile_state, wrapper_state, expected
):
    lab = make_lab(tmp_path, monkeypatch, profile_state=profile_state, wrapper_state=wrapper_state)
    result = run_execute(lab)
    assert result["status"] == expected
    validation = validate(result, lab)
    assert validation["status"] == "ok", validation["failures"]
    assert validation["failures"] == []
    assert all(validation["checks"].values())
    assert validation["read_only"] is True
    assert validation["mutation_performed"] is False


def test_blocked_receipt_validates(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    write_exact(lab.profile_destination, THIRD_PROFILE_BYTES)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    validation = validate(result, lab)
    assert validation["status"] == "ok", validation["failures"]


def test_compensated_failure_receipt_validates(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="missing")
    result = run_execute(lab, failure_hook=_fail_second_commit)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATED
    validation = validate(result, lab)
    assert validation["status"] == "ok", validation["failures"]
    receipt = read_receipt(result)
    assert receipt["compensation"]["attempted"] is True
    assert receipt["compensation"]["complete"] is True
    assert receipt["safety"]["compensation_executed"] is True


def test_incomplete_compensation_receipt_validates_and_is_honest(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab, failure_hook=_drift_then_fail(lab))
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATION_INCOMPLETE
    validation = validate(result, lab)
    assert validation["status"] == "ok", validation["failures"]
    receipt = read_receipt(result)
    assert receipt["compensation"]["complete"] is False
    assert receipt["compensation"]["entries"][0]["result"] == "refused_drifted_created_file"


def test_verification_failed_receipt_validates(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="match")
    result = run_execute(lab, failure_hook=_fail_post_verify)
    assert result["status"] == wrre.STATUS_VERIFICATION_FAILED
    validation = validate(result, lab)
    assert validation["status"] == "ok", validation["failures"]


def test_unknown_receipt_reference_is_deterministically_not_found(tmp_path):
    validation = wrre.validate_saved_receipt("wrr_missing", str(tmp_path))
    assert validation["status"] == "not_found"
    assert validation["failures"] == ["receipt bundle not found"]
    assert wrre.validate_saved_receipt("../escape", str(tmp_path))["status"] == "not_found"


# --------------------------------------------------------------------------- #
# Tamper rejection
# --------------------------------------------------------------------------- #


def test_manifest_checksum_tamper_is_rejected(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab)
    directory = receipt_dir(result)
    manifest = read_manifest(result)
    manifest["checksums"][wrre.RECEIPT_JSON] = "0" * 64
    rewrite(directory, wrre.RECEIPT_MANIFEST, manifest)
    validation = validate(result, lab)
    assert validation["status"] == "failed"
    assert validation["checks"]["checksums"] is False


def test_receipt_body_tamper_without_manifest_refresh_is_rejected(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab)
    directory = receipt_dir(result)
    receipt = read_receipt(result)
    receipt["status"] = wrre.STATUS_NO_CHANGE
    rewrite(directory, wrre.RECEIPT_JSON, receipt)
    validation = validate(result, lab)
    assert validation["status"] == "failed"
    assert validation["checks"]["checksums"] is False


@pytest.mark.parametrize(
    "mutate,broken_check",
    [
        (
            lambda r: r["operations"][1].update({"relative_destination": "bin/shellforgeai.cmd"}),
            "allowlist_and_operations",
        ),
        (
            lambda r: r.update({"allowlist": [{"source": "any", "destination": "any"}]}),
            "allowlist_and_operations",
        ),
        (
            lambda r: r["operations"].append(dict(r["operations"][0])),
            "allowlist_and_operations",
        ),
        (
            lambda r: r["operations"][0].update({"backup_relative_path": "C:\\Windows\\evil"}),
            "no_sensitive_fields",
        ),
        (
            lambda r: r["operations"][0].update({"post_change_sha256": "0" * 64}),
            "allowlist_and_operations",
        ),
        (lambda r: r["plan"].update({"confirmation_matched": False}), "plan_confirmation"),
        (lambda r: r["plan"].update({"canonical_packet_sha256": "nope"}), "plan_confirmation"),
        (lambda r: r["safety"].update({"powershell_executed": True}), "safety"),
        (lambda r: r["safety"].update({"exact_two_file_allowlist": False}), "safety"),
        (lambda r: r.update({"status": wrre.STATUS_NO_CHANGE}), "status_precedence"),
        (
            lambda r: r.update({"source_content": "@echo off"}),
            "no_sensitive_fields",
        ),
        (
            lambda r: r.update({"environment": {"PATH": "/usr/bin"}}),
            "no_sensitive_fields",
        ),
        (
            lambda r: r["compensation"].update(
                {"attempted": True, "entries": [{"action": "rm -rf", "relative_destination": "x"}]}
            ),
            "compensation",
        ),
    ],
)
def test_receipt_field_path_and_mapping_tamper_is_rejected(
    tmp_path, monkeypatch, mutate, broken_check
):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab)
    directory = receipt_dir(result)
    receipt = read_receipt(result)
    mutate(receipt)
    rewrite(directory, wrre.RECEIPT_JSON, receipt)
    refresh_manifest(directory)
    validation = validate(result, lab)
    assert validation["status"] == "failed"
    assert validation["checks"]["checksums"] is True
    assert validation["checks"][broken_check] is False


# --------------------------------------------------------------------------- #
# Privacy
# --------------------------------------------------------------------------- #


def test_receipt_contains_no_file_contents_or_environment_dump(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="stale")
    result = run_execute(lab)
    directory = receipt_dir(result)
    blob = "\n".join(
        (directory / name).read_bytes().decode("utf-8") for name in wrre.RECEIPT_REQUIRED_FILES
    )
    for fragment in (
        "@echo off",
        "SHELLFORGEAI_RUNTIME_ROOT",
        "%ERRORLEVEL%",
        "allow_risks",
        "deny_risks",
        "description: inspect",
        STALE_PROFILE_BYTES.decode("utf-8").strip(),
        CANONICAL_INSPECT_PROFILE_BYTES.decode("utf-8").strip(),
        CANONICAL_WRAPPER_BYTES.decode("utf-8").strip(),
    ):
        assert fragment not in blob
    receipt = read_receipt(result)
    for key in ("environment", "environ", "env", "secrets", "token", "password"):
        assert key not in receipt


def test_sensitive_absolute_paths_are_absent_from_receipt_and_result(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="stale")
    result = run_execute(lab)
    directory = receipt_dir(result)
    blob = "\n".join(
        (directory / name).read_bytes().decode("utf-8") for name in wrre.RECEIPT_REQUIRED_FILES
    )
    for absolute in (str(lab.staged), str(lab.runtime), str(lab.packet_path), str(tmp_path)):
        assert absolute not in blob
    envelope = dict(result)
    envelope.pop("receipt_path")
    serialized = json.dumps(envelope)
    assert str(lab.staged) not in serialized
    assert str(lab.runtime) not in serialized
    findings: list[str] = []
    wrre._scan_forbidden(read_receipt(result), findings)
    assert findings == []


def test_blocked_receipt_sanitizes_blockers(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    write_exact(lab.profile_destination, THIRD_PROFILE_BYTES)
    result = run_execute(lab)
    receipt = read_receipt(result)
    assert receipt["blockers"]
    for blocker in receipt["blockers"]:
        assert str(lab.runtime) not in blocker
        assert str(lab.staged) not in blocker
    assert validate(result, lab)["status"] == "ok"


def test_backup_paths_are_recorded_relative_to_the_durable_root(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="stale")
    result = run_execute(lab)
    for operation in read_receipt(result)["operations"]:
        relative = operation["backup_relative_path"]
        if relative is None:
            continue
        assert not relative.startswith("/")
        assert ".." not in relative
        assert (lab.runtime / relative).is_file()


# --------------------------------------------------------------------------- #
# Direct receipt validator helper
# --------------------------------------------------------------------------- #


def test_receipt_helper_accepts_and_rejects_deterministically(tmp_path, monkeypatch, capsys):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab)
    helper = load_script(RECEIPT_HELPER)
    code = helper.main([result["receipt_id"], "--data-dir", str(lab.data_dir), "--json"])
    payload = json.loads(capsys.readouterr().out.strip())
    assert code == 0
    assert payload["accepted"] is True
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False

    code = helper.main(["wrr_missing", "--data-dir", str(lab.data_dir), "--json"])
    payload = json.loads(capsys.readouterr().out.strip())
    assert code == 1
    assert payload["accepted"] is False
    assert payload["status"] == "not_found"


def test_receipt_helper_never_mutates_the_bundle(tmp_path, monkeypatch, capsys):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab)
    directory = receipt_dir(result)
    before = {p.name: p.read_bytes() for p in sorted(directory.iterdir())}
    helper = load_script(RECEIPT_HELPER)
    helper.main([result["receipt_id"], "--data-dir", str(lab.data_dir), "--json"])
    capsys.readouterr()
    after = {p.name: p.read_bytes() for p in sorted(directory.iterdir())}
    assert before == after


# --------------------------------------------------------------------------- #
# Recipe registry and preservation of existing lanes
# --------------------------------------------------------------------------- #


def test_registry_metadata_documents_the_governed_two_file_lane():
    recipe = recipe_registry.get_recipe("windows.runtime_reconcile")
    assert recipe is not None
    assert recipe["executable"] is False
    assert recipe["receipt_required"] is True
    assert recipe["verification_required"] is True
    assert recipe["rollback_available"] is False
    assert recipe["mutation_class"] == recipe_registry.MUTATION_WINDOWS_EXACT_TWO_FILE_ONLY
    assert recipe["first_safe_command"].startswith(
        "python scripts/windows_runtime_reconcile_preflight.py"
    )
    joined = " ".join(recipe["safe_next_commands"])
    assert "scripts/windows_runtime_reconcile_acceptance.py" in joined
    assert "scripts/windows_runtime_reconcile_execute.py" in joined
    assert "scripts/windows_runtime_reconcile_receipt_acceptance.py" in joined
    assert "scripts/windows_runtime_reconcile_verify.py" in joined
    assert "--confirm-plan-sha256" in joined
    notes = " ".join(recipe["safety_notes"])
    assert "config/profiles/inspect.yaml" in notes
    assert "scripts/windows/sfai.cmd -> bin/sfai.cmd" in notes
    assert "retained and never pruned" in notes
    assert "no post-success rollback command" in notes
    gates = " ".join(recipe["approval_gates"])
    assert "--confirm-plan-sha256" in gates
    assert "not a portable approval attestation" in gates


def test_registry_does_not_weaken_the_docker_disposable_restart_gates():
    docker = recipe_registry.get_recipe("docker.disposable_restart")
    assert docker["status"] == recipe_registry.STATUS_DISABLED_EXECUTE_LANE
    assert docker["mutation_class"] == recipe_registry.MUTATION_GOVERNED_DISPOSABLE_ONLY
    assert docker["required_target_labels"] == dict(
        recipe_registry.REQUIRED_DISPOSABLE_RESTART_LABELS
    )
    assert docker["executable"] is False
    assert docker["receipt_required"] is True


def test_existing_docker_receipt_conventions_are_untouched(tmp_path, monkeypatch):
    assert recipe_execution.RECEIPT_REQUIRED_FILES == (
        "recipe-receipt.json",
        "recipe-receipt.md",
        "manifest.json",
    )
    assert recipe_execution.recipe_receipt_root(tmp_path).name == "recipe_receipts"
    assert wrre.windows_reconcile_receipt_root(tmp_path).name == wrre.RECEIPT_ROOT_NAME
    assert recipe_execution.recipe_receipt_root(tmp_path) != wrre.windows_reconcile_receipt_root(
        tmp_path
    )
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab)
    docker_view = recipe_execution.validate_receipt(result["receipt_id"], str(lab.data_dir))
    assert docker_view["status"] == "not_found"
    assert docker_view["mutation_performed"] is False


def test_pr313_receipts_are_not_reachable_from_the_docker_receipt_root(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="match", wrapper_state="match")
    run_execute(lab)
    assert not (lab.data_dir / "recipe_receipts").exists()


def test_no_broad_copy_repair_or_apply_files_command_is_introduced():
    from shellforgeai import cli

    names = {
        str(entry.name or getattr(entry.callback, "__name__", "")).casefold()
        for entry in cli.app.registered_commands
    }
    names |= {str(group.name or "").casefold() for group in cli.app.registered_groups}
    for forbidden in ("copy", "repair", "apply-files", "apply_files", "reconcile"):
        assert forbidden not in names


def test_no_command_module_reaches_the_execute_lane():
    commands = Path("src/shellforgeai/commands")
    offenders = [
        path.name
        for path in commands.rglob("*.py")
        if "windows_runtime_reconcile_execution" in path.read_bytes().decode("utf-8")
    ]
    assert offenders == []


def test_natural_language_and_boolean_confirmation_are_not_execution_sources(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    for phrase in ("yes", "true", "please fix the windows runtime", "confirm", "1"):
        result = run_execute(lab, confirm_plan_sha256=phrase)
        assert result["status"] == wrre.STATUS_BLOCKED
        assert result["receipt_id"] is None
        assert result["safety"]["natural_language_execution"] is False
    assert not lab.profile_destination.exists()
    assert not lab.data_dir.exists()
