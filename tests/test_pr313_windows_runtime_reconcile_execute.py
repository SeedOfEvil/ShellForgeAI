"""PR313 governed two-file Windows runtime reconciliation execute lane."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from shellforgeai.core import windows_runtime_reconcile_execution as wrre

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
PR304_HELPER = SCRIPTS / "windows_runtime_integrity.py"
PR305_HELPER = SCRIPTS / "windows_runtime_reconcile_preflight.py"
EXECUTE_HELPER = SCRIPTS / "windows_runtime_reconcile_execute.py"

FIXED_CLOCK = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)

WRAPPER = (
    "@echo off\r\n"
    "setlocal\r\n"
    "set SHELLFORGEAI_RUNTIME_ROOT=%~dp0..\r\n"
    '"%~dp0..\\Python314\\python.exe" -m shellforgeai %*\r\n'
    "exit /b %ERRORLEVEL%\r\n"
)
PROFILE = (
    "name: inspect\n"
    "description: inspect\n"
    "allow_risks: [read]\n"
    "ask_risks: [change]\n"
    "deny_risks: [service, system, danger]\n"
    "allow_shell_raw: false\n"
    "online_allowed: false\n"
)
STALE_PROFILE = PROFILE.replace("description: inspect", "description: stale")
THIRD_PROFILE = PROFILE.replace("description: inspect", "description: third")
STALE_WRAPPER = WRAPPER.replace("setlocal\r\n", "setlocal\r\nrem stale\r\n")
THIRD_WRAPPER = WRAPPER.replace("setlocal\r\n", "setlocal\r\nrem third\r\n")


def load_script(path: Path):
    spec = importlib.util.spec_from_file_location(f"_pr313_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def force_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(platform, "release", lambda: "2025")
    monkeypatch.setattr(platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(platform, "platform", lambda: "Windows-2025")


@dataclass
class Lab:
    staged: Path
    runtime: Path
    data_dir: Path
    packet_path: Path
    packet: dict
    artifacts: list[Path]
    confirm: str

    @property
    def profile_destination(self) -> Path:
        return self.runtime / "config/profiles/inspect.yaml"

    @property
    def wrapper_destination(self) -> Path:
        return self.runtime / "bin/sfai.cmd"


def _write_state(path: Path, state: str, staged_text: str, stale_text: str) -> None:
    if state == "missing":
        return
    path.write_text(staged_text if state == "match" else stale_text, encoding="utf-8")


def build_pr304(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime: Path,
    *,
    name: str = "pr304.json",
    cwd: str | None = None,
) -> Path:
    helper = load_script(PR304_HELPER)
    monkeypatch.setattr(helper, "_site_roots", lambda: [])
    args = argparse.Namespace(
        expected_source_root=str(REPO_ROOT / "src"),
        runtime_root=str(runtime),
        wrapper_path=str(runtime / "bin/sfai.cmd"),
        canonical_wrapper_path=str(runtime / "bin/sfai.cmd"),
        entrypoint_path=str(runtime / "Python314/Scripts/shellforgeai.exe"),
        profile="inspect",
        json=True,
        out_json=None,
    )
    packet = helper.build_packet(args)
    if cwd is not None:
        # invocation context is deliberately excluded from PR304 stable identity.
        packet["invocation"]["cwd"] = cwd
    target = tmp_path / name
    target.write_text(json.dumps(packet, sort_keys=True), encoding="utf-8")
    return target


def build_plan(monkeypatch: pytest.MonkeyPatch, artifacts, staged: Path, runtime: Path) -> dict:
    helper = load_script(PR305_HELPER)
    return helper.build_packet([str(a) for a in artifacts], str(staged), str(runtime))


def make_lab(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile_state: str = "missing",
    wrapper_state: str = "stale",
    staged_profile: str = PROFILE,
    staged_wrapper: str = WRAPPER,
    artifact_count: int = 1,
) -> Lab:
    force_windows(monkeypatch)
    staged = tmp_path / "staged"
    (staged / "config/profiles").mkdir(parents=True)
    (staged / "config/profiles/inspect.yaml").write_text(staged_profile, encoding="utf-8")
    (staged / "scripts/windows").mkdir(parents=True)
    (staged / "scripts/windows/sfai.cmd").write_text(staged_wrapper, encoding="utf-8")

    runtime = tmp_path / "runtime"
    (runtime / "config/profiles").mkdir(parents=True)
    (runtime / "bin").mkdir(parents=True)
    (runtime / "Python314/Scripts").mkdir(parents=True)
    (runtime / "Python314/python.exe").write_text("", encoding="utf-8")
    (runtime / "Python314/Scripts/shellforgeai.exe").write_text("", encoding="utf-8")
    _write_state(
        runtime / "config/profiles/inspect.yaml", profile_state, staged_profile, STALE_PROFILE
    )
    _write_state(runtime / "bin/sfai.cmd", wrapper_state, staged_wrapper, STALE_WRAPPER)

    artifacts = [build_pr304(tmp_path, monkeypatch, runtime, name="pr304-staged.json")]
    if artifact_count == 2:
        artifacts.append(
            build_pr304(
                tmp_path,
                monkeypatch,
                runtime,
                name="pr304-system32.json",
                cwd="C:\\Windows\\System32",
            )
        )
    packet = build_plan(monkeypatch, artifacts, staged, runtime)
    packet_path = tmp_path / "pr305.json"
    packet_path.write_text(json.dumps(packet, sort_keys=True), encoding="utf-8")
    return Lab(
        staged=staged,
        runtime=runtime,
        data_dir=tmp_path / "data",
        packet_path=packet_path,
        packet=packet,
        artifacts=artifacts,
        confirm=wrre.canonical_plan_sha256(packet),
    )


def run_execute(lab: Lab, **overrides):
    kwargs = {
        "staged_source_root": str(lab.staged),
        "durable_runtime_root": str(lab.runtime),
        "confirm_plan_sha256": lab.confirm,
        "data_dir": str(lab.data_dir),
        "validators": wrre.load_validators(SCRIPTS),
        "clock": lambda: FIXED_CLOCK,
    }
    packet_path = overrides.pop("packet_path", lab.packet_path)
    artifacts = overrides.pop("artifacts", lab.artifacts)
    kwargs.update(overrides)
    return wrre.execute_windows_runtime_reconcile(packet_path, artifacts, **kwargs)


def resave_packet(lab: Lab, packet: dict) -> Lab:
    lab.packet = packet
    lab.packet_path.write_text(json.dumps(packet, sort_keys=True), encoding="utf-8")
    lab.confirm = wrre.canonical_plan_sha256(packet)
    return lab


def receipt_of(result: dict) -> dict:
    return json.loads(
        (Path(result["receipt_path"]) / wrre.RECEIPT_JSON).read_bytes().decode("utf-8")
    )


def temp_or_backup_files(runtime: Path) -> list[str]:
    return sorted(
        p.name
        for p in runtime.rglob("*")
        if wrre.TEMP_MARKER in p.name or wrre.BACKUP_MARKER in p.name
    )


def temp_files(runtime: Path) -> list[str]:
    return sorted(p.name for p in runtime.rglob("*") if wrre.TEMP_MARKER in p.name)


def backup_files(runtime: Path) -> list[Path]:
    return sorted(p for p in runtime.rglob("*") if wrre.BACKUP_MARKER in p.name)


# --------------------------------------------------------------------------- #
# Platform, confirmation, and packet gates
# --------------------------------------------------------------------------- #


def test_linux_is_unsupported_with_zero_mutation(tmp_path):
    result = wrre.execute_windows_runtime_reconcile(
        tmp_path / "missing.json",
        [tmp_path / "missing-artifact.json"],
        staged_source_root=str(tmp_path / "staged"),
        durable_runtime_root=str(tmp_path / "runtime"),
        confirm_plan_sha256="a" * 64,
        data_dir=str(tmp_path / "data"),
        validators=wrre.load_validators(SCRIPTS),
    )
    assert result["status"] == wrre.STATUS_UNSUPPORTED
    assert result["mutation_performed"] is False
    assert result["receipt_id"] is None
    assert result["safety"]["read_only"] is True
    assert not (tmp_path / "data").exists()


@pytest.mark.parametrize("confirmation", ["", "not-a-hash", "A" * 64, "a" * 63, "z" * 64])
def test_missing_or_malformed_confirmation_blocks_without_receipt(
    tmp_path, monkeypatch, confirmation
):
    lab = make_lab(tmp_path, monkeypatch)
    result = run_execute(lab, confirm_plan_sha256=confirmation)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None
    assert result["mutation_performed"] is False
    assert not lab.data_dir.exists()
    assert not lab.profile_destination.exists()
    assert temp_or_backup_files(lab.runtime) == []


def test_incorrect_plan_hash_confirmation_blocks_without_receipt(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    result = run_execute(lab, confirm_plan_sha256="b" * 64)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert "confirmation" in result["reason"]
    assert result["receipt_id"] is None
    assert not lab.data_dir.exists()
    assert temp_or_backup_files(lab.runtime) == []


def test_any_packet_field_change_requires_new_confirmation(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    stale_confirmation = lab.confirm
    packet = dict(lab.packet)
    packet["warnings"] = ["operator note"]
    resave_packet(lab, packet)
    assert wrre.canonical_plan_sha256(packet) != stale_confirmation
    result = run_execute(lab, confirm_plan_sha256=stale_confirmation)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None


def test_canonical_confirmation_identity_is_deterministic_and_binds_the_object(
    tmp_path, monkeypatch
):
    lab = make_lab(tmp_path, monkeypatch)
    reloaded = json.loads(lab.packet_path.read_bytes().decode("utf-8"))
    assert wrre.canonical_plan_sha256(reloaded) == lab.confirm
    assert wrre.canonical_plan_json(reloaded) == json.dumps(
        reloaded, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert wrre.confirmation_matches(lab.confirm, lab.confirm) is True
    assert wrre.confirmation_matches("b" * 64, lab.confirm) is False


def test_unreadable_or_invalid_packet_blocks_without_receipt(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    lab.packet_path.write_text("{not json", encoding="utf-8")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None
    assert not lab.data_dir.exists()


def test_invalid_pr305_packet_is_rejected(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    packet = json.loads(json.dumps(lab.packet))
    packet["safety"]["powershell_executed"] = True
    resave_packet(lab, packet)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None
    assert any("safety" in blocker for blocker in result["blockers"])


def test_wrong_recipe_id_is_rejected(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    packet = json.loads(json.dumps(lab.packet))
    packet["recipe_id"] = "windows.other_capability"
    resave_packet(lab, packet)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None


def test_wrong_allowlist_is_rejected(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    packet = json.loads(json.dumps(lab.packet))
    packet["allowlist"][1]["destination"] = "bin/shellforgeai.cmd"
    resave_packet(lab, packet)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("allowlist" in blocker for blocker in result["blockers"])


def test_more_than_two_operations_is_rejected(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    packet = json.loads(json.dumps(lab.packet))
    packet["operations"].append(json.loads(json.dumps(packet["operations"][0])))
    resave_packet(lab, packet)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None


def test_reordered_operations_are_rejected(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    packet = json.loads(json.dumps(lab.packet))
    packet["operations"] = [packet["operations"][1], packet["operations"][0]]
    resave_packet(lab, packet)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("ordering" in blocker or "allowlist" in blocker for blocker in result["blockers"])


def test_blocked_or_unsupported_plan_status_is_refused(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    packet = json.loads(json.dumps(lab.packet))
    packet["status"] = "blocked"
    resave_packet(lab, packet)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED


# --------------------------------------------------------------------------- #
# Evidence and roots
# --------------------------------------------------------------------------- #


def test_missing_or_malformed_pr304_artifact_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    bad = tmp_path / "bad-pr304.json"
    bad.write_text("[]", encoding="utf-8")
    result = run_execute(lab, artifacts=[bad])
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None
    assert not lab.profile_destination.exists()


def test_too_many_pr304_artifacts_block(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, artifact_count=2)
    result = run_execute(lab, artifacts=[*lab.artifacts, lab.artifacts[0]])
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("one or two" in blocker for blocker in result["blockers"])


def test_two_agreeing_pr304_artifacts_are_compared_and_accepted(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, artifact_count=2)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_EXECUTED
    assert result["evidence"]["pr304_stable_identity_compared"] is True
    assert result["evidence"]["pr304_stable_identity_matched"] is True


def test_disagreeing_pr304_artifacts_block(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, artifact_count=2)
    payload = json.loads(lab.artifacts[1].read_bytes().decode("utf-8"))
    payload["wrapper"]["sha256"] = "f" * 64
    lab.artifacts[1].write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("stable identity" in blocker for blocker in result["blockers"])


def test_root_mismatch_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    other = tmp_path / "other-staged"
    other.mkdir()
    result = run_execute(lab, staged_source_root=str(other))
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("staged source root" in blocker for blocker in result["blockers"])
    assert not lab.profile_destination.exists()


def test_relative_roots_are_refused(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    result = run_execute(lab, durable_runtime_root="runtime")
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("absolute" in blocker for blocker in result["blockers"])


def test_roots_are_recorded_as_fingerprints_only(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="match", wrapper_state="match")
    result = run_execute(lab)
    roots = result["roots"]
    assert wrre.is_plan_sha256(roots["staged_source_root_fingerprint_sha256"])
    assert wrre.is_plan_sha256(roots["durable_runtime_root_fingerprint_sha256"])
    assert str(lab.staged) not in json.dumps(roots)


# --------------------------------------------------------------------------- #
# Containment, reparse, and source validation
# --------------------------------------------------------------------------- #


def test_source_path_escape_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    outside = tmp_path / "outside-config"
    (outside / "profiles").mkdir(parents=True)
    (outside / "profiles/inspect.yaml").write_text(PROFILE, encoding="utf-8")
    shutil.rmtree(lab.staged / "config")
    (lab.staged / "config").symlink_to(outside, target_is_directory=True)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("escapes the staged source root" in blocker for blocker in result["blockers"])
    assert not lab.profile_destination.exists()
    assert temp_or_backup_files(lab.runtime) == []


def test_destination_path_escape_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    outside = tmp_path / "outside-bin"
    outside.mkdir()
    (outside / "sfai.cmd").write_text(STALE_WRAPPER, encoding="utf-8")
    shutil.rmtree(lab.runtime / "bin")
    (lab.runtime / "bin").symlink_to(outside, target_is_directory=True)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("escapes the durable runtime root" in blocker for blocker in result["blockers"])
    assert (outside / "sfai.cmd").read_bytes().decode("utf-8") == STALE_WRAPPER


def test_source_symlink_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    real = lab.staged / "config/profiles/inspect.real.yaml"
    real.write_text(PROFILE, encoding="utf-8")
    target = lab.staged / "config/profiles/inspect.yaml"
    target.unlink()
    target.symlink_to(real)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("reparse point or symlink" in blocker for blocker in result["blockers"])


def test_destination_symlink_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    real = lab.runtime / "bin/sfai.real.cmd"
    real.write_text(STALE_WRAPPER, encoding="utf-8")
    target = lab.wrapper_destination
    target.unlink()
    target.symlink_to(real)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("reparse point or symlink" in blocker for blocker in result["blockers"])
    assert real.read_bytes().decode("utf-8") == STALE_WRAPPER


def test_reparse_parent_component_blocks_without_escaping(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    real_dir = lab.staged / "scripts/real-windows"
    real_dir.mkdir()
    (real_dir / "sfai.cmd").write_text(WRAPPER, encoding="utf-8")
    shutil.rmtree(lab.staged / "scripts/windows")
    (lab.staged / "scripts/windows").symlink_to(real_dir, target_is_directory=True)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    blockers = " ".join(result["blockers"])
    assert "source path chain contains a reparse point or symlink" in blockers
    assert "windows" in blockers
    assert "escapes the staged source root" not in blockers


def test_missing_source_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    (lab.staged / "config/profiles/inspect.yaml").unlink()
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("missing or not a regular file" in blocker for blocker in result["blockers"])
    assert not lab.profile_destination.exists()


def test_source_hash_drift_blocks_the_whole_transaction(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    (lab.staged / "config/profiles/inspect.yaml").write_text(THIRD_PROFILE, encoding="utf-8")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("drifted from the accepted plan" in blocker for blocker in result["blockers"])
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == STALE_WRAPPER
    assert temp_or_backup_files(lab.runtime) == []


def test_oversized_source_blocks(tmp_path, monkeypatch):
    oversized = WRAPPER + ("rem padding\r\n" * 25000)
    assert len(oversized.encode("utf-8")) > wrre.MAX_SOURCE_BYTES["scripts/windows/sfai.cmd"]
    lab = make_lab(tmp_path, monkeypatch, staged_wrapper=oversized)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("maximum size" in blocker for blocker in result["blockers"])


@pytest.mark.parametrize(
    "bad_profile",
    [
        "name: inspect\nallow_risks: [read\n",
        "name: not-inspect\ndescription: x\n",
        "- just\n- a\n- list\n",
        "name: inspect\nallow_risks: [not-a-risk-tier]\n",
    ],
)
def test_invalid_inspect_profile_blocks(tmp_path, monkeypatch, bad_profile):
    lab = make_lab(tmp_path, monkeypatch, staged_profile=bad_profile)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("inspect profile" in blocker for blocker in result["blockers"])
    assert not lab.profile_destination.exists()


def test_profile_source_must_decode_as_utf8(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    (lab.staged / "config/profiles/inspect.yaml").write_bytes(b"name: inspect\n\xff\xfe")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED


def test_unsafe_yaml_object_construction_is_refused(tmp_path, monkeypatch):
    unsafe = "!!python/object/apply:os.system ['echo unsafe']\n"
    lab = make_lab(tmp_path, monkeypatch, staged_profile=unsafe)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("YAML" in blocker or "mapping" in blocker for blocker in result["blockers"])


def test_invalid_wrapper_semantic_markers_block(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, staged_wrapper=WRAPPER.replace("%ERRORLEVEL%", "0"))
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("semantic markers" in blocker for blocker in result["blockers"])


def test_missing_destination_parent_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing")
    shutil.rmtree(lab.runtime / "config/profiles")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("parent directory does not exist" in blocker for blocker in result["blockers"])
    assert not (lab.runtime / "config/profiles").exists()


def test_destination_that_is_a_directory_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing")
    lab.profile_destination.mkdir()
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("not a regular file" in blocker for blocker in result["blockers"])


# --------------------------------------------------------------------------- #
# Stale, partial, and no-op state machine
# --------------------------------------------------------------------------- #


def test_planned_create_and_replace_both_execute(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    assert [op["operation"] for op in lab.packet["operations"]] == [
        "create_required",
        "replace_required",
    ]
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_EXECUTED
    assert lab.profile_destination.read_bytes().decode("utf-8") == PROFILE
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == WRAPPER
    assert result["safety"]["file_create_executed"] is True
    assert result["safety"]["file_replace_executed"] is True
    assert result["safety"]["atomic_replace_executed"] is True
    assert result["safety"]["backup_created"] is True
    assert result["safety"]["read_only"] is False
    assert result["safety"]["mutation_performed"] is True
    assert temp_files(lab.runtime) == []
    assert len(backup_files(lab.runtime)) == 1


def test_planned_create_narrowed_to_no_op_when_destination_matches(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    lab.profile_destination.write_text(PROFILE, encoding="utf-8")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_PARTIAL_EXECUTED
    profile_op, wrapper_op = result["operations"]
    assert profile_op["saved_operation"] == "create_required"
    assert profile_op["revalidated_operation"] == "no_change"
    assert profile_op["narrowed_to_no_op"] is True
    assert profile_op["mutation_performed"] is False
    assert profile_op["backup_created"] is False
    assert wrapper_op["mutation_performed"] is True


def test_planned_create_conflict_blocks_everything(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    lab.profile_destination.write_text(THIRD_PROFILE, encoding="utf-8")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("conflicting destination" in blocker for blocker in result["blockers"])
    assert lab.profile_destination.read_bytes().decode("utf-8") == THIRD_PROFILE
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == STALE_WRAPPER
    assert temp_or_backup_files(lab.runtime) == []
    assert result["receipt_id"] is not None


def test_planned_replace_narrowed_to_no_op_when_destination_matches(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="stale")
    lab.profile_destination.write_text(PROFILE, encoding="utf-8")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_PARTIAL_EXECUTED
    profile_op = result["operations"][0]
    assert profile_op["saved_operation"] == "replace_required"
    assert profile_op["revalidated_operation"] == "no_change"
    assert profile_op["narrowed_to_no_op"] is True
    assert profile_op["backup_created"] is False
    assert len(backup_files(lab.runtime)) == 1


def test_planned_replace_third_hash_blocks_everything(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="stale")
    lab.profile_destination.write_text(THIRD_PROFILE, encoding="utf-8")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("third hash" in blocker for blocker in result["blockers"])
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == STALE_WRAPPER
    assert temp_or_backup_files(lab.runtime) == []


def test_planned_replace_destination_disappearance_blocks_everything(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="stale")
    lab.profile_destination.unlink()
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("disappeared" in blocker for blocker in result["blockers"])
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == STALE_WRAPPER


def test_planned_no_change_stays_a_no_op(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="match", wrapper_state="match")
    assert lab.packet["status"] == "no_change"
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_NO_CHANGE
    assert result["mutation_performed"] is False
    assert result["safety"]["read_only"] is True
    assert result["safety"]["backup_created"] is False
    assert temp_or_backup_files(lab.runtime) == []
    assert all(op["mutation_performed"] is False for op in result["operations"])


def test_planned_no_change_mismatch_blocks_everything(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="match", wrapper_state="match")
    lab.profile_destination.write_text(THIRD_PROFILE, encoding="utf-8")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("no longer matches" in blocker for blocker in result["blockers"])
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == WRAPPER


def test_planned_no_change_disappearance_blocks_everything(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="match", wrapper_state="match")
    lab.profile_destination.unlink()
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("disappeared" in blocker for blocker in result["blockers"])


def test_one_no_op_plus_one_replacement_is_partial(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="match")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_PARTIAL_EXECUTED
    assert result["operations"][0]["revalidated_operation"] == "replace_required"
    assert result["operations"][1]["revalidated_operation"] == "no_change"
    assert lab.profile_destination.read_bytes().decode("utf-8") == PROFILE
    assert len(backup_files(lab.runtime)) == 1


def test_one_no_op_plus_one_create_is_partial(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="match")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_PARTIAL_EXECUTED
    assert result["operations"][0]["revalidated_operation"] == "create_required"
    assert lab.profile_destination.read_bytes().decode("utf-8") == PROFILE
    assert backup_files(lab.runtime) == []


def test_successful_rerun_with_a_fresh_plan_is_idempotent(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    first = run_execute(lab)
    assert first["status"] == wrre.STATUS_EXECUTED
    backups_after_first = backup_files(lab.runtime)
    assert len(backups_after_first) == 1

    fresh_artifacts = [
        build_pr304(tmp_path, monkeypatch, lab.runtime, name="pr304-second.json")
    ]
    fresh_packet = build_plan(monkeypatch, fresh_artifacts, lab.staged, lab.runtime)
    assert fresh_packet["status"] == "no_change"
    second_path = tmp_path / "pr305-second.json"
    second_path.write_text(json.dumps(fresh_packet, sort_keys=True), encoding="utf-8")
    second = run_execute(
        lab,
        packet_path=second_path,
        artifacts=fresh_artifacts,
        confirm_plan_sha256=wrre.canonical_plan_sha256(fresh_packet),
    )
    assert second["status"] == wrre.STATUS_NO_CHANGE
    assert second["mutation_performed"] is False
    assert second["safety"]["read_only"] is True
    assert backup_files(lab.runtime) == backups_after_first
    assert temp_files(lab.runtime) == []


def test_stale_plan_cannot_be_replayed_after_success(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    assert run_execute(lab)["status"] == wrre.STATUS_EXECUTED
    replay = run_execute(lab)
    assert replay["status"] == wrre.STATUS_NO_CHANGE
    assert replay["mutation_performed"] is False
    assert all(op["narrowed_to_no_op"] for op in replay["operations"])


# --------------------------------------------------------------------------- #
# Preparation, backups, atomicity, and verification
# --------------------------------------------------------------------------- #


def test_all_preparation_completes_before_the_first_commit(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    phases: list[tuple[str, str]] = []

    def hook(phase, target):
        phases.append((phase, target))
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_EXECUTED
    names = [phase for phase, _ in phases]
    first_commit = names.index("commit")
    assert names.count("temp") == 2
    assert all(index < first_commit for index, name in enumerate(names) if name == "temp")
    assert all(index < first_commit for index, name in enumerate(names) if name == "backup")


def test_backup_is_exclusive_same_directory_and_collision_resistant(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="match")
    expected = (
        f"inspect.yaml.{wrre.BACKUP_MARKER}-{wrre._stamp(FIXED_CLOCK)}-{lab.confirm[:8]}.bak"
    )
    squatter = lab.profile_destination.parent / expected
    squatter.write_text("pre-existing backup", encoding="utf-8")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_PARTIAL_EXECUTED
    assert squatter.read_bytes().decode("utf-8") == "pre-existing backup"
    backups = [p for p in backup_files(lab.runtime) if p != squatter]
    assert len(backups) == 1
    assert backups[0].parent == lab.profile_destination.parent
    assert backups[0].name.startswith(f"inspect.yaml.{wrre.BACKUP_MARKER}-")
    assert lab.confirm[:8] in backups[0].name


def test_backup_hash_matches_the_pre_change_destination(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="match")
    pre_change = wrre._sha256_bytes(STALE_PROFILE.encode("utf-8"))
    result = run_execute(lab)
    op = result["operations"][0]
    assert op["backup_created"] is True
    assert op["backup_sha256"] == pre_change
    assert op["current_pre_change_sha256"] == pre_change
    backup = backup_files(lab.runtime)[0]
    assert wrre._sha256_file(backup) == pre_change
    assert op["backup_relative_path"] == f"config/profiles/{backup.name}"


def test_temporary_file_hash_verification_is_enforced(tmp_path):
    destination = tmp_path / "target.bin"
    prepared = wrre._Prepared(
        evaluation=wrre.FileEvaluation("a", "b"),
        destination=destination,
        operation="create_required",
        source_sha256="0" * 64,
    )
    with pytest.raises(OSError, match="temporary file hash verification failed"):
        wrre._create_temp(prepared, data=b"payload")
    assert not destination.exists()


def test_commit_uses_atomic_os_replace_only(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    real_replace = os.replace
    calls: list[tuple[str, str]] = []

    def spy(src, dst, *args, **kwargs):
        calls.append((str(src), str(dst)))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(wrre.os, "replace", spy)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_EXECUTED
    assert len(calls) == 2
    assert [dst for _, dst in calls] == [
        str(lab.profile_destination),
        str(lab.wrapper_destination),
    ]
    assert all(wrre.TEMP_MARKER in src for src, _ in calls)


def test_final_hash_verification_is_recorded(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    result = run_execute(lab)
    for op in result["operations"]:
        assert op["hash_verification"] == "passed"
        assert op["commit_result"] == "committed"
        assert op["post_change_sha256"] == op["expected_post_change_sha256"]
        assert op["temporary_preparation"] == "committed"
    assert result["post_verification"]["status"] == "passed"


def test_injected_failure_before_any_commit_causes_zero_mutation(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")

    def hook(phase, target):
        if phase == "temp" and target == "bin/sfai.cmd":
            return "injected preparation failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["mutation_performed"] is False
    assert not lab.profile_destination.exists()
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == STALE_WRAPPER
    assert temp_files(lab.runtime) == []
    assert result["receipt_id"] is not None


def test_injected_failure_on_the_first_commit_leaves_no_mutation(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")

    def hook(phase, target):
        if phase == "commit" and target == "config/profiles/inspect.yaml":
            return "injected first-commit failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["mutation_performed"] is False
    assert not lab.profile_destination.exists()
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == STALE_WRAPPER
    assert temp_files(lab.runtime) == []
    assert result["compensation"]["attempted"] is False


def test_replacement_compensation_restores_the_original_hash(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="missing")
    assert [op["operation"] for op in lab.packet["operations"]] == [
        "replace_required",
        "create_required",
    ]

    def hook(phase, target):
        if phase == "commit" and target == "bin/sfai.cmd":
            return "injected second-commit failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATED
    assert result["compensation"]["attempted"] is True
    assert result["compensation"]["complete"] is True
    entry = result["compensation"]["entries"][0]
    assert entry["action"] == "restore_from_execution_backup"
    assert entry["result"] == "restored"
    assert lab.profile_destination.read_bytes().decode("utf-8") == STALE_PROFILE
    assert not lab.wrapper_destination.exists()
    assert len(backup_files(lab.runtime)) == 1
    assert result["safety"]["compensation_executed"] is True
    assert temp_files(lab.runtime) == []


def test_create_compensation_removes_only_the_execution_created_file(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")

    def hook(phase, target):
        if phase == "commit" and target == "bin/sfai.cmd":
            return "injected second-commit failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATED
    entry = result["compensation"]["entries"][0]
    assert entry["action"] == "remove_execution_created_file"
    assert entry["result"] == "removed"
    assert not lab.profile_destination.exists()
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == STALE_WRAPPER


def test_compensation_refuses_to_remove_a_drifted_created_file(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")

    def hook(phase, target):
        if phase == "commit" and target == "bin/sfai.cmd":
            lab.profile_destination.write_text(THIRD_PROFILE, encoding="utf-8")
            return "injected second-commit failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATION_INCOMPLETE
    assert result["compensation"]["complete"] is False
    entry = result["compensation"]["entries"][0]
    assert entry["result"] == "refused_drifted_created_file"
    assert lab.profile_destination.read_bytes().decode("utf-8") == THIRD_PROFILE
    assert lab.wrapper_destination.read_bytes().decode("utf-8") == STALE_WRAPPER


def test_post_verification_failure_retains_backups_without_restoration(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="match")

    def hook(phase, target):
        if phase == "post_verify":
            return "injected post-verification failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_VERIFICATION_FAILED
    assert result["compensation"]["attempted"] is False
    assert result["post_verification"]["status"] == "failed"
    assert lab.profile_destination.read_bytes().decode("utf-8") == PROFILE
    assert len(backup_files(lab.runtime)) == 1
    assert any("backups retained" in warning for warning in result["warnings"])


def test_create_refuses_when_destination_appears_between_prepare_and_commit(
    tmp_path, monkeypatch
):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="match")

    def hook(phase, target):
        if phase == "commit" and target == "config/profiles/inspect.yaml":
            lab.profile_destination.write_text(THIRD_PROFILE, encoding="utf-8")
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("appeared" in blocker for blocker in result["blockers"])
    assert result["mutation_performed"] is False
    assert lab.profile_destination.read_bytes().decode("utf-8") == THIRD_PROFILE
    assert temp_files(lab.runtime) == []


# --------------------------------------------------------------------------- #
# Direct entry point behaviour
# --------------------------------------------------------------------------- #


def test_direct_helper_is_unsupported_on_linux_without_mutation(tmp_path, capsys):
    helper = load_script(EXECUTE_HELPER)
    data_dir = tmp_path / "data"
    code = helper.main(
        [
            str(tmp_path / "packet.json"),
            str(tmp_path / "pr304.json"),
            "--staged-source-root",
            str(tmp_path / "staged"),
            "--durable-runtime-root",
            str(tmp_path / "runtime"),
            "--confirm-plan-sha256",
            "a" * 64,
            "--data-dir",
            str(data_dir),
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out.strip())
    assert code == 0
    assert payload["status"] == "unsupported"
    assert payload["mutation_performed"] is False
    assert payload["receipt_id"] is None
    assert payload["safety"]["subprocess_executed"] is False
    assert payload["safety"]["powershell_executed"] is False
    assert not data_dir.exists()


def test_direct_helper_rejects_arbitrary_mapping_and_boolean_confirmation(tmp_path):
    helper = load_script(EXECUTE_HELPER)
    for argv in (
        ["p.json", "a.json", "--yes"],
        ["p.json", "a.json", "--source", "x", "--destination", "y"],
        ["p.json", "a.json", "--confirm"],
    ):
        with pytest.raises(SystemExit):
            helper.main(argv)


def test_confirmation_argument_is_required(tmp_path):
    helper = load_script(EXECUTE_HELPER)
    with pytest.raises(SystemExit):
        helper.main(
            [
                "p.json",
                "a.json",
                "--staged-source-root",
                "/s",
                "--durable-runtime-root",
                "/r",
                "--data-dir",
                str(tmp_path),
            ]
        )


def test_module_import_and_helper_load_perform_no_mutation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    importlib.reload(wrre)
    for script in (
        EXECUTE_HELPER,
        SCRIPTS / "windows_runtime_reconcile_receipt_acceptance.py",
        SCRIPTS / "windows_runtime_reconcile_verify.py",
    ):
        load_script(script)
    assert sorted(p.name for p in tmp_path.iterdir()) == []


def test_allowlist_is_exact_fixed_and_free_of_traversal():
    assert wrre.ALLOWLIST == (
        ("config/profiles/inspect.yaml", "config/profiles/inspect.yaml"),
        ("scripts/windows/sfai.cmd", "bin/sfai.cmd"),
    )
    for source, destination in wrre.ALLOWLIST:
        for value in (source, destination):
            assert ".." not in value
            assert "\\" not in value
            assert "*" not in value
            assert not value.startswith("/")
            assert ":" not in value
    assert "shellforgeai.cmd" not in {destination for _, destination in wrre.ALLOWLIST}
