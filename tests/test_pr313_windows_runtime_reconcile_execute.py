"""PR313 governed two-file Windows runtime reconciliation execute lane."""

from __future__ import annotations

import argparse
import hashlib
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

# Byte-exact synthetic fixtures.
#
# Every fixture below whose raw bytes participate in a product decision (planning,
# execution, backup, atomic replacement, compensation, receipt, verification, or
# tamper detection) is declared as an exact ``bytes`` constant and written with
# ``Path.write_bytes``. ``Path.write_text`` applies platform newline translation,
# which on Windows rewrites "\r\n" as "\r\r\n" and bare "\n" as "\r\n"; that changes
# the fixture bytes and therefore every SHA-256 the product compares. Byte constants
# plus ``write_bytes`` keep the same fixture identical on Linux and Windows.
#
# The wrapper deliberately keeps the maintained PR304 semantic markers: "%~dp0",
# "SHELLFORGEAI_RUNTIME_ROOT", "Python314\\python.exe", "-m shellforgeai %*", and
# "%ERRORLEVEL%". CRLF is intentional for a .cmd wrapper; the profile stays LF.
CANONICAL_WRAPPER_BYTES = (
    b"@echo off\r\n"
    b'set "SHELLFORGEAI_RUNTIME_ROOT=%~dp0.."\r\n'
    b'"%SHELLFORGEAI_RUNTIME_ROOT%\\Python314\\python.exe" -m shellforgeai %*\r\n'
    b"exit /b %ERRORLEVEL%\r\n"
)
STALE_WRAPPER_BYTES = CANONICAL_WRAPPER_BYTES.replace(
    b"@echo off\r\n", b"@echo off\r\nrem stale\r\n"
)
THIRD_WRAPPER_BYTES = CANONICAL_WRAPPER_BYTES.replace(
    b"@echo off\r\n", b"@echo off\r\nrem third\r\n"
)
MARKERLESS_WRAPPER_BYTES = CANONICAL_WRAPPER_BYTES.replace(b"%ERRORLEVEL%", b"0")
OVERSIZED_WRAPPER_BYTES = CANONICAL_WRAPPER_BYTES + (b"rem padding\r\n" * 25000)

CANONICAL_INSPECT_PROFILE_BYTES = (
    b"name: inspect\n"
    b"description: inspect\n"
    b"allow_risks: [read]\n"
    b"ask_risks: [change]\n"
    b"deny_risks: [service, system, danger]\n"
    b"allow_shell_raw: false\n"
    b"online_allowed: false\n"
)
STALE_PROFILE_BYTES = CANONICAL_INSPECT_PROFILE_BYTES.replace(
    b"description: inspect", b"description: stale"
)
THIRD_PROFILE_BYTES = CANONICAL_INSPECT_PROFILE_BYTES.replace(
    b"description: inspect", b"description: third"
)


def write_exact(path: Path, payload: bytes) -> str:
    """Write byte-exact fixture content and return its SHA-256 hexdigest.

    The returned digest is computed from the bytes actually written, never from a
    separate string that could undergo different newline or encoding handling.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def force_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministically exercise the Linux unsupported path on any host."""
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "release", lambda: "6.8.0")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(platform, "platform", lambda: "Linux-6.8.0")


def symlink_or_skip(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    """Create a symlink, or skip when the host refuses the privilege.

    Windows only permits symlink creation with Developer Mode or
    SeCreateSymbolicLinkPrivilege. Skipping on OSError keeps the reparse-refusal
    coverage on every host that can express it, without reporting a host privilege
    limitation as a product failure.
    """
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - host dependent
        pytest.skip(f"host cannot create symlinks for reparse coverage: {exc.__class__.__name__}")


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


def _write_state(path: Path, state: str, staged_bytes: bytes, stale_bytes: bytes) -> None:
    if state == "missing" or not path.parent.is_dir():
        return
    write_exact(path, staged_bytes if state == "match" else stale_bytes)


def _build_profile_parent(runtime: Path, state: str, tmp_path: Path) -> None:
    """Materialise the exact config/profiles parent chain in a named state."""
    config = runtime / "config"
    profiles = config / "profiles"
    if state == "present":
        profiles.mkdir(parents=True)
    elif state == "missing_profiles":
        config.mkdir(parents=True)
    elif state == "missing_all":
        pass
    elif state == "file_config":
        write_exact(config, b"hostile")
    elif state == "file_profiles":
        config.mkdir(parents=True)
        write_exact(profiles, b"hostile")
    elif state == "reparse_profiles":
        config.mkdir(parents=True)
        real = tmp_path / "outside-profiles"
        real.mkdir(exist_ok=True)
        symlink_or_skip(profiles, real, target_is_directory=True)
    else:  # pragma: no cover - defensive
        raise ValueError(f"unknown profile parent state: {state}")


def _build_wrapper_parent(runtime: Path, state: str, tmp_path: Path) -> None:
    """Materialise the fixed bin parent, which PR313 must never create."""
    target = runtime / "bin"
    if state == "present":
        target.mkdir(parents=True)
    elif state == "missing":
        pass
    elif state == "file":
        write_exact(target, b"hostile")
    elif state == "reparse":
        real = tmp_path / "outside-bin"
        real.mkdir(exist_ok=True)
        symlink_or_skip(target, real, target_is_directory=True)
    else:  # pragma: no cover - defensive
        raise ValueError(f"unknown wrapper parent state: {state}")


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
    staged_profile: bytes = CANONICAL_INSPECT_PROFILE_BYTES,
    staged_wrapper: bytes = CANONICAL_WRAPPER_BYTES,
    artifact_count: int = 1,
    profile_parent: str = "present",
    wrapper_parent: str = "present",
) -> Lab:
    force_windows(monkeypatch)
    staged = tmp_path / "staged"
    write_exact(staged / "config/profiles/inspect.yaml", staged_profile)
    write_exact(staged / "scripts/windows/sfai.cmd", staged_wrapper)

    runtime = tmp_path / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    _build_profile_parent(runtime, profile_parent, tmp_path)
    _build_wrapper_parent(runtime, wrapper_parent, tmp_path)
    (runtime / "Python314/Scripts").mkdir(parents=True)
    write_exact(runtime / "Python314/python.exe", b"")
    write_exact(runtime / "Python314/Scripts/shellforgeai.exe", b"")
    _write_state(
        runtime / "config/profiles/inspect.yaml",
        profile_state,
        staged_profile,
        STALE_PROFILE_BYTES,
    )
    _write_state(runtime / "bin/sfai.cmd", wrapper_state, staged_wrapper, STALE_WRAPPER_BYTES)

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


def test_linux_is_unsupported_with_zero_mutation(tmp_path, monkeypatch):
    # Simulate Linux explicitly so the unsupported path is exercised on every host,
    # including a real Windows runner, instead of depending on the actual platform.
    force_linux(monkeypatch)
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
    assert result["platform"]["system"] == "linux"
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
    write_exact(outside / "profiles/inspect.yaml", CANONICAL_INSPECT_PROFILE_BYTES)
    shutil.rmtree(lab.staged / "config")
    symlink_or_skip(lab.staged / "config", outside, target_is_directory=True)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("escapes the staged source root" in blocker for blocker in result["blockers"])
    assert not lab.profile_destination.exists()
    assert temp_or_backup_files(lab.runtime) == []


def test_destination_path_escape_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    outside = tmp_path / "outside-bin"
    outside.mkdir()
    write_exact(outside / "sfai.cmd", STALE_WRAPPER_BYTES)
    shutil.rmtree(lab.runtime / "bin")
    symlink_or_skip(lab.runtime / "bin", outside, target_is_directory=True)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("escapes the durable runtime root" in blocker for blocker in result["blockers"])
    assert (outside / "sfai.cmd").read_bytes() == STALE_WRAPPER_BYTES


def test_source_symlink_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    real = lab.staged / "config/profiles/inspect.real.yaml"
    write_exact(real, CANONICAL_INSPECT_PROFILE_BYTES)
    target = lab.staged / "config/profiles/inspect.yaml"
    target.unlink()
    symlink_or_skip(target, real)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("reparse point or symlink" in blocker for blocker in result["blockers"])


def test_destination_symlink_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    real = lab.runtime / "bin/sfai.real.cmd"
    write_exact(real, STALE_WRAPPER_BYTES)
    target = lab.wrapper_destination
    target.unlink()
    symlink_or_skip(target, real)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("reparse point or symlink" in blocker for blocker in result["blockers"])
    assert real.read_bytes() == STALE_WRAPPER_BYTES


def test_reparse_parent_component_blocks_without_escaping(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    real_dir = lab.staged / "scripts/real-windows"
    real_dir.mkdir()
    write_exact(real_dir / "sfai.cmd", CANONICAL_WRAPPER_BYTES)
    shutil.rmtree(lab.staged / "scripts/windows")
    symlink_or_skip(lab.staged / "scripts/windows", real_dir, target_is_directory=True)
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
    write_exact(lab.staged / "config/profiles/inspect.yaml", THIRD_PROFILE_BYTES)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("drifted from the accepted plan" in blocker for blocker in result["blockers"])
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES
    assert temp_or_backup_files(lab.runtime) == []


def test_oversized_source_blocks(tmp_path, monkeypatch):
    assert len(OVERSIZED_WRAPPER_BYTES) > wrre.MAX_SOURCE_BYTES["scripts/windows/sfai.cmd"]
    lab = make_lab(tmp_path, monkeypatch, staged_wrapper=OVERSIZED_WRAPPER_BYTES)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("maximum size" in blocker for blocker in result["blockers"])


@pytest.mark.parametrize(
    "bad_profile",
    [
        b"name: inspect\nallow_risks: [read\n",
        b"name: not-inspect\ndescription: x\n",
        b"- just\n- a\n- list\n",
        b"name: inspect\nallow_risks: [not-a-risk-tier]\n",
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
    unsafe = b"!!python/object/apply:os.system ['echo unsafe']\n"
    lab = make_lab(tmp_path, monkeypatch, staged_profile=unsafe)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("YAML" in blocker or "mapping" in blocker for blocker in result["blockers"])


def test_invalid_wrapper_semantic_markers_block(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, staged_wrapper=MARKERLESS_WRAPPER_BYTES)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("semantic markers" in blocker for blocker in result["blockers"])


def created_dirs(result: dict) -> list[str]:
    return [
        entry
        for op in result["operations"]
        for entry in (op.get("destination_parent") or {}).get("created_directories") or []
    ]


def assert_no_directory_mutation(lab: Lab, result: dict, *, expect: set[str] = frozenset()) -> None:
    """No authorized directory beyond `expect` may exist, and none may be recorded."""
    assert created_dirs(result) == []
    assert result["safety"]["parent_directory_create_executed"] is False
    for relative in ("config", "config/profiles"):
        if relative not in expect:
            assert not (lab.runtime / relative).exists(), relative


# --------------------------------------------------------------------------- #
# Exact destination-parent contract
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("wrapper_parent", ["missing", "file", "reparse"])
def test_unsafe_or_missing_bin_parent_blocks_and_creates_nothing(
    tmp_path, monkeypatch, wrapper_parent
):
    # PR313 never creates "bin". An unsafe or absent wrapper parent is a blocking
    # runtime-layout failure: the PR305 plan itself blocks, so the plan is not
    # executable and no directory is ever created.
    lab = make_lab(tmp_path, monkeypatch, wrapper_parent=wrapper_parent)
    saved_parent = lab.packet["operations"][1]["destination_parent"]
    assert saved_parent["relative_path"] == "bin"
    assert saved_parent["creation_allowed"] is False
    assert saved_parent["state"] == "blocked"
    assert saved_parent["creation_chain"] == []
    assert saved_parent["blockers"]
    assert lab.packet["status"] == "blocked"
    assert lab.packet["summary"]["parent_blocked"] == 1

    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None
    if wrapper_parent == "missing":
        assert not (lab.runtime / "bin").exists()
    assert created_dirs(result) == []
    assert result["safety"]["parent_directory_create_executed"] is False


@pytest.mark.parametrize(
    "profile_parent,expected_chain",
    [
        ("missing_all", ["config", "config/profiles"]),
        ("missing_profiles", ["config/profiles"]),
    ],
)
def test_authorized_parent_chain_is_created_exactly(
    tmp_path, monkeypatch, profile_parent, expected_chain
):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent=profile_parent,
    )
    saved = lab.packet["operations"][0]["destination_parent"]
    assert saved["state"] == "create_required"
    assert saved["creation_chain"] == expected_chain
    assert saved["relative_path"] == "config/profiles"
    assert saved["creation_allowed"] is True

    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_EXECUTED, result["blockers"]
    assert created_dirs(result) == expected_chain
    assert result["safety"]["parent_directory_create_executed"] is True
    assert result["safety"]["parent_directory_compensation_executed"] is False
    assert (lab.runtime / "config/profiles").is_dir()
    assert lab.profile_destination.read_bytes() == CANONICAL_INSPECT_PROFILE_BYTES
    assert lab.wrapper_destination.read_bytes() == CANONICAL_WRAPPER_BYTES
    # Nothing outside the exact authorized chain was created.
    assert sorted(p.name for p in lab.runtime.iterdir()) == [
        "Python314",
        "bin",
        "config",
    ]


def test_present_parent_requires_no_directory_action(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    assert lab.packet["operations"][0]["destination_parent"]["state"] == "present"
    assert lab.packet["operations"][1]["destination_parent"] == {
        "contract_version": 1,
        "relative_path": "bin",
        "state": "present",
        "creation_allowed": False,
        "creation_chain": [],
        "blockers": [],
    }
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_EXECUTED
    assert created_dirs(result) == []
    assert result["safety"]["parent_directory_create_executed"] is False


@pytest.mark.parametrize(
    "profile_parent", ["file_config", "file_profiles", "reparse_profiles"]
)
def test_hostile_parent_chain_blocks_everything(tmp_path, monkeypatch, profile_parent):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent=profile_parent,
    )
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert created_dirs(result) == []
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES
    assert temp_or_backup_files(lab.runtime) == []


def test_saved_chain_narrows_when_config_appears_safely(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    assert lab.packet["operations"][0]["destination_parent"]["creation_chain"] == [
        "config",
        "config/profiles",
    ]
    (lab.runtime / "config").mkdir()
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_EXECUTED
    parent = result["operations"][0]["destination_parent"]
    assert parent["saved_creation_chain"] == ["config", "config/profiles"]
    assert parent["revalidated_creation_chain"] == ["config/profiles"]
    assert parent["narrowed"] is True
    assert created_dirs(result) == ["config/profiles"]


def test_saved_chain_narrows_to_no_parent_action(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    (lab.runtime / "config/profiles").mkdir(parents=True)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_EXECUTED
    parent = result["operations"][0]["destination_parent"]
    assert parent["revalidated_state"] == "present"
    assert parent["narrowed"] is True
    assert created_dirs(result) == []
    assert result["safety"]["parent_directory_create_executed"] is False


def test_saved_present_parent_that_disappeared_blocks(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    shutil.rmtree(lab.runtime / "config/profiles")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("no longer a safe existing directory" in b for b in result["blockers"])
    assert created_dirs(result) == []
    assert not (lab.runtime / "config/profiles").exists()


@pytest.mark.parametrize("hostile", ["file", "reparse"])
def test_saved_create_chain_that_turned_hostile_blocks(tmp_path, monkeypatch, hostile):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    if hostile == "file":
        write_exact(lab.runtime / "config", b"hostile")
    else:
        real = tmp_path / "late-outside"
        real.mkdir()
        symlink_or_skip(lab.runtime / "config", real, target_is_directory=True)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert created_dirs(result) == []


def test_legacy_plan_without_parent_contract_is_refused(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    legacy = json.loads(json.dumps(lab.packet))
    legacy.pop("destination_parent_contract_version")
    for op in legacy["operations"]:
        op.pop("destination_parent")
    resave_packet(lab, legacy)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None
    assert any("regenerate" in blocker for blocker in result["blockers"])
    assert_no_directory_mutation(lab, result)


def test_parent_metadata_change_changes_the_confirmation_hash(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    original = lab.confirm
    mutated = json.loads(json.dumps(lab.packet))
    mutated["operations"][0]["destination_parent"]["creation_chain"] = ["config"]
    assert wrre.canonical_plan_sha256(mutated) != original


@pytest.mark.parametrize(
    "confirmation", ["", "not-a-hash", "b" * 64], ids=["missing", "malformed", "wrong"]
)
def test_unconfirmed_execution_creates_zero_directories(tmp_path, monkeypatch, confirmation):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    result = run_execute(lab, confirm_plan_sha256=confirmation)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert result["receipt_id"] is None
    assert_no_directory_mutation(lab, result)
    assert not lab.data_dir.exists()


def test_linux_unsupported_creates_zero_directories(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    force_linux(monkeypatch)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_UNSUPPORTED
    assert_no_directory_mutation(lab, result)
    assert not lab.data_dir.exists()


def test_source_drift_creates_zero_directories(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    write_exact(lab.staged / "config/profiles/inspect.yaml", THIRD_PROFILE_BYTES)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert_no_directory_mutation(lab, result)


def test_wrapper_conflict_prevents_profile_parent_creation(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    write_exact(lab.wrapper_destination, THIRD_WRAPPER_BYTES)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("third hash" in blocker for blocker in result["blockers"])
    assert_no_directory_mutation(lab, result)


def test_full_no_op_creates_zero_directories(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="match", wrapper_state="match")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_NO_CHANGE
    assert created_dirs(result) == []
    assert result["safety"]["parent_directory_create_executed"] is False
    assert temp_or_backup_files(lab.runtime) == []


def test_first_parent_creation_failure_leaves_no_mutation(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )

    def hook(phase, target):
        return "injected first-directory failure" if phase == "parent_directory" else None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert_no_directory_mutation(lab, result)
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES
    assert temp_or_backup_files(lab.runtime) == []


def test_second_parent_creation_failure_removes_the_first_directory(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )

    def hook(phase, target):
        if phase == "parent_directory" and target == "config/profiles":
            return "injected second-directory failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATED
    assert created_dirs(result) == ["config"]
    assert result["directory_compensation"]["attempted"] is True
    assert result["directory_compensation"]["complete"] is True
    assert result["directory_compensation"]["entries"][0]["result"] == "removed"
    assert not (lab.runtime / "config").exists()
    assert result["safety"]["parent_directory_create_executed"] is True
    assert result["safety"]["parent_directory_compensation_executed"] is True
    assert result["safety"]["file_create_executed"] is False


@pytest.mark.parametrize("phase", ["backup", "temp"])
def test_preparation_failure_removes_execution_created_directories(
    tmp_path, monkeypatch, phase
):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )

    def hook(injected_phase, target):
        return "injected preparation failure" if injected_phase == phase else None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATED
    assert created_dirs(result) == ["config", "config/profiles"]
    # Reverse order: the deepest directory is removed first.
    removed = [e["relative_directory"] for e in result["directory_compensation"]["entries"]]
    assert removed == ["config/profiles", "config"]
    assert not (lab.runtime / "config").exists()
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES
    assert temp_files(lab.runtime) == []


def test_commit_failure_runs_file_then_directory_compensation(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )

    def hook(phase, target):
        if phase == "commit" and target == "bin/sfai.cmd":
            return "injected second-commit failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATED
    assert result["compensation"]["attempted"] is True
    assert result["directory_compensation"]["attempted"] is True
    assert not lab.profile_destination.exists()
    assert not (lab.runtime / "config").exists()
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES


def test_pre_existing_directory_is_never_removed(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_profiles",
    )

    def hook(phase, target):
        return "injected failure" if phase == "temp" else None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATED
    assert created_dirs(result) == ["config/profiles"]
    assert not (lab.runtime / "config/profiles").exists()
    # "config" pre-existed and must survive.
    assert (lab.runtime / "config").is_dir()


def test_nonempty_execution_created_directory_is_not_removed(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )

    def hook(phase, target):
        if phase == "temp":
            write_exact(lab.runtime / "config/profiles/unrelated.txt", b"someone else")
            return "injected failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATION_INCOMPLETE
    assert result["directory_compensation"]["complete"] is False
    results = {
        e["relative_directory"]: e["result"]
        for e in result["directory_compensation"]["entries"]
    }
    assert results["config/profiles"] == "refused_not_empty"
    assert (lab.runtime / "config/profiles/unrelated.txt").is_file()
    assert result["safety"]["parent_directory_compensation_executed"] is True


def test_directory_compensation_uses_no_recursive_delete(tmp_path, monkeypatch):
    lab = make_lab(
        tmp_path,
        monkeypatch,
        profile_state="missing",
        wrapper_state="stale",
        profile_parent="missing_all",
    )
    calls: list[str] = []
    real_rmdir = os.rmdir
    monkeypatch.setattr(
        wrre.os, "rmdir", lambda path: (calls.append(str(path)), real_rmdir(path))[1]
    )
    monkeypatch.setattr(
        wrre, "shutil", None, raising=False
    )  # the module must not reach for a recursive helper

    def hook(phase, target):
        return "injected failure" if phase == "temp" else None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATED
    assert len(calls) == 2


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
    assert lab.profile_destination.read_bytes() == CANONICAL_INSPECT_PROFILE_BYTES
    assert lab.wrapper_destination.read_bytes() == CANONICAL_WRAPPER_BYTES
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
    write_exact(lab.profile_destination, CANONICAL_INSPECT_PROFILE_BYTES)
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
    write_exact(lab.profile_destination, THIRD_PROFILE_BYTES)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("conflicting destination" in blocker for blocker in result["blockers"])
    assert lab.profile_destination.read_bytes() == THIRD_PROFILE_BYTES
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES
    assert temp_or_backup_files(lab.runtime) == []
    assert result["receipt_id"] is not None


def test_planned_replace_narrowed_to_no_op_when_destination_matches(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="stale")
    write_exact(lab.profile_destination, CANONICAL_INSPECT_PROFILE_BYTES)
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
    write_exact(lab.profile_destination, THIRD_PROFILE_BYTES)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("third hash" in blocker for blocker in result["blockers"])
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES
    assert temp_or_backup_files(lab.runtime) == []


def test_planned_replace_destination_disappearance_blocks_everything(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="stale")
    lab.profile_destination.unlink()
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("disappeared" in blocker for blocker in result["blockers"])
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES


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
    write_exact(lab.profile_destination, THIRD_PROFILE_BYTES)
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("no longer matches" in blocker for blocker in result["blockers"])
    assert lab.wrapper_destination.read_bytes() == CANONICAL_WRAPPER_BYTES


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
    assert lab.profile_destination.read_bytes() == CANONICAL_INSPECT_PROFILE_BYTES
    assert len(backup_files(lab.runtime)) == 1


def test_one_no_op_plus_one_create_is_partial(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="match")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_PARTIAL_EXECUTED
    assert result["operations"][0]["revalidated_operation"] == "create_required"
    assert lab.profile_destination.read_bytes() == CANONICAL_INSPECT_PROFILE_BYTES
    assert backup_files(lab.runtime) == []


def test_successful_rerun_with_a_fresh_plan_is_idempotent(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")
    first = run_execute(lab)
    assert first["status"] == wrre.STATUS_EXECUTED
    backups_after_first = backup_files(lab.runtime)
    assert len(backups_after_first) == 1

    fresh_artifacts = [build_pr304(tmp_path, monkeypatch, lab.runtime, name="pr304-second.json")]
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
    expected = f"inspect.yaml.{wrre.BACKUP_MARKER}-{wrre._stamp(FIXED_CLOCK)}-{lab.confirm[:8]}.bak"
    squatter = lab.profile_destination.parent / expected
    write_exact(squatter, b"pre-existing backup")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_PARTIAL_EXECUTED
    assert squatter.read_bytes() == b"pre-existing backup"
    backups = [p for p in backup_files(lab.runtime) if p != squatter]
    assert len(backups) == 1
    assert backups[0].parent == lab.profile_destination.parent
    assert backups[0].name.startswith(f"inspect.yaml.{wrre.BACKUP_MARKER}-")
    assert lab.confirm[:8] in backups[0].name


def test_backup_hash_matches_the_pre_change_destination(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="stale", wrapper_state="match")
    pre_change = hashlib.sha256(STALE_PROFILE_BYTES).hexdigest()
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


def test_exclusive_write_requests_binary_mode_and_preserves_crlf_bytes(tmp_path, monkeypatch):
    # Regression: os.open defaults to text mode on Windows, where the C runtime
    # rewrites "\n" as "\r\n" on write. Without O_BINARY every backup, temporary
    # file, and restore would be silently corrupted and the durable runtime could
    # never receive the exact approved source bytes.
    captured: dict[str, int] = {}
    real_open = os.open

    def spy(path, flags, *args, **kwargs):
        captured["flags"] = flags
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(wrre.os, "open", spy)
    target = tmp_path / "exact.cmd"
    wrre._exclusive_write(target, CANONICAL_WRAPPER_BYTES)

    assert target.read_bytes() == CANONICAL_WRAPPER_BYTES
    assert b"\r\r\n" not in target.read_bytes()
    assert getattr(os, "O_BINARY", 0) == wrre._O_BINARY
    assert captured["flags"] & os.O_CREAT
    assert captured["flags"] & os.O_EXCL
    assert captured["flags"] & wrre._O_BINARY == wrre._O_BINARY
    with pytest.raises(FileExistsError):
        wrre._exclusive_write(target, CANONICAL_WRAPPER_BYTES)


def test_backup_and_committed_bytes_are_never_newline_normalized(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="match", wrapper_state="stale")
    result = run_execute(lab)
    assert result["status"] == wrre.STATUS_PARTIAL_EXECUTED
    backup = backup_files(lab.runtime)[0]
    # The replaced wrapper is CRLF; both the retained backup and the committed
    # destination must hold the exact original and source bytes.
    assert backup.read_bytes() == STALE_WRAPPER_BYTES
    assert lab.wrapper_destination.read_bytes() == CANONICAL_WRAPPER_BYTES
    assert b"\r\r\n" not in backup.read_bytes()
    assert b"\r\r\n" not in lab.wrapper_destination.read_bytes()
    wrapper_op = result["operations"][1]
    assert wrapper_op["backup_sha256"] == hashlib.sha256(STALE_WRAPPER_BYTES).hexdigest()
    assert wrapper_op["post_change_sha256"] == hashlib.sha256(CANONICAL_WRAPPER_BYTES).hexdigest()


def test_compensation_restores_exact_crlf_bytes(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")

    def hook(phase, target):
        return "injected verify failure" if phase == "verify" and target == "bin/sfai.cmd" else None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATED
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES
    assert b"\r\r\n" not in lab.wrapper_destination.read_bytes()


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
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES
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
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES
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
    assert lab.profile_destination.read_bytes() == STALE_PROFILE_BYTES
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
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES


def test_compensation_refuses_to_remove_a_drifted_created_file(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="stale")

    def hook(phase, target):
        if phase == "commit" and target == "bin/sfai.cmd":
            write_exact(lab.profile_destination, THIRD_PROFILE_BYTES)
            return "injected second-commit failure"
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_FAILED_COMPENSATION_INCOMPLETE
    assert result["compensation"]["complete"] is False
    entry = result["compensation"]["entries"][0]
    assert entry["result"] == "refused_drifted_created_file"
    assert lab.profile_destination.read_bytes() == THIRD_PROFILE_BYTES
    assert lab.wrapper_destination.read_bytes() == STALE_WRAPPER_BYTES


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
    assert lab.profile_destination.read_bytes() == CANONICAL_INSPECT_PROFILE_BYTES
    assert len(backup_files(lab.runtime)) == 1
    assert any("backups retained" in warning for warning in result["warnings"])


def test_create_refuses_when_destination_appears_between_prepare_and_commit(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch, profile_state="missing", wrapper_state="match")

    def hook(phase, target):
        if phase == "commit" and target == "config/profiles/inspect.yaml":
            write_exact(lab.profile_destination, THIRD_PROFILE_BYTES)
        return None

    result = run_execute(lab, failure_hook=hook)
    assert result["status"] == wrre.STATUS_BLOCKED
    assert any("appeared" in blocker for blocker in result["blockers"])
    assert result["mutation_performed"] is False
    assert lab.profile_destination.read_bytes() == THIRD_PROFILE_BYTES
    assert temp_files(lab.runtime) == []


# --------------------------------------------------------------------------- #
# Direct entry point behaviour
# --------------------------------------------------------------------------- #


def test_direct_helper_is_unsupported_on_linux_without_mutation(tmp_path, capsys, monkeypatch):
    force_linux(monkeypatch)
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
    assert payload["platform"]["system"] == "linux"
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
