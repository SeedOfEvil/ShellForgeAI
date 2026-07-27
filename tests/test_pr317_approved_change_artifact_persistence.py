"""Focused PR317 tests: governed atomic artifact-bundle publisher and loader.

PR316 owns the four-file contract, the canonical bytes, the manifest, the
bundle identity, and the bundle ID. These tests prove PR317 persists those
exact bytes verbatim under one fixed ShellForgeAI-owned subtree, never
overwrites, never replaces, never deletes anything it did not create, and
grants no approval, capability support, receipt linkage, or execution.
"""

from __future__ import annotations

import ast
import dataclasses
import errno
import hashlib
import inspect
import json
import os
import stat as stat_module
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

# The PR316 focused suite owns the maintained reviewed-context fixtures. They
# are reused verbatim so PR317 never invents its own bundle schema.
from test_pr316_approved_change_artifact_bundle import (  # noqa: E402
    FIXTURE_A_BUNDLE_IDENTITY_SHA256,
    FIXTURE_A_CONTEXT_SHA256,
    FIXTURE_A_EVIDENCE_SHA256,
    FIXTURE_A_FILE_SHA256,
    FIXTURE_A_FILE_SIZES,
    FIXTURE_A_SUBJECT_SHA256,
    build,
    context_alt_provenance,
    context_b,
)

from shellforgeai.core import approved_change_artifact_persistence as persistence
from shellforgeai.core.approvals import Proposal
from shellforgeai.core.approved_change_artifact_bundle import (
    APPROVED_CHANGE_SUBJECT_FILENAME,
    BUNDLE_FILE_ORDER,
    BUNDLE_FILENAMES,
    BUNDLE_ID_PREFIX,
    CONSTRUCTION_EVIDENCE_FILENAME,
    MANIFEST_FILENAME,
    SUPPLEMENTAL_CONTEXT_FILENAME,
    ApprovedChangeArtifactBundle,
    ApprovedChangeArtifactBundleFile,
    validate_approved_change_artifact_bundle,
)
from shellforgeai.core.approved_change_artifact_persistence import (
    APPROVED_CHANGE_ARTIFACTS_DIRNAME,
    CONFIRMATION_SCOPE,
    LOAD_STATUSES,
    MAX_PERSISTED_BUNDLE_FILE_BYTES,
    MAX_PERSISTED_BUNDLE_TOTAL_BYTES,
    PERMANENT_PERSISTENCE_WARNINGS,
    PUBLICATION_STATUSES,
    TEMPORARY_DIRECTORY_PREFIX,
    ApprovedChangeArtifactBundleLoadResult,
    ApprovedChangeArtifactBundlePublicationResult,
    atomic_no_replace_directory_publish,
    load_persisted_approved_change_artifact_bundle,
    publish_approved_change_artifact_bundle,
)
from shellforgeai.core.approved_change_contract import (
    ApprovalAttestation,
    ApprovedChangeContract,
)

NOT_A_HASH = "0" * 64
LINUX_ONLY = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux atomic no-replace primitive"
)
WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="Windows atomic no-replace primitive")
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX-only filesystem behaviour")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def bundle_a() -> ApprovedChangeArtifactBundle:
    result = build()
    assert result.status == "bundle_constructed"
    return result.bundle


def bundle_b() -> ApprovedChangeArtifactBundle:
    result = build(context_b())
    assert result.status == "bundle_constructed"
    return result.bundle


def data_dir(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    root.mkdir()
    return root


_EXACT = object()


def publish(bundle, root: Path, confirmation=_EXACT):
    return publish_approved_change_artifact_bundle(
        bundle,
        data_dir=root,
        confirm_bundle_identity_sha256=(
            bundle.bundle_identity_sha256 if confirmation is _EXACT else confirmation
        ),
    )


def publication_root(root: Path) -> Path:
    return root / APPROVED_CHANGE_ARTIFACTS_DIRNAME


def bundle_directory(root: Path, bundle) -> Path:
    return publication_root(root) / bundle.bundle_id


def expected_bytes(bundle) -> dict[str, bytes]:
    return {item.relative_path: item.content_utf8.encode("utf-8") for item in bundle.files}


def write_bundle_directory(root: Path, bundle, *, mutate=None) -> Path:
    """Materialise a bundle directory directly, bypassing the publisher."""
    directory = bundle_directory(root, bundle)
    directory.mkdir(parents=True)
    payload = expected_bytes(bundle)
    if mutate is not None:
        payload = mutate(dict(payload))
    for name, data in payload.items():
        (directory / name).write_bytes(data)
    return directory


class FsRecorder:
    """Record every filesystem primitive this module can reach."""

    NAMES = (
        "mkdir",
        "makedirs",
        "open",
        "scandir",
        "listdir",
        "lstat",
        "stat",
        "rmdir",
        "unlink",
        "remove",
        "rename",
        "replace",
        "fsync",
        "write",
        "read",
    )

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def touched(self, root: Path) -> list[tuple[str, str]]:
        marker = str(root)
        return [entry for entry in self.calls if marker in entry[1]]

    def creations(self, root: Path) -> list[tuple[str, str]]:
        marker = str(root)
        return [
            entry
            for entry in self.calls
            if marker in entry[1] and entry[0] in {"mkdir", "makedirs", "rename", "replace"}
        ]


@pytest.fixture
def fs_recorder(monkeypatch):
    recorder = FsRecorder()

    def wrap(name):
        original = getattr(os, name)

        def recorded(*args, **kwargs):
            first = args[0] if args else ""
            recorder.calls.append((name, str(first)))
            return original(*args, **kwargs)

        return recorded

    for name in FsRecorder.NAMES:
        if hasattr(os, name):
            monkeypatch.setattr(os, name, wrap(name))
    return recorder


@pytest.fixture
def no_replace_primitives(monkeypatch):
    """Prove no replace-capable primitive is ever reachable during publication."""

    def boom(*args, **kwargs):
        raise AssertionError("a replace-capable primitive was used")

    monkeypatch.setattr(os, "replace", boom)
    monkeypatch.setattr(os, "rename", boom)
    monkeypatch.setattr(Path, "replace", boom)
    monkeypatch.setattr(Path, "rename", boom)
    return True


def inject_failure(monkeypatch, target: str, exc: Exception | None = None):
    """Fail deterministically at one named internal publication stage."""
    failure = exc or OSError("injected failure")

    def failpoint(name: str) -> None:
        if name == target:
            raise failure

    monkeypatch.setattr(persistence, "_failpoint", failpoint)


def run_at(monkeypatch, target: str, action):
    """Run ``action`` exactly when one named internal stage is reached."""
    seen: list[str] = []

    def failpoint(name: str) -> None:
        if name == target and target not in seen:
            seen.append(target)
            action()

    monkeypatch.setattr(persistence, "_failpoint", failpoint)
    return seen


def assert_never_approves(result) -> None:
    assert result.overwrite_performed is False
    assert result.host_configuration_mutation_performed is False
    assert result.approval_created is False
    assert result.contract_created is False
    assert result.receipt_created is False
    assert result.capability_support_evaluated is False
    assert result.capability_supported is False
    assert result.approval_evaluated is False
    assert result.authorization_evaluated is False
    assert result.execution_allowed is False
    assert result.execution_available is False
    assert result.execution_status == "not_executed"
    assert result.warnings == PERMANENT_PERSISTENCE_WARNINGS
    assert "Traceback" not in " ".join(result.errors)
    assert list(result.errors) == sorted(set(result.errors))


def assert_inert(result) -> None:
    """The ledger for a result that never touched or changed the filesystem."""
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.artifact_write_performed is False
    assert result.filesystem_accessed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert_never_approves(result)


# --------------------------------------------------------------------------
# Exact successful publication
# --------------------------------------------------------------------------


def test_first_publication_writes_exactly_the_four_canonical_files(tmp_path, no_replace_primitives):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    result = publish(bundle, root)

    assert isinstance(result, ApprovedChangeArtifactBundlePublicationResult)
    assert result.status == "bundle_published"
    assert result.errors == ()
    assert result.bundle_id == bundle.bundle_id
    assert result.bundle_identity_sha256 == bundle.bundle_identity_sha256
    assert result.confirmation_matched is True
    assert result.confirmation_scope == CONFIRMATION_SCOPE
    assert result.relative_bundle_directory == (
        f"{APPROVED_CHANGE_ARTIFACTS_DIRNAME}/{bundle.bundle_id}"
    )
    assert str(tmp_path) not in result.relative_bundle_directory
    assert result.publication_root_created is True
    assert result.temporary_directory_created is True
    assert result.all_files_prepared_before_publish is True
    assert result.prepared_file_count == 4
    assert result.file_flush_status == "passed"
    assert result.atomic_publish_attempted is True
    assert result.atomic_publish_succeeded is True
    assert result.atomic_publish_outcome == "published"
    assert result.post_validation_status == "passed"
    assert result.temporary_cleanup == "not_required"
    assert result.residual_temporary_directory == ""

    directory = bundle_directory(root, bundle)
    assert directory.is_dir()
    assert sorted(item.name for item in directory.iterdir()) == sorted(BUNDLE_FILENAMES)
    for logical in bundle.files:
        stored = (directory / logical.relative_path).read_bytes()
        assert stored == logical.content_utf8.encode("utf-8")
        assert len(stored) == logical.size_bytes
        assert hashlib.sha256(stored).hexdigest() == logical.sha256
    # No temporary directory survives and nothing extra exists beside the bundle.
    assert sorted(item.name for item in publication_root(root).iterdir()) == [bundle.bundle_id]


def test_successful_publication_reports_an_accurate_mutation_ledger(tmp_path):
    root = data_dir(tmp_path)
    result = publish(bundle_a(), root)
    assert result.read_only is False
    assert result.mutation_performed is True
    assert result.artifact_write_performed is True
    assert result.filesystem_accessed is True
    assert result.publication_performed is True
    assert result.persistence_performed is True
    assert result.persisted_bundle_present is True
    assert_never_approves(result)


def test_published_bundle_reloads_and_revalidates(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)

    loaded = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert isinstance(loaded, ApprovedChangeArtifactBundleLoadResult)
    assert loaded.status == "persisted_bundle_loaded"
    assert loaded.errors == ()
    assert loaded.bundle_id == bundle.bundle_id
    assert loaded.bundle_identity_sha256 == bundle.bundle_identity_sha256
    assert loaded.bundle == bundle
    assert loaded.bundle_validation.status == "bundle_valid"
    assert validate_approved_change_artifact_bundle(loaded.bundle).bundle_valid is True
    assert loaded.read_only is True
    assert loaded.mutation_performed is False
    assert loaded.artifact_write_performed is False
    assert loaded.filesystem_accessed is True
    assert loaded.persistence_performed is False
    assert_never_approves(loaded)


def test_persisted_files_match_the_committed_fixed_fixture_reference_values(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    assert bundle.bundle_identity_sha256 == FIXTURE_A_BUNDLE_IDENTITY_SHA256
    publish(bundle, root)
    directory = bundle_directory(root, bundle)
    for name in BUNDLE_FILENAMES:
        raw = (directory / name).read_bytes()
        assert len(raw) == FIXTURE_A_FILE_SIZES[name]
        assert hashlib.sha256(raw).hexdigest() == FIXTURE_A_FILE_SHA256[name]
    manifest = json.loads((directory / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert manifest["supplemental_context_sha256"] == FIXTURE_A_CONTEXT_SHA256
    assert manifest["subject_sha256"] == FIXTURE_A_SUBJECT_SHA256
    assert manifest["construction_evidence_sha256"] == FIXTURE_A_EVIDENCE_SHA256


def test_publication_accepts_a_bundle_dictionary(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    result = publish_approved_change_artifact_bundle(
        bundle.model_dump(mode="json"),
        data_dir=root,
        confirm_bundle_identity_sha256=bundle.bundle_identity_sha256,
    )
    assert result.status == "bundle_published"
    assert bundle_directory(root, bundle).is_dir()


def test_publication_root_is_created_only_beneath_the_explicit_data_dir(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    assert sorted(item.name for item in root.iterdir()) == [APPROVED_CHANGE_ARTIFACTS_DIRNAME]
    assert sorted(item.name for item in tmp_path.iterdir()) == ["data"]


# --------------------------------------------------------------------------
# Exact binary-byte preservation
# --------------------------------------------------------------------------


def test_persisted_bytes_are_the_exact_pr316_utf8_encoding(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    directory = bundle_directory(root, bundle)
    for logical in bundle.files:
        raw = (directory / logical.relative_path).read_bytes()
        assert raw == logical.content_utf8.encode("utf-8")
        assert not raw.startswith(b"\xef\xbb\xbf")
        assert b"\r\n" not in raw
        assert not raw.endswith(b"\n")
        assert raw.decode("utf-8") == logical.content_utf8
        # No reserialization, no re-indentation, no changed Unicode escaping.
        assert json.dumps(
            json.loads(raw), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        assert b"\n  " not in raw


def test_publication_never_reserializes_or_pretty_prints(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    directory = bundle_directory(root, bundle)
    for logical in bundle.files:
        text = (directory / logical.relative_path).read_text(encoding="utf-8")
        assert text == logical.content_utf8
        assert "\n" not in text


# --------------------------------------------------------------------------
# Existing-identical idempotency
# --------------------------------------------------------------------------


def test_second_publication_of_the_same_bundle_is_already_present(tmp_path, fs_recorder):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    first = publish(bundle, root)
    assert first.status == "bundle_published"

    directory = bundle_directory(root, bundle)
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    }
    fs_recorder.calls.clear()

    second = publish(bundle, root)
    assert second.status == "bundle_already_present"
    assert second.bundle_id == bundle.bundle_id
    assert second.bundle_identity_sha256 == bundle.bundle_identity_sha256
    assert second.read_only is True
    assert second.mutation_performed is False
    assert second.artifact_write_performed is False
    assert second.filesystem_accessed is True
    assert second.publication_performed is False
    assert second.persistence_performed is False
    assert second.persisted_bundle_present is True
    assert second.temporary_directory_created is False
    assert second.publication_root_created is False
    assert second.prepared_file_count == 0
    assert second.atomic_publish_attempted is False
    assert second.temporary_cleanup == "not_required"
    assert_never_approves(second)

    # Write spies: nothing was created, renamed, or replaced.
    assert fs_recorder.creations(root) == []
    assert not [entry for entry in fs_recorder.touched(root) if entry[0] in {"write", "unlink"}]
    after = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    }
    assert after == before
    assert sorted(item.name for item in publication_root(root).iterdir()) == [bundle.bundle_id]


def test_repeated_publication_is_stable_across_many_attempts(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    assert publish(bundle, root).status == "bundle_published"
    for _ in range(3):
        assert publish(bundle, root).status == "bundle_already_present"
    assert sorted(item.name for item in publication_root(root).iterdir()) == [bundle.bundle_id]


def test_two_different_bundles_publish_side_by_side(tmp_path):
    root = data_dir(tmp_path)
    first, second = bundle_a(), bundle_b()
    assert first.bundle_id != second.bundle_id
    assert publish(first, root).status == "bundle_published"
    assert publish(second, root).status == "bundle_published"
    assert sorted(item.name for item in publication_root(root).iterdir()) == sorted(
        [first.bundle_id, second.bundle_id]
    )


# --------------------------------------------------------------------------
# Confirmation gates
# --------------------------------------------------------------------------


def confirmation_cases(bundle):
    return {
        "missing": "",
        "none": None,
        "malformed": "not-a-hash",
        "short": bundle.bundle_identity_sha256[:63],
        "long": bundle.bundle_identity_sha256 + "0",
        "uppercase": bundle.bundle_identity_sha256.upper(),
        "whitespace": f" {bundle.bundle_identity_sha256} ",
        "bundle_id": bundle.bundle_id,
        "subject_hash": FIXTURE_A_SUBJECT_SHA256,
        "context_hash": FIXTURE_A_CONTEXT_SHA256,
        "evidence_hash": FIXTURE_A_EVIDENCE_SHA256,
        "other_bundle": bundle_b().bundle_identity_sha256,
        "zeroes": NOT_A_HASH,
        "integer": 5,
    }


@pytest.mark.parametrize("case", sorted(confirmation_cases(build().bundle)))
def test_invalid_confirmation_blocks_with_zero_filesystem_access(
    case, tmp_path, fs_recorder, no_replace_primitives
):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    fs_recorder.calls.clear()
    result = publish(bundle, root, confirmation=confirmation_cases(bundle)[case])

    assert result.status == "invalid_publication_input"
    assert result.confirmation_matched is False
    assert result.errors
    assert_inert(result)
    assert fs_recorder.touched(root) == []
    assert list(root.iterdir()) == []
    assert result.publication_root_created is False
    assert result.temporary_directory_created is False


def test_exact_confirmation_is_required_and_sufficient(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    assert publish(bundle, root, confirmation=NOT_A_HASH).status == "invalid_publication_input"
    assert list(root.iterdir()) == []
    assert publish(bundle, root).status == "bundle_published"


def test_confirmation_is_never_inferred_from_the_bundle(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    signature = inspect.signature(publish_approved_change_artifact_bundle)
    parameter = signature.parameters["confirm_bundle_identity_sha256"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty
    with pytest.raises(TypeError):
        publish_approved_change_artifact_bundle(bundle, data_dir=root)  # type: ignore[call-arg]
    assert list(root.iterdir()) == []


def test_confirmation_scope_is_publication_only(tmp_path):
    root = data_dir(tmp_path)
    result = publish(bundle_a(), root)
    assert result.confirmation_scope == CONFIRMATION_SCOPE
    assert "approval" not in CONFIRMATION_SCOPE
    assert "execution" not in CONFIRMATION_SCOPE
    assert any("execution confirmation" in warning for warning in result.warnings)


# --------------------------------------------------------------------------
# Invalid bundle gates
# --------------------------------------------------------------------------


def invalid_bundles():
    valid = build().bundle
    tampered = valid.model_dump(mode="json")
    tampered["files"][0]["sha256"] = NOT_A_HASH

    stale = valid.model_dump(mode="json")
    stale["files"][3]["content_utf8"] = build(context_b()).bundle.files[3].content_utf8

    mixed = valid.model_dump(mode="json")
    other = build(context_b()).bundle
    mixed["files"][1] = other.files[1].model_dump(mode="json")

    bad_id = valid.model_dump(mode="json")
    bad_id["bundle_id"] = "acb_" + NOT_A_HASH

    bad_identity = valid.model_dump(mode="json")
    bad_identity["bundle_identity_sha256"] = NOT_A_HASH

    missing = valid.model_dump(mode="json")
    missing["files"] = missing["files"][:3]

    return {
        "none": None,
        "empty_mapping": {},
        "string": "acb_" + NOT_A_HASH,
        "list": [],
        "tampered_checksum": tampered,
        "stale_manifest": stale,
        "mixed_bundle": mixed,
        "invalid_bundle_id": bad_id,
        "invalid_bundle_identity": bad_identity,
        "missing_file": missing,
    }


@pytest.mark.parametrize("case", sorted(invalid_bundles()))
def test_invalid_bundle_blocks_with_zero_filesystem_access(case, tmp_path, fs_recorder):
    root = data_dir(tmp_path)
    candidate = invalid_bundles()[case]
    fs_recorder.calls.clear()
    result = publish_approved_change_artifact_bundle(
        candidate,
        data_dir=root,
        confirm_bundle_identity_sha256=FIXTURE_A_BUNDLE_IDENTITY_SHA256,
    )
    assert result.status == "invalid_publication_input"
    assert result.errors
    assert_inert(result)
    assert fs_recorder.touched(root) == []
    assert list(root.iterdir()) == []


def test_publisher_never_raises_for_untrusted_input(tmp_path):
    root = data_dir(tmp_path)
    for candidate in (None, {}, [], "x", 3, object(), {"files": None}):
        for confirmation in (None, "", NOT_A_HASH, "ZZ", 5):
            result = publish_approved_change_artifact_bundle(
                candidate, data_dir=root, confirm_bundle_identity_sha256=confirmation
            )
            assert isinstance(result, ApprovedChangeArtifactBundlePublicationResult)
            assert result.status == "invalid_publication_input"
    assert list(root.iterdir()) == []


# --------------------------------------------------------------------------
# Fixed-root safety
# --------------------------------------------------------------------------


def test_relative_data_dir_is_rejected_without_filesystem_access(
    tmp_path, monkeypatch, fs_recorder
):
    monkeypatch.chdir(tmp_path)
    fs_recorder.calls.clear()
    result = publish_approved_change_artifact_bundle(
        bundle_a(),
        data_dir=Path("data"),
        confirm_bundle_identity_sha256=FIXTURE_A_BUNDLE_IDENTITY_SHA256,
    )
    assert result.status == "publication_blocked"
    assert result.filesystem_accessed is False
    assert result.mutation_performed is False
    assert fs_recorder.touched(tmp_path) == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("value", ["/", os.path.abspath(os.sep)])
def test_filesystem_root_data_dir_is_rejected(value, tmp_path):
    result = publish_approved_change_artifact_bundle(
        bundle_a(),
        data_dir=value,
        confirm_bundle_identity_sha256=FIXTURE_A_BUNDLE_IDENTITY_SHA256,
    )
    assert result.status == "publication_blocked"
    assert result.mutation_performed is False
    assert any("root" in error for error in result.errors)


def test_windows_drive_root_shape_is_rejected():
    result = publish_approved_change_artifact_bundle(
        bundle_a(),
        data_dir=Path("C:\\") if os.name == "nt" else Path("/"),
        confirm_bundle_identity_sha256=FIXTURE_A_BUNDLE_IDENTITY_SHA256,
    )
    assert result.status == "publication_blocked"


def test_missing_data_dir_is_rejected(tmp_path):
    result = publish(bundle_a(), tmp_path / "absent")
    assert result.status == "publication_blocked"
    assert any("exist" in error for error in result.errors)
    assert not (tmp_path / "absent").exists()


def test_data_dir_that_is_a_file_is_rejected(tmp_path):
    target = tmp_path / "data-file"
    target.write_text("not a directory", encoding="utf-8")
    result = publish(bundle_a(), target)
    assert result.status == "publication_blocked"
    assert any("directory" in error for error in result.errors)
    assert target.read_text(encoding="utf-8") == "not a directory"


@POSIX_ONLY
def test_symlinked_data_dir_is_rejected(tmp_path):
    real = data_dir(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    result = publish(bundle_a(), link)
    assert result.status == "publication_blocked"
    assert any("symlink" in error for error in result.errors)
    assert list(real.iterdir()) == []


@POSIX_ONLY
def test_symlinked_publication_root_is_rejected(tmp_path):
    root = data_dir(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    publication_root(root).symlink_to(elsewhere, target_is_directory=True)
    result = publish(bundle_a(), root)
    assert result.status == "publication_blocked"
    assert any("symlink" in error for error in result.errors)
    assert list(elsewhere.iterdir()) == []


def test_publication_root_that_is_a_file_is_rejected(tmp_path):
    root = data_dir(tmp_path)
    publication_root(root).write_text("occupied", encoding="utf-8")
    result = publish(bundle_a(), root)
    assert result.status == "publication_blocked"
    assert publication_root(root).read_text(encoding="utf-8") == "occupied"


@POSIX_ONLY
def test_symlinked_final_bundle_directory_is_never_followed(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    publication_root(root).mkdir()
    bundle_directory(root, bundle).symlink_to(elsewhere, target_is_directory=True)
    result = publish(bundle, root)
    assert result.status == "publication_blocked"
    assert list(elsewhere.iterdir()) == []
    assert bundle_directory(root, bundle).is_symlink()


def test_publisher_accepts_no_arbitrary_destination_argument():
    signature = inspect.signature(publish_approved_change_artifact_bundle)
    assert sorted(signature.parameters) == [
        "bundle",
        "confirm_bundle_identity_sha256",
        "data_dir",
    ]
    loader = inspect.signature(load_persisted_approved_change_artifact_bundle)
    assert sorted(loader.parameters) == ["bundle_id", "data_dir"]


def test_publication_root_name_is_fixed_and_not_configurable(tmp_path):
    assert APPROVED_CHANGE_ARTIFACTS_DIRNAME == "approved_change_artifacts"
    root = data_dir(tmp_path)
    publish(bundle_a(), root)
    assert publication_root(root).is_dir()


def test_no_write_occurs_outside_the_fixed_subtree(tmp_path, fs_recorder):
    root = data_dir(tmp_path)
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    fs_recorder.calls.clear()
    publish(bundle_a(), root)
    assert fs_recorder.touched(sibling) == []
    assert list(sibling.iterdir()) == []
    for name, path in fs_recorder.creations(root):
        assert str(publication_root(root)) in path or path == str(publication_root(root)), name


# --------------------------------------------------------------------------
# Exact loader references
# --------------------------------------------------------------------------


INVALID_REFERENCES = [
    "",
    "   ",
    "latest",
    "current",
    "most recent",
    "acb_",
    "acb_" + "a" * 63,
    "acb_" + "a" * 65,
    "acb_" + "A" * 64,
    "ACB_" + "a" * 64,
    "a" * 64,
    "acb_" + "a" * 8,
    "acb_" + "g" * 64,
    " acb_" + "a" * 64,
    "acb_" + "a" * 64 + " ",
    "acb_" + "a" * 64 + "/manifest.json",
    "../acb_" + "a" * 64,
    "..",
    "/acb_" + "a" * 64,
    "C:\\acb_" + "a" * 64,
    "\\\\server\\share\\acb_" + "a" * 64,
    "acb_" + "a" * 64 + "\\manifest.json",
    "acb_" + "a" * 63 + "*",
]


@pytest.mark.parametrize("reference", INVALID_REFERENCES)
def test_loader_rejects_every_inexact_reference(reference, tmp_path):
    root = data_dir(tmp_path)
    publish(bundle_a(), root)
    result = load_persisted_approved_change_artifact_bundle(reference, data_dir=root)
    assert result.status == "invalid_persisted_bundle_reference"
    assert result.bundle is None
    assert result.filesystem_accessed is False
    assert_never_approves(result)


@pytest.mark.parametrize("reference", [None, 5, Path("x"), b"acb_", ["acb_"]])
def test_loader_rejects_non_string_references(reference, tmp_path):
    root = data_dir(tmp_path)
    result = load_persisted_approved_change_artifact_bundle(reference, data_dir=root)
    assert result.status == "invalid_persisted_bundle_reference"
    assert result.filesystem_accessed is False


def test_loader_rejects_a_prefix_of_a_published_bundle(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id[:-1], data_dir=root)
    assert result.status == "invalid_persisted_bundle_reference"


def test_loader_rejects_the_uppercase_variant_of_a_published_bundle(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id.upper(), data_dir=root)
    assert result.status == "invalid_persisted_bundle_reference"


def test_loader_reports_not_found_for_an_absent_bundle(tmp_path):
    root = data_dir(tmp_path)
    result = load_persisted_approved_change_artifact_bundle("acb_" + "a" * 64, data_dir=root)
    assert result.status == "persisted_bundle_not_found"
    assert result.bundle is None
    assert result.filesystem_accessed is True
    assert_never_approves(result)


def test_loader_rejects_an_unsafe_data_dir(tmp_path):
    result = load_persisted_approved_change_artifact_bundle(
        "acb_" + "a" * 64, data_dir=Path("relative")
    )
    assert result.status == "unsafe_persistence_root"
    assert result.filesystem_accessed is False


@POSIX_ONLY
def test_loader_rejects_a_symlinked_bundle_directory(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    other = bundle_b()
    publication_root(root).joinpath(other.bundle_id).symlink_to(
        bundle_directory(root, bundle), target_is_directory=True
    )
    result = load_persisted_approved_change_artifact_bundle(other.bundle_id, data_dir=root)
    assert result.status in {"persisted_bundle_invalid", "unsafe_persistence_root"}
    assert result.bundle is None


def test_loader_never_follows_a_path_inside_the_manifest(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    source = inspect.getsource(persistence.load_persisted_approved_change_artifact_bundle)
    assert "manifest_filename" not in source
    loaded = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert loaded.status == "persisted_bundle_loaded"


def test_loader_never_raises_for_untrusted_input(tmp_path):
    root = data_dir(tmp_path)
    for reference in (None, "", "latest", 3, object(), "acb_" + "z" * 64):
        for directory in (root, Path("relative"), "", None, 7):
            result = load_persisted_approved_change_artifact_bundle(reference, data_dir=directory)
            assert isinstance(result, ApprovedChangeArtifactBundleLoadResult)
            assert result.status in LOAD_STATUSES
            assert result.status != "persisted_bundle_loaded"


# --------------------------------------------------------------------------
# Exact file-set loading
# --------------------------------------------------------------------------


def test_loader_rejects_a_missing_file(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    directory = write_bundle_directory(root, bundle)
    (directory / MANIFEST_FILENAME).unlink()
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert any("missing" in error for error in result.errors)


def test_loader_rejects_an_extra_file(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    directory = write_bundle_directory(root, bundle)
    (directory / "extra.json").write_text("{}", encoding="utf-8")
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert any("unexpected" in error for error in result.errors)


def test_loader_rejects_a_nested_directory(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    directory = write_bundle_directory(root, bundle)
    (directory / "nested").mkdir()
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"


def test_loader_rejects_a_directory_named_like_a_bundle_file(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    directory = write_bundle_directory(root, bundle)
    (directory / MANIFEST_FILENAME).unlink()
    (directory / MANIFEST_FILENAME).mkdir()
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert any("regular file" in error for error in result.errors)


@POSIX_ONLY
def test_loader_rejects_a_symlinked_persisted_file(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    directory = write_bundle_directory(root, bundle)
    target = tmp_path / "outside.json"
    target.write_bytes((directory / MANIFEST_FILENAME).read_bytes())
    (directory / MANIFEST_FILENAME).unlink()
    (directory / MANIFEST_FILENAME).symlink_to(target)
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert any("symlink" in error for error in result.errors)


@POSIX_ONLY
def test_loader_rejects_a_fifo_in_place_of_a_persisted_file(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    directory = write_bundle_directory(root, bundle)
    (directory / MANIFEST_FILENAME).unlink()
    os.mkfifo(directory / MANIFEST_FILENAME)
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert any("regular file" in error for error in result.errors)


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda data: {**data, MANIFEST_FILENAME: b"\xff\xfe not utf-8"}, id="utf8"),
        pytest.param(
            lambda data: {
                **data,
                MANIFEST_FILENAME: b"\xef\xbb\xbf" + data[MANIFEST_FILENAME],
            },
            id="bom",
        ),
        pytest.param(
            lambda data: {
                **data,
                MANIFEST_FILENAME: data[MANIFEST_FILENAME].replace(b",", b",\r\n", 1),
            },
            id="crlf",
        ),
        pytest.param(
            lambda data: {**data, MANIFEST_FILENAME: data[MANIFEST_FILENAME] + b"\n"},
            id="trailing_newline",
        ),
        pytest.param(
            lambda data: {
                **data,
                MANIFEST_FILENAME: json.dumps(
                    json.loads(data[MANIFEST_FILENAME]), indent=2, sort_keys=True
                ).encode("utf-8"),
            },
            id="pretty_printed",
        ),
        pytest.param(
            lambda data: {**data, SUPPLEMENTAL_CONTEXT_FILENAME: b"{}"}, id="wrong_content"
        ),
        pytest.param(
            lambda data: {
                **data,
                CONSTRUCTION_EVIDENCE_FILENAME: data[APPROVED_CHANGE_SUBJECT_FILENAME],
            },
            id="mixed_roles",
        ),
    ],
)
def test_loader_rejects_noncanonical_or_mixed_stored_bytes(mutation, tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    write_bundle_directory(root, bundle, mutate=mutation)
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert result.bundle is None
    assert result.errors
    assert_never_approves(result)


def test_loader_rejects_a_bundle_stored_under_another_bundle_id(tmp_path):
    root = data_dir(tmp_path)
    first, second = bundle_a(), bundle_b()
    directory = publication_root(root) / second.bundle_id
    directory.mkdir(parents=True)
    for name, data in expected_bytes(first).items():
        (directory / name).write_bytes(data)
    result = load_persisted_approved_change_artifact_bundle(second.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert result.bundle is None


# --------------------------------------------------------------------------
# Read bounds
# --------------------------------------------------------------------------


def test_documented_read_bounds_are_conservative_constants():
    assert MAX_PERSISTED_BUNDLE_FILE_BYTES == 1_048_576
    assert MAX_PERSISTED_BUNDLE_TOTAL_BYTES == 4_194_304
    assert MAX_PERSISTED_BUNDLE_TOTAL_BYTES == 4 * MAX_PERSISTED_BUNDLE_FILE_BYTES


def test_exact_boundary_file_is_accepted(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    write_bundle_directory(root, bundle)
    largest = max(FIXTURE_A_FILE_SIZES.values())
    monkeypatch.setattr(persistence, "MAX_PERSISTED_BUNDLE_FILE_BYTES", largest)
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_loaded"


def test_one_byte_over_the_per_file_limit_is_rejected(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    write_bundle_directory(root, bundle)
    largest = max(FIXTURE_A_FILE_SIZES.values())
    monkeypatch.setattr(persistence, "MAX_PERSISTED_BUNDLE_FILE_BYTES", largest - 1)
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert any("per-file limit" in error for error in result.errors)


def test_exact_boundary_total_is_accepted(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    write_bundle_directory(root, bundle)
    total = sum(FIXTURE_A_FILE_SIZES.values())
    monkeypatch.setattr(persistence, "MAX_PERSISTED_BUNDLE_TOTAL_BYTES", total)
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_loaded"
    assert result.total_bytes_read == total


def test_one_byte_over_the_total_limit_is_rejected(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    write_bundle_directory(root, bundle)
    total = sum(FIXTURE_A_FILE_SIZES.values())
    monkeypatch.setattr(persistence, "MAX_PERSISTED_BUNDLE_TOTAL_BYTES", total - 1)
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert any("total limit" in error for error in result.errors)


def test_oversized_persisted_file_is_rejected_before_it_is_read(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    directory = write_bundle_directory(root, bundle)
    monkeypatch.setattr(persistence, "MAX_PERSISTED_BUNDLE_FILE_BYTES", 32)
    reads: list[str] = []
    original = persistence._read_bounded
    monkeypatch.setattr(
        persistence,
        "_read_bounded",
        lambda path, size: (reads.append(path.name), original(path, size))[1],
    )
    result = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert result.status == "persisted_bundle_invalid"
    assert reads == []
    assert directory.is_dir()


def test_bounded_read_fails_closed_on_truncation(tmp_path):
    target = tmp_path / "payload"
    target.write_bytes(b"abcd")
    with pytest.raises(OSError):
        persistence._read_bounded(target, 8)


def test_bounded_read_fails_closed_when_the_file_grew(tmp_path):
    target = tmp_path / "payload"
    target.write_bytes(b"abcdefgh")
    with pytest.raises(OSError):
        persistence._read_bounded(target, 4)


def test_bounded_read_fails_closed_when_size_changes_between_stat_and_read(tmp_path, monkeypatch):
    target = tmp_path / "payload"
    target.write_bytes(b"abcd")
    real_fstat = os.fstat
    calls: list[int] = []

    def drifting_fstat(fd):
        info = real_fstat(fd)
        calls.append(fd)
        if len(calls) > 1:
            return os.stat_result(
                (
                    info.st_mode,
                    info.st_ino,
                    info.st_dev,
                    info.st_nlink,
                    info.st_uid,
                    info.st_gid,
                    info.st_size + 1,
                    info.st_atime,
                    info.st_mtime,
                    info.st_ctime,
                )
            )
        return info

    monkeypatch.setattr(os, "fstat", drifting_fstat)
    with pytest.raises(OSError):
        persistence._read_bounded(target, 4)


@POSIX_ONLY
def test_bounded_read_refuses_a_non_regular_file(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(OSError):
        persistence._read_bounded(fifo, 1)


# --------------------------------------------------------------------------
# Atomic no-replace behaviour
# --------------------------------------------------------------------------


def test_final_directory_is_absent_throughout_preparation(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    final = bundle_directory(root, bundle)
    observations: list[tuple[str, bool]] = []

    def failpoint(name: str) -> None:
        observations.append((name, final.exists()))

    monkeypatch.setattr(persistence, "_failpoint", failpoint)
    result = publish(bundle, root)
    assert result.status == "bundle_published"
    assert [name for name, _ in observations][-4:] == [
        "atomic_publish",
        "publication_root_flush",
        "post_publication_load",
        "post_publication_validate",
    ]
    # Every stage up to and including the single commit sees no final directory.
    commit = [name for name, _ in observations].index("atomic_publish")
    assert [exists for _, exists in observations[: commit + 1]] == [False] * (commit + 1)
    assert all(exists for _, exists in observations[commit + 1 :])


def test_temporary_directory_is_a_private_sibling_of_the_final_directory(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    seen: list[Path] = []

    def failpoint(name: str) -> None:
        if name == "temporary_directory_flush":
            seen.extend(publication_root(root).iterdir())

    monkeypatch.setattr(persistence, "_failpoint", failpoint)
    assert publish(bundle, root).status == "bundle_published"
    assert len(seen) == 1
    temporary = seen[0]
    assert temporary.parent == publication_root(root)
    assert temporary.parent == bundle_directory(root, bundle).parent
    assert temporary.name.startswith(TEMPORARY_DIRECTORY_PREFIX)
    assert temporary.name != bundle.bundle_id
    # The pending name carries no bundle ID and no semantic identity.
    assert bundle.bundle_id not in temporary.name
    assert bundle.bundle_identity_sha256 not in temporary.name
    assert len(temporary.name) == persistence.TEMPORARY_DIRECTORY_NAME_LENGTH


def test_temporary_nonce_never_reaches_the_published_bundle(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    monkeypatch.setattr(persistence, "_temporary_nonce", lambda: "deadbeef" * 4)
    result = publish(bundle, root)
    assert result.status == "bundle_published"
    directory = bundle_directory(root, bundle)
    assert "deadbeef" not in result.relative_bundle_directory
    assert "deadbeef" not in result.bundle_id
    assert "deadbeef" not in result.bundle_identity_sha256
    for name in BUNDLE_FILENAMES:
        assert b"deadbeef" not in (directory / name).read_bytes()
    # A second publication with a different nonce still yields the same identity.
    other = bundle_b()
    monkeypatch.setattr(persistence, "_temporary_nonce", lambda: "cafebabe" * 4)
    second = publish(other, root)
    assert second.status == "bundle_published"
    assert second.bundle_identity_sha256 == other.bundle_identity_sha256


def test_all_four_files_are_verified_before_the_single_commit(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    prepared: list[list[str]] = []

    def failpoint(name: str) -> None:
        if name == "atomic_publish":
            temporary = next(
                item
                for item in publication_root(root).iterdir()
                if item.name.startswith(TEMPORARY_DIRECTORY_PREFIX)
            )
            prepared.append(sorted(item.name for item in temporary.iterdir()))

    monkeypatch.setattr(persistence, "_failpoint", failpoint)
    result = publish(bundle, root)
    assert result.status == "bundle_published"
    assert prepared == [sorted(BUNDLE_FILENAMES)]
    assert result.all_files_prepared_before_publish is True
    assert result.prepared_file_count == 4


def test_exactly_one_final_directory_transition_occurs(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    calls: list[tuple[Path, Path]] = []
    real = persistence.atomic_no_replace_directory_publish

    def counted(source, destination):
        calls.append((source, destination))
        return real(source, destination)

    monkeypatch.setattr(persistence, "atomic_no_replace_directory_publish", counted)
    assert publish(bundle, root).status == "bundle_published"
    assert len(calls) == 1
    assert calls[0][1] == bundle_directory(root, bundle)


def test_publication_never_uses_a_replace_capable_primitive(tmp_path, no_replace_primitives):
    root = data_dir(tmp_path)
    assert publish(bundle_a(), root).status == "bundle_published"


# --------------------------------------------------------------------------
# Platform primitive behaviour
# --------------------------------------------------------------------------


def test_atomic_helper_publishes_only_when_the_destination_is_absent(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload").write_text("x", encoding="utf-8")
    destination = tmp_path / "destination"
    outcome = atomic_no_replace_directory_publish(source, destination)
    assert outcome.outcome == "published"
    assert destination.is_dir()
    assert not source.exists()
    assert (destination / "payload").read_text(encoding="utf-8") == "x"


@pytest.mark.parametrize("kind", ["empty_directory", "populated_directory", "file"])
def test_atomic_helper_never_replaces_an_existing_destination(kind, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload").write_text("new", encoding="utf-8")
    destination = tmp_path / "destination"
    if kind == "file":
        destination.write_text("existing", encoding="utf-8")
    else:
        destination.mkdir()
        if kind == "populated_directory":
            (destination / "payload").write_text("existing", encoding="utf-8")

    outcome = atomic_no_replace_directory_publish(source, destination)
    assert outcome.outcome == "destination_exists"
    assert source.is_dir()
    assert (source / "payload").read_text(encoding="utf-8") == "new"
    if kind == "file":
        assert destination.read_text(encoding="utf-8") == "existing"
    elif kind == "populated_directory":
        assert (destination / "payload").read_text(encoding="utf-8") == "existing"
    else:
        assert list(destination.iterdir()) == []


def test_atomic_helper_rejects_cross_parent_use(tmp_path):
    source = tmp_path / "a" / "source"
    source.mkdir(parents=True)
    destination = tmp_path / "b" / "destination"
    destination.parent.mkdir()
    outcome = atomic_no_replace_directory_publish(source, destination)
    assert outcome.outcome == "rejected"
    assert source.is_dir()
    assert not destination.exists()


@pytest.mark.parametrize(
    "source,destination",
    [
        ("relative", "other"),
        (None, None),
    ],
)
def test_atomic_helper_rejects_unvalidated_paths(source, destination, tmp_path):
    left = Path(source) if isinstance(source, str) else source
    right = Path(destination) if isinstance(destination, str) else destination
    outcome = atomic_no_replace_directory_publish(left, right)
    assert outcome.outcome == "rejected"


def test_atomic_helper_rejects_an_identical_source_and_destination(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    assert atomic_no_replace_directory_publish(source, source).outcome == "rejected"


def test_atomic_helper_rejects_a_missing_source(tmp_path):
    outcome = atomic_no_replace_directory_publish(tmp_path / "absent", tmp_path / "destination")
    assert outcome.outcome == "rejected"


def test_atomic_helper_rejects_a_file_source(tmp_path):
    source = tmp_path / "source"
    source.write_text("x", encoding="utf-8")
    outcome = atomic_no_replace_directory_publish(source, tmp_path / "destination")
    assert outcome.outcome == "rejected"


@POSIX_ONLY
def test_atomic_helper_rejects_a_symlinked_source(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    source = tmp_path / "source"
    source.symlink_to(real, target_is_directory=True)
    outcome = atomic_no_replace_directory_publish(source, tmp_path / "destination")
    assert outcome.outcome == "rejected"
    assert real.is_dir()


def test_unsupported_platform_reports_without_any_fallback(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "destination"
    monkeypatch.setattr(persistence.sys, "platform", "sunos5")
    monkeypatch.setattr(persistence.os, "name", "posix")
    outcome = atomic_no_replace_directory_publish(source, destination)
    assert outcome.outcome == "unsupported"
    assert source.is_dir()
    assert not destination.exists()


def test_publication_fails_closed_when_no_atomic_primitive_exists(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    monkeypatch.setattr(
        persistence,
        "atomic_no_replace_directory_publish",
        lambda source, destination: persistence.AtomicNoReplaceOutcome(
            "unsupported", "none", "no primitive"
        ),
    )
    result = publish(bundle, root)
    assert result.status == "atomic_publication_unsupported"
    assert result.atomic_publish_attempted is True
    assert result.atomic_publish_succeeded is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.mutation_performed is True
    assert result.artifact_write_performed is True
    assert result.temporary_cleanup == "completed"
    assert not bundle_directory(root, bundle).exists()
    assert list(root.iterdir()) == []
    assert_never_approves(result)


@LINUX_ONLY
def test_linux_renameat2_primitive_publishes_and_refuses(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "destination"
    first = persistence._linux_renameat2_no_replace(source, destination)
    assert first.outcome == "published"
    assert first.platform_primitive == "linux_renameat2_no_replace"
    source.mkdir()
    second = persistence._linux_renameat2_no_replace(source, destination)
    assert second.outcome == "destination_exists"
    assert source.is_dir()
    assert destination.is_dir()


@LINUX_ONLY
def test_linux_primitive_is_selected_on_linux(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outcome = atomic_no_replace_directory_publish(source, tmp_path / "destination")
    assert outcome.platform_primitive == "linux_renameat2_no_replace"


@WINDOWS_ONLY
def test_windows_move_primitive_publishes_and_refuses(tmp_path):  # pragma: no cover - Windows lane
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "destination"
    first = persistence._windows_move_file_no_replace(source, destination)
    assert first.outcome == "published"
    assert first.platform_primitive == "windows_movefileexw_no_replace"
    source.mkdir()
    second = persistence._windows_move_file_no_replace(source, destination)
    assert second.outcome == "destination_exists"
    assert source.is_dir()
    assert destination.is_dir()


@WINDOWS_ONLY
def test_windows_primitive_is_selected_on_windows(tmp_path):  # pragma: no cover - Windows lane
    source = tmp_path / "source"
    source.mkdir()
    outcome = atomic_no_replace_directory_publish(source, tmp_path / "destination")
    assert outcome.platform_primitive == "windows_movefileexw_no_replace"


def test_both_platform_implementations_are_defined():
    assert callable(persistence._linux_renameat2_no_replace)
    assert callable(persistence._windows_move_file_no_replace)
    assert persistence._RENAME_NOREPLACE == 1
    assert persistence._MOVEFILE_NO_FLAGS == 0


# --------------------------------------------------------------------------
# Destination-appeared race
# --------------------------------------------------------------------------


def race_destination(root: Path, bundle, kind: str):
    directory = bundle_directory(root, bundle)

    def create():
        if kind == "identical":
            payload = expected_bytes(bundle)
        elif kind == "conflicting":
            payload = expected_bytes(bundle_b())
        elif kind == "invalid":
            payload = {name: b"{}" for name in BUNDLE_FILENAMES}
        else:
            payload = {}
        directory.mkdir(parents=True, exist_ok=True)
        for name, data in payload.items():
            (directory / name).write_bytes(data)

    return create


@pytest.mark.parametrize("kind", ["identical", "conflicting", "invalid", "empty"])
@pytest.mark.parametrize("stage", ["temporary_directory_flush", "atomic_publish"])
def test_destination_appearing_before_commit_never_replaces_anything(
    kind, stage, tmp_path, monkeypatch
):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publication_root(root).mkdir()
    run_at(monkeypatch, stage, race_destination(root, bundle, kind))

    result = publish(bundle, root)
    directory = bundle_directory(root, bundle)
    assert directory.is_dir()

    if kind == "identical":
        assert result.status == "bundle_already_present"
        assert result.persisted_bundle_present is True
        for logical in bundle.files:
            assert (directory / logical.relative_path).read_bytes() == logical.content_utf8.encode(
                "utf-8"
            )
    else:
        assert result.status == "publication_blocked"
        assert result.persisted_bundle_present is False

    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.overwrite_performed is False
    # The invocation wrote only its own temporary files, then removed them.
    assert result.mutation_performed is True
    assert result.artifact_write_performed is True
    assert result.temporary_cleanup == "completed"
    assert result.temporary_cleanup_performed is True
    assert result.residual_temporary_directory == ""
    assert sorted(item.name for item in publication_root(root).iterdir()) == [bundle.bundle_id]
    if stage == "atomic_publish":
        assert result.atomic_publish_attempted is True
        assert result.atomic_publish_outcome == "destination_exists"
    assert result.atomic_publish_succeeded is False
    assert_never_approves(result)


def test_destination_that_appeared_is_never_removed_or_renamed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publication_root(root).mkdir()
    run_at(monkeypatch, "atomic_publish", race_destination(root, bundle, "invalid"))
    result = publish(bundle, root)
    assert result.status == "publication_blocked"
    directory = bundle_directory(root, bundle)
    assert sorted(item.name for item in directory.iterdir()) == sorted(BUNDLE_FILENAMES)
    for name in BUNDLE_FILENAMES:
        assert (directory / name).read_bytes() == b"{}"


# --------------------------------------------------------------------------
# Existing destination (pre-existing, not a race)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind",
    ["empty", "invalid", "conflicting", "missing_file", "extra_file", "tampered_bytes"],
)
def test_conflicting_existing_directory_blocks_without_writing(kind, tmp_path, fs_recorder):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    directory = bundle_directory(root, bundle)
    directory.mkdir(parents=True)
    if kind == "invalid":
        for name in BUNDLE_FILENAMES:
            (directory / name).write_bytes(b"{}")
    elif kind == "conflicting":
        for name, data in expected_bytes(bundle_b()).items():
            (directory / name).write_bytes(data)
    elif kind in {"missing_file", "extra_file", "tampered_bytes"}:
        for name, data in expected_bytes(bundle).items():
            (directory / name).write_bytes(data)
        if kind == "missing_file":
            (directory / MANIFEST_FILENAME).unlink()
        elif kind == "extra_file":
            (directory / "extra.txt").write_text("x", encoding="utf-8")
        else:
            (directory / SUPPLEMENTAL_CONTEXT_FILENAME).write_bytes(b"{}")

    before = sorted((path.name, path.read_bytes()) for path in directory.iterdir())
    fs_recorder.calls.clear()

    result = publish(bundle, root)
    assert result.status == "publication_blocked"
    assert result.overwrite_performed is False
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.read_only is True
    assert result.mutation_performed is False
    assert result.artifact_write_performed is False
    assert result.temporary_directory_created is False
    assert_never_approves(result)

    # The existing directory was neither repaired, replaced, renamed, nor deleted.
    assert sorted((path.name, path.read_bytes()) for path in directory.iterdir()) == before
    assert fs_recorder.creations(root) == []
    assert sorted(item.name for item in publication_root(root).iterdir()) == [bundle.bundle_id]


def test_existing_identical_directory_written_by_hand_is_already_present(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    write_bundle_directory(root, bundle)
    result = publish(bundle, root)
    assert result.status == "bundle_already_present"
    assert result.read_only is True
    assert result.post_validation_status == "passed"


# --------------------------------------------------------------------------
# Preparation failures
# --------------------------------------------------------------------------


PRECOMMIT_STAGES = [
    "publication_root_create",
    "temporary_directory_create",
    "file_create:1",
    "file_create:2",
    "file_create:3",
    "file_create:4",
    "write",
    "file_flush",
    "file_hash_verify",
    "prepared_bundle_reconstruct",
    "prepared_bundle_validate",
    "temporary_directory_flush",
    "atomic_publish",
]


#: ``publication_root_create`` can only fire when the root does not yet exist,
#: so it is covered by its own dedicated test rather than the pre-existing-content
#: parametrization below.
PRECOMMIT_STAGES_WITH_EXISTING_CONTENT = [
    stage for stage in PRECOMMIT_STAGES if stage != "publication_root_create"
]


@pytest.mark.parametrize("stage", PRECOMMIT_STAGES_WITH_EXISTING_CONTENT)
def test_every_precommit_failure_leaves_no_published_bundle(stage, tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    preexisting = bundle_b()
    write_bundle_directory(root, preexisting)
    untouched = sorted(
        (path.name, path.read_bytes()) for path in bundle_directory(root, preexisting).iterdir()
    )

    inject_failure(monkeypatch, stage)
    result = publish(bundle, root)

    assert result.status == "publication_failed_precommit"
    assert result.errors
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.atomic_publish_succeeded is False
    assert result.post_validation_status == "not_attempted"
    assert result.overwrite_performed is False
    assert not bundle_directory(root, bundle).exists()
    assert result.temporary_cleanup in {"not_required", "completed"}
    assert result.residual_temporary_directory == ""
    assert_never_approves(result)

    # No pre-existing content changed, and no temporary directory survives.
    assert (
        sorted(
            (path.name, path.read_bytes()) for path in bundle_directory(root, preexisting).iterdir()
        )
        == untouched
    )
    assert sorted(item.name for item in publication_root(root).iterdir()) == [preexisting.bundle_id]


@pytest.mark.parametrize("stage", PRECOMMIT_STAGES)
def test_precommit_failure_reports_an_accurate_mutation_ledger(stage, tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    inject_failure(monkeypatch, stage)
    result = publish(bundle_a(), root)
    assert result.filesystem_accessed is True
    wrote_something = stage not in {"publication_root_create", "temporary_directory_create"}
    if wrote_something:
        # A temporary write followed by cleanup is still a filesystem mutation.
        assert result.read_only is False
        assert result.mutation_performed is True
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.overwrite_performed is False


def test_publication_root_creation_failure_creates_nothing(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    inject_failure(monkeypatch, "publication_root_create")
    result = publish(bundle_a(), root)
    assert result.status == "publication_failed_precommit"
    assert result.publication_root_created is False
    assert result.temporary_directory_created is False
    assert result.artifact_write_performed is False
    assert list(root.iterdir()) == []


def test_temporary_directory_creation_failure_removes_the_root_it_created(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    inject_failure(monkeypatch, "temporary_directory_create")
    result = publish(bundle_a(), root)
    assert result.status == "publication_failed_precommit"
    assert result.publication_root_created is True
    assert result.temporary_directory_created is False
    assert list(root.iterdir()) == []


def test_a_preexisting_publication_root_is_never_removed(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    publication_root(root).mkdir()
    inject_failure(monkeypatch, "temporary_directory_create")
    result = publish(bundle_a(), root)
    assert result.status == "publication_failed_precommit"
    assert result.publication_root_created is False
    assert publication_root(root).is_dir()


@pytest.mark.parametrize("index", [1, 2, 3, 4])
def test_each_file_creation_failure_cleans_up_only_its_own_files(index, tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    inject_failure(monkeypatch, f"file_create:{index}")
    result = publish(bundle_a(), root)
    assert result.status == "publication_failed_precommit"
    assert result.prepared_file_count == index - 1
    assert result.all_files_prepared_before_publish is False
    assert list(root.iterdir()) == []


def test_file_flush_failure_blocks_the_commit(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    inject_failure(monkeypatch, "file_flush")
    result = publish(bundle, root)
    assert result.status == "publication_failed_precommit"
    assert result.file_flush_status == "failed"
    assert result.atomic_publish_attempted is False
    assert not bundle_directory(root, bundle).exists()


def test_prepared_bundle_validation_failure_blocks_the_commit(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    monkeypatch.setattr(
        persistence,
        "validate_approved_change_artifact_bundle",
        _validator_that_fails_on_second_call(),
    )
    result = publish(bundle, root)
    assert result.status == "publication_failed_precommit"
    assert result.atomic_publish_attempted is False
    assert not bundle_directory(root, bundle).exists()
    assert list(root.iterdir()) == []


def _validator_that_fails_on_second_call():
    real = validate_approved_change_artifact_bundle
    seen: list[int] = []

    def validator(candidate):
        seen.append(1)
        result = real(candidate)
        if len(seen) == 1:
            return result
        return result.model_copy(
            update={
                "status": "bundle_invalid",
                "bundle_valid": False,
                "errors": ("injected prepared-bundle validation failure",),
            }
        )

    return validator


# --------------------------------------------------------------------------
# Cleanup safety
# --------------------------------------------------------------------------


def test_normal_cleanup_removes_only_the_invocation_temporary_directory(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    inject_failure(monkeypatch, "temporary_directory_flush")
    result = publish(bundle_a(), root)
    assert result.temporary_cleanup == "completed"
    assert result.temporary_cleanup_performed is True
    assert result.residual_temporary_directory == ""
    assert list(root.iterdir()) == []


def test_an_unexpected_extra_entry_is_preserved_and_cleanup_is_incomplete(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()

    def intrude():
        temporary = next(
            item
            for item in publication_root(root).iterdir()
            if item.name.startswith(TEMPORARY_DIRECTORY_PREFIX)
        )
        (temporary / "intruder.txt").write_text("not ours", encoding="utf-8")

    seen: list[str] = []

    def failpoint(name: str) -> None:
        if name == "temporary_directory_flush" and not seen:
            seen.append(name)
            intrude()
            raise OSError("injected failure")

    monkeypatch.setattr(persistence, "_failpoint", failpoint)
    result = publish(bundle, root)

    assert result.status == "publication_failed_cleanup_incomplete"
    assert result.temporary_cleanup == "incomplete"
    assert result.temporary_cleanup_performed is False
    assert result.residual_temporary_directory.startswith(TEMPORARY_DIRECTORY_PREFIX)
    assert str(tmp_path) not in result.residual_temporary_directory
    assert result.publication_performed is False
    assert not bundle_directory(root, bundle).exists()

    temporary = publication_root(root) / result.residual_temporary_directory
    assert temporary.is_dir()
    assert sorted(item.name for item in temporary.iterdir()) == ["intruder.txt"]
    assert (temporary / "intruder.txt").read_text(encoding="utf-8") == "not ours"
    assert any("preserved" in error for error in result.errors)


def test_cleanup_refuses_a_temporary_path_that_is_no_longer_a_directory(tmp_path):
    root = data_dir(tmp_path)
    publication_root(root).mkdir()
    temporary = publication_root(root) / f"{TEMPORARY_DIRECTORY_PREFIX}x"
    temporary.write_text("not a directory", encoding="utf-8")
    state = persistence._PublicationState(
        temporary_directory=temporary, temporary_directory_created=True
    )
    status, errors = persistence._cleanup_temporary_directory(state)
    assert status == "incomplete"
    assert errors
    assert temporary.read_text(encoding="utf-8") == "not a directory"


@POSIX_ONLY
def test_cleanup_refuses_a_temporary_directory_that_became_a_symlink(tmp_path):
    root = data_dir(tmp_path)
    publication_root(root).mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("keep", encoding="utf-8")
    temporary = publication_root(root) / f"{TEMPORARY_DIRECTORY_PREFIX}x"
    temporary.symlink_to(elsewhere, target_is_directory=True)
    state = persistence._PublicationState(
        temporary_directory=temporary, temporary_directory_created=True
    )
    status, errors = persistence._cleanup_temporary_directory(state)
    assert status == "incomplete"
    assert errors
    assert (elsewhere / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_cleanup_refuses_a_tracked_file_outside_the_temporary_directory(tmp_path):
    root = data_dir(tmp_path)
    publication_root(root).mkdir()
    temporary = publication_root(root) / f"{TEMPORARY_DIRECTORY_PREFIX}x"
    temporary.mkdir()
    outsider = root / "outsider.txt"
    outsider.write_text("keep", encoding="utf-8")
    state = persistence._PublicationState(
        temporary_directory=temporary,
        temporary_directory_created=True,
        created_files=[outsider],
    )
    status, errors = persistence._cleanup_temporary_directory(state)
    assert status == "incomplete"
    assert any("no longer belongs" in error for error in errors)
    assert outsider.read_text(encoding="utf-8") == "keep"


def test_cleanup_is_a_noop_when_no_temporary_directory_was_created():
    state = persistence._PublicationState()
    assert persistence._cleanup_temporary_directory(state) == ("not_required", [])


def test_publication_root_cleanup_only_removes_an_invocation_created_empty_root(tmp_path):
    root = data_dir(tmp_path)
    created = publication_root(root)
    created.mkdir()
    (created / "unrelated").write_text("keep", encoding="utf-8")
    state = persistence._PublicationState(publication_root_created=True)
    persistence._cleanup_publication_root(created, root, state)
    assert created.is_dir()
    assert (created / "unrelated").read_text(encoding="utf-8") == "keep"

    (created / "unrelated").unlink()
    persistence._cleanup_publication_root(created, root, state)
    assert not created.exists()


def test_publication_root_cleanup_never_touches_a_preexisting_root(tmp_path):
    root = data_dir(tmp_path)
    existing = publication_root(root)
    existing.mkdir()
    state = persistence._PublicationState(publication_root_created=False)
    persistence._cleanup_publication_root(existing, root, state)
    assert existing.is_dir()


def test_no_publication_occurs_after_incomplete_cleanup(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()

    def failpoint(name: str) -> None:
        if name == "temporary_directory_flush":
            temporary = next(
                item
                for item in publication_root(root).iterdir()
                if item.name.startswith(TEMPORARY_DIRECTORY_PREFIX)
            )
            (temporary / "intruder.txt").write_text("x", encoding="utf-8")
            raise OSError("injected failure")

    monkeypatch.setattr(persistence, "_failpoint", failpoint)
    result = publish(bundle, root)
    assert result.status == "publication_failed_cleanup_incomplete"
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert not bundle_directory(root, bundle).exists()


def test_cleanup_never_uses_generic_recursive_deletion():
    source = module_code_without_strings()
    for token in ("shutil", "rmtree", "os.walk", "rglob", "iterdir"):
        assert token not in source, token


# --------------------------------------------------------------------------
# Post-publication verification failure
# --------------------------------------------------------------------------


@pytest.mark.parametrize("stage", ["post_publication_load", "post_publication_validate"])
def test_post_publication_failure_retains_the_published_bundle(stage, tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    inject_failure(monkeypatch, stage)
    result = publish(bundle, root)

    assert result.status == "published_verification_failed"
    assert result.atomic_publish_succeeded is True
    assert result.publication_performed is True
    assert result.persistence_performed is True
    assert result.persisted_bundle_present is True
    assert result.mutation_performed is True
    assert result.artifact_write_performed is True
    assert result.read_only is False
    assert result.post_validation_status == "failed"
    assert result.errors
    assert_never_approves(result)

    # The published bundle is retained for operator investigation.
    directory = bundle_directory(root, bundle)
    assert directory.is_dir()
    assert sorted(item.name for item in directory.iterdir()) == sorted(BUNDLE_FILENAMES)
    for logical in bundle.files:
        assert (directory / logical.relative_path).read_bytes() == logical.content_utf8.encode(
            "utf-8"
        )


def test_post_publication_load_returning_invalid_is_reported_truthfully(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    real = persistence.load_persisted_approved_change_artifact_bundle

    def loader(bundle_id, *, data_dir):
        result = real(bundle_id, data_dir=data_dir)
        return result.model_copy(
            update={"status": "persisted_bundle_invalid", "bundle": None, "errors": ("injected",)}
        )

    monkeypatch.setattr(persistence, "load_persisted_approved_change_artifact_bundle", loader)
    result = publish(bundle, root)
    assert result.status == "published_verification_failed"
    assert bundle_directory(root, bundle).is_dir()
    assert result.publication_performed is True


def test_no_rollback_to_absence_after_publication(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    removals: list[str] = []
    real_rmdir, real_unlink = os.rmdir, os.unlink
    monkeypatch.setattr(os, "rmdir", lambda p: (removals.append(str(p)), real_rmdir(p))[1])
    monkeypatch.setattr(os, "unlink", lambda p: (removals.append(str(p)), real_unlink(p))[1])
    inject_failure(monkeypatch, "post_publication_load")
    publish(bundle, root)
    directory = bundle_directory(root, bundle)
    assert directory.is_dir()
    assert not [item for item in removals if str(directory) in item]


# --------------------------------------------------------------------------
# Flush behaviour
# --------------------------------------------------------------------------


def test_file_and_directory_flush_success_is_reported(tmp_path):
    root = data_dir(tmp_path)
    result = publish(bundle_a(), root)
    assert result.file_flush_status == "passed"
    if os.name == "nt":  # pragma: no cover - Windows lane
        assert result.temporary_directory_flush_status == "unsupported"
        assert result.publication_root_flush_status == "unsupported"
    else:
        assert result.temporary_directory_flush_status == "passed"
        assert result.publication_root_flush_status == "passed"


def test_directory_flush_unsupported_is_reported_without_inventing_success(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    monkeypatch.setattr(
        persistence, "_fsync_directory", lambda path: ("unsupported", "no primitive")
    )
    result = publish(bundle_a(), root)
    assert result.status == "bundle_published"
    assert result.temporary_directory_flush_status == "unsupported"
    assert result.publication_root_flush_status == "unsupported"


def test_directory_flush_failure_blocks_the_commit(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    monkeypatch.setattr(persistence, "_fsync_directory", lambda path: ("failed", "flush failed"))
    result = publish(bundle, root)
    assert result.status == "publication_failed_precommit"
    assert result.temporary_directory_flush_status == "failed"
    assert not bundle_directory(root, bundle).exists()


def test_post_commit_root_flush_failure_does_not_delete_the_bundle(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    calls: list[Path] = []
    real = persistence._fsync_directory

    def flusher(path):
        calls.append(path)
        if len(calls) > 1:
            return "failed", "post-commit flush failed"
        return real(path)

    monkeypatch.setattr(persistence, "_fsync_directory", flusher)
    result = publish(bundle, root)
    assert result.publication_root_flush_status == "failed"
    assert result.publication_performed is True
    assert result.persistence_performed is True
    assert bundle_directory(root, bundle).is_dir()
    assert any("durability" in error for error in result.errors)


def test_flush_helpers_never_claim_false_durability(tmp_path):
    target = tmp_path / "missing"
    status, detail = persistence._fsync_directory(target)
    assert status in {"failed", "unsupported"}
    assert status != "passed"
    if status == "failed":
        assert detail


# --------------------------------------------------------------------------
# Write-capable file flush
#
# On Windows `os.fsync` maps to `FlushFileBuffers`, which requires write access
# on the handle. A read-only descriptor fails with EBADF, so the prepared-file
# flush must open write-capable. These tests fail against a read-only flush
# descriptor on every platform, and additionally reproduce the native Windows
# failure on the Windows lane.
# --------------------------------------------------------------------------


def flush_open_flags(path: Path, monkeypatch) -> list[int]:
    """Record the raw flags `_flush_file` passes to `os.open`."""
    recorded: list[int] = []
    real_open = os.open

    def spy(target, flags, *args, **kwargs):
        if str(target) == str(path):
            recorded.append(flags)
        return real_open(target, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    persistence._flush_file(path)
    return recorded


def test_prepared_file_flush_opens_a_write_capable_descriptor(tmp_path, monkeypatch):
    target = tmp_path / "payload"
    persistence._write_exact_file(target, b"abcd")
    flags = flush_open_flags(target, monkeypatch)
    assert len(flags) == 1
    access = flags[0] & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
    assert access == os.O_RDWR
    assert access != os.O_RDONLY
    assert flags[0] & getattr(os, "O_BINARY", 0) == getattr(os, "O_BINARY", 0)
    assert flags[0] & getattr(os, "O_NOFOLLOW", 0) == getattr(os, "O_NOFOLLOW", 0)


def test_prepared_file_flush_succeeds_on_a_real_prepared_file(tmp_path):
    target = tmp_path / "payload"
    persistence._write_exact_file(target, b"abcd")
    persistence._flush_file(target)
    assert target.read_bytes() == b"abcd"


def test_prepared_file_flush_keeps_the_no_follow_and_identity_protections(tmp_path):
    target = tmp_path / "payload"
    persistence._write_exact_file(target, b"abcd")
    source = inspect.getsource(persistence._flush_file)
    assert "_open_regular_file_no_follow" in source
    assert "os.open(" not in source
    # A directory, a missing path, and a non-regular entry are all refused.
    with pytest.raises(OSError):
        persistence._flush_file(tmp_path)
    with pytest.raises(OSError):
        persistence._flush_file(tmp_path / "absent")


@POSIX_ONLY
def test_prepared_file_flush_refuses_a_symlink(tmp_path):
    real = tmp_path / "real"
    persistence._write_exact_file(real, b"abcd")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError):
        persistence._flush_file(link)
    assert real.read_bytes() == b"abcd"


@WINDOWS_ONLY
def test_windows_prepared_file_flush_succeeds(tmp_path):  # pragma: no cover - Windows lane
    """The exact native regression: a read-only handle raised EBADF here."""
    target = tmp_path / "payload"
    persistence._write_exact_file(target, b"abcd")
    persistence._flush_file(target)
    read_only = os.open(target, os.O_RDONLY | os.O_BINARY)
    try:
        # Documented Windows behaviour: FlushFileBuffers needs write access.
        # The publisher must never depend on this descriptor.
        with pytest.raises(OSError):
            os.fsync(read_only)
    finally:
        os.close(read_only)


def test_ebadf_flush_failure_is_never_downgraded_to_unsupported(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()

    def bad_descriptor(fd):
        raise OSError(errno.EBADF, "Bad file descriptor")

    monkeypatch.setattr(os, "fsync", bad_descriptor)
    result = publish(bundle, root)
    assert result.status == "publication_failed_precommit"
    assert result.file_flush_status == "failed"
    assert result.file_flush_status != "unsupported"
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.atomic_publish_attempted is False
    assert result.errors
    assert not bundle_directory(root, bundle).exists()
    assert list(root.iterdir()) == []


def test_windows_durability_contract_end_to_end(tmp_path, monkeypatch):
    """One flow covering the full contract the Windows lane must satisfy."""
    root = data_dir(tmp_path)
    bundle = bundle_a()

    # 1. First publication succeeds with a proven file flush.
    first = publish(bundle, root)
    assert first.status == "bundle_published"
    assert first.file_flush_status == "passed"
    assert first.publication_performed is True
    assert first.persistence_performed is True
    assert first.overwrite_performed is False
    assert_never_approves(first)

    # 2. The exact PR316 byte streams, lengths, and checksums are unchanged.
    directory = bundle_directory(root, bundle)
    assert sorted(item.name for item in directory.iterdir()) == sorted(BUNDLE_FILENAMES)
    for logical in bundle.files:
        raw = (directory / logical.relative_path).read_bytes()
        assert raw == logical.content_utf8.encode("utf-8")
        assert len(raw) == FIXTURE_A_FILE_SIZES[logical.relative_path]
        assert hashlib.sha256(raw).hexdigest() == FIXTURE_A_FILE_SHA256[logical.relative_path]

    # 3. The loader reads it back and revalidates through PR316.
    loaded = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert loaded.status == "persisted_bundle_loaded"
    assert loaded.bundle == bundle
    assert loaded.bundle_validation.status == "bundle_valid"

    # 4. A second identical publication writes nothing and refreshes nothing.
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    }
    second = publish(bundle, root)
    assert second.status == "bundle_already_present"
    assert second.read_only is True
    assert second.mutation_performed is False
    assert second.artifact_write_performed is False
    assert second.temporary_directory_created is False
    assert {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    } == before

    # 5. An injected file-flush failure still blocks and cleans up completely.
    other = bundle_b()
    inject_failure(monkeypatch, "file_flush")
    blocked = publish(other, root)
    assert blocked.status == "publication_failed_precommit"
    assert blocked.file_flush_status == "failed"
    assert blocked.temporary_cleanup == "completed"
    assert blocked.temporary_cleanup_performed is True
    assert blocked.residual_temporary_directory == ""
    assert not bundle_directory(root, other).exists()
    assert sorted(item.name for item in publication_root(root).iterdir()) == [bundle.bundle_id]
    assert {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    } == before


# --------------------------------------------------------------------------
# Short private pending-directory names
#
# The pending directory once carried the full 68-character bundle ID, which made
# the unpublished temporary path 42 characters longer than the durable path it
# prepares. Under normal Windows pytest temporary-root geometry that pushed the
# temporary `supplemental-context.json` path to exactly MAX_PATH and exclusive
# creation failed with Errno 2. These tests fail against the full-ID pending
# name on every platform.
# --------------------------------------------------------------------------


def pending_names(root: Path, bundle, monkeypatch) -> list[str]:
    """Capture the pending directory names observed during one publication."""
    seen: list[str] = []

    def failpoint(name: str) -> None:
        if name == "temporary_directory_flush":
            seen.extend(
                item.name
                for item in publication_root(root).iterdir()
                if item.name.startswith(TEMPORARY_DIRECTORY_PREFIX)
            )

    monkeypatch.setattr(persistence, "_failpoint", failpoint)
    assert publish(bundle, root).status == "bundle_published"
    return seen


def test_pending_directory_name_is_short_and_carries_no_bundle_id(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    names = pending_names(root, bundle, monkeypatch)
    assert len(names) == 1
    name = names[0]

    assert name.startswith(TEMPORARY_DIRECTORY_PREFIX)
    token = name[len(TEMPORARY_DIRECTORY_PREFIX) :]
    assert len(token) == 2 * persistence.TEMPORARY_NONCE_BYTES
    assert all(character in "0123456789abcdef" for character in token)
    assert len(name) == persistence.TEMPORARY_DIRECTORY_NAME_LENGTH
    # Short enough that preparation can never be the binding length constraint.
    assert len(name) <= len(APPROVED_CHANGE_ARTIFACTS_DIRNAME)
    assert len(name) < len(bundle.bundle_id)

    assert bundle.bundle_id not in name
    assert bundle.bundle_identity_sha256 not in name
    for semantic in (
        FIXTURE_A_CONTEXT_SHA256,
        FIXTURE_A_SUBJECT_SHA256,
        FIXTURE_A_EVIDENCE_SHA256,
    ):
        assert semantic not in name


def test_pending_path_is_always_shorter_than_the_final_path_it_prepares(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    name = pending_names(root, bundle, monkeypatch)[0]
    longest_pending = max(
        len(str(publication_root(root) / name / filename)) for filename in BUNDLE_FILENAMES
    )
    longest_final = max(
        len(str(bundle_directory(root, bundle) / filename)) for filename in BUNDLE_FILENAMES
    )
    assert longest_pending < longest_final


def test_pending_directory_is_an_exclusive_direct_child_of_the_fixed_root(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    observed: list[Path] = []
    real_mkdir = os.mkdir

    def spy(path, *args, **kwargs):
        observed.append(Path(path))
        return real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "mkdir", spy)
    assert publish(bundle, root).status == "bundle_published"
    pending = [p for p in observed if p.name.startswith(TEMPORARY_DIRECTORY_PREFIX)]
    assert len(pending) == 1
    assert pending[0].parent == publication_root(root)
    assert pending[0].parent == bundle_directory(root, bundle).parent

    # Exclusive: `os.mkdir` is used, and a colliding name is never reused.
    persistence._write_exact_file(tmp_path / "probe", b"x")
    existing = publication_root(root) / f"{TEMPORARY_DIRECTORY_PREFIX}{'0' * 16}"
    existing.mkdir()
    with pytest.raises(FileExistsError):
        os.mkdir(existing, persistence.PERSISTED_DIRECTORY_MODE)


def test_two_invocations_receive_distinct_private_pending_names(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    first = pending_names(root, bundle_a(), monkeypatch)[0]
    second = pending_names(root, bundle_b(), monkeypatch)[0]
    assert first != second
    assert {first, second} == {first, second}
    # Both are still the same fixed short shape.
    for name in (first, second):
        assert len(name) == persistence.TEMPORARY_DIRECTORY_NAME_LENGTH
    # A large sample of tokens stays unique.
    tokens = {persistence._temporary_nonce() for _ in range(256)}
    assert len(tokens) == 256


def test_pending_token_never_reaches_any_durable_artifact(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    monkeypatch.setattr(persistence, "_temporary_nonce", lambda: "abcdef0123456789")
    result = publish(bundle, root)
    assert result.status == "bundle_published"
    directory = bundle_directory(root, bundle)
    assert "abcdef0123456789" not in directory.name
    assert "abcdef0123456789" not in result.relative_bundle_directory
    assert "abcdef0123456789" not in result.bundle_id
    assert "abcdef0123456789" not in result.bundle_identity_sha256
    assert "abcdef0123456789" not in json.dumps(result.model_dump(mode="json"))
    for name in BUNDLE_FILENAMES:
        assert b"abcdef0123456789" not in (directory / name).read_bytes()
    loaded = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert loaded.status == "persisted_bundle_loaded"
    assert "abcdef0123456789" not in json.dumps(loaded.model_dump(mode="json"))


def test_final_bundle_directory_is_still_the_exact_full_bundle_id(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    result = publish(bundle, root)
    assert result.status == "bundle_published"
    directory = bundle_directory(root, bundle)
    assert directory.name == bundle.bundle_id
    assert directory.name == f"acb_{bundle.bundle_identity_sha256}"
    assert len(directory.name) == 68
    assert directory.parent.name == APPROVED_CHANGE_ARTIFACTS_DIRNAME
    assert result.relative_bundle_directory == (
        f"{APPROVED_CHANGE_ARTIFACTS_DIRNAME}/{bundle.bundle_id}"
    )


def test_normal_test_root_geometry_publishes_end_to_end(tmp_path, monkeypatch):
    """The full contract under an unshortened, ordinary test temporary root."""
    root = data_dir(tmp_path)
    bundle = bundle_a()

    # 1. First publication, with a proven file flush.
    first = publish(bundle, root)
    assert first.status == "bundle_published"
    assert first.file_flush_status == "passed"
    assert first.publication_performed is True
    assert first.persistence_performed is True
    assert first.overwrite_performed is False
    assert_never_approves(first)

    # 2. Exact PR316 bytes, lengths, hashes, bundle identity, and bundle ID.
    directory = bundle_directory(root, bundle)
    assert sorted(item.name for item in directory.iterdir()) == sorted(BUNDLE_FILENAMES)
    for logical in bundle.files:
        raw = (directory / logical.relative_path).read_bytes()
        assert raw == logical.content_utf8.encode("utf-8")
        assert len(raw) == FIXTURE_A_FILE_SIZES[logical.relative_path]
        assert hashlib.sha256(raw).hexdigest() == FIXTURE_A_FILE_SHA256[logical.relative_path]
    assert first.bundle_identity_sha256 == FIXTURE_A_BUNDLE_IDENTITY_SHA256
    assert first.bundle_id == f"acb_{FIXTURE_A_BUNDLE_IDENTITY_SHA256}"

    # 3. Loader.
    loaded = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    assert loaded.status == "persisted_bundle_loaded"
    assert loaded.bundle == bundle

    # 4. Idempotency with zero writes and unchanged timestamps.
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    }
    second = publish(bundle, root)
    assert second.status == "bundle_already_present"
    assert second.read_only is True
    assert second.artifact_write_performed is False
    assert second.temporary_directory_created is False
    assert {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    } == before

    # 5. Conflicting existing content stays blocked without overwrite.
    conflicting = bundle_b()
    conflicting_directory = publication_root(root) / conflicting.bundle_id
    conflicting_directory.mkdir()
    for name in BUNDLE_FILENAMES:
        (conflicting_directory / name).write_bytes(b"{}")
    conflict = publish(conflicting, root)
    assert conflict.status == "publication_blocked"
    assert conflict.overwrite_performed is False
    assert conflict.artifact_write_performed is False
    for name in BUNDLE_FILENAMES:
        assert (conflicting_directory / name).read_bytes() == b"{}"

    # 6. Destination-appeared no-replace behaviour.
    third = build(context_alt_provenance()).bundle
    assert third.bundle_id not in {bundle.bundle_id, conflicting.bundle_id}
    run_at(monkeypatch, "atomic_publish", race_destination(root, third, "identical"))
    raced = publish(third, root)
    assert raced.status == "bundle_already_present"
    assert raced.atomic_publish_attempted is True
    assert raced.atomic_publish_outcome == "destination_exists"
    assert raced.atomic_publish_succeeded is False
    assert raced.temporary_cleanup == "completed"
    assert raced.overwrite_performed is False

    # 7. Injected failure leaves no final bundle and cleans up completely. A
    # second ordinary test root keeps this independent of the bundles above.
    fresh = tmp_path / "data-second"
    fresh.mkdir()
    inject_failure(monkeypatch, "file_flush")
    blocked_result = publish(bundle, fresh)
    assert blocked_result.status == "publication_failed_precommit"
    assert blocked_result.file_flush_status == "failed"
    assert blocked_result.temporary_cleanup == "completed"
    assert blocked_result.temporary_cleanup_performed is True
    assert blocked_result.residual_temporary_directory == ""
    assert blocked_result.publication_performed is False
    assert not bundle_directory(fresh, bundle).exists()
    assert list(fresh.iterdir()) == []

    # The bundles under the first root were never touched by any of the above.
    assert {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    } == before
    assert not [
        item
        for item in publication_root(root).iterdir()
        if item.name.startswith(TEMPORARY_DIRECTORY_PREFIX)
    ]


def test_unaddressable_final_path_fails_closed_before_anything_is_created(
    tmp_path, monkeypatch, fs_recorder
):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    # A limit that the fixed final bundle path cannot satisfy under this root.
    longest_final = max(
        len(str(bundle_directory(root, bundle) / name)) for name in BUNDLE_FILENAMES
    )
    monkeypatch.setattr(persistence, "MAX_PUBLICATION_PATH_CHARS", longest_final - 1)
    fs_recorder.calls.clear()

    result = publish(bundle, root)
    assert result.status == "publication_blocked"
    assert any("too long" in error for error in result.errors)
    assert result.publication_performed is False
    assert result.persistence_performed is False
    assert result.overwrite_performed is False
    assert result.publication_root_created is False
    assert result.temporary_directory_created is False
    assert result.artifact_write_performed is False
    assert result.mutation_performed is False
    assert result.atomic_publish_attempted is False
    assert_never_approves(result)

    # Nothing was created: no publication root, no pending directory, no bundle.
    assert list(root.iterdir()) == []
    assert fs_recorder.creations(root) == []
    # Only lengths are reported; no host absolute path leaks into the result.
    assert str(tmp_path) not in json.dumps(result.model_dump(mode="json"))


def test_unaddressable_final_path_never_disturbs_an_existing_bundle(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    assert publish(bundle, root).status == "bundle_published"
    directory = bundle_directory(root, bundle)
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    }

    other = bundle_b()
    longest_final = max(len(str(bundle_directory(root, other) / name)) for name in BUNDLE_FILENAMES)
    monkeypatch.setattr(persistence, "MAX_PUBLICATION_PATH_CHARS", longest_final - 1)
    result = publish(other, root)
    assert result.status == "publication_blocked"
    assert not bundle_directory(root, other).exists()
    assert sorted(item.name for item in publication_root(root).iterdir()) == [bundle.bundle_id]
    assert {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(directory.iterdir())
    } == before


def test_publication_path_limit_matches_the_platform():
    if os.name == "nt":  # pragma: no cover - Windows lane
        assert persistence.MAX_PUBLICATION_PATH_CHARS == 259
    else:
        assert persistence.MAX_PUBLICATION_PATH_CHARS == 4095
    source = module_code_without_strings()
    # No extended-length path support was added.
    assert "\\\\?\\" not in ast.unparse(module_tree_without_docstrings())
    assert "GetLongPathName" not in source
    assert "GetShortPathName" not in source


@WINDOWS_ONLY
def test_windows_normal_test_root_geometry_fits_max_path(tmp_path):  # pragma: no cover - Windows
    """The exact native regression: the prepared path once hit MAX_PATH here."""
    root = data_dir(tmp_path)
    bundle = bundle_a()
    result = publish(bundle, root)
    assert result.status == "bundle_published"
    assert result.file_flush_status == "passed"
    directory = bundle_directory(root, bundle)
    for name in BUNDLE_FILENAMES:
        assert len(str(directory / name)) <= persistence.MAX_PUBLICATION_PATH_CHARS
        assert (directory / name).is_file()


# --------------------------------------------------------------------------
# Immutability
# --------------------------------------------------------------------------


def test_publication_and_load_results_are_frozen(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    result = publish(bundle, root)
    with pytest.raises(ValidationError):
        result.status = "publication_blocked"
    with pytest.raises(ValidationError):
        result.overwrite_performed = True
    loaded = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    with pytest.raises(ValidationError):
        loaded.status = "persisted_bundle_invalid"
    with pytest.raises(ValidationError):
        loaded.bundle.bundle_id = "acb_" + NOT_A_HASH


def test_result_sequences_are_immutable_tuples(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    result = publish(bundle, root)
    loaded = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    for sequence in (result.errors, result.warnings, loaded.errors, loaded.warnings):
        assert isinstance(sequence, tuple)
        with pytest.raises(AttributeError):
            sequence.append("extra")
    assert isinstance(PERMANENT_PERSISTENCE_WARNINGS, tuple)
    assert isinstance(loaded.bundle.files, tuple)


def test_atomic_outcome_record_is_frozen(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outcome = atomic_no_replace_directory_publish(source, tmp_path / "destination")
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.outcome = "failed"


def test_statuses_are_fixed_tuples():
    assert isinstance(PUBLICATION_STATUSES, tuple)
    assert isinstance(LOAD_STATUSES, tuple)
    assert set(PUBLICATION_STATUSES) == {
        "bundle_published",
        "bundle_already_present",
        "publication_blocked",
        "invalid_publication_input",
        "publication_failed_precommit",
        "publication_failed_cleanup_incomplete",
        "published_verification_failed",
        "atomic_publication_unsupported",
    }
    assert set(LOAD_STATUSES) == {
        "persisted_bundle_loaded",
        "persisted_bundle_not_found",
        "persisted_bundle_invalid",
        "invalid_persisted_bundle_reference",
        "unsafe_persistence_root",
    }


# --------------------------------------------------------------------------
# Permanent warnings
# --------------------------------------------------------------------------


def test_permanent_warnings_state_every_required_boundary(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    results = [
        publish(bundle, root),
        publish(bundle, root),
        publish(bundle, root, confirmation=NOT_A_HASH),
        load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root),
        load_persisted_approved_change_artifact_bundle("latest", data_dir=root),
    ]
    required = (
        "not approval",
        "not authorization",
        "ApprovedChangeContract",
        "authenticated identity",
        "not subject identity",
        "capability support",
        "artifact publication",
        "execution confirmation",
        "execution eligibility",
        "no overwrite",
        "reviewed before sharing",
        "no redaction",
    )
    for result in results:
        assert result.warnings == PERMANENT_PERSISTENCE_WARNINGS
        joined = " ".join(result.warnings)
        for phrase in required:
            assert phrase in joined, phrase


# --------------------------------------------------------------------------
# Semantic separation
# --------------------------------------------------------------------------


def test_a_persisted_bundle_creates_no_approval_capability_receipt_or_execution(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    result = publish(bundle, root)
    loaded = load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root)
    for outcome in (result, loaded):
        assert outcome.approval_created is False
        assert outcome.contract_created is False
        assert outcome.receipt_created is False
        assert outcome.capability_support_evaluated is False
        assert outcome.capability_supported is False
        assert outcome.approval_evaluated is False
        assert outcome.authorization_evaluated is False
        assert outcome.execution_allowed is False
        assert outcome.execution_available is False
        assert outcome.execution_status == "not_executed"
        assert outcome.host_configuration_mutation_performed is False
    # Nothing outside the four fixed files exists: no receipt, marker, or sidecar.
    assert sorted(item.name for item in bundle_directory(root, bundle).iterdir()) == sorted(
        BUNDLE_FILENAMES
    )


def test_publication_result_is_never_persisted_as_a_fifth_file(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    result = publish(bundle, root)
    directory = bundle_directory(root, bundle)
    assert len(list(directory.iterdir())) == 4
    for name in BUNDLE_FILENAMES:
        raw = (directory / name).read_bytes()
        assert b"publication_root_created" not in raw
        assert b"confirmation_matched" not in raw
    assert result.status == "bundle_published"


def test_no_result_field_embeds_a_host_absolute_path(tmp_path, monkeypatch):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    outcomes = [
        publish(bundle, root),
        publish(bundle, root),
        load_persisted_approved_change_artifact_bundle(bundle.bundle_id, data_dir=root),
    ]
    inject_failure(monkeypatch, "temporary_directory_flush")
    outcomes.append(publish(bundle_b(), root))
    for outcome in outcomes:
        payload = outcome.model_dump(mode="json")
        payload.pop("bundle", None)
        payload.pop("bundle_validation", None)
        assert str(tmp_path) not in json.dumps(payload)


# --------------------------------------------------------------------------
# Static source guards
# --------------------------------------------------------------------------


def module_tree_without_docstrings():
    tree = ast.parse(Path(persistence.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body.pop(0)
            if not node.body:
                node.body.append(ast.Pass())
    return tree


def module_code_without_strings():
    tree = module_tree_without_docstrings()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node.value = ""
    return ast.unparse(tree)


def test_static_no_execution_network_model_or_shell_surface():
    source = module_code_without_strings()
    for token in (
        "subprocess",
        "os.system",
        "popen",
        "socket",
        "docker",
        "compose",
        "powershell",
        "winrm",
        "qga",
        "requests",
        "httpx",
        "urllib",
        "provider",
        "os.environ",
        "getenv",
        "shutil",
        "rmtree",
        "glob",
        "walk",
    ):
        assert token not in source, token


def test_static_no_replace_capable_final_publication():
    source = module_code_without_strings()
    for token in ("os.replace", "os.rename(", ".replace(", ".rename("):
        assert token not in source, token
    assert "renameat2" in source
    assert "MoveFileExW" in source


def test_static_no_approval_capability_receipt_or_cli_surface():
    source = module_code_without_strings()
    for token in (
        "Proposal",
        "core.approvals",
        "ApprovalAttestation",
        "ApprovedChangeContract",
        "capability_registry",
        "CAPABILITY_REGISTRY",
        "bind_capability",
        "evaluate_capability",
        "preflight",
        "link_receipt",
        "recipe",
        "RECIPE",
        "typer",
        "app.command",
        "add_typer",
        "windows_runtime_reconcile",
        "ask_routing",
        "intent",
    ):
        assert token not in source, token


def test_static_never_imports_or_names_approval_or_contract_types():
    tree = module_tree_without_docstrings()
    forbidden = {"ApprovalAttestation", "ApprovedChangeContract", "Proposal"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert forbidden.isdisjoint(alias.name for alias in node.names)
        if isinstance(node, ast.Name):
            assert node.id not in forbidden
        if isinstance(node, ast.Attribute):
            assert node.attr not in forbidden


def test_static_import_set_is_exactly_the_maintained_dependencies():
    tree = ast.parse(Path(persistence.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert imported == {
        "__future__",
        "ctypes",
        "dataclasses",
        "hashlib",
        "hmac",
        "json",
        "os",
        "pathlib",
        "platform",
        "pydantic",
        "re",
        "secrets",
        "shellforgeai.core.approved_change_artifact_bundle",
        "stat",
        "sys",
        "typing",
    }


def test_static_native_api_use_is_isolated_to_the_atomic_helper():
    tree = module_tree_without_docstrings()
    holders: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if "ctypes" in ast.unparse(node):
            holders.add(node.name)
    assert holders == {
        "_linux_renameat2_no_replace",
        "_windows_move_file_no_replace",
    }


def test_static_signatures_never_take_proposal_or_return_approval_types():
    for _, obj in inspect.getmembers(persistence, inspect.isfunction):
        signature = inspect.signature(obj)
        assert all(param.annotation is not Proposal for param in signature.parameters.values())
        assert signature.return_annotation not in {ApprovalAttestation, ApprovedChangeContract}
        assert "Proposal" not in str(signature)


def test_module_exposes_no_cli_registry_delete_or_generic_write_surface():
    for name in (
        "app",
        "cli",
        "main",
        "register",
        "REGISTRY",
        "CAPABILITY_REGISTRY",
        "delete_persisted_approved_change_artifact_bundle",
        "remove_bundle",
        "overwrite_bundle",
        "update_bundle",
        "copy_bundle",
        "export_bundle",
        "write_file",
        "resolve_latest_bundle",
        "latest_bundle",
    ):
        assert not hasattr(persistence, name), name


def test_public_surface_is_exactly_the_two_operations_and_the_atomic_helper():
    public = sorted(
        name
        for name, obj in inspect.getmembers(persistence, inspect.isfunction)
        if not name.startswith("_") and obj.__module__ == persistence.__name__
    )
    assert public == [
        "atomic_no_replace_directory_publish",
        "load_persisted_approved_change_artifact_bundle",
        "publish_approved_change_artifact_bundle",
    ]


def test_module_is_not_imported_by_cli_approvals_recipes_or_execution():
    roots = [Path("src/shellforgeai/cli"), Path("src/shellforgeai/core")]
    offenders = []
    for base in roots:
        for path in base.rglob("*.py"):
            if path.name == "approved_change_artifact_persistence.py":
                continue
            if "approved_change_artifact_persistence" in path.read_text(encoding="utf-8"):
                offenders.append(str(path))
    assert offenders == []


def test_fixed_layout_literals_are_module_constants():
    source = ast.unparse(module_tree_without_docstrings())
    assert "'approved_change_artifacts'" in source
    assert "'.pending-'" in source
    assert APPROVED_CHANGE_ARTIFACTS_DIRNAME == "approved_change_artifacts"
    assert TEMPORARY_DIRECTORY_PREFIX == ".pending-"


def test_bundle_id_prefix_and_filenames_are_taken_from_pr316():
    # PR317 never redefines the PR316 bundle-ID prefix or the four filenames.
    assert persistence.BUNDLE_ID_PREFIX is BUNDLE_ID_PREFIX
    assert persistence.BUNDLE_FILENAMES is BUNDLE_FILENAMES
    assert persistence._BUNDLE_ID_RE.pattern == rf"^{BUNDLE_ID_PREFIX}[0-9a-f]{{64}}$"
    source = ast.unparse(module_tree_without_docstrings())
    assert "'acb_'" not in source
    for filename in BUNDLE_FILENAMES:
        assert f"'{filename}'" not in source


# --------------------------------------------------------------------------
# Documentation contract
# --------------------------------------------------------------------------


def test_persistence_documentation_records_the_fixed_contract():
    document = Path("docs/APPROVED_CHANGE_ARTIFACT_PERSISTENCE.md").read_text(encoding="utf-8")
    for phrase in (
        "approved_change_artifacts",
        "confirm_bundle_identity_sha256",
        "bundle_already_present",
        "published_verification_failed",
        "atomic_publication_unsupported",
        "RENAME_NOREPLACE",
        "MoveFileExW",
        str(MAX_PERSISTED_BUNDLE_FILE_BYTES),
        str(MAX_PERSISTED_BUNDLE_TOTAL_BYTES),
        "no overwrite",
    ):
        assert phrase in document, phrase


def test_validation_matrix_maps_the_persistence_module_to_this_suite():
    matrix = json.loads(Path("scripts/validation_matrix.json").read_text(encoding="utf-8"))
    rules = [
        rule
        for rule in matrix["rules"]
        if rule["pattern"].endswith("approved_change_artifact_persistence.py")
    ]
    assert len(rules) == 1
    assert "tests/test_pr317_approved_change_artifact_persistence.py" in rules[0]["tests"]


# --------------------------------------------------------------------------
# Prepared-file helpers
# --------------------------------------------------------------------------


def test_exclusive_write_refuses_an_existing_file(tmp_path):
    target = tmp_path / "payload"
    target.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        persistence._write_exact_file(target, b"new")
    assert target.read_bytes() == b"existing"


def test_prepared_file_verification_detects_a_byte_length_change(tmp_path):
    target = tmp_path / "payload"
    persistence._write_exact_file(target, b"abcd")
    with pytest.raises(OSError):
        persistence._verify_prepared_file(target, b"abcde")


def test_prepared_file_verification_detects_a_checksum_change(tmp_path):
    target = tmp_path / "payload"
    persistence._write_exact_file(target, b"abcd")
    with pytest.raises(OSError):
        persistence._verify_prepared_file(target, b"abce")


def test_prepared_files_use_restrictive_modes_where_supported(tmp_path):
    root = data_dir(tmp_path)
    bundle = bundle_a()
    publish(bundle, root)
    if os.name == "nt":  # pragma: no cover - Windows lane
        pytest.skip("POSIX mode bits are not meaningful on Windows")
    directory = bundle_directory(root, bundle)
    assert stat_module.S_IMODE(directory.stat().st_mode) == 0o700
    for name in BUNDLE_FILENAMES:
        assert stat_module.S_IMODE((directory / name).stat().st_mode) == 0o600


def test_bundle_reconstruction_rejects_records_without_a_manifest():
    bundle = bundle_a()
    records = tuple(item for item in bundle.files if item.relative_path != MANIFEST_FILENAME)
    reconstructed, errors = persistence._bundle_from_records(records)
    assert reconstructed is None
    assert errors


def test_bundle_reconstruction_rejects_an_unparseable_manifest():
    bundle = bundle_a()
    broken = ApprovedChangeArtifactBundleFile(
        relative_path=MANIFEST_FILENAME,
        role="manifest",
        content_utf8="{",
        size_bytes=1,
        sha256=hashlib.sha256(b"{").hexdigest(),
    )
    records = tuple(
        broken if item.relative_path == MANIFEST_FILENAME else item for item in bundle.files
    )
    reconstructed, errors = persistence._bundle_from_records(records)
    assert reconstructed is None
    assert any("parseable" in error for error in errors)


def test_bundle_file_order_is_the_maintained_pr316_order():
    assert tuple(name for name, _ in BUNDLE_FILE_ORDER) == BUNDLE_FILENAMES
    assert BUNDLE_FILENAMES == (
        SUPPLEMENTAL_CONTEXT_FILENAME,
        APPROVED_CHANGE_SUBJECT_FILENAME,
        CONSTRUCTION_EVIDENCE_FILENAME,
        MANIFEST_FILENAME,
    )


def test_errno_constants_used_by_the_linux_primitive_are_the_real_ones():
    assert errno.EEXIST == 17
    assert errno.ENOTEMPTY == 39 or os.name == "nt"
