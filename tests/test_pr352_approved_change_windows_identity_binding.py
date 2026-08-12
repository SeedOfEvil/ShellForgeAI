"""Focused PR352 exact Windows identity-evidence provenance binding tests."""

from __future__ import annotations

import json
from typing import Literal

import pytest
from test_pr319_approved_change_approval_artifact_persistence import (
    artifact_file,
    artifact_for,
    bundle_a,
    data_dir,
    publish_artifact,
)

from shellforgeai.core import approved_change_windows_identity_binding as binding_module
from shellforgeai.core.approved_change_windows_identity_binding import (
    ApprovedChangeWindowsIdentityBinding,
    bind_windows_process_identity_to_approval_artifact,
    canonical_windows_identity_binding_json,
    compute_windows_identity_binding_sha256,
)
from shellforgeai.core.windows_process_identity_evidence import (
    WindowsProcessIdentityEvidence,
    compute_windows_process_identity_evidence_sha256,
)


def evidence(*, sid: str = "S-1-5-18", luid: str = "00000000000003e7"):
    return WindowsProcessIdentityEvidence(principal_sid=sid, authentication_session_luid=luid)


@pytest.fixture
def published(tmp_path):
    root = data_dir(tmp_path)
    artifact = artifact_for(bundle_a(), root, approved_by="self-asserted-human-label")
    result = publish_artifact(artifact, root)
    assert result.status == "approval_artifact_published"
    return root, artifact


def bind(root, artifact, identity=None, **overrides):
    identity = identity or evidence()
    values = {
        "data_dir": root,
        "confirm_approval_artifact_identity_sha256": artifact.approval_artifact_identity_sha256,
        "confirm_identity_evidence_sha256": compute_windows_process_identity_evidence_sha256(
            identity
        ),
    }
    values.update(overrides)
    return bind_windows_process_identity_to_approval_artifact(
        artifact.approval_artifact_id, identity, **values
    )


def test_deterministic_binding_uses_exact_upstream_identities(published):
    root, artifact = published
    first = bind(root, artifact)
    second = bind(root, artifact)
    assert first.status == "identity_binding_constructed"
    assert first.binding == second.binding
    assert first.identity_binding_identity_sha256 == second.identity_binding_identity_sha256
    assert first.binding is not None
    canonical = canonical_windows_identity_binding_json(first.binding)
    assert canonical == json.dumps(
        first.binding.model_dump(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert compute_windows_identity_binding_sha256(first.binding) == (
        first.identity_binding_identity_sha256
    )
    assert first.identity_binding_identity_sha256 not in {
        artifact.approval_artifact_identity_sha256,
        artifact.subject_sha256,
        first.identity_evidence_sha256,
    }


def test_approved_by_is_neither_compared_nor_copied_and_service_sid_is_not_authority(published):
    root, artifact = published
    result = bind(root, artifact)
    assert result.status == "identity_binding_constructed"
    payload = result.binding.model_dump()
    assert "approved_by" not in payload
    assert "self-asserted-human-label" not in canonical_windows_identity_binding_json(
        result.binding
    )
    assert payload["principal_sid"] == "S-1-5-18"
    assert payload["authentication_session_luid"] == "00000000000003e7"
    assert result.verified_human_identity is False
    assert result.authenticated_identity_evaluated is False
    assert result.approved_by_comparison_evaluated is False
    assert result.authorization_evaluated is False


@pytest.mark.parametrize(
    ("artifact_id", "artifact_confirmation", "evidence_confirmation", "identity", "status"),
    [
        ("aca_bad", "0" * 64, "0" * 64, evidence(), "invalid_identity_binding_input"),
        ("aca_" + "0" * 64, "BAD", "0" * 64, evidence(), "invalid_identity_binding_input"),
        ("aca_" + "0" * 64, "0" * 64, "BAD", evidence(), "invalid_identity_binding_input"),
        (
            "aca_" + "0" * 64,
            "0" * 64,
            "0" * 64,
            {"principal_sid": "not-a-sid", "authentication_session_luid": "0" * 16},
            "identity_evidence_invalid",
        ),
        (
            "aca_" + "0" * 64,
            "0" * 64,
            "0" * 64,
            evidence(),
            "identity_evidence_confirmation_mismatch",
        ),
    ],
)
def test_pure_failures_precede_the_exact_loader(
    tmp_path,
    monkeypatch,
    artifact_id,
    artifact_confirmation,
    evidence_confirmation,
    identity,
    status,
):
    calls = []
    monkeypatch.setattr(
        binding_module,
        "load_persisted_approved_change_approval_artifact",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    result = bind_windows_process_identity_to_approval_artifact(
        artifact_id,
        identity,
        data_dir=tmp_path,
        confirm_approval_artifact_identity_sha256=artifact_confirmation,
        confirm_identity_evidence_sha256=evidence_confirmation,
    )
    assert result.status == status
    assert calls == []
    assert result.binding is None


@pytest.mark.parametrize(
    "identity",
    [
        {"principal_sid": "s-1-5-18", "authentication_session_luid": "0" * 16},
        {"principal_sid": "S-1-5-18", "authentication_session_luid": "ABC"},
    ],
)
def test_pr342_authority_rejects_noncanonical_sid_and_luid_before_loading(
    tmp_path, monkeypatch, identity
):
    monkeypatch.setattr(
        binding_module,
        "load_persisted_approved_change_approval_artifact",
        lambda *args, **kwargs: pytest.fail("loader must not be called"),
    )
    result = bind_windows_process_identity_to_approval_artifact(
        "aca_" + "0" * 64,
        identity,
        data_dir=tmp_path,
        confirm_approval_artifact_identity_sha256="0" * 64,
        confirm_identity_evidence_sha256="0" * 64,
    )
    assert result.status == "identity_evidence_invalid"


@pytest.mark.parametrize(
    "altered",
    [
        evidence(sid="S-1-5-19"),
        evidence(luid="00000000000003e8"),
    ],
)
def test_confirmed_evidence_tampering_fails_before_loading(published, monkeypatch, altered):
    root, artifact = published
    calls = []
    monkeypatch.setattr(
        binding_module,
        "load_persisted_approved_change_approval_artifact",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    result = bind(
        root,
        artifact,
        altered,
        confirm_identity_evidence_sha256=compute_windows_process_identity_evidence_sha256(
            evidence()
        ),
    )
    assert result.status == "identity_evidence_confirmation_mismatch"
    assert calls == []


def test_missing_and_confirmation_mismatched_artifacts_fail_closed(published):
    root, artifact = published
    missing = bind_windows_process_identity_to_approval_artifact(
        "aca_" + "0" * 64,
        evidence(),
        data_dir=root,
        confirm_approval_artifact_identity_sha256="0" * 64,
        confirm_identity_evidence_sha256=compute_windows_process_identity_evidence_sha256(
            evidence()
        ),
    )
    mismatch = bind(root, artifact, confirm_approval_artifact_identity_sha256="0" * 64)
    assert missing.status == "approval_artifact_not_available"
    assert mismatch.status == "approval_artifact_confirmation_mismatch"
    assert missing.binding is mismatch.binding is None


def test_tampered_persisted_artifact_is_not_repaired_or_bound(published):
    root, artifact = published
    path = artifact_file(root, artifact)
    path.write_bytes(
        path.read_bytes().replace(b"self-asserted-human-label", b"tampered-human-label")
    )
    before = path.read_bytes()
    result = bind(root, artifact)
    assert result.status == "approval_artifact_not_available"
    assert result.binding is None
    assert path.read_bytes() == before


def test_binding_identity_changes_for_every_bound_provenance_fact(published):
    root, artifact = published
    original = bind(root, artifact).binding
    assert original is not None
    changes = {
        "approval_artifact_id": "aca_" + "1" * 64,
        "approval_artifact_identity_sha256": "1" * 64,
        "subject_sha256": "1" * 64,
        "principal_sid": "S-1-5-19",
        "authentication_session_luid": "00000000000003e8",
        "identity_evidence_sha256": "1" * 64,
    }
    baseline = compute_windows_identity_binding_sha256(original)
    for field, value in changes.items():
        changed = ApprovedChangeWindowsIdentityBinding.model_validate(
            original.model_copy(update={field: value}).model_dump()
        )
        assert compute_windows_identity_binding_sha256(changed) != baseline


def test_complete_safety_ledger_remains_false(published):
    root, artifact = published
    result = bind(root, artifact)
    false_fields = [
        name
        for name, field in type(result).model_fields.items()
        if field.annotation is Literal[False]
    ]
    assert false_fields
    assert all(getattr(result, name) is False for name in false_fields)
    assert result.read_only is True
    assert result.execution_status == "not_executed"
    assert result.identity_binding_evaluated is True
    assert result.identity_evidence_bound is True
