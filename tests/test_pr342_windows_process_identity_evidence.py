"""Focused tests for native Windows current-process token identity evidence."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from shellforgeai.core import windows_process_identity_evidence as identity


class FakeNative:
    def __init__(self, value=("S-1-5-21-100-200-300-400", 0, 999, 1), error=None):
        self.value, self.error = value, error
        self.token_opened = False
        self.token_user_evaluated = False
        self.token_statistics_evaluated = False
        self.sid_conversion_evaluated = False
        self.calls = 0

    def collect(self):
        self.calls += 1
        if self.error:
            raise self.error
        self.token_opened = self.token_user_evaluated = True
        self.token_statistics_evaluated = self.sid_conversion_evaluated = True
        return self.value


def collect(fake):
    return identity.collect_current_windows_process_identity_evidence(
        platform="windows", native_factory=lambda: fake
    )


def test_success_contract_and_canonical_identity():
    fake = FakeNative()
    result = collect(fake)
    assert result.status == "identity_evidence_collected" and fake.calls == 1
    assert result.principal_sid == "S-1-5-21-100-200-300-400"
    assert result.authentication_session_luid == "00000000000003e7"
    assert result.token_type == "primary" and len(result.identity_evidence_sha256) == 64
    assert result.os_identity_evaluated and result.os_identity_available
    for field in (
        "approval_identity_bound",
        "approval_freshness_evaluated",
        "authorization_evaluated",
        "rbac_evaluated",
        "preflight_evaluated",
        "receipt_created",
        "execution_allowed",
        "persistence_performed",
        "credential_read",
        "secret_read",
        "auth_cache_read",
        "group_membership_evaluated",
        "privileges_evaluated",
        "elevation_evaluated",
        "integrity_level_evaluated",
        "powershell_executed",
        "winrm_used",
        "qga_used",
        "network_call",
        "model_called",
        "subprocess_executed",
        "shell_executed",
        "host_configuration_mutation_performed",
    ):
        assert getattr(result, field) is False


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_unsupported_precedes_native_loading(platform):
    calls = []
    result = identity.collect_current_windows_process_identity_evidence(
        platform=platform, native_factory=lambda: calls.append(1)
    )
    assert result.status == "unsupported" and calls == []
    assert not result.os_identity_evaluated and not result.os_identity_available


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (identity.NativeTokenError("open_process_token", 5), "identity_evidence_unavailable"),
        (identity.NativeTokenError("token_user_sizing", 87), "identity_evidence_unavailable"),
        (identity.NativeTokenError("token_user", 5), "identity_evidence_unavailable"),
        (identity.NativeTokenError("token_statistics_sizing", 87), "identity_evidence_unavailable"),
        (identity.NativeTokenError("token_statistics", 5), "identity_evidence_unavailable"),
        (identity.NativeTokenError("sid_conversion", 87), "identity_evidence_unavailable"),
        (RuntimeError("surprise"), "identity_collection_failed"),
    ],
)
def test_failures_are_bounded_and_fail_closed(error, status):
    result = collect(FakeNative(error=error))
    assert result.status == status and not result.os_identity_available
    assert result.principal_sid == "" and result.identity_evidence_sha256 == ""
    assert len(result.errors) == 1 and "Traceback" not in result.errors[0]
    assert not result.authorization_evaluated and not result.execution_allowed


@pytest.mark.parametrize("sid", ["S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32-544"])
def test_valid_sid_families(sid):
    assert collect(FakeNative(value=(sid, 0, 0, 1))).principal_sid == sid


@pytest.mark.parametrize("sid", ["", " S-1-5-18", "S-1-5-18 ", "not-a-sid", "S-1-5-x"])
def test_invalid_sid_is_not_published(sid):
    result = collect(FakeNative(value=(sid, 0, 0, 1)))
    assert result.status == "identity_collection_failed" and result.principal_sid == ""


def test_non_primary_token_is_invalid():
    result = collect(FakeNative(value=("S-1-5-18", 0, 0, 2)))
    assert result.status == "identity_evidence_invalid" and not result.os_identity_available


def test_luid_boundaries_and_identity_determinism():
    assert identity._luid(0, 0) == "0000000000000000"
    assert identity._luid(-1, 0xFFFFFFFF) == "ffffffffffffffff"
    first = identity.WindowsProcessIdentityEvidence(
        principal_sid="S-1-5-18", authentication_session_luid="00000000000003e7"
    )
    reordered = dict(reversed(list(first.model_dump().items())))
    assert identity.compute_windows_process_identity_evidence_sha256(
        first
    ) == identity.compute_windows_process_identity_evidence_sha256(reordered)
    changed_sid = first.model_copy(update={"principal_sid": "S-1-5-19"})
    changed_luid = first.model_copy(update={"authentication_session_luid": "00000000000003e8"})
    assert identity.compute_windows_process_identity_evidence_sha256(
        first
    ) != identity.compute_windows_process_identity_evidence_sha256(changed_sid)
    assert identity.compute_windows_process_identity_evidence_sha256(
        first
    ) != identity.compute_windows_process_identity_evidence_sha256(changed_luid)
    assert "sha256" not in identity.canonical_windows_process_identity_evidence_json(first)


def test_models_are_frozen_and_forbid_extras():
    evidence = identity.WindowsProcessIdentityEvidence(
        principal_sid="S-1-5-18", authentication_session_luid="0" * 16
    )
    with pytest.raises(ValidationError):
        evidence.principal_sid = "S-1-5-19"
    with pytest.raises(ValidationError):
        identity.WindowsProcessIdentityEvidence(
            principal_sid="S-1-5-18", authentication_session_luid="0" * 16, pid=1
        )
    result = collect(FakeNative())
    with pytest.raises(ValidationError):
        result.status = "unsupported"


def test_static_boundary_has_no_forbidden_authorities():
    source = Path(identity.__file__).read_text(encoding="utf-8")
    imports = " ".join(
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    )
    for forbidden in (
        "subprocess",
        "socket",
        "getpass",
        "approved_change_pr304_evidence_freshness",
        "approved_change_approval",
        "windows_runtime_reconcile",
        "shellforgeai.cli",
        "provider",
    ):
        assert forbidden not in imports
    for forbidden in (
        "LookupAccountSid",
        "TokenGroups",
        "TokenPrivileges",
        "TokenElevation",
        "PowerShell",
        "WinRM",
        "whoami",
    ):
        assert forbidden not in source
    assert "TOKEN_QUERY = 0x0008" in source


def test_native_cleanup_calls_are_single_and_finally_guarded():
    """Keep the two native ownership releases structurally unambiguous."""
    tree = ast.parse(Path(identity.__file__).read_text(encoding="utf-8"))
    native_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "_WindowsNativeTokenAccess"
    )
    collect_node = next(
        node
        for node in native_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "collect"
    )
    calls = [
        node.func.attr
        for node in ast.walk(collect_node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert calls.count("CloseHandle") == 1
    assert calls.count("LocalFree") == 1
    final_calls = [
        node.func.attr
        for try_node in ast.walk(collect_node)
        if isinstance(try_node, ast.Try)
        for statement in try_node.finalbody
        for node in ast.walk(statement)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert "CloseHandle" in final_calls and "LocalFree" in final_calls
