"""Read-only identity evidence from the current Windows process primary token."""

from __future__ import annotations

import ctypes
import hashlib
import json
import re
import sys
from collections.abc import Callable, Mapping
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, field_validator

TOKEN_QUERY = 0x0008
TOKEN_USER = 1
TOKEN_STATISTICS = 10
ERROR_INSUFFICIENT_BUFFER = 122
MAX_SID_LENGTH = 184

EVIDENCE_TYPE = "windows_current_process_token_identity"
IDENTITY_SOURCE = "windows_process_access_token"
COLLECTOR_SCOPE = "current_process_primary_token"

WARNINGS = (
    "the SID identifies the Windows security principal represented by the current process token",
    "AuthenticationId identifies the Windows authentication/logon session associated with "
    "that token and is not durable",
    "this is not physical-human identity, MFA proof, domain-authentication freshness, or "
    "credential validity",
    "this does not compare to approved_by or bind identity to an approval",
    "this is not approval/evidence freshness, authorization, role/RBAC evaluation, "
    "current-state validation, or preflight",
    "this creates no receipt, grants no execution eligibility, and invokes no PR313 execution",
    "natural language cannot turn this evidence into execution",
)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class WindowsProcessIdentityEvidence(_Frozen):
    schema_version: Literal[1] = 1
    identity_evidence_type: Literal["windows_current_process_token_identity"] = EVIDENCE_TYPE
    platform: Literal["windows"] = "windows"
    identity_source: Literal["windows_process_access_token"] = IDENTITY_SOURCE
    collector_scope: Literal["current_process_primary_token"] = COLLECTOR_SCOPE
    principal_sid: str
    authentication_session_luid: str
    token_type: Literal["primary"] = "primary"

    @field_validator("principal_sid")
    @classmethod
    def _valid_sid(cls, value: str) -> str:
        if not value or len(value) > MAX_SID_LENGTH or value != value.strip():
            raise ValueError("principal SID is empty, unsafe, or too long")
        if not re.fullmatch(r"S-\d+(?:-\d+)+", value):
            raise ValueError("principal SID is not canonical SID text")
        return value

    @field_validator("authentication_session_luid")
    @classmethod
    def _valid_luid(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{16}", value):
            raise ValueError("AuthenticationId must be 16 lowercase hexadecimal characters")
        return value


Status = Literal[
    "identity_evidence_collected",
    "unsupported",
    "identity_evidence_unavailable",
    "identity_evidence_invalid",
    "identity_collection_failed",
]


class WindowsProcessIdentityResult(_Frozen):
    status: Status
    reason: str
    platform: str
    identity_evidence_type: str = EVIDENCE_TYPE
    identity_source: str = IDENTITY_SOURCE
    collector_scope: str = COLLECTOR_SCOPE
    principal_sid: str = ""
    authentication_session_luid: str = ""
    token_type: str = ""
    identity_evidence_sha256: str = ""
    native_token_open_evaluated: bool = False
    native_token_opened: bool = False
    token_user_evaluated: bool = False
    token_statistics_evaluated: bool = False
    sid_conversion_evaluated: bool = False
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    os_identity_evaluated: bool = False
    os_identity_available: bool = False
    verified_human_identity: Literal[False] = False
    mfa_evaluated: Literal[False] = False
    domain_authentication_freshness_evaluated: Literal[False] = False
    credential_validity_evaluated: Literal[False] = False
    approval_identity_bound: Literal[False] = False
    approval_freshness_evaluated: Literal[False] = False
    evidence_freshness_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    role_membership_evaluated: Literal[False] = False
    rbac_evaluated: Literal[False] = False
    preflight_evaluated: Literal[False] = False
    receipt_created: Literal[False] = False
    receipt_linked: Literal[False] = False
    current_state_revalidation_evaluated: Literal[False] = False
    persistence_performed: Literal[False] = False
    artifact_write_performed: Literal[False] = False
    publication_performed: Literal[False] = False
    credential_read: Literal[False] = False
    secret_read: Literal[False] = False
    auth_cache_read: Literal[False] = False
    group_membership_evaluated: Literal[False] = False
    privileges_evaluated: Literal[False] = False
    elevation_evaluated: Literal[False] = False
    integrity_level_evaluated: Literal[False] = False
    powershell_executed: Literal[False] = False
    winrm_used: Literal[False] = False
    qga_used: Literal[False] = False
    remote_execution: Literal[False] = False
    subprocess_executed: Literal[False] = False
    shell_executed: Literal[False] = False
    natural_language_execution: Literal[False] = False
    network_call: Literal[False] = False
    model_called: Literal[False] = False
    service_control_executed: Literal[False] = False
    process_termination_executed: Literal[False] = False
    registry_modified: Literal[False] = False
    host_configuration_mutation_performed: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"


def canonical_windows_process_identity_evidence_json(
    value: WindowsProcessIdentityEvidence | Mapping[str, Any],
) -> str:
    model = (
        value
        if isinstance(value, WindowsProcessIdentityEvidence)
        else WindowsProcessIdentityEvidence.model_validate(value)
    )
    return json.dumps(model.model_dump(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_windows_process_identity_evidence_sha256(
    value: WindowsProcessIdentityEvidence | Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        canonical_windows_process_identity_evidence_json(value).encode()
    ).hexdigest()


class NativeTokenError(RuntimeError):
    def __init__(self, phase: str, code: int):
        super().__init__(f"{phase} failed with Windows error {code}")
        self.phase = phase


class NativeTokenAccess(Protocol):
    token_opened: bool
    token_user_evaluated: bool
    token_statistics_evaluated: bool
    sid_conversion_evaluated: bool

    def collect(self) -> tuple[str, int, int, int]: ...


class _WindowsNativeTokenAccess:
    def __init__(self) -> None:
        from ctypes import wintypes

        self.wintypes = wintypes
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self.token_opened = False
        self.token_user_evaluated = False
        self.token_statistics_evaluated = False
        self.sid_conversion_evaluated = False
        self._declare()

    def _declare(self) -> None:
        w = self.wintypes
        self.kernel32.GetCurrentProcess.argtypes = []
        self.kernel32.GetCurrentProcess.restype = w.HANDLE
        self.kernel32.CloseHandle.argtypes = [w.HANDLE]
        self.kernel32.CloseHandle.restype = w.BOOL
        self.kernel32.LocalFree.argtypes = [w.HLOCAL]
        self.kernel32.LocalFree.restype = w.HLOCAL
        self.advapi32.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
        self.advapi32.OpenProcessToken.restype = w.BOOL
        self.advapi32.GetTokenInformation.argtypes = [
            w.HANDLE,
            ctypes.c_int,
            w.LPVOID,
            w.DWORD,
            ctypes.POINTER(w.DWORD),
        ]
        self.advapi32.GetTokenInformation.restype = w.BOOL
        self.advapi32.ConvertSidToStringSidW.argtypes = [w.LPVOID, ctypes.POINTER(w.LPWSTR)]
        self.advapi32.ConvertSidToStringSidW.restype = w.BOOL

    def _query(self, token: Any, info_class: int, phase: str) -> ctypes.Array[Any]:
        w = self.wintypes
        needed = w.DWORD()
        ctypes.set_last_error(0)
        ok = self.advapi32.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
        if ok or ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER or not needed.value:
            raise NativeTokenError(f"{phase}_sizing", ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not self.advapi32.GetTokenInformation(
            token, info_class, buffer, needed, ctypes.byref(needed)
        ):
            raise NativeTokenError(phase, ctypes.get_last_error())
        return buffer

    def collect(self) -> tuple[str, int, int, int]:
        w = self.wintypes

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", w.DWORD), ("HighPart", w.LONG)]

        class TOKEN_STATISTICS_STRUCT(ctypes.Structure):
            _fields_ = [
                ("TokenId", LUID),
                ("AuthenticationId", LUID),
                ("ExpirationTime", ctypes.c_longlong),
                ("TokenType", w.DWORD),
                ("ImpersonationLevel", w.DWORD),
                ("DynamicCharged", w.DWORD),
                ("DynamicAvailable", w.DWORD),
                ("GroupCount", w.DWORD),
                ("PrivilegeCount", w.DWORD),
                ("ModifiedId", LUID),
            ]

        token = w.HANDLE()
        if not self.advapi32.OpenProcessToken(
            self.kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
        ):
            raise NativeTokenError("open_process_token", ctypes.get_last_error())
        self.token_opened = True
        try:
            user = self._query(token, TOKEN_USER, "token_user")
            self.token_user_evaluated = True
            sid_pointer = ctypes.cast(user, ctypes.POINTER(w.LPVOID)).contents.value
            sid_text = w.LPWSTR()
            self.sid_conversion_evaluated = True
            if not sid_pointer or not self.advapi32.ConvertSidToStringSidW(
                sid_pointer, ctypes.byref(sid_text)
            ):
                raise NativeTokenError("sid_conversion", ctypes.get_last_error())
            try:
                sid = sid_text.value or ""
            finally:
                self.kernel32.LocalFree(sid_text)
            statistics_buffer = self._query(token, TOKEN_STATISTICS, "token_statistics")
            self.token_statistics_evaluated = True
            statistics = ctypes.cast(
                statistics_buffer, ctypes.POINTER(TOKEN_STATISTICS_STRUCT)
            ).contents
            return (
                sid,
                int(statistics.AuthenticationId.HighPart),
                int(statistics.AuthenticationId.LowPart),
                int(statistics.TokenType),
            )
        finally:
            self.kernel32.CloseHandle(token)


def _luid(high: int, low: int) -> str:
    return f"{(((high & 0xFFFFFFFF) << 32) | (low & 0xFFFFFFFF)):016x}"


def collect_current_windows_process_identity_evidence(
    *,
    platform: str | None = None,
    native_factory: Callable[[], NativeTokenAccess] = _WindowsNativeTokenAccess,
) -> WindowsProcessIdentityResult:
    """Collect current-process primary-token SID and AuthenticationId evidence."""
    system = (platform or sys.platform).lower()
    if system not in {"win32", "windows"}:
        return WindowsProcessIdentityResult(
            status="unsupported",
            reason="native Windows process-token identity is unsupported on this platform",
            platform=system,
        )
    native: NativeTokenAccess | None = None
    try:
        native = native_factory()
        sid, high, low, token_type = native.collect()
        if token_type != 1:
            return _result(
                native,
                "identity_evidence_invalid",
                "current process token was not a primary token",
                system,
            )
        evidence = WindowsProcessIdentityEvidence(
            principal_sid=sid, authentication_session_luid=_luid(high, low)
        )
        return _result(
            native,
            "identity_evidence_collected",
            "current Windows process primary-token identity collected",
            system,
            evidence,
        )
    except (NativeTokenError, OSError) as exc:
        return _result(
            native, "identity_evidence_unavailable", str(exc)[:200], system, error=str(exc)[:200]
        )
    except Exception as exc:
        return _result(
            native,
            "identity_collection_failed",
            "native process-token identity collection failed",
            system,
            error=type(exc).__name__,
        )


def _result(
    native: NativeTokenAccess | None,
    status: Status,
    reason: str,
    platform: str,
    evidence: WindowsProcessIdentityEvidence | None = None,
    *,
    error: str = "",
) -> WindowsProcessIdentityResult:
    return WindowsProcessIdentityResult(
        status=status,
        reason=reason,
        platform=platform,
        principal_sid=evidence.principal_sid if evidence else "",
        authentication_session_luid=evidence.authentication_session_luid if evidence else "",
        token_type=evidence.token_type if evidence else "",
        identity_evidence_sha256=compute_windows_process_identity_evidence_sha256(evidence)
        if evidence
        else "",
        native_token_open_evaluated=native is not None,
        native_token_opened=bool(native and native.token_opened),
        token_user_evaluated=bool(native and native.token_user_evaluated),
        token_statistics_evaluated=bool(native and native.token_statistics_evaluated),
        sid_conversion_evaluated=bool(native and native.sid_conversion_evaluated),
        os_identity_evaluated=native is not None,
        os_identity_available=evidence is not None,
        errors=(error,) if error else (),
    )
