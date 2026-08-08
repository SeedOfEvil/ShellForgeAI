"""Pure PR304 Windows runtime-integrity packet and evidence-set contract."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

MODE = "windows_runtime_integrity"
CLOCK_SOURCE = "local_system_utc_plus_monotonic"
MAX_CAPTURE_DURATION_MS = 600_000
_UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
ALLOWED_STATUS = frozenset({"ok", "attention", "blocked", "unsupported"})
ALLOWED_CHECK = frozenset({"pass", "attention", "blocked", "not_requested", "unsupported"})
FALSE_KEYS = (
    "natural_language_execution",
    "powershell_executed",
    "winrm_used",
    "qga_used",
    "remote_execution",
    "subprocess_executed",
    "shell_executed",
    "shell_true",
    "arbitrary_command_execution",
    "network_call",
    "model_called",
    "secret_read",
    "auth_cache_read",
    "software_install_executed",
    "software_uninstall_executed",
    "wrapper_modified",
    "file_deleted",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "service_control_executed",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
)
STABLE_PATHS = (
    ("status",),
    ("python_runtime", "executable"),
    ("shellforgeai_import", "module_file"),
    ("shellforgeai_import", "package_root"),
    ("shellforgeai_import", "expected_source_match"),
    ("runtime_context", "resolved"),
    ("runtime_context", "runtime_root"),
    ("runtime_context", "profile_root"),
    ("runtime_context", "source"),
    ("runtime_context", "checked_sources"),
    ("wrapper", "sha256"),
    ("wrapper", "canonical_sha256"),
    ("wrapper", "normalized_text_equal"),
    ("wrapper", "material_match"),
    ("embedded_python", "expected_path"),
    ("embedded_python", "exists"),
    ("entrypoint", "path"),
    ("entrypoint", "exists"),
    ("invalid_distribution_residue", "matches"),
    ("invalid_distribution_residue", "residue_count"),
)
EVIDENCE_WARNINGS = (
    "evidence-set identity is not evidence freshness",
    "collector-owned capture chronology is not authenticated or externally trusted",
    "local system UTC may be wrong and no clock synchronization is checked",
    "monotonic duration proves only local elapsed collection duration",
    "state may already have changed",
    "packet role labels are caller-assigned and not authenticated",
    "PR304 packet status is an evidence fact, not authorization",
    "the PR304 packets and evidence set were not persisted",
)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Pr304PacketValidationResult(_Frozen):
    status: Literal["packet_valid", "packet_invalid", "invalid_packet_input"]
    packet_valid: bool = False
    packet_identity_sha256: str = ""
    packet_status: str = ""
    platform_system: str = ""
    capture_chronology_available: bool = False
    capture_chronology_valid: bool = False
    capture_started_at_utc: str = ""
    capture_completed_at_utc: str = ""
    capture_duration_ms: int | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = EVIDENCE_WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False


class Pr304EvidenceObservation(_Frozen):
    role: Literal["source_root_observation", "system32_observation"]
    packet_identity_sha256: str
    packet_mode: Literal["windows_runtime_integrity"] = MODE
    packet_status: str
    platform_system: str
    capture_chronology_available: bool
    capture_chronology_valid: bool
    capture_started_at_utc: str = ""
    capture_completed_at_utc: str = ""
    capture_duration_ms: int | None = None


class Pr304RuntimeIntegrityEvidenceSet(_Frozen):
    schema_version: Literal[1] = 1
    evidence_set_type: Literal["pr304_windows_runtime_integrity_two_packet_evidence_set"] = (
        "pr304_windows_runtime_integrity_two_packet_evidence_set"
    )
    comparison_scope: Literal["exact_ordered_source_root_and_system32_packets"] = (
        "exact_ordered_source_root_and_system32_packets"
    )
    source_root_observation: Pr304EvidenceObservation
    system32_observation: Pr304EvidenceObservation
    stable_field_comparison_evaluated: Literal[True] = True
    stable_fields_consistent: bool
    stable_field_mismatches: tuple[str, ...] = ()
    capture_chronology_evaluated: Literal[True] = True
    capture_chronology_available: bool
    capture_chronology_valid: bool
    earliest_capture_started_at_utc: str = ""
    latest_capture_completed_at_utc: str = ""
    combined_capture_span_ms: int | None = None


class Pr304EvidenceSetPreparationResult(_Frozen):
    status: Literal["evidence_set_prepared", "evidence_set_invalid", "evidence_set_inconsistent"]
    reason: str = ""
    evidence_packets_validated: bool = False
    evidence_set_prepared: bool = False
    evidence_set: Pr304RuntimeIntegrityEvidenceSet | None = None
    source_root_packet_identity_sha256: str = ""
    system32_packet_identity_sha256: str = ""
    evidence_set_identity_sha256: str = ""
    stable_field_comparison_evaluated: bool = False
    stable_fields_consistent: bool = False
    stable_field_mismatches: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = EVIDENCE_WARNINGS
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    pr304_packets_persisted: Literal[False] = False
    evidence_set_persisted: Literal[False] = False
    evidence_freshness_evaluated: Literal[False] = False
    authorization_evaluated: Literal[False] = False
    execution_allowed: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"


def _sorted(errors: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(set(errors)))


def canonical_packet_json(packet: Mapping[str, Any]) -> str:
    return json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_packet_identity_sha256(packet: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_packet_json(packet).encode("utf-8")).hexdigest()


def _get(obj: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(key)
    return cur


def _expected_status(payload: Mapping[str, Any]) -> str:
    checks = payload.get("checks", [])
    platform = payload.get("platform", {})
    if not isinstance(platform, Mapping) or platform.get("system") != "windows":
        return "unsupported"
    states = {item.get("status") for item in checks if isinstance(item, Mapping)}
    if "blocked" in states:
        return "blocked"
    if states & {"attention", "not_requested"}:
        return "attention"
    return "ok"


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_PATTERN.fullmatch(value) is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None


def _observation_errors(payload: Mapping[str, Any]) -> list[str]:
    observation = payload.get("observation")
    if observation is None:
        return []  # Explicit compatibility path for exact pre-PR340 packets.
    if not isinstance(observation, Mapping):
        return ["observation must be an object"]
    required = {
        "capture_started_at_utc",
        "capture_completed_at_utc",
        "capture_duration_ms",
        "clock_source",
    }
    errors: list[str] = []
    if set(observation) != required:
        errors.append("observation must contain exactly the required fields")
    started = _parse_utc(observation.get("capture_started_at_utc"))
    completed = _parse_utc(observation.get("capture_completed_at_utc"))
    if started is None:
        errors.append("capture_started_at_utc must be canonical UTC")
    if completed is None:
        errors.append("capture_completed_at_utc must be canonical UTC")
    if started is not None and completed is not None and completed < started:
        errors.append("capture completion must not precede capture start")
    duration = observation.get("capture_duration_ms")
    if isinstance(duration, bool) or not isinstance(duration, int):
        errors.append("capture_duration_ms must be an integer")
    elif duration < 0 or duration > MAX_CAPTURE_DURATION_MS:
        errors.append(f"capture_duration_ms must be between 0 and {MAX_CAPTURE_DURATION_MS}")
    if observation.get("clock_source") != CLOCK_SOURCE:
        errors.append(f"clock_source must be {CLOCK_SOURCE}")
    return errors


def packet_validation_errors(
    payload: Mapping[str, Any], expect_status: str | None = None
) -> list[str]:
    """Return the maintained PR304 errors in their legacy deterministic order."""
    errors: list[str] = []
    errors.extend(_observation_errors(payload))
    if payload.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if payload.get("mode") != MODE:
        errors.append("mode must be windows_runtime_integrity")
    status = payload.get("status")
    if status not in ALLOWED_STATUS:
        errors.append("invalid top-level status")
    if expect_status and status != expect_status:
        errors.append(f"expected status {expect_status}, got {status}")
    checks = payload.get("checks")
    if not isinstance(checks, list) or not all(isinstance(item, Mapping) for item in checks):
        errors.append("checks must be a list of objects")
        checks = []
    states = [item.get("status") for item in checks]
    if any(state not in ALLOWED_CHECK for state in states):
        errors.append("invalid check status")
    summary = payload.get("summary")
    if not isinstance(summary, Mapping):
        errors.append("summary must be an object")
    else:
        for state in ALLOWED_CHECK:
            if summary.get(state, 0) != states.count(state):
                errors.append(f"summary count mismatch for {state}")
    if status in ALLOWED_STATUS and status != _expected_status(payload):
        errors.append("top-level status precedence is incorrect")
    if payload.get("read_only") is not True or payload.get("mutation_performed") is not False:
        errors.append("top-level read-only/mutation flags are unsafe")
    safety = payload.get("safety")
    if (
        not isinstance(safety, Mapping)
        or safety.get("read_only") is not True
        or safety.get("mutation_performed") is not False
    ):
        errors.append("safety block read-only/mutation flags are unsafe")
    else:
        for key in FALSE_KEYS:
            if safety.get(key) is not False:
                errors.append(f"unsafe safety flag: {key}")
    first = payload.get("first_safe_command")
    if not isinstance(first, str) or not first.strip():
        errors.append("first_safe_command is missing")
    elif any(
        bad in first.casefold()
        for bad in (" pip ", "install", "cleanup", "delete", "remove", "powershell")
    ):
        errors.append("first_safe_command appears mutating or executes wrapper")
    platform = payload.get("platform", {})
    system = platform.get("system") if isinstance(platform, Mapping) else None
    if status == "unsupported" and system == "windows":
        errors.append("unsupported artifact claims Windows platform")
    if status == "blocked" and "blocked" not in states:
        errors.append("blocked artifact lacks blocked check")
    if status == "attention" and (
        "blocked" in states or not ({"attention", "not_requested"} & set(states))
    ):
        errors.append("attention artifact state mismatch")
    if status == "ok" and ({"blocked", "attention", "not_requested", "unsupported"} & set(states)):
        errors.append("ok artifact has non-pass checks")
    return errors


def validate_windows_runtime_integrity_packet(
    payload: Any, expect_status: str | None = None
) -> Pr304PacketValidationResult:
    if not isinstance(payload, Mapping):
        return Pr304PacketValidationResult(
            status="invalid_packet_input", errors=("packet must be a mapping",)
        )
    try:
        identity = compute_packet_identity_sha256(payload)
    except (TypeError, ValueError):
        return Pr304PacketValidationResult(
            status="invalid_packet_input", errors=("packet must be canonicalizable JSON",)
        )
    errors = packet_validation_errors(payload, expect_status)
    platform = payload.get("platform", {})
    observation = payload.get("observation")
    chronology_available = isinstance(observation, Mapping)
    chronology_valid = chronology_available and not _observation_errors(payload)
    return Pr304PacketValidationResult(
        status="packet_invalid" if errors else "packet_valid",
        packet_valid=not errors,
        packet_identity_sha256=identity,
        packet_status=payload.get("status") if isinstance(payload.get("status"), str) else "",
        platform_system=platform.get("system")
        if isinstance(platform, Mapping) and isinstance(platform.get("system"), str)
        else "",
        capture_chronology_available=chronology_available,
        capture_chronology_valid=chronology_valid,
        capture_started_at_utc=observation.get("capture_started_at_utc", "")
        if isinstance(observation, Mapping)
        else "",
        capture_completed_at_utc=observation.get("capture_completed_at_utc", "")
        if isinstance(observation, Mapping)
        else "",
        capture_duration_ms=observation.get("capture_duration_ms") if chronology_valid else None,
        errors=_sorted(errors),
    )


def compare_stable_fields(payloads: Sequence[Mapping[str, Any]]) -> list[str]:
    if len(payloads) < 2:
        return []
    errors: list[str] = []
    for index, payload in enumerate(payloads[1:], start=2):
        for path in STABLE_PATHS:
            if _get(payloads[0], path) != _get(payload, path):
                errors.append(f"artifact {index} stable field mismatch: {'.'.join(path)}")
    return errors


def canonical_evidence_set_json(value: Pr304RuntimeIntegrityEvidenceSet | Mapping[str, Any]) -> str:
    model = (
        value
        if isinstance(value, Pr304RuntimeIntegrityEvidenceSet)
        else Pr304RuntimeIntegrityEvidenceSet.model_validate(value)
    )
    return json.dumps(
        model.model_dump(mode="python"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def compute_evidence_set_identity_sha256(
    value: Pr304RuntimeIntegrityEvidenceSet | Mapping[str, Any],
) -> str:
    return hashlib.sha256(canonical_evidence_set_json(value).encode("utf-8")).hexdigest()


def prepare_pr304_runtime_integrity_evidence_set(
    source_root_packet: Any, system32_packet: Any
) -> Pr304EvidenceSetPreparationResult:
    source = validate_windows_runtime_integrity_packet(source_root_packet)
    system32 = validate_windows_runtime_integrity_packet(system32_packet)
    errors = [
        *(f"source_root: {e}" for e in source.errors),
        *(f"system32: {e}" for e in system32.errors),
    ]
    if errors:
        return Pr304EvidenceSetPreparationResult(
            status="evidence_set_invalid",
            reason="one or both PR304 packets are invalid",
            source_root_packet_identity_sha256=source.packet_identity_sha256,
            system32_packet_identity_sha256=system32.packet_identity_sha256,
            errors=_sorted(errors),
        )
    mismatches = compare_stable_fields([source_root_packet, system32_packet])
    chronology_available = (
        source.capture_chronology_available and system32.capture_chronology_available
    )
    chronology_valid = source.capture_chronology_valid and system32.capture_chronology_valid
    starts = (
        [source.capture_started_at_utc, system32.capture_started_at_utc] if chronology_valid else []
    )
    completions = (
        [source.capture_completed_at_utc, system32.capture_completed_at_utc]
        if chronology_valid
        else []
    )
    earliest = min(starts) if starts else ""
    latest = max(completions) if completions else ""
    span_ms = (
        int((_parse_utc(latest) - _parse_utc(earliest)).total_seconds() * 1000)
        if chronology_valid
        else None
    )
    evidence = Pr304RuntimeIntegrityEvidenceSet(
        source_root_observation=Pr304EvidenceObservation(
            role="source_root_observation",
            packet_identity_sha256=source.packet_identity_sha256,
            packet_status=source.packet_status,
            platform_system=source.platform_system,
            capture_chronology_available=source.capture_chronology_available,
            capture_chronology_valid=source.capture_chronology_valid,
            capture_started_at_utc=source.capture_started_at_utc,
            capture_completed_at_utc=source.capture_completed_at_utc,
            capture_duration_ms=source.capture_duration_ms,
        ),
        system32_observation=Pr304EvidenceObservation(
            role="system32_observation",
            packet_identity_sha256=system32.packet_identity_sha256,
            packet_status=system32.packet_status,
            platform_system=system32.platform_system,
            capture_chronology_available=system32.capture_chronology_available,
            capture_chronology_valid=system32.capture_chronology_valid,
            capture_started_at_utc=system32.capture_started_at_utc,
            capture_completed_at_utc=system32.capture_completed_at_utc,
            capture_duration_ms=system32.capture_duration_ms,
        ),
        stable_fields_consistent=not mismatches,
        stable_field_mismatches=_sorted(mismatches),
        capture_chronology_available=chronology_available,
        capture_chronology_valid=chronology_valid,
        earliest_capture_started_at_utc=earliest,
        latest_capture_completed_at_utc=latest,
        combined_capture_span_ms=span_ms,
    )
    identity = compute_evidence_set_identity_sha256(evidence)
    return Pr304EvidenceSetPreparationResult(
        status="evidence_set_inconsistent" if mismatches else "evidence_set_prepared",
        reason="stable PR304 fields differ"
        if mismatches
        else "the exact ordered PR304 evidence set is structurally valid",
        evidence_packets_validated=True,
        evidence_set_prepared=True,
        evidence_set=evidence,
        source_root_packet_identity_sha256=source.packet_identity_sha256,
        system32_packet_identity_sha256=system32.packet_identity_sha256,
        evidence_set_identity_sha256=identity,
        stable_field_comparison_evaluated=True,
        stable_fields_consistent=not mismatches,
        stable_field_mismatches=_sorted(mismatches),
        errors=_sorted(mismatches),
    )
