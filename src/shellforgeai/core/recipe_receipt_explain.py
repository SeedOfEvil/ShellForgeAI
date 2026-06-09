"""Deterministic governed recipe receipt finding explanations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shellforgeai.core.recipe_receipt_audit import (
    audit_safety,
    receipt_audit,
    receipt_integrity,
)

EXPLAIN_MODE = "v2_recipe_receipt_finding_explain"
EXPLAIN_SOURCES = {"integrity", "audit", "audit-bundle", "compare"}
_SEVERITIES = {"info", "warning", "failed", "blocked"}


@dataclass(frozen=True)
class FindingExplanation:
    code: str
    title: str
    severity: str
    meaning: str
    why_it_matters: str
    safe_next_commands: tuple[str, ...]
    not_performed: tuple[str, ...] = (
        "No repair was attempted.",
        "No artifact was deleted.",
        "No recipe/recovery/rollback was executed.",
    )


def _cmds(*commands: str) -> tuple[str, ...]:
    return commands


_COMMON_NEXT = _cmds(
    "shellforgeai recipes receipt integrity --json",
    "shellforgeai recipes receipt audit --json",
    "shellforgeai recipes receipt history --json",
)
_INTEGRITY_NEXT = _cmds(
    "shellforgeai recipes receipt integrity --include-exports --include-audit-bundles --json",
)
_VALIDATE_NEXT = _cmds(
    "shellforgeai recipes receipt integrity --include-exports --include-audit-bundles --json",
    "shellforgeai recipes receipt audit-bundle-validate <bundle_id> --json",
    "shellforgeai recipes receipt export-validate <export_id> --json",
)
_AUDIT_NEXT = _cmds(
    "shellforgeai recipes receipt audit --json",
    "shellforgeai recipes receipt inspect <receipt_id> --json",
    "shellforgeai verify --receipt <receipt_id> --json",
)
_COMPARE_NEXT = _cmds(
    "shellforgeai recipes receipt compare <before> <after> --json",
    "shellforgeai recipes receipt audit --json",
)


EXPLANATIONS: dict[str, FindingExplanation] = {
    "malformed_json": FindingExplanation(
        "malformed_json",
        "Malformed JSON",
        "failed",
        "A ShellForgeAI-owned receipt or artifact JSON file could not be parsed.",
        "The artifact may be incomplete, edited incorrectly, or copied with truncation.",
        _INTEGRITY_NEXT,
    ),
    "missing_required_file": FindingExplanation(
        "missing_required_file",
        "Missing required file",
        "failed",
        "An owned receipt/export/bundle is missing a required manifest-contract file.",
        "Validation cannot prove the artifact is complete when required files are absent.",
        _VALIDATE_NEXT,
    ),
    "checksum_mismatch": FindingExplanation(
        "checksum_mismatch",
        "Checksum mismatch",
        "failed",
        "A file checksum recorded in a manifest does not match the current file content.",
        "The artifact may have been edited, truncated, copied incorrectly, or corrupted.",
        _VALIDATE_NEXT,
    ),
    "missing_manifest": FindingExplanation(
        "missing_manifest",
        "Missing manifest",
        "failed",
        "An owned export or audit bundle is missing its manifest file.",
        "Without the manifest, ShellForgeAI cannot verify the artifact inventory.",
        _VALIDATE_NEXT,
    ),
    "missing_checksums": FindingExplanation(
        "missing_checksums",
        "Missing checksums",
        "failed",
        "An owned export or audit bundle is missing checksums.json.",
        "Without recorded checksums, integrity drift cannot be confirmed locally.",
        _VALIDATE_NEXT,
    ),
    "unsupported_artifact": FindingExplanation(
        "unsupported_artifact",
        "Unsupported artifact",
        "warning",
        "An owned artifact shape was not recognized as a supported governed receipt/export/bundle.",
        "Unsupported shapes may not carry the receipt safety fields ShellForgeAI expects.",
        _COMMON_NEXT,
    ),
    "unsupported_receipt": FindingExplanation(
        "unsupported_receipt",
        "Unsupported receipt",
        "warning",
        "A receipt uses an unsupported mode, schema, or recipe id for governed receipt auditing.",
        "ShellForgeAI cannot apply the governed audit assumptions to unsupported receipts.",
        _AUDIT_NEXT,
    ),
    "missing_original_receipt": FindingExplanation(
        "missing_original_receipt",
        "Missing original receipt",
        "failed",
        "A recovery receipt points to an original receipt that is not present locally.",
        "The recovery chain cannot be audited end-to-end without the original governed receipt.",
        _AUDIT_NEXT,
    ),
    "verification_failed": FindingExplanation(
        "verification_failed",
        "Verification failed",
        "failed",
        "A governed receipt records a failed verification status.",
        "The recorded post-check evidence did not satisfy the receipt verification contract.",
        _AUDIT_NEXT,
    ),
    "safety_drift": FindingExplanation(
        "safety_drift",
        "Safety drift recorded",
        "blocked",
        "A receipt or compare result shows a safety flag outside the expected false state.",
        "Safety drift records behavior requiring operator review before trust.",
        _AUDIT_NEXT,
    ),
    "production_restart_recorded": FindingExplanation(
        "production_restart_recorded",
        "Production restart recorded",
        "blocked",
        "A receipt records that a production restart safety flag was true.",
        "Governed disposable restart receipts should stay outside production restart lanes.",
        _AUDIT_NEXT,
    ),
    "docker_compose_executed_recorded": FindingExplanation(
        "docker_compose_executed_recorded",
        "Docker Compose execution recorded",
        "blocked",
        "A receipt records Docker Compose execution where governed receipt audit expected none.",
        "This finding requires review because receipt explain never authorizes Compose mutation.",
        _AUDIT_NEXT,
    ),
    "shell_true_recorded": FindingExplanation(
        "shell_true_recorded",
        "shell=True recorded",
        "blocked",
        "A receipt records shell=True execution.",
        "Governed receipt flows require argv-based narrow actions, not shell execution.",
        _AUDIT_NEXT,
    ),
    "arbitrary_command_execution_recorded": FindingExplanation(
        "arbitrary_command_execution_recorded",
        "Arbitrary command execution recorded",
        "blocked",
        "A receipt records arbitrary command execution.",
        "Broad command execution is outside the governed recipe safety boundary.",
        _AUDIT_NEXT,
    ),
    "natural_language_execution_recorded": FindingExplanation(
        "natural_language_execution_recorded",
        "Natural-language execution recorded",
        "blocked",
        "A receipt records natural-language execution.",
        "Natural language is not an execution lane in ShellForgeAI governed recipes.",
        _AUDIT_NEXT,
    ),
    "container_restarted_recorded": FindingExplanation(
        "container_restarted_recorded",
        "Container restart recorded",
        "warning",
        "A receipt records a container restart as historical evidence.",
        "This is audit evidence only; explain does not restart or re-run the target.",
        _AUDIT_NEXT,
    ),
    "recovery_receipt_without_original": FindingExplanation(
        "recovery_receipt_without_original",
        "Recovery receipt without original",
        "failed",
        "A recovery receipt exists without the original governed receipt available locally.",
        "The chain cannot be inspected or compared completely without the original receipt.",
        _AUDIT_NEXT,
    ),
    "export_checksum_failed": FindingExplanation(
        "export_checksum_failed",
        "Receipt export checksum failed",
        "failed",
        "A receipt export checksum validation failed.",
        "The export may have changed after creation or copied incompletely.",
        _cmds("shellforgeai recipes receipt export-validate <export_id> --json", *_INTEGRITY_NEXT),
    ),
    "audit_bundle_checksum_failed": FindingExplanation(
        "audit_bundle_checksum_failed",
        "Audit bundle checksum failed",
        "failed",
        "A receipt audit bundle checksum validation failed.",
        "The support packet may have changed after creation or copied incompletely.",
        _cmds(
            "shellforgeai recipes receipt audit-bundle-validate <bundle_id> --json",
            *_INTEGRITY_NEXT,
        ),
    ),
    "audit_bundle_missing_file": FindingExplanation(
        "audit_bundle_missing_file",
        "Audit bundle missing file",
        "failed",
        "A receipt audit bundle is missing a required support packet file.",
        "Support handoff cannot rely on an incomplete audit bundle.",
        _cmds(
            "shellforgeai recipes receipt audit-bundle-validate <bundle_id> --json",
            *_INTEGRITY_NEXT,
        ),
    ),
    "receipt_export_missing_file": FindingExplanation(
        "receipt_export_missing_file",
        "Receipt export missing file",
        "failed",
        "A receipt export is missing a required file.",
        "The exported receipt evidence may be incomplete.",
        _cmds("shellforgeai recipes receipt export-validate <export_id> --json", *_INTEGRITY_NEXT),
    ),
    "receipt_type_changed": FindingExplanation(
        "receipt_type_changed",
        "Receipt type changed",
        "warning",
        "Compare found that receipt type changed between artifacts.",
        "A type change may indicate the comparison spans execution and recovery receipts.",
        _COMPARE_NEXT,
    ),
    "status_changed": FindingExplanation(
        "status_changed",
        "Status changed",
        "warning",
        "Compare found that receipt status changed between artifacts.",
        "A status change can affect whether downstream verification should trust the artifact.",
        _COMPARE_NEXT,
    ),
    "verification_status_changed": FindingExplanation(
        "verification_status_changed",
        "Verification status changed",
        "warning",
        "Compare found that verification status changed between artifacts.",
        "Verification changes should be reviewed before using receipts as evidence.",
        _COMPARE_NEXT,
    ),
    "target_changed": FindingExplanation(
        "target_changed",
        "Target changed",
        "warning",
        "Compare found that the recorded target changed.",
        "A target change means the receipts may not describe the same governed object.",
        _COMPARE_NEXT,
    ),
    "recipe_changed": FindingExplanation(
        "recipe_changed",
        "Recipe changed",
        "warning",
        "Compare found that the recipe id changed.",
        "Recipe changes alter the assumptions used for receipt interpretation.",
        _COMPARE_NEXT,
    ),
    "action_argv_changed": FindingExplanation(
        "action_argv_changed",
        "Action argv changed",
        "warning",
        "Compare found that the recorded action argv changed.",
        "Argument drift may change what the governed recipe actually recorded.",
        _COMPARE_NEXT,
    ),
    "safety_flag_changed": FindingExplanation(
        "safety_flag_changed",
        "Safety flag changed",
        "blocked",
        "Compare found that one or more safety flags changed.",
        "Safety flag changes require local audit before trusting the newer artifact.",
        _COMPARE_NEXT,
    ),
    "safety_drift_detected": FindingExplanation(
        "safety_drift_detected",
        "Safety drift detected",
        "blocked",
        "Compare or audit detected a safety flag outside the expected state.",
        "Safety drift requires review and is not repaired automatically.",
        _COMPARE_NEXT,
    ),
    "stable_no_change": FindingExplanation(
        "stable_no_change",
        "Stable: no change",
        "info",
        "Compare did not find a relevant change for this category.",
        "Stable compare output can be kept as audit evidence without taking action.",
        _COMPARE_NEXT,
        (
            "No mutation was attempted.",
            "No receipt was rerun.",
            "No recipe/recovery/rollback was executed.",
        ),
    ),
    "no_receipts_found": FindingExplanation(
        "no_receipts_found",
        "No receipts found",
        "info",
        "No governed recipe receipts were found for the selected source or filters.",
        "There is no local receipt evidence to explain yet.",
        _cmds("shellforgeai recipes receipt history --json"),
        ("No artifact was created.", "No recipe was executed.", "No model was called."),
    ),
    "no_matching_target": FindingExplanation(
        "no_matching_target",
        "No matching target",
        "info",
        "No governed receipts matched the requested target filter.",
        "The filter may be too narrow or the receipt may not be present locally.",
        _cmds(
            "shellforgeai recipes receipt audit --json",
            "shellforgeai recipes receipt history --json",
        ),
    ),
    "no_matching_recipe": FindingExplanation(
        "no_matching_recipe",
        "No matching recipe",
        "info",
        "No governed receipts matched the requested recipe filter.",
        "The filter may be too narrow or the receipt may not be present locally.",
        _cmds(
            "shellforgeai recipes receipt audit --json",
            "shellforgeai recipes receipt history --json",
        ),
    ),
    "no_findings": FindingExplanation(
        "no_findings",
        "No findings",
        "info",
        "No governed receipt findings require action for the selected source and filters.",
        "No integrity or safety drift signal was present in the local evidence ShellForgeAI read.",
        _COMMON_NEXT,
        ("No repair was attempted.", "No artifact was deleted.", "No command was executed."),
    ),
}

_ALIASES = {
    "malformed_receipt": "malformed_json",
    "receipt_validation_warning": "verification_failed",
    "unsupported_recipe": "unsupported_receipt",
    "no_safety_drift": "no_findings",
    "no_production_restart": "no_findings",
    "recovery_links_original": "no_findings",
    "required_file": "missing_required_file",
    "json_parse": "malformed_json",
    "checksum": "checksum_mismatch",
    "linkage": "missing_original_receipt",
    "missing original receipt": "missing_original_receipt",
}

_SAFETY_FIELD_TO_CODE = {
    "production_restart_executed": "production_restart_recorded",
    "docker_compose_executed": "docker_compose_executed_recorded",
    "shell_true": "shell_true_recorded",
    "arbitrary_command_execution": "arbitrary_command_execution_recorded",
    "natural_language_execution": "natural_language_execution_recorded",
    "container_restarted": "container_restarted_recorded",
}

_COMPARE_FIELD_TO_CODE = {
    "receipt_type": "receipt_type_changed",
    "status": "status_changed",
    "verification_status": "verification_status_changed",
    "target": "target_changed",
    "recipe_id": "recipe_changed",
    "action_argv": "action_argv_changed",
}


def known_finding_codes() -> tuple[str, ...]:
    return tuple(sorted(EXPLANATIONS))


def explain_safety() -> dict[str, bool]:
    safety = audit_safety()
    safety.update(
        {
            "repair_attempted": False,
            "artifact_deleted": False,
        }
    )
    return safety


def _normalize_code(code: str) -> str:
    normalized = "_".join(re.findall(r"[a-z0-9]+", (code or "").lower()))
    return _ALIASES.get(normalized, normalized)


def _finding_codes_from_integrity(payload: dict[str, Any]) -> list[str]:
    codes: list[str] = []
    for finding in payload.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        artifact_type = str(finding.get("artifact_type") or "")
        check = str(finding.get("check") or "")
        msg = str(finding.get("message") or "").lower()
        code = _normalize_code(check)
        if "checksum" in msg:
            code = "checksum_mismatch"
            if artifact_type == "receipt_export":
                code = "export_checksum_failed"
            if artifact_type == "audit_bundle":
                code = "audit_bundle_checksum_failed"
        elif "missing manifest" in msg or "manifest" in msg and "missing" in msg:
            code = "missing_manifest"
        elif "checksums" in msg and "missing" in msg:
            code = "missing_checksums"
        elif "missing required" in msg or "missing file" in msg:
            code = "missing_required_file"
            if artifact_type == "receipt_export":
                code = "receipt_export_missing_file"
            if artifact_type == "audit_bundle":
                code = "audit_bundle_missing_file"
        elif "malformed" in msg:
            code = "malformed_json"
        elif "unsupported" in msg:
            code = "unsupported_artifact"
        elif "missing original" in msg:
            code = "missing_original_receipt"
        for field, mapped in _SAFETY_FIELD_TO_CODE.items():
            if field in msg:
                code = mapped
        codes.append(code)
    return codes


def _finding_codes_from_audit(payload: dict[str, Any]) -> list[str]:
    status = payload.get("status")
    if status == "empty":
        return ["no_receipts_found"]
    if status == "no_matches":
        filters = payload.get("filters") if isinstance(payload.get("filters"), dict) else {}
        if filters.get("target"):
            return ["no_matching_target"]
        if filters.get("recipe_id"):
            return ["no_matching_recipe"]
        return ["no_receipts_found"]
    codes: list[str] = []
    for finding in payload.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        raw = str(finding.get("kind") or finding.get("code") or "")
        msg = str(finding.get("message") or "").lower()
        code = _normalize_code(raw)
        for field, mapped in _SAFETY_FIELD_TO_CODE.items():
            if field in msg:
                code = mapped
        if code != "no_findings":
            codes.append(code)
    return codes


def _manual_compare_codes() -> list[str]:
    return []


def _unique(codes: list[str]) -> list[str]:
    out: list[str] = []
    for code in codes:
        normalized = _normalize_code(code)
        if normalized and normalized not in out:
            out.append(normalized)
    return out


def _explanation_dict(code: str) -> dict[str, Any]:
    normalized = _normalize_code(code)
    item = EXPLANATIONS.get(normalized)
    if item is None:
        return {
            "code": code,
            "title": "Unknown finding",
            "severity": "warning",
            "meaning": "ShellForgeAI has no deterministic explanation for this finding code yet.",
            "why_it_matters": "Run the read-only integrity scan to collect current local evidence.",
            "safe_next_commands": ["shellforgeai recipes receipt integrity --json"],
            "not_performed": [
                "No repair was attempted.",
                "No artifact was deleted.",
                "No recipe/recovery/rollback was executed.",
            ],
        }
    return {
        "code": item.code,
        "title": item.title,
        "severity": item.severity if item.severity in _SEVERITIES else "warning",
        "meaning": item.meaning,
        "why_it_matters": item.why_it_matters,
        "safe_next_commands": list(item.safe_next_commands),
        "not_performed": list(item.not_performed),
    }


def _summary(explanations: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "findings_explained": len(explanations),
        "info": 0,
        "warnings": 0,
        "failed": 0,
        "blocked": 0,
    }
    for item in explanations:
        sev = item.get("severity")
        if sev == "info":
            summary["info"] += 1
        elif sev == "warning":
            summary["warnings"] += 1
        elif sev == "failed":
            summary["failed"] += 1
        elif sev == "blocked":
            summary["blocked"] += 1
    return summary


def receipt_explain(
    data_dir: Path | str,
    *,
    source: str = "integrity",
    finding: str | None = None,
    target: str | None = None,
    recipe_id: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Explain governed receipt finding codes without executing or mutating anything."""
    normalized_source = (source or "integrity").strip().lower()
    warnings: list[str] = []
    if normalized_source not in EXPLAIN_SOURCES:
        warnings.append(f"unsupported source '{source}'; using integrity")
        normalized_source = "integrity"

    if finding:
        codes = [_normalize_code(finding)]
        source_for_payload = "manual"
    elif normalized_source == "audit":
        source_payload = receipt_audit(
            data_dir, target=target, recipe_id=recipe_id, limit=limit, include_compare_summary=True
        )
        codes = _finding_codes_from_audit(source_payload)
        warnings.extend(str(w) for w in source_payload.get("warnings") or [])
        source_for_payload = normalized_source
    elif normalized_source == "audit-bundle":
        source_payload = receipt_integrity(
            data_dir,
            target=target,
            recipe_id=recipe_id,
            limit=limit,
            include_exports=False,
            include_audit_bundles=True,
        )
        codes = [c for c in _finding_codes_from_integrity(source_payload) if "audit_bundle" in c]
        warnings.extend(str(w) for w in source_payload.get("warnings") or [])
        source_for_payload = normalized_source
    elif normalized_source == "compare":
        codes = _manual_compare_codes()
        source_for_payload = normalized_source
    else:
        source_payload = receipt_integrity(
            data_dir,
            target=target,
            recipe_id=recipe_id,
            limit=limit,
            include_exports=True,
            include_audit_bundles=True,
        )
        codes = _finding_codes_from_integrity(source_payload)
        warnings.extend(str(w) for w in source_payload.get("warnings") or [])
        source_for_payload = normalized_source

    codes = _unique(codes)
    if not codes:
        codes = ["no_findings"]
    explanations = [_explanation_dict(code) for code in codes]
    unknown = bool(finding and _normalize_code(finding) not in EXPLANATIONS)
    if unknown:
        status = "unknown_finding"
    elif all(item.get("code") == "no_findings" for item in explanations):
        status = "no_findings"
    else:
        status = "ok"
    return {
        "schema_version": 1,
        "mode": EXPLAIN_MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "source": source_for_payload,
        "filters": {
            "target": target or None,
            "recipe_id": recipe_id or None,
            "limit": int(limit),
            "finding": finding or None,
        },
        "summary": _summary(explanations),
        "explanations": explanations,
        "first_safe_command": "shellforgeai recipes receipt integrity --json",
        "safe_next_commands": list(_COMMON_NEXT),
        "warnings": list(dict.fromkeys(warnings)),
        "safety": explain_safety(),
    }
