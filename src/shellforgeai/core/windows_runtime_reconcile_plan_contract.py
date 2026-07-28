"""Pure maintained Windows runtime-reconcile plan contract (PR305/PR313 seam).

The rules in this module are not new. They are the exact saved-packet rules that
already governed the ``windows.runtime_reconcile`` lane, previously expressed in
exactly two places:

* ``scripts/windows_runtime_reconcile_acceptance.py`` — the maintained PR305
  saved-packet acceptance validator (``errs`` and ``parent_errs``);
* ``src/shellforgeai/core/windows_runtime_reconcile_execution.py`` — the
  maintained PR313 canonical plan identity plus the narrower executable-plan
  contract (``_plan_contract_errors``).

Both of those consumers now delegate here, so the algorithms live in exactly one
place and no consumer may drift from another. Nothing was widened, narrowed, or
reordered in the move: the acceptance validator still returns the same failures
for the same packets, and PR313 still accepts and refuses exactly what it did.

**This module is pure.** It holds constants, canonicalization, SHA-256 identity,
structural validation, and one immutable result model. It performs no
filesystem access, no current-state evaluation, no preparation, no backup, no
atomic replacement, no compensation, no receipt handling, no verification, no
subprocess, no shell, no network, no clock read, no environment read, and no
mutation of any kind. It never inspects a staged source root, a durable runtime
root, ``System32``, or any host path: it evaluates only the mapping it is
handed, and it never mutates that mapping.

Validating a packet here means only that the packet is structurally the exact
maintained plan. It is not authorization, not current-state preflight, not
evidence freshness, not receipt linkage, and not execution eligibility.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

#: The exact saved-packet schema version.
PLAN_SCHEMA_VERSION = 1

#: The exact saved-packet mode and recipe ID.
PLAN_MODE = "windows_runtime_reconcile"
RECIPE_ID = "windows.runtime_reconcile"

#: The complete, fixed, ordered two-file allowlist. Nothing else is reachable,
#: and no widening, reordering, glob, prefix, alias, or caller-supplied mapping
#: exists.
ALLOWLIST: tuple[tuple[str, str], ...] = (
    ("config/profiles/inspect.yaml", "config/profiles/inspect.yaml"),
    ("scripts/windows/sfai.cmd", "bin/sfai.cmd"),
)

#: Every status a saved PR305 packet may carry.
PLAN_STATUSES: tuple[str, ...] = ("ready", "no_change", "blocked", "unsupported")

#: The only statuses a saved packet may carry and still describe an executable
#: plan. ``no_change`` is accepted because it is still the exact validated plan
#: identity for the observed state; it grants no execution eligibility.
ACCEPTED_PLAN_STATUSES: tuple[str, ...] = ("ready", "no_change")

#: Every operation a saved packet may record.
PLAN_OPERATIONS: tuple[str, ...] = (
    "no_change",
    "create_required",
    "replace_required",
    "blocked",
)

#: The operations an accepted saved packet may record. ``blocked`` is absent.
SAVED_OPERATIONS: tuple[str, ...] = ("no_change", "create_required", "replace_required")

#: Exact fixed destination-parent contract.
#:
#: Only the inspect-profile destination may have its parent chain created, and
#: only the exact ``config`` / ``config/profiles`` components beneath an
#: already-existing durable runtime root. The wrapper parent ``bin`` must
#: already exist. No generic mkdir, bootstrap, installer, or caller-supplied
#: directory is reachable.
PARENT_CONTRACT_VERSION = 1
PARENT_RELATIVE: Mapping[str, str] = {
    "config/profiles/inspect.yaml": "config/profiles",
    "bin/sfai.cmd": "bin",
}
PARENT_CREATION_ALLOWED: Mapping[str, bool] = {
    "config/profiles/inspect.yaml": True,
    "bin/sfai.cmd": False,
}
AUTHORIZED_PARENT_DIRECTORIES: tuple[str, ...] = ("config", "config/profiles")
PARENT_STATES: tuple[str, ...] = ("present", "create_required", "blocked")

#: The deferred gates every saved packet must still declare as future gates.
REQUIRED_FUTURE_GATES: frozenset[str] = frozenset(
    {
        "future.operator_confirmation",
        "future.saved_preflight_validation",
        "future.unchanged_rechecks",
        "future.same_directory_backup_before_replace",
        "future.atomic_replacement",
        "future.post_copy_hash_verification",
        "future.receipt_required",
        "future.pr304_post_change_staged_root",
        "future.pr304_post_change_system32_multi_artifact_acceptance",
    }
)

#: Safety-ledger keys a saved preview-only packet must report as ``false``.
UNSAFE_SAFETY_FALSE_KEYS: tuple[str, ...] = (
    "mutation_performed",
    "execution_available",
    "execution_implemented",
    "copy_executed",
    "create_executed",
    "replace_executed",
    "delete_executed",
    "rename_executed",
    "backup_created",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "software_install_executed",
    "software_uninstall_executed",
    "service_control_executed",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
    "powershell_executed",
    "winrm_used",
    "qga_used",
    "subprocess_executed",
    "shell_executed",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "network_call",
    "model_called",
    "secret_read",
    "auth_cache_read",
)

PLAN_VALIDATION_STATUSES = (
    "plan_packet_accepted",
    "plan_packet_rejected",
    "invalid_plan_packet_input",
)
PlanValidationStatus = Literal[
    "plan_packet_accepted",
    "plan_packet_rejected",
    "invalid_plan_packet_input",
]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- #
# Canonicalization and deterministic plan identity
# --------------------------------------------------------------------------- #


def canonical_plan_json(packet: Mapping[str, Any]) -> str:
    """Deterministic canonical JSON used for the confirmation identity.

    Mapping keys are sorted, separators are compact, ``ensure_ascii`` is off so
    Unicode is preserved exactly, and there is no BOM and no trailing newline.
    The packet is read, never modified.
    """
    return json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_plan_sha256(packet: Mapping[str, Any]) -> str:
    """Compute the full, untruncated canonical plan identity SHA-256."""
    return hashlib.sha256(canonical_plan_json(packet).encode("utf-8")).hexdigest()


def is_plan_sha256(value: object) -> bool:
    """Return whether ``value`` is exactly 64 lowercase hexadecimal characters."""
    return bool(_SHA256_RE.fullmatch(str(value or "")))


def confirmation_matches(supplied: str, expected: str) -> bool:
    """Compare two plan SHA-256 values in constant time, format-checked first."""
    if not is_plan_sha256(supplied) or not is_plan_sha256(expected):
        return False
    return hmac.compare_digest(str(supplied), str(expected))


# --------------------------------------------------------------------------- #
# Maintained PR305 saved-packet acceptance
# --------------------------------------------------------------------------- #


def destination_parent_contract_errors(op: Mapping[str, Any]) -> list[str]:
    """Validate the exact fixed destination-parent contract for one operation."""
    e: list[str] = []
    rel_dst = op.get("allowlist_destination")
    parent = op.get("destination_parent")
    if not isinstance(parent, dict):
        return ["missing destination_parent contract"]
    if not isinstance(rel_dst, str) or rel_dst not in PARENT_RELATIVE:
        return ["destination_parent on a non-allowlisted destination"]
    if parent.get("contract_version") != PARENT_CONTRACT_VERSION:
        e.append("destination_parent contract_version must be 1")
    if parent.get("relative_path") != PARENT_RELATIVE[rel_dst]:
        e.append("destination_parent relative_path mismatch")
    allowed = PARENT_CREATION_ALLOWED[rel_dst]
    if parent.get("creation_allowed") is not allowed:
        e.append("destination_parent creation permission mismatch")
    state = parent.get("state")
    if state not in PARENT_STATES:
        e.append("invalid destination_parent state")
    chain = parent.get("creation_chain")
    if not isinstance(chain, list) or any(not isinstance(x, str) for x in chain):
        e.append("destination_parent creation_chain must be a list of strings")
        chain = []
    if not allowed and chain:
        e.append("destination_parent creation is not authorized for this destination")
    for entry in chain:
        if entry not in AUTHORIZED_PARENT_DIRECTORIES:
            e.append("destination_parent creation_chain entry outside the exact allowlist")
        if entry.startswith("/") or entry.startswith("\\") or re.match(r"^[A-Za-z]:", entry):
            e.append("destination_parent creation_chain entry must be relative")
        if ".." in entry.split("/") or "\\" in entry:
            e.append("destination_parent creation_chain entry uses an unsafe path form")
    if len(set(chain)) != len(chain):
        e.append("destination_parent creation_chain contains duplicates")
    if chain != [x for x in AUTHORIZED_PARENT_DIRECTORIES if x in chain]:
        e.append("destination_parent creation_chain ordering mismatch")
    if state == "create_required" and not chain:
        e.append("destination_parent create_required without a creation chain")
    if state in {"present", "blocked"} and chain:
        e.append("destination_parent creation chain on a non-creating state")
    if state == "blocked" and not (parent.get("blockers") or []):
        e.append("blocked destination_parent without a blocker")
    if state != "blocked" and (parent.get("blockers") or []):
        e.append("destination_parent blockers on a non-blocked state")
    return e


def saved_plan_packet_acceptance_errors(p: Mapping[str, Any]) -> list[str]:
    """Return every maintained PR305 acceptance failure for one saved packet.

    An empty list means the packet is a structurally valid saved
    ``windows_runtime_reconcile`` preview packet. It may still carry status
    ``blocked`` or ``unsupported``: acceptance validates shape and internal
    consistency, never executability.
    """
    e: list[str] = []
    if p.get("schema_version") != PLAN_SCHEMA_VERSION:
        e.append("schema_version must be 1")
    if p.get("destination_parent_contract_version") != PARENT_CONTRACT_VERSION:
        e.append("destination_parent_contract_version must be 1")
    if p.get("mode") != PLAN_MODE:
        e.append("mode must be windows_runtime_reconcile")
    if p.get("recipe_id") != RECIPE_ID:
        e.append("recipe_id must be windows.runtime_reconcile")
    if p.get("status") not in PLAN_STATUSES:
        e.append("invalid status")
    if p.get("read_only") is not True or p.get("mutation_performed") is not False:
        e.append("unsafe top-level safety")
    raw_safety = p.get("safety")
    s: Mapping[str, Any] = raw_safety if isinstance(raw_safety, dict) else {}
    if s.get("read_only") is not True:
        e.append("safety.read_only must be true")
    for k in UNSAFE_SAFETY_FALSE_KEYS:
        if s.get(k) is not False:
            e.append(f"unsafe safety flag: {k}")
    raw_ops = p.get("operations")
    ops: list[Any] = []
    if isinstance(raw_ops, list):
        ops = raw_ops
    else:
        e.append("operations must be list")
    if len(ops) > 2:
        e.append("too many operations")
    if [(o.get("allowlist_source"), o.get("allowlist_destination")) for o in ops] != list(
        ALLOWLIST[: len(ops)]
    ):
        e.append("operation ordering or allowlist mismatch")
    counts = {k: 0 for k in PLAN_OPERATIONS}
    for o in ops:
        op = o.get("operation")
        if op not in PLAN_OPERATIONS:
            e.append("invalid operation")
        else:
            counts[op] += 1
        if not re.fullmatch(r"[0-9a-f]{64}", str(o.get("source_sha256") or "")):
            e.append("missing/invalid source sha256")
        if o.get("existing_destination_sha256") is not None and not re.fullmatch(
            r"[0-9a-f]{64}", str(o.get("existing_destination_sha256"))
        ):
            e.append("invalid destination sha256")
        if o.get("expected_post_change_sha256") != o.get("source_sha256"):
            e.append("expected post-change hash mismatch")
        if op == "create_required" and o.get("creation_required") is not True:
            e.append("create flag mismatch")
        if op == "replace_required" and o.get("replacement_required") is not True:
            e.append("replace flag mismatch")
        if "<UTCSTAMP>" not in str(o.get("backup_path_pattern")):
            e.append("backup pattern missing UTCSTAMP")
        e += destination_parent_contract_errors(o)
    raw_summary = p.get("summary")
    summ: Mapping[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    if summ.get("total_operations") != len(ops):
        e.append("summary total mismatch")
    for k, v in counts.items():
        if summ.get(k) != v:
            e.append(f"summary count mismatch: {k}")
    parent_counts = {k: 0 for k in PARENT_STATES}
    for o in ops:
        state = (o.get("destination_parent") or {}).get("state")
        if state in parent_counts:
            parent_counts[state] += 1
    for state, value in parent_counts.items():
        if summ.get(f"parent_{state}") != value:
            e.append(f"summary count mismatch: parent_{state}")
    if parent_counts["blocked"] and p.get("status") != "blocked":
        e.append("plan with a blocked destination parent must be blocked")
    raw_host = p.get("platform")
    expected = (
        "unsupported"
        if not isinstance(raw_host, Mapping) or raw_host.get("system") != "windows"
        else (
            "blocked"
            if counts["blocked"] or p.get("blockers")
            else (
                "ready" if counts["create_required"] or counts["replace_required"] else "no_change"
            )
        )
    )
    if p.get("status") != expected:
        e.append("status precedence mismatch")
    raw_gates = p.get("gates")
    gates: list[Any] = raw_gates if isinstance(raw_gates, list) else []
    names = [g.get("name") for g in gates]
    if len(names) != len(set(names)):
        e.append("duplicate gates")
    for g in gates:
        if g.get("name") in REQUIRED_FUTURE_GATES and g.get("status") != "future_gate":
            e.append("future gate not marked future_gate")
    if not REQUIRED_FUTURE_GATES.issubset(set(names)):
        e.append("missing future gates")
    return e


def saved_plan_executable_contract_errors(packet: Mapping[str, Any]) -> list[str]:
    """Return the narrower maintained PR313 executable-plan contract failures.

    Acceptance alone is not enough to name an executable plan: a structurally
    valid packet may be ``blocked`` or ``unsupported``, may carry fewer than two
    operations, and may record a ``blocked`` operation. This restates exactly
    the maintained PR313 narrowing, and widens nothing.
    """
    errors: list[str] = []
    if packet.get("destination_parent_contract_version") != PARENT_CONTRACT_VERSION:
        errors.append(
            "saved packet predates the destination-parent contract; regenerate the "
            "PR305 plan and confirm its new canonical hash"
        )
    if packet.get("mode") != PLAN_MODE:
        errors.append("saved packet mode is not windows_runtime_reconcile")
    if packet.get("recipe_id") != RECIPE_ID:
        errors.append("saved packet recipe_id is not windows.runtime_reconcile")
    if packet.get("status") not in ACCEPTED_PLAN_STATUSES:
        errors.append("saved packet status is not ready or no_change")
    expected_allowlist = [{"source": a, "destination": b} for a, b in ALLOWLIST]
    if packet.get("allowlist") != expected_allowlist:
        errors.append("saved packet allowlist does not match the exact two-file allowlist")
    operations = packet.get("operations")
    if not isinstance(operations, list) or len(operations) != len(ALLOWLIST):
        errors.append("saved packet must contain exactly two allowlisted operations")
        return errors
    pairs = [
        (op.get("allowlist_source"), op.get("allowlist_destination"))
        if isinstance(op, dict)
        else (None, None)
        for op in operations
    ]
    if pairs != list(ALLOWLIST):
        errors.append("saved packet operation ordering or allowlist mismatch")
    for op in operations:
        if not isinstance(op, dict) or op.get("operation") not in SAVED_OPERATIONS:
            errors.append("saved packet contains a non-executable operation")
            break
    return errors


# --------------------------------------------------------------------------- #
# One immutable structured validation result
# --------------------------------------------------------------------------- #


class WindowsRuntimeReconcilePlanValidationResult(BaseModel):
    """Structured, non-throwing saved-plan validation result.

    The result reports only maintained typed facts and safe fixed relative
    values: the plan status, the plan mode, the plan recipe ID, the canonical
    plan identity, and the destination-parent contract version. It never
    carries the packet, an absolute path, a staged-source root, a durable
    runtime root, a backup path pattern, file contents, a user name, or a host
    name.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: PlanValidationStatus
    reason: str = ""
    plan_valid: bool
    plan_status: str = ""
    plan_mode: str = ""
    plan_recipe_id: str = ""
    plan_sha256: str = ""
    canonical_byte_length: int = 0
    destination_parent_contract_version: int = 0
    allowlist: tuple[tuple[str, str], ...] = ()
    errors: tuple[str, ...] = ()

    # Accurate safety ledger. Plan validation is pure and reaches nothing.
    read_only: Literal[True] = True
    mutation_performed: Literal[False] = False
    filesystem_accessed: Literal[False] = False
    current_state_evaluated: Literal[False] = False
    execution_available: Literal[False] = False
    execution_status: Literal["not_executed"] = "not_executed"


def _plan_validation_result(
    status: PlanValidationStatus,
    *,
    reason: str = "",
    errors: list[str] | None = None,
    plan_status: str = "",
    plan_mode: str = "",
    plan_recipe_id: str = "",
    plan_sha256: str = "",
    canonical_byte_length: int = 0,
    destination_parent_contract_version: int = 0,
    allowlist: tuple[tuple[str, str], ...] = (),
) -> WindowsRuntimeReconcilePlanValidationResult:
    return WindowsRuntimeReconcilePlanValidationResult(
        status=status,
        reason=reason,
        plan_valid=status == "plan_packet_accepted",
        plan_status=plan_status,
        plan_mode=plan_mode,
        plan_recipe_id=plan_recipe_id,
        plan_sha256=plan_sha256,
        canonical_byte_length=canonical_byte_length,
        destination_parent_contract_version=destination_parent_contract_version,
        allowlist=allowlist,
        errors=tuple(sorted(set(errors or ()))),
    )


def validate_saved_windows_runtime_reconcile_plan_packet(
    packet: Any,
) -> WindowsRuntimeReconcilePlanValidationResult:
    """Validate one supplied saved plan mapping. Pure, inert, non-throwing.

    A packet is accepted only when it passes both maintained gates: the PR305
    saved-packet acceptance validator *and* the narrower PR313 executable-plan
    contract. The supplied mapping is read only; it is never modified, never
    written anywhere, and never returned.

    Acceptance means the packet is structurally the exact maintained plan. It is
    never authorization, current-state preflight, evidence freshness, receipt
    linkage, or execution eligibility.
    """
    if not isinstance(packet, Mapping):
        return _plan_validation_result(
            "invalid_plan_packet_input",
            reason="a saved plan packet must be a mapping",
            errors=["saved plan packet must be a mapping"],
        )

    try:
        canonical = canonical_plan_json(packet)
    except (TypeError, ValueError):
        return _plan_validation_result(
            "invalid_plan_packet_input",
            reason="the saved plan packet is not canonicalizable JSON",
            errors=["saved plan packet is not canonicalizable JSON"],
        )
    encoded = canonical.encode("utf-8")
    identity = hashlib.sha256(encoded).hexdigest()

    errors = list(saved_plan_packet_acceptance_errors(packet))
    errors.extend(saved_plan_executable_contract_errors(packet))

    status_value = packet.get("status")
    plan_status = status_value if isinstance(status_value, str) else ""
    mode_value = packet.get("mode")
    recipe_value = packet.get("recipe_id")
    version_value = packet.get("destination_parent_contract_version")
    reported = dict(
        plan_status=plan_status,
        plan_mode=mode_value if isinstance(mode_value, str) else "",
        plan_recipe_id=recipe_value if isinstance(recipe_value, str) else "",
        plan_sha256=identity,
        canonical_byte_length=len(encoded),
        destination_parent_contract_version=(
            version_value
            if isinstance(version_value, int) and not isinstance(version_value, bool)
            else 0
        ),
    )

    host_block = packet.get("platform")
    if not isinstance(host_block, Mapping) or host_block.get("system") != "windows":
        errors.append("saved packet platform.system is not windows")

    if errors:
        return _plan_validation_result(
            "plan_packet_rejected",
            reason="the saved plan packet failed maintained PR305/PR313 validation",
            errors=errors,
            **reported,
        )
    return _plan_validation_result(
        "plan_packet_accepted",
        reason=(
            "the saved plan packet is one maintained-validator-approved Windows "
            "runtime-reconcile plan"
        ),
        allowlist=ALLOWLIST,
        **reported,
    )
