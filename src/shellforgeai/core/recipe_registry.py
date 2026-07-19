"""V2 governed recipe registry (read-only).

This module defines ShellForgeAI's locked toolbox map before any future
execution lane is enabled. It never executes recipes, never mutates Docker or
Compose state, and only uses read-only scene metadata for eligibility checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "1"
REGISTRY_MODE = "v2_recipe_registry"
DETAIL_MODE = "v2_recipe_detail"
ELIGIBILITY_MODE = "v2_recipe_eligibility"

STATUS_AVAILABLE_READ_ONLY = "available_read_only"
STATUS_PREVIEW_ONLY = "preview_only"
STATUS_DISABLED_EXECUTE_LANE = "disabled_until_execute_lane"
STATUS_DISABLED_CLEANUP_LANE = "disabled_until_explicit_cleanup_lane"
STATUS_FUTURE = "future"

MUTATION_NONE = "none"
MUTATION_GOVERNED_DISPOSABLE_ONLY = "governed_disposable_only"
MUTATION_SHELLFORGEAI_METADATA_ONLY = "shellforgeai_owned_metadata_only"

BROAD_TARGETS = {"all", "*", "everything", "all containers", "all services", "docker"}
PRODUCTION_TARGETS = {"shellforgeai"}
REQUIRED_DISPOSABLE_RESTART_LABELS = {
    "shellforgeai.disposable": "true",
    "shellforgeai.allow_restart": "true",
}


def safety_flags() -> dict[str, bool]:
    """Common PR154 safety ledger for read-only recipe surfaces."""

    return {
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
        "model_called": False,
    }


@dataclass(frozen=True)
class Recipe:
    recipe_id: str
    title: str
    category: str
    status: str
    mutation_class: str
    description: str
    first_safe_command: str
    safe_next_commands: tuple[str, ...] = ()
    required_target_labels: dict[str, str] = field(default_factory=dict)
    forbidden_targets: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    preflight_gates: tuple[str, ...] = ()
    approval_gates: tuple[str, ...] = ()
    verification_required: bool = False
    rollback_available: bool = False
    receipt_required: bool = False
    safety_notes: tuple[str, ...] = ()
    blocked_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "recipe_id": self.recipe_id,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "mutation_class": self.mutation_class,
            "description": self.description,
            "required_target_labels": dict(self.required_target_labels),
            "forbidden_targets": list(self.forbidden_targets),
            "required_evidence": list(self.required_evidence),
            "preflight_gates": list(self.preflight_gates),
            "approval_gates": list(self.approval_gates),
            "verification_required": self.verification_required,
            "rollback_available": self.rollback_available,
            "receipt_required": self.receipt_required,
            "first_safe_command": self.first_safe_command,
            "safe_next_commands": list(
                self.safe_next_commands or (self.first_safe_command,)
            ),
            "blocked_reason": self.blocked_reason,
            "safety_notes": list(self.safety_notes),
            "executable": False,
        }


_RECIPES: tuple[Recipe, ...] = (
    Recipe(
        recipe_id="status.report",
        title="Generate current status report",
        category="status",
        status=STATUS_AVAILABLE_READ_ONLY,
        mutation_class=MUTATION_NONE,
        description="Build the current read-only status snapshot and safe next command.",
        first_safe_command="shellforgeai status --json",
        safe_next_commands=("shellforgeai triage --json",),
        required_evidence=("read-only Docker/system status collectors",),
        safety_notes=("Read-only report generation; no recipe execution.",),
    ),
    Recipe(
        recipe_id="triage.docker",
        title="Rank Docker suspects",
        category="triage",
        status=STATUS_AVAILABLE_READ_ONLY,
        mutation_class=MUTATION_NONE,
        description=(
            "Rank Docker suspects from read-only container inventory, inspect, logs, and stats."
        ),
        first_safe_command="shellforgeai triage --json",
        safe_next_commands=("shellforgeai triage docker detail <target> --json",),
        required_evidence=("read-only Docker visibility collectors",),
        safety_notes=("Collector names stay visible in raw/tooling views only.",),
    ),
    Recipe(
        recipe_id="propose.next_action",
        title="Preview next safe action",
        category="propose",
        status=STATUS_AVAILABLE_READ_ONLY,
        mutation_class=MUTATION_NONE,
        description="Preview a bounded operator next step without creating or executing a fix.",
        first_safe_command="shellforgeai propose --json",
        safe_next_commands=("shellforgeai apply-preview --json",),
        required_evidence=("status/triage artifact or current read-only scene",),
        safety_notes=("Proposal preview only; no plan execution.",),
    ),
    Recipe(
        recipe_id="apply.preview",
        title="Preview execution boundary",
        category="apply-preview",
        status=STATUS_AVAILABLE_READ_ONLY,
        mutation_class=MUTATION_NONE,
        description="Show what ShellForgeAI would refuse or gate before any future apply lane.",
        first_safe_command="shellforgeai apply-preview --json",
        safe_next_commands=("shellforgeai verify --json",),
        required_evidence=("proposal/triage context when available",),
        safety_notes=("Validation/preview only; no apply execution.",),
    ),
    Recipe(
        recipe_id="verify.current_state",
        title="Verify current observed state",
        category="verify",
        status=STATUS_AVAILABLE_READ_ONLY,
        mutation_class=MUTATION_NONE,
        description="Re-check the observed read-only state after inspection or operator action.",
        first_safe_command="shellforgeai verify --json",
        safe_next_commands=("shellforgeai handoff --json",),
        required_evidence=("current read-only status/triage scene",),
        safety_notes=("Verification observes only; it does not remediate.",),
    ),
    Recipe(
        recipe_id="handoff.operator",
        title="Produce operator handoff packet",
        category="handoff",
        status=STATUS_AVAILABLE_READ_ONLY,
        mutation_class=MUTATION_NONE,
        description="Produce a read-only operator handoff packet and optional metadata artifact.",
        first_safe_command="shellforgeai handoff --json",
        safe_next_commands=("shellforgeai handoff history --limit 5",),
        required_evidence=("status/triage/propose/apply-preview/verify context",),
        safety_notes=(
            "Handoff writes ShellForgeAI metadata only when explicitly saved/exported.",
        ),
    ),
    Recipe(
        recipe_id="docker.disposable_restart",
        title="Restart exact disposable allowlisted container",
        category="docker",
        status=STATUS_DISABLED_EXECUTE_LANE,
        mutation_class=MUTATION_GOVERNED_DISPOSABLE_ONLY,
        description=(
            "Governed restart for one exact disposable, allowlisted container from a "
            "valid saved preflight with explicit confirmation and receipt verification."
        ),
        required_target_labels=REQUIRED_DISPOSABLE_RESTART_LABELS,
        forbidden_targets=(
            "shellforgeai production container",
            "unlabeled containers",
            "broad targets",
        ),
        required_evidence=(
            "current target labels",
            "preflight target state",
            "recent triage detail",
        ),
        preflight_gates=(
            "exact target",
            "target found",
            "production target refused",
            "labels present",
        ),
        approval_gates=(
            "explicit operator confirmation",
            "receipt",
            "verification",
            "rollback posture",
        ),
        verification_required=True,
        rollback_available=True,
        receipt_required=True,
        first_safe_command=(
            "shellforgeai recipes preflight --recipe docker.disposable_restart "
            "--target <target> --save"
        ),
        safe_next_commands=(
            (
                "shellforgeai recipes preflight --recipe docker.disposable_restart "
                "--target <target> --save"
            ),
            "shellforgeai recipes preflight validate <preflight_id>",
            "shellforgeai recipes execute <preflight_id> --confirm",
            "shellforgeai recipes receipt validate <receipt_id>",
            "shellforgeai verify --receipt <receipt_id>",
        ),
        blocked_reason="Execution requires a valid saved preflight and explicit --confirm.",
        safety_notes=(
            (
                "Only recipes execute may run the exact disposable restart action for "
                "an allowlisted target."
            ),
            (
                "Natural-language execution, Docker Compose, cleanup, remediation, "
                "and rollback stay refused."
            ),
        ),
    ),
    Recipe(
        recipe_id="metadata.cleanup_review",
        title="Review ShellForgeAI-owned metadata cleanup posture",
        category="metadata",
        status=STATUS_AVAILABLE_READ_ONLY,
        mutation_class=MUTATION_NONE,
        description="Review metadata hygiene and cleanup posture without deleting anything.",
        first_safe_command="shellforgeai audit cleanup review",
        safe_next_commands=("shellforgeai audit cleanup review",),
        required_evidence=("ShellForgeAI metadata inventory",),
        safety_notes=("Review only; no cleanup execution.",),
    ),
    Recipe(
        recipe_id="windows.runtime_reconcile",
        title="Preview Windows durable runtime reconciliation",
        category="windows",
        status=STATUS_PREVIEW_ONLY,
        mutation_class=MUTATION_NONE,
        description=(
            "Preview-only governed reconciliation for exactly the inspect profile and "
            "Windows sfai.cmd wrapper from validated PR304 runtime-integrity artifacts. "
            "Execution is not implemented."
        ),
        required_evidence=(
            "one or two saved PR304 windows_runtime_integrity packets",
            "explicit staged source root",
            "explicit durable runtime root",
        ),
        preflight_gates=(
            "Windows platform",
            "PR304 artifact validation and stable identity",
            "exact two-file allowlist",
            "source/destination containment and safety",
            "hash availability",
        ),
        approval_gates=(
            "future explicit operator confirmation",
            "future saved-preflight validation",
            "future unchanged evidence/source/destination rechecks",
            "future same-directory backup before replacement",
            "future atomic replacement",
            "future post-copy hash verification",
            "future receipt",
            "future post-change PR304 verification from staged root and System32",
        ),
        verification_required=True,
        rollback_available=False,
        receipt_required=True,
        first_safe_command=(
            "python scripts/windows_runtime_reconcile_preflight.py <pr304.json> "
            "--staged-source-root <source> --durable-runtime-root <runtime> --json"
        ),
        safe_next_commands=(
            (
                "python scripts/windows_runtime_reconcile_preflight.py <pr304-a.json> "
                "<pr304-b.json> --staged-source-root <source> "
                "--durable-runtime-root <runtime> --out-json <packet.json> --json"
            ),
            "python scripts/windows_runtime_reconcile_acceptance.py <packet.json> --json",
        ),
        blocked_reason="Preview-only: execution requires a future approved implementation.",
        safety_notes=(
            (
                "This recipe has no execute lane and cannot create, replace, back up, "
                "clean, or repair files."
            ),
            (
                "The standalone helper may save only a deterministic ShellForgeAI "
                "metadata packet when explicitly requested and refuses overwrite."
            ),
        ),
    ),
    Recipe(
        recipe_id="metadata.cleanup_execute",
        title="Execute ShellForgeAI-owned metadata cleanup",
        category="metadata",
        status=STATUS_DISABLED_CLEANUP_LANE,
        mutation_class=MUTATION_SHELLFORGEAI_METADATA_ONLY,
        description=(
            "Future governed cleanup lane for ShellForgeAI-owned metadata only. "
            "Disabled here and never suggested as the first step."
        ),
        required_evidence=("cleanup review", "cleanup plan", "archive validation"),
        preflight_gates=("review", "plan", "archive", "validate"),
        approval_gates=("explicit confirm",),
        verification_required=True,
        rollback_available=False,
        receipt_required=True,
        first_safe_command="shellforgeai audit cleanup review",
        safe_next_commands=("shellforgeai audit cleanup review",),
        blocked_reason=(
            "Cleanup execution requires a separate explicit cleanup lane and is disabled."
        ),
        safety_notes=("Do not execute cleanup from recipes.",),
    ),
)


def recipes() -> list[dict[str, Any]]:
    return [recipe.to_dict() for recipe in _RECIPES]


def get_recipe(recipe_id: str) -> dict[str, Any] | None:
    wanted = (recipe_id or "").strip()
    for recipe in _RECIPES:
        if recipe.recipe_id == wanted:
            return recipe.to_dict()
    return None


def registry_payload() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": REGISTRY_MODE,
        "read_only": True,
        "mutation_performed": False,
        "recipes": recipes(),
        "recipe_count": len(_RECIPES),
        "safe_next_commands": [
            "shellforgeai status --json",
            "shellforgeai triage --json",
            "shellforgeai recipes inspect docker.disposable_restart --json",
        ],
        "safety": safety_flags(),
    }


def detail_payload(recipe_id: str) -> dict[str, Any]:
    recipe = get_recipe(recipe_id)
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": DETAIL_MODE,
        "read_only": True,
        "mutation_performed": False,
        "safety": safety_flags(),
    }
    if recipe is None:
        return {
            **base,
            "status": "not_found",
            "recipe_id": recipe_id,
            "recipe": None,
            "safe_next_commands": ["shellforgeai recipes list"],
            "warnings": ["recipe not found"],
        }
    return {
        **base,
        "status": "ok",
        "recipe_id": recipe_id,
        "recipe": recipe,
        "warnings": [],
    }


def _normalize_labels(labels: dict[str, Any] | None) -> dict[str, str]:
    return {str(k): str(v) for k, v in (labels or {}).items()}


def _target_row_from_scene(
    target: str, scene: dict[str, Any] | None
) -> dict[str, Any] | None:
    for row in (scene or {}).get("containers") or []:
        if isinstance(row, dict) and str(row.get("name") or "") == target:
            return row
    return None


def _target_metadata(target: str, scene: dict[str, Any] | None) -> dict[str, Any]:
    row = _target_row_from_scene(target, scene)
    labels = _normalize_labels(row.get("labels") if isinstance(row, dict) else None)
    lower_target = (target or "").strip().lower()
    return {
        "input": target,
        "name": row.get("name") if row else target,
        "target_found": row is not None,
        "production_target": lower_target in PRODUCTION_TARGETS,
        "broad_target": lower_target in BROAD_TARGETS,
        "labels": labels,
        "state": row.get("state") if row else None,
        "status": row.get("status") if row else None,
    }


def eligibility_payload(
    recipe_id: str,
    target: str,
    *,
    scene: dict[str, Any] | None = None,
) -> dict[str, Any]:
    recipe = get_recipe(recipe_id)
    base = {
        "schema_version": SCHEMA_VERSION,
        "mode": ELIGIBILITY_MODE,
        "read_only": True,
        "mutation_performed": False,
        "recipe_id": recipe_id,
        "target": target,
        "safety": safety_flags(),
    }
    if recipe is None:
        return {
            **base,
            "status": "not_found",
            "eligible": False,
            "eligibility": "blocked",
            "recipe": None,
            "target_metadata": _target_metadata(target, scene),
            "blockers": ["recipe not found"],
            "gates": [],
            "first_safe_command": "shellforgeai recipes list",
            "safe_next_commands": ["shellforgeai recipes list"],
        }

    metadata = _target_metadata(target, scene)
    labels = dict(metadata["labels"])
    required_labels = dict(recipe.get("required_target_labels") or {})
    missing_labels = [
        f"{k}={v}" for k, v in required_labels.items() if labels.get(k) != v
    ]
    blockers: list[str] = []
    if metadata["production_target"]:
        blockers.append("production target refused")
    if metadata["broad_target"]:
        blockers.append("broad target refused")
    if required_labels and not metadata["target_found"]:
        blockers.append("target not found")
    if missing_labels:
        blockers.extend(f"missing required label: {label}" for label in missing_labels)

    disabled = (
        recipe["status"].startswith("disabled_until")
        or recipe["status"] == STATUS_FUTURE
    )
    if disabled and recipe["mutation_class"] != MUTATION_NONE:
        blockers.append(recipe.get("blocked_reason") or "execution disabled")

    if recipe["mutation_class"] == MUTATION_NONE and not blockers:
        eligibility = "eligible_read_only"
        eligible = True
        status = "ok"
    elif recipe["status"] == STATUS_PREVIEW_ONLY and not blockers:
        eligibility = "preview_only"
        eligible = False
        status = "blocked"
    elif disabled:
        eligibility = "disabled"
        eligible = False
        status = "blocked"
    else:
        eligibility = "blocked"
        eligible = False
        status = "blocked"

    gates = [
        {
            "name": "read_only_registry",
            "status": "passed",
            "reason": "eligibility check only; no recipe execution",
        }
    ]
    for gate in recipe.get("preflight_gates") or []:
        gates.append(
            {
                "name": gate,
                "status": "pending_or_failed",
                "reason": "future preflight gate",
            }
        )
    for gate in recipe.get("approval_gates") or []:
        gates.append(
            {"name": gate, "status": "required", "reason": "future approval gate"}
        )

    first_safe_command = str(
        recipe.get("first_safe_command") or "shellforgeai recipes list"
    )
    if recipe_id == "docker.disposable_restart" and metadata["production_target"]:
        first_safe_command = "shellforgeai status --json"
    elif recipe_id == "docker.disposable_restart" and blockers:
        first_safe_command = "shellforgeai triage --json"
    if recipe_id == "metadata.cleanup_execute":
        first_safe_command = "shellforgeai audit cleanup review"

    target_metadata = {
        **metadata,
        "required_labels": required_labels,
        "required_labels_present": [
            f"{k}={v}" for k, v in required_labels.items() if labels.get(k) == v
        ],
        "required_labels_missing": missing_labels,
    }
    return {
        **base,
        "status": status,
        "eligible": eligible,
        "eligibility": eligibility,
        "recipe": recipe,
        "target_metadata": target_metadata,
        "blockers": blockers,
        "gates": gates,
        "first_safe_command": first_safe_command,
        "safe_next_commands": [first_safe_command, "shellforgeai recipes list"],
    }
