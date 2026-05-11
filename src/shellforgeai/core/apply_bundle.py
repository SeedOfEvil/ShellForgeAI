"""Apply preflight + operator execution bundle export (PR33).

This module turns an approved :class:`Proposal` into a static, operator-run
bundle on disk. **ShellForgeAI does not execute anything.** The generated
shell scripts contain a deliberate ``exit 2`` before any operator command so
they cannot accidentally run if invoked. ``apply`` remains validation-only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shellforgeai.core.approvals import (
    RISK_HIGH,
    RISK_MEDIUM,
    RISK_VALUES,
    STATUS_APPROVED,
    STATUS_CANCELED,
    STATUS_PENDING,
    STATUS_REJECTED,
    Proposal,
    has_broad_destructive_words,
    validate_proposal_payload,
)

BUNDLE_SCHEMA_VERSION = "1"
EXECUTION_NOT_EXECUTED = "not_executed"
EXECUTION_ALLOWED = False  # invariant for PR33

SAFETY_LINE = "ShellForgeAI generated this bundle but did not execute it."

PREFIGHT_FILES = (
    "apply-preview.md",
    "operator-commands.sh",
    "rollback.sh",
    "validation.md",
    "apply-preflight.json",
)


# ---------------------------------------------------------------------------
# Preflight result model


@dataclass
class PreflightCheck:
    name: str
    status: str  # "passed" | "failed" | "warning"
    message: str = ""


@dataclass
class PreflightResult:
    proposal: Proposal | None
    status: str  # "passed" | "failed"
    checks: list[PreflightCheck] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    def add(self, name: str, ok: bool, message: str = "") -> None:
        self.checks.append(
            PreflightCheck(name=name, status="passed" if ok else "failed", message=message)
        )
        if not ok and message:
            self.errors.append(message)

    def warn(self, name: str, message: str) -> None:
        self.checks.append(PreflightCheck(name=name, status="warning", message=message))
        self.warnings.append(message)


# ---------------------------------------------------------------------------
# Preflight


def run_preflight(proposal: Proposal | None, *, require_approved: bool = True) -> PreflightResult:
    """Run deterministic safety checks against a proposal."""
    result = PreflightResult(proposal=proposal, status="passed")

    if proposal is None:
        result.status = "failed"
        result.errors.append("proposal is missing")
        result.checks.append(
            PreflightCheck(name="proposal_present", status="failed", message="proposal is missing")
        )
        return result

    payload = json.loads(proposal.model_dump_json())
    schema_errors, schema_warnings = validate_proposal_payload(payload)
    if schema_errors:
        for err in schema_errors:
            result.errors.append(err)
        result.checks.append(
            PreflightCheck(
                name="proposal_schema",
                status="failed",
                message="; ".join(schema_errors),
            )
        )
        result.status = "failed"
    else:
        result.checks.append(
            PreflightCheck(name="proposal_schema", status="passed", message="Proposal schema valid")
        )

    if proposal.execution.allowed is not False:
        result.add(
            "execution_allowed_false",
            False,
            "execution.allowed must be false in this alpha",
        )
        result.status = "failed"
    else:
        result.add("execution_allowed_false", True, "execution.allowed=false")

    if proposal.execution.status != EXECUTION_NOT_EXECUTED:
        result.add(
            "execution_status_not_executed",
            False,
            f"execution.status must be {EXECUTION_NOT_EXECUTED}",
        )
        result.status = "failed"
    else:
        result.add("execution_status_not_executed", True, "execution.status=not_executed")

    if require_approved:
        if proposal.status == STATUS_APPROVED:
            result.add(
                "status_approved",
                True,
                "proposal is approved",
            )
        elif proposal.status == STATUS_PENDING:
            result.add(
                "status_approved",
                False,
                "proposal is pending, not approved",
            )
            result.status = "failed"
        elif proposal.status == STATUS_REJECTED:
            result.add(
                "status_approved",
                False,
                "proposal was rejected; refusing to generate operator bundle",
            )
            result.status = "failed"
        elif proposal.status == STATUS_CANCELED:
            result.add(
                "status_approved",
                False,
                "proposal was canceled; refusing to generate operator bundle",
            )
            result.status = "failed"
        else:
            result.add(
                "status_approved",
                False,
                f"unknown proposal status: {proposal.status}",
            )
            result.status = "failed"

    if proposal.risk not in RISK_VALUES:
        result.add("risk_valid", False, f"unknown risk value: {proposal.risk}")
        result.status = "failed"
    else:
        result.add("risk_valid", True, f"risk={proposal.risk}")

    if proposal.is_mutating():
        for required in ("OPERATOR-RUN", "REQUIRES APPROVAL"):
            if required not in proposal.safety_labels:
                result.add(
                    f"safety_label_{required.lower().replace(' ', '_')}",
                    False,
                    f"mutating proposal missing safety label: {required}",
                )
                result.status = "failed"

    if proposal.risk in (RISK_MEDIUM, RISK_HIGH) and not proposal.rollback:
        result.add(
            "rollback_present",
            False,
            f"{proposal.risk}-risk proposal is missing rollback",
        )
        result.status = "failed"
    elif proposal.rollback:
        result.add("rollback_present", True, "rollback present")

    if not proposal.verification:
        result.add(
            "verification_present",
            False,
            "proposal is missing verification",
        )
        result.status = "failed"
    else:
        result.add("verification_present", True, "verification present")

    if not proposal.proposed_steps:
        result.add("steps_present", False, "proposal has no proposed_steps")
        result.status = "failed"
    else:
        result.add("steps_present", True, f"{len(proposal.proposed_steps)} step(s)")

    # Warnings (non-fatal)
    for w in schema_warnings:
        result.warnings.append(w)
    if proposal.risk == RISK_HIGH:
        result.warn("risk_high", "proposal risk is high")
    if has_broad_destructive_words(proposal.proposed_steps):
        result.warn(
            "broad_destructive_words",
            "broad destructive words detected in proposed_steps",
        )
    if proposal.source_evidence:
        ev_path = Path(proposal.source_evidence)
        if not ev_path.exists():
            result.warn(
                "source_evidence_path",
                f"source evidence path not present on filesystem: {ev_path}",
            )

    return result


# ---------------------------------------------------------------------------
# Bundle generation


def bundle_dir_for(data_dir: Path, proposal_id: str) -> Path:
    return Path(data_dir) / "apply_bundles" / proposal_id


def _render_preview_md(proposal: Proposal, preflight: PreflightResult) -> str:
    lines: list[str] = []
    lines.append("# Apply preview")
    lines.append("")
    lines.append(f"- Proposal: {proposal.proposal_id}")
    if proposal.session_id:
        lines.append(f"- Session: {proposal.session_id}")
    if proposal.component:
        lines.append(f"- Component: {proposal.component}")
    lines.append(f"- Title: {proposal.title}")
    lines.append(f"- Risk: {proposal.risk}")
    if proposal.impact:
        lines.append(f"- Impact: {proposal.impact}")
    lines.append(f"- Approval status: {proposal.status}")
    if proposal.approval.reason:
        lines.append(f"- Approval reason: {proposal.approval.reason}")
    if proposal.approval.approved_at:
        lines.append(f"- Approved at: {proposal.approval.approved_at}")
    lines.append("- Execution: not_executed (execution_allowed=false)")
    if proposal.safety_labels:
        lines.append(f"- Safety labels: {', '.join(proposal.safety_labels)}")
    if proposal.source_evidence:
        lines.append(f"- Source evidence: {proposal.source_evidence}")
    if proposal.source_runbook:
        lines.append(f"- Source runbook: {proposal.source_runbook}")
    lines.append("")

    lines.append("## Preconditions")
    lines.append("")
    if proposal.preconditions:
        for p in proposal.preconditions:
            lines.append(f"- {p}")
    else:
        lines.append("- None recorded.")
    lines.append("")

    lines.append("## Proposed steps (OPERATOR-RUN, ShellForgeAI did not execute these)")
    lines.append("")
    if proposal.proposed_steps:
        for s in proposal.proposed_steps:
            lines.append(f"- {s}")
    else:
        lines.append("- None recorded.")
    lines.append("")

    lines.append("## Rollback")
    lines.append("")
    if proposal.rollback:
        for r in proposal.rollback:
            lines.append(f"- {r}")
    else:
        lines.append("- None recorded.")
    lines.append("")

    lines.append("## Validation (post-fix)")
    lines.append("")
    if proposal.verification:
        for v in proposal.verification:
            lines.append(f"- {v}")
    else:
        lines.append("- None recorded.")
    lines.append("")

    if preflight.warnings:
        lines.append("## Preflight warnings")
        lines.append("")
        for w in preflight.warnings:
            lines.append(f"- {w}")
        lines.append("")

    lines.append("## Safety note")
    lines.append("")
    lines.append(f"- {SAFETY_LINE}")
    lines.append("- Every command below must be reviewed by a human operator before running.")
    lines.append(
        "- Approval marks intent; it does not execute commands. ShellForgeAI's apply "
        "remains validation-only in this alpha."
    )
    return "\n".join(lines) + "\n"


_SCRIPT_HEADER = """#!/usr/bin/env bash
set -euo pipefail

echo "ShellForgeAI generated this operator-run script."
echo "Review every command before running."
echo "ShellForgeAI did not execute this script."
exit 2
# OPERATOR-RUN COMMANDS BELOW -- REMOVE EXIT ONLY AFTER HUMAN REVIEW
"""


def _shell_comment(text: str) -> list[str]:
    out: list[str] = []
    for line in str(text).splitlines() or [str(text)]:
        out.append(f"# {line}")
    return out


def _render_operator_script(proposal: Proposal, *, kind: str) -> str:
    """Render operator-commands.sh or rollback.sh.

    ``kind`` is ``"commands"`` or ``"rollback"``.
    """
    lines: list[str] = [_SCRIPT_HEADER.rstrip("\n"), ""]
    lines.append(f"# Proposal: {proposal.proposal_id}")
    lines.append(f"# Title: {proposal.title}")
    lines.append(f"# Risk: {proposal.risk}")
    lines.append(f"# Status: {proposal.status}")
    if proposal.safety_labels:
        lines.append("# Safety labels: " + ", ".join(proposal.safety_labels))
    lines.append("")
    if kind == "commands":
        lines.append("# ---- Preconditions (read-only suggestions) ----")
        for p in proposal.preconditions or []:
            lines.extend(_shell_comment(f"PRECHECK: {p}"))
        lines.append("")
        lines.append("# ---- Proposed operator-run commands ----")
        if not proposal.proposed_steps:
            lines.append("# (no commands)")
        for s in proposal.proposed_steps:
            lines.extend(_shell_comment(f"OPERATOR-RUN: {s}"))
        lines.append("")
        lines.append("# ---- Post-fix verification (read-only suggestions) ----")
        for v in proposal.verification or []:
            lines.extend(_shell_comment(f"VERIFY: {v}"))
    else:  # rollback
        lines.append("# ---- Rollback steps ----")
        if not proposal.rollback:
            lines.append("# (no rollback recorded)")
        for r in proposal.rollback:
            lines.extend(_shell_comment(f"ROLLBACK: {r}"))
    lines.append("")
    lines.append(f"# {SAFETY_LINE}")
    return "\n".join(lines) + "\n"


def _render_validation_md(proposal: Proposal) -> str:
    lines: list[str] = []
    lines.append("# Post-fix validation")
    lines.append("")
    lines.append(f"- Proposal: {proposal.proposal_id}")
    lines.append(f"- Title: {proposal.title}")
    lines.append("")
    lines.append("## Read-only validation steps")
    lines.append("")
    if proposal.verification:
        for v in proposal.verification:
            lines.append(f"- {v}")
    else:
        lines.append(
            "- No verification recorded. Re-run `shellforgeai diagnose <target>` after "
            "the fix to confirm the previously-failing signal is gone."
        )
    lines.append("")
    lines.append("## Safety note")
    lines.append("")
    lines.append(f"- {SAFETY_LINE}")
    lines.append(
        "- These steps are read-only suggestions; no mutation is performed by ShellForgeAI."
    )
    return "\n".join(lines) + "\n"


def _render_preflight_json(
    proposal: Proposal, preflight: PreflightResult, *, bundle_dir: Path
) -> dict[str, Any]:
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "proposal_id": proposal.proposal_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "proposal_status": proposal.status,
        "preflight_status": preflight.status,
        "execution_allowed": EXECUTION_ALLOWED,
        "execution_status": EXECUTION_NOT_EXECUTED,
        "risk": proposal.risk,
        "safety_labels": list(proposal.safety_labels),
        "source_proposal": proposal.source_runbook or proposal.source_evidence or "",
        "bundle_dir": str(bundle_dir),
        "checks": [
            {"name": c.name, "status": c.status, "message": c.message} for c in preflight.checks
        ],
        "errors": list(preflight.errors),
        "warnings": list(preflight.warnings),
    }


@dataclass
class BundleResult:
    bundle_dir: Path
    preflight_path: Path
    files: list[Path]
    preflight: PreflightResult


def generate_bundle(
    proposal: Proposal,
    *,
    data_dir: Path,
    preflight: PreflightResult | None = None,
) -> BundleResult:
    """Write the operator execution bundle under ``<data_dir>/apply_bundles/<id>/``.

    Generation never executes any command. The shell scripts include a
    deliberate early ``exit 2`` so they cannot run if accidentally invoked.
    """
    if preflight is None:
        preflight = run_preflight(proposal)
    bundle_dir = bundle_dir_for(Path(data_dir), proposal.proposal_id)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    preview = bundle_dir / "apply-preview.md"
    cmds = bundle_dir / "operator-commands.sh"
    rollback = bundle_dir / "rollback.sh"
    validation = bundle_dir / "validation.md"
    preflight_path = bundle_dir / "apply-preflight.json"

    preview.write_text(_render_preview_md(proposal, preflight), encoding="utf-8")
    cmds.write_text(_render_operator_script(proposal, kind="commands"), encoding="utf-8")
    rollback.write_text(_render_operator_script(proposal, kind="rollback"), encoding="utf-8")
    validation.write_text(_render_validation_md(proposal), encoding="utf-8")
    preflight_payload = _render_preflight_json(proposal, preflight, bundle_dir=bundle_dir)
    preflight_path.write_text(
        json.dumps(preflight_payload, indent=2),
        encoding="utf-8",
    )

    return BundleResult(
        bundle_dir=bundle_dir,
        preflight_path=preflight_path,
        files=[preview, cmds, rollback, validation, preflight_path],
        preflight=preflight,
    )


def write_diagnostic_preflight(
    proposal: Proposal | None,
    *,
    data_dir: Path,
    preflight: PreflightResult,
    proposal_id: str,
) -> Path:
    """Write a stand-alone apply-preflight.json for a failed preflight.

    Used when we want to record the refusal but not generate any of the
    operator-run scripts (rejected/canceled/pending proposals).
    """
    bundle_dir = bundle_dir_for(Path(data_dir), proposal_id)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    preflight_path = bundle_dir / "apply-preflight.json"
    pseudo = proposal or Proposal(proposal_id=proposal_id, status="unknown", risk="low")
    payload = _render_preflight_json(pseudo, preflight, bundle_dir=bundle_dir)
    payload["preflight_status"] = preflight.status
    preflight_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return preflight_path
