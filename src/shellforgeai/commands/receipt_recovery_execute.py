"""Confirm-gated receipt recovery-execute command registration (PR194).

Behavior-preserving extraction of the governed ``recipes receipt
recovery-execute`` handler from ``shellforgeai.cli``. The module attaches the
command to the existing receipt Typer group and delegates to the same
confirm-gated core recovery executor plus the same human renderer. The command
surface, explicit ``--confirm`` requirement, exact-target
disposable/allowlist/production gates, strict JSON contract, recovery receipt
writing, verification recording, and exit codes are unchanged. It introduces
no Docker Compose, shell, model, natural-language, broad-target, or arbitrary
command execution behavior, and no artifact repair/delete behavior.
"""

from __future__ import annotations

import json
import sys
from typing import Annotated, Any

import typer

from shellforgeai.core.recipe_receipt_recovery import execute_receipt_recovery


def _cli():
    return sys.modules["shellforgeai.cli"]


def _render_receipt_recovery_execute_human(payload: dict[str, Any]) -> str:
    status = str(payload.get("status") or "blocked")
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    target_name = target.get("name") or "unknown"
    if status == "executed":
        verification = (
            payload.get("verification") if isinstance(payload.get("verification"), dict) else {}
        )
        action = payload.get("action") if isinstance(payload.get("action"), dict) else {}
        return (
            "\n".join(
                [
                    "Recovery execution: completed",
                    f"Receipt: {payload.get('receipt_id')}",
                    f"Recovery receipt: {payload.get('recovery_receipt_id')}",
                    f"Recipe: {payload.get('recipe_id')}",
                    f"Target: {target_name}",
                    "",
                    "Action:",
                    " ".join(str(part) for part in action.get("argv") or []),
                    "",
                    "Verification:",
                    "- restart attempted: "
                    f"{str(bool(action.get('docker_restart_attempted'))).lower()}",
                    "- restart succeeded: "
                    f"{str(bool(action.get('docker_restart_succeeded'))).lower()}",
                    "- StartedAt changed: "
                    f"{str(bool(verification.get('started_at_changed'))).lower()}",
                    "",
                    "Safety:",
                    "- Exact disposable target only.",
                    "- Explicit --confirm was required.",
                    "- No Docker Compose command was executed.",
                    "- No cleanup/remediation/rollback outside this recovery recipe was executed.",
                    "- This is bounded recovery restart, not true rollback of prior process state.",
                    "",
                    "First safe command:",
                    str(payload.get("first_safe_command") or ""),
                ]
            ).rstrip()
            + "\n"
        )

    lines = ["Recovery execution: blocked"]
    if target_name != "unknown":
        lines.append(f"Target: {target_name}")
    if payload.get("reason"):
        lines.append(f"Reason: {payload.get('reason')}")
    lines.extend(
        [
            "",
            "Safety:",
            "- No action was taken.",
            "- No container was restarted.",
            "- This is bounded recovery restart only when explicitly confirmed; "
            "no true rollback is available.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def register(recipes_receipt_app: typer.Typer) -> None:
    """Register the confirm-gated receipt recovery-execute command."""

    @recipes_receipt_app.command("recovery-execute")
    def recipes_receipt_recovery_execute(
        ctx: typer.Context,
        receipt_ref: Annotated[
            str,
            typer.Argument(
                help="Saved disposable restart receipt id or ShellForgeAI-owned path.",
                metavar="RECEIPT_REF",
            ),
        ],
        confirm: Annotated[
            bool,
            typer.Option("--confirm", help="Explicitly confirm bounded recovery restart."),
        ] = False,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Execute bounded disposable recovery restart from a valid receipt. Not true rollback."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = execute_receipt_recovery(receipt_ref, runtime.session.data_dir, confirm=confirm)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(_render_receipt_recovery_execute_human(payload), nl=False)
        if payload.get("status") != "executed":
            raise typer.Exit(1)
