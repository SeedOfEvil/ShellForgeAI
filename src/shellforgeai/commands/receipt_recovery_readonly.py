"""Read-only recovery receipt status/validate command registration (PR193).

Behavior-preserving extraction of the read-only ``recipes receipt`` recovery
inspection handlers from ``shellforgeai.cli``. The module attaches commands to
the existing receipt Typer group and delegates to the same receipt-aware verify
and validate builders plus human renderers. It does not move governed recipe
execution or governed recovery execution (``recipes receipt recovery-execute``),
and it introduces no Docker/Compose, shell, model, cleanup, remediation,
rollback execution, recovery execution, repair, or delete behavior.
"""

from __future__ import annotations

import json
import sys
from typing import Annotated

import typer

from shellforgeai.core.recipe_execution import (
    validate_receipt as validate_recipe_receipt,
)
from shellforgeai.core.recipe_receipt_verify import verify_recipe_receipt


def _cli():
    return sys.modules["shellforgeai.cli"]


def register(recipes_receipt_app: typer.Typer) -> None:
    """Register read-only recovery receipt status/validate commands."""

    @recipes_receipt_app.command("recovery-status")
    def recipes_receipt_recovery_status(
        ctx: typer.Context,
        recovery_receipt_ref: Annotated[
            str, typer.Argument(help="Recovery receipt id or ShellForgeAI-owned path.")
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Read-only status for a recovery receipt via receipt-aware verify."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = verify_recipe_receipt(recovery_receipt_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_v2_receipt_verify_human(payload), nl=False)
        if payload.get("status") != "passed":
            raise typer.Exit(1)

    @recipes_receipt_app.command("recovery-validate")
    def recipes_receipt_recovery_validate(
        ctx: typer.Context,
        recovery_receipt_ref: Annotated[
            str, typer.Argument(help="Recovery receipt id or ShellForgeAI-owned path.")
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Validate a recovery receipt. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = validate_recipe_receipt(recovery_receipt_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_validate_human(payload), nl=False)
        if payload.get("status") != "ok":
            raise typer.Exit(1)
