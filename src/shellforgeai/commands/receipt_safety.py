"""Governed receipt verify/validate/rollback-preview command registration (PR192).

Behavior-preserving extraction of the read-only ``recipes receipt`` verify,
validate, and rollback-preview handlers (plus the existing top-level
``rollback-preview`` alias) from ``shellforgeai.cli`` and
``shellforgeai.commands.receipt_audit``. The module attaches commands to the
existing receipt Typer group and delegates to the same core builders and human
renderers. It does not move governed recipe execution or recovery execution
(``recipes receipt recovery-execute`` and the recovery status/validate
handlers stay in ``cli.py``), and it introduces no Docker/Compose, shell,
model, cleanup, remediation, rollback execution, recovery execution, repair,
or delete behavior.
"""

from __future__ import annotations

import json
import sys
from typing import Annotated

import typer

from shellforgeai.core.recipe_execution import (
    validate_receipt as validate_recipe_receipt,
)
from shellforgeai.core.recipe_receipt_rollback_preview import preview_receipt_rollback
from shellforgeai.core.recipe_receipt_verify import verify_recipe_receipt


def _cli():
    return sys.modules["shellforgeai.cli"]


def register(recipes_receipt_app: typer.Typer, app: typer.Typer | None = None) -> None:
    """Register read-only governed receipt verify/validate/rollback-preview commands."""

    @recipes_receipt_app.command("verify")
    def recipes_receipt_verify(
        ctx: typer.Context,
        receipt_ref: Annotated[
            str,
            typer.Argument(
                help="Saved receipt id or ShellForgeAI-owned path.", metavar="RECEIPT_REF"
            ),
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Verify a governed recipe execution receipt. Read-only; no retry or rollback."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = verify_recipe_receipt(receipt_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_v2_receipt_verify_human(payload), nl=False)
        if payload.get("status") != "passed":
            raise typer.Exit(1)

    @recipes_receipt_app.command("validate")
    def recipes_receipt_validate(
        ctx: typer.Context,
        receipt_ref: Annotated[
            str,
            typer.Argument(
                help="Saved receipt id or ShellForgeAI-owned path.", metavar="RECEIPT_REF"
            ),
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Validate a governed recipe execution receipt. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = validate_recipe_receipt(receipt_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_validate_human(payload), nl=False)
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @recipes_receipt_app.command("rollback-preview")
    def recipes_receipt_rollback_preview(
        ctx: typer.Context,
        receipt_ref: Annotated[
            str,
            typer.Argument(
                help="Saved receipt id or ShellForgeAI-owned path.", metavar="RECEIPT_REF"
            ),
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Preview rollback/recovery posture for a governed receipt. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = preview_receipt_rollback(receipt_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_receipt_rollback_preview_human(payload), nl=False)
        if payload.get("status") not in {"limited", "preview_ready", "unsupported_recipe"}:
            raise typer.Exit(1)

    if app is not None:

        @app.command("rollback-preview")
        def rollback_preview_receipt(
            ctx: typer.Context,
            receipt: Annotated[str, typer.Option("--receipt", help="Receipt id or owned path.")],
            json_out: Annotated[
                bool, typer.Option("--json", help="Emit strict JSON only.")
            ] = False,
        ) -> None:
            """Preview rollback/recovery posture for a governed receipt. Read-only."""
            cli = _cli()
            runtime = cli._ctx(ctx)
            payload = preview_receipt_rollback(receipt, runtime.session.data_dir)
            if json_out:
                typer.echo(json.dumps(payload))
            else:
                typer.echo(cli._render_receipt_rollback_preview_human(payload), nl=False)
            if payload.get("status") not in {"limited", "preview_ready", "unsupported_recipe"}:
                raise typer.Exit(1)
