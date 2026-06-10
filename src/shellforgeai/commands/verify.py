"""``verify`` command registration (extracted from ``cli.py`` in PR185).

Behavior-preserving move of the read-only V2 verification command. Current-
state verification and receipt-aware verification continue to delegate to the
existing ``shellforgeai.cli`` helpers and ``recipe_receipt_verify`` integration
so output, exit codes, JSON strictness, and safety flags remain unchanged. This
module registers Typer wiring only; it does not introduce cleanup,
remediation, rollback, recovery, Docker/Compose mutation, restart, shell, or
model execution behavior.
"""

from __future__ import annotations

import json
import sys
from typing import Annotated

import typer

from shellforgeai.core.recipe_receipt_verify import verify_recipe_receipt


def register(app: typer.Typer) -> None:
    """Register the read-only top-level ``verify`` command on ``app``."""

    cli = sys.modules["shellforgeai.cli"]

    @app.command("verify")
    def verify(
        ctx: typer.Context,
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        brief: Annotated[bool, typer.Option("--brief", help="Emit bounded verify output.")] = False,
        target: Annotated[
            str | None, typer.Option("--target", help="Verify one exact visible target.")
        ] = None,
        from_status: Annotated[
            bool, typer.Option("--from-status", help="Use current deterministic status context.")
        ] = False,
        from_triage: Annotated[
            bool, typer.Option("--from-triage", help="Use current deterministic triage context.")
        ] = False,
        from_propose: Annotated[
            bool,
            typer.Option(
                "--from-propose", help="Verify current state after proposal context only."
            ),
        ] = False,
        from_apply_preview: Annotated[
            bool,
            typer.Option(
                "--from-apply-preview",
                help="Verify current state after apply-preview context only; no apply is assumed.",
            ),
        ] = False,
        receipt: Annotated[
            str | None,
            typer.Option(
                "--receipt", help="Verify a governed recipe execution receipt by id or owned path."
            ),
        ] = None,
    ) -> None:
        """Read-only V2 verification. Current-state by default; receipt-aware with --receipt."""
        runtime = cli._ctx(ctx)
        if receipt:
            payload = verify_recipe_receipt(receipt, runtime.session.data_dir)
            if json_output:
                typer.echo(json.dumps(payload))
            elif brief:
                typer.echo(cli._render_v2_verify_brief(payload), nl=False)
            else:
                typer.echo(cli._render_v2_receipt_verify_human(payload), nl=False)
            if payload.get("status") != "passed":
                raise typer.Exit(1)
            return
        payload = cli._build_v2_verify_payload(
            target=target,
            from_status=from_status,
            from_triage=from_triage,
            from_propose=from_propose,
            from_apply_preview=from_apply_preview,
        )
        if json_output:
            typer.echo(json.dumps(payload))
            return
        if brief:
            typer.echo(cli._render_v2_verify_brief(payload), nl=False)
            return
        typer.echo(cli._render_v2_verify_human(payload), nl=False)
