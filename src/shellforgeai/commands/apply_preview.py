"""``apply-preview`` command registration (extracted from ``cli.py`` in PR187).

Behavior-preserving move of the read-only V2 execution-boundary preview
command. The handler continues to delegate to the existing
``shellforgeai.cli`` payload/render helpers so output, JSON strictness, brief
mode, refusal/blocked output, execution-boundary language, first-safe-command
and safe-next-command guidance remain unchanged. Apply-preview stays
preview-only: this module registers Typer wiring only and does not introduce
apply, cleanup, remediation, rollback, recovery, Docker/Compose mutation,
restart, shell, or model execution behavior.
"""

from __future__ import annotations

import json
import sys
from typing import Annotated

import typer


def register(app: typer.Typer) -> None:
    """Register the read-only top-level ``apply-preview`` command on ``app``."""

    cli = sys.modules["shellforgeai.cli"]

    @app.command("apply-preview")
    def apply_preview(
        ctx: typer.Context,
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        brief: Annotated[bool, typer.Option("--brief", help="Emit bounded apply preview.")] = False,
        target: Annotated[
            str | None, typer.Option("--target", help="Preview gates for one exact target.")
        ] = None,
        from_propose: Annotated[
            bool,
            typer.Option("--from-propose", help="Use current deterministic proposal context."),
        ] = False,
        from_triage: Annotated[
            bool,
            typer.Option("--from-triage", help="Use current deterministic triage context."),
        ] = False,
    ) -> None:
        """Read-only V2 execution-boundary preview. Does not apply or execute."""
        _ = ctx
        payload = cli._build_v2_apply_preview_payload(
            target=target, from_propose=from_propose, from_triage=from_triage
        )
        if json_output:
            typer.echo(json.dumps(payload))
            return
        if brief:
            typer.echo(cli._render_v2_apply_preview_brief(payload), nl=False)
            return
        typer.echo(cli._render_v2_apply_preview_human(payload), nl=False)
