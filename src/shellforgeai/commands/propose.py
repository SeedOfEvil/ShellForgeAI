"""``propose`` command registration (extracted from ``cli.py`` in PR187).

Behavior-preserving move of the read-only V2 next-action proposal preview
command. The handler continues to delegate to the existing
``shellforgeai.cli`` payload/render helpers so output, JSON strictness, brief
mode, safety flags, first-safe-command and safe-next-command guidance remain
unchanged. This module registers Typer wiring only; it does not introduce
cleanup, remediation, rollback, recovery, Docker/Compose mutation, restart,
shell, or model execution behavior.
"""

from __future__ import annotations

import json
import sys
from typing import Annotated

import typer


def register(app: typer.Typer) -> None:
    """Register the read-only top-level ``propose`` command on ``app``."""

    cli = sys.modules["shellforgeai.cli"]

    @app.command()
    def propose(
        ctx: typer.Context,
        json_output: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        brief: Annotated[
            bool, typer.Option("--brief", help="Emit bounded proposal preview.")
        ] = False,
        target: Annotated[
            str | None, typer.Option("--target", help="Preview next action for one target.")
        ] = None,
        from_triage: Annotated[
            bool,
            typer.Option(
                "--from-triage",
                help="Use current deterministic triage ranking as proposal input.",
            ),
        ] = False,
    ) -> None:
        """Read-only V2 next-action proposal preview. No plan or action is created."""
        _ = ctx
        payload = cli._build_v2_propose_payload(target=target, from_triage=from_triage)
        if json_output:
            typer.echo(json.dumps(payload))
            return
        if brief:
            typer.echo(cli._render_v2_propose_brief(payload), nl=False)
            return
        typer.echo(cli._render_v2_propose_human(payload), nl=False)
