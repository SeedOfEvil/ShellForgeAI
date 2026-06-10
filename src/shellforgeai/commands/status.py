"""``status`` command registration (extracted from ``cli.py`` in PR182).

Behavior-preserving move of the read-only V2 golden-path ``status`` command.
All shared payload/render helpers remain in ``shellforgeai.cli``; this module
resolves them lazily at call time so monkeypatching and registration order are
preserved exactly. No mutation, model call, artifact write, or subprocess
execution is introduced here.
"""

from __future__ import annotations

import json
import sys

import typer


def register(app: typer.Typer) -> None:
    """Register the ``status`` command on the root Typer ``app``.

    The handler delegates entirely to the existing ``shellforgeai.cli``
    helpers (``_build_status_payload``, ``_render_ops_report_brief``,
    ``_render_status_human``) so output, exit codes, and read-only safety are
    identical to the pre-extraction implementation.
    """

    cli = sys.modules["shellforgeai.cli"]

    @app.command()
    def status(
        ctx: typer.Context,
        json_output: bool = typer.Option(False, "--json"),
        brief: bool = typer.Option(False, "--brief", help="Mirror ops report --brief output."),
        top: int = typer.Option(
            5, "--top", min=1, help="Maximum ranked Docker suspects to inspect."
        ),
        verbose: bool = typer.Option(
            False, "--verbose", help="Accepted for compatibility; status stays concise."
        ),
        since: str | None = typer.Option(None, "--since", help="Accepted for compatibility."),
        include_retention: bool = typer.Option(
            False,
            "--include-retention",
            help="Accepted for compatibility; no artifacts are written.",
        ),
        include_index: bool = typer.Option(
            False, "--include-index", help="Accepted for compatibility."
        ),
        include_audit: bool = typer.Option(
            False, "--include-audit", help="Accepted for compatibility."
        ),
        include_approvals: bool = typer.Option(
            False, "--include-approvals", help="Accepted for compatibility."
        ),
    ) -> None:
        """Read-only V2 golden-path status entrypoint.

        This is a small deterministic wrapper around the concise ops-report path.
        It does not call the model, write artifacts, create proposals/missions, or
        execute cleanup/remediation/rollback/Docker/Compose actions.
        """
        _ = (
            ctx,
            verbose,
            since,
            include_retention,
            include_index,
            include_audit,
            include_approvals,
        )
        payload = cli._build_status_payload(top=top)
        if json_output:
            typer.echo(json.dumps(payload))
            return
        if brief:
            typer.echo(cli._render_ops_report_brief(payload), nl=False)
            return
        typer.echo(cli._render_status_human(payload), nl=False)
