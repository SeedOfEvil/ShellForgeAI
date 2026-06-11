"""Governed receipt audit/reporting command registration (PR188).

Behavior-preserving extraction of read-only/artifact-only ``recipes receipt``
audit/report handlers from ``shellforgeai.cli``. The module attaches commands to
the existing receipt Typer group and delegates to the same core builders and
human renderers. It does not move governed recipe execution or recovery
execution, and it introduces no Docker/Compose, shell, model, cleanup,
remediation, rollback, repair, or delete behavior.
"""

from __future__ import annotations

import json
import sys
from typing import Annotated

import typer

from shellforgeai.core.recipe_receipt_audit import receipt_audit as build_receipt_audit
from shellforgeai.core.recipe_receipt_audit import (
    receipt_audit_bundle as build_receipt_audit_bundle,
)
from shellforgeai.core.recipe_receipt_audit import (
    receipt_audit_bundle_validate as build_receipt_audit_bundle_validate,
)
from shellforgeai.core.recipe_receipt_audit import receipt_integrity as build_receipt_integrity
from shellforgeai.core.recipe_receipt_explain import receipt_explain as build_receipt_explain


def _cli():
    return sys.modules["shellforgeai.cli"]


def register(recipes_receipt_app: typer.Typer) -> None:
    """Register read-only/artifact-only governed receipt report commands."""

    @recipes_receipt_app.command("explain")
    def recipes_receipt_explain(
        ctx: typer.Context,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        source: Annotated[
            str,
            typer.Option(
                "--source",
                help="Local source to explain: integrity, audit, audit-bundle, or compare.",
            ),
        ] = "integrity",
        finding: Annotated[
            str | None,
            typer.Option(
                "--finding", help="Explain one deterministic finding code without scanning."
            ),
        ] = None,
        target: Annotated[
            str | None,
            typer.Option("--target", help="Only read findings for this target when available."),
        ] = None,
        recipe_id: Annotated[
            str | None,
            typer.Option("--recipe", help="Only read findings for this recipe id when available."),
        ] = None,
        limit: Annotated[
            int,
            typer.Option(
                "--limit", min=1, max=100, help="Maximum recent receipt artifacts to read."
            ),
        ] = 20,
    ) -> None:
        """Explain governed receipt audit/integrity findings locally. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_explain(
            runtime.session.data_dir,
            source=source,
            finding=finding,
            target=target,
            recipe_id=recipe_id,
            limit=limit,
        )
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_explain_human(payload), nl=False)

    @recipes_receipt_app.command("integrity")
    def recipes_receipt_integrity(
        ctx: typer.Context,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        target: Annotated[
            str | None,
            typer.Option(
                "--target", help="Only scan artifacts for this target when metadata exists."
            ),
        ] = None,
        recipe_id: Annotated[
            str | None,
            typer.Option(
                "--recipe", help="Only scan artifacts for this recipe id when metadata exists."
            ),
        ] = None,
        limit: Annotated[
            int,
            typer.Option(
                "--limit",
                min=1,
                max=100,
                help="Maximum recent primary receipt artifacts to scan (1-100).",
            ),
        ] = 50,
        include_exports: Annotated[
            bool,
            typer.Option(
                "--include-exports", help="Also scan existing ShellForgeAI-owned receipt exports."
            ),
        ] = False,
        include_audit_bundles: Annotated[
            bool,
            typer.Option(
                "--include-audit-bundles",
                help="Also scan existing ShellForgeAI-owned audit bundles.",
            ),
        ] = False,
    ) -> None:
        """Scan governed receipt/export/audit-bundle artifacts for integrity drift. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_integrity(
            runtime.session.data_dir,
            target=target,
            recipe_id=recipe_id,
            limit=limit,
            include_exports=include_exports,
            include_audit_bundles=include_audit_bundles,
        )
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_integrity_human(payload), nl=False)
        if payload.get("status") == "failed":
            raise typer.Exit(1)

    @recipes_receipt_app.command("audit")
    def recipes_receipt_audit(
        ctx: typer.Context,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        target: Annotated[
            str | None,
            typer.Option("--target", help="Only include receipt chains for this target."),
        ] = None,
        recipe_id: Annotated[
            str | None,
            typer.Option("--recipe", help="Only include receipt chains for this recipe id."),
        ] = None,
        limit: Annotated[
            int,
            typer.Option(
                "--limit",
                min=1,
                max=100,
                help="Maximum recent receipt artifacts to inspect (1-100).",
            ),
        ] = 20,
        include_exports: Annotated[
            bool,
            typer.Option(
                "--include-exports", help="Include known local export refs if discoverable."
            ),
        ] = False,
        include_compare_summary: Annotated[
            bool,
            typer.Option(
                "--include-compare-summary",
                help="Show explicit read-only compare command availability; do not run compare.",
            ),
        ] = False,
    ) -> None:
        """Summarize governed execution/recovery receipt chains. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_audit(
            runtime.session.data_dir,
            target=target,
            recipe_id=recipe_id,
            limit=limit,
            include_exports=include_exports,
            include_compare_summary=include_compare_summary,
        )
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_audit_human(payload), nl=False)
        if payload.get("status") == "failed":
            raise typer.Exit(1)

    @recipes_receipt_app.command("audit-bundle")
    def recipes_receipt_audit_bundle(
        ctx: typer.Context,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        target: Annotated[
            str | None,
            typer.Option("--target", help="Only include receipt chains for this target."),
        ] = None,
        recipe_id: Annotated[
            str | None,
            typer.Option("--recipe", help="Only include receipt chains for this recipe id."),
        ] = None,
        limit: Annotated[
            int,
            typer.Option(
                "--limit",
                min=1,
                max=100,
                help="Maximum recent receipt artifacts to inspect (1-100).",
            ),
        ] = 20,
        include_exports: Annotated[
            bool,
            typer.Option(
                "--include-exports", help="Include known local export refs if discoverable."
            ),
        ] = False,
        include_compare_summary: Annotated[
            bool,
            typer.Option(
                "--include-compare-summary",
                help="Include read-only compare availability summary; do not run compare.",
            ),
        ] = False,
    ) -> None:
        """Create an artifact-only governed receipt audit support bundle."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_audit_bundle(
            runtime.session.data_dir,
            target=target,
            recipe_id=recipe_id,
            limit=limit,
            include_exports=include_exports,
            include_compare_summary=include_compare_summary,
        )
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_audit_bundle_human(payload), nl=False)
        if payload.get("status") != "created":
            raise typer.Exit(1)

    @recipes_receipt_app.command("audit-bundle-validate")
    def recipes_receipt_audit_bundle_validate(
        ctx: typer.Context,
        bundle_ref: Annotated[
            str, typer.Argument(help="Audit bundle id or ShellForgeAI-owned bundle path.")
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Validate a governed receipt audit bundle. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_audit_bundle_validate(bundle_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_audit_bundle_validate_human(payload), nl=False)
        if payload.get("status") != "ok":
            raise typer.Exit(1)
