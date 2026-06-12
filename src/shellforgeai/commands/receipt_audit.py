"""Governed receipt audit/history/export/compare command registration (PR191).

Behavior-preserving extraction of read-only/artifact-only ``recipes receipt``
audit/history/export/compare handlers from ``shellforgeai.cli``. The module attaches commands to
the existing receipt Typer group and delegates to the same core builders and
human renderers. It does not move governed recipe execution or recovery
execution, and it introduces no Docker/Compose, shell, model, cleanup,
remediation, rollback execution, recovery execution, repair, or delete behavior.
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
from shellforgeai.core.recipe_receipt_audit import receipt_compare as build_receipt_compare
from shellforgeai.core.recipe_receipt_audit import (
    receipt_compare_latest as build_receipt_compare_latest,
)
from shellforgeai.core.recipe_receipt_audit import receipt_export as build_receipt_export
from shellforgeai.core.recipe_receipt_audit import (
    receipt_export_validate as build_receipt_export_validate,
)
from shellforgeai.core.recipe_receipt_audit import receipt_history as build_receipt_history
from shellforgeai.core.recipe_receipt_audit import receipt_inspect as build_receipt_inspect
from shellforgeai.core.recipe_receipt_audit import receipt_integrity as build_receipt_integrity
from shellforgeai.core.recipe_receipt_explain import receipt_explain as build_receipt_explain
from shellforgeai.core.recipe_receipt_rollback_preview import preview_receipt_rollback


def _cli():
    return sys.modules["shellforgeai.cli"]


def register(recipes_receipt_app: typer.Typer, app: typer.Typer | None = None) -> None:
    """Register read-only/artifact-only governed receipt audit/history commands."""

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

    @recipes_receipt_app.command("history")
    def recipes_receipt_history(
        ctx: typer.Context,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        limit: Annotated[
            int, typer.Option("--limit", help="Maximum receipts to list (1-100).")
        ] = 20,
    ) -> None:
        """List governed recipe execution and recovery receipts newest first. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_history(runtime.session.data_dir, limit=limit)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_history_human(payload), nl=False)

    @recipes_receipt_app.command("inspect")
    def recipes_receipt_inspect(
        ctx: typer.Context,
        receipt_ref: Annotated[
            str, typer.Argument(help="Receipt id or ShellForgeAI-owned receipt path.")
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Inspect a governed execution or recovery receipt. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_inspect(receipt_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_inspect_human(payload), nl=False)
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @recipes_receipt_app.command("export")
    def recipes_receipt_export(
        ctx: typer.Context,
        receipt_ref: Annotated[
            str, typer.Argument(help="Receipt id or ShellForgeAI-owned receipt path.")
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Export a validated receipt bundle to ShellForgeAI-owned export metadata."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_export(receipt_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_export_human(payload), nl=False)
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @recipes_receipt_app.command("export-validate")
    def recipes_receipt_export_validate(
        ctx: typer.Context,
        export_ref: Annotated[
            str, typer.Argument(help="Receipt export id or ShellForgeAI-owned export path.")
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Validate an exported receipt bundle. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_export_validate(export_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(cli._render_recipe_receipt_export_validate_human(payload), nl=False)
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @recipes_receipt_app.command("compare")
    def recipes_receipt_compare(
        ctx: typer.Context,
        before_receipt_ref: Annotated[str, typer.Argument(help="Earlier receipt id/ref.")],
        after_receipt_ref: Annotated[str, typer.Argument(help="Later receipt id/ref.")],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        only_changed: Annotated[
            bool, typer.Option("--only-changed", help="Hide stable fields in human output.")
        ] = False,
    ) -> None:
        """Compare two governed receipt artifacts read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_compare(
            before_receipt_ref, after_receipt_ref, runtime.session.data_dir
        )
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(
                cli._render_recipe_receipt_compare_human(payload, only_changed=only_changed),
                nl=False,
            )
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @recipes_receipt_app.command("compare-latest")
    def recipes_receipt_compare_latest(
        ctx: typer.Context,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        only_changed: Annotated[
            bool, typer.Option("--only-changed", help="Hide stable fields in human output.")
        ] = False,
    ) -> None:
        """Compare the two newest governed receipt artifacts read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_receipt_compare_latest(runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(
                cli._render_recipe_receipt_compare_human(payload, only_changed=only_changed),
                nl=False,
            )
        if payload.get("status") not in {"ok", "not_enough_history"}:
            raise typer.Exit(1)

    @recipes_receipt_app.command("rollback-preview")
    def recipes_receipt_rollback_preview(
        ctx: typer.Context,
        receipt_ref: Annotated[
            str, typer.Argument(help="Saved receipt id or ShellForgeAI-owned path.")
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
