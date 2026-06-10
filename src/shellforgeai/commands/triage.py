# ruff: noqa: F821
from __future__ import annotations

import functools
import sys
from typing import Annotated

import typer


def _sync_cli_globals() -> None:
    """Expose cli-owned helpers/imports for behavior-preserving handlers."""

    cli = sys.modules["shellforgeai.cli"]
    for name, value in vars(cli).items():
        if name.startswith("__"):
            continue
        globals()[name] = value


def _wrap_extracted_callbacks(*apps: typer.Typer) -> None:
    """Refresh cli globals at callback runtime while preserving Typer metadata."""

    def wrap(callback):
        if callback is None or getattr(callback, "__module__", None) != __name__:
            return callback
        if getattr(callback, "_shellforgeai_refreshes_cli_globals", False):
            return callback

        @functools.wraps(callback)
        def wrapped(*args, **kwargs):
            _sync_cli_globals()
            return callback(*args, **kwargs)

        wrapped._shellforgeai_refreshes_cli_globals = True
        return wrapped

    for app in apps:
        if app.registered_callback is not None:
            app.registered_callback.callback = wrap(app.registered_callback.callback)
        for command in app.registered_commands:
            command.callback = wrap(command.callback)


def register(
    triage_app: typer.Typer,
    triage_docker_app: typer.Typer,
    triage_docker_snapshot_app: typer.Typer,
) -> None:
    """Register read-only ``triage`` command handlers extracted from ``cli.py``."""

    _sync_cli_globals()

    @triage_app.callback(invoke_without_command=True)
    def triage(
        ctx: typer.Context,
        brief: Annotated[
            bool, typer.Option("--brief", help="Emit bounded brief triage output.")
        ] = False,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        target: Annotated[
            str | None,
            typer.Option("--target", help="Show V2 detail for one ranked suspect."),
        ] = None,
        top: Annotated[int, typer.Option("--top", min=1, help="Maximum ranked suspects.")] = 5,
    ) -> None:
        """Read-only V2 triage entrypoint: ranked suspects and first safe command."""
        if ctx.invoked_subcommand is not None:
            return
        if target:
            detail = _build_v2_triage_detail_payload(target)
            if json_out:
                typer.echo(json.dumps(detail))
                return
            typer.echo(_render_v2_triage_detail_human(detail), nl=False)
            return
        payload = _build_v2_triage_payload(top=top)
        if json_out:
            typer.echo(json.dumps(payload))
            return
        if brief:
            typer.echo(_render_v2_triage_brief(payload), nl=False)
            return
        typer.echo(_render_v2_triage_human(payload), nl=False)

    @triage_docker_app.callback(invoke_without_command=True)
    def triage_docker(
        ctx: typer.Context,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        brief: Annotated[
            bool,
            typer.Option("--brief", help="Mirror the V2 brief triage view (read-only)."),
        ] = False,
    ) -> None:
        """PR81 read-only Docker triage ranking ("scene awareness").

        Inventories the current Docker scene using existing read-only collectors,
        ranks suspicious containers across multiple failure classes (crashloop,
        noisy errors, bad HTTP, disk pressure, permission denied, high-CPU watch),
        and prints evidence/why/safe-next-command per suspect. Never restarts,
        stops, removes, prunes, or otherwise mutates anything.

        ``--brief`` is a PR146 compatibility alias that mirrors the bounded
        ``shellforgeai triage --brief`` view so operators get one consistent
        brief shape regardless of which entrypoint they reach for.
        """
        from shellforgeai.core.triage_ranking import (
            collect_scene,
            rank_scene,
            render_human,
        )

        if ctx.invoked_subcommand is not None:
            return

        if brief:
            # Compatibility alias: mirror the V2 top-level brief triage view so
            # `triage docker --brief` never feels staler than `triage --brief`.
            typer.echo(_render_v2_triage_brief(_build_v2_triage_payload()), nl=False)
            return

        scene = collect_scene()
        payload = rank_scene(scene)

        if json_out:
            typer.echo(json.dumps(payload))
            return

        console.print(render_human(payload), end="")

    @triage_docker_app.command("detail")
    def triage_docker_detail(
        suspect: Annotated[str | None, typer.Argument(help="Suspect name.")] = None,
        rank: Annotated[
            int | None, typer.Option("--rank", min=1, help="Rank number to inspect.")
        ] = None,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """PR83 read-only Docker triage detail drilldown for one ranked suspect."""
        from shellforgeai.core.triage_ranking import (
            build_detail_payload,
            collect_scene,
            rank_scene,
            render_detail_human,
        )

        if suspect is not None and rank is not None:
            raise typer.BadParameter("provide suspect or --rank, not both")
        scene = collect_scene()
        ranked = rank_scene(scene)
        payload = build_detail_payload(scene, ranked, suspect_name=suspect, rank=rank)
        if json_out:
            typer.echo(json.dumps(payload))
            if payload.get("status") == "ok":
                return
            raise typer.Exit(1 if payload.get("status") == "error" else 0)
        console.print(render_detail_human(payload), end="")
        if payload.get("status") == "error":
            raise typer.Exit(1)

    @triage_docker_app.command("timeline")
    def triage_docker_timeline(
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        window: Annotated[int, typer.Option("--window", min=1)] = 5,
        top: Annotated[int, typer.Option("--top", min=1)] = 5,
        only_regressions: Annotated[bool, typer.Option("--only-regressions")] = False,
        include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    ) -> None:
        from shellforgeai.core.triage_ranking import (
            build_snapshot_timeline,
            render_snapshot_timeline_human,
        )

        payload = build_snapshot_timeline(
            Path(load_settings().app.data_dir),
            window=window,
            top=top,
            only_regressions=only_regressions,
            include_stable=include_stable,
        )
        if json_out:
            typer.echo(json.dumps(payload))
            if payload.get("status") == "ok":
                return
            raise typer.Exit(1)
        console.print(render_snapshot_timeline_human(payload), end="")
        if payload.get("status") not in ("ok", "warn"):
            raise typer.Exit(1)

    @triage_docker_snapshot_app.callback()
    def triage_docker_snapshot(
        ctx: typer.Context,
        top: Annotated[int, typer.Option("--top", min=1, help="Limit to top N suspects.")] = 5,
        include_details: Annotated[
            bool, typer.Option("--include-details", help="Include compact detail evidence.")
        ] = False,
        save: Annotated[
            bool, typer.Option("--save", help="Save snapshot artifact packet.")
        ] = False,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """PR84 read-only Docker triage incident snapshot / handoff."""
        if ctx.invoked_subcommand is not None:
            return
        from shellforgeai.core.triage_ranking import (
            build_snapshot_payload,
            collect_scene,
            rank_scene,
            render_saved_snapshot_human,
            render_snapshot_human,
            save_snapshot_artifact,
        )

        scene = collect_scene()
        ranked = rank_scene(scene)
        payload = build_snapshot_payload(scene, ranked, top=top, include_details=include_details)
        if save:
            source_command = "shellforgeai triage docker snapshot --save"
            if include_details:
                source_command += " --include-details"
            if top != 5:
                source_command += f" --top {top}"
            saved = save_snapshot_artifact(
                payload, Path(load_settings().app.data_dir), source_command=source_command
            )
            if json_out:
                typer.echo(json.dumps(saved))
                return
            console.print(render_saved_snapshot_human(saved), end="")
            return
        if json_out:
            typer.echo(json.dumps(payload))
            return
        console.print(render_snapshot_human(payload), end="")

    @triage_docker_snapshot_app.command("validate")
    def triage_docker_snapshot_validate(
        snapshot: Annotated[str, typer.Argument(help="Snapshot artifact id or path.")],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        from shellforgeai.core.triage_ranking import (
            render_snapshot_validation_human,
            validate_snapshot_artifact,
        )

        payload = validate_snapshot_artifact(snapshot, Path(load_settings().app.data_dir))
        if json_out:
            typer.echo(json.dumps(payload))
            if payload.get("status") == "ok":
                return
            raise typer.Exit(1)
        console.print(render_snapshot_validation_human(payload), end="")

    @triage_docker_snapshot_app.command("export")
    def triage_docker_snapshot_export(
        ctx: typer.Context,
        snapshot: Annotated[str, typer.Argument(help="Snapshot artifact id or path.")],
        as_json: Annotated[bool, typer.Option("--json")] = False,
        output: Annotated[
            Path | None, typer.Option("--output", help="Output path under <data_dir>/exports.")
        ] = None,
    ) -> None:
        from shellforgeai.core.triage_ranking import export_snapshot_artifact

        payload = export_snapshot_artifact(
            snapshot, Path(load_settings().app.data_dir), output=output
        )
        if as_json:
            console.print_json(json.dumps(payload))
            if payload.get("status") == "exported":
                return
            raise typer.Exit(code=1)
        if payload.get("status") != "exported":
            console.print("Triage snapshot export failed")
            for w in payload.get("warnings") or []:
                console.print(f"- {w}")
            raise typer.Exit(code=1)
        exp = payload.get("export") or {}
        src = payload.get("source_snapshot") or {}
        console.print("Triage snapshot export created")
        console.print("\nSource snapshot:")
        console.print(f"- id: {src.get('id')}")
        console.print(f"- path: {src.get('path')}")
        console.print(f"- validation: {'passed' if src.get('validated') else 'failed'}")
        console.print("\nExport:")
        console.print(f"- id: {exp.get('id')}")
        console.print(f"- path: {exp.get('path')}")
        console.print("- files:")
        for f in exp.get("files") or []:
            console.print(f"  - {f}")

    @triage_docker_snapshot_app.command("compare")
    def triage_docker_snapshot_compare(
        snapshot_a: Annotated[str, typer.Argument(help="Before snapshot id or path.")],
        snapshot_b: Annotated[str, typer.Argument(help="After snapshot id or path.")],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        top: Annotated[int, typer.Option("--top", min=1)] = 5,
        only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
        include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
        include_evidence: Annotated[bool, typer.Option("--include-evidence")] = False,
    ) -> None:
        from shellforgeai.core.triage_ranking import (
            compare_snapshot_payload,
            render_snapshot_compare_human,
            validate_snapshot_artifact,
        )

        data_dir = Path(load_settings().app.data_dir)
        va = validate_snapshot_artifact(snapshot_a, data_dir)
        vb = validate_snapshot_artifact(snapshot_b, data_dir)
        if va.get("status") != "ok" or vb.get("status") != "ok":
            payload = {
                "schema_version": 1,
                "mode": "docker_triage_snapshot_compare",
                "status": "error",
                "read_only": True,
                "mutation_performed": False,
                "warnings": ["snapshot validation failed"],
                "summary": {},
                "regressions": [],
                "recoveries": [],
                "stable": [],
                "new_suspects": [],
                "removed_suspects": [],
                "safety": {"read_only": True, "mutation_performed": False},
            }
        else:
            sa = json.loads(
                Path((va.get("artifact") or {}).get("path") or "")
                .joinpath("triage-snapshot.json")
                .read_text(encoding="utf-8")
            )
            sb = json.loads(
                Path((vb.get("artifact") or {}).get("path") or "")
                .joinpath("triage-snapshot.json")
                .read_text(encoding="utf-8")
            )
            payload = compare_snapshot_payload(
                sa,
                sb,
                top=top,
                only_changed=only_changed,
                include_stable=include_stable,
                include_evidence=include_evidence,
            )
        if json_out:
            typer.echo(json.dumps(payload))
            if payload.get("status") == "ok":
                return
            raise typer.Exit(1)
        console.print(render_snapshot_compare_human(payload), end="")
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @triage_docker_snapshot_app.command("compare-export")
    def triage_docker_snapshot_compare_export(
        export_a: Annotated[str, typer.Argument(help="Before export path.")],
        export_b: Annotated[str, typer.Argument(help="After export path.")],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
        top: Annotated[int, typer.Option("--top", min=1)] = 5,
        only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
        include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
        include_evidence: Annotated[bool, typer.Option("--include-evidence")] = False,
    ) -> None:
        from shellforgeai.core.triage_ranking import (
            compare_snapshot_exports,
            render_snapshot_compare_human,
        )

        payload = compare_snapshot_exports(
            export_a,
            export_b,
            top=top,
            only_changed=only_changed,
            include_stable=include_stable,
            include_evidence=include_evidence,
        )
        if json_out:
            typer.echo(json.dumps(payload))
            if payload.get("status") == "ok":
                return
            raise typer.Exit(1)
        console.print(render_snapshot_compare_human(payload), end="")
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @triage_docker_snapshot_app.command("export-validate")
    def triage_docker_snapshot_export_validate(
        ctx: typer.Context,
        export_path: Annotated[str, typer.Argument(help="Export path.")],
        as_json: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        from shellforgeai.core.triage_ranking import validate_snapshot_export

        _ = _ctx(ctx)
        payload = validate_snapshot_export(export_path)
        if as_json:
            console.print_json(json.dumps(payload))
            if payload.get("status") == "ok":
                return
            raise typer.Exit(code=1)
        if payload.get("status") != "ok":
            console.print("Triage snapshot export validation failed")
            for w in payload.get("warnings") or []:
                console.print(f"- {w}")
            raise typer.Exit(code=1)
        console.print("Triage snapshot export validation passed")
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    _wrap_extracted_callbacks(triage_app, triage_docker_app, triage_docker_snapshot_app)
