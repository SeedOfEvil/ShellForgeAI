"""Read-only governed recipe registry/preflight command registration (PR189).

Behavior-preserving extraction of the read-only ``recipes`` registry, list,
inspect, eligibility, and preflight (build/save/validate) handlers from
``shellforgeai.cli``. The module attaches commands to the existing recipes
Typer groups and delegates to the same core registry/preflight builders and
human renderers, so output, JSON strictness, exit codes, target gating, and
artifact behavior are unchanged.

Governed execution stays out of this module: ``recipes execute``,
``recipes receipt recovery-execute``, and all receipt recovery/rollback
handlers remain in ``shellforgeai.cli``. This module introduces no
Docker/Compose, restart, cleanup, remediation, rollback, recovery, shell,
model, or arbitrary/natural-language execution behavior.
"""

from __future__ import annotations

import json
import sys
from typing import Annotated, Any

import typer

from shellforgeai.core.recipe_preflight import (
    build_preflight_packet,
    save_preflight_packet,
    validate_preflight_packet,
)
from shellforgeai.core.recipe_registry import (
    detail_payload as recipe_detail_payload,
)
from shellforgeai.core.recipe_registry import (
    eligibility_payload as recipe_eligibility_payload,
)
from shellforgeai.core.recipe_registry import (
    registry_payload as recipe_registry_payload,
)


def _cli():
    return sys.modules["shellforgeai.cli"]


def _collect_recipe_scene() -> dict[str, Any]:
    from shellforgeai.core import triage_ranking

    try:
        return triage_ranking.collect_scene()
    except Exception:
        return {"containers": []}


def _render_recipe_groups_human(payload: dict[str, Any]) -> str:
    groups = (
        ("Available read-only", lambda r: r.get("status") == "available_read_only"),
        (
            "Preview-only / disabled until governed execution lane",
            lambda r: (
                str(r.get("status", "")).startswith("disabled_until")
                or r.get("status") == "preview_only"
            ),
        ),
        ("Future / forbidden", lambda r: r.get("status") == "future"),
    )
    lines = ["ShellForgeAI V2 governed recipe registry", ""]
    recipes = list(payload.get("recipes") or [])
    for title, predicate in groups:
        members = [r for r in recipes if predicate(r)]
        if not members:
            continue
        lines.append(title + ":")
        for recipe in members:
            lines.append(
                f"- {recipe['recipe_id']} — {recipe['title']} "
                f"[{recipe['status']}; mutation={recipe['mutation_class']}]"
            )
            lines.append(f"  First safe command: {recipe['first_safe_command']}")
        lines.append("")
    lines.append("Safety note: This command is read-only. No recipe was executed.")
    return "\n".join(lines) + "\n"


def _render_recipe_detail_human(payload: dict[str, Any]) -> str:
    if payload.get("status") == "not_found":
        return (
            f"Recipe not found: {payload.get('recipe_id')}\n"
            "No action was taken.\n"
            "Safe next command: shellforgeai recipes list\n"
        )
    recipe = payload.get("recipe") or {}
    lines = [
        f"Recipe: {recipe.get('recipe_id')}",
        f"Title: {recipe.get('title')}",
        f"Status: {recipe.get('status')}",
        f"Mutation class: {recipe.get('mutation_class')}",
        f"Description: {recipe.get('description')}",
        "",
        "Required gates:",
    ]
    gates = list(recipe.get("preflight_gates") or []) + list(recipe.get("approval_gates") or [])
    if gates:
        lines.extend(f"- {gate}" for gate in gates)
    else:
        lines.append("- none for read-only inspection")
    lines.extend(
        [
            "",
            f"Verification required: {str(bool(recipe.get('verification_required'))).lower()}",
            f"Rollback available: {str(bool(recipe.get('rollback_available'))).lower()}",
            f"Receipt required: {str(bool(recipe.get('receipt_required'))).lower()}",
            f"First safe command: {recipe.get('first_safe_command')}",
            "Why safe/disabled:",
        ]
    )
    notes = list(recipe.get("safety_notes") or [])
    if recipe.get("blocked_reason"):
        notes.append(recipe["blocked_reason"])
    lines.extend(f"- {note}" for note in (notes or ["Read-only registry detail; no action taken."]))
    lines.append("No action was taken.")
    return "\n".join(lines) + "\n"


def _render_recipe_eligibility_human(payload: dict[str, Any]) -> str:
    if payload.get("status") == "not_found":
        return (
            f"Recipe not found: {payload.get('recipe_id')}\n"
            "Eligibility: blocked\n"
            "No action was taken.\n"
            "First safe command: shellforgeai recipes list\n"
        )
    meta = payload.get("target_metadata") or {}
    lines = [
        f"Recipe: {payload.get('recipe_id')}",
        f"Eligibility: {payload.get('eligibility')}",
        f"Target: {payload.get('target')}",
        f"target_found: {str(bool(meta.get('target_found'))).lower()}",
        f"production_target: {str(bool(meta.get('production_target'))).lower()}",
        "Required labels present:",
    ]
    present = list(meta.get("required_labels_present") or [])
    missing = list(meta.get("required_labels_missing") or [])
    lines.extend(f"- {label}" for label in (present or ["none"]))
    lines.append("Required labels missing:")
    lines.extend(f"- {label}" for label in (missing or ["none"]))
    lines.append("Blockers:")
    lines.extend(f"- {blocker}" for blocker in (payload.get("blockers") or ["none"]))
    lines.extend(
        [
            f"First safe command: {payload.get('first_safe_command')}",
            "No action was taken.",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_recipe_preflight_human(payload: dict[str, Any]) -> str:
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    target_name = str(target.get("name") or payload.get("target") or "")
    status = str(payload.get("status") or "blocked")
    lines: list[str] = []
    if status == "preflight_ready":
        lines.extend(
            [
                "Recipe preflight: ready",
                f"Recipe: {payload.get('recipe_id')}",
                f"Target: {target_name}",
                (
                    "Target class: "
                    f"{payload.get('target_class') or 'disposable allowlisted container'}"
                ),
                "",
                "Would preview:",
            ]
        )
        argv = (
            (payload.get("action_preview") or {}).get("argv")
            if isinstance(payload.get("action_preview"), dict)
            else []
        )
        lines.append(f"  {' '.join(str(part) for part in (argv or []))}")
        lines.extend(["", "Gates:"])
        for gate in payload.get("gates") or []:
            label = str(gate.get("name") or "").replace("_", " ")
            lines.append(f"- {label}: {gate.get('status')}")
    else:
        lines.extend(
            [
                "Recipe preflight: blocked"
                if status != "not_found"
                else "Recipe preflight: not_found",
                f"Recipe: {payload.get('recipe_id')}",
                f"Target: {target_name}",
                (
                    "Reason: "
                    f"{payload.get('reason') or ', '.join(payload.get('blockers') or ['blocked'])}"
                ),
            ]
        )
    if payload.get("artifact_written"):
        lines.extend(
            [
                "",
                f"Preflight ID: {payload.get('preflight_id')}",
                f"Preflight path: {payload.get('preflight_path')}",
                f"Manifest path: {payload.get('manifest_path')}",
            ]
        )
    lines.extend(
        [
            "",
            "Safety:",
            "- Read-only preflight.",
            "- No command was executed.",
            "- No container was restarted.",
            "- No remediation, rollback, cleanup, Docker Compose, or shell action occurred.",
            "",
            "First safe command:",
            f"  {payload.get('first_safe_command')}",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_recipe_preflight_validate_human(payload: dict[str, Any]) -> str:
    lines = [
        f"Recipe preflight validation: {payload.get('status')}",
        f"Preflight ID: {payload.get('preflight_id') or 'unknown'}",
        f"Path: {payload.get('preflight_path') or 'not found'}",
        "Checks:",
    ]
    for key, value in (payload.get("checks") or {}).items():
        lines.append(f"- {key}: {str(bool(value)).lower()}")
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    lines.append("No action was taken.")
    return "\n".join(lines) + "\n"


def register(recipes_app: typer.Typer, recipes_preflight_app: typer.Typer) -> None:
    """Register read-only recipe registry/eligibility/preflight commands."""

    @recipes_app.callback(invoke_without_command=True)
    def recipes_root(
        ctx: typer.Context,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """List the read-only V2 governed recipe registry."""
        if ctx.invoked_subcommand is not None:
            return
        payload = recipe_registry_payload()
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(_render_recipe_groups_human(payload), nl=False)

    @recipes_app.command("list")
    def recipes_list(
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """List governed recipes without executing any recipe."""
        payload = recipe_registry_payload()
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(_render_recipe_groups_human(payload), nl=False)

    @recipes_app.command("inspect")
    def recipes_inspect(
        recipe_id: Annotated[str, typer.Argument(help="Recipe id to inspect.")],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Inspect one governed recipe. No action is taken."""
        payload = recipe_detail_payload(recipe_id)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(_render_recipe_detail_human(payload), nl=False)
        if payload.get("status") == "not_found":
            raise typer.Exit(1)

    @recipes_app.command("eligibility")
    def recipes_eligibility(
        recipe_id: Annotated[str, typer.Option("--recipe", help="Recipe id to evaluate.")],
        target: Annotated[str, typer.Option("--target", help="Exact target name to evaluate.")],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Evaluate read-only recipe eligibility for an exact target. No execution."""
        from shellforgeai.core import triage_ranking

        try:
            scene = triage_ranking.collect_scene()
        except Exception:
            scene = {"containers": []}
        payload = recipe_eligibility_payload(recipe_id, target, scene=scene)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(_render_recipe_eligibility_human(payload), nl=False)
        if payload.get("status") == "not_found":
            raise typer.Exit(1)

    @recipes_preflight_app.callback(invoke_without_command=True)
    def recipes_preflight_root(
        ctx: typer.Context,
        recipe_id: Annotated[
            str | None, typer.Option("--recipe", help="Recipe id to preflight.")
        ] = None,
        target: Annotated[
            str | None, typer.Option("--target", help="Exact target name to evaluate.")
        ] = None,
        save: Annotated[
            bool, typer.Option("--save", help="Write a ShellForgeAI-owned preflight artifact.")
        ] = False,
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Build a read-only governed recipe preflight packet. No execution."""
        if ctx.invoked_subcommand is not None:
            return
        if not recipe_id or not target:
            message = "--recipe and --target are required for recipes preflight"
            if json_out:
                typer.echo(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "mode": "v2_recipe_preflight",
                            "status": "error",
                            "read_only": True,
                            "mutation_performed": False,
                            "blockers": [message],
                        }
                    )
                )
            else:
                typer.echo(
                    f"Recipe preflight: blocked\nReason: {message}\nNo action was taken.\n",
                    nl=False,
                )
            raise typer.Exit(2)
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = build_preflight_packet(recipe_id, target, scene=_collect_recipe_scene())
        if save:
            try:
                payload = save_preflight_packet(payload, runtime.session.data_dir)
            except ValueError as exc:
                payload = {
                    **payload,
                    "status": "error",
                    "warnings": [str(exc)],
                    "artifact_written": False,
                }
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(_render_recipe_preflight_human(payload), nl=False)
        if payload.get("status") == "error":
            raise typer.Exit(1)

    @recipes_preflight_app.command("validate")
    def recipes_preflight_validate(
        ctx: typer.Context,
        preflight_ref: Annotated[
            str, typer.Argument(help="Saved preflight id or ShellForgeAI-owned path.")
        ],
        json_out: Annotated[bool, typer.Option("--json", help="Emit strict JSON only.")] = False,
    ) -> None:
        """Validate a saved recipe preflight packet. Read-only."""
        cli = _cli()
        runtime = cli._ctx(ctx)
        payload = validate_preflight_packet(preflight_ref, runtime.session.data_dir)
        if json_out:
            typer.echo(json.dumps(payload))
        else:
            typer.echo(_render_recipe_preflight_validate_human(payload), nl=False)
        if payload.get("status") != "ok":
            raise typer.Exit(1)
