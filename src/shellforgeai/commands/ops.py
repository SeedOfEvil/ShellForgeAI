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


def register(ops_app: typer.Typer, ops_report_app: typer.Typer) -> None:
    """Register read-only ``ops`` command handlers extracted from ``cli.py``."""

    _sync_cli_globals()

    @ops_app.command("status")
    def ops_status(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
        settings = load_settings()
        profile = load_profile(settings.app.default_profile, Path.cwd())
        session = build_session_context(settings, profile, mode="cli", cwd=Path.cwd())
        data_dir = session.data_dir
        warnings: list[str] = []
        now = datetime.now(timezone.utc).isoformat()

        evidence_path = latest_evidence_artifact(data_dir)
        latest_evidence: dict[str, Any] | None = None
        if evidence_path and evidence_path.exists():
            ev = _safe_load_json(evidence_path, warnings) or {}
            latest_evidence = {
                "id": evidence_path.parent.name,
                "path": str(evidence_path),
                "created_at": ev.get("created_at"),
                "updated_at": ev.get("updated_at"),
                "age_seconds": _age_seconds(ev, evidence_path),
                "target": ev.get("target"),
                "runbook_present": (evidence_path.parent / "runbook.json").exists(),
            }

        proposals_root = data_dir / "proposals"
        proposal_items: list[dict[str, Any]] = []
        proposal_counts = {
            k: 0 for k in ("pending", "approved", "rejected", "canceled", "archived", "unknown")
        }
        for p in sorted(proposals_root.glob("*.json")) if proposals_root.exists() else []:
            obj = _safe_load_json(p, warnings)
            if not obj:
                continue
            st = str(obj.get("status") or "unknown")
            proposal_counts[st if st in proposal_counts else "unknown"] += 1
            proposal_items.append({"path": p, "payload": obj})
        latest_prop = max(proposal_items, key=lambda x: _ts(x["payload"], x["path"]), default=None)
        prop_summary = None
        if latest_prop:
            pp = latest_prop["payload"]
            compose = pp.get("compose") if isinstance(pp.get("compose"), dict) else {}
            prop_summary = {
                "id": pp.get("proposal_id") or latest_prop["path"].stem,
                "path": str(latest_prop["path"]),
                "kind": pp.get("kind"),
                "status": pp.get("status", "unknown"),
                "target": pp.get("target_container"),
                "created_at": pp.get("created_at"),
                "updated_at": pp.get("updated_at"),
                "age_seconds": _age_seconds(pp, latest_prop["path"]),
                "compose": {
                    "managed": bool(compose.get("managed") or compose.get("detected")),
                    "project": compose.get("project"),
                    "service": compose.get("service"),
                    "restart_scope": "container",
                    "compose_mutation": False,
                },
            }

        mission_items: list[dict[str, Any]] = []
        mission_counts = {k: 0 for k in ("ready", "executed", "blocked", "failed", "unknown")}
        for p in (
            sorted((data_dir / "missions").glob("**/mission.json"))
            if (data_dir / "missions").exists()
            else []
        ):
            obj = _safe_load_json(p, warnings)
            if not obj:
                continue
            st = str(obj.get("status") or "unknown")
            mission_counts[st if st in mission_counts else "unknown"] += 1
            mission_items.append({"path": p, "payload": obj})
        latest_m = max(mission_items, key=lambda x: _ts(x["payload"], x["path"]), default=None)
        latest_exec = max(
            [m for m in mission_items if str(m["payload"].get("status")) == "executed"],
            key=lambda x: _ts(x["payload"], x["path"]),
            default=None,
        )

        def _mission_summary(item: dict[str, Any] | None) -> dict[str, Any] | None:
            if not item:
                return None
            mp = item["payload"]
            compose = mp.get("compose") if isinstance(mp.get("compose"), dict) else {}
            return {
                "id": mp.get("mission_id") or item["path"].parent.name,
                "path": str(item["path"]),
                "mission_type": mp.get("mission_type", "docker_restart"),
                "status": mp.get("status", "unknown"),
                "target": mp.get("target_container"),
                "proposal_id": mp.get("proposal_id"),
                "created_at": mp.get("created_at"),
                "updated_at": mp.get("updated_at"),
                "age_seconds": _age_seconds(mp, item["path"]),
                "compose": {
                    "managed": bool(compose.get("managed") or compose.get("detected")),
                    "project": compose.get("project"),
                    "service": compose.get("service"),
                    "restart_scope": "container",
                    "compose_mutation": False,
                },
            }

        latest_mission = _mission_summary(latest_m)
        latest_executed = _mission_summary(latest_exec)
        audit_status = "unknown"
        if (data_dir / "audit_events.jsonl").exists():
            audit_status = "ok"
        cleanup_report = scan_metadata_hygiene(data_dir)
        total_bytes = cleanup_report.get("total_bytes", 0)
        cleanup_status = "ok" if isinstance(total_bytes, int) and total_bytes >= 0 else "unknown"
        payload = {
            "schema_version": "1",
            "status": "warn" if warnings else "ok",
            "generated_at": now,
            "data_dir": str(data_dir),
            "latest_evidence": latest_evidence,
            "proposals": {"latest": prop_summary, "counts": proposal_counts},
            "missions": {
                "latest": latest_mission,
                "latest_executed": latest_executed,
                "counts": mission_counts,
            },
            "compose": {
                "recent_managed_targets_count": sum(
                    1 for i in [prop_summary, latest_mission] if i and i["compose"]["managed"]
                ),
                "latest_target": (latest_mission or prop_summary or {}).get("target"),
                "latest_project": ((latest_mission or prop_summary or {}).get("compose") or {}).get(
                    "project"
                ),
                "latest_service": ((latest_mission or prop_summary or {}).get("compose") or {}).get(
                    "service"
                ),
                "compose_mutation": False,
            },
            "safety": {
                "read_only": True,
                "natural_language_mutation_refused": True,
                "arbitrary_command_execution": False,
                "compose_mutation": False,
                "execution_requires_apply_gate": True,
            },
            "audit": {"status": audit_status, "latest_export": None, "latest_closure_report": None},
            "cleanup": {
                "status": cleanup_status,
                "latest_cleanup_plan": None,
                "latest_cleanup_archive": None,
            },
            "warnings": warnings,
            "next_safe_commands": [
                'shellforgeai ask "show compose context for this restart proposal"',
                "shellforgeai approvals list --all",
                "shellforgeai mission restart status <mission-id>",
                "shellforgeai audit validate",
            ],
        }
        if json_out:
            typer.echo(json.dumps(payload))
            return
        console.print("ShellForgeAI ops status")
        console.print("\nLatest evidence:")
        if not latest_evidence:
            console.print("- none found")
        else:
            console.print(f"- artifact: {latest_evidence['id']}")
            console.print(f"- age_seconds: {latest_evidence['age_seconds']}")
        console.print("\nProposals:")
        console.print(f"- latest: {(prop_summary or {}).get('id', 'none')}")
        console.print(f"- counts: {proposal_counts}")
        console.print("\nMissions:")
        console.print(f"- latest: {(latest_mission or {}).get('id', 'none')}")
        console.print(f"- latest executed: {(latest_executed or {}).get('id', 'none')}")
        console.print("\nSafety:")
        console.print("- read_only: true")
        console.print("- compose_mutation: false")
        console.print("- arbitrary_command_execution: false")
        console.print("- apply gate: required")

    @session_summary_app.command("validate")
    def session_summary_validate(
        summary_ref: Annotated[str, typer.Argument(help="Summary id or summary directory path")],
        json_out: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        from shellforgeai.core.interactive_summary_artifact import validate_interactive_summary

        payload = validate_interactive_summary(summary_ref, Path(load_settings().app.data_dir))
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        console.print(
            "Interactive summary validation passed"
            if payload.get("status") == "ok"
            else "Interactive summary validation failed"
        )
        for k, v in (payload.get("checks") or {}).items():
            console.print(f"- {k}: {'ok' if v else 'failed'}")
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @session_summary_app.command("export")
    def session_summary_export(
        summary_ref: Annotated[str, typer.Argument(help="Summary id or path")],
        json_out: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        from shellforgeai.core.interactive_summary_artifact import export_interactive_summary

        payload = export_interactive_summary(summary_ref, Path(load_settings().app.data_dir))
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "exported" else 1)
        if payload.get("status") != "exported":
            console.print("Interactive summary export failed")
            for warning in payload.get("warnings") or []:
                console.print(f"- {warning}")
            raise typer.Exit(1)
        export = payload.get("export") or {}
        source = payload.get("source_summary") or {}
        console.print(
            "Interactive summary export created"
            if not payload.get("existing")
            else "Interactive summary export already exists (reused)"
        )
        console.print(f"- summary_id: {source.get('id')}")
        console.print(f"- export_id: {export.get('id')}")
        console.print(f"- path: {export.get('path')}")

    @session_summary_app.command("export-validate")
    def session_summary_export_validate(
        export_ref: Annotated[str, typer.Argument(help="Export id or path")],
        json_out: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        from shellforgeai.core.interactive_summary_artifact import (
            validate_interactive_summary_export,
        )

        payload = validate_interactive_summary_export(
            export_ref, Path(load_settings().app.data_dir)
        )
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        console.print(
            "Interactive summary export validation passed"
            if payload.get("status") == "ok"
            else "Interactive summary export validation failed"
        )
        for k, v in (payload.get("checks") or {}).items():
            console.print(f"- {k}: {'ok' if v else 'failed'}")
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    def _render_interactive_summary_history_human(payload: dict[str, Any]) -> str:
        lines = ["Interactive summary history", ""]
        if payload.get("status") == "empty":
            lines.append("No saved interactive summaries found.")
            lines.append("Try: shellforgeai interactive, then /summary --save")
        else:
            latest = (payload.get("summaries") or [None])[0]
            if latest:
                lines.extend(["Latest:", ""])
                lines.append(f"- {latest.get('summary_id')}")
                lines.append(f"- created: {latest.get('created_at') or '-'}")
                lines.append(f"- events: {latest.get('events_seen', 0)}")
                latest_checks = latest.get("checks_count", 0)
                latest_findings = latest.get("findings_count", 0)
                lines.append(f"- checks/findings: {latest_checks}/{latest_findings}")
                lines.append(f"- refusals: {latest.get('refusals_count', 0)}")
                lines.append(f"- first safe command: {latest.get('first_safe_command') or '-'}")
                lines.append(f"- path: {latest.get('path')}")
            lines.extend(["", "Recent summaries:"])
            for idx, summary in enumerate(payload.get("summaries") or [], start=1):
                lines.append(f"{idx}. {summary.get('summary_id')}")
                lines.append(f"   created: {summary.get('created_at') or '-'}")
                lines.append(f"   events: {summary.get('events_seen', 0)}")
                checks_count = summary.get("checks_count", 0)
                findings_count = summary.get("findings_count", 0)
                lines.append(f"   checks/findings: {checks_count}/{findings_count}")
                lines.append(f"   refusals: {summary.get('refusals_count', 0)}")
                lines.append(f"   first safe command: {summary.get('first_safe_command') or '-'}")
                lines.append(f"   path: {summary.get('path')}")
        if payload.get("warnings"):
            lines.extend(["", "Warnings:"])
            for warning in payload.get("warnings") or []:
                lines.append(f"- {warning}")
        lines.extend(
            [
                "",
                (
                    "Safety: read-only. No collection, mutation, cleanup, remediation, "
                    "rollback, or Compose command executed."
                ),
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    def _render_interactive_summary_compare_human(
        payload: dict[str, Any], *, include_stable: bool = False
    ) -> str:
        if payload.get("mode") == "interactive_summary_compare_export":
            title = "Interactive summary export compare"
        else:
            title = (
                "Interactive summary compare-latest"
                if payload.get("compare_latest")
                else "Interactive summary compare"
            )
        lines = [title]
        if payload.get("compare_latest"):
            lines.append("Comparing latest two summaries...")
        lines.extend(["", f"Status: {payload.get('status')}"])
        if payload.get("status") != "ok":
            for warning in payload.get("warnings") or []:
                lines.append(f"- {warning}")
            lines.append(
                "Safety: read-only. No collectors/model/shell/mutation, cleanup, remediation, "
                "rollback, or Compose command executed."
            )
            return "\n".join(lines).rstrip() + "\n"
        if payload.get("mode") == "interactive_summary_compare_export":
            before = payload.get("before") or {}
            after = payload.get("after") or {}
            lines.append(
                f"Before export: {before.get('export_ref') or payload.get('before_export_id')}"
            )
            lines.append(
                f"After export: {after.get('export_ref') or payload.get('after_export_id')}"
            )
            lines.append(f"Before summary: {payload.get('before_summary_id')}")
            lines.append(f"After summary: {payload.get('after_summary_id')}")
        else:
            lines.append(f"Before: {payload.get('before_summary_id')}")
            lines.append(f"After: {payload.get('after_summary_id')}")
        summary = payload.get("summary") or {}
        lines.extend(
            [
                "",
                "Changes:",
                f"- events: {summary.get('events_before')} -> {summary.get('events_after')}",
                f"- checks: {summary.get('checks_before')} -> {summary.get('checks_after')}",
                f"- findings: {summary.get('findings_before')} -> {summary.get('findings_after')}",
                f"- new findings: {summary.get('new_findings')}",
                f"- resolved/missing findings: {summary.get('resolved_or_missing_findings')}",
                f"- new refusals: {summary.get('new_refusals')}",
                f"- safety drift: {summary.get('safety_drift')}",
            ]
        )
        for label, key in (
            ("New checks", "new_checks"),
            ("New findings", "new_findings"),
            ("Resolved/missing checks", "resolved_or_missing_checks"),
            ("Resolved/missing findings", "resolved_or_missing_findings"),
            ("New refusals", "new_refusals"),
        ):
            values = payload.get(key) or []
            if values:
                lines.extend(["", f"{label}:"])
                for value in values[:8]:
                    lines.append(f"- {value}")
        if payload.get("safety_drift"):
            lines.extend(["", "Safety drift:"])
            for item in payload.get("safety_drift") or []:
                lines.append(f"- {item.get('flag')}: {item.get('before')} -> {item.get('after')}")
        if include_stable and payload.get("stable"):
            lines.extend(["", "Stable items:"])
            for key, value in (payload.get("stable") or {}).items():
                lines.append(f"- {key}: {value}")
        lines.extend(["", f"First safe command: {payload.get('first_safe_command') or '-'}"])
        lines.append(
            "Safety: read-only. No collectors/model/shell/mutation, cleanup, remediation, "
            "rollback, or Compose command executed."
        )
        return "\n".join(lines).rstrip() + "\n"

    @session_summary_app.command("history")
    def session_summary_history(
        json_out: Annotated[bool, typer.Option("--json")] = False,
        limit: Annotated[int, typer.Option("--limit", min=1)] = 10,
    ) -> None:
        from shellforgeai.core.interactive_summary_artifact import interactive_summary_history

        payload = interactive_summary_history(Path(load_settings().app.data_dir), limit=limit)
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0)
        console.print(_render_interactive_summary_history_human(payload), end="")

    @session_summary_app.command("compare")
    def session_summary_compare(
        before_ref: Annotated[str, typer.Argument(help="Before summary id or path")],
        after_ref: Annotated[str, typer.Argument(help="After summary id or path")],
        json_out: Annotated[bool, typer.Option("--json")] = False,
        only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
        include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    ) -> None:
        from shellforgeai.core.interactive_summary_artifact import compare_interactive_summaries

        payload = compare_interactive_summaries(
            before_ref,
            after_ref,
            Path(load_settings().app.data_dir),
            only_changed=only_changed,
            include_stable=include_stable,
        )
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        if payload.get("status") != "ok":
            console.print(_render_interactive_summary_compare_human(payload), end="")
            raise typer.Exit(1)
        console.print(
            _render_interactive_summary_compare_human(payload, include_stable=include_stable),
            end="",
        )

    @session_summary_app.command("compare-export")
    def session_summary_compare_export(
        before_ref: Annotated[
            str, typer.Argument(help="Before interactive summary export id or path")
        ],
        after_ref: Annotated[
            str, typer.Argument(help="After interactive summary export id or path")
        ],
        json_out: Annotated[bool, typer.Option("--json")] = False,
        only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
        include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    ) -> None:
        from shellforgeai.core.interactive_summary_artifact import (
            compare_interactive_summary_exports,
        )

        payload = compare_interactive_summary_exports(
            before_ref,
            after_ref,
            Path(load_settings().app.data_dir),
            only_changed=only_changed,
            include_stable=include_stable,
        )
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        if payload.get("status") != "ok":
            console.print(_render_interactive_summary_compare_human(payload), end="")
            raise typer.Exit(1)
        console.print(
            _render_interactive_summary_compare_human(payload, include_stable=include_stable),
            end="",
        )

    @session_summary_app.command("compare-latest")
    def session_summary_compare_latest(
        json_out: Annotated[bool, typer.Option("--json")] = False,
        only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
        include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
    ) -> None:
        from shellforgeai.core.interactive_summary_artifact import (
            compare_latest_interactive_summaries,
        )

        payload = compare_latest_interactive_summaries(
            Path(load_settings().app.data_dir),
            only_changed=only_changed,
            include_stable=include_stable,
        )
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        if payload.get("status") != "ok":
            console.print(_render_interactive_summary_compare_human(payload), end="")
            raise typer.Exit(1)
        console.print(
            _render_interactive_summary_compare_human(payload, include_stable=include_stable),
            end="",
        )

    @ops_report_app.callback()
    def ops_report(
        ctx: typer.Context,
        json_out: Annotated[bool, typer.Option("--json")] = False,
        top: Annotated[int, typer.Option("--top", min=1)] = 5,
        include_details: Annotated[bool, typer.Option("--include-details")] = False,
        include_remediation: Annotated[bool, typer.Option("--include-remediation")] = False,
        include_timeline: Annotated[bool, typer.Option("--include-timeline")] = False,
        save: Annotated[bool, typer.Option("--save")] = False,
        brief: Annotated[
            bool, typer.Option("--brief", help="Render compact human pressure-mode output.")
        ] = False,
    ) -> None:
        if ctx.invoked_subcommand is not None:
            return
        payload = _build_ops_report_payload(
            top=top,
            include_details=include_details,
            include_remediation=include_remediation,
            include_timeline=include_timeline,
            include_visibility=brief and not json_out and not save,
        )
        if save:
            from shellforgeai.core.ops_report_artifact import save_ops_report

            saved = save_ops_report(
                payload,
                Path(load_settings().app.data_dir),
                source_command="shellforgeai ops report --save",
            )
            if json_out:
                typer.echo(json.dumps(saved))
                return
            console.print("Ops report saved")
            console.print(f"- id: {saved.get('report_id')}")
            console.print(f"- path: {saved.get('report_path')}")
            return
        if json_out:
            typer.echo(json.dumps(payload))
            return
        if brief:
            typer.echo(_render_ops_report_brief(payload), nl=False)
            return
        top_suspect = payload["suspects"][0] if payload["suspects"] else None
        lines = ["ShellForgeAI 2AM Operator Report", ""]
        lines.append(
            "Status: "
            f"{payload.get('status')} — "
            f"{payload['summary'].get('critical', 0)} critical and "
            f"{payload['summary'].get('high', 0)} high Docker suspects found."
        )
        lines.append(
            "Summary: "
            f"{payload['summary'].get('critical', 0)} critical, "
            f"{payload['summary'].get('high', 0)} high suspects"
        )
        if top_suspect:
            lines.append(f"Top suspect: {top_suspect['name']} — {top_suspect['severity']} severity")
            lines.append(f"First safe command: {triage_detail_command(top_suspect['name'])}")
        lines.extend(["", "Safety:"])
        for k, v in payload["safety"].items():
            lines.append(f"- {k}: {str(v).lower()}")
        lines.extend(["", "Current scene:"])
        for k, v in payload["summary"].items():
            lines.append(f"- {k}: {v}")
        lines.extend(["", "Top suspects:"])
        if not payload["suspects"]:
            lines.append("- none")
        for s in payload["suspects"]:
            lines.append(
                f"{s['rank']}. {s['name']} — {s['severity']} / {s['confidence']} confidence"
            )
            if s["evidence_summary"]:
                lines.append(f"   Why: {', '.join(s['evidence_summary'][:3])}")
            lines.append(f"   Safe inspect: {triage_detail_command(s['name'])}")
            lines.append(f"   Remediation gate: {s['remediation']['eligibility']}")
            lines.append(f"   Explain: {remediation_eligibility_explain_command(s['name'])}")
        lines.extend(["", "Remediation lane:"])
        lines.append(f"- self-test quick: {payload['remediation_lane']['self_test_quick']}")
        lines.append(f"- self-test standard: {payload['remediation_lane']['self_test_standard']}")
        lines.append(f"- self-test full: {payload['remediation_lane']['self_test_full']}")
        lines.append(f"- latest lifecycle audit: {payload['remediation_lane']['latest_audit']}")
        lines.extend(["", "Recommended next steps:"])
        for idx, cmd in enumerate(payload["safe_next_commands"][:5], start=1):
            lines.append(f"{idx}. {cmd}")
        typer.echo("\n".join(lines).rstrip() + "\n")

    @ops_report_app.command("validate")
    def ops_report_validate(
        report_ref: Annotated[str, typer.Argument(help="Report id or report directory path")],
        json_out: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        from shellforgeai.core.ops_report_artifact import validate_ops_report

        payload = validate_ops_report(report_ref, Path(load_settings().app.data_dir))
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        console.print(
            "Ops report validation passed"
            if payload.get("status") == "ok"
            else "Ops report validation failed"
        )
        for k, v in (payload.get("checks") or {}).items():
            console.print(f"- {k}: {'ok' if v else 'failed'}")
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @ops_report_app.command("export")
    def ops_report_export(
        report_ref: Annotated[str, typer.Argument(help="Report id or path")],
        json_out: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        from shellforgeai.core.ops_report_artifact import export_ops_report

        payload = export_ops_report(report_ref, Path(load_settings().app.data_dir))
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "exported" else 1)
        if payload.get("status") != "exported":
            console.print("Ops report export failed")
            for w in payload.get("warnings") or []:
                console.print(f"- {w}")
            raise typer.Exit(1)
        ex = payload.get("export") or {}
        src = payload.get("source_report") or {}
        console.print(
            "Ops report export created"
            if not payload.get("existing")
            else "Ops report export already exists (reused)"
        )
        console.print(f"- report_id: {src.get('id')}")
        console.print(f"- export_id: {ex.get('id')}")
        console.print(f"- path: {ex.get('path')}")

    @ops_report_app.command("export-validate")
    def ops_report_export_validate(
        export_ref: Annotated[str, typer.Argument(help="Export id or path")],
        json_out: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        from shellforgeai.core.ops_report_artifact import validate_ops_report_export

        payload = validate_ops_report_export(export_ref, Path(load_settings().app.data_dir))
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        console.print(
            "Ops report export validation passed"
            if payload.get("status") == "ok"
            else "Ops report export validation failed"
        )
        for k, v in (payload.get("checks") or {}).items():
            console.print(f"- {k}: {'ok' if v else 'failed'}")
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    def _render_ops_report_compare_human(
        payload: dict[str, Any], *, top: int = 5, include_stable: bool = False
    ) -> str:
        summary = payload.get("summary") or {}
        reports = payload.get("reports") or {}
        lines = ["Ops report compare", "", "Reports:"]
        lines.append(f"- before: {(reports.get('before') or {}).get('id', 'unknown')}")
        lines.append(f"- after:  {(reports.get('after') or {}).get('id', 'unknown')}")
        lines.extend(["", "Scene drift:"])
        for key in (
            "suspects_before",
            "suspects_after",
            "new",
            "resolved_or_missing",
            "escalated",
            "improved",
            "stable",
        ):
            lines.append(f"- {key.replace('_', ' ')}: {summary.get(key, 0)}")
        lines.extend(["", "Top changes:"])
        changes = (
            (payload.get("severity_escalations") or [])
            + (payload.get("severity_improvements") or [])
            + (payload.get("rank_changes") or [])
        )
        if not changes:
            lines.append("- none")
        for idx, ch in enumerate(changes[: max(1, top)], start=1):
            lines.append(f"{idx}. {ch.get('name')}")
            lines.append(f"   severity: {ch.get('before_severity')} -> {ch.get('after_severity')}")
            lines.append(f"   rank: {ch.get('before_rank')} -> {ch.get('after_rank')}")
        lines.extend(["", "Remediation lane:"])
        lane = payload.get("remediation_lane") or {}
        lines.append(f"- before: {lane.get('before')}")
        lines.append(f"- after: {lane.get('after')}")
        lines.append("- no execution recorded")
        lines.extend(["", "Safety:", "- read_only=true", "- mutation_performed=false"])
        if include_stable and payload.get("stable_suspects"):
            lines.extend(["", "Stable suspects:"])
            for name in payload.get("stable_suspects") or []:
                lines.append(f"- {name}")
        lines.extend(["", "Safe next commands:"])
        for cmd in (payload.get("safe_next_commands") or [])[:5]:
            lines.append(f"- {cmd}")
        return "\n".join(lines).rstrip() + "\n"

    def _render_ops_report_history_human(payload: dict[str, Any]) -> str:
        lines = ["Ops report history", ""]
        summary = payload.get("summary") or {}
        lines.append(f"Reports found: {summary.get('reports_found', 0)}")
        lines.append("")
        reports = payload.get("reports") or []
        if not reports:
            lines.append("No saved ops reports found.")
        for idx, report in enumerate(reports, start=1):
            lines.append(f"{idx}. {report.get('report_id')}")
            lines.append(f"   created: {report.get('created_at') or '-'}")
            lines.append(f"   suspects: {report.get('suspects_ranked')}")
            lines.append(f"   critical: {report.get('critical')}")
            lines.append(f"   high: {report.get('high')}")
            lines.append(f"   top suspect: {report.get('top_suspect') or '-'}")
            lines.append(f"   path: {report.get('path')}")
        lines.extend(["", "Latest compare availability:"])
        lines.append(
            "- available"
            if summary.get("valid_reports", 0) >= 2
            else "- unavailable (need >=2 valid reports)"
        )
        if payload.get("warnings"):
            lines.extend(["", "Warnings:"])
            for warning in payload.get("warnings") or []:
                lines.append(f"- {warning}")
        lines.extend(["", "Safe next commands:"])
        for cmd in (payload.get("safe_next_commands") or [])[:5]:
            lines.append(f"- {cmd}")
        lines.extend(["", "Safety:", "- read_only=true", "- mutation_performed=false"])
        return "\n".join(lines).rstrip() + "\n"

    @ops_report_app.command("compare")
    def ops_report_compare(
        before_ref: Annotated[str, typer.Argument(help="Before report id or path")],
        after_ref: Annotated[str, typer.Argument(help="After report id or path")],
        json_out: Annotated[bool, typer.Option("--json")] = False,
        only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
        include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
        top: Annotated[int, typer.Option("--top", min=1)] = 5,
    ) -> None:
        from shellforgeai.core.ops_report_artifact import compare_ops_reports

        payload = compare_ops_reports(
            before_ref,
            after_ref,
            Path(load_settings().app.data_dir),
            only_changed=only_changed,
            include_stable=include_stable,
        )
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        if payload.get("status") != "ok":
            console.print("Ops report compare failed")
            for warning in payload.get("warnings") or []:
                console.print(f"- {warning}")
            raise typer.Exit(1)
        console.print(
            _render_ops_report_compare_human(payload, top=top, include_stable=include_stable),
            end="",
        )

    @ops_report_app.command("history")
    def ops_report_history(
        json_out: Annotated[bool, typer.Option("--json")] = False,
        limit: Annotated[int, typer.Option("--limit", min=1)] = 10,
        include_drift: Annotated[bool, typer.Option("--include-drift")] = False,
    ) -> None:
        from shellforgeai.core.ops_report_artifact import (
            ops_report_history as build_ops_report_history,
        )

        payload = build_ops_report_history(
            Path(load_settings().app.data_dir), limit=limit, include_drift=include_drift
        )
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        console.print(_render_ops_report_history_human(payload), end="")
        if payload.get("status") != "ok":
            raise typer.Exit(1)

    @ops_report_app.command("compare-latest")
    def ops_report_compare_latest(
        json_out: Annotated[bool, typer.Option("--json")] = False,
        only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
        include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
        top: Annotated[int, typer.Option("--top", min=1)] = 5,
    ) -> None:
        from shellforgeai.core.ops_report_artifact import compare_latest_ops_reports

        payload = compare_latest_ops_reports(
            Path(load_settings().app.data_dir),
            only_changed=only_changed,
            include_stable=include_stable,
        )
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        if payload.get("status") != "ok":
            console.print("Ops report compare-latest unavailable")
            for warning in payload.get("warnings") or []:
                console.print(f"- {warning}")
            raise typer.Exit(1)
        console.print(
            _render_ops_report_compare_human(payload, top=top, include_stable=include_stable),
            end="",
        )

    @ops_report_app.command("compare-export")
    def ops_report_compare_export(
        before_ref: Annotated[str, typer.Argument(help="Before export id or path")],
        after_ref: Annotated[str, typer.Argument(help="After export id or path")],
        json_out: Annotated[bool, typer.Option("--json")] = False,
        only_changed: Annotated[bool, typer.Option("--only-changed")] = False,
        include_stable: Annotated[bool, typer.Option("--include-stable")] = False,
        top: Annotated[int, typer.Option("--top", min=1)] = 5,
    ) -> None:
        from shellforgeai.core.ops_report_artifact import compare_ops_report_exports

        payload = compare_ops_report_exports(
            before_ref,
            after_ref,
            Path(load_settings().app.data_dir),
            only_changed=only_changed,
            include_stable=include_stable,
        )
        if json_out:
            typer.echo(json.dumps(payload))
            raise typer.Exit(0 if payload.get("status") == "ok" else 1)
        if payload.get("status") != "ok":
            console.print("Ops report export compare failed")
            for warning in payload.get("warnings") or []:
                console.print(f"- {warning}")
            raise typer.Exit(1)
        console.print(
            _render_ops_report_compare_human(payload, top=top, include_stable=include_stable),
            end="",
        )

    _wrap_extracted_callbacks(ops_app, ops_report_app)
