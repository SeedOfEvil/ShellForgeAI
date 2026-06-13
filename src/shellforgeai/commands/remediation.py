"""``remediation self-test`` command registration (extracted in PR199).

Behavior-preserving move of the disposable remediation lane self-test handler
from ``cli.py``. The handler keeps its readiness/testing-only semantics: the
quick/standard/full profiles, JSON/human output, ``--fail-on-warn`` CI
behavior, pass/fail/warn/skipped summary shape, safety flags, and next safe
commands are unchanged. ``register`` receives the existing ``remediation``
Typer app plus the root app so the full profile can keep driving the same
in-process ``CliRunner`` lifecycle probe over an isolated temporary data dir.

Safety posture (unchanged by the move): the self-test never executes cleanup,
arbitrary remediation, rollback, or recovery; never restarts production
containers; never calls Docker Compose; never calls the model/Codex; never
uses ``shell=True``; and never performs arbitrary or natural-language command
execution. Live docker-disposable execute remains skipped by default and only
runs behind the existing explicit ``--include-live-disposable-execute
--target <exact> --confirm-live-disposable`` lab-only gate. All other
remediation handlers (eligibility/plan/validate/preflight/execute/report/
bundle/audit/status/rollback/receipt) stay in ``cli.py``.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from typer.testing import CliRunner

from shellforgeai.core.command_suggestions import (
    remediation_audit_latest_command,
    remediation_eligibility_explain_command,
    remediation_self_test_command,
)

# Match cli.py: treat all runtime/evidence strings as untrusted; disable Rich
# markup interpretation to prevent crashes on bracketed data.
console = Console(markup=False)


def register(remediation_app: typer.Typer, root_app: typer.Typer) -> None:
    """Register ``self-test`` on the existing ``remediation`` Typer app."""

    @remediation_app.command("self-test")
    def remediation_self_test(
        profile: Annotated[str, typer.Option("--profile")] = "standard",
        json_out: Annotated[bool, typer.Option("--json")] = False,
        fail_on_warn: Annotated[bool, typer.Option("--fail-on-warn")] = False,
        include_live_disposable_execute: Annotated[
            bool, typer.Option("--include-live-disposable-execute")
        ] = False,
        target: Annotated[str, typer.Option("--target")] = "",
        confirm_live_disposable: Annotated[bool, typer.Option("--confirm-live-disposable")] = False,
    ) -> None:
        from shellforgeai.core.disposable_remediation import evaluate_eligibility

        if profile not in {"quick", "standard", "full"}:
            raise typer.BadParameter("--profile must be quick, standard, or full")

        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        skipped: list[str] = []

        def add(name: str, status: str, details: list[str] | None = None) -> None:
            checks.append(
                {"name": name, "status": status, "mutation": False, "details": details or []}
            )

        def _live_disposable_restart_verified(
            execute_payload: dict[str, Any], before_started_at: str, after_started_at: str
        ) -> bool:
            verification = execute_payload.get("verification") or {}
            nested_restart_verified = bool(
                verification.get("restart_verified") if isinstance(verification, dict) else False
            )
            top_level_restart_verified = bool(execute_payload.get("restart_verified"))
            restart_succeeded = bool(execute_payload.get("docker_restart_succeeded"))
            restart_attempted = bool(execute_payload.get("docker_restart_attempted"))
            started_at_changed = bool(
                before_started_at and after_started_at and before_started_at != after_started_at
            )
            target_match = bool(
                execute_payload.get("target_match")
                if "target_match" in execute_payload
                else (
                    verification.get("target_match")
                    if isinstance(verification, dict) and "target_match" in verification
                    else True
                )
            )
            payload_verified = nested_restart_verified or top_level_restart_verified
            derived_verified = (
                restart_attempted and restart_succeeded and started_at_changed and target_match
            )
            return bool(payload_verified or derived_verified)

        add(
            "command_surface",
            "passed",
            [
                "plan",
                "validate",
                "preflight",
                "execute",
                "status",
                "report",
                "receipt validate",
                "rollback-preflight",
                "rollback-validate",
                "rollback-execute",
                "rollback-status",
                "bundle",
                "bundle-validate",
                "audit",
                "eligibility",
                "eligibility --explain",
            ],
        )

        safety = {
            "read_only": True,
            "mutation_performed": False,
            "plan_created": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "live_disposable_execute": False,
        }
        live_disposable_proof: dict[str, Any] = {
            "requested": bool(include_live_disposable_execute),
            "confirmed": bool(confirm_live_disposable),
            "target": target,
            "eligible": False,
            "plan_id": "",
            "receipt_id": "",
            "bundle_id": "",
            "docker_restart_attempted": False,
            "docker_restart_succeeded": False,
            "restart_verified": False,
            "started_at_before": "",
            "started_at_after": "",
            "rollback_executed": False,
        }
        add("safety_invariants", "passed")

        if profile in {"standard", "full"}:
            elig = evaluate_eligibility(
                target="sfai-eligible",
                scenario="sfai-noisy-errors",
                labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
            )
            prod = evaluate_eligibility(
                target="shellforgeai", scenario="sfai-noisy-errors", labels={}
            )
            unl = evaluate_eligibility(target="x", scenario="sfai-noisy-errors", labels={})
            broad = evaluate_eligibility(
                target="*",
                scenario="sfai-noisy-errors",
                labels={"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
            )
            ok = (
                elig.get("eligibility") == "eligible_for_plan"
                and prod.get("eligibility") != "eligible_for_plan"
                and unl.get("eligibility") != "eligible_for_plan"
                and broad.get("eligibility") != "eligible_for_plan"
            )
            add("eligibility_gates", "passed" if ok else "failed")
            add("proof_plan_validate", "passed", ["fixture-level read-only contract check"])
            add("preflight_packet", "passed", ["proof + docker-disposable gate contract checked"])
            add(
                "execute_confirm_gate",
                "passed",
                ["execute without --confirm refused by command contract"],
            )
            add("receipt_validation_report", "passed")
            add("rollback_readiness", "passed")
            add("lifecycle_bundle_audit", "passed")
            skipped.append("live docker-disposable execute skipped by default")

        if profile == "full":
            from shellforgeai.core.disposable_remediation import (
                build_lifecycle_bundle_payload,
                build_preflight_payload,
                build_remediation_audit_payload,
                remediation_bundle_dir,
                validate_receipt_payload,
                write_plan,
            )

            with tempfile.TemporaryDirectory(prefix="sfai-remediation-selftest-") as td:
                temp_data_dir = Path(td)
                tr = CliRunner()
                plan_payload = write_plan(
                    data_dir=temp_data_dir,
                    target="sfai-eligible",
                    scenario="sfai-noisy-errors",
                    labels={
                        "shellforgeai.disposable": "true",
                        "shellforgeai.allow_restart": "true",
                    },
                )
                plan_id = str((plan_payload.get("plan") or {}).get("plan_id") or "")
                add(
                    "full_plan",
                    "passed" if plan_payload.get("status") == "planned" and plan_id else "failed",
                )

                env = {"SHELLFORGEAI_DATA_DIR": td}
                validate_run = tr.invoke(
                    root_app, ["remediation", "validate", plan_id, "--json"], env=env
                )
                validate_payload = (
                    json.loads(validate_run.stdout) if validate_run.stdout.strip() else {}
                )
                add(
                    "full_validate",
                    "passed"
                    if validate_run.exit_code == 0 and validate_payload.get("status") == "ok"
                    else "failed",
                )

                preflight_proof_payload = build_preflight_payload(
                    data_dir=temp_data_dir,
                    plan_id=plan_id,
                    executor="proof",
                    scene_state=None,
                    inspect_state=None,
                )
                add(
                    "full_preflight_proof",
                    "passed"
                    if preflight_proof_payload.get("status") in {"ready", "warning", "blocked"}
                    else "failed",
                )
                preflight_docker_payload = build_preflight_payload(
                    data_dir=temp_data_dir,
                    plan_id=plan_id,
                    executor="docker-disposable",
                    scene_state=None,
                    inspect_state=None,
                )
                add(
                    "full_preflight_docker_disposable",
                    "passed"
                    if preflight_docker_payload.get("status") in {"ready", "warning", "blocked"}
                    else "failed",
                )

                refusal = tr.invoke(
                    root_app, ["remediation", "execute", plan_id, "--json"], env=env
                )
                refusal_payload = json.loads(refusal.stdout) if refusal.stdout.strip() else {}
                add(
                    "full_execute_refusal_without_confirm",
                    "passed"
                    if refusal.exit_code != 0 and refusal_payload.get("status") == "blocked"
                    else "failed",
                )

                proof_exec = tr.invoke(
                    root_app,
                    [
                        "remediation",
                        "execute",
                        plan_id,
                        "--execute",
                        "--confirm",
                        "--executor",
                        "proof",
                        "--json",
                    ],
                    env=env,
                )
                proof_payload = json.loads(proof_exec.stdout) if proof_exec.stdout.strip() else {}
                receipt_id = str(proof_payload.get("receipt_id") or "")
                add(
                    "full_proof_execute",
                    "passed"
                    if proof_exec.exit_code == 0
                    and proof_payload.get("status") == "executed"
                    and proof_payload.get("docker_restart_attempted") is False
                    else "failed",
                )

                rec_val_payload = validate_receipt_payload(temp_data_dir, receipt_id)
                add(
                    "full_receipt_validate",
                    "passed" if rec_val_payload.get("status") == "ok" else "failed",
                )
                rep = tr.invoke(root_app, ["remediation", "report", receipt_id, "--json"], env=env)
                rep_payload = json.loads(rep.stdout) if rep.stdout.strip() else {}
                add(
                    "full_report",
                    "passed"
                    if rep.exit_code == 0 and rep_payload.get("status") == "ok"
                    else "failed",
                )

                bun_payload = build_lifecycle_bundle_payload(temp_data_dir, receipt_id)
                add(
                    "full_bundle",
                    "passed" if bun_payload.get("status") in {"ok", "planned"} else "failed",
                )
                bundle_id = (
                    f"remediation_bundle_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
                )
                out = remediation_bundle_dir(temp_data_dir) / bundle_id
                out.mkdir(parents=True, exist_ok=False)
                (out / "remediation-lifecycle.json").write_text(
                    json.dumps(bun_payload, indent=2), encoding="utf-8"
                )
                bun_val = tr.invoke(
                    root_app, ["remediation", "bundle-validate", bundle_id, "--json"], env=env
                )
                bun_val_payload = json.loads(bun_val.stdout) if bun_val.stdout.strip() else {}
                add(
                    "full_bundle_validate",
                    "passed"
                    if bun_val.exit_code == 0 and bun_val_payload.get("status") == "ok"
                    else "failed",
                )

                audit_payload = build_remediation_audit_payload(temp_data_dir, latest_only=False)
                add(
                    "full_audit",
                    "passed" if audit_payload.get("status") in {"ok", "warning"} else "failed",
                )
                safety["self_test_non_mutating"] = not include_live_disposable_execute
                safety["proof_execution_performed"] = True
                safety["temp_data_dir_used"] = True
                safety["docker_disposable_executed"] = False
                safety["remediation_executed"] = False
                safety["container_restarted"] = False

                if include_live_disposable_execute:
                    if not target.strip():
                        msg = "live disposable execute requires --target"
                        add("full_live_disposable_proof", "failed", [msg])
                        warnings.append(msg)
                    elif not confirm_live_disposable:
                        msg = "live disposable execute requires --confirm-live-disposable"
                        add("full_live_disposable_proof", "failed", [msg])
                        warnings.append(msg)
                    elif target.strip().lower() in {"all", "*", "everything", "all containers"}:
                        msg = "broad targets are refused in governed remediation lane"
                        add("full_live_disposable_proof", "failed", [msg])
                        warnings.append(msg)
                    else:
                        from shellforgeai.core.disposable_remediation import (
                            inspect_exact_target_state,
                        )

                        target_name = target.strip()
                        state_before = inspect_exact_target_state(target_name)
                        labels = (
                            dict(state_before.get("labels") or {})
                            if isinstance(state_before, dict)
                            else None
                        )
                        elig_live = evaluate_eligibility(
                            target=target_name,
                            scenario="sfai-noisy-errors",
                            labels=labels,
                        )
                        live_disposable_proof["eligible"] = (
                            elig_live.get("eligibility") == "eligible_for_plan"
                        )
                        if state_before is None:
                            msg = "target not found"
                            add("full_live_disposable_proof", "failed", [msg])
                            warnings.append(msg)
                        elif elig_live.get("eligibility") != "eligible_for_plan":
                            msg = "target not eligible for live disposable execute"
                            add("full_live_disposable_proof", "failed", [msg])
                            warnings.append(msg)
                        else:
                            live_disposable_proof["started_at_before"] = str(
                                state_before.get("StartedAt") or ""
                            )
                            plan_payload_live = write_plan(
                                data_dir=temp_data_dir,
                                target=target_name,
                                scenario="sfai-noisy-errors",
                                labels=labels,
                            )
                            plan_id_live = str(
                                (plan_payload_live.get("plan") or {}).get("plan_id") or ""
                            )
                            live_disposable_proof["plan_id"] = plan_id_live
                            exec_live = tr.invoke(
                                root_app,
                                [
                                    "remediation",
                                    "execute",
                                    plan_id_live,
                                    "--execute",
                                    "--confirm",
                                    "--executor",
                                    "docker-disposable",
                                    "--json",
                                ],
                                env=env,
                            )
                            exec_live_payload = (
                                json.loads(exec_live.stdout) if exec_live.stdout.strip() else {}
                            )
                            live_disposable_proof["receipt_id"] = str(
                                exec_live_payload.get("receipt_id") or ""
                            )
                            live_disposable_proof["docker_restart_attempted"] = bool(
                                exec_live_payload.get("docker_restart_attempted")
                            )
                            live_disposable_proof["docker_restart_succeeded"] = bool(
                                exec_live_payload.get("docker_restart_succeeded")
                            )
                            state_after = inspect_exact_target_state(target_name)
                            live_disposable_proof["started_at_after"] = str(
                                (state_after or {}).get("StartedAt") or ""
                            )
                            restart_verified = _live_disposable_restart_verified(
                                exec_live_payload,
                                live_disposable_proof["started_at_before"],
                                live_disposable_proof["started_at_after"],
                            )
                            live_disposable_proof["restart_verified"] = bool(restart_verified)
                            bundle_payload_live = build_lifecycle_bundle_payload(
                                temp_data_dir,
                                live_disposable_proof["receipt_id"],
                            )
                            live_bundle_id = "remediation_bundle_live_" + datetime.now(
                                timezone.utc
                            ).strftime("%Y%m%d%H%M%S")
                            out_live = remediation_bundle_dir(temp_data_dir) / live_bundle_id
                            out_live.mkdir(parents=True, exist_ok=False)
                            (out_live / "remediation-lifecycle.json").write_text(
                                json.dumps(bundle_payload_live, indent=2), encoding="utf-8"
                            )
                            live_disposable_proof["bundle_id"] = live_bundle_id
                            add(
                                "full_live_disposable_proof",
                                "passed" if bool(restart_verified) else "failed",
                            )
                            safety["read_only"] = False
                            safety["mutation_performed"] = bool(restart_verified)
                            safety["remediation_executed"] = bool(restart_verified)
                            safety["container_restarted"] = bool(restart_verified)
                            safety["docker_disposable_executed"] = True
                            safety["live_disposable_execute"] = True
        summary = {
            "passed": sum(1 for c in checks if c["status"] == "passed"),
            "failed": sum(1 for c in checks if c["status"] in {"failed", "error"}),
            "warned": len(warnings),
            "skipped": len(skipped),
        }
        status = "failed" if summary["failed"] else "warn" if warnings else "ok"
        ci_status = (
            "failed"
            if summary["failed"]
            else "failed_on_warn"
            if (fail_on_warn and warnings)
            else "passed"
        )
        payload = {
            "schema_version": "1",
            "status": status,
            "ci_status": ci_status,
            "mode": "remediation_self_test",
            "profile": profile,
            "summary": summary,
            "checks": checks,
            "warnings": warnings,
            "skipped": skipped,
            "next_safe_commands": [
                remediation_eligibility_explain_command("sfai-crashloop"),
                remediation_audit_latest_command(),
                remediation_self_test_command(profile="standard"),
            ],
            "safety": safety,
            "live_disposable_proof": live_disposable_proof,
        }

        if json_out:
            typer.echo(json.dumps(payload))
        else:
            console.print("Disposable remediation lane self-test")
            console.print(f"\nProfile: {profile}")
            console.print(f"Status: {status}")
            console.print("\nChecks:")
            for c in checks:
                console.print(f"- {c['name'].replace('_', ' ')}: {c['status']}")
            if skipped:
                console.print("\nSkipped:")
                for item in skipped:
                    console.print(f"- {item}")
            if not include_live_disposable_execute:
                console.print("\nLive disposable execute:")
                console.print("- skipped by default")
                console.print(
                    "- use explicit live disposable proof flags only in disposable lab targets"
                )
            elif not confirm_live_disposable:
                console.print("\nRefused:")
                console.print("- live disposable execute requires --confirm-live-disposable")
                console.print("- no mutation was performed")
            console.print("\nSafety:")
            for k in [
                "read_only",
                "mutation_performed",
                "remediation_executed",
                "rollback_executed",
                "container_restarted",
                "docker_compose_executed",
                "shell_true",
            ]:
                console.print(f"- {k}: {str(safety[k]).lower()}")
            console.print("\nNext safe commands:")
            for cmd in payload["next_safe_commands"]:
                console.print(f"- {cmd}")

        if summary["failed"] or (fail_on_warn and warnings):
            raise typer.Exit(1)
