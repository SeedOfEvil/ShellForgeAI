"""``ask`` command registration (extracted from ``cli.py`` in PR190).

Behavior-preserving move of the top-level deterministic ``ask`` command. The
deterministic read-only routing chain, mutation-refusal handlers, status/ops
report renderers, and the evidence-backed model path all continue to delegate
to the existing ``shellforgeai.cli`` helpers (resolved lazily at call time),
so routing order, refusal wording, no-action-taken output, JSON behavior,
artifacts, exit codes, and safety boundaries remain unchanged. This module
registers Typer wiring only; it introduces no cleanup, remediation, rollback,
recovery, Docker/Compose mutation, restart, shell, arbitrary or
natural-language execution, and no new model fallback behavior.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Any

import typer

_MODEL_PHASE_MESSAGES = {
    "preparing_context": "Preparing model context...",
    "building_prompt": "Building model prompt...",
    "starting_provider": "Starting model provider...",
    "sending_prompt": "Sending read-only evidence...",
    "waiting_for_response": "Waiting for model response...",
    "response_file_detected": "Model response file detected...",
    "capturing_response": "Capturing model response...",
    "cleaning_up_children": "Cleaning up model child processes...",
}


def _model_progress_callback() -> Any:
    seen: set[str] = set()

    def _progress(phase: str) -> None:
        message = _MODEL_PHASE_MESSAGES.get(phase)
        if message and phase not in seen:
            seen.add(phase)
            print(message, file=sys.stderr)

    return _progress


def _cli() -> Any:
    return sys.modules["shellforgeai.cli"]


def register(app: typer.Typer) -> None:
    """Register the top-level ``ask`` command on ``app``."""

    @app.command()
    def ask(
        ctx: typer.Context,
        question: str,
        context: str = typer.Option("standard", "--context"),
        full_context: bool = typer.Option(False, "--full-context"),
        raw: bool = typer.Option(False, "--raw"),
        no_evidence: bool = typer.Option(
            False, "--no-evidence", help="Disable evidence-aware routing for this ask."
        ),
        explain_evidence: bool = typer.Option(
            False,
            "--explain-evidence",
            help="Show deterministic evidence used/missing for Docker/operator answers.",
        ),
        since: str = typer.Option("30m", "--since"),
    ) -> None:

        from shellforgeai.core.ask_docker_grounding import (
            build_docker_evidence_context,
            is_docker_operator_ask,
            render_docker_evidence_explainability,
        )
        from shellforgeai.core.ask_routing import (
            EVIDENCE_BACKED,
            PLAIN,
            AskRoute,
            evidence_brief,
            extract_container_target,
            is_brief_ops_report_ask,
            is_ops_report_ask,
            network_reachability_brief,
            route_ask_intent,
            target_container_status,
        )
        from shellforgeai.core.command_suggestions import filter_unsupported_command_suggestions
        from shellforgeai.core.diagnose import findings_summary_line
        from shellforgeai.core.runbook import build_runbook, render_runbook_md
        from shellforgeai.core.windows_operator_ux import (
            WINDOWS_OPERATOR_INTENT_HANDOFF,
            WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL,
            WINDOWS_OPERATOR_INTENT_NEXT_CHECK,
            WINDOWS_OPERATOR_INTENT_PERFORMANCE,
            WINDOWS_OPERATOR_INTENT_STATUS,
            WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL,
            classify_windows_operator_intent,
            render_windows_operator_guidance,
        )
        from shellforgeai.llm.prompts import build_contextual_prompt
        from shellforgeai.llm.schemas import ModelRequest

        cli = _cli()
        windows_route = None
        if not no_evidence:
            windows_route = classify_windows_operator_intent(
                question, host_system=platform.system()
            )
            if windows_route is not None and (
                windows_route.intent
                in {
                    WINDOWS_OPERATOR_INTENT_STATUS,
                    WINDOWS_OPERATOR_INTENT_NEXT_CHECK,
                    WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL,
                }
                or not windows_route.host_is_windows
            ):
                limitation_lines = ()
                if windows_route.intent == WINDOWS_OPERATOR_INTENT_NEXT_CHECK:
                    limitation_lines = (
                        "Windows metric limitations:",
                        "- Load average is not available on Windows.",
                        "- Memory summary unavailable from this collector on Windows.",
                        "- Linux-only collectors skipped on Windows.",
                    )
                cli.console.print(
                    render_windows_operator_guidance(
                        windows_route, limitation_lines=limitation_lines
                    )
                )
                return
        runtime = cli._ctx(ctx)
        if windows_route is not None and windows_route.intent in {
            WINDOWS_OPERATOR_INTENT_PERFORMANCE,
            WINDOWS_OPERATOR_INTENT_STRONGEST_SIGNAL,
            WINDOWS_OPERATOR_INTENT_HANDOFF,
        }:
            from shellforgeai.interactive.repl import _render_windows_parity_prompt

            rendered, _latest_context = _render_windows_parity_prompt(runtime, question)
            cli.console.print(rendered)
            return
        if not no_evidence:
            if cli._handle_receipt_recovery_ask(question):
                return
            if cli._handle_receipt_rollback_preview_ask(question):
                return
            if cli._handle_receipt_audit_ask(question):
                return
            if cli._handle_recipe_registry_ask(question):
                return
            if cli._handle_v2_handoff_ask(question):
                return
            if cli._handle_v2_verify_ask(question):
                return
            if cli._is_status_ask(question):
                payload = cli._build_status_payload()
                cli.console.print("Read-only status (deterministic ask routing):")
                cli.console.print("")
                typer.echo(cli._render_status_human(payload), nl=False)
                return
            if cli._handle_v2_apply_preview_ask(question):
                return
            if cli._handle_v2_apply_preview_mutation_refusal(question):
                return
            if cli._handle_v2_propose_ask(question):
                return
            if cli._handle_v2_propose_mutation_refusal(question):
                return
            if cli._handle_retention_ask(runtime, question):
                return
            if cli._handle_incident_search_ask(runtime, question):
                return
            if cli._handle_guard_ask(runtime, question):
                return
            if cli._handle_command_help_ask(question):
                return
            if cli._handle_pressure_mutation_refusal(question):
                if explain_evidence:
                    cli.console.print("")
                    cli.console.print(render_docker_evidence_explainability(None), end="")
                return
            if cli._handle_v2_triage_ask(question):
                return
            if is_ops_report_ask(question):
                brief_ask = is_brief_ops_report_ask(question)
                payload = cli._build_ops_report_payload(include_visibility=brief_ask)
                if brief_ask:
                    cli.console.print("Read-only brief ops report (deterministic ask routing):")
                    cli.console.print("")
                    typer.echo(cli._render_ops_report_brief(payload), nl=False)
                else:
                    cli.console.print("Read-only ops report (deterministic ask routing):")
                    cli.console.print("")
                    typer.echo(cli._render_broad_triage_answer(payload))
                return
            if cli._handle_broad_triage_ask(runtime, question):
                return
            if cli._handle_mission_restart_ask(runtime, question):
                return
            if cli._handle_restart_plan_ask(runtime, question):
                return
            if cli._handle_compose_restart_preview_ask(runtime, question):
                return
            if cli._handle_compose_restart_proposal_ask(runtime, question):
                return
            if cli._handle_compose_context_ask(runtime, question):
                return
            if cli._handle_lab_restart_verification_ask(runtime, question):
                return
            if cli._handle_lab_restart_ask(runtime, question):
                return
            if cli._handle_immediate_fix_ask(runtime, question):
                return
            if cli._handle_export_ask(runtime, question):
                return
            if cli._handle_apply_approved_ask(runtime, question):
                return
            if cli._handle_actions_ask(runtime, question):
                return
            if cli._handle_create_restart_proposal_ask(runtime, question):
                return
            if cli._handle_create_proposals_ask(runtime, question):
                return
            if cli._handle_mutation_refusal_ask(question):
                if explain_evidence:
                    cli.console.print("")
                    cli.console.print(render_docker_evidence_explainability(None), end="")
                return
        provider = cli.build_provider(runtime.settings)
        ctx_mode = "full" if full_context else context

        route = AskRoute(mode=PLAIN) if no_evidence else route_ask_intent(question)
        # PR289 — Windows interactive evidence-context parity: on a Windows
        # host, model-backed asks carry the bounded read-only Windows evidence
        # packet so answers are grounded in actual host facts.
        windows_packet: dict[str, Any] | None = None
        if not no_evidence and platform.system().lower() == "windows":
            from shellforgeai.core.windows_evidence_context import (
                WINDOWS_EVIDENCE_MODEL_DIRECTIVE,
                build_windows_evidence_context,
                windows_evidence_prompt_facts,
            )

            windows_packet = build_windows_evidence_context()
            try:
                # PR289 — record the exact Windows evidence packet passed into
                # model context so QA acceptance can verify grounding from the
                # established artifact flow (read-only; no new write surface).
                import json as _json

                cli._ensure_artifact_dir(runtime)
                (runtime.session.artifact_dir / "windows-evidence-context.json").write_text(
                    _json.dumps(windows_packet, indent=2, sort_keys=True), encoding="utf-8"
                )
            except Exception:
                pass  # artifact recording must never break the ask path

        def _apply_windows_evidence_context(prompt_context: dict[str, Any]) -> None:
            if windows_packet is None:
                return
            prompt_context["identity"] = (
                "Windows host with local read-only evidence; answers must come "
                "from the Windows evidence packet."
            )
            prompt_context["windows_evidence"] = windows_packet
            prompt_context["windows_evidence_directive"] = WINDOWS_EVIDENCE_MODEL_DIRECTIVE
            prompt_context["evidence_label"] = "Windows local read-only evidence"
            windows_rows = windows_evidence_prompt_facts(windows_packet)
            existing_rows = prompt_context.get("evidence")
            if isinstance(existing_rows, list):
                prompt_context["evidence"] = windows_rows + existing_rows
            else:
                prompt_context["evidence"] = windows_rows

        # PR222 — ground Docker/operator questions in deterministic ShellForgeAI
        # triage evidence before formatting model assistance. Read-only: this
        # only reads the current Docker scene; it never mutates anything.
        docker_grounding: dict[str, Any] | None = None
        if not no_evidence and is_docker_operator_ask(question):
            docker_grounding = build_docker_evidence_context()
        evidence_result = None
        evidence_error: str | None = None
        if route.mode == EVIDENCE_BACKED:
            try:
                evidence_result = cli.diagnose_target(
                    runtime, route.target, online=False, since=since
                )
            except Exception as exc:  # collection failure: degrade, do not hallucinate
                evidence_error = f"{type(exc).__name__}: {exc}"

        if route.mode == EVIDENCE_BACKED and evidence_result is not None:
            cli._ensure_artifact_dir(runtime)
            if route.network_reachability:
                try:
                    from shellforgeai.core.collectors import collect_network_evidence

                    existing_sources = {i.source for i in evidence_result.evidence.items}
                    for ni in collect_network_evidence(runtime):
                        if ni.source not in existing_sources:
                            evidence_result.evidence.items.append(ni)
                except Exception:
                    pass
            ev_path = runtime.session.artifact_dir / "evidence.json"
            ev_path.write_text(evidence_result.evidence.model_dump_json(indent=2), encoding="utf-8")
            brief = evidence_brief(evidence_result.findings, evidence_result.evidence.items)
            # Extract target container for any evidence-backed ask. This lets
            # "is the healthy web service okay?" surface sfai-healthy-web's
            # Docker health, not just for reachability questions.
            target_container = extract_container_target(question)
            tc_status = target_container_status(evidence_result.evidence.items, target_container)
            oncall_overview = cli._is_oncall_overview_question(question)
            use_net_rank = route.network_reachability or oncall_overview
            net_brief = (
                network_reachability_brief(
                    evidence_result.findings,
                    evidence_result.evidence.items,
                    target_container=target_container,
                    max_containers=20,
                    max_findings=20,
                )
                if use_net_rank
                else None
            )
            synthesis_hints = (
                cli._network_reachability_hints(
                    evidence_result.findings, evidence_result.evidence.items
                )
                if use_net_rank
                else []
            )
            prompt_context = {
                "ask_intent": route.intent_label,
                "identity": "CLI-first Linux ops harness with read-only safety boundaries.",
                "host": platform.platform(),
                "mode": runtime.session.mode,
                "session_id": evidence_result.session_id,
                "mutation_request": route.mutation_request,
                "safety": (
                    "Inspect-only; no restart/stop/start/delete/install/firewall changes "
                    "performed. apply remains validation-only."
                ),
            }
            if cli._is_path_ownership_question(question):
                prompt_context["ownership_context"] = cli._ownership_context(
                    evidence_result.evidence.items
                )
                prompt_context["ownership_directive"] = (
                    "For path ownership questions, answer in this order: file existence/stat, "
                    "symlink target, mount target/source/options (if present), package owner "
                    "status, then container/host boundary caveat. Do not stop at package owner "
                    "alone."
                )
                own_rows = cli._ownership_evidence_rows(evidence_result.evidence.items)
                if own_rows:
                    existing_rows = prompt_context.get("evidence")
                    if isinstance(existing_rows, list):
                        prompt_context["evidence"] = own_rows + existing_rows
                    else:
                        prompt_context["evidence"] = own_rows
            if target_container:
                prompt_context["target_container"] = target_container
            if tc_status is not None:
                prompt_context["target_container_status"] = tc_status
                prompt_context["target_container_directive"] = (
                    "target_container_status reflects Docker container inventory + "
                    "problem summary. If state=running and (health=healthy or bucket=healthy), "
                    "say the container is running and healthy; do NOT fall back to a "
                    "local-process check (e.g. 'nginx not found in this container') for a "
                    "Docker lab/service target. If log_themes are present, name them and the "
                    "container in the answer."
                )
            if net_brief is not None:
                prompt_context["network_reachability_brief"] = net_brief
                # Use the reachability-ranked findings rows so the model sees
                # targeted/network-themed findings first.
                prompt_context["findings"] = net_brief["findings"]
                prompt_context["evidence"] = brief["evidence"]
            else:
                prompt_context["findings"] = brief["findings"]
                prompt_context["evidence"] = brief["evidence"]
            if synthesis_hints:
                prompt_context["synthesis_hints"] = synthesis_hints
                prompt_context["evidence_ranking"] = (
                    "Rank evidence in this order for reachability questions: "
                    "(1) target/app/container log themes (DNS, upstream unreachable, "
                    "connection refused, timeout, TLS) -- see "
                    "network_reachability_brief.container_log_evidence; "
                    "(2) service listener/exposure evidence; "
                    "(3) runtime network basics (DNS resolver, default route, listeners) "
                    "-- see network_reachability_brief.runtime_network_basics; "
                    "(4) visibility limitations. "
                    "Healthy runtime DNS/default route does NOT cancel app/container logs "
                    "showing reachability failure. If container_log_evidence contains an "
                    "entry, name that container and its themes explicitly in the answer. "
                    "Do not say 'no DNS-specific evidence' or 'reachability unconfirmed' "
                    "when container_log_evidence is non-empty. Do not label the host "
                    "network globally broken unless runtime evidence supports it."
                )
            if docker_grounding is not None:
                prompt_context["deterministic_docker_evidence"] = docker_grounding["prompt_block"]
            _apply_windows_evidence_context(prompt_context)
            # Reachability briefs, target-container blocks, and the Windows
            # evidence packet need more headroom than 2500 chars to stay
            # intact in the prompt.
            effective_mode = (
                "full"
                if (net_brief is not None or tc_status is not None or windows_packet is not None)
                and ctx_mode != "full"
                else ctx_mode
            )
            prompt = build_contextual_prompt(question, prompt_context, mode=effective_mode)
        else:
            prompt_context = {
                "host": platform.platform(),
                "mode": runtime.session.mode,
                "identity": "CLI-first Linux ops harness with read-only safety boundaries.",
            }
            if route.mode == EVIDENCE_BACKED and evidence_error is not None:
                prompt_context["evidence_unavailable"] = (
                    f"Recognized as ops diagnostic ({route.intent_label}) but read-only "
                    f"evidence collection failed: {evidence_error}. Do not invent findings."
                )
            if docker_grounding is not None:
                prompt_context["deterministic_docker_evidence"] = docker_grounding["prompt_block"]
            _apply_windows_evidence_context(prompt_context)
            prompt = build_contextual_prompt(
                question,
                prompt_context,
                mode="full" if windows_packet is not None and ctx_mode != "full" else ctx_mode,
            )
        resp = provider.complete(
            ModelRequest(
                prompt=prompt,
                model=runtime.settings.model.model,
                provider=runtime.settings.model.provider,
                timeout_seconds=runtime.settings.model.timeout_seconds,
                metadata={"raw": raw, "progress_callback": _model_progress_callback()},
            )
        )
        if not resp.ok:
            if windows_packet is not None:
                # PR289 — model/auth failed, but the bounded read-only Windows
                # evidence packet still answers safely.
                from shellforgeai.core.windows_evidence_context import (
                    render_windows_evidence_answer,
                )

                cli.console.print(render_windows_evidence_answer(question, windows_packet))
                cli.console.print(
                    "\nModel assistance is unavailable, so the read-only Windows "
                    "evidence above is the answer."
                )
                # PR291 — preserve the actual bounded Codex failure reason so
                # the lane can distinguish repository trust, timeout, binary
                # resolution, and auth readiness failures. No auth-cache read,
                # no environment dump; stderr excerpt is bounded + sanitized.
                failure_meta = getattr(resp, "metadata", None) or {}
                failure_class = str(failure_meta.get("codex_exec_error_class") or "unknown")
                cli.console.print(f"Model failure class: {failure_class}")
                try:
                    import json as _json

                    cli._ensure_artifact_dir(runtime)
                    diagnostics = {
                        key: failure_meta.get(key)
                        for key in (
                            "codex_command_built",
                            "codex_command_started",
                            "codex_exec_attempted",
                            "model_call_attempted",
                            "codex_exec_exit_code",
                            "codex_exec_timed_out",
                            "codex_process_completed",
                            "codex_child_cleanup_performed",
                            "codex_exec_error_class",
                            "codex_exec_error_message",
                            "codex_exec_stderr_excerpt",
                            "output_last_message_requested",
                            "output_last_message_path",
                            "output_file_created",
                            "model_response_captured",
                            "model_response_nonempty",
                            "model_response_excerpt",
                            "stdin_prompt_sent",
                            "stdin_closed",
                            "codex_binary",
                            "codex_resolved_binary",
                            "sandbox_mode",
                            "approval_policy",
                            "skip_git_repo_check_used",
                        )
                    }
                    diagnostics["model_assisted_answer_ran"] = False
                    diagnostics["fallback_used"] = True
                    (runtime.session.artifact_dir / "model-failure-diagnostics.json").write_text(
                        _json.dumps(diagnostics, indent=2, sort_keys=True), encoding="utf-8"
                    )
                except Exception:
                    pass  # diagnostics recording must never break the ask path
                cli.console.print("Check model auth with: shellforgeai model doctor --json")
                return
            if docker_grounding is not None:
                # PR222 — model/auth failed, but deterministic Docker triage
                # evidence still answers safely. Emit the grounded block plus a
                # clean auth-diagnostic pointer (a real read-only command), not
                # an unsupported command or an invented diagnosis.
                cli._emit_docker_grounding_answer(
                    runtime, question, docker_grounding, model_available=False
                )
                if explain_evidence:
                    cli.console.print("")
                    cli.console.print(
                        render_docker_evidence_explainability(docker_grounding), end=""
                    )
                cli.console.print(
                    "\nModel assistance is unavailable, so the deterministic ShellForgeAI "
                    "evidence above is the answer."
                )
                cli.console.print("Check model auth with: shellforgeai model doctor --json")
                return
            err_text = (resp.error or "").lower()
            if "not found on path" in err_text or "install" in err_text:
                cli.console.print(
                    "Model unavailable. Install Codex CLI and login with: codex login --device-auth"
                )
            elif "auth" in err_text or "login" in err_text:
                cli.console.print(
                    "Codex auth failed. Check readiness with: shellforgeai model doctor --json"
                )
            elif "timed out" in err_text:
                cli.console.print("Codex timed out before producing a response.")
            elif "argument" in err_text:
                stderr_snippet = (resp.raw or {}).get("stderr", "") if resp.raw else ""
                cli.console.print(
                    "Codex CLI argument error: "
                    + (resp.error or "unexpected CLI options")
                    + (f"\n{stderr_snippet}" if stderr_snippet else "")
                )
            elif "no final response" in err_text:
                cli.console.print("Codex returned no final response.")
            else:
                stderr_snippet = (resp.raw or {}).get("stderr", "") if resp.raw else ""
                cli.console.print(
                    f"Codex error: {resp.error or 'unknown failure'}"
                    + (f"\n{stderr_snippet}" if stderr_snippet else "")
                )
            raise typer.Exit(code=1)
        answer_text = resp.text
        removed_commands: list[str] = []
        if docker_grounding is not None:
            # PR222 — never let model output route operators to unsupported or
            # mutation-style commands; rewrite them to the deterministic safe
            # next command before printing.
            answer_text, removed_commands = filter_unsupported_command_suggestions(
                resp.text, safe_next_command=docker_grounding.get("safe_next_command")
            )
        windows_gated = False
        if windows_packet is not None:
            from shellforgeai.core.windows_evidence_context import (
                is_rejected_windows_model_answer,
                render_windows_evidence_answer,
            )

            if is_rejected_windows_model_answer(answer_text):
                # PR289 — project/policy preamble, metadata-primary, or
                # container-framed output never reaches stdout as the answer;
                # replace it with the evidence-grounded Windows answer.
                windows_gated = True
                answer_text = render_windows_evidence_answer(question, windows_packet)
        cli.console.print(answer_text)
        if not windows_gated:
            cli.console.print(
                f"\nProvider: {resp.provider}\nModel: {resp.model}\n{cli._usage_line(resp)}"
            )
        if docker_grounding is not None:
            cli.console.print("")
            cli._emit_docker_grounding_answer(
                runtime,
                question,
                docker_grounding,
                removed_commands=removed_commands,
                model_available=True,
            )
            if explain_evidence:
                cli.console.print("")
                cli.console.print(render_docker_evidence_explainability(docker_grounding), end="")
        if route.mode == EVIDENCE_BACKED and evidence_result is not None:
            artifact_dir = runtime.session.artifact_dir
            ev_path = artifact_dir / "evidence.json"
            ask_summary_path = artifact_dir / "ask-summary.md"
            ask_summary_path.write_text(
                f"# Ask: evidence-backed\n\n"
                f"Session: {evidence_result.session_id}\n"
                f"Intent: {route.intent_label}\n"
                f"Question: {question}\n\n"
                f"{findings_summary_line(list(evidence_result.findings))}\n\n"
                f"## Answer\n\n{resp.text}\n",
                encoding="utf-8",
            )
            runbook_md_path: Path | None = None
            if route.fix_plan:
                rb = build_runbook(
                    session_id=evidence_result.session_id,
                    target=route.target or "docker",
                    evidence_items=list(evidence_result.evidence.items),
                    findings=list(evidence_result.findings),
                    source_artifacts=[str(ev_path)],
                )
                runbook_md_path = artifact_dir / "runbook.md"
                import json

                (artifact_dir / "runbook.json").write_text(
                    json.dumps(rb.to_schema_dict(), indent=2), encoding="utf-8"
                )
                runbook_md_path.write_text(render_runbook_md(rb), encoding="utf-8")
            cli.console.print(
                "\nEvidence-backed ask:"
                f"\n- intent: {route.intent_label}"
                f"\n- session: {evidence_result.session_id}"
                f"\n- {findings_summary_line(list(evidence_result.findings))}"
                f"\n- evidence: {ev_path}"
                f"\n- ask summary: {ask_summary_path}"
                + (f"\n- runbook: {runbook_md_path}" if runbook_md_path else "")
            )
            if route.mutation_request:
                cli.console.print(
                    "\nSafety: detected a mutation-style request. ShellForgeAI ran read-only "
                    "evidence only. No restart/stop/start/delete/install/firewall changes were "
                    "performed. apply remains validation-only."
                )
        elif route.mode == EVIDENCE_BACKED and evidence_error is not None:
            cli.console.print(
                f"\nNote: this question matched the {route.intent_label} diagnostic intent, "
                "but read-only evidence collection failed in this runtime. Try "
                f'`shellforgeai diagnose "{question}" --save-plan` for a full diagnose run.'
            )
        if raw and resp.raw and resp.raw.get("stdout_jsonl"):
            cli.console.print(resp.raw["stdout_jsonl"])
