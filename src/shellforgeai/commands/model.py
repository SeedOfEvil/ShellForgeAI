"""``model`` command group registration (extracted in PR196).

Behavior-preserving move of the ``model`` command group: ``model doctor``
(previously registered from :mod:`shellforgeai.commands.doctor` since PR182)
and ``model test`` (previously inline in ``cli.py``). The handlers delegate to
existing ``shellforgeai.cli`` module attributes (resolved at call time) so
monkeypatch hooks like ``cli.build_provider``, the shared console, output,
exit codes, and safety behavior are preserved exactly.

``model doctor`` remains the read-only provider-readiness report: it prints
the provider doctor fields (provider/model/fallback, codex binary detection,
auth cache presence separately from live auth readiness, sandbox/approval) and suggests
``codex login`` recovery when the auth cache is missing. It never calls model
inference, never starts a Codex task, and never mutates anything. ``model
test`` keeps its existing explicit one-shot model call surface unchanged. No
cleanup, remediation, rollback, recovery, Docker/Compose mutation, restart,
shell execution, or arbitrary/natural-language execution is introduced here.
"""

from __future__ import annotations

import json as json_lib
import sys
from typing import Annotated

import typer

from shellforgeai.llm.schemas import ModelRequest


def register(model_app: typer.Typer) -> None:
    """Register ``doctor`` and ``test`` on the existing ``model`` Typer app.

    Both handlers resolve shared ``shellforgeai.cli`` helpers lazily (for
    example ``cli.build_provider`` and ``cli.console``) to preserve the
    monkeypatch hooks used by the test suite and the exact current behavior.
    """

    cli = sys.modules["shellforgeai.cli"]

    @model_app.command("doctor")
    def model_doctor(
        ctx: typer.Context,
        json_output: bool = typer.Option(False, "--json", help="Emit strict JSON output."),
    ) -> None:
        runtime = cli._ctx(ctx)
        warnings: list[str] = []
        try:
            provider = cli.build_provider(runtime.settings)
            info = provider.doctor()
        except Exception as exc:
            info = {
                "provider": runtime.settings.model.provider,
                "model": runtime.settings.model.model,
                "auth_readiness": "unknown",
                "auth_reason": "doctor_unavailable",
            }
            warnings.append(f"model doctor readiness unavailable: {exc}")
        auth_cache_present = bool(info.get("auth_cache_present"))
        auth_readiness = str(info.get("auth_readiness") or "unknown")
        auth_reason = str(info.get("auth_reason") or "status_unknown")
        ok = auth_readiness not in {
            "failed",
            "error",
            "missing_binary",
            "missing_auth_cache",
            "unauthorized",
        }
        live_probe_available = bool(info.get("live_probe_available", False))
        live_probe_performed = bool(info.get("live_probe_performed", False))
        safe_next_command = str(info.get("safe_next_command") or "shellforgeai model doctor --json")
        if json_output:
            payload = {
                "schema_version": 1,
                "mode": "model_doctor",
                "status": "ok" if ok else "warning",
                "ok": ok,
                "read_only": True,
                "mutation_performed": False,
                "provider": info.get("provider"),
                "model": info.get("model"),
                "codex_binary": info.get("codex_binary"),
                "codex_version": info.get("codex_version"),
                "auth_cache_present": auth_cache_present,
                "auth_readiness": auth_readiness,
                "auth_reason": auth_reason,
                "auth_verification_status": info.get("auth_verification_status", auth_readiness),
                "auth_readiness_label": info.get(
                    "auth_readiness_label", auth_readiness.replace("_", " ")
                ),
                "live_probe_available": live_probe_available,
                "live_probe_performed": live_probe_performed,
                "model_called": False,
                "safe_next_command": safe_next_command,
                "warnings": warnings,
                "doctor": info,
                "safety": {
                    "read_only": True,
                    "mutation_performed": False,
                    "cleanup" + "_executed": False,
                    "remediation" + "_executed": False,
                    "rollback" + "_executed": False,
                    "recovery" + "_executed": False,
                    "docker_compose" + "_executed": False,
                    "container" + "_restarted": False,
                    "natural_language_execution": False,
                    "shell_true": False,
                    "model_called": False,
                },
            }
            typer.echo(json_lib.dumps(payload, sort_keys=True, separators=(",", ":")))
            return
        for k, v in info.items():
            cli.console.print(f"{k}={v}")
        cli.console.print(f"Auth cache: {'present' if auth_cache_present else 'missing'}")
        readiness_label = auth_readiness.replace("_", " ")
        cli.console.print(f"Live auth readiness: {readiness_label}")
        if auth_reason == "auth_cache_present_live_probe_not_run":
            cli.console.print("Reason: default model doctor does not call the model")
        else:
            cli.console.print(f"Reason: {auth_reason}")
        cli.console.print(f"Safe next step: {safe_next_command}")
        if auth_readiness == "missing_binary":
            cli.console.print(
                "Codex CLI binary is missing; configure Codex before model-backed synthesis."
            )
        elif auth_readiness in {"missing_auth_cache", "failed"} or not auth_cache_present:
            cli.console.print("Suggested login: codex login (or codex login --device-auth)")

    @model_app.command("test")
    def model_test(
        ctx: typer.Context,
        prompt: Annotated[str, typer.Argument()] = "Reply with: Hello.",
        raw: bool = typer.Option(False, "--raw"),
        timeout: int | None = typer.Option(None, "--timeout"),
        model: str | None = typer.Option(None, "--model"),
    ) -> None:
        runtime = cli._ctx(ctx)
        provider = cli.build_provider(runtime.settings)
        req = ModelRequest(
            prompt=prompt,
            model=model or runtime.settings.model.model,
            provider=runtime.settings.model.provider,
            timeout_seconds=timeout or runtime.settings.model.timeout_seconds,
            metadata={"raw": raw},
        )
        resp = provider.complete(req)
        cli.console.print(resp.text)
        cli.console.print(
            f"\nProvider: {resp.provider}\n"
            f"Model: {resp.model}\n"
            f"OK: {str(resp.ok).lower()}\n"
            f"{cli._usage_line(resp)}"
        )
        if raw and resp.raw and resp.raw.get("stdout_jsonl"):
            cli.console.print(resp.raw["stdout_jsonl"])
