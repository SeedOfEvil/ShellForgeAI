"""``model`` command group registration (extracted in PR196).

Behavior-preserving move of the ``model`` command group: ``model doctor``
(previously registered from :mod:`shellforgeai.commands.doctor` since PR182)
and ``model test`` (previously inline in ``cli.py``). The handlers delegate to
existing ``shellforgeai.cli`` module attributes (resolved at call time) so
monkeypatch hooks like ``cli.build_provider``, the shared console, output,
exit codes, and safety behavior are preserved exactly.

``model doctor`` remains the read-only provider-readiness report: it prints
the provider doctor fields (provider/model/fallback, codex binary detection,
auth cache/readiness with ``status_unknown``, sandbox/approval) and suggests
``codex login`` recovery when the auth cache is missing. It never calls model
inference, never starts a Codex task, and never mutates anything. ``model
test`` keeps its existing explicit one-shot model call surface unchanged. No
cleanup, remediation, rollback, recovery, Docker/Compose mutation, restart,
shell execution, or arbitrary/natural-language execution is introduced here.
"""

from __future__ import annotations

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
    def model_doctor(ctx: typer.Context) -> None:
        runtime = cli._ctx(ctx)
        provider = cli.build_provider(runtime.settings)
        info = provider.doctor()
        for k, v in info.items():
            cli.console.print(f"{k}={v}")
        if not info.get("auth_cache_present"):
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
