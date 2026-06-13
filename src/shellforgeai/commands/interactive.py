"""``interactive`` command registration (extracted from ``cli.py`` in PR200).

Behavior-preserving move of the top-level interactive launcher. The launcher is
Typer wiring only: it resolves the runtime context and hands off to the existing
``shellforgeai.interactive.start_interactive`` REPL implementation, which is not
moved or modified by this PR. The operator-facing surface is unchanged: the
``interactive`` command keeps its ``--no-trust-cache`` and ``--yes-trust``
options (including the trust-prompt help text), startup/exit behavior,
deterministic read-only routing, mutation refusal, and not-a-shell posture.

Safety posture (unchanged by the move): the launcher itself executes nothing.
It introduces no cleanup, remediation, rollback, or recovery execution; no
Docker/Compose mutation or container/production restart; no ``shell=True``; no
arbitrary or natural-language command execution; and no model/Codex call. The
``--yes-trust`` flag only gates the workspace trust prompt; it does not grant
mutation, shell execution, or bypass any safety refusal. Interactive routing
and refusal semantics live in ``shellforgeai.interactive`` and are untouched.
"""

from __future__ import annotations

import sys

import typer


def register(app: typer.Typer) -> None:
    """Register the top-level ``interactive`` launcher on ``app``."""

    cli = sys.modules["shellforgeai.cli"]

    @app.command("interactive")
    def interactive(
        ctx: typer.Context,
        no_trust_cache: bool = typer.Option(False, "--no-trust-cache"),
        yes_trust: bool = typer.Option(
            False,
            "--yes-trust",
            help=(
                "Trust the current workspace for this interactive session and skip the "
                "trust prompt. Only gates the workspace prompt; does not grant mutation, "
                "shell execution, or bypass safety refusals."
            ),
        ),
    ) -> None:
        from shellforgeai.interactive import start_interactive

        start_interactive(cli._ctx(ctx), no_trust_cache=no_trust_cache, yes_trust=yes_trust)
