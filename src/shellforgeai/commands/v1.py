"""``v1 check`` command registration (extracted from ``cli.py`` in PR195).

Behavior-preserving move of the read-only V1 readiness/check handler. The
handler delegates to ``shellforgeai.core.v1_readiness.run_v1_readiness_check``
with the root Typer app supplied by ``cli.py`` so the command surface, JSON
payload, human rendering, exit codes, and safety posture remain unchanged.
"""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console

console = Console(markup=False)


def register(v1_app: typer.Typer, root_app: typer.Typer) -> None:
    """Register the V1 readiness check command on the existing ``v1`` app."""

    @v1_app.command("check")
    def v1_check(
        profile: Annotated[str, typer.Option("--profile")] = "standard",
        json_output: Annotated[bool, typer.Option("--json")] = False,
        fail_on_warn: Annotated[bool, typer.Option("--fail-on-warn")] = False,
    ) -> None:
        from shellforgeai.core.v1_readiness import run_v1_readiness_check

        try:
            payload = run_v1_readiness_check(root_app, profile=profile)
        except ValueError as exc:
            if json_output:
                typer.echo(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "mode": "v1_readiness_check",
                            "status": "failed",
                            "error": str(exc),
                        }
                    )
                )
            else:
                console.print(f"Error: {exc}")
            raise typer.Exit(1) from None

        if (
            fail_on_warn
            and payload.get("status") == "warn"
            and payload.get("ci_status") != "failed"
        ):
            payload["ci_status"] = "failed_on_warn"

        if json_output:
            typer.echo(json.dumps(payload))
        else:
            console.print("ShellForgeAI V1 readiness check")
            console.print("")
            console.print(f"Profile: {payload['profile']}")
            console.print(f"Status: {payload['status']}")
            console.print("\nPassed:")
            for c in payload["checks"]:
                if c["status"] == "passed":
                    console.print(f"- {c['name']}")
            if payload.get("warnings"):
                console.print("\nWarnings:")
                for w in payload["warnings"]:
                    console.print(f"- {w}")
            console.print("\nSafety:")
            for k, v in payload["safety"].items():
                console.print(f"- {k}: {str(v).lower()}")

        exit_code = 1 if payload.get("status") == "failed" else 0
        if fail_on_warn and payload.get("status") == "warn":
            exit_code = 1
        raise typer.Exit(exit_code)
