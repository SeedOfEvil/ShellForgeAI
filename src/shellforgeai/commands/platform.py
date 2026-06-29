"""Read-only platform status commands."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console

from shellforgeai.platform_detection import platform_doctor_payload

console = Console(markup=False, width=120)


def register(platform_app: typer.Typer) -> None:
    """Register read-only platform commands."""

    @platform_app.command("doctor")
    def platform_doctor(
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        payload = platform_doctor_payload()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        platform_info = payload["platform"]
        support = payload["support"]
        console.print("ShellForgeAI platform doctor")
        console.print(f"Status: {payload['status']}")
        console.print(f"Platform: {platform_info['system']}")
        console.print(f"Lane: {support['lane']}")
        console.print(f"Read-only: {str(payload['read_only']).lower()}")
        console.print(f"Mutation performed: {str(payload['mutation_performed']).lower()}")
        console.print(payload["message"])
        console.print(f"Next safe command: {payload['next_safe_command']}")
