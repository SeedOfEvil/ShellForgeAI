"""Read-only Windows V1 doctor commands."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console

from shellforgeai.windows_doctor import render_windows_doctor_text, windows_doctor_payload

console = Console(markup=False, width=120)


def register(windows_app: typer.Typer) -> None:
    """Register local read-only Windows commands."""

    @windows_app.command("doctor")
    def windows_doctor(
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        payload = windows_doctor_payload()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_doctor_text(payload))
