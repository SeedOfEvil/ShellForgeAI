"""Read-only Windows V1 doctor, status, evidence, and services commands."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console

from shellforgeai.windows_doctor import render_windows_doctor_text, windows_doctor_payload
from shellforgeai.windows_evidence import render_windows_evidence_text, windows_evidence_payload
from shellforgeai.windows_services import (
    DEFAULT_MAX_SERVICES,
    render_windows_services_text,
    windows_services_payload,
)
from shellforgeai.windows_status import render_windows_status_text, windows_status_payload

console = Console(markup=False, width=120)


def register(windows_app: typer.Typer) -> None:
    """Register local read-only Windows commands."""

    @windows_app.command("evidence")
    def windows_evidence(
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        payload = windows_evidence_payload()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_evidence_text(payload))

    @windows_app.command("doctor")
    def windows_doctor(
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        payload = windows_doctor_payload()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_doctor_text(payload))

    @windows_app.command("status")
    def windows_status(
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        payload = windows_status_payload()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_status_text(payload))

    @windows_app.command("services")
    def windows_services(
        json_output: Annotated[bool, typer.Option("--json")] = False,
        limit: Annotated[
            int,
            typer.Option("--limit", help="Bounded max services to list (1-500)."),
        ] = DEFAULT_MAX_SERVICES,
    ) -> None:
        payload = windows_services_payload(max_services=limit)
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_services_text(payload))
