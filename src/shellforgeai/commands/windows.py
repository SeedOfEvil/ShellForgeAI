"""Read-only Windows V1 commands."""

from __future__ import annotations

import json
from typing import Annotated, Any

import typer
from rich.console import Console

from shellforgeai.windows_disks import (
    DEFAULT_DISKS_LIMIT,
    render_windows_disks_text,
    validate_disks_limit,
    windows_disks_payload,
)
from shellforgeai.windows_doctor import render_windows_doctor_text, windows_doctor_payload
from shellforgeai.windows_evidence import (
    EVIDENCE_DISKS_DEFAULT_LIMIT,
    EVIDENCE_PROCESSES_DEFAULT_LIMIT,
    EVIDENCE_SERVICES_DEFAULT_LIMIT,
    render_windows_evidence_text,
    validate_evidence_disks_limit,
    validate_evidence_processes_limit,
    validate_evidence_services_limit,
    windows_evidence_payload,
)
from shellforgeai.windows_memory import render_windows_memory_text, windows_memory_payload
from shellforgeai.windows_network import render_windows_network_text, windows_network_payload
from shellforgeai.windows_processes import (
    DEFAULT_PROCESSES_LIMIT,
    render_windows_processes_text,
    validate_processes_limit,
    windows_processes_payload,
)
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
        include_services: Annotated[
            bool,
            typer.Option(
                "--include-services",
                help="Opt in to a bounded read-only services component in the bundle.",
            ),
        ] = False,
        services_limit: Annotated[
            int | None,
            typer.Option(
                "--services-limit",
                help="Bounded max services in the opt-in services component (1-500).",
            ),
        ] = None,
        include_disks: Annotated[
            bool,
            typer.Option(
                "--include-disks",
                help="Opt in to a bounded read-only disks component in the bundle.",
            ),
        ] = False,
        disks_limit: Annotated[
            int | None,
            typer.Option(
                "--disks-limit",
                help="Bounded max disk roots in the opt-in disks component (1-64).",
            ),
        ] = None,
        include_processes: Annotated[
            bool,
            typer.Option(
                "--include-processes",
                help="Opt in to a bounded read-only processes component in the bundle.",
            ),
        ] = False,
        processes_limit: Annotated[
            int | None,
            typer.Option(
                "--processes-limit",
                help="Bounded max processes in the opt-in processes component (1-200).",
            ),
        ] = None,
    ) -> None:
        kwargs: dict[str, Any] = {}
        if include_services:
            try:
                kwargs["services_limit"] = validate_evidence_services_limit(
                    EVIDENCE_SERVICES_DEFAULT_LIMIT if services_limit is None else services_limit
                )
            except ValueError as exc:
                raise typer.BadParameter(str(exc), param_hint="--services-limit") from exc
            kwargs["include_services"] = True
        elif services_limit is not None:
            raise typer.BadParameter(
                "--services-limit requires --include-services",
                param_hint="--services-limit",
            )
        if include_disks:
            try:
                kwargs["disks_limit"] = validate_evidence_disks_limit(
                    EVIDENCE_DISKS_DEFAULT_LIMIT if disks_limit is None else disks_limit
                )
            except ValueError as exc:
                raise typer.BadParameter(str(exc), param_hint="--disks-limit") from exc
            kwargs["include_disks"] = True
        elif disks_limit is not None:
            raise typer.BadParameter(
                "--disks-limit requires --include-disks",
                param_hint="--disks-limit",
            )
        if include_processes:
            try:
                kwargs["processes_limit"] = validate_evidence_processes_limit(
                    EVIDENCE_PROCESSES_DEFAULT_LIMIT if processes_limit is None else processes_limit
                )
            except ValueError as exc:
                raise typer.BadParameter(str(exc), param_hint="--processes-limit") from exc
            kwargs["include_processes"] = True
        elif processes_limit is not None:
            raise typer.BadParameter(
                "--processes-limit requires --include-processes",
                param_hint="--processes-limit",
            )
        payload = windows_evidence_payload(**kwargs)
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

    @windows_app.command("disks")
    def windows_disks(
        json_output: Annotated[bool, typer.Option("--json")] = False,
        limit: Annotated[
            int,
            typer.Option("--limit", help="Bounded max disk roots to report (1-64)."),
        ] = DEFAULT_DISKS_LIMIT,
    ) -> None:
        try:
            validated_limit = validate_disks_limit(limit)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--limit") from exc
        payload = windows_disks_payload(limit=validated_limit)
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_disks_text(payload))

    @windows_app.command("memory")
    def windows_memory(
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Inspect Windows physical memory using a bounded read-only collector."""

        payload = windows_memory_payload()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_memory_text(payload))

    @windows_app.command("network")
    def windows_network(
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Inspect local Windows network interfaces using a bounded read-only collector."""

        payload = windows_network_payload()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_network_text(payload))

    @windows_app.command("processes")
    def windows_processes(
        json_output: Annotated[bool, typer.Option("--json")] = False,
        limit: Annotated[
            int,
            typer.Option("--limit", help="Bounded max processes to list (1-200)."),
        ] = DEFAULT_PROCESSES_LIMIT,
    ) -> None:
        try:
            validated_limit = validate_processes_limit(limit)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--limit") from exc
        payload = windows_processes_payload(limit=validated_limit)
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_processes_text(payload))

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
