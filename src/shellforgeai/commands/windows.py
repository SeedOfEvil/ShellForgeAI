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
from shellforgeai.windows_events import (
    DEFAULT_EVENTS_LIMIT,
    DEFAULT_SINCE_HOURS,
    render_windows_events_text,
    validate_events_limit,
    validate_since_hours,
    windows_events_payload,
)
from shellforgeai.windows_evidence import (
    EVIDENCE_DISKS_DEFAULT_LIMIT,
    EVIDENCE_NETWORK_DEFAULT_ADDRESS_LIMIT,
    EVIDENCE_NETWORK_DEFAULT_INTERFACE_LIMIT,
    EVIDENCE_PROCESSES_DEFAULT_LIMIT,
    EVIDENCE_SERVICES_DEFAULT_LIMIT,
    EVIDENCE_VOLUMES_DEFAULT_LIMIT,
    render_windows_evidence_text,
    validate_evidence_disks_limit,
    validate_evidence_events_limit,
    validate_evidence_events_since_hours,
    validate_evidence_network_address_limit,
    validate_evidence_network_interface_limit,
    validate_evidence_processes_limit,
    validate_evidence_services_limit,
    validate_evidence_volumes_limit,
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
from shellforgeai.windows_volumes import (
    DEFAULT_VOLUMES_LIMIT,
    render_windows_volumes_text,
    validate_volumes_limit,
    windows_volumes_payload,
)

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
        include_events: Annotated[
            bool,
            typer.Option(
                "--include-events",
                help="Opt in to bounded read-only local Windows System Event metadata.",
            ),
        ] = False,
        events_limit: Annotated[
            int | None,
            typer.Option(
                "--events-limit",
                help=(
                    "Bounded max System events in the opt-in events component (1-200; default 50)."
                ),
            ),
        ] = None,
        events_since_hours: Annotated[
            int | None,
            typer.Option(
                "--events-since-hours",
                help="Bounded System events lookback in hours (1-168; default 24).",
            ),
        ] = None,
        include_network: Annotated[
            bool,
            typer.Option(
                "--include-network",
                help="Opt in to bounded read-only local Windows network-interface metadata.",
            ),
        ] = False,
        network_interface_limit: Annotated[
            int | None,
            typer.Option(
                "--network-interface-limit",
                help=(
                    "Bounded max network interfaces in opt-in network component (1-32; default 32)."
                ),
            ),
        ] = None,
        network_address_limit: Annotated[
            int | None,
            typer.Option(
                "--network-address-limit",
                help=(
                    "Bounded max addresses per interface in opt-in network component "
                    "(1-16; default 16)."
                ),
            ),
        ] = None,
        include_volumes: Annotated[
            bool,
            typer.Option(
                "--include-volumes",
                help=(
                    "Explicitly opt in to bounded read-only local drive-root volumes only "
                    "in the evidence bundle (default off)."
                ),
            ),
        ] = False,
        volumes_limit: Annotated[
            int | None,
            typer.Option(
                "--volumes-limit",
                help=(
                    "Bounded max local drive-root volumes in opt-in volumes component "
                    "(range 1-64; default 32; requires --include-volumes)."
                ),
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
        if include_events:
            try:
                kwargs["events_limit"] = validate_evidence_events_limit(
                    DEFAULT_EVENTS_LIMIT if events_limit is None else events_limit
                )
                kwargs["events_since_hours"] = validate_evidence_events_since_hours(
                    DEFAULT_SINCE_HOURS if events_since_hours is None else events_since_hours
                )
            except ValueError as exc:
                raise typer.BadParameter(
                    str(exc), param_hint="--events-limit/--events-since-hours"
                ) from exc
            kwargs["include_events"] = True
        else:
            if events_limit is not None:
                raise typer.BadParameter(
                    "--events-limit requires --include-events",
                    param_hint="--events-limit",
                )
            if events_since_hours is not None:
                raise typer.BadParameter(
                    "--events-since-hours requires --include-events",
                    param_hint="--events-since-hours",
                )
        if include_network:
            try:
                kwargs["network_interface_limit"] = validate_evidence_network_interface_limit(
                    EVIDENCE_NETWORK_DEFAULT_INTERFACE_LIMIT
                    if network_interface_limit is None
                    else network_interface_limit
                )
                kwargs["network_address_limit"] = validate_evidence_network_address_limit(
                    EVIDENCE_NETWORK_DEFAULT_ADDRESS_LIMIT
                    if network_address_limit is None
                    else network_address_limit
                )
            except ValueError as exc:
                raise typer.BadParameter(
                    str(exc), param_hint="--network-interface-limit/--network-address-limit"
                ) from exc
            kwargs["include_network"] = True
        else:
            if network_interface_limit is not None:
                raise typer.BadParameter(
                    "--network-interface-limit requires --include-network",
                    param_hint="--network-interface-limit",
                )
            if network_address_limit is not None:
                raise typer.BadParameter(
                    "--network-address-limit requires --include-network",
                    param_hint="--network-address-limit",
                )
        if include_volumes:
            try:
                kwargs["volumes_limit"] = validate_evidence_volumes_limit(
                    EVIDENCE_VOLUMES_DEFAULT_LIMIT if volumes_limit is None else volumes_limit
                )
            except ValueError as exc:
                raise typer.BadParameter(str(exc), param_hint="--volumes-limit") from exc
            kwargs["include_volumes"] = True
        elif volumes_limit is not None:
            raise typer.BadParameter(
                "--volumes-limit requires --include-volumes",
                param_hint="--volumes-limit",
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

    @windows_app.command("volumes")
    def windows_volumes(
        json_output: Annotated[bool, typer.Option("--json")] = False,
        limit: Annotated[
            int,
            typer.Option("--limit", help="Bounded max local drive-root volumes to report (1-64)."),
        ] = DEFAULT_VOLUMES_LIMIT,
    ) -> None:
        """Inspect local Windows drive-root volumes/filesystems read-only."""

        try:
            validated_limit = validate_volumes_limit(limit)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--limit") from exc
        payload = windows_volumes_payload(limit=validated_limit)
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_volumes_text(payload))

    @windows_app.command("events")
    def windows_events(
        json_output: Annotated[bool, typer.Option("--json")] = False,
        limit: Annotated[
            int,
            typer.Option("--limit", help="Bounded max System events to list (1-200)."),
        ] = DEFAULT_EVENTS_LIMIT,
        since_hours: Annotated[
            int,
            typer.Option(
                "--since-hours", help="Bounded System Event Log lookback in hours (1-168)."
            ),
        ] = DEFAULT_SINCE_HOURS,
    ) -> None:
        """Inspect local Windows System Critical/Error/Warning metadata read-only."""

        try:
            validated_limit = validate_events_limit(limit)
            validated_since_hours = validate_since_hours(since_hours)
        except ValueError as exc:
            hint = "--since-hours" if "--since-hours" in str(exc) else "--limit"
            raise typer.BadParameter(str(exc), param_hint=hint) from exc
        payload = windows_events_payload(limit=validated_limit, since_hours=validated_since_hours)
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return

        console.print(render_windows_events_text(payload))

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
