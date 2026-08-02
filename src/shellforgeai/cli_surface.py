"""Read-only adapter from the assembled Typer app to an immutable CLI surface."""

from __future__ import annotations

from functools import lru_cache

from typer.main import get_command

from shellforgeai.core.command_suggestion_validation import (
    CliSurfaceSnapshot,
    SurfaceArgument,
    SurfaceCommand,
    SurfaceOption,
)


@lru_cache(maxsize=1)
def snapshot_packaged_cli_surface() -> CliSurfaceSnapshot:
    """Inspect registrations and parameters without parsing or invoking callbacks."""
    from shellforgeai.cli import app  # lazy: never imported by the pure validator

    root = get_command(app)
    commands: list[SurfaceCommand] = []

    def visit(command: object, path: tuple[str, ...]) -> None:
        options: list[SurfaceOption] = []
        arguments: list[SurfaceArgument] = []
        for parameter in getattr(command, "params", ()):
            choices = (
                tuple(str(value) for value in parameter.type.choices)
                if hasattr(parameter.type, "choices")
                else ()
            )
            if getattr(parameter, "param_type_name", "") == "option":
                parameter_type = parameter.type
                options.append(
                    SurfaceOption(
                        tuple(parameter.opts + parameter.secondary_opts),
                        not parameter.is_flag,
                        parameter.required,
                        choices,
                        getattr(parameter_type, "min", None),
                        getattr(parameter_type, "max", None),
                    )
                )
            elif getattr(parameter, "param_type_name", "") == "argument":
                arguments.append(
                    SurfaceArgument(parameter.name or "argument", parameter.required, choices)
                )
        is_group = hasattr(command, "list_commands") and hasattr(command, "get_command")
        if path and (not is_group or getattr(command, "invoke_without_command", False)):
            commands.append(SurfaceCommand(path, tuple(options), tuple(arguments)))
        if is_group:
            from typer._click.core import Context

            context = Context(command)
            for name in sorted(command.list_commands(context)):
                child = command.get_command(context, name)
                if child is not None:
                    visit(child, (*path, name))

    visit(root, ())
    # Some maintained bounds are semantic rather than Click type constraints.
    bounded: list[SurfaceCommand] = []
    for command in commands:
        options = tuple(
            SurfaceOption(
                option.names,
                option.takes_value,
                option.required,
                ("quick", "standard", "full")
                if command.path == ("windows", "evidence") and "--profile" in option.names
                else option.choices,
                option.minimum,
                option.maximum,
            )
            for option in command.options
        )
        bounded.append(SurfaceCommand(command.path, options, command.arguments))
    return CliSurfaceSnapshot(tuple(bounded))
