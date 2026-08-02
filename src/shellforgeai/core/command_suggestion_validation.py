"""Pure, fail-closed validation for operator command suggestions.

This module knows no CLI application and performs no command invocation.  A
higher-level adapter supplies an immutable description of the packaged Click
tree, keeping core policy independently testable and free of CLI import cycles.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Literal

RouteFamily = Literal["linux_primary", "windows_read_only", "unsupported"]
SuggestionClass = Literal[
    "portable_read_only", "linux_read_only", "windows_read_only", "preview_read_only"
]

NO_VALIDATED_COMMAND = "No validated safe command is available for this context."
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_UNSAFE = re.compile(r"(?:\n|\r|&&|\|\||[;|`$\\]|>>?|<\(|\$\()")


@dataclass(frozen=True)
class SurfaceOption:
    names: tuple[str, ...]
    takes_value: bool
    required: bool = False
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None


@dataclass(frozen=True)
class SurfaceArgument:
    name: str
    required: bool
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class SurfaceCommand:
    path: tuple[str, ...]
    options: tuple[SurfaceOption, ...]
    arguments: tuple[SurfaceArgument, ...]


@dataclass(frozen=True)
class CliSurfaceSnapshot:
    commands: tuple[SurfaceCommand, ...]


@dataclass(frozen=True)
class SuggestionPolicy:
    command_path: tuple[str, ...]
    safety_class: SuggestionClass


@dataclass(frozen=True)
class CommandSuggestionValidationResult:
    original_command: str
    canonical_command: str | None
    valid: bool
    reason: str
    active_platform_family: RouteFamily
    intended_platform_family: RouteFamily
    matched_command_path: tuple[str, ...]
    matched_arguments: tuple[str, ...]
    matched_options: tuple[str, ...]
    safety_class: str | None
    replacement_command: str | None = None
    read_only: bool = True
    mutation_performed: bool = False


def validate_command_suggestion(
    command: str,
    *,
    active_platform: RouteFamily,
    intended_platform: RouteFamily | None,
    surface: CliSurfaceSnapshot,
    policies: tuple[SuggestionPolicy, ...],
) -> CommandSuggestionValidationResult:
    """Validate syntax, packaged surface, explicit policy, and platform."""
    target = intended_platform or active_platform

    def rejected(reason: str, path: tuple[str, ...] = ()) -> CommandSuggestionValidationResult:
        return CommandSuggestionValidationResult(
            command, None, False, reason, active_platform, target, path, (), (), None
        )

    raw = (command or "").strip()
    if not raw:
        return rejected("empty")
    if _UNSAFE.search(raw):
        return rejected("shell_metacharacter")
    try:
        tokens = shlex.split(raw, posix=True)
    except ValueError:
        return rejected("malformed")
    if not tokens or tokens[0] != "shellforgeai":
        return rejected("noncanonical_executable")
    candidates = sorted(surface.commands, key=lambda item: len(item.path), reverse=True)
    matched = next(
        (item for item in candidates if tuple(tokens[1 : 1 + len(item.path)]) == item.path), None
    )
    if matched is None:
        return rejected("unknown_command")
    remainder = tokens[1 + len(matched.path) :]
    option_map = {name: option for option in matched.options for name in option.names}
    seen: set[SurfaceOption] = set()
    option_names: list[str] = []
    arguments: list[str] = []
    index = 0
    while index < len(remainder):
        token = remainder[index]
        if token.startswith("-"):
            option = option_map.get(token)
            if option is None:
                return rejected("unknown_option", matched.path)
            if option in seen:
                return rejected("duplicate_option", matched.path)
            seen.add(option)
            option_names.append(token)
            if option.takes_value:
                index += 1
                if index >= len(remainder) or remainder[index].startswith("-"):
                    return rejected("missing_option_value", matched.path)
                value = remainder[index]
                if option.choices and value not in option.choices:
                    return rejected("invalid_option_value", matched.path)
                if option.minimum is not None or option.maximum is not None:
                    try:
                        numeric = int(value)
                    except ValueError:
                        return rejected("invalid_option_value", matched.path)
                    if option.minimum is not None and numeric < option.minimum:
                        return rejected("invalid_option_value", matched.path)
                    if option.maximum is not None and numeric > option.maximum:
                        return rejected("invalid_option_value", matched.path)
            index += 1
            continue
        arguments.append(token)
        index += 1
    if any(option.required and option not in seen for option in matched.options):
        return rejected("missing_required_option", matched.path)
    if len(arguments) > len(matched.arguments):
        return rejected("extra_argument", matched.path)
    if len(arguments) < sum(argument.required for argument in matched.arguments):
        return rejected("missing_argument", matched.path)
    for value, spec in zip(arguments, matched.arguments, strict=False):
        if spec.choices and value not in spec.choices:
            return rejected("invalid_argument", matched.path)
        if not _IDENTIFIER.fullmatch(value):
            return rejected("invalid_argument", matched.path)
    policy = next((item for item in policies if item.command_path == matched.path), None)
    if policy is None:
        return rejected("not_suggestable", matched.path)
    # Unsupported-local guidance is deliberately narrower than the general
    # portable class.  Platform doctor is the only supported way to establish
    # the host lane; an explicit supported target remains a separate policy.
    if (
        active_platform == "unsupported"
        and intended_platform is None
        and matched.path != ("platform", "doctor")
    ):
        return rejected("wrong_platform", matched.path)
    allowed = {
        "unsupported": {"portable_read_only"},
        "linux_primary": {"portable_read_only", "linux_read_only", "preview_read_only"},
        "windows_read_only": {"portable_read_only", "windows_read_only"},
    }[target]
    if policy.safety_class not in allowed:
        return rejected("wrong_platform", matched.path)
    canonical = " ".join(tokens)
    return CommandSuggestionValidationResult(
        command,
        canonical,
        True,
        "valid",
        active_platform,
        target,
        matched.path,
        tuple(arguments),
        tuple(option_names),
        policy.safety_class,
    )


def validate_suggestion_with_fallback(
    command: str,
    fallback: str | None,
    *,
    active_platform: RouteFamily,
    intended_platform: RouteFamily | None,
    surface: CliSurfaceSnapshot,
    policies: tuple[SuggestionPolicy, ...],
) -> CommandSuggestionValidationResult:
    """Try one independent fallback; never recurse or retain an invalid value."""
    original = validate_command_suggestion(
        command,
        active_platform=active_platform,
        intended_platform=intended_platform,
        surface=surface,
        policies=policies,
    )
    if original.valid or not fallback or fallback.strip() == (command or "").strip():
        return original
    replacement = validate_command_suggestion(
        fallback,
        active_platform=active_platform,
        intended_platform=intended_platform,
        surface=surface,
        policies=policies,
    )
    if not replacement.valid:
        return original
    return CommandSuggestionValidationResult(
        original.original_command,
        None,
        False,
        original.reason,
        original.active_platform_family,
        original.intended_platform_family,
        original.matched_command_path,
        original.matched_arguments,
        original.matched_options,
        original.safety_class,
        replacement.canonical_command,
    )
