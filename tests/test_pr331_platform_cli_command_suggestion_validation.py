from __future__ import annotations

import importlib
import sys

import pytest

from shellforgeai.cli_surface import snapshot_packaged_cli_surface
from shellforgeai.core.command_suggestion_validation import (
    NO_VALIDATED_COMMAND,
    validate_command_suggestion,
    validate_suggestion_with_fallback,
)
from shellforgeai.core.command_suggestions import filter_unsupported_command_suggestions
from shellforgeai.core.safe_commands import (
    SAFE_COMMANDS,
    SUGGESTION_POLICIES,
    filter_or_replace_unsafe_command_suggestions,
    validate_operator_command_suggestion,
)
from shellforgeai.core.windows_operator_ux import (
    WINDOWS_OPERATOR_INTENT_SERVICES,
    windows_operator_safe_commands,
)


def _validate(command: str, platform: str = "linux_primary"):
    return validate_command_suggestion(
        command,
        active_platform=platform,
        intended_platform=None,
        surface=snapshot_packaged_cli_surface(),
        policies=SUGGESTION_POLICIES,
    )


def test_complete_registry_conforms_to_real_packaged_surface() -> None:
    assert SAFE_COMMANDS
    for entry in SAFE_COMMANDS:
        concrete = entry.command.replace("<suspect>", "api-1")
        result = _validate(concrete)
        assert result.valid, (entry.id, result.reason)
        assert result.read_only is True
        assert result.mutation_performed is False
        assert concrete.startswith("shellforgeai ")
        assert entry.read_only is True and entry.mutation is False and entry.suggest is True


@pytest.mark.parametrize(
    "stale",
    (
        "shellforgeai propose docker --json",
        "shellforgeai apply-preview docker --json",
        "shellforgeai verify docker --json",
        "shellforgeai handoff docker --json",
    ),
)
def test_stale_positional_forms_are_rejected(stale: str) -> None:
    assert not _validate(stale).valid


@pytest.mark.parametrize(
    "command,reason",
    (
        ("shellforgeai missing --json", "unknown_command"),
        ("shellforgeai windows missing --json", "unknown_command"),
        ("shellforgeai status --bogus", "unknown_option"),
        ("shellforgeai --json status", "unknown_command"),
        ("shellforgeai windows services --limit", "missing_option_value"),
        ("shellforgeai status extra", "extra_argument"),
        ("shellforgeai triage docker detail bad/name --json", "invalid_argument"),
        ("shellforgeai windows evidence --profile impossible --json", "invalid_option_value"),
        ("shellforgeai windows events --since-hours 2 --limit 2 --limit 3", "duplicate_option"),
        ("shellforgeai windows services --since-hours 2", "unknown_option"),
        ("shellforgeai triage docker --limit 2", "unknown_option"),
        ("shellforgeai status --json; whoami", "shell_metacharacter"),
        ("shellforgeai status --json\nshellforgeai doctor", "shell_metacharacter"),
        ("sfai status --json", "noncanonical_executable"),
    ),
)
def test_exact_surface_rejections(command: str, reason: str) -> None:
    result = _validate(command)
    assert not result.valid
    assert result.reason == reason


@pytest.mark.parametrize(
    "command",
    (
        "shellforgeai remediation execute --target api --scenario restart --confirm",
        "shellforgeai recipes execute disposable-container-restart --target api --confirm",
        "shellforgeai remediation rollback-execute receipt --confirm",
        "shellforgeai audit cleanup execute --confirm cleanup",
        "shellforgeai mission restart execute mission --confirm",
    ),
)
def test_parse_surface_does_not_imply_suggestable(command: str) -> None:
    result = _validate(command)
    assert not result.valid
    assert result.reason in {"not_suggestable", "unknown_option", "missing_required_option"}


def test_platform_target_policy_and_windows_order() -> None:
    windows = "shellforgeai windows services --json --limit 25"
    assert _validate(windows, "windows_read_only").valid
    assert _validate(windows, "linux_primary").reason == "wrong_platform"
    explicit = validate_command_suggestion(
        windows,
        active_platform="linux_primary",
        intended_platform="windows_read_only",
        surface=snapshot_packaged_cli_surface(),
        policies=SUGGESTION_POLICIES,
    )
    assert explicit.valid
    commands = windows_operator_safe_commands(WINDOWS_OPERATOR_INTENT_SERVICES)
    assert commands[0] == windows
    assert all("triage docker" not in command for command in commands)


def test_unsupported_allows_only_platform_doctor() -> None:
    representatives = {
        ("platform", "doctor"): "shellforgeai platform doctor --json",
        ("model", "doctor"): "shellforgeai model doctor --json",
        ("status",): "shellforgeai status --json",
        ("doctor",): "shellforgeai doctor --json",
        ("ops", "report"): "shellforgeai ops report --json",
        ("ops", "status"): "shellforgeai ops status --json",
        ("triage", "docker"): "shellforgeai triage docker --json",
        ("triage", "docker", "detail"): ("shellforgeai triage docker detail api-1 --json"),
        ("triage", "docker", "snapshot"): "shellforgeai triage docker snapshot --json",
        ("triage", "docker", "timeline"): "shellforgeai triage docker timeline --json",
        ("propose",): "shellforgeai propose --from-triage --json",
        ("apply-preview",): "shellforgeai apply-preview --from-triage --json",
        ("verify",): "shellforgeai verify --from-triage --json",
        ("handoff",): "shellforgeai handoff --from-triage --json",
        ("windows", "evidence"): ("shellforgeai windows evidence --profile standard --json"),
        ("windows", "status"): "shellforgeai windows status --json",
        ("windows", "doctor"): "shellforgeai windows doctor --json",
        ("windows", "processes"): "shellforgeai windows processes --json --limit 10",
        ("windows", "events"): ("shellforgeai windows events --json --limit 50 --since-hours 24"),
        ("windows", "network"): "shellforgeai windows network --json",
        ("windows", "volumes"): "shellforgeai windows volumes --json --limit 32",
        ("windows", "services"): "shellforgeai windows services --json --limit 25",
    }
    assert set(representatives) == {policy.command_path for policy in SUGGESTION_POLICIES}
    valid_paths = {
        path for path, command in representatives.items() if _validate(command, "unsupported").valid
    }
    assert valid_paths == {("platform", "doctor")}
    for path, command in representatives.items():
        result = _validate(command, "unsupported")
        if path != ("platform", "doctor"):
            assert result.reason == "wrong_platform", path


def test_model_doctor_remains_portable_only_on_supported_hosts() -> None:
    command = "shellforgeai model doctor --json"
    assert _validate(command, "linux_primary").valid
    assert _validate(command, "windows_read_only").valid
    assert _validate(command, "unsupported").reason == "wrong_platform"


def test_fallback_is_independently_validated_once() -> None:
    surface = snapshot_packaged_cli_surface()
    valid = validate_suggestion_with_fallback(
        "shellforgeai stale",
        "shellforgeai status --json",
        active_platform="linux_primary",
        intended_platform=None,
        surface=surface,
        policies=SUGGESTION_POLICIES,
    )
    assert not valid.valid
    assert valid.replacement_command == "shellforgeai status --json"
    invalid = validate_suggestion_with_fallback(
        "shellforgeai stale",
        "shellforgeai also-stale",
        active_platform="linux_primary",
        intended_platform=None,
        surface=surface,
        policies=SUGGESTION_POLICIES,
    )
    assert invalid.replacement_command is None
    duplicate = validate_suggestion_with_fallback(
        "shellforgeai stale",
        "shellforgeai stale",
        active_platform="linux_primary",
        intended_platform=None,
        surface=surface,
        policies=SUGGESTION_POLICIES,
    )
    assert duplicate.replacement_command is None
    assert NO_VALIDATED_COMMAND == "No validated safe command is available for this context."


def test_validation_is_deterministic_and_does_not_invoke_callbacks(monkeypatch) -> None:
    import typer._click.core

    def forbidden(*args, **kwargs):  # pragma: no cover - assertion helper
        raise AssertionError("a command callback was invoked")

    monkeypatch.setattr(typer._click.core.Command, "invoke", forbidden)
    first = _validate("shellforgeai ops report --brief")
    second = _validate("shellforgeai ops report --brief")
    assert first == second


def test_pure_validator_import_does_not_import_cli() -> None:
    original_cli = sys.modules.get("shellforgeai.cli")
    sys.modules.pop("shellforgeai.core.command_suggestion_validation", None)
    sys.modules.pop("shellforgeai.cli", None)
    importlib.import_module("shellforgeai.core.command_suggestion_validation")
    assert "shellforgeai.cli" not in sys.modules
    if original_cli is not None:
        sys.modules["shellforgeai.cli"] = original_cli


def test_surface_exception_fails_closed(monkeypatch) -> None:
    import shellforgeai.cli_surface

    monkeypatch.setattr(
        shellforgeai.cli_surface,
        "snapshot_packaged_cli_surface",
        lambda: (_ for _ in ()).throw(RuntimeError("internal click object")),
    )
    result = validate_operator_command_suggestion("shellforgeai status --json")
    assert not result.valid
    assert result.canonical_command is None
    assert result.reason == "surface_unavailable"
    assert result.read_only and not result.mutation_performed


def test_central_filter_propagates_platform_to_original_and_fallback() -> None:
    invalid = "Try shellforgeai triage docker --json."
    windows_fallback = "shellforgeai windows services --json --limit 25"
    windows = filter_or_replace_unsafe_command_suggestions(
        invalid,
        active_platform="windows_read_only",
        fallback_command=windows_fallback,
    )
    assert "triage docker" not in windows.safe_text
    assert windows_fallback in windows.safe_text
    assert windows.replacement_commands == [windows_fallback]

    wrong_fallback = filter_or_replace_unsafe_command_suggestions(
        invalid,
        active_platform="windows_read_only",
        fallback_command="shellforgeai triage docker --json",
    )
    assert "triage docker" not in wrong_fallback.safe_text
    assert NO_VALIDATED_COMMAND in wrong_fallback.safe_text
    assert wrong_fallback.replacement_commands == []


@pytest.mark.parametrize(
    "fallback",
    (
        "shellforgeai status --json; whoami",
        "shellforgeai remediation execute --target api --scenario restart --confirm",
    ),
)
def test_central_filter_never_inserts_malformed_or_governed_fallback(fallback: str) -> None:
    result = filter_or_replace_unsafe_command_suggestions(
        "Try shellforgeai stale --json.",
        fallback_command=fallback,
    )
    assert fallback not in result.safe_text
    assert NO_VALIDATED_COMMAND in result.safe_text


def test_wrapper_validates_explicit_fallback_with_forwarded_platform() -> None:
    source = "Try shellforgeai triage docker --json"
    fallback = "shellforgeai windows status --json"
    cleaned, removed = filter_unsupported_command_suggestions(
        source,
        safe_next_command=fallback,
        active_platform="windows_read_only",
    )
    assert removed == ["shellforgeai triage docker --json"]
    assert fallback in cleaned
    assert "triage docker" not in cleaned

    cleaned, _ = filter_unsupported_command_suggestions(
        "Try shellforgeai stale --json",
        safe_next_command=fallback,
        active_platform="linux_primary",
    )
    assert fallback not in cleaned
    assert NO_VALIDATED_COMMAND in cleaned


def test_explicit_targets_flow_through_central_filter_without_changing_local_policy() -> None:
    docker = "shellforgeai triage docker --json"
    explicit_docker = filter_or_replace_unsafe_command_suggestions(
        f"Try {docker}.",
        active_platform="windows_read_only",
        intended_platform="linux_primary",
        fallback_command=docker,
    )
    assert docker in explicit_docker.safe_text
    assert explicit_docker.removed_suggestions == []

    windows = "shellforgeai windows services --json --limit 25"
    explicit_windows = filter_or_replace_unsafe_command_suggestions(
        f"Try {windows}.",
        active_platform="linux_primary",
        intended_platform="windows_read_only",
    )
    assert windows in explicit_windows.safe_text
    assert explicit_windows.removed_suggestions == []

    local_linux = filter_or_replace_unsafe_command_suggestions(
        f"Try {windows}.", active_platform="linux_primary", fallback_command=windows
    )
    assert windows not in local_linux.safe_text
    assert NO_VALIDATED_COMMAND in local_linux.safe_text
