"""PR336 deterministic platform-aware progressive-help contract."""

from __future__ import annotations

import pytest

from shellforgeai.core.platform_operator_contract import build_platform_operator_contract
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.help import HELP_USAGE, render_advanced_help, render_quick_help
from shellforgeai.platform_detection import PlatformInfo


def _contract(system: str):
    return build_platform_operator_contract(
        PlatformInfo(
            system=system, python_platform="test", os_name="test", release="test", machine="test"
        )
    )


@pytest.mark.parametrize("alias", ["help", "/help", "?", "commands", "what can I do?"])
def test_default_aliases_select_identical_local_help(alias: str) -> None:
    routed = route_input(alias)
    assert routed.name == "/help"
    assert routed.args == ""


def test_linux_quick_help_is_bounded_and_platform_specific() -> None:
    text = render_quick_help(_contract("linux"))
    assert len(text.splitlines()) <= 40
    for expected in (
        "Linux/Docker read-only",
        "What looks unhealthy?",
        "Why does this system feel slow?",
        "Is my Docker container crashing?",
        "strongest CPU, memory, disk, or process signal",
        "Based on evidence already collected",
        "status --brief",
        "ops report --brief",
        "v1 check quick",
        "triage docker",
        "/pending  /summary",
        "/help advanced",
        "Natural-language fixes",
    ):
        assert expected in text
    assert "windows evidence" not in text.lower()


def test_windows_quick_help_has_native_journey_without_linux_leakage() -> None:
    text = render_quick_help(_contract("windows"))
    assert len(text.splitlines()) <= 40
    for expected in (
        "Windows local read-only",
        "What looks unhealthy?",
        "Is anything crashing?",
        "Why does this system feel slow?",
        "Are any services unhealthy?",
        "Am I running out of disk space?",
        "Is networking okay?",
        "strongest CPU, memory, disk, or process signal",
        "Based on evidence already collected",
        "shellforgeai windows evidence --profile standard --json",
        "shellforgeai windows status --json",
    ):
        assert expected in text
    lowered = text.lower()
    for forbidden in (
        "systemctl",
        "journalctl",
        "linux df",
        "linux ip",
        "/proc",
        " ss ",
        "inode",
        "linux ps",
    ):
        assert forbidden not in lowered


@pytest.mark.parametrize("system", ["darwin", "unknown"])
def test_unsupported_quick_help_is_honest_and_generic(system: str) -> None:
    text = render_quick_help(_contract(system))
    assert "Local operator evidence support is unavailable" in text
    assert "shellforgeai platform doctor --json" in text
    assert "ask explain this command" in text
    assert "/pending  /summary" in text
    assert "/help advanced" in text
    assert "Linux/Docker operator" not in text
    assert "Windows local read-only" not in text


@pytest.mark.parametrize("form", ["help advanced", "/help advanced"])
def test_advanced_forms_select_same_bounded_reference(form: str) -> None:
    routed = route_input(form)
    assert routed.name == "/help"
    assert routed.args == "advanced"
    text = render_advanced_help()
    assert len(text.splitlines()) <= 100
    for expected in (
        "Session:",
        "Status and evidence:",
        "Linux/Docker diagnostics",
        "Windows read-only diagnostics",
        "V2 read-only lifecycle:",
        "Reports and artifacts:",
        "Governed explicit workflows — never executed from natural language:",
        "recipes execute <id> --confirm",
        "recovery-execute <id> --confirm",
        "Refused natural-language actions",
        "no provider, dispatcher, collector, or command runs",
    ):
        assert expected in text


@pytest.mark.parametrize("form", ["help nonsense", "/help nonsense", "help windows", "/help linux"])
def test_invalid_help_topics_route_to_local_usage(form: str) -> None:
    routed = route_input(form)
    assert routed.name == "/help"
    assert routed.args not in {"", "advanced"}
    assert HELP_USAGE == "Usage: help [advanced]"


def test_unknown_slash_and_mutation_priority_are_unchanged() -> None:
    assert route_input("/definitely-unknown").name == "/definitely-unknown"
    for text in (
        "docker restart sfai-crashloop",
        "cleanup execute --confirm",
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "rm -rf /",
    ):
        assert route_input(text).name == "mutation_refused"
