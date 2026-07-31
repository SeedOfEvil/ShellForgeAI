"""PR329 shared platform-aware operator response contract."""

from __future__ import annotations

import dataclasses
import inspect
from pathlib import Path

import pytest

from shellforgeai.core import platform_operator_contract as contract_module
from shellforgeai.core.platform_operator_contract import (
    PlatformOperatorContract,
    build_platform_operator_contract,
    render_unsupported_platform_operator_response,
)
from shellforgeai.platform_detection import PlatformInfo


def _info(system: str) -> PlatformInfo:
    return PlatformInfo(system, f"{system}-test", "test", "test", "test")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("system", "expected"),
    [
        (
            "linux",
            {
                "display_name": "Linux",
                "support_lane": "linux_docker_v1",
                "route_family": "linux_primary",
                "local_evidence_available": True,
                "summary_heading": "Linux/Docker operator summary",
                "evidence_label": "Linux/Docker local read-only evidence",
                "fallback_heading": "Linux/Docker read-only fallback",
                "visibility": "linux-docker-local-read-only",
            },
        ),
        (
            "windows",
            {
                "display_name": "Windows",
                "support_lane": "windows_read_only_doctor_v1",
                "route_family": "windows_read_only",
                "local_evidence_available": True,
                "summary_heading": "Windows operator summary",
                "evidence_label": "Windows local read-only evidence",
                "fallback_heading": "Windows read-only fallback",
                "visibility": "windows-local-read-only",
            },
        ),
        (
            "darwin",
            {
                "display_name": "macOS",
                "support_lane": "unsupported",
                "route_family": "unsupported",
                "local_evidence_available": False,
                "summary_heading": "macOS operator support",
                "evidence_label": "No supported local operational evidence lane",
                "fallback_heading": "Unsupported platform",
                "visibility": "unsupported",
            },
        ),
        (
            "unknown",
            {
                "display_name": "this host",
                "support_lane": "unsupported",
                "route_family": "unsupported",
                "local_evidence_available": False,
                "summary_heading": "Operator support",
                "evidence_label": "No supported local operational evidence lane",
                "fallback_heading": "Unsupported platform",
                "visibility": "unsupported",
            },
        ),
    ],
)
def test_exact_platform_matrix(system: str, expected: dict[str, object]) -> None:
    value = build_platform_operator_contract(_info(system))
    assert value.platform_system == system
    for field, expected_value in expected.items():
        assert getattr(value, field) == expected_value
    assert value.next_safe_command == "shellforgeai platform doctor --json"
    if expected["local_evidence_available"]:
        assert value.unsupported_reason is None
    else:
        assert value.unsupported_reason is not None


def test_default_builder_reuses_maintained_detector(monkeypatch) -> None:
    info = _info("windows")
    monkeypatch.setattr(contract_module, "detect_platform", lambda: info)
    assert build_platform_operator_contract() == build_platform_operator_contract(info)


def test_contract_is_frozen_and_builder_has_no_user_text_parameter() -> None:
    value = build_platform_operator_contract(_info("linux"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.display_name = "other"  # type: ignore[misc]
    assert tuple(inspect.signature(build_platform_operator_contract).parameters) == ("info",)
    assert {field.name for field in dataclasses.fields(PlatformOperatorContract)} == {
        "platform_system",
        "display_name",
        "support_lane",
        "route_family",
        "local_evidence_available",
        "summary_heading",
        "evidence_label",
        "fallback_heading",
        "visibility",
        "unsupported_reason",
        "next_safe_command",
    }


@pytest.mark.parametrize("system,display", [("darwin", "macOS"), ("unknown", "this host")])
def test_unsupported_renderer_is_bounded_and_platform_aware(system: str, display: str) -> None:
    rendered = render_unsupported_platform_operator_response(
        build_platform_operator_contract(_info(system))
    )
    assert rendered.startswith("Unsupported platform\n")
    assert f"Detected platform: {display}" in rendered
    assert "Support lane: unsupported" in rendered
    assert "read_only=true" in rendered
    assert "mutation_performed=false" in rendered
    assert "No supported local operational evidence lane was selected." in rendered
    assert rendered.count("shellforgeai platform doctor --json") == 1
    for forbidden in ("systemctl", "journalctl", "df -i", "Event Log", "PowerShell"):
        assert forbidden not in rendered


def test_renderer_rejects_supported_contract() -> None:
    with pytest.raises(ValueError):
        render_unsupported_platform_operator_response(
            build_platform_operator_contract(_info("linux"))
        )


def test_contract_static_purity_and_deferred_pr_boundaries() -> None:
    source = (
        Path("src/shellforgeai/core/platform_operator_contract.py")
        .read_text(encoding="utf-8")
        .lower()
    )
    forbidden = (
        "route_input",
        "route_ask_intent",
        "from shellforgeai.core.collectors",
        "from shellforgeai.llm",
        "import shellforgeai.llm",
        "from shellforgeai.core.command_suggestions",
        "from shellforgeai.core.safe_commands",
        "subprocess",
        "powershell",
        "winrm",
        "threadpoolexecutor",
        "concurrent.futures",
        "deadline",
        "time.",
        "open(",
        "write_text",
        "socket",
        "http",
        "approved_change",
    )
    for token in forbidden:
        assert token not in source


def test_ask_and_interactive_import_the_single_shared_contract() -> None:
    ask_source = Path("src/shellforgeai/commands/ask.py").read_text(encoding="utf-8")
    repl_source = Path("src/shellforgeai/interactive/repl.py").read_text(encoding="utf-8")
    for source in (ask_source, repl_source):
        assert "build_platform_operator_contract" in source
        assert "render_unsupported_platform_operator_response" in source
    assert "route_ask_intent(question)" in ask_source
    assert ask_source.index("route_ask_intent(question)") < ask_source.index(
        "provider = cli.build_provider"
    )
    start = repl_source.index("def start_interactive(")
    contract = repl_source.index("operator_contract = build_platform_operator_contract()", start)
    loop = repl_source.index("while True:", start)
    assert contract < loop
