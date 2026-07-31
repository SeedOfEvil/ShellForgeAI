"""PR329 shared platform-aware operator response contract."""

from __future__ import annotations

import builtins
import dataclasses
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from shellforgeai.core import platform_operator_contract as contract_module
from shellforgeai.core.platform_operator_contract import (
    PlatformOperatorContract,
    build_platform_operator_contract,
    render_unsupported_platform_operator_response,
)
from shellforgeai.interactive import repl
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


class _ConsoleCapture:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        self.lines.append(" ".join(str(arg) for arg in args))

    def clear(self) -> None:
        self.lines.append("<clear>")

    def status(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return SimpleNamespace(__enter__=lambda self: self, __exit__=lambda *args: False)


def _drive_unsupported_repl(monkeypatch, tmp_path: Path, system: str, inputs: list[str]):
    console = _ConsoleCapture()
    calls = {"collect": 0, "diagnose": 0, "dispatch": [], "provider": 0, "model": 0}
    contract = build_platform_operator_contract(_info(system))
    monkeypatch.setattr(repl, "Console", lambda *args, **kwargs: console)
    monkeypatch.setattr(repl, "build_banner", lambda *args, **kwargs: "banner")
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *args, **kwargs: True)
    monkeypatch.setattr(repl, "build_platform_operator_contract", lambda: contract)
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda self, path: True)
    monkeypatch.setattr(
        repl,
        "StreamRenderer",
        lambda *args, **kwargs: SimpleNamespace(
            render=lambda *args, **kwargs: calls.__setitem__("model", calls["model"] + 1)
        ),
    )

    def forbidden_collect():
        calls["collect"] += 1
        raise AssertionError("machine-health collection reached")

    def forbidden_diagnose(*args, **kwargs):  # noqa: ANN002, ANN003
        calls["diagnose"] += 1
        raise AssertionError("diagnosis reached")

    def dispatch(_console, argv):  # noqa: ANN001
        calls["dispatch"].append(tuple(argv))
        return "metadata"

    def forbidden_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        calls["provider"] += 1
        raise AssertionError("provider reached")

    monkeypatch.setattr(repl, "_collect_machine_health", forbidden_collect)
    monkeypatch.setattr(repl, "diagnose_target", forbidden_diagnose)
    monkeypatch.setattr(repl, "_run_interactive_cli_dispatch", dispatch)
    monkeypatch.setattr(repl, "build_provider", forbidden_provider)
    sequence = iter([*inputs, "/exit"])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(sequence))
    runtime = SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_pr329",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr329",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="fake", model="fake", timeout_seconds=1)
        ),
    )
    runtime.session.data_dir.mkdir(parents=True)
    repl.start_interactive(runtime, no_trust_cache=True)
    return "\n".join(console.lines), calls


@pytest.mark.parametrize("system", ["darwin", "unknown"])
@pytest.mark.parametrize(
    "operator_input",
    [
        "/health",
        "diagnose disk",
        "is this machine healthy",
        "triage docker",
        "check firewall",
        "delete logs",
        "what did you check?",
    ],
)
def test_unsupported_interactive_evidence_boundaries_fail_before_runtime(
    monkeypatch, tmp_path: Path, system: str, operator_input: str
) -> None:
    output, calls = _drive_unsupported_repl(monkeypatch, tmp_path, system, [operator_input])
    assert "Unsupported platform" in output
    assert "read_only=true" in output
    assert "mutation_performed=false" in output
    assert "No local evidence was collected and no action was taken." in output
    assert output.count("shellforgeai platform doctor --json") == 1
    assert calls == {"collect": 0, "diagnose": 0, "dispatch": [], "provider": 0, "model": 0}
    assert not runtime_artifacts(tmp_path)


def runtime_artifacts(tmp_path: Path) -> list[Path]:
    artifact_root = tmp_path / "data" / "artifacts"
    return list(artifact_root.rglob("*")) if artifact_root.exists() else []


@pytest.mark.parametrize("system", ["darwin", "unknown"])
def test_unsupported_service_mutation_refuses_before_platform_fallback(
    monkeypatch, tmp_path: Path, system: str
) -> None:
    output, calls = _drive_unsupported_repl(monkeypatch, tmp_path, system, ["restart nginx"])
    assert "No action was taken" in output
    assert "Unsupported platform" not in output
    assert calls == {"collect": 0, "diagnose": 0, "dispatch": [], "provider": 0, "model": 0}


@pytest.mark.parametrize("system", ["darwin", "unknown"])
def test_unsupported_non_evidence_dispatch_remains_available(
    monkeypatch, tmp_path: Path, system: str
) -> None:
    output, calls = _drive_unsupported_repl(monkeypatch, tmp_path, system, ["version"])
    assert "Unsupported platform" not in output
    assert calls["dispatch"] == [("version",)]
    assert calls["collect"] == calls["diagnose"] == calls["provider"] == calls["model"] == 0


def test_dispatch_boundary_uses_exact_routed_argv() -> None:
    unsupported = build_platform_operator_contract(_info("darwin"))
    linux = build_platform_operator_contract(_info("linux"))
    assert repl._unsupported_local_evidence_response_if_needed(
        unsupported, routed_name="cli_dispatch", routed_argv=("triage", "docker")
    )
    assert repl._unsupported_local_evidence_response_if_needed(
        unsupported, routed_name="cli_dispatch", routed_argv=("ops", "report")
    )
    assert (
        repl._unsupported_local_evidence_response_if_needed(
            unsupported, routed_name="cli_dispatch", routed_argv=("version",)
        )
        is None
    )
    assert (
        repl._unsupported_local_evidence_response_if_needed(
            linux, evidence_boundary="pending_followup"
        )
        is None
    )


def test_generic_linux_summary_consumes_contract_presentation() -> None:
    state = repl.InteractiveSessionSummaryState(session_id="linux")
    state.note_check("load, filesystem capacity, inode usage, processes, Docker context")
    rendered = repl.render_interactive_session_summary(
        state, build_platform_operator_contract(_info("linux"))
    )
    assert "Linux/Docker operator summary" in rendered
    assert "Evidence: Linux/Docker local read-only evidence" in rendered
    assert "Visibility: linux-docker-local-read-only" in rendered
    assert "Windows services" not in rendered


def test_generic_windows_summary_consumes_contract_and_bounded_native_context() -> None:
    state = repl.InteractiveSessionSummaryState(session_id="windows")
    state.note_check(
        "Windows host basics; physical and virtual memory; drives and volumes; "
        "Windows processes; Windows services and service state; Event Log unavailable"
    )
    rendered = repl.render_interactive_session_summary(
        state, build_platform_operator_contract(_info("windows"))
    )
    assert "Windows operator summary" in rendered
    assert "Evidence: Windows local read-only evidence" in rendered
    assert "Visibility: windows-local-read-only" in rendered
    for forbidden in (
        "load average",
        "inode",
        "systemd",
        "journalctl",
        "df -i",
        "ps aux",
        "/var/log",
    ):
        assert forbidden not in rendered
