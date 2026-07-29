"""PR324: the interactive startup banner identifies the local host platform.

Scope is banner identity/presentation only. These tests inject the platform
identity so they are deterministic on Linux and on native Windows, and they
guard that PR324 did not touch routing, collectors, model calls, mutation
refusal, or the command surface.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive import banner as banner_module
from shellforgeai.interactive.banner import (
    GENERIC_PLATFORM_LABEL,
    NEUTRAL_QUOTES,
    QUOTES,
    build_banner,
    platform_label,
    quotes_for_platform,
)

runner = CliRunner()

BANNER_SOURCE = Path("src/shellforgeai/interactive/banner.py")

LINUX_ONLY_TERMS = ("journalctl", "systemctl", "sudo", "grep", "container", "inode")

REQUIRED_BANNER_FIELDS = (
    "ShellForgeAI",
    "Version:",
    "Mode/Profile:",
    "Model:",
    "Workspace:",
    "Trust status:",
    "Quote:",
)

# The exact top-level CLI command surface as of PR324. PR324 adds no command.
EXPECTED_COMMAND_SURFACE = {
    "actions",
    "apply",
    "apply-preview",
    "approvals",
    "ask",
    "audit",
    "compose",
    "diagnose",
    "doctor",
    "export",
    "guard",
    "handoff",
    "inspect",
    "interactive",
    "logs",
    "mission",
    "model",
    "ops",
    "plan",
    "platform",
    "propose",
    "recipes",
    "remediation",
    "research",
    "rollback",
    "rollback-preview",
    "runbook",
    "safe-actions",
    "self-test",
    "session",
    "status",
    "tools",
    "triage",
    "v1",
    "validate-export",
    "validate-runbook",
    "verify",
    "version",
    "windows",
}


def _runtime():
    class X: ...

    rt = X()
    rt.session = X()
    rt.profile = X()
    rt.settings = X()
    rt.settings.model = X()
    rt.session.mode = "inspect"
    rt.profile.name = "inspect"
    rt.settings.model.provider = "codex"
    rt.settings.model.model = "gpt-5.5"
    return rt


def _banner_text(host_system: str | None, *, trusted: bool = True) -> str:
    panel = build_banner(
        _runtime(), trusted, chooser=lambda values: values[0], host_system=host_system
    )
    return str(panel.renderable)


# 1-4: exact platform labels and the safe fallback.


def test_linux_banner_label_is_exact() -> None:
    assert "CLI-first AI Ops for Linux" in _banner_text("Linux")


def test_windows_banner_label_is_exact() -> None:
    text = _banner_text("Windows")
    assert "CLI-first AI Ops for Windows" in text
    assert "CLI-first AI Ops for Linux" not in text


def test_macos_banner_label_is_exact() -> None:
    text = _banner_text("Darwin")
    assert "CLI-first AI Ops for macOS" in text
    assert "CLI-first AI Ops for Linux" not in text


@pytest.mark.parametrize("value", ["", "   ", "Java", "SunOS", "FreeBSD", "unknown-os"])
def test_unknown_platform_falls_back_safely(value: str) -> None:
    text = _banner_text(value)
    assert f"CLI-first AI Ops for {GENERIC_PLATFORM_LABEL}" in text
    assert "CLI-first AI Ops for this host" in text
    assert "CLI-first AI Ops for Linux" not in text
    assert "CLI-first AI Ops for Windows" not in text
    assert "CLI-first AI Ops for macOS" not in text


# 5: case/whitespace normalization of injected platform names.


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Linux", "Linux"),
        ("linux", "Linux"),
        ("LINUX", "Linux"),
        ("  Linux  ", "Linux"),
        ("Windows", "Windows"),
        ("windows", "Windows"),
        ("WINDOWS", "Windows"),
        ("\tWindows\n", "Windows"),
        ("Darwin", "macOS"),
        ("darwin", "macOS"),
        (" DARWIN ", "macOS"),
    ],
)
def test_injected_platform_names_normalize(value: str, expected: str) -> None:
    assert platform_label(value) == expected
    assert f"CLI-first AI Ops for {expected}" in _banner_text(value)


def test_platform_label_default_uses_local_platform_system(monkeypatch) -> None:
    monkeypatch.setattr(banner_module.platform, "system", lambda: "Windows")
    assert platform_label() == "Windows"
    assert "CLI-first AI Ops for Windows" in _banner_text(None)


# 6-7: quote pools.


@pytest.mark.parametrize("value", ["Windows", "Darwin", "", "SunOS"])
def test_non_linux_quote_pool_is_neutral(value: str) -> None:
    assert quotes_for_platform(value) is NEUTRAL_QUOTES


def test_linux_quote_pool_is_unchanged() -> None:
    assert quotes_for_platform("Linux") is QUOTES
    assert QUOTES == [
        "CLI just do it.",
        "Read-only today, root cause tomorrow.",
        "In logs we trust.",
        "No YAML was harmed in the making of this diagnosis.",
        "sudo? Not without a plan.",
        "Grep first, panic later.",
        "Your shell has entered the chat.",
        "Trust, but verify with journalctl.",
        "Works on my container.",
        "The prompt is mightier than the outage.",
    ]


def test_neutral_quotes_are_a_subset_of_quotes_in_order() -> None:
    assert NEUTRAL_QUOTES
    assert set(NEUTRAL_QUOTES).issubset(set(QUOTES))
    neutral = set(NEUTRAL_QUOTES)
    assert [q for q in QUOTES if q in neutral] == NEUTRAL_QUOTES


def test_every_neutral_quote_excludes_linux_only_terms() -> None:
    for quote in NEUTRAL_QUOTES:
        low = quote.lower()
        for term in LINUX_ONLY_TERMS:
            assert term not in low, f"neutral quote {quote!r} contains {term!r}"


@pytest.mark.parametrize("value", ["Windows", "Darwin", "", "SunOS"])
def test_no_neutral_quote_can_render_linux_terms_in_the_banner(value: str) -> None:
    """Exhaustive: every selectable quote for a non-Linux host stays safe."""
    for index in range(len(NEUTRAL_QUOTES)):
        panel = build_banner(
            _runtime(), True, chooser=lambda values, i=index: values[i], host_system=value
        )
        text = str(panel.renderable).lower()
        for term in LINUX_ONLY_TERMS:
            assert term not in text, f"{value!r} banner leaked {term!r}"
        assert "cli-first ai ops for linux" not in text


def test_windows_banner_chooser_receives_only_the_neutral_pool() -> None:
    seen: list[list[str]] = []

    def recording_chooser(values):
        seen.append(values)
        return values[0]

    build_banner(_runtime(), True, chooser=recording_chooser, host_system="Windows")
    assert seen == [NEUTRAL_QUOTES]


# 8: deterministic chooser behavior.


def test_deterministic_chooser_selects_first_quote() -> None:
    assert f"Quote: {QUOTES[0]}" in _banner_text("Linux")
    assert f"Quote: {NEUTRAL_QUOTES[0]}" in _banner_text("Windows")
    assert f"Quote: {NEUTRAL_QUOTES[0]}" in _banner_text("Darwin")
    assert f"Quote: {NEUTRAL_QUOTES[0]}" in _banner_text("")


def test_default_chooser_is_random_choice() -> None:
    default = inspect.signature(build_banner).parameters["chooser"].default
    assert default is banner_module.random.choice


def test_host_system_is_keyword_only_with_none_default() -> None:
    param = inspect.signature(build_banner).parameters["host_system"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
    assert param.default is None


# 9-11: existing banner fields, trust states, build line.


@pytest.mark.parametrize("value", ["Linux", "Windows", "Darwin", "", "SunOS"])
def test_existing_banner_fields_are_preserved(value: str) -> None:
    text = _banner_text(value)
    for field in REQUIRED_BANNER_FIELDS:
        assert field in text, f"{value!r} banner lost {field!r}"
    assert "Mode/Profile: inspect/inspect" in text
    assert "Model: codex/gpt-5.5" in text
    assert f"Workspace: {Path.cwd()}" in text


@pytest.mark.parametrize("value", ["Linux", "Windows", "Darwin", ""])
def test_trusted_and_untrusted_states(value: str) -> None:
    assert "Trust status: trusted" in _banner_text(value, trusted=True)
    assert "Trust status: untrusted" in _banner_text(value, trusted=False)


@pytest.mark.parametrize("value", ["Linux", "Windows", "Darwin", ""])
def test_build_information_line_is_preserved(value: str, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_BUILD_PR", "324")
    monkeypatch.setenv("SHELLFORGEAI_BUILD_COMMIT", "abc1234")
    text = _banner_text(value)
    assert "324" in text and "abc1234" in text
    assert "Version:" in text


# 12-13: interactive startup integration.


def test_default_no_argument_startup_is_platform_aware() -> None:
    result = runner.invoke(app, input="n\n")
    assert result.exit_code == 0
    assert f"CLI-first AI Ops for {platform_label()}" in result.stdout
    for field in ("ShellForgeAI", "Version:", "Mode/Profile:", "Model:", "Workspace:"):
        assert field in result.stdout


def test_interactive_alias_startup_is_platform_aware() -> None:
    result = runner.invoke(app, ["interactive"], input="n\n")
    assert result.exit_code == 0
    assert f"CLI-first AI Ops for {platform_label()}" in result.stdout
    assert "ShellForgeAI" in result.stdout


# 14: command surface unchanged.


def test_command_surface_is_unchanged() -> None:
    command = typer.main.get_command(app)
    assert set(command.commands) == EXPECTED_COMMAND_SURFACE


# 15: banner.py imports nothing that could execute, collect, or mutate.


def _imported_roots() -> set[str]:
    tree = ast.parse(BANNER_SOURCE.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module)
    return roots


def test_banner_imports_are_a_known_safe_set() -> None:
    assert _imported_roots() == {
        "__future__",
        "platform",
        "random",
        "pathlib",
        "rich.panel",
        "shellforgeai.version",
    }


def test_banner_does_not_import_execution_or_mutation_modules() -> None:
    forbidden = (
        "subprocess",
        "shutil",
        "shlex",
        "os",
        "socket",
        "http",
        "httpx",
        "requests",
        "urllib",
        "asyncio",
        "collectors",
        "llm",
        "providers",
        "recipes",
        "remediation",
        "rollback",
        "cleanup",
        "docker",
        "compose",
        "windows_",
        "credential",
        "secret",
        "auth",
        "keyring",
    )
    roots = _imported_roots()
    for root in roots:
        low = root.lower()
        for term in forbidden:
            assert term not in low, f"banner.py imports {root!r} (matched {term!r})"


def test_banner_source_has_no_execution_or_network_calls() -> None:
    source = BANNER_SOURCE.read_text(encoding="utf-8")
    for term in (
        "subprocess",
        "os.system",
        "popen",
        "eval(",
        "exec(",
        "open(",
        "write_text",
        "socket",
        "requests",
        "httpx",
        "powershell",
        "winrm",
    ):
        assert term not in source.lower(), f"banner.py contains {term!r}"
