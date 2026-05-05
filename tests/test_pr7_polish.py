from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.banner import QUOTES, build_banner
from shellforgeai.interactive.repl import _is_machine_health_question, _sanitize_provider_error
from shellforgeai.llm.prompts import build_model_prompt
from shellforgeai.llm.system_prompt import SHELLFORGE_SYSTEM_PROMPT
from shellforgeai.version import get_build_info

runner = CliRunner()


def test_banner_quote_deterministic(monkeypatch):
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
    panel = build_banner(rt, True, chooser=lambda q: q[0])
    txt = str(panel.renderable)
    assert "ShellForgeAI" in txt and "CLI-first AI Ops for Linux" in txt
    assert QUOTES[0] in txt


def test_build_info_env(monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_BUILD_PR", "7")
    monkeypatch.setenv("SHELLFORGEAI_BUILD_COMMIT", "abc1234")
    b = get_build_info()
    assert b.github_pr == "7" and b.git_commit == "abc1234"


def test_prompt_has_system_identity():
    p = build_model_prompt("q", {"token": "x"})
    assert "You are ShellForgeAI" in p and "validation-only" in p and "[REDACTED]" in p


def test_machine_health_intent_detection():
    assert _is_machine_health_question("Any issue on this machine?")
    assert _is_machine_health_question("Is my computer having any issue?")
    assert _is_machine_health_question("So is everything okay with my computer?")


def test_bwrap_error_sanitized():
    msg = _sanitize_provider_error("bwrap: No permissions to create a new namespace")
    assert "provider/container sandbox limitation" in msg


def test_system_prompt_disallows_direct_machine_inspection():
    assert "Do not run shell commands" in SHELLFORGE_SYSTEM_PROMPT


def test_unknown_slash_does_not_call_model(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("model provider should not be built")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", boom)
    res = runner.invoke(app, ["interactive", "--no-trust-cache"], input="y\n/unknown\n/exit\n")
    assert res.exit_code == 0 and "Unknown command: /unknown" in res.stdout


def test_model_command_uses_doctor_only(monkeypatch):
    class P:
        def doctor(self):
            return {"provider": "openai-codex", "model": "gpt-5.5"}

        def complete(self, req):
            raise AssertionError("complete should not be called for /model")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", lambda *_: P())
    res = runner.invoke(app, ["interactive", "--no-trust-cache"], input="y\n/model\n/exit\n")
    assert res.exit_code == 0 and "provider=openai-codex" in res.stdout


def test_workspace_and_profile_are_deterministic(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("model should not be called")

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", boom)
    res = runner.invoke(
        app,
        ["interactive", "--no-trust-cache"],
        input="y\n/workspace\n/profile\n/mode\n/audit\n/tools\n/exit\n",
    )
    assert res.exit_code == 0
    assert "Workspace:" in res.stdout and "Profile:" in res.stdout and "Mode:" in res.stdout


def test_health_prompt_never_silent_on_empty_stream(monkeypatch):
    class Provider:
        def stream_complete(self, req):
            yield {"type": "final", "response": type("R", (), {"text": ""})()}

    class FakeRes:
        session_id = "s1"
        target_type = type("T", (), {"value": "host"})()
        findings = []
        evidence = type("E", (), {"items": []})()
        proposed_plan = type("P", (), {"model_dump_json": lambda self, indent=2: "{}"})()

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", lambda *_: Provider())
    monkeypatch.setattr("shellforgeai.interactive.repl.diagnose_target", lambda *a, **k: FakeRes())
    res = runner.invoke(
        app,
        ["interactive", "--no-trust-cache"],
        input="y\nIs my computer having any issue?\n/exit\n",
    )
    assert res.exit_code == 0
    assert "Collected 0 read-only evidence item(s)" in res.stdout
    assert "## Assessment" in res.stdout


def test_health_prompt_fallback_on_heading_only_model_response(monkeypatch):
    class Provider:
        def complete(self, req):
            return type("R", (), {"text": "## Assessment\n"})()

    class FakeRes:
        session_id = "s1"
        target_type = type("T", (), {"value": "host"})()
        findings = []
        evidence = type("E", (), {"items": []})()
        proposed_plan = type("P", (), {"model_dump_json": lambda self, indent=2: "{}"})()

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", lambda *_: Provider())
    monkeypatch.setattr("shellforgeai.interactive.repl.diagnose_target", lambda *a, **k: FakeRes())
    res = runner.invoke(
        app, ["interactive", "--no-trust-cache"], input="y\nIs my computer okay?\n/exit\n"
    )
    assert res.exit_code == 0
    assert "## Assessment" in res.stdout
    assert "No critical issue seen from current read-only context." in res.stdout


def test_health_prompt_fallback_on_collector_request_boilerplate(monkeypatch):
    class Provider:
        def complete(self, req):
            return type("R", (), {"text": "I only have host/mode context so far."})()

    class FakeRes:
        session_id = "s1"
        target_type = type("T", (), {"value": "host"})()
        findings = []
        evidence = type("E", (), {"items": []})()
        proposed_plan = type("P", (), {"model_dump_json": lambda self, indent=2: "{}"})()

    monkeypatch.setattr("shellforgeai.interactive.repl.build_provider", lambda *_: Provider())
    monkeypatch.setattr("shellforgeai.interactive.repl.diagnose_target", lambda *a, **k: FakeRes())
    res = runner.invoke(
        app,
        ["interactive", "--no-trust-cache"],
        input="y\nAnything wrong with my computer?\n/exit\n",
    )
    assert res.exit_code == 0
    assert "No critical issue seen from current read-only context." in res.stdout
