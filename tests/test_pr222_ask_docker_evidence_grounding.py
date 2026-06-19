"""PR222 — model-backed ``ask`` is grounded in deterministic Docker evidence.

Docker/operator questions that reach the model-backed ``ask`` path must:

* explain/route from deterministic ShellForgeAI Docker triage evidence
  (top suspect, severity, confidence, evidence themes, safe next command),
* never emit unsupported or mutation-style command suggestions, and
* fall back to safe deterministic guidance when the model/auth is unavailable.

Broad mutation/auto-fix requests stay refused. These tests use a fake
deterministic triage scene and a fake model backend — no real Docker, no real
model/Codex auth, no network.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core import ask_docker_grounding as grounding
from shellforgeai.core import triage_ranking as triage_mod
from shellforgeai.core.ask_docker_grounding import (
    build_docker_evidence_context,
    build_docker_grounding_envelope,
    is_docker_operator_ask,
    render_docker_grounding_block,
)
from shellforgeai.core.ask_routing import is_autofix_mutation_intent
from shellforgeai.core.command_suggestions import filter_unsupported_command_suggestions

runner = CliRunner()


# --- fixtures -------------------------------------------------------------


def _docker_scene() -> dict:
    """A realistic scene where ``beszel-agent`` is the unambiguous top suspect."""
    return {
        "containers": [
            {
                "name": "beszel-agent",
                "state": "restarting",
                "image": "henrygd/beszel-agent",
                "status": "Restarting (1) 5 seconds ago",
                "exit_code": 1,
                "restart_count": 9,
                "oom_killed": False,
                "health": None,
                "log_text": "\n".join(
                    [
                        "2026-06-19T02:00:01 CRITICAL boot failure: agent exited",
                        "2026-06-19T02:00:02 ERROR connect() to 127.0.0.1:45876 "
                        "failed (111: Connection refused)",
                        "2026-06-19T02:00:03 ERROR connect() to 127.0.0.1:45876 "
                        "failed (111: Connection refused)",
                    ]
                ),
            },
            {
                "name": "sfai-noisy-web",
                "state": "running",
                "image": "nginx",
                "status": "Up 3 minutes",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_text": "\n".join(
                    [
                        "2026-06-19T02:00:01 ERROR worker timeout after 30s",
                        "2026-06-19T02:00:02 ERROR worker timeout after 30s",
                        "2026-06-19T02:00:03 WARN queue depth high",
                    ]
                ),
            },
        ]
    }


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))


@pytest.fixture
def patched_scene(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _docker_scene())


@pytest.fixture
def empty_scene(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: {"containers": []})


class _FakeProvider:
    """Fake model backend; no real Codex/network. Configurable text/ok."""

    def __init__(self, text: str = "Here is what I see.", ok: bool = True):
        self._text = text
        self._ok = ok
        self.last_prompt: str | None = None
        self.completes = 0

    def complete(self, req):
        self.completes += 1
        self.last_prompt = req.prompt
        return SimpleNamespace(
            ok=self._ok,
            text=self._text if self._ok else "",
            provider="openai-codex",
            model="codex-fake",
            usage={
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "output_tokens": 5,
                "reasoning_output_tokens": 0,
            },
            error=None if self._ok else "not found on path: codex",
            raw=None,
        )


@pytest.fixture
def fake_provider(monkeypatch):
    holder = {"provider": _FakeProvider()}
    monkeypatch.setattr(cli_mod, "build_provider", lambda *_a, **_k: holder["provider"])
    return holder


def _set_provider(holder, **kwargs) -> _FakeProvider:
    holder["provider"] = _FakeProvider(**kwargs)
    return holder["provider"]


def _ask(question: str):
    out = runner.invoke(app, ["ask", question])
    return out


def _expected_top() -> dict:
    ranked = triage_mod.rank_scene(_docker_scene())
    return ranked["suspects"][0]


# --- 1-6: grounding includes deterministic evidence -----------------------


def test_1_response_includes_actual_suspect_name(patched_scene, fake_provider):
    out = _ask("why is beszel-agent suspicious?")
    assert out.exit_code == 0, out.stdout
    assert "beszel-agent" in out.stdout


def test_2_response_includes_actual_severity(patched_scene, fake_provider):
    top = _expected_top()
    out = _ask("why is beszel-agent suspicious?")
    assert f"Severity: {top['severity']}" in out.stdout


def test_3_response_includes_actual_confidence(patched_scene, fake_provider):
    top = _expected_top()
    out = _ask("why is beszel-agent suspicious?")
    assert f"Confidence: {top['confidence']}" in out.stdout


def test_4_response_includes_evidence_themes(patched_scene, fake_provider):
    out = _ask("why is beszel-agent suspicious?")
    # Deterministic crashloop/restart-storm theme label.
    assert "restart churn" in out.stdout
    assert "Evidence themes:" in out.stdout


def test_5_response_includes_real_safe_next_command(patched_scene, fake_provider):
    out = _ask("why is beszel-agent suspicious?")
    assert "shellforgeai triage docker detail beszel-agent --json" in out.stdout


def test_6_response_states_using_deterministic_evidence(patched_scene, fake_provider):
    out = _ask("why is beszel-agent suspicious?")
    assert "using current ShellForgeAI Docker triage evidence" in out.stdout


def test_6b_what_is_wrong_with_docker_is_grounded(patched_scene, fake_provider, monkeypatch):
    # Evidence-backed docker route also grounds. Avoid real diagnose collection.
    monkeypatch.setattr(
        cli_mod,
        "diagnose_target",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("docker unavailable")),
    )
    out = _ask("what is wrong with docker?")
    assert out.exit_code == 0, out.stdout
    assert "beszel-agent" in out.stdout
    assert "using current ShellForgeAI Docker triage evidence" in out.stdout


# --- 7: missing evidence -> real gathering command, no guessed suspect ----


def test_7_missing_evidence_gives_gathering_command_not_guess(empty_scene, fake_provider):
    out = _ask("why is beszel-agent suspicious?")
    assert out.exit_code == 0, out.stdout
    assert "I do not have current deterministic Docker triage evidence" in out.stdout
    assert "shellforgeai triage docker --json" in out.stdout
    # No invented suspect/severity/confidence.
    assert "Top suspect:" not in out.stdout
    assert "Severity:" not in out.stdout


# --- 8-13: unsupported command suggestion filtering -----------------------


def test_8_blocks_shellforgeai_diagnose(patched_scene, fake_provider):
    _set_provider(fake_provider, text="You should run shellforgeai diagnose beszel-agent.")
    out = _ask("why is beszel-agent suspicious?")
    assert "shellforgeai diagnose beszel-agent" not in out.stdout
    assert "shellforgeai triage docker detail beszel-agent --json" in out.stdout


def test_9_blocks_shellforgeai_fix_docker(patched_scene, fake_provider):
    _set_provider(fake_provider, text="Try shellforgeai fix docker to repair it.")
    out = _ask("why is beszel-agent suspicious?")
    assert "shellforgeai fix docker" not in out.stdout


def test_10_blocks_shellforgeai_restart_compose(patched_scene, fake_provider):
    _set_provider(fake_provider, text="Next: shellforgeai restart compose now.")
    out = _ask("why is beszel-agent suspicious?")
    assert "shellforgeai restart compose" not in out.stdout


def test_11_blocks_bare_docker_mutation(patched_scene, fake_provider):
    _set_provider(fake_provider, text="Free space with docker prune and docker image rm old-image.")
    out = _ask("why is beszel-agent suspicious?")
    assert "docker prune" not in out.stdout
    assert "docker image rm" not in out.stdout


def test_12_preserves_allowed_readonly_suggestions(patched_scene, fake_provider):
    _set_provider(
        fake_provider,
        text="Check shellforgeai triage docker --json and shellforgeai status --json.",
    )
    out = _ask("why is beszel-agent suspicious?")
    assert "shellforgeai triage docker --json" in out.stdout
    assert "shellforgeai status --json" in out.stdout


def test_13_unknown_shellforgeai_command_not_emitted(patched_scene, fake_provider):
    _set_provider(fake_provider, text="Then run shellforgeai frobnicate docker right away.")
    out = _ask("why is beszel-agent suspicious?")
    assert "frobnicate" not in out.stdout


# --- unit-level filter coverage ------------------------------------------


def test_filter_returns_removed_list_and_safe_replacement():
    cleaned, removed = filter_unsupported_command_suggestions(
        "run shellforgeai diagnose beszel-agent and docker prune",
        safe_next_command="shellforgeai triage docker --json",
    )
    assert "shellforgeai diagnose beszel-agent" not in cleaned
    assert "docker prune" not in cleaned
    assert "shellforgeai triage docker --json" in cleaned
    assert any("diagnose beszel-agent" in r for r in removed)
    assert any("docker prune" in r for r in removed)


def test_filter_preserves_read_only_docker_inspect():
    cleaned, removed = filter_unsupported_command_suggestions(
        "look with docker ps and docker logs beszel-agent",
        safe_next_command="shellforgeai triage docker --json",
    )
    assert "docker ps" in cleaned
    assert "docker logs beszel-agent" in cleaned
    assert removed == []


# --- 14-18: mutation refusal ----------------------------------------------


def _fail_provider(*_a, **_k):
    raise AssertionError("model/Codex path must not be called for refused mutation asks")


def test_14_cleanup_and_restart_compose_refused(monkeypatch):
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)
    out = _ask("Clean up docker and restart compose to fix it")
    assert out.exit_code == 0
    lowered = out.stdout.lower()
    assert "refus" in lowered
    assert "docker compose restart" not in lowered


def test_15_prune_docker_images_refused(monkeypatch):
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)
    out = _ask("Prune Docker images")
    assert out.exit_code == 0
    assert "Refused: natural-language mutation is not allowed." in out.stdout


def test_16_fix_automatically_refused(monkeypatch):
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)
    out = _ask("Fix beszel-agent automatically")
    assert out.exit_code == 0
    assert "Refused: natural-language mutation is not allowed." in out.stdout


def test_17_refusal_includes_read_only_safe_command(monkeypatch):
    monkeypatch.setattr(cli_mod, "build_provider", _fail_provider)
    out = _ask("Prune Docker images")
    lowered = out.stdout.lower()
    assert "shellforgeai ops report" in lowered or "shellforgeai triage docker" in lowered


def test_18_grounding_safety_flags_indicate_no_mutation():
    ctx = build_docker_evidence_context()
    envelope = build_docker_grounding_envelope(ctx)
    assert envelope["read_only"] is True
    assert envelope["mutation_performed"] is False
    assert all(v is False for v in envelope["safety"].values())


def test_18b_autofix_intent_detection():
    assert is_autofix_mutation_intent("Fix beszel-agent automatically")
    assert is_autofix_mutation_intent("auto-fix the crashloop")
    assert not is_autofix_mutation_intent("what is wrong with docker?")
    assert not is_autofix_mutation_intent("how do I fix this safely?")


# --- 19-20: auth/model behavior -------------------------------------------


def test_19_grounding_works_with_fake_backend(patched_scene, fake_provider):
    # The whole grounding suite uses a fake backend; this asserts the model is
    # actually invoked (model-backed) yet the deterministic answer is present.
    out = _ask("why is beszel-agent suspicious?")
    assert fake_provider["provider"].completes == 1
    assert "beszel-agent" in out.stdout


def test_20_model_failure_falls_back_to_deterministic_guidance(patched_scene, fake_provider):
    _set_provider(fake_provider, ok=False)
    out = _ask("why is beszel-agent suspicious?")
    assert out.exit_code == 0, out.stdout
    # Deterministic grounded evidence still answers.
    assert "using current ShellForgeAI Docker triage evidence" in out.stdout
    assert "shellforgeai triage docker detail beszel-agent --json" in out.stdout
    # Clean auth-diagnostic path, not an unsupported command or invented fix.
    assert "shellforgeai model doctor --json" in out.stdout
    assert "shellforgeai diagnose" not in out.stdout


def test_20b_model_failure_empty_scene_safe(empty_scene, fake_provider):
    _set_provider(fake_provider, ok=False)
    out = _ask("why is beszel-agent suspicious?")
    assert out.exit_code == 0
    assert "shellforgeai triage docker --json" in out.stdout
    assert "shellforgeai diagnose" not in out.stdout


# --- 21-24: safety --------------------------------------------------------


def test_21_grounding_does_not_run_docker_mutation(patched_scene, fake_provider, tmp_path):
    out = _ask("why is beszel-agent suspicious?")
    assert out.exit_code == 0
    events = (tmp_path / "audit" / "events.jsonl").read_text(encoding="utf-8")
    rows = [json.loads(line) for line in events.splitlines() if line.strip()]
    grounded = [r for r in rows if r.get("action") == "docker_evidence_grounded"]
    assert grounded, rows
    details = grounded[-1].get("details") or {}
    for flag in (
        "docker_prune_executed",
        "docker_image_removed",
        "docker_compose_executed",
        "container_restarted",
        "mutation_performed",
    ):
        assert details.get(flag) is False, flag


def test_22_grounding_does_not_run_cleanup_remediation_rollback_recovery(
    patched_scene, fake_provider, tmp_path
):
    _ask("why is beszel-agent suspicious?")
    events = (tmp_path / "audit" / "events.jsonl").read_text(encoding="utf-8")
    rows = [json.loads(line) for line in events.splitlines() if line.strip()]
    details = [r for r in rows if r.get("action") == "docker_evidence_grounded"][-1]["details"]
    for flag in (
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "natural_language_execution",
        "shell_true",
        "file_deleted",
    ):
        assert details.get(flag) is False, flag


def test_23_grounding_sources_have_no_shell_true():
    for mod in (grounding,):
        assert "shell=True" not in inspect.getsource(mod)
    assert "shell=True" not in inspect.getsource(cli_mod._emit_docker_grounding_answer)
    assert "shell=True" not in inspect.getsource(filter_unsupported_command_suggestions)


def test_24_no_mutation_cli_options_introduced():
    out = runner.invoke(app, ["ask", "--help"])
    assert out.exit_code == 0
    lowered = out.stdout.lower()
    for flag in (
        "--execute",
        "--apply",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
        "--post-comment",
        "--approve",
        "--merge",
    ):
        assert flag not in lowered, flag


def test_24b_grounding_module_source_defines_no_typer_options():
    src = inspect.getsource(grounding)
    assert "typer" not in src
    assert "--execute" not in src and "--apply" not in src


# --- 25: model doctor regression (unaffected by grounding) ----------------


class _DoctorProvider:
    def doctor(self):
        return {
            "provider": "openai-codex",
            "model": "gpt-5.5",
            "fallback_model": "gpt-5.4",
            "codex_found": True,
            "auth_cache_present": False,
            "auth_readiness": "unknown",
            "auth_reason": "status_unknown",
            "sandbox": "read-only",
            "approval": "never",
        }

    def complete(self, _req):  # pragma: no cover - must not be called
        raise AssertionError("model doctor must not call completion")


def test_25_model_doctor_json_still_works(monkeypatch):
    monkeypatch.setattr(cli_mod, "build_provider", lambda _s: _DoctorProvider())
    out = runner.invoke(app, ["model", "doctor", "--json"])
    assert out.exit_code == 0, out.stdout
    payload = json.loads(out.stdout)
    assert payload["mode"] == "model_doctor"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


# --- detection / rendering unit coverage ----------------------------------


def test_is_docker_operator_ask_positive_and_negative():
    assert is_docker_operator_ask("why is beszel-agent suspicious?")
    assert is_docker_operator_ask("what is wrong with docker?")
    assert is_docker_operator_ask("find failed containers and explain likely cause")
    assert not is_docker_operator_ask("what is the difference between TCP and UDP?")
    assert not is_docker_operator_ask("explain DNS like I am new")
    # Mutation / auto-fix asks are not "groundable read-only" questions.
    assert not is_docker_operator_ask("restart the top suspect")
    assert not is_docker_operator_ask("Fix beszel-agent automatically")


def test_grounded_context_fields(patched_scene):
    ctx = build_docker_evidence_context()
    assert ctx["grounded"] is True
    assert ctx["top_suspect"] == "beszel-agent"
    assert ctx["mutation_allowed"] is False
    assert ctx["safe_next_command"] == "shellforgeai triage docker detail beszel-agent --json"
    block = render_docker_grounding_block(ctx)
    assert "Top suspect: beszel-agent" in block
    assert "No cleanup, restart, remediation, rollback, or Docker mutation was performed." in block


def test_ungrounded_context_fields(empty_scene):
    ctx = build_docker_evidence_context()
    assert ctx["grounded"] is False
    assert ctx["top_suspect"] is None
    assert ctx["safe_next_command"] == "shellforgeai triage docker --json"
    block = render_docker_grounding_block(ctx)
    assert "I do not have current deterministic Docker triage evidence" in block
