"""PR82 — Broad ask routes use deterministic Docker triage ranking.

Verifies that natural-language broad-Docker / 2AM triage asks route to
the deterministic PR81 triage engine (``triage_ranking.collect_scene`` +
``rank_scene``) rather than drifting into model-only rephrase. Mutation
asks tied to the ranking ("restart the top suspect", "fix the
crashloop", "clean up disk pressure now", "stop noisy-errors", "apply
the top fix") must still refuse with the PR82 no-mutation wording.

These tests use the PR81 battle-lab fixture (no live Docker, no
daemon, no subprocess) and patch ``triage_ranking.collect_scene`` so
they run offline.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core import triage_ranking as triage_mod
from shellforgeai.core.ask_routing import (
    is_broad_docker_triage_intent,
    is_triage_mutation_intent,
)

runner = CliRunner()


# --- fixture: realistic battle-lab scene (mirrors PR81 fixture) -----------


def _battle_lab_scene() -> dict:
    crashloop_log = "\n".join(
        f"2024-05-20T14:50:0{i} CRITICAL boot failure: payment-init exited with 42"
        for i in range(6)
    )
    noisy_log = "\n".join(
        [
            "2024-05-20T14:50:01 ERROR payment-worker timeout after 30s",
            "2024-05-20T14:50:02 WARN queue depth high (1024)",
            "2024-05-20T14:50:03 ERROR payment-worker timeout after 30s",
            "2024-05-20T14:50:04 WARN queue depth high (1100)",
            "2024-05-20T14:50:05 ERROR payment-worker timeout after 30s",
            "2024-05-20T14:50:06 WARN queue depth high (1200)",
            "2024-05-20T14:50:07 Exception: PaymentTimeoutError",
        ]
    )
    bad_http_log = "\n".join(
        [
            "2024/05/20 14:50:01 [error] 1#1: *5 connect() to 127.0.0.1:9999 "
            "failed (111: Connection refused) while connecting to upstream",
            "2024/05/20 14:50:02 [error] 1#1: *6 connect() to 127.0.0.1:9999 "
            "failed (111: Connection refused) while connecting to upstream",
            "2024/05/20 14:50:03 192.168.0.1 - - [20/May/2024:14:50:03 +0000] "
            '"GET / HTTP/1.1" 502 150',
            "2024/05/20 14:50:04 192.168.0.1 - - [20/May/2024:14:50:04 +0000] "
            '"GET /api HTTP/1.1" 502 150',
            "2024/05/20 14:50:05 [crit] 1#1: open() failed "
            "(13: Permission denied) — single stray entry",
        ]
    )
    disk_log = "\n".join(
        [
            "2024-05-20T14:50:01 ERROR write failed: simulated disk pressure, filler=96.0M",
            "2024-05-20T14:50:02 ERROR write failed: simulated disk pressure, filler=97.0M",
            "2024-05-20T14:50:03 ERROR write failed: simulated disk pressure, filler=98.0M",
        ]
    )
    perm_log = "\n".join(
        [
            "2024-05-20T14:50:01 ERROR permission denied reading /blocked/secret.txt",
            "2024-05-20T14:50:02 ERROR permission denied reading /blocked/secret.txt",
            "2024-05-20T14:50:03 ERROR permission denied reading /blocked/secret.txt",
            "2024-05-20T14:50:04 ERROR EACCES on /blocked",
        ]
    )
    return {
        "containers": [
            {
                "name": "sfai-crashloop",
                "state": "restarting",
                "exit_code": 42,
                "restart_count": 173,
                "oom_killed": False,
                "health": None,
                "log_text": crashloop_log,
            },
            {
                "name": "sfai-noisy-errors",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_text": noisy_log,
            },
            {
                "name": "sfai-bad-http",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "unhealthy",
                "log_text": bad_http_log,
            },
            {
                "name": "sfai-disk-pressure",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_text": disk_log,
            },
            {
                "name": "sfai-permission-denied",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_text": perm_log,
            },
        ]
    }


@pytest.fixture(autouse=True)
def _isolate_runtime(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))


@pytest.fixture
def patched_scene(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())


# ---------- pure routing -------------------------------------------------


def test_broad_intent_whats_on_fire():
    assert is_broad_docker_triage_intent("what's on fire?")


def test_broad_intent_2am_triage():
    assert is_broad_docker_triage_intent("2AM triage")


def test_broad_intent_docker_box_feels_broken():
    assert is_broad_docker_triage_intent("the Docker box feels broken")


def test_broad_intent_rank_docker_suspects():
    assert is_broad_docker_triage_intent("rank Docker suspects")


def test_broad_intent_broadly_scan_scene():
    assert is_broad_docker_triage_intent("broadly scan the current scene")


def test_broad_intent_rank_battle_lab_suspects():
    assert is_broad_docker_triage_intent("rank all sfai-battle-lab suspects by severity")


def test_broad_intent_inspect_first():
    assert is_broad_docker_triage_intent("what should I inspect first?")


def test_broad_intent_show_current_suspects():
    assert is_broad_docker_triage_intent("show current Docker suspects")


def test_broad_intent_containers_look_suspicious():
    assert is_broad_docker_triage_intent("what containers look suspicious?")


def test_broad_intent_2am_brief_paragraph():
    # The actual prompt from the PR82 brief.
    q = (
        "It is 2AM and the Docker box feels broken. Broadly scan the current "
        "scene and rank all sfai-battle-lab suspects by severity. Do not mutate "
        "anything. Keep it short."
    )
    assert is_broad_docker_triage_intent(q)


def test_broad_intent_does_not_match_generic_question():
    assert not is_broad_docker_triage_intent("what is the difference between TCP and UDP?")


def test_broad_intent_does_not_match_mutation_phrases():
    for q in (
        "restart the top suspect",
        "fix the crashloop",
        "clean up disk pressure now",
        "stop noisy-errors",
        "apply the top fix",
        "docker compose restart the top one",
    ):
        assert not is_broad_docker_triage_intent(q), q


def test_triage_mutation_intent_phrases():
    for q in (
        "restart the top suspect",
        "fix the crashloop",
        "clean up disk pressure now",
        "stop noisy-errors",
        "apply the top fix",
        "create a restart proposal for the top suspect",
        "docker compose restart the top one",
        "delete old files causing disk pressure",
    ):
        assert is_triage_mutation_intent(q), q


def test_triage_mutation_intent_does_not_match_read_only_phrases():
    for q in (
        "what's on fire?",
        "2AM triage",
        "rank Docker suspects",
        "show current Docker suspects",
    ):
        assert not is_triage_mutation_intent(q), q


# ---------- broad ask: deterministic triage rendered -----------------------


def _invoke_ask(question: str):
    out = runner.invoke(app, ["ask", question])
    assert out.exit_code == 0, out.stdout
    return out


def test_ask_whats_on_fire_routes_to_deterministic_triage(patched_scene):
    out = _invoke_ask("what's on fire?")
    assert "Read-only Docker triage ranking" in out.stdout
    assert "sfai-crashloop" in out.stdout


def test_ask_2am_triage_routes_to_deterministic_triage(patched_scene):
    out = _invoke_ask("2AM triage")
    assert "Read-only Docker triage ranking" in out.stdout


def test_ask_docker_box_feels_broken_routes(patched_scene):
    out = _invoke_ask("the Docker box feels broken")
    assert "Read-only Docker triage ranking" in out.stdout


def test_ask_rank_docker_suspects_routes(patched_scene):
    out = _invoke_ask("rank Docker suspects")
    assert "Read-only Docker triage ranking" in out.stdout


def test_ask_rank_battle_lab_includes_all_fixture_suspects(patched_scene):
    out = _invoke_ask("rank all sfai-battle-lab suspects by severity")
    for name in (
        "sfai-crashloop",
        "sfai-bad-http",
        "sfai-disk-pressure",
        "sfai-noisy-errors",
        "sfai-permission-denied",
    ):
        assert name in out.stdout, name


def test_broad_ask_includes_crashloop(patched_scene):
    out = _invoke_ask("what's on fire?")
    assert "sfai-crashloop" in out.stdout


def test_broad_ask_includes_bad_http(patched_scene):
    out = _invoke_ask("what's on fire?")
    assert "sfai-bad-http" in out.stdout


def test_broad_ask_includes_disk_pressure(patched_scene):
    out = _invoke_ask("what's on fire?")
    assert "sfai-disk-pressure" in out.stdout


def test_broad_ask_includes_noisy_errors(patched_scene):
    out = _invoke_ask("what's on fire?")
    assert "sfai-noisy-errors" in out.stdout


def test_broad_ask_includes_permission_denied(patched_scene):
    out = _invoke_ask("what's on fire?")
    assert "sfai-permission-denied" in out.stdout


def test_broad_ask_preserves_crashloop_as_top(patched_scene):
    out = _invoke_ask("what's on fire?")
    # crashloop should appear before all other suspects in the output.
    crashloop_pos = out.stdout.index("sfai-crashloop")
    for name in (
        "sfai-bad-http",
        "sfai-disk-pressure",
        "sfai-noisy-errors",
        "sfai-permission-denied",
    ):
        assert crashloop_pos < out.stdout.index(name), name


def test_broad_ask_marks_crashloop_critical_or_high(patched_scene):
    out = _invoke_ask("what's on fire?")
    # crashloop should be tagged critical (or at minimum high) in the answer.
    cl_line_idx = out.stdout.index("sfai-crashloop")
    snippet = out.stdout[cl_line_idx : cl_line_idx + 200]
    assert ("critical" in snippet) or ("high" in snippet)


def test_broad_ask_includes_safety_statement(patched_scene):
    out = _invoke_ask("what's on fire?")
    assert "read_only: true" in out.stdout
    assert "mutation_performed: false" in out.stdout
    assert "no restart/stop/delete/prune/apply/cleanup was executed" in out.stdout


def test_broad_ask_includes_read_only_next_commands(patched_scene):
    out = _invoke_ask("what's on fire?")
    assert "Safe next:" in out.stdout
    # Each suspect should get a read-only diagnose-shaped follow-up command.
    assert "shellforgeai diagnose " in out.stdout
    # Footer with next safe steps must include the deterministic triage cmd.
    assert "Next safe steps:" in out.stdout
    assert "shellforgeai triage docker --json" in out.stdout


def test_broad_ask_does_not_include_execution_commands(patched_scene):
    out = _invoke_ask("what's on fire?")
    lowered = out.stdout.lower()
    for forbidden in (
        "docker restart",
        "docker compose restart",
        "audit cleanup execute",
        "mission execute --execute --confirm",
        "apply --execute",
        "apply --latest-approved",
        "shell=true",
    ):
        assert forbidden not in lowered, forbidden


# ---------- deterministic grounding rules --------------------------------


def test_broad_ask_preserves_triage_ordering(patched_scene):
    out = _invoke_ask("what's on fire?")
    # Read deterministic ranking via the engine, then assert ask output keeps it.
    payload = triage_mod.rank_scene(_battle_lab_scene())
    expected_order = [s["name"] for s in payload["suspects"]]
    seen_positions: list[int] = []
    for name in expected_order:
        seen_positions.append(out.stdout.index(name))
    assert seen_positions == sorted(seen_positions), seen_positions


def test_broad_ask_preserves_severity_labels(patched_scene):
    payload = triage_mod.rank_scene(_battle_lab_scene())
    out = _invoke_ask("what's on fire?")
    for s in payload["suspects"]:
        name = s["name"]
        idx = out.stdout.index(name)
        # The ranking header line (e.g. "1. sfai-crashloop — critical / high
        # confidence") must contain the deterministic severity.
        snippet = out.stdout[idx : idx + 200]
        assert s["severity"] in snippet, (name, s["severity"])
        assert s["confidence"] in snippet, (name, s["confidence"])


def test_broad_ask_does_not_invent_suspects(patched_scene):
    payload = triage_mod.rank_scene(_battle_lab_scene())
    known_names = {s["name"] for s in payload["suspects"]} | {
        w["name"] for w in (payload.get("watch") or [])
    }
    out = _invoke_ask("what's on fire?")
    for line in out.stdout.splitlines():
        # Only consider lines that start with a rank number + name (the
        # rendered "1. sfai-foo" / "2. sfai-bar" header lines).
        stripped = line.strip()
        if not stripped or not stripped[0].isdigit():
            continue
        parts = stripped.split(" ", 2)
        if len(parts) < 2:
            continue
        candidate = parts[1].strip(".")
        if candidate.startswith("sfai-"):
            assert candidate in known_names, candidate


def test_broad_ask_does_not_omit_fixture_suspects(patched_scene):
    out = _invoke_ask("what's on fire?")
    payload = triage_mod.rank_scene(_battle_lab_scene())
    for s in payload["suspects"]:
        assert s["name"] in out.stdout, s["name"]


def test_broad_ask_does_not_attach_disk_pressure_to_bad_http(patched_scene):
    """Per-container evidence isolation must survive the ask renderer."""
    out = _invoke_ask("what's on fire?")
    bad_http_idx = out.stdout.index("sfai-bad-http")
    # Find the next suspect header to scope the bad-http section.
    next_idx = bad_http_idx + len("sfai-bad-http")
    for name in (
        "sfai-disk-pressure",
        "sfai-noisy-errors",
        "sfai-permission-denied",
        "sfai-crashloop",
    ):
        pos = out.stdout.find(name, next_idx)
        if pos != -1:
            next_idx = (
                min(next_idx, pos)
                if next_idx == bad_http_idx + len("sfai-bad-http")
                else min(next_idx, pos)
            )
    bad_http_section = out.stdout[bad_http_idx:next_idx]
    lowered = bad_http_section.lower()
    assert "disk pressure" not in lowered
    assert "disk_pressure" not in lowered


def test_broad_ask_does_not_attach_permission_denied_to_bad_http(patched_scene):
    out = _invoke_ask("what's on fire?")
    bad_http_idx = out.stdout.index("sfai-bad-http")
    next_idx = len(out.stdout)
    for name in (
        "sfai-disk-pressure",
        "sfai-noisy-errors",
        "sfai-permission-denied",
        "sfai-crashloop",
    ):
        pos = out.stdout.find(name, bad_http_idx + len("sfai-bad-http"))
        if pos != -1:
            next_idx = min(next_idx, pos)
    bad_http_section = out.stdout[bad_http_idx:next_idx]
    lowered = bad_http_section.lower()
    assert "permission denied" not in lowered
    assert "permission_denied" not in lowered


def test_broad_ask_handles_empty_scene(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: {"containers": []})
    out = _invoke_ask("what's on fire?")
    assert "No suspects ranked from current scene." in out.stdout
    # Safety statement still present.
    assert "read_only: true" in out.stdout
    assert "mutation_performed: false" in out.stdout


def test_broad_ask_handles_collection_failure(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("docker daemon unavailable")

    monkeypatch.setattr(triage_mod, "collect_scene", boom)
    out = _invoke_ask("what's on fire?")
    assert "Read-only triage failed" in out.stdout
    assert "shellforgeai triage docker --json" in out.stdout


# ---------- mutation refusal -------------------------------------------


@pytest.mark.parametrize(
    "question",
    [
        "restart the top suspect",
        "fix the crashloop",
        "clean up disk pressure now",
        "stop noisy-errors",
        "apply the top fix",
    ],
)
def test_broad_ask_mutation_refused(question, patched_scene):
    out = _invoke_ask(question)
    assert "I can rank suspects read-only" in out.stdout
    assert "will not execute fixes from ask" in out.stdout


def test_broad_ask_mutation_refusal_states_no_mutation(patched_scene):
    out = _invoke_ask("restart the top suspect")
    assert "No restart, cleanup, apply, or proposal was executed." in out.stdout


def test_broad_ask_mutation_refusal_does_not_render_triage(patched_scene):
    out = _invoke_ask("fix the crashloop")
    # Refusal must NOT silently render the deterministic ranking; it should
    # only point the operator back to the explicit CLI commands.
    assert "Read-only Docker triage ranking" not in out.stdout


def test_broad_ask_mutation_refusal_directs_to_explicit_cli(patched_scene):
    out = _invoke_ask("restart the top suspect")
    assert "shellforgeai triage docker" in out.stdout
    assert "shellforgeai diagnose docker --container <name> --json" in out.stdout


def test_broad_ask_mutation_refusal_does_not_create_proposals(patched_scene, tmp_path):
    _invoke_ask("apply the top fix")
    # Proposal/mission directories under the data_dir must remain empty (no
    # autopilot proposal/mission creation from ask).
    for sub in ("approvals", "missions"):
        d = tmp_path / sub
        if d.exists():
            for path in d.rglob("*.json"):
                # Nothing in this tmp_path should have been created during ask.
                raise AssertionError(f"unexpected artifact created: {path}")


# ---------- safety regressions ----------------------------------------


def test_handler_source_has_no_shell_true():
    src = inspect.getsource(cli_mod._handle_broad_triage_ask)
    assert "shell=True" not in src


def test_handler_source_does_not_call_mutation_helpers():
    src = inspect.getsource(cli_mod._handle_broad_triage_ask)
    # Look for actual mutation/execution helpers being CALLED (paren forms),
    # not safety-flag keys that happen to embed the substring "executed".
    for forbidden in (
        "apply_bundle.",
        "mission_record_execution_result(",
        "mission_apply_delegation_command(",
        "prepare_mission(",
        "create_pending(",
        "cleanup_execute(",
        "lab_restart_mod.execute",
        "subprocess.run(",
        "subprocess.Popen(",
        "os.system(",
        "shell=True",
    ):
        assert forbidden not in src, forbidden


def test_renderer_source_has_no_shell_true():
    src = inspect.getsource(cli_mod._render_broad_triage_answer)
    assert "shell=True" not in src


def test_broad_ask_does_not_invoke_collect_evidence(monkeypatch, patched_scene):
    """The broad-triage handler must not fall through to evidence collection."""
    called: dict[str, int] = {"count": 0}

    def fake_diagnose_target(*a, **k):
        called["count"] += 1
        raise AssertionError("evidence collection must not run for broad triage ask")

    monkeypatch.setattr(cli_mod, "diagnose_target", fake_diagnose_target)
    out = _invoke_ask("what's on fire?")
    assert called["count"] == 0
    assert "Read-only Docker triage ranking" in out.stdout


def test_broad_ask_does_not_invoke_model_provider(monkeypatch, patched_scene):
    """The broad-triage handler must answer from deterministic triage only.

    No model provider may be built/called for these prompts — drift into
    LLM rephrase is exactly what PR82 is fixing.
    """

    def fail_build_provider(*a, **k):
        raise AssertionError("model provider must not be built for broad triage ask")

    monkeypatch.setattr(cli_mod, "build_provider", fail_build_provider)
    out = _invoke_ask("what's on fire?")
    assert "Read-only Docker triage ranking" in out.stdout


def test_broad_ask_audit_event_has_no_mutation_flags(patched_scene, tmp_path):
    from shellforgeai.audit.storage import AuditStorage

    _invoke_ask("what's on fire?")
    events_path = tmp_path / "audit" / "events.jsonl"
    assert events_path.exists()
    storage = AuditStorage(tmp_path)
    rows = list(storage.read_events())
    relevant = [r for r in rows if r.get("action") == "broad_triage_rendered"]
    assert relevant, rows
    details = relevant[-1].get("details") or {}
    for k in (
        "mutation_performed",
        "cleanup_executed",
        "proposal_created",
        "mission_created",
        "apply_executed",
        "docker_compose_executed",
        "container_restarted",
        "natural_language_execution",
        "shell_true",
    ):
        assert details.get(k) is False, k


def test_broad_ask_mutation_refusal_audit_event(patched_scene, tmp_path):
    from shellforgeai.audit.storage import AuditStorage

    _invoke_ask("restart the top suspect")
    storage = AuditStorage(tmp_path)
    rows = list(storage.read_events())
    relevant = [r for r in rows if r.get("action") == "broad_triage_mutation_refused"]
    assert relevant, rows
    last = relevant[-1]
    assert last.get("status") == "refused"
    details = last.get("details") or {}
    for k in (
        "mutation_performed",
        "cleanup_executed",
        "proposal_created",
        "mission_created",
        "apply_executed",
        "docker_compose_executed",
        "container_restarted",
        "natural_language_execution",
        "shell_true",
    ):
        assert details.get(k) is False, k
