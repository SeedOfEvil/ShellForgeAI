"""PR81 — Read-only Docker triage ranking tests.

Drives the scoring engine from synthetic battle-lab fixtures (no live Docker,
no daemon, no subprocess). Verifies scoring, ranking, JSON shape, human
output, and the safety invariants required by the PR81 brief.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core import triage_ranking as triage_mod
from shellforgeai.core.triage_ranking import (
    MODE,
    SCHEMA_VERSION,
    rank_scene,
)

runner = CliRunner()


# --- fixture: noisy battle-lab scene ---------------------------------------


def _battle_lab_scene() -> dict:
    return {
        "containers": [
            {
                "name": "sfai-crashloop",
                "state": "restarting",
                "exit_code": 42,
                "restart_count": 12,
                "oom_killed": False,
                "health": None,
                "log_themes": {"error_line": 4, "traceback": 1},
            },
            {
                "name": "sfai-bad-http",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "unhealthy",
                "log_themes": {
                    "connection_refused": 5,
                    "upstream_unreachable": 2,
                },
            },
            {
                "name": "sfai-noisy-errors",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_themes": {"error_line": 8, "traceback": 1},
            },
            {
                "name": "sfai-disk-pressure",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_themes": {"read_only_fs": 2},
                "log_no_space_left": True,
                "disk_free_pct": 3,
            },
            {
                "name": "sfai-permission-denied",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_themes": {"permission_denied": 5},
            },
            {
                "name": "sfai-high-cpu",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "cpu_percent": 92.0,
                "log_themes": {},
            },
            {
                "name": "sfai-quiet",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_themes": {},
            },
        ]
    }


def _by_name(suspects: list) -> dict:
    return {s["name"]: s for s in suspects}


# --- scoring / ranking ----------------------------------------------------


def test_crashloop_ranks_critical_or_high():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-crashloop" in s
    assert s["sfai-crashloop"]["severity"] in {"critical", "high"}


def test_crashloop_ranks_above_noisy_and_high_cpu():
    payload = rank_scene(_battle_lab_scene())
    suspects = payload["suspects"]
    names = [x["name"] for x in suspects]
    assert "sfai-crashloop" in names
    # Crashloop must outrank noisy-errors and must not be tied with watch cases.
    crashloop_rank = names.index("sfai-crashloop")
    assert "sfai-noisy-errors" in names
    assert crashloop_rank < names.index("sfai-noisy-errors")
    # High-CPU healthy should be in watch list, not in suspects.
    assert "sfai-high-cpu" not in names


def test_bad_http_suspect_present():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-bad-http" in s
    assert "bad_http" in s["sfai-bad-http"]["classes"]


def test_noisy_errors_suspect_present():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-noisy-errors" in s
    assert "noisy_errors" in s["sfai-noisy-errors"]["classes"]


def test_disk_pressure_suspect_present():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-disk-pressure" in s
    assert "disk_pressure" in s["sfai-disk-pressure"]["classes"]


def test_permission_denied_suspect_present():
    payload = rank_scene(_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-permission-denied" in s
    assert "permission_denied" in s["sfai-permission-denied"]["classes"]


def test_high_cpu_healthy_is_watch_only():
    payload = rank_scene(_battle_lab_scene())
    watch_names = {w["name"] for w in payload["watch"]}
    assert "sfai-high-cpu" in watch_names
    # And severity is watch, never critical.
    w = next(w for w in payload["watch"] if w["name"] == "sfai-high-cpu")
    assert w["severity"] == "watch"


def test_multiple_active_scenarios_listed():
    payload = rank_scene(_battle_lab_scene())
    names = {s["name"] for s in payload["suspects"]}
    expected = {
        "sfai-crashloop",
        "sfai-bad-http",
        "sfai-noisy-errors",
        "sfai-disk-pressure",
        "sfai-permission-denied",
    }
    assert expected.issubset(names)


def test_every_suspect_has_evidence_why_and_safe_next():
    payload = rank_scene(_battle_lab_scene())
    for s in payload["suspects"]:
        assert s.get("evidence"), s
        assert s.get("why"), s
        assert s.get("safe_next_commands"), s


def test_safe_next_commands_are_read_only():
    payload = rank_scene(_battle_lab_scene())
    for s in payload["suspects"]:
        for cmd in s["safe_next_commands"]:
            lowered = cmd.lower()
            # Read-only verbs only.
            assert lowered.startswith("shellforgeai diagnose ") or lowered.startswith(
                "shellforgeai ask "
            ), cmd
            for forbidden in (
                "restart",
                "stop ",
                " rm ",
                "remove",
                "prune",
                "apply",
                "mission ",
                "cleanup execute",
                "compose up",
                "compose down",
                "compose restart",
            ):
                assert forbidden not in lowered, cmd
    for cmd in payload["next_safe_commands"]:
        lowered = cmd.lower()
        for forbidden in (
            "restart",
            "prune",
            "apply",
            " rm ",
            "compose up",
            "compose down",
        ):
            assert forbidden not in lowered, cmd


# --- JSON output contract --------------------------------------------------


def _invoke_json(monkeypatch, scene):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: scene)
    out = runner.invoke(app, ["triage", "docker", "--json"])
    assert out.exit_code == 0, out.stdout
    return out


def test_triage_json_strict_parseable(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    # No text before/after JSON.
    body = out.stdout.strip()
    payload = json.loads(body)
    assert isinstance(payload, dict)
    # Ensure single-line / parseable: stdout should be the JSON only (plus
    # optional trailing newline from typer.echo).
    assert out.stdout.endswith("\n")
    assert out.stdout.count("\n") == 1


def test_triage_json_schema_version_and_mode(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    p = json.loads(out.stdout)
    assert p["schema_version"] == SCHEMA_VERSION
    assert p["mode"] == MODE


def test_triage_json_includes_suspects_and_summary(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    p = json.loads(out.stdout)
    assert isinstance(p["suspects"], list) and p["suspects"]
    assert isinstance(p["summary"], dict)
    for key in ("containers_seen", "suspects_ranked", "critical", "high", "medium", "watch"):
        assert key in p["summary"]


def test_triage_json_safety_flags(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    p = json.loads(out.stdout)
    safety = p["safety"]
    assert safety["read_only"] is True
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
        assert safety[k] is False, k
    assert p["read_only"] is True
    assert p["mutation_performed"] is False


def test_triage_json_required_keys(monkeypatch):
    out = _invoke_json(monkeypatch, _battle_lab_scene())
    p = json.loads(out.stdout)
    for k in (
        "schema_version",
        "mode",
        "summary",
        "suspects",
        "safety",
        "warnings",
        "next_safe_commands",
    ):
        assert k in p


def test_triage_json_empty_scene_is_warn(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: {"containers": []})
    out = runner.invoke(app, ["triage", "docker", "--json"])
    assert out.exit_code == 0
    p = json.loads(out.stdout)
    assert p["status"] == "warn"
    assert p["suspects"] == []
    assert p["safety"]["read_only"] is True


# --- human output contract -------------------------------------------------


def test_human_ranks_suspects(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker"])
    assert out.exit_code == 0, out.stdout
    text = out.stdout
    assert "Docker triage suspects" in text
    assert "sfai-crashloop" in text
    # Severity / confidence / why / safe next must be rendered.
    assert "Severity:" in text
    assert "Confidence:" in text
    assert "Why ranked here:" in text
    assert "Safe next command:" in text


def test_human_includes_safety_statement(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker"])
    assert "read_only: true" in out.stdout
    assert "mutation_performed: false" in out.stdout
    assert "no restart/stop/delete/prune was executed" in out.stdout


def test_human_includes_next_safe_steps(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker"])
    assert "Next safe steps:" in out.stdout


def test_human_includes_watch_line(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker"])
    assert "Watch:" in out.stdout
    assert "sfai-high-cpu" in out.stdout


# --- safety regression -----------------------------------------------------


def _module_text() -> str:
    return Path(inspect.getfile(triage_mod)).read_text(encoding="utf-8")


def test_no_shell_true_in_triage_module():
    text = _module_text()
    assert "shell=True" not in text


def test_triage_does_not_import_mutation_helpers():
    text = _module_text()
    forbidden = [
        "from shellforgeai.core.apply_bundle",
        "from shellforgeai.core.mission",
        "from shellforgeai.core.actions",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
    ]
    for f in forbidden:
        assert f not in text, f


def test_triage_does_not_call_mutation_methods(monkeypatch):
    # Stand up a real run, ensure no plan/proposal/mission/apply files written.
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker", "--json"])
    assert out.exit_code == 0
    p = json.loads(out.stdout)
    assert p["safety"]["proposal_created"] is False
    assert p["safety"]["mission_created"] is False
    assert p["safety"]["apply_executed"] is False
    assert p["safety"]["cleanup_executed"] is False
    assert p["safety"]["docker_compose_executed"] is False
    assert p["safety"]["container_restarted"] is False


# ===========================================================================
# PR81-followup: realistic battle-lab fixtures (timestamp-prefixed log text)
# Per-container evidence isolation, missing scenarios, watch lane, and the
# bad-http anti-attribution guard.
# ===========================================================================


def _realistic_battle_lab_scene() -> dict:
    """Battle-lab scene mirroring the Docker01 live QA observation.

    Logs are timestamp-prefixed (the real container log shape) so the line
    classifier must not require ERROR to be at the start of the line.
    """
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
            # Nginx sometimes prints a single permission-denied as an errno
            # decoration — this must NOT pin permission_denied class on this
            # bad-http suspect.
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
            {
                "name": "shellforgeai",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "cpu_percent": 95.0,
                "log_text": "",
            },
            {
                "name": "sfai-quiet",
                "state": "running",
                "exit_code": 0,
                "restart_count": 0,
                "oom_killed": False,
                "health": "healthy",
                "log_text": "2024-05-20T14:50:01 INFO heartbeat ok",
            },
        ]
    }


# --- per-container evidence isolation -------------------------------------


def test_disk_pressure_evidence_does_not_attach_to_bad_http():
    payload = rank_scene(_realistic_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-bad-http" in s
    assert "disk_pressure" not in s["sfai-bad-http"]["classes"]


def test_permission_denied_evidence_does_not_attach_to_bad_http():
    payload = rank_scene(_realistic_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-bad-http" in s
    assert "permission_denied" not in s["sfai-bad-http"]["classes"]


def test_each_suspects_classes_come_from_its_own_evidence():
    payload = rank_scene(_realistic_battle_lab_scene())
    s = _by_name(payload["suspects"])
    # disk_pressure class only on sfai-disk-pressure
    disk_owners = [n for n, e in s.items() if "disk_pressure" in e["classes"]]
    assert disk_owners == ["sfai-disk-pressure"]
    # permission_denied class only on sfai-permission-denied
    perm_owners = [n for n, e in s.items() if "permission_denied" in e["classes"]]
    assert perm_owners == ["sfai-permission-denied"]
    # noisy_errors class only on sfai-noisy-errors
    noisy_owners = [n for n, e in s.items() if "noisy_errors" in e["classes"]]
    assert noisy_owners == ["sfai-noisy-errors"]
    # bad_http class only on sfai-bad-http
    http_owners = [n for n, e in s.items() if "bad_http" in e["classes"]]
    assert http_owners == ["sfai-bad-http"]


def test_global_scene_evidence_is_not_copied_to_every_suspect():
    payload = rank_scene(_realistic_battle_lab_scene())
    for s in payload["suspects"]:
        # No suspect should ever pick up every class — that would mean global
        # evidence leaked into per-container classification.
        assert len(s["classes"]) < 5, s


# --- broad triage covers ALL active battle-lab scenarios ------------------


def test_all_active_battle_lab_scenarios_are_ranked():
    payload = rank_scene(_realistic_battle_lab_scene())
    names = {s["name"] for s in payload["suspects"]}
    expected = {
        "sfai-crashloop",
        "sfai-noisy-errors",
        "sfai-bad-http",
        "sfai-disk-pressure",
        "sfai-permission-denied",
    }
    assert expected.issubset(names), names


def test_noisy_errors_ranks_on_timestamp_prefixed_logs():
    payload = rank_scene(_realistic_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-noisy-errors" in s
    assert "noisy_errors" in s["sfai-noisy-errors"]["classes"]


def test_disk_pressure_ranks_on_simulated_marker():
    payload = rank_scene(_realistic_battle_lab_scene())
    s = _by_name(payload["suspects"])
    assert "sfai-disk-pressure" in s
    assert "disk_pressure" in s["sfai-disk-pressure"]["classes"]


def test_running_containers_can_still_rank_as_suspects():
    payload = rank_scene(_realistic_battle_lab_scene())
    running_suspects = [s["name"] for s in payload["suspects"] if s["name"] != "sfai-crashloop"]
    # noisy, bad-http, disk, perm are all running yet must appear.
    assert {
        "sfai-noisy-errors",
        "sfai-bad-http",
        "sfai-disk-pressure",
        "sfai-permission-denied",
    }.issubset(set(running_suspects))


def test_crashloop_outranks_noisy_and_watch():
    payload = rank_scene(_realistic_battle_lab_scene())
    names = [s["name"] for s in payload["suspects"]]
    assert names[0] == "sfai-crashloop"
    assert "shellforgeai" not in names  # high-CPU healthy belongs in watch


def test_high_cpu_healthy_is_watch_not_critical():
    payload = rank_scene(_realistic_battle_lab_scene())
    watch_names = {w["name"] for w in payload["watch"]}
    assert "shellforgeai" in watch_names
    w = next(w for w in payload["watch"] if w["name"] == "shellforgeai")
    assert w["severity"] == "watch"
    # And NOT in suspects.
    assert "shellforgeai" not in [s["name"] for s in payload["suspects"]]


def test_at_least_five_scenarios_in_suspects_or_watch():
    payload = rank_scene(_realistic_battle_lab_scene())
    total = {s["name"] for s in payload["suspects"]} | {w["name"] for w in payload["watch"]}
    assert len(total) >= 5


# --- log classifier sanity -------------------------------------------------


def test_classify_logs_matches_timestamp_prefixed_error():
    from shellforgeai.core.triage_ranking import classify_logs

    text = "2024-05-20T14:50:01 ERROR payment-worker timeout"
    out = classify_logs(text)
    assert out.get("noisy_error", 0) >= 1


def test_classify_logs_matches_simulated_disk_pressure():
    from shellforgeai.core.triage_ranking import classify_logs

    text = "2024-05-20 ERROR write failed: simulated disk pressure, filler=96.0M"
    out = classify_logs(text)
    assert out.get("disk_pressure", 0) >= 1


def test_classify_logs_matches_nginx_upstream_refused():
    from shellforgeai.core.triage_ranking import classify_logs

    text = "connect() to 127.0.0.1:9999 failed (111: Connection refused)"
    out = classify_logs(text)
    assert out.get("bad_http", 0) >= 1


def test_classify_logs_is_per_text_only():
    from shellforgeai.core.triage_ranking import classify_logs

    # First call shouldn't leak state into the second.
    classify_logs("ERROR everywhere ERROR ERROR")
    out = classify_logs("nothing interesting here")
    assert out == {}


# --- human / JSON contract on realistic fixture ---------------------------


def test_human_output_includes_all_realistic_battle_lab_names(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _realistic_battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker"])
    assert out.exit_code == 0
    for name in (
        "sfai-crashloop",
        "sfai-noisy-errors",
        "sfai-bad-http",
        "sfai-disk-pressure",
        "sfai-permission-denied",
    ):
        assert name in out.stdout, name
    assert "Evidence:" in out.stdout


def test_json_realistic_includes_classes_evidence_and_all_names(monkeypatch):
    monkeypatch.setattr(triage_mod, "collect_scene", lambda *a, **k: _realistic_battle_lab_scene())
    out = runner.invoke(app, ["triage", "docker", "--json"])
    assert out.exit_code == 0
    p = json.loads(out.stdout)
    names = {s["name"] for s in p["suspects"]}
    for n in (
        "sfai-crashloop",
        "sfai-noisy-errors",
        "sfai-bad-http",
        "sfai-disk-pressure",
        "sfai-permission-denied",
    ):
        assert n in names, n
    for s in p["suspects"]:
        assert s.get("classes")
        assert s.get("evidence")


# --- collect_scene: per-container isolation, no live docker --------------


def test_collect_scene_uses_per_container_logs_only(monkeypatch):
    """``collect_scene`` must classify each container's log text in isolation.

    We stub the underlying docker collectors and verify the resulting scene
    has log_text populated per container and no cross-container theme leak.
    """
    from shellforgeai.tools import containers as containers_tool
    from shellforgeai.tools.base import ToolResult

    inventory = {
        "containers": [
            {"name": "alpha", "state": "running"},
            {"name": "beta", "state": "running"},
        ]
    }

    def fake_containers(all_containers=True):
        return ToolResult(tool="docker.containers", stdout=json.dumps(inventory))

    def fake_inspect(name):
        return ToolResult(
            tool="docker.inspect",
            stdout=json.dumps(
                {
                    "name": name,
                    "exit_code": 0,
                    "restart_count": 0,
                    "oom_killed": False,
                    "health": "healthy",
                }
            ),
        )

    def fake_logs(name, tail=200, max_bytes=65536):
        if name == "alpha":
            body = (
                "2024-05-20 ERROR write failed: simulated disk pressure, "
                "filler=96.0M\n"
                "2024-05-20 ERROR write failed: simulated disk pressure, "
                "filler=97.0M\n"
            )
        else:
            body = "2024-05-20 INFO beta is fine\n"
        return ToolResult(tool="docker.container_logs", stdout=body)

    monkeypatch.setattr(containers_tool, "containers", fake_containers)
    monkeypatch.setattr(containers_tool, "inspect", fake_inspect)
    monkeypatch.setattr(containers_tool, "container_logs", fake_logs)
    monkeypatch.setattr(triage_mod, "_collect_cpu_stats", lambda: {})

    scene = triage_mod.collect_scene()
    by_name = {c["name"]: c for c in scene["containers"]}
    assert "simulated disk pressure" in by_name["alpha"]["log_text"]
    assert "simulated disk pressure" not in by_name["beta"]["log_text"]

    payload = rank_scene(scene)
    s = _by_name(payload["suspects"])
    assert "alpha" in s
    assert "disk_pressure" in s["alpha"]["classes"]
    assert "beta" not in s  # quiet container, not ranked


def test_collect_scene_no_daemon_returns_empty(monkeypatch):
    from shellforgeai.tools import containers as containers_tool
    from shellforgeai.tools.base import ToolResult

    monkeypatch.setattr(
        containers_tool,
        "containers",
        lambda all_containers=True: ToolResult(
            tool="docker.containers", ok=False, exit_code=127, stderr="no docker"
        ),
    )
    scene = triage_mod.collect_scene()
    assert scene == {"containers": []}
