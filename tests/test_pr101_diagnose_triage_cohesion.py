from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _scene_for(
    name: str, log_themes: dict[str, int], *, state: str = "running", restart_count: int = 0
):
    return {
        "containers": [
            {
                "name": name,
                "state": state,
                "restart_count": restart_count,
                "exit_code": 1 if restart_count else 0,
                "oom_killed": False,
                "log_themes": log_themes,
            }
        ]
    }


def _host_with_systemd_limits(_ctx):
    return [
        EvidenceItem(
            source="systemd.status",
            category=EvidenceCategory.service,
            title="systemd",
            ok=False,
            summary="not found",
            content="systemctl: not found",
        ),
        EvidenceItem(
            source="journal.recent",
            category=EvidenceCategory.logs,
            title="journal",
            ok=False,
            summary="not found",
            content="journalctl: not found",
        ),
    ]


def test_diagnose_known_container_uses_live_triage_path(tmp_path, monkeypatch):
    import shellforgeai.core.diagnose as diagnose_mod

    called = {"scene": 0}

    def _scene():
        called["scene"] += 1
        return _scene_for(
            "sfai-crashloop", {"crashloop_boot": 2}, state="restarting", restart_count=8
        )

    monkeypatch.setattr(diagnose_mod, "collect_host_evidence", _host_with_systemd_limits)
    monkeypatch.setattr(diagnose_mod, "collect_local_knowledge_evidence", lambda *_a, **_k: [])
    monkeypatch.setattr(diagnose_mod, "collect_scene", _scene)

    r = runner.invoke(app, ["diagnose", "sfai-crashloop", "--json"], env=_env(tmp_path))
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert called["scene"] > 0
    assert payload["triage_context"]["detected"] is True
    assert payload["triage_context"]["severity"] == "critical"
    assert "crashloop" in payload["triage_context"]["classes"]
    assert "restart_storm" in payload["triage_context"]["classes"]
    assert payload["container_scope"]["detected"] is True
    assert payload["container_scope"]["host_checks_demoted"] is True
    joined_titles = " ".join(f["title"].lower() for f in payload.get("findings") or [])
    assert "systemd is unavailable" not in joined_titles
    assert "journalctl is unavailable" not in joined_titles


@pytest.mark.parametrize(
    ("target", "themes", "expected_class"),
    [
        ("sfai-bad-http", {"bad_http": 4}, "bad_http"),
        ("sfai-disk-pressure", {"disk_pressure": 4}, "disk_pressure"),
        ("sfai-noisy-errors", {"noisy_error": 8}, "noisy_errors"),
        ("sfai-permission-denied", {"permission_denied": 3}, "permission_denied"),
    ],
)
def test_diagnose_known_container_classes_and_safe_commands(
    tmp_path, monkeypatch, target: str, themes: dict[str, int], expected_class: str
):
    import shellforgeai.core.diagnose as diagnose_mod

    monkeypatch.setattr(diagnose_mod, "collect_host_evidence", lambda _ctx: [])
    monkeypatch.setattr(diagnose_mod, "collect_local_knowledge_evidence", lambda *_a, **_k: [])
    monkeypatch.setattr(diagnose_mod, "collect_scene", lambda: _scene_for(target, themes))

    r = runner.invoke(app, ["diagnose", target, "--json"], env=_env(tmp_path))
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert payload["triage_context"]["detected"] is True
    assert expected_class in payload["triage_context"]["classes"]
    cmds = payload["safe_next_commands"]
    assert any(f"triage docker detail {target}" in c for c in cmds)
    assert any(f"remediation eligibility --target {target} --explain" in c for c in cmds)
    banned = " ".join(cmds)
    for bad in [
        "diagnose docker --target",
        "diagnose logs --target",
        "diagnose disk --target",
        "docker restart",
        "docker compose restart",
        "remediation execute",
        "rollback-execute",
        "cleanup execute",
        "--execute --confirm",
    ]:
        assert bad not in banned


def test_diagnose_unknown_target_preserves_behavior(tmp_path, monkeypatch):
    import shellforgeai.core.diagnose as diagnose_mod

    monkeypatch.setattr(diagnose_mod, "collect_host_evidence", lambda _ctx: [])
    monkeypatch.setattr(diagnose_mod, "collect_local_knowledge_evidence", lambda *_a, **_k: [])
    monkeypatch.setattr(diagnose_mod, "collect_scene", lambda: {"containers": []})

    r = runner.invoke(app, ["diagnose", "totally-unknown-target", "--json"], env=_env(tmp_path))
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert payload["triage_context"] == {}
    assert payload["container_scope"] == {}
    assert payload["safe_next_commands"] == []
