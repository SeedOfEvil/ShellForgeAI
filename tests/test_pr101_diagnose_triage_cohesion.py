from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def test_diagnose_known_container_json_has_triage_context(tmp_path, monkeypatch):
    import shellforgeai.core.diagnose as diagnose_mod

    def _host(_ctx):
        payload = {
            "failing": [
                {
                    "name": "sfai-crashloop",
                    "state": "restarting",
                    "restart_count": 8,
                    "exit_code": 1,
                    "log_themes": {"crashloop_boot": 2},
                },
                {
                    "name": "sfai-bad-http",
                    "state": "running",
                    "log_themes": {"bad_http": 3},
                },
                {
                    "name": "sfai-disk-pressure",
                    "state": "running",
                    "log_themes": {"disk_pressure": 3},
                },
                {
                    "name": "sfai-permission-denied",
                    "state": "running",
                    "log_themes": {"permission_denied": 3},
                },
            ],
            "noisy": [
                {"name": "sfai-noisy-errors", "state": "running", "log_themes": {"noisy_error": 6}}
            ],
        }
        from shellforgeai.core.evidence import EvidenceItem

        return [
            EvidenceItem(
                source="docker.problem_summary",
                category="service",
                title="docker summary",
                ok=True,
                summary="ok",
                content=json.dumps(payload),
            )
        ]

    monkeypatch.setattr(diagnose_mod, "collect_host_evidence", _host)
    monkeypatch.setattr(diagnose_mod, "collect_local_knowledge_evidence", lambda *_a, **_k: [])

    r = runner.invoke(app, ["diagnose", "sfai-crashloop", "--json"], env=_env(tmp_path))
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert payload["triage_context"]["detected"] is True
    assert payload["triage_context"]["severity"] == "critical"
    assert "crashloop" in payload["triage_context"]["classes"]
    assert "restart_storm" in payload["triage_context"]["classes"]
    assert payload["container_scope"]["detected"] is True
    assert payload["container_scope"]["host_checks_demoted"] is True
    assert payload["safety"]["mutation_performed"] is False
    cmds = payload["safe_next_commands"]
    assert any("triage docker detail sfai-crashloop" in c for c in cmds)
    assert any("remediation eligibility --target sfai-crashloop --explain" in c for c in cmds)
    bad = " ".join(cmds)
    assert "diagnose docker --target" not in bad
    assert "diagnose logs --target" not in bad
    assert "docker restart" not in bad
    assert "docker compose restart" not in bad
    assert "remediation execute" not in bad
    assert "rollback-execute" not in bad
    assert "cleanup execute" not in bad
    assert "--execute --confirm" not in bad
