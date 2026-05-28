from shellforgeai.cli import _handle_mutation_refusal_ask
from shellforgeai.core.triage_ranking import render_detail_human, render_human


def _sample_payload():
    return {
        "summary": {
            "containers_seen": 5,
            "suspects_ranked": 2,
            "critical": 1,
            "high": 1,
            "medium": 0,
            "watch": 0,
        },
        "suspects": [
            {
                "rank": 1,
                "name": "sfai-crashloop",
                "severity": "critical",
                "confidence": "high",
                "score": 95,
                "classes": ["restart_storm"],
                "why": ["restart storm"],
                "evidence": [{"type": "restart_count", "value": 99}],
                "safe_next_commands": ["shellforgeai triage docker detail sfai-crashloop"],
            },
            {
                "rank": 2,
                "name": "sfai-noisy-errors",
                "severity": "high",
                "confidence": "medium",
                "score": 78,
                "classes": ["noisy_errors"],
                "why": ["error logs"],
                "evidence": [{"type": "error_hits", "value": 22}],
                "safe_next_commands": ["shellforgeai triage docker detail sfai-noisy-errors"],
            },
        ],
        "watch": [],
        "next_safe_commands": ["shellforgeai triage docker detail --rank 1"],
    }


def test_triage_human_has_status_top_and_first_safe_command():
    out = render_human(_sample_payload())
    assert "Status:" in out
    assert "Top suspect: sfai-crashloop" in out
    assert "First safe command: shellforgeai triage docker detail sfai-crashloop" in out


def test_triage_detail_has_eligibility_first_safe_command():
    payload = {
        "status": "ok",
        "target": {"input": "sfai-crashloop", "rank": 1, "rank_total": 2},
        "suspect": _sample_payload()["suspects"][0],
    }
    out = render_detail_human(payload)
    assert (
        "First safe command: shellforgeai remediation eligibility --target sfai-crashloop --explain"
        in out
    )


def test_mutation_refusal_mentions_no_action_and_read_only_alternative(capsys):
    assert _handle_mutation_refusal_ask("please restart sfai-crashloop") is True
    out = capsys.readouterr().out.lower()
    assert "no action was performed" in out
    assert "first safe command: shellforgeai ops report" in out
    forbidden = [
        "docker restart",
        "docker compose restart",
        "docker compose up",
        "docker compose down",
        "docker system prune",
        "docker volume prune",
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "cleanup execute --confirm",
    ]
    for term in forbidden:
        assert term not in out
