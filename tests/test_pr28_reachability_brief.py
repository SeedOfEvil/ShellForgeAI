"""PR28 follow-up: surface sfai-bad-network in network reachability ask.

Validates that the network_reachability brief, target-container extraction,
and CLI ask wiring put per-container DNS/upstream/reachability log evidence
in the prompt and findings — not buried under truncated Docker aggregates.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.ask_routing import (
    extract_container_target,
    network_reachability_brief,
)
from shellforgeai.core.diagnose import Finding
from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem

runner = CliRunner()


# ---------- target extraction ----------


@pytest.mark.parametrize(
    "phrase,expected",
    [
        ("why is bad-network failing?", "sfai-bad-network"),
        ("explain bad network failure", "sfai-bad-network"),
        ("missing-env error", "sfai-missing-env"),
        ("issue with sfai-noisy-logs", "sfai-noisy-logs"),
        ("network reachability is broken", ""),
        ("DNS errors in logs", ""),
    ],
)
def test_extract_container_target(phrase: str, expected: str) -> None:
    assert extract_container_target(phrase) == expected


# ---------- network_reachability_brief ----------


def _problem_summary_item(payload: dict) -> EvidenceItem:
    return EvidenceItem(
        source="docker.problem_summary",
        category=EvidenceCategory.logs,
        ok=True,
        title="Container problem summary",
        summary="docker_total=6 failing=2 noisy=2",
        content=json.dumps(payload),
    )


def _runtime_item(source: str, ok: bool = True, summary: str = "ok") -> EvidenceItem:
    return EvidenceItem(
        source=source,
        category=EvidenceCategory.network,
        ok=ok,
        title=source,
        summary=summary,
        content=summary,
    )


def _lab_payload() -> dict:
    return {
        "available": True,
        "total": 6,
        "failing": [
            {
                "name": "sfai-missing-env",
                "state": "exited",
                "exit_code": 42,
                "log_themes": {"missing_required_setting": 3},
                "log_sample": ["ERROR REQUIRED_SETTING is missing"],
            },
            {
                "name": "sfai-restart-loop",
                "state": "restarting",
                "exit_code": 1,
                "log_themes": {"simulated_crash": 6},
                "log_sample": ["Simulated crash"],
            },
            {
                "name": "sfai-bad-volume-perms",
                "state": "exited",
                "exit_code": 1,
                "log_themes": {"read_only_fs": 1, "permission_denied": 1},
                "log_sample": ["read-only file system"],
            },
        ],
        "noisy": [
            {
                "name": "sfai-noisy-logs",
                "state": "running",
                "exit_code": 0,
                "log_themes": {"warn_line": 2, "error_line": 1},
                "log_sample": ["WARN slow", "ERROR something noisy"],
            },
            {
                "name": "sfai-bad-network",
                "state": "running",
                "exit_code": 0,
                "log_themes": {"dns_failure": 4},
                "log_sample": [
                    "Could not resolve host upstream.invalid",
                    "temporary failure in name resolution",
                ],
            },
        ],
    }


def test_brief_includes_bad_network_when_running_with_dns_themes() -> None:
    items = [
        _problem_summary_item(_lab_payload()),
        _runtime_item("network.resolution_test"),
        _runtime_item("network.default_route"),
        _runtime_item("network.dns"),
    ]
    brief = network_reachability_brief([], items, target_container="sfai-bad-network")
    names = [r["container"] for r in brief["container_log_evidence"]]
    assert "sfai-bad-network" in names
    # Targeted container is pinned to the front.
    assert names[0] == "sfai-bad-network"
    bad = brief["container_log_evidence"][0]
    assert bad["state"] == "running"
    assert "dns_resolution" in bad["themes"]
    assert any("name resolution" in line for line in bad["log_sample"])


def test_brief_excludes_pure_warn_error_noise_without_network_theme() -> None:
    items = [_problem_summary_item(_lab_payload())]
    brief = network_reachability_brief([], items)
    names = [r["container"] for r in brief["container_log_evidence"]]
    # noisy-logs has no network theme -> not in container_log_evidence.
    assert "sfai-noisy-logs" not in names
    # bad-network has dns_failure -> included.
    assert "sfai-bad-network" in names


def test_brief_target_container_never_truncated() -> None:
    payload = {"available": True, "total": 20, "failing": [], "noisy": []}
    # Fill noisy with 15 throwaway containers all carrying connection_refused.
    for i in range(15):
        payload["noisy"].append(
            {
                "name": f"svc-{i}",
                "state": "running",
                "log_themes": {"connection_refused": 1},
                "log_sample": [],
            }
        )
    payload["noisy"].append(
        {
            "name": "sfai-bad-network",
            "state": "running",
            "log_themes": {"dns_failure": 4},
            "log_sample": ["Could not resolve host upstream.invalid"],
        }
    )
    brief = network_reachability_brief(
        [],
        [_problem_summary_item(payload)],
        target_container="sfai-bad-network",
        max_containers=5,
    )
    names = [r["container"] for r in brief["container_log_evidence"]]
    assert "sfai-bad-network" in names, names
    assert names[0] == "sfai-bad-network"
    assert len(names) <= 5


def test_brief_runtime_network_basics_listed_separately() -> None:
    items = [
        _problem_summary_item(_lab_payload()),
        _runtime_item("network.resolution_test", ok=True, summary="resolved=ok"),
        _runtime_item("network.default_route", ok=True, summary="default via 172.17.0.1"),
    ]
    brief = network_reachability_brief([], items)
    sources = [r["source"] for r in brief["runtime_network_basics"]]
    assert "network.resolution_test" in sources
    assert "network.default_route" in sources


def test_brief_findings_pin_target_and_network_themes_first() -> None:
    findings = [
        Finding(severity="info", title="random unrelated info", detail="x"),
        Finding(severity="warning", title="generic warning A", detail="x"),
        Finding(
            severity="warning",
            title="sfai-bad-network is running but logs show dns failure",
            detail="themes=dns_failure",
        ),
        Finding(
            severity="warning",
            title="some-svc upstream unreachable",
            detail="themes=upstream_unreachable",
        ),
    ]
    brief = network_reachability_brief(
        findings,
        [_problem_summary_item(_lab_payload())],
        target_container="sfai-bad-network",
    )
    titles = [r["title"] for r in brief["findings"]]
    assert "sfai-bad-network" in titles[0]


# ---------- CLI integration: prompt actually carries bad-network ----------


class _FakeProvider:
    def __init__(self, text="ok answer"):
        self._text = text
        self.last_prompt: str | None = None

    def complete(self, req):
        self.last_prompt = req.prompt
        return SimpleNamespace(
            ok=True,
            text=self._text,
            provider="openai-codex",
            model="codex-fake",
            usage={
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "output_tokens": 5,
                "reasoning_output_tokens": 0,
            },
            error=None,
            raw=None,
        )


@pytest.fixture
def patch_provider(monkeypatch):
    holder = {"provider": _FakeProvider()}

    def factory(*_a, **_kw):
        return holder["provider"]

    monkeypatch.setattr("shellforgeai.cli.build_provider", factory)
    return holder


def _diag_with_lab_payload():
    payload = _lab_payload()
    summary_item = EvidenceItem(
        source="docker.problem_summary",
        category=EvidenceCategory.logs,
        ok=True,
        title="Container problem summary",
        summary="docker_total=6 failing=3 noisy=2",
        content=json.dumps(payload),
    )
    findings = [
        Finding(
            severity="warning",
            title=(
                "sfai-bad-network is running but logs show dns failure (app/container reachability)"
            ),
            detail="themes=dns_failure",
        ),
        Finding(
            severity="critical",
            title="sfai-restart-loop appears to be in a restart loop",
            detail="state=restarting",
        ),
    ]
    items = [
        summary_item,
        EvidenceItem(
            source="system.container_detect",
            category=EvidenceCategory.host,
            ok=True,
            title="Container detection",
            summary="container=docker",
            content="docker",
        ),
        EvidenceItem(
            source="network.resolution_test",
            category=EvidenceCategory.network,
            ok=True,
            title="DNS test",
            summary="resolved",
            content="",
        ),
        EvidenceItem(
            source="network.default_route",
            category=EvidenceCategory.network,
            ok=True,
            title="Default route",
            summary="default via 172.17.0.1",
            content="",
        ),
    ]
    return SimpleNamespace(
        session_id="sess-net",
        target="docker",
        target_type=SimpleNamespace(value="generic"),
        findings=findings,
        evidence=SimpleNamespace(
            items=items,
            model_dump_json=lambda indent=2: json.dumps({"items": []}),
        ),
        proposed_plan=SimpleNamespace(model_dump_json=lambda indent=2: "{}"),
        warnings=[],
        errors=[],
    )


@pytest.mark.parametrize(
    "question",
    [
        "network reachability is broken",
        "why is bad-network failing?",
        "DNS errors in logs",
        "app cannot reach upstream",
    ],
)
def test_ask_prompt_mentions_bad_network_with_dns_theme(
    monkeypatch, patch_provider, question: str
) -> None:
    monkeypatch.setattr(
        "shellforgeai.cli.diagnose_target", lambda *a, **k: _diag_with_lab_payload()
    )
    monkeypatch.setattr("shellforgeai.core.collectors.collect_network_evidence", lambda _ctx: [])
    res = runner.invoke(app, ["ask", question])
    assert res.exit_code == 0, res.stdout
    prompt = patch_provider["provider"].last_prompt or ""
    assert "sfai-bad-network" in prompt, question
    assert "dns_resolution" in prompt, question
    assert "container_log_evidence" in prompt, question
    assert "runtime_network_basics" in prompt, question


def test_ask_bad_network_question_pins_target_in_prompt(monkeypatch, patch_provider) -> None:
    monkeypatch.setattr(
        "shellforgeai.cli.diagnose_target", lambda *a, **k: _diag_with_lab_payload()
    )
    monkeypatch.setattr("shellforgeai.core.collectors.collect_network_evidence", lambda _ctx: [])
    res = runner.invoke(app, ["ask", "why is bad-network failing?"])
    assert res.exit_code == 0, res.stdout
    prompt = patch_provider["provider"].last_prompt or ""
    assert '"target_container": "sfai-bad-network"' in prompt
    # The first container_log_evidence row must be the target.
    payload_start = prompt.find('"container_log_evidence"')
    assert payload_start > -1
    head = prompt[payload_start : payload_start + 800]
    assert "sfai-bad-network" in head


def test_ask_dns_errors_does_not_get_truncated(monkeypatch, patch_provider) -> None:
    monkeypatch.setattr(
        "shellforgeai.cli.diagnose_target", lambda *a, **k: _diag_with_lab_payload()
    )
    monkeypatch.setattr("shellforgeai.core.collectors.collect_network_evidence", lambda _ctx: [])
    res = runner.invoke(app, ["ask", "DNS errors in logs"])
    assert res.exit_code == 0, res.stdout
    prompt = patch_provider["provider"].last_prompt or ""
    # The reachability ranking paragraph and the bad-network row must both
    # be present — i.e. the brief was not truncated away.
    assert "container_log_evidence is non-empty" in prompt
    assert "sfai-bad-network" in prompt
    assert "dns_resolution" in prompt
