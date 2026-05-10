"""PR28: Network/log ask polish + reachability ranking.

Tests cover:
- routing for new and typo-tolerant network/reachability prompts
- target-specific bad-network handling
- finer-grained log theme classification (connection_refused, timeout, tls)
- reachability ranking hints when runtime network is OK but app logs fail
- safety: mutation-style network requests stay read-only
- regression: PR26/PR27 behaviors preserved
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import _network_reachability_hints, app
from shellforgeai.core.ask_routing import (
    EVIDENCE_BACKED,
    PLAIN,
    is_mutation_request,
    is_network_reachability_intent,
    route_ask_intent,
)
from shellforgeai.core.diagnose import (
    Finding,
    _findings_from_docker,
    displayed_finding_severity_counts,
)
from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem
from shellforgeai.interactive.commands import route_input
from shellforgeai.tools import containers
from shellforgeai.tools.base import ToolResult
from shellforgeai.util.subprocess import CommandResult

runner = CliRunner()


# ---------- routing ----------


@pytest.mark.parametrize(
    "phrase",
    [
        "network reachability is broken",
        "netwrok reachability is broken",
        "reechability is broken",
        "upstream is unreachable",
        "upstram unreachable",
        "app cannot reach upstream",
        "service dependency unreachable",
        "container network broken",
        "dns errors in logs",
        "dns erorrs in logs",
        "connection refused errors",
        "coneccion refused errors",
        "timeout errors",
        "timout errors",
        "network errors",
        "why cant the app reach the server?",
    ],
)
def test_route_evidence_backed_for_network_phrases(phrase: str) -> None:
    r = route_ask_intent(phrase)
    assert r.mode == EVIDENCE_BACKED, phrase
    assert r.target in {"docker", "logs", "network"}, (phrase, r.target)
    assert r.network_reachability is True, phrase
    assert r.intent_label == "network_reachability", phrase


def test_route_bad_network_targets_lab_container() -> None:
    r = route_ask_intent("why is bad-network failing?")
    assert r.mode == EVIDENCE_BACKED
    assert r.target == "docker"
    assert r.network_reachability is True


def test_diagnose_routing_bad_network() -> None:
    cmd = route_input("why is bad-network failing?")
    assert cmd.name == "diagnose"
    assert cmd.args == "docker"


def test_route_plain_question_unchanged() -> None:
    r = route_ask_intent("Explain the difference between TCP and UDP in two short paragraphs.")
    assert r.mode == PLAIN
    assert r.network_reachability is False


def test_is_network_reachability_intent_basic() -> None:
    assert is_network_reachability_intent("network reachability is broken")
    assert is_network_reachability_intent("upstream is unreachable")
    assert is_network_reachability_intent("dns errors in logs")
    assert is_network_reachability_intent("connection refused errors")
    assert not is_network_reachability_intent("how does TCP work?")


# ---------- theme classification ----------


def test_classify_connection_refused() -> None:
    text = "ERROR connect() failed: Connection refused while connecting to upstream"
    themes = containers._classify_log(text)
    assert themes.get("connection_refused", 0) >= 1


def test_classify_timeout() -> None:
    text = "WARN read timed out\nERROR i/o timeout connecting to api.example.com"
    themes = containers._classify_log(text)
    assert themes.get("timeout", 0) >= 1


def test_classify_tls_certificate() -> None:
    text = "ERROR x509: certificate has expired or is not yet valid\nTLS handshake failed"
    themes = containers._classify_log(text)
    assert themes.get("tls_certificate", 0) >= 1


def test_classify_dns_failure_unchanged() -> None:
    text = "Could not resolve host upstream.invalid\ntemporary failure in name resolution"
    themes = containers._classify_log(text)
    assert themes.get("dns_failure", 0) >= 1


# ---------- finding generation for noisy + themes ----------


def _problem_summary_payload(name: str, themes: dict[str, int], state: str = "running") -> str:
    bucket = "noisy" if state == "running" else "failing"
    return json.dumps(
        {
            "available": True,
            "total": 1,
            "failing": []
            if bucket == "noisy"
            else [
                {
                    "name": name,
                    "image": "img",
                    "state": state,
                    "exit_code": 1,
                    "restart_count": 0,
                    "log_themes": themes,
                    "log_sample": [],
                }
            ],
            "noisy": [
                {
                    "name": name,
                    "image": "img",
                    "state": state,
                    "exit_code": 0,
                    "restart_count": 0,
                    "log_themes": themes,
                    "log_sample": [],
                }
            ]
            if bucket == "noisy"
            else [],
        }
    )


def _summary_item(payload: str) -> EvidenceItem:
    return EvidenceItem(
        source="docker.problem_summary",
        category=EvidenceCategory.logs,
        ok=True,
        title="Container problem summary",
        summary="docker_total=1 failing=0 noisy=1",
        content=payload,
    )


def test_findings_for_bad_network_running_with_dns_errors() -> None:
    payload = _problem_summary_payload("sfai-bad-network", {"dns_failure": 4})
    findings = _findings_from_docker([_summary_item(payload)])
    assert any(
        f.severity == "warning" and "sfai-bad-network" in f.title and "reachab" in f.title.lower()
        for f in findings
    ), [f.title for f in findings]


def test_findings_for_running_with_connection_refused_is_warning() -> None:
    payload = _problem_summary_payload("svc", {"connection_refused": 3})
    findings = _findings_from_docker([_summary_item(payload)])
    assert any(f.severity == "warning" for f in findings)


def test_findings_for_running_with_timeout_is_warning() -> None:
    payload = _problem_summary_payload("svc", {"timeout": 2})
    findings = _findings_from_docker([_summary_item(payload)])
    assert any(f.severity == "warning" for f in findings)


def test_findings_for_running_with_tls_is_warning() -> None:
    payload = _problem_summary_payload("svc", {"tls_certificate": 1})
    findings = _findings_from_docker([_summary_item(payload)])
    assert any(f.severity == "warning" for f in findings)


def test_findings_severity_counts_match() -> None:
    payload = _problem_summary_payload("sfai-bad-network", {"dns_failure": 3})
    findings = _findings_from_docker([_summary_item(payload)])
    counts = displayed_finding_severity_counts(findings)
    assert counts["warning"] >= 1
    # No critical from a noisy/running container.
    assert counts["critical"] == 0


# ---------- ranking hints ----------


def test_ranking_hints_prioritize_app_log_when_runtime_ok() -> None:
    findings = [
        Finding(
            severity="warning",
            title=(
                "sfai-bad-network is running but logs show dns failure (app/container reachability)"
            ),
            detail="themes=dns_failure",
        ),
    ]
    items = [
        SimpleNamespace(source="network.resolution_test", ok=True),
        SimpleNamespace(source="network.default_route", ok=True),
        SimpleNamespace(source="system.container_detect", ok=True),
    ]
    hints = _network_reachability_hints(findings, items)
    assert any("Surface this first" in h for h in hints)
    assert any("does NOT cancel" in h for h in hints)
    assert any("container namespace" in h for h in hints)


def test_ranking_hints_skip_runtime_caveat_when_no_app_finding() -> None:
    findings = [Finding(severity="info", title="all good", detail="")]
    items = [
        SimpleNamespace(source="network.resolution_test", ok=True),
        SimpleNamespace(source="network.default_route", ok=True),
    ]
    hints = _network_reachability_hints(findings, items)
    # No app/container reachability finding -> no "first" hint or runtime cancel hint.
    assert not any("Surface this first" in h for h in hints)
    assert not any("does NOT cancel" in h for h in hints)


# ---------- CLI integration ----------


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


def _fake_diag_with_bad_network(*_a, **_kw):
    findings = [
        Finding(
            severity="warning",
            title=(
                "sfai-bad-network is running but logs show dns failure (app/container reachability)"
            ),
            detail="themes=dns_failure",
        )
    ]
    items = [
        EvidenceItem(
            source="docker.problem_summary",
            category=EvidenceCategory.logs,
            ok=True,
            title="Container problem summary",
            summary="docker_total=5 failing=3 noisy=2 failing_names=sfai-missing-env",
            content="{}",
        ),
        EvidenceItem(
            source="system.container_detect",
            category=EvidenceCategory.host,
            ok=True,
            title="Container detection",
            summary="container=docker",
            content="docker",
        ),
    ]
    return SimpleNamespace(
        session_id="sess-net",
        target="docker",
        target_type=SimpleNamespace(value="generic"),
        findings=findings,
        evidence=SimpleNamespace(
            items=items,
            model_dump_json=lambda indent=2: '{"items":[]}',
        ),
        proposed_plan=SimpleNamespace(model_dump_json=lambda indent=2: "{}"),
        warnings=[],
        errors=[],
    )


def test_ask_network_reachability_includes_ranking_in_prompt(monkeypatch, patch_provider):
    monkeypatch.setattr("shellforgeai.cli.diagnose_target", _fake_diag_with_bad_network)
    monkeypatch.setattr("shellforgeai.core.collectors.collect_network_evidence", lambda _ctx: [])
    res = runner.invoke(app, ["ask", "network reachability is broken"])
    assert res.exit_code == 0, res.stdout
    prompt = patch_provider["provider"].last_prompt or ""
    assert "evidence_ranking" in prompt
    assert "synthesis_hints" in prompt
    assert "sfai-bad-network" in prompt
    # Mention of the boundary: app/container vs host-wide.
    assert "host-wide" in prompt or "container reachability" in prompt
    # Evidence-backed banner shown.
    assert "Evidence-backed ask" in res.stdout


def test_ask_bad_network_target_mentions_container(monkeypatch, patch_provider):
    monkeypatch.setattr("shellforgeai.cli.diagnose_target", _fake_diag_with_bad_network)
    monkeypatch.setattr("shellforgeai.core.collectors.collect_network_evidence", lambda _ctx: [])
    res = runner.invoke(app, ["ask", "why is bad-network failing?"])
    assert res.exit_code == 0, res.stdout
    prompt = patch_provider["provider"].last_prompt or ""
    assert "sfai-bad-network" in prompt


# ---------- safety ----------


@pytest.mark.parametrize(
    "phrase",
    [
        "fix the network",
        "open port 443",
        "change DNS",
        "restart the network",
        "add firewall rule for upstream",
    ],
)
def test_network_mutation_phrases_marked_mutation(phrase: str) -> None:
    assert is_mutation_request(phrase) or route_ask_intent(phrase).mutation_request


def test_ask_network_mutation_does_not_call_apply(monkeypatch, patch_provider):
    monkeypatch.setattr("shellforgeai.cli.diagnose_target", _fake_diag_with_bad_network)
    monkeypatch.setattr("shellforgeai.core.collectors.collect_network_evidence", lambda _ctx: [])
    res = runner.invoke(app, ["ask", "please open port 443 to fix the network"])
    assert res.exit_code == 0, res.stdout
    assert "Safety:" in res.stdout
    assert "read-only" in res.stdout.lower()


def test_apply_remains_validation_only(tmp_path):
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        '{"plan_id":"p1","goal":"g","session_id":"s","steps":[]}',
        encoding="utf-8",
    )
    res = runner.invoke(app, ["apply", str(plan_path)])
    assert res.exit_code == 0
    assert "intentionally disabled" in res.stdout


# ---------- regression: PR26 lab detection unchanged ----------


def _stub_docker(monkeypatch, ps_out: str, inspects: dict, logs_map: dict):
    monkeypatch.setattr(
        containers.host,
        "command_exists",
        lambda c: ToolResult(tool="command.exists", ok=True, stdout="/usr/bin/docker"),
    )

    def fake_run(cmd, timeout=15):
        if cmd[:2] == ["docker", "ps"]:
            return CommandResult(cmd, 0, ps_out, "", 0)
        if cmd[:2] == ["docker", "inspect"]:
            name = cmd[2]
            data = inspects.get(name)
            if data is None:
                return CommandResult(cmd, 1, "", f"inspect failed for {name}", 0)
            return CommandResult(cmd, 0, json.dumps([data]), "", 0)
        if cmd[:2] == ["docker", "logs"]:
            name = cmd[-1]
            return CommandResult(cmd, 0, logs_map.get(name, ""), "", 0)
        return CommandResult(cmd, 1, "", "unmatched", 0)

    monkeypatch.setattr(containers, "run_command", fake_run)


def test_regression_bad_network_finding_still_reaches_diagnosis(monkeypatch):
    ps = "id5\tsfai-bad-network\timg\tUp\trunning\t2 min\t\n"
    inspects = {
        "sfai-bad-network": {
            "Name": "/sfai-bad-network",
            "Id": "x" * 12,
            "Config": {"Image": "img"},
            "RestartCount": 0,
            "State": {
                "Status": "running",
                "Running": True,
                "ExitCode": 0,
                "Error": "",
                "OOMKilled": False,
                "Health": None,
            },
        }
    }
    logs_map = {
        "sfai-bad-network": (
            "Could not resolve host upstream.invalid\nERROR temporary failure in name resolution\n"
        )
    }
    _stub_docker(monkeypatch, ps, inspects, logs_map)
    summary = containers.problem_summary()
    assert summary.ok
    item = EvidenceItem(
        source="docker.problem_summary",
        category=EvidenceCategory.logs,
        ok=True,
        title="Container problem summary",
        summary=summary.stderr,
        content=summary.stdout,
    )
    findings = _findings_from_docker([item])
    titles = " | ".join(f.title for f in findings)
    assert "sfai-bad-network" in titles
    assert any(f.severity == "warning" for f in findings)
