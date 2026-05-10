from __future__ import annotations

from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.ask_routing import (
    EVIDENCE_BACKED,
    PLAIN,
    evidence_brief,
    is_mutation_request,
    route_ask_intent,
)

runner = CliRunner()


# ---------- pure routing ----------


def test_route_plain_for_generic_question() -> None:
    r = route_ask_intent("what is the difference between TCP and UDP?")
    assert r.mode == PLAIN
    assert r.target == ""


def test_route_plain_for_conceptual_explainer() -> None:
    r = route_ask_intent("explain DNS like I am new")
    assert r.mode == PLAIN


def test_route_evidence_backed_for_failed_containers() -> None:
    r = route_ask_intent("find failed containers and explain likely cause")
    assert r.mode == EVIDENCE_BACKED
    assert r.target in {"docker", "logs"}
    assert r.target == "docker"


def test_route_evidence_backed_for_app_restarting() -> None:
    r = route_ask_intent("why is the app restarting?")
    assert r.mode == EVIDENCE_BACKED
    assert r.target == "docker"


def test_route_evidence_backed_for_anything_crashing() -> None:
    r = route_ask_intent("is anything crashing?")
    assert r.mode == EVIDENCE_BACKED
    assert r.target == "docker"


def test_route_evidence_backed_for_write_to_disk() -> None:
    r = route_ask_intent("why can the service not write to disk?")
    assert r.mode == EVIDENCE_BACKED
    assert r.target == "logs"


def test_route_evidence_backed_for_network_reachability() -> None:
    r = route_ask_intent("network reachability is broken")
    assert r.mode == EVIDENCE_BACKED
    assert r.target in {"docker", "network"}


def test_route_evidence_backed_for_disk_full() -> None:
    r = route_ask_intent("is my disk getting full?")
    assert r.mode == EVIDENCE_BACKED
    assert r.target == "disk"


def test_route_evidence_backed_for_perf() -> None:
    r = route_ask_intent("my device feels sluggish")
    assert r.mode == EVIDENCE_BACKED
    assert r.target in {"performance", "host"}


def test_route_evidence_backed_for_service_check() -> None:
    r = route_ask_intent("is nginx running?")
    assert r.mode == EVIDENCE_BACKED
    assert r.target == "nginx"


def test_route_marks_mutation_request_for_restart_nginx() -> None:
    r = route_ask_intent("can you restart nginx?")
    assert r.mode == EVIDENCE_BACKED
    assert r.mutation_request is True


def test_route_marks_mutation_for_open_port() -> None:
    r = route_ask_intent("can you open port 443?")
    assert r.mutation_request is True


def test_route_logs_mutation_refused_routes_to_evidence_logs() -> None:
    r = route_ask_intent("delete logs")
    assert r.mode == EVIDENCE_BACKED
    assert r.target == "logs"
    assert r.mutation_request is True


def test_is_mutation_request_basic() -> None:
    assert is_mutation_request("please restart nginx")
    assert is_mutation_request("install some-package")
    assert not is_mutation_request("how does TCP work?")


def test_evidence_brief_compact() -> None:
    findings = [SimpleNamespace(severity="critical", title="t", detail="d" * 600)]
    items = [
        SimpleNamespace(
            source="docker.containers",
            ok=True,
            title="containers",
            summary="exited=2 running=3",
        )
    ]
    brief = evidence_brief(findings, items)
    assert brief["findings"][0]["severity"] == "critical"
    assert len(brief["findings"][0]["detail"]) <= 400
    assert brief["evidence"][0]["source"] == "docker.containers"


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


def _fake_diagnosis(target: str, findings=None, items=None):
    findings = findings or []
    items = items or []
    return SimpleNamespace(
        session_id="sess-fake",
        target=target,
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


def test_ask_plain_does_not_collect_evidence(monkeypatch, patch_provider):
    called = {"diagnose": False}

    def fake_diag(*a, **k):
        called["diagnose"] = True
        return _fake_diagnosis("host")

    monkeypatch.setattr("shellforgeai.cli.diagnose_target", fake_diag)
    res = runner.invoke(app, ["ask", "what is the difference between TCP and UDP?"])
    assert res.exit_code == 0, res.stdout
    assert called["diagnose"] is False
    assert "Evidence-backed ask:" not in res.stdout


def test_ask_evidence_backed_failed_containers(monkeypatch, patch_provider):
    captured = {}

    def fake_diag(runtime, target, online=False, since="30m"):
        captured["target"] = target
        findings = [
            SimpleNamespace(
                severity="critical",
                title="container exited",
                detail="sfai-missing-env exited 42 (REQUIRED_SETTING missing)",
            ),
            SimpleNamespace(
                severity="critical",
                title="restart loop",
                detail="sfai-restart-loop is restarting",
            ),
        ]
        items = [
            SimpleNamespace(
                source="docker.containers",
                ok=True,
                title="containers",
                summary="exited=2 running=3",
            )
        ]
        return _fake_diagnosis("docker", findings=findings, items=items)

    monkeypatch.setattr("shellforgeai.cli.diagnose_target", fake_diag)
    res = runner.invoke(app, ["ask", "find failed containers and explain likely cause"])
    assert res.exit_code == 0, res.stdout
    assert captured["target"] == "docker"
    assert "Evidence-backed ask:" in res.stdout
    assert "docker" in res.stdout
    # prompt should include the findings
    prompt = patch_provider["provider"].last_prompt or ""
    assert "container exited" in prompt
    assert "restart loop" in prompt


def test_ask_evidence_backed_write_to_disk(monkeypatch, patch_provider):
    captured = {}

    def fake_diag(runtime, target, online=False, since="30m"):
        captured["target"] = target
        return _fake_diagnosis(
            "logs",
            findings=[
                SimpleNamespace(
                    severity="critical",
                    title="write failure",
                    detail="cannot create /data/out.txt (read-only)",
                )
            ],
            items=[
                SimpleNamespace(
                    source="logs.search_errors",
                    ok=True,
                    title="error themes",
                    summary="read-only filesystem",
                )
            ],
        )

    monkeypatch.setattr("shellforgeai.cli.diagnose_target", fake_diag)
    res = runner.invoke(app, ["ask", "why can the service not write to disk?"])
    assert res.exit_code == 0, res.stdout
    assert captured["target"] == "logs"
    prompt = patch_provider["provider"].last_prompt or ""
    assert "read-only" in prompt or "write failure" in prompt


def test_ask_mutation_request_does_not_mutate(monkeypatch, patch_provider):
    captured = {"target": None}

    def fake_diag(runtime, target, online=False, since="30m"):
        captured["target"] = target
        return _fake_diagnosis(target)

    monkeypatch.setattr("shellforgeai.cli.diagnose_target", fake_diag)
    res = runner.invoke(app, ["ask", "can you restart nginx?"])
    assert res.exit_code == 0, res.stdout
    assert captured["target"] == "nginx"
    assert "Safety:" in res.stdout
    assert "read-only" in res.stdout.lower()


def test_ask_no_evidence_flag_disables_routing(monkeypatch, patch_provider):
    called = {"diagnose": False}

    def fake_diag(*a, **k):
        called["diagnose"] = True
        return _fake_diagnosis("docker")

    monkeypatch.setattr("shellforgeai.cli.diagnose_target", fake_diag)
    res = runner.invoke(
        app, ["ask", "--no-evidence", "find failed containers and explain likely cause"]
    )
    assert res.exit_code == 0, res.stdout
    assert called["diagnose"] is False


def test_ask_evidence_collection_failure_degrades(monkeypatch, patch_provider):
    def fake_diag(*a, **k):
        raise RuntimeError("docker unavailable")

    monkeypatch.setattr("shellforgeai.cli.diagnose_target", fake_diag)
    res = runner.invoke(app, ["ask", "find failed containers and explain likely cause"])
    assert res.exit_code == 0, res.stdout
    assert "diagnostic intent" in res.stdout
    assert "shellforgeai diagnose" in res.stdout


def test_apply_remains_validation_only(tmp_path):
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        '{"plan_id":"p1","goal":"g","session_id":"s","steps":[]}',
        encoding="utf-8",
    )
    res = runner.invoke(app, ["apply", str(plan_path)])
    assert res.exit_code == 0
    assert "intentionally disabled" in res.stdout


def test_ask_say_ok_still_works(monkeypatch, patch_provider):
    monkeypatch.setattr(
        "shellforgeai.cli.diagnose_target",
        lambda *a, **k: pytest.fail("plain ask should not call diagnose"),
    )
    res = runner.invoke(app, ["ask", "Say ok."])
    assert res.exit_code == 0, res.stdout
    assert "ok answer" in res.stdout
    assert "Provider: openai-codex" in res.stdout
