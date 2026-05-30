from __future__ import annotations

import ast
import builtins
import json
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.interactive import repl
from shellforgeai.interactive.commands import route_input
from shellforgeai.llm.schemas import ModelResponse

runner = CliRunner()


def _fake_scene(*, empty: bool = False, visibility: str | None = None) -> dict:
    scene: dict = {"containers": [] if empty else [{"name": "sfai-crashloop", "labels": {}}]}
    if visibility:
        scene["visibility"] = visibility
    return scene


def _fake_ranked(*, empty: bool = False) -> dict:
    if empty:
        return {
            "summary": {"containers_seen": 0, "suspects_ranked": 0, "critical": 0, "high": 0},
            "suspects": [],
        }
    return {
        "summary": {"containers_seen": 2, "suspects_ranked": 2, "critical": 1, "high": 1},
        "suspects": [
            {
                "rank": 1,
                "name": "sfai-crashloop",
                "severity": "critical",
                "confidence": "high",
                "classes": ["restart_storm"],
                "evidence": [
                    {"type": "restart_count", "value": 9},
                    {"type": "exit_code", "value": 1},
                    {"type": "state", "value": "restarting"},
                    {"type": "extra", "value": "bounded away"},
                ],
            },
            {
                "rank": 2,
                "name": "sfai-bad-http",
                "severity": "high",
                "confidence": "high",
                "classes": ["bad_http"],
                "evidence": [{"type": "bad_http", "value": 502}],
            },
        ],
    }


def _patch_ops(
    monkeypatch, tmp_path: Path, *, empty: bool = False, visibility: str | None = None
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.collect_scene",
        lambda: _fake_scene(empty=empty, visibility=visibility),
    )
    monkeypatch.setattr(
        "shellforgeai.core.triage_ranking.rank_scene", lambda scene: _fake_ranked(empty=empty)
    )
    monkeypatch.setattr(
        "shellforgeai.core.self_test.run_self_test_commands",
        lambda profile, include_skipped=False: {"status": "ok", "warnings": []},
    )
    monkeypatch.setattr(
        "shellforgeai.core.disposable_remediation.build_remediation_audit_payload",
        lambda data_dir, latest_only=True: {"status": "ok"},
    )


def _forbidden_mutation_commands() -> tuple[str, ...]:
    return (
        "remediation execute --confirm",
        "rollback execute --confirm",
        "rollback-execute --confirm",
        "cleanup execute --confirm",
        "docker restart",
        "docker compose restart",
        "docker compose up",
        "docker compose down",
        "docker system prune",
        "docker volume prune",
    )


def test_ops_report_brief_renders_bounded_concise_human_output(monkeypatch, tmp_path) -> None:
    _patch_ops(monkeypatch, tmp_path, visibility="container_limited")
    r = runner.invoke(app, ["ops", "report", "--brief"])
    assert r.exit_code == 0
    out = r.stdout
    low = out.lower()
    assert "Status: degraded" in out
    assert "Risk: 1 critical, 1 high Docker suspects" in out
    assert "Visibility: container-limited" in out
    assert "Top issue:" in out
    assert "sfai-crashloop" in out
    assert "Evidence:" in out
    assert out.count("- restart_count") == 1
    assert out.count("\n- ") <= 6
    assert "First safe command:" in out
    assert "shellforgeai triage docker detail sfai-crashloop" in out
    assert "Safety:" in out
    assert "Read-only. No restart, cleanup, remediation, or Compose command executed." in out
    assert "|" not in out
    assert "Artifacts" not in out
    assert "Recommended next steps" not in out
    assert low.count("shellforgeai ") == 1
    for forbidden in _forbidden_mutation_commands():
        assert forbidden not in low


def test_ops_report_brief_no_suspects_falls_back_to_json_command(monkeypatch, tmp_path) -> None:
    _patch_ops(monkeypatch, tmp_path, empty=True)
    r = runner.invoke(app, ["ops", "report", "--brief"])
    assert r.exit_code == 0
    out = r.stdout
    assert "Status: OK / no current suspects" in out
    assert "Risk: no ranked Docker suspects" in out
    assert "Top issue:" not in out
    assert "Evidence:" not in out
    assert "shellforgeai ops report --json" in out
    assert "Read-only. No mutation executed." in out


def test_ops_report_json_remains_strict_and_brief_json_is_unchanged(monkeypatch, tmp_path) -> None:
    _patch_ops(monkeypatch, tmp_path)
    normal = runner.invoke(app, ["ops", "report", "--json"])
    brief = runner.invoke(app, ["ops", "report", "--brief", "--json"])
    assert normal.exit_code == 0
    assert brief.exit_code == 0
    normal_payload = json.loads(normal.stdout)
    brief_payload = json.loads(brief.stdout)
    assert brief_payload == normal_payload
    assert brief_payload["safety"]["read_only"] is True
    assert brief_payload["safety"]["cleanup_executed"] is False
    assert brief_payload["safety"]["remediation_executed"] is False
    assert brief_payload["safety"]["rollback_executed"] is False
    assert brief_payload["safety"]["docker_compose_executed"] is False
    assert brief_payload["safety"]["shell_true"] is False
    assert brief_payload["safety"]["arbitrary_command_execution"] is False
    assert brief_payload["safety"]["natural_language_execution"] is False


def test_ask_pressure_phrases_route_to_brief_without_model(monkeypatch, tmp_path) -> None:
    _patch_ops(monkeypatch, tmp_path)
    monkeypatch.setattr(
        cli_mod,
        "build_provider",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("model must not be called")),
    )
    for phrase in ("no novel", "I have five minutes", "what is on fire, keep it short"):
        r = runner.invoke(app, ["ask", phrase])
        assert r.exit_code == 0
        out = r.stdout
        assert "Read-only brief ops report (deterministic ask routing):" in out
        assert "Status:" in out
        assert "Risk:" in out
        assert "First safe command:" in out
        assert "Recommended next steps" not in out


def test_ask_quick_mutation_phrases_refuse_without_mutation(monkeypatch, tmp_path) -> None:
    _patch_ops(monkeypatch, tmp_path)
    for phrase in ("quickly restart shellforgeai", "no novel, clean up docker"):
        r = runner.invoke(app, ["ask", phrase])
        assert r.exit_code == 0
        out = r.stdout.lower()
        assert "refusing to execute" in out and "execute mutations" in out
        assert "no restart, cleanup, remediation, rollback, docker, or compose command was" in out
        assert "executed" in out
        assert "shellforgeai ops report --brief" in out
        for forbidden in _forbidden_mutation_commands():
            assert forbidden not in out


class _FakeProvider:
    def complete(self, request):  # noqa: ANN001
        return ModelResponse(provider="fake", model="fake", text="Safe ask fallback.", ok=True)

    def doctor(self):
        return {"provider": "fake", "ready": "yes", "auth_cache_present": False}


def _drive_repl(
    monkeypatch, tmp_path: Path, inputs: list[str]
) -> tuple[str, list[tuple[str, ...]]]:
    printed: list[str] = []
    dispatched: list[tuple[str, ...]] = []

    class _Cap:
        def print(self, *args, **kwargs):  # noqa: ANN002, ANN003
            printed.append(" ".join(str(a) for a in args))

        def clear(self):
            printed.append("<clear>")

        def status(self, *args, **kwargs):  # noqa: ANN002, ANN003
            class _Ctx:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *exc):
                    return False

            return _Ctx()

    def _fake_dispatch(console, argv):  # noqa: ANN001
        dispatched.append(tuple(argv))
        console.print(f"DISPATCH {' '.join(argv)}")
        return f"DISPATCH {' '.join(argv)}\n"

    monkeypatch.setattr(repl, "Console", lambda *a, **k: _Cap())
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *a, **k: True)
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: _FakeProvider())
    monkeypatch.setattr(repl, "_run_interactive_cli_dispatch", _fake_dispatch)
    monkeypatch.setattr(repl.WorkspaceTrustStore, "is_trusted", lambda self, p: True)
    monkeypatch.setattr(
        repl,
        "StreamRenderer",
        lambda *a, **k: SimpleNamespace(render=lambda text, *_: printed.append(str(text))),
    )

    seq = iter(inputs)

    def _fake_input(prompt: str = "") -> str:
        try:
            return next(seq)
        except StopIteration as exc:
            raise EOFError from exc

    monkeypatch.setattr(builtins, "input", _fake_input)
    runtime = SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_pr133_fixture",
            data_dir=tmp_path / "data",
            artifact_dir=tmp_path / "data" / "artifacts" / "sf_pr133_fixture",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="fake", model="fake", timeout_seconds=30),
        ),
    )
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    repl.start_interactive(runtime, no_trust_cache=True)
    return "\n".join(printed), dispatched


def test_interactive_pressure_phrases_dispatch_brief_report(monkeypatch, tmp_path) -> None:
    out, dispatched = _drive_repl(monkeypatch, tmp_path, ["no novel", "quick status", "/exit"])
    assert dispatched == [("ops", "report", "--brief"), ("ops", "report", "--brief")]
    assert "DISPATCH ops report --brief" in out


def test_interactive_quick_mutation_refuses(monkeypatch, tmp_path) -> None:
    out, dispatched = _drive_repl(monkeypatch, tmp_path, ["restart it now", "/exit"])
    assert dispatched == []
    low = out.lower()
    assert "no action was taken" in low
    assert "safe read-only alternatives" in low


def test_route_input_supports_brief_flag_and_refuses_quick_mutation() -> None:
    assert route_input("ops report --brief").argv == ("ops", "report", "--brief")
    assert route_input("no novel").argv == ("ops", "report", "--brief")
    assert route_input("restart it now").name == "mutation_refused"


def test_pr133_sources_do_not_add_shell_true_or_arbitrary_execution() -> None:
    touched = [
        Path("src/shellforgeai/cli.py"),
        Path("src/shellforgeai/core/ask_routing.py"),
        Path("src/shellforgeai/interactive/commands.py"),
    ]
    for path in touched:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    assert not (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    )
