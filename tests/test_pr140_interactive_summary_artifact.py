"""PR140: interactive session-summary save/validate/export artifacts."""

from __future__ import annotations

import ast
import builtins
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.core.diagnose import DiagnosisResult, Finding
from shellforgeai.core.evidence import EvidenceBundle, EvidenceCategory, EvidenceItem, TargetType
from shellforgeai.core.plans import Plan, PlanStep
from shellforgeai.interactive import repl

runner = CliRunner()


class _NoModelProvider:
    complete_calls = 0

    def complete(self, request):  # noqa: ANN001
        type(self).complete_calls += 1
        raise AssertionError("summary artifact workflow must not call the model")

    def doctor(self):
        return {"provider": "none", "ready": "no"}


def _fake_health_result() -> DiagnosisResult:
    item = EvidenceItem(
        source="host.resources",
        category=EvidenceCategory.host,
        ok=True,
        title="Host resources",
        summary="loadavg 0.10 0.05 0.01",
        content="loadavg 0.10 0.05 0.01",
        metadata={"status": "ok"},
    )
    return DiagnosisResult(
        session_id="sf_pr140_diag",
        target="health",
        target_type=TargetType.host,
        created_at=datetime.now(timezone.utc),
        evidence=EvidenceBundle(target="health", target_type=TargetType.host, items=[item]),
        findings=[Finding(severity="info", title="Read-only health check", detail="Fixture")],
        proposed_plan=Plan(
            plan_id="plan_pr140",
            goal="health",
            session_id="sf_pr140_diag",
            steps=[PlanStep(step_id="1", title="Review", description="Review evidence")],
        ),
        runtime_context={"visibility": "container_limited"},
    )


def _drive_repl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    inputs: list[str],
    *,
    patch_diagnose: bool = True,
) -> tuple[str, type[_NoModelProvider], Path]:
    printed: list[str] = []

    class _Cap:
        def print(self, *args, **kwargs):  # noqa: ANN002, ANN003
            printed.append(" ".join(str(a) for a in args))

        def print_json(self, *args, **kwargs):  # noqa: ANN002, ANN003
            printed.append(str(kwargs.get("data", args)))

        def clear(self):
            printed.append("<clear>")

        def status(self, *args, **kwargs):  # noqa: ANN002, ANN003
            class _Ctx:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *exc):
                    return False

            return _Ctx()

    class _Provider(_NoModelProvider):
        complete_calls = 0

    monkeypatch.setattr(repl, "Console", lambda *a, **k: _Cap())
    monkeypatch.setattr(repl, "_confirm_workspace", lambda *a, **k: True)
    monkeypatch.setattr(repl, "build_provider", lambda *a, **k: _Provider())
    if patch_diagnose:
        monkeypatch.setattr(repl, "diagnose_target", lambda *a, **k: _fake_health_result())
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
    data_dir = tmp_path / "data"
    runtime = SimpleNamespace(
        session=SimpleNamespace(
            session_id="sf_pr140_fixture",
            data_dir=data_dir,
            artifact_dir=data_dir / "artifacts" / "sf_pr140_fixture",
            mode="inspect",
        ),
        profile=SimpleNamespace(name="standard", online_allowed=False, allow_shell_raw=False),
        settings=SimpleNamespace(
            model=SimpleNamespace(provider="fake", model="fake", timeout_seconds=30),
        ),
    )
    data_dir.mkdir(parents=True, exist_ok=True)
    repl.start_interactive(runtime, no_trust_cache=True)
    return "\n".join(printed), _Provider, data_dir


def _json_object_from_output(out: str) -> dict:
    return json.loads(out[out.index("{") : out.rindex("}") + 1])


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def test_summary_save_creates_artifact_and_safe_human_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, provider, data_dir = _drive_repl(monkeypatch, tmp_path, ["/summary --save", "/exit"])
    assert "Session summary saved:" in out
    assert "shellforgeai session summary validate" in out
    assert "shellforgeai session summary export" in out
    assert "execute" not in out.lower()
    assert "restart" not in out.lower()
    saved_dirs = list((data_dir / "interactive_summaries").glob("interactive_summary_*"))
    assert len(saved_dirs) == 1
    artifact = saved_dirs[0]
    assert (artifact / "interactive-summary.json").exists()
    assert (artifact / "interactive-summary.md").exists()
    assert (artifact / "manifest.json").exists()
    assert provider.complete_calls == 0


def test_summary_save_json_is_strict_json_and_artifact_validates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, _provider, data_dir = _drive_repl(
        monkeypatch, tmp_path, ["summary --save --json", "/exit"]
    )
    payload = _json_object_from_output(out)
    assert payload["saved"] is True
    assert payload["summary_id"].startswith("interactive_summary_")
    assert payload["summary_path"].endswith(payload["summary_id"])
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    result = runner.invoke(
        app,
        ["session", "summary", "validate", payload["summary_id"], "--json"],
        env={"SHELLFORGEAI_DATA_DIR": str(data_dir)},
    )
    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["status"] == "ok"


def test_manifest_checksums_and_non_mutating_summary_safety(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, _provider, _data_dir = _drive_repl(
        monkeypatch, tmp_path, ["/summary --save --json", "/exit"]
    )
    payload = _json_object_from_output(out)
    artifact = Path(payload["summary_path"])
    manifest = json.loads((artifact / "manifest.json").read_text(encoding="utf-8"))
    for rel, expected in manifest["checksums"].items():
        assert _sha(artifact / rel) == expected
    summary = json.loads((artifact / "interactive-summary.json").read_text(encoding="utf-8"))
    safety = summary["safety"]
    assert safety["read_only"] is True
    for key in [
        "mutation_performed",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "docker_compose_executed",
        "container_restarted",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
    ]:
        assert safety[key] is False


def test_validate_by_id_and_directory_path_and_controlled_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, _provider, data_dir = _drive_repl(
        monkeypatch, tmp_path, ["/summary --save --json", "/exit"]
    )
    payload = _json_object_from_output(out)
    env = {"SHELLFORGEAI_DATA_DIR": str(data_dir)}
    by_id = runner.invoke(
        app, ["session", "summary", "validate", payload["summary_id"], "--json"], env=env
    )
    by_path = runner.invoke(
        app, ["session", "summary", "validate", payload["summary_path"], "--json"], env=env
    )
    missing = runner.invoke(app, ["session", "summary", "validate", "missing", "--json"], env=env)
    assert by_id.exit_code == 0
    assert by_path.exit_code == 0
    assert missing.exit_code == 1
    assert json.loads(missing.stdout)["status"] == "not_found"
    artifact = Path(payload["summary_path"])
    (artifact / "interactive-summary.json").write_text("{bad", encoding="utf-8")
    malformed = runner.invoke(
        app, ["session", "summary", "validate", payload["summary_id"], "--json"], env=env
    )
    assert malformed.exit_code == 1
    assert json.loads(malformed.stdout)["status"] == "failed"
    assert "Traceback" not in malformed.stdout


def test_export_and_export_validate_are_idempotent_and_controlled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, _provider, data_dir = _drive_repl(
        monkeypatch, tmp_path, ["/summary --save --json", "/exit"]
    )
    payload = _json_object_from_output(out)
    env = {"SHELLFORGEAI_DATA_DIR": str(data_dir)}
    first = runner.invoke(
        app, ["session", "summary", "export", payload["summary_id"], "--json"], env=env
    )
    assert first.exit_code == 0, first.stdout
    exported = json.loads(first.stdout)
    export_path = Path(exported["export"]["path"])
    assert (export_path / "export-manifest.json").exists()
    by_id = runner.invoke(
        app, ["session", "summary", "export-validate", exported["export"]["id"], "--json"], env=env
    )
    by_path = runner.invoke(
        app, ["session", "summary", "export-validate", str(export_path), "--json"], env=env
    )
    assert by_id.exit_code == 0
    assert by_path.exit_code == 0
    second = runner.invoke(
        app, ["session", "summary", "export", payload["summary_id"], "--json"], env=env
    )
    assert second.exit_code == 0
    assert json.loads(second.stdout)["existing"] is True
    missing = runner.invoke(app, ["session", "summary", "export", "missing", "--json"], env=env)
    assert missing.exit_code == 1
    assert json.loads(missing.stdout)["status"] == "not_found"
    assert "Traceback" not in missing.stdout


def test_refused_mutation_prompt_is_recorded_in_saved_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, _provider, _data_dir = _drive_repl(
        monkeypatch, tmp_path, ["restart compose", "/summary --save --json", "/exit"]
    )
    payload = _json_object_from_output(out)
    summary = json.loads((Path(payload["summary_path"]) / "interactive-summary.json").read_text())
    assert summary["refusals"]
    assert any("refused" in refusal for refusal in summary["refusals"])


def test_no_context_summary_can_be_saved_and_validates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out, _provider, data_dir = _drive_repl(
        monkeypatch, tmp_path, ["/summary --save --json", "/exit"], patch_diagnose=False
    )
    payload = _json_object_from_output(out)
    result = runner.invoke(
        app,
        ["session", "summary", "validate", payload["summary_path"], "--json"],
        env={"SHELLFORGEAI_DATA_DIR": str(data_dir)},
    )
    assert result.exit_code == 0


def test_existing_summary_rendering_remains_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    human, _provider, _data_dir = _drive_repl(
        monkeypatch, tmp_path, ["/summary", "/exit"], patch_diagnose=False
    )
    assert "Session summary: read-only inspection session." in human
    assert "No diagnostic evidence has been collected" in human
    json_out, _provider2, _data_dir2 = _drive_repl(
        monkeypatch, tmp_path / "json", ["/summary --json", "/exit"], patch_diagnose=False
    )
    payload = _json_object_from_output(json_out)
    assert payload["mode"] == "interactive_session_summary"
    assert payload["first_safe_command"] == "shellforgeai ops report --brief"


def test_static_safety_invariants_for_summary_artifacts() -> None:
    sources = [
        Path("src/shellforgeai/interactive/repl.py"),
        Path("src/shellforgeai/interactive/commands.py"),
        Path("src/shellforgeai/core/interactive_summary_artifact.py"),
    ]
    joined = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    assert "shell=True" not in joined
    assert "os.system" not in joined
    for forbidden in [
        "cleanup execute",
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "docker compose restart",
        "docker restart",
        "production restart",
    ]:
        assert forbidden not in joined
    for path in sources:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert not (
                    getattr(node.func.value, "id", "") == "subprocess"
                    and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}
                )
