"""PR20 polish: friendly mini-report and evidence count consistency."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.repl import (
    _detect_action_request,
    _operator_followup_text,
)
from shellforgeai.render.summary import write_diagnosis_summary_md

runner = CliRunner()


# ---------- summary.md mini-report ----------


class _Item:
    def __init__(self, source: str, summary: str, ok: bool = True) -> None:
        self.source = source
        self.summary = summary
        self.ok = ok
        self.metadata = {"status": "ok" if ok else "unavailable"}


class _Finding:
    def __init__(self, title: str) -> None:
        self.title = title


def _write(tmp_path: Path, items: list[_Item], findings: list[_Finding]) -> Path:
    artifact_dir = tmp_path
    (artifact_dir / "evidence.json").write_text(
        json.dumps({"items": [{"source": i.source} for i in items]}), encoding="utf-8"
    )
    (artifact_dir / "plan.json").write_text("{}", encoding="utf-8")
    summary_path = artifact_dir / "summary.md"
    write_diagnosis_summary_md(
        path=summary_path,
        session_id="s1",
        target="performance",
        target_type="host",
        created_at="2026-05-06T00:00:00+00:00",
        evidence_items=items,
        findings=findings,
        artifact_dir=artifact_dir,
    )
    return summary_path


def test_summary_md_required_sections(tmp_path: Path) -> None:
    items = [
        _Item("system.cpu_memory", "cpus=32 mem=78.1GiB/220.3GiB swap=0B/8.0GiB"),
        _Item("host.resources", "loadavg=2.5,3.0,2.7"),
        _Item("disk.usage", "/ 59% used"),
        _Item("disk.inodes", "/ 45% used"),
        _Item("storage.pressure", "io_some_avg10=0 io_some_avg60=0 io_some_avg300=0"),
    ]
    summary_path = _write(tmp_path, items, [])
    text = summary_path.read_text(encoding="utf-8")
    for required in (
        "# ShellForgeAI Diagnosis Summary",
        "Session: s1",
        "Target: performance",
        "Target type: host",
        "Created: 2026-05-06",
        "Evidence count: 5",
        "Findings count: 0",
        "## Assessment",
        "## Key evidence",
        "## Findings",
        "## Artifacts",
        "## Safety note",
        "No changes were applied",
    ):
        assert required in text, f"missing: {required}"


def test_summary_md_no_findings_message(tmp_path: Path) -> None:
    summary_path = _write(tmp_path, [_Item("disk.usage", "/ 10% used")], [])
    assert "No actionable findings were raised" in summary_path.read_text(encoding="utf-8")


def test_summary_md_lists_only_existing_artifacts(tmp_path: Path) -> None:
    summary_path = _write(tmp_path, [_Item("disk.usage", "/ 10% used")], [])
    text = summary_path.read_text(encoding="utf-8")
    assert "evidence.json" in text
    assert "plan.json" in text
    assert "summary.md" in text
    assert "model-response.md" not in text


def test_summary_md_lists_model_response_when_present(tmp_path: Path) -> None:
    (tmp_path / "model-response.md").write_text("ok", encoding="utf-8")
    summary_path = _write(tmp_path, [_Item("disk.usage", "/ 10% used")], [])
    text = summary_path.read_text(encoding="utf-8")
    assert "model-response.md" in text


def test_summary_md_no_raw_json_dumps(tmp_path: Path) -> None:
    items = [_Item("system.container_detect", 'container={"is_container":"yes"}')]
    summary_path = _write(tmp_path, items, [])
    text = summary_path.read_text(encoding="utf-8")
    assert '{"is_container"' not in text
    assert '{"items"' not in text


def test_summary_md_evidence_count_matches_items(tmp_path: Path) -> None:
    items = [_Item(f"tool.{i}", "x") for i in range(7)]
    summary_path = _write(tmp_path, items, [])
    assert "Evidence count: 7" in summary_path.read_text(encoding="utf-8")


# ---------- CLI evidence count consistency ----------


def test_cli_diagnose_summary_count_matches_evidence_json(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    res = runner.invoke(app, ["diagnose", "disk", "--save-plan"])
    assert res.exit_code == 0
    out = res.output
    ev_line = [ln for ln in out.splitlines() if ln.startswith("Evidence:")][0]
    cli_count = int(ev_line.split()[1])
    artifact_dirs = list(tmp_path.rglob("evidence.json"))
    assert artifact_dirs, "evidence.json not written"
    data = json.loads(artifact_dirs[0].read_text(encoding="utf-8"))
    json_count = len(data["items"])
    assert cli_count == json_count
    summary_paths = list(tmp_path.rglob("summary.md"))
    assert summary_paths, "summary.md not written"
    summary_text = summary_paths[0].read_text(encoding="utf-8")
    assert f"Evidence count: {json_count}" in summary_text


def test_cli_diagnose_does_not_print_phantom_model_response(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    res = runner.invoke(app, ["diagnose", "disk"])
    assert res.exit_code == 0
    assert "- model response: n/a" in res.output


# ---------- followup text polish ----------


def test_followup_text_warmer_phrasing() -> None:
    txt = _operator_followup_text("storage/I/O", "pressure signals and active processes")
    assert "I can dig into the storage/I/O angle next" in txt
    assert "I’ll keep it read-only" in txt
    assert "pass pass" not in txt
    assert "read-only read-only" not in txt


def test_followup_text_strips_pass_suffix() -> None:
    txt = _operator_followup_text("broader read-only health pass", "x")
    assert "broader read-only" not in txt
    assert "health pass" not in txt
    assert "health angle" in txt


# ---------- action request polish ----------


def test_restart_request_does_not_execute_and_stays_concise() -> None:
    txt = _detect_action_request("Can you restart nginx for me?")
    assert txt is not None
    assert "can't run that action" in txt.lower() or "can’t run that action" in txt.lower()
    assert "nginx" in txt
    assert "read-only" in txt
    # not a wall of text
    assert len(txt) < 600


def test_install_request_handled() -> None:
    txt = _detect_action_request("please install htop")
    assert txt is not None
    assert "validation-only" in txt


def test_review_action_phrases_are_not_intercepted() -> None:
    assert _detect_action_request("what would you check before restarting nginx?") is None
    assert _detect_action_request("explain restart of nginx") is None


def test_innocent_question_not_intercepted() -> None:
    assert _detect_action_request("where do I start?") is None
    assert _detect_action_request("how do I install python?") is None
