"""PR142: exported interactive summary compare workflow."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _env(data_dir: Path) -> dict[str, str]:
    return {"SHELLFORGEAI_DATA_DIR": str(data_dir)}


def _summary(
    data_dir: Path,
    summary_id: str,
    *,
    created_at: str = "2026-05-31T17:00:00Z",
    checks: list[str] | None = None,
    findings: list[str] | None = None,
    refusals: list[str] | None = None,
    artifacts: list[str] | None = None,
    safe: str = "shellforgeai ops report --json",
    safety: dict[str, Any] | None = None,
) -> Path:
    out = data_dir / "interactive_summaries" / summary_id
    out.mkdir(parents=True)
    payload = {
        "schema_version": "1",
        "mode": "interactive_session_summary",
        "status": "ok",
        "summary_id": summary_id,
        "summary_path": str(out),
        "session_id": f"session-{summary_id}",
        "created_at": created_at,
        "events_seen": 1,
        "checks": checks or [],
        "findings": findings or [],
        "refusals": refusals or [],
        "latest_artifacts": artifacts or [],
        "first_safe_command": safe,
        "runtime_context": {"visibility": "container_limited"},
        "read_only": True,
        "mutation_performed": False,
        "saved": True,
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "cleanup_executed": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "production_restart_executed": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "natural_language_execution": False,
            **(safety or {}),
        },
    }
    (out / "interactive-summary.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "interactive-summary.md").write_text("# summary\n", encoding="utf-8")
    manifest = {
        "schema_version": "1",
        "kind": "interactive_session_summary",
        "mode": "interactive_session_summary_artifact",
        "summary_id": summary_id,
        "created_at": created_at,
        "source": "test",
        "files": ["interactive-summary.json", "interactive-summary.md", "manifest.json"],
        "checksums": {
            "interactive-summary.json": _sha(out / "interactive-summary.json"),
            "interactive-summary.md": _sha(out / "interactive-summary.md"),
        },
        "safety": payload["safety"],
        "session": {"session_id": payload["session_id"], "events_seen": 1},
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return out


def _export(data_dir: Path, summary_id: str) -> str:
    result = runner.invoke(
        app, ["session", "summary", "export", summary_id, "--json"], env=_env(data_dir)
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    return payload["export"]["id"]


def _pair(data_dir: Path) -> tuple[str, str]:
    _summary(
        data_dir,
        "interactive_summary_20260531_170000_before",
        checks=["disk checked", "health checked"],
        findings=["disk ok", "cpu ok"],
        refusals=["refused restart"],
        artifacts=["artifact-a"],
    )
    _summary(
        data_dir,
        "interactive_summary_20260531_170100_after",
        created_at="2026-05-31T17:01:00Z",
        checks=["disk checked", "network checked"],
        findings=["disk ok", "memory pressure"],
        refusals=["refused restart", "refused cleanup"],
        artifacts=["artifact-b"],
    )
    return (
        _export(data_dir, "interactive_summary_20260531_170000_before"),
        _export(data_dir, "interactive_summary_20260531_170100_after"),
    )


def _compare(data_dir: Path, before: str, after: str, *extra: str):
    return runner.invoke(
        app,
        ["session", "summary", "compare-export", before, after, *extra],
        env=_env(data_dir),
    )


def _files(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {str(path.relative_to(root)): _sha(path) for path in root.rglob("*") if path.is_file()}


def _rewrite_export_checksums(export_dir: Path) -> None:
    manifest_path = export_dir / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for rel in ["interactive-summary.json", "interactive-summary.md", "manifest.json"]:
        manifest["checksums"][rel] = _sha(export_dir / rel)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_compare_export_valid_exports_returns_status_ok(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    result = _compare(tmp_path, before, after, "--json")
    payload = json.loads(result.stdout)
    assert result.exit_code == 0
    assert payload["status"] == "ok"
    assert payload["mode"] == "interactive_summary_compare_export"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_compare_export_json_emits_strict_json(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    result = _compare(tmp_path, before, after, "--json")
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["safety"]["shell_true"] is False


def test_compare_export_human_output_has_title_and_refs(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    result = _compare(tmp_path, before, after)
    assert result.exit_code == 0
    assert "Interactive summary export compare" in result.stdout
    assert "Before export:" in result.stdout
    assert before in result.stdout
    assert "After export:" in result.stdout
    assert after in result.stdout
    assert "Before summary:" in result.stdout
    assert "After summary:" in result.stdout
    assert "No collectors/model/shell/mutation" in result.stdout


def test_compare_export_detects_changed_finding_check_and_refusal(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    payload = json.loads(_compare(tmp_path, before, after, "--json").stdout)
    fields = {change["field"] for change in payload["changes"]}
    assert {"checks", "findings", "refusals"}.issubset(fields)
    assert "network checked" in payload["new_checks"]
    assert "memory pressure" in payload["new_findings"]
    assert "refused cleanup" in payload["new_refusals"]


def test_compare_export_include_stable_reports_stable_items(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    payload = json.loads(_compare(tmp_path, before, after, "--include-stable", "--json").stdout)
    assert payload["stable"]["checks"] == ["disk checked"]
    assert payload["stable"]["findings"] == ["disk ok"]
    assert payload["summary"]["stable"] >= 2


def test_compare_export_only_changed_suppresses_stable_items(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    payload = json.loads(
        _compare(tmp_path, before, after, "--include-stable", "--only-changed", "--json").stdout
    )
    assert payload["stable"] == {}


def test_compare_export_same_export_ok_with_no_changes(tmp_path: Path) -> None:
    before, _after = _pair(tmp_path)
    payload = json.loads(_compare(tmp_path, before, before, "--include-stable", "--json").stdout)
    assert payload["status"] == "ok"
    assert payload["changes"] == []
    assert payload["summary"]["new"] == 0
    assert payload["summary"]["resolved_or_missing"] == 0
    assert payload["summary"]["stable"] > 0


def test_compare_export_missing_before_ref_nonzero_not_found(tmp_path: Path) -> None:
    _summary(tmp_path, "interactive_summary_20260531_170100_after")
    after = _export(tmp_path, "interactive_summary_20260531_170100_after")
    result = _compare(tmp_path, "export_interactive_summary_missing", after, "--json")
    payload = json.loads(result.stdout)
    assert result.exit_code != 0
    assert payload["status"] == "not_found"
    assert "Traceback" not in result.stdout


def test_compare_export_missing_after_ref_nonzero_not_found(tmp_path: Path) -> None:
    _summary(tmp_path, "interactive_summary_20260531_170000_before")
    before = _export(tmp_path, "interactive_summary_20260531_170000_before")
    result = _compare(tmp_path, before, "export_interactive_summary_missing", "--json")
    payload = json.loads(result.stdout)
    assert result.exit_code != 0
    assert payload["status"] == "not_found"
    assert "Traceback" not in result.stdout


def test_compare_export_malformed_export_controlled_failure(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    (tmp_path / "exports" / before / "interactive-summary.json").write_text(
        "{bad", encoding="utf-8"
    )
    result = _compare(tmp_path, before, after, "--json")
    payload = json.loads(result.stdout)
    assert result.exit_code != 0
    assert payload["status"] == "failed"
    assert "malformed json" in " ".join(payload["warnings"])
    assert "Traceback" not in result.stdout


def test_compare_export_safety_drift_is_detected(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    export_dir = tmp_path / "exports" / after
    summary_path = export_dir / "interactive-summary.json"
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    payload["safety"]["container_restarted"] = True
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path = export_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["safety"]["container_restarted"] = True
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _rewrite_export_checksums(export_dir)
    result = _compare(tmp_path, before, after, "--json")
    payload = json.loads(result.stdout)
    assert result.exit_code == 0
    assert payload["summary"]["safety_drift"] >= 1
    assert any(item["flag"] == "container_restarted" for item in payload["safety_drift"])


def test_compare_export_never_reruns_collectors(tmp_path: Path, monkeypatch) -> None:
    before, after = _pair(tmp_path)

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("collector must not run")

    monkeypatch.setattr("shellforgeai.tools.host.collect", _boom, raising=False)
    monkeypatch.setattr("shellforgeai.tools.containers.collect", _boom, raising=False)
    result = _compare(tmp_path, before, after, "--json")
    assert result.exit_code == 0, result.stdout


def test_compare_export_never_calls_model_codex(tmp_path: Path, monkeypatch) -> None:
    before, after = _pair(tmp_path)
    monkeypatch.setattr(
        "shellforgeai.cli.build_provider",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("model")),
    )
    result = _compare(tmp_path, before, after, "--json")
    assert result.exit_code == 0, result.stdout


def test_compare_export_never_executes_shell_or_subprocess(tmp_path: Path, monkeypatch) -> None:
    before, after = _pair(tmp_path)
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("run"))
    )
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("popen"))
    )
    result = _compare(tmp_path, before, after, "--json")
    assert result.exit_code == 0, result.stdout


def test_compare_export_never_mutates_files_beyond_existing_artifacts(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    before_files = _files(tmp_path)
    result = _compare(tmp_path, before, after, "--json")
    assert result.exit_code == 0, result.stdout
    assert _files(tmp_path) == before_files


def test_compare_export_rejects_unsafe_paths(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    result = _compare(tmp_path, "/etc/passwd", after, "--json")
    payload = json.loads(result.stdout)
    assert result.exit_code != 0
    assert payload["status"] == "failed"
    assert "unsafe export reference" in " ".join(payload["warnings"])
    assert before


def test_export_validate_still_passes_for_compared_exports(tmp_path: Path) -> None:
    before, after = _pair(tmp_path)
    for export_ref in (before, after):
        result = runner.invoke(
            app, ["session", "summary", "export-validate", export_ref, "--json"], env=_env(tmp_path)
        )
        assert result.exit_code == 0, result.stdout
        assert json.loads(result.stdout)["status"] == "ok"
