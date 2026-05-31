"""PR141: saved interactive summary history/compare workflow."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _artifact(
    data_dir: Path,
    summary_id: str,
    *,
    created_at: str,
    events_seen: int = 0,
    checks: list[str] | None = None,
    findings: list[str] | None = None,
    refusals: list[str] | None = None,
    safety: dict[str, Any] | None = None,
    artifacts: list[str] | None = None,
    visibility: str = "container_limited",
    first_safe_command: str = "shellforgeai ops report --json",
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
        "events_seen": events_seen,
        "checks": checks or [],
        "findings": findings or [],
        "refusals": refusals or [],
        "latest_artifacts": artifacts or [],
        "first_safe_command": first_safe_command,
        "runtime_context": {"visibility": visibility},
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
        "session": {"session_id": payload["session_id"], "events_seen": events_seen},
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return out


def _env(data_dir: Path) -> dict[str, str]:
    return {"SHELLFORGEAI_DATA_DIR": str(data_dir)}


def _all_files(root: Path) -> set[str]:
    if not root.exists():
        return set()
    return {str(path.relative_to(root)) for path in root.rglob("*")}


def test_history_with_no_summaries_returns_empty_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(app, ["session", "summary", "history", "--json"], env=_env(tmp_path))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "interactive_summary_history"
    assert payload["status"] == "empty"
    assert payload["count"] == 0
    assert payload["read_only"] is True
    assert "Traceback" not in result.stdout


def test_history_with_one_summary_returns_latest_summary(tmp_path: Path) -> None:
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165626_aaaaaa",
        created_at="2026-05-31T16:56:26Z",
        events_seen=2,
        checks=["ops report"],
    )
    result = runner.invoke(app, ["session", "summary", "history", "--json"], env=_env(tmp_path))
    payload = json.loads(result.stdout)
    assert result.exit_code == 0
    assert payload["latest_summary_id"] == "interactive_summary_20260531_165626_aaaaaa"
    assert payload["summaries"][0]["events_seen"] == 2
    assert payload["summaries"][0]["checks_count"] == 1


def test_history_respects_limit(tmp_path: Path) -> None:
    for i in range(3):
        _artifact(
            tmp_path,
            f"interactive_summary_20260531_16562{i}_aaaaaa",
            created_at=f"2026-05-31T16:56:2{i}Z",
        )
    result = runner.invoke(
        app, ["session", "summary", "history", "--limit", "2", "--json"], env=_env(tmp_path)
    )
    payload = json.loads(result.stdout)
    assert payload["limit"] == 2
    assert len(payload["summaries"]) == 2


def test_history_json_emits_strict_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["session", "summary", "history", "--json"], env=_env(tmp_path))
    assert json.loads(result.stdout)["schema_version"] == "1"
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")


def test_history_human_output_includes_latest_and_read_only_safety_note(tmp_path: Path) -> None:
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165626_bbbbbb",
        created_at="2026-05-31T16:56:26Z",
        first_safe_command="shellforgeai ops report --json",
    )
    result = runner.invoke(app, ["session", "summary", "history"], env=_env(tmp_path))
    assert result.exit_code == 0
    assert "Interactive summary history" in result.stdout
    assert "Latest:" in result.stdout
    assert "shellforgeai ops report --json" in result.stdout
    assert "Safety: read-only" in result.stdout
    assert "No collection, mutation" in result.stdout


def test_history_does_not_write_files_or_mutate_state(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_cccccc", created_at="2026-05-31T16:56:26Z"
    )
    before = _all_files(tmp_path)
    result = runner.invoke(app, ["session", "summary", "history", "--json"], env=_env(tmp_path))
    assert result.exit_code == 0
    assert _all_files(tmp_path) == before


def test_compare_two_summaries_returns_status_ok(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    _artifact(
        tmp_path, "interactive_summary_20260531_165727_after", created_at="2026-05-31T16:57:27Z"
    )
    result = runner.invoke(
        app,
        [
            "session",
            "summary",
            "compare",
            "interactive_summary_20260531_165626_before",
            "interactive_summary_20260531_165727_after",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "ok"


def test_compare_detects_new_findings(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165727_after",
        created_at="2026-05-31T16:57:27Z",
        findings=["new disk pressure finding"],
    )
    payload = json.loads(
        runner.invoke(
            app,
            [
                "session",
                "summary",
                "compare",
                "interactive_summary_20260531_165626_before",
                "interactive_summary_20260531_165727_after",
                "--json",
            ],
            env=_env(tmp_path),
        ).stdout
    )
    assert payload["summary"]["new_findings"] == 1
    assert payload["new_findings"] == ["new disk pressure finding"]


def test_compare_detects_missing_or_resolved_findings(tmp_path: Path) -> None:
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165626_before",
        created_at="2026-05-31T16:56:26Z",
        findings=["old noisy finding"],
    )
    _artifact(
        tmp_path, "interactive_summary_20260531_165727_after", created_at="2026-05-31T16:57:27Z"
    )
    payload = json.loads(
        runner.invoke(
            app,
            [
                "session",
                "summary",
                "compare",
                "interactive_summary_20260531_165626_before",
                "interactive_summary_20260531_165727_after",
                "--json",
            ],
            env=_env(tmp_path),
        ).stdout
    )
    assert payload["summary"]["resolved_or_missing_findings"] == 1
    assert payload["resolved_or_missing_findings"] == ["old noisy finding"]


def test_compare_detects_new_refusals(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165727_after",
        created_at="2026-05-31T16:57:27Z",
        refusals=["mutation request refused"],
    )
    payload = json.loads(
        runner.invoke(
            app,
            [
                "session",
                "summary",
                "compare",
                "interactive_summary_20260531_165626_before",
                "interactive_summary_20260531_165727_after",
                "--json",
            ],
            env=_env(tmp_path),
        ).stdout
    )
    assert payload["summary"]["new_refusals"] == 1
    assert payload["new_refusals"] == ["mutation request refused"]


def test_compare_detects_safety_drift_if_safety_flags_differ(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165727_after",
        created_at="2026-05-31T16:57:27Z",
        safety={"runtime_visibility_changed": True},
    )
    result = runner.invoke(
        app,
        [
            "session",
            "summary",
            "compare",
            "interactive_summary_20260531_165626_before",
            "interactive_summary_20260531_165727_after",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["safety_drift"] == 1
    assert payload["safety_drift"][0]["flag"] == "runtime_visibility_changed"


def test_compare_only_changed_suppresses_stable_items(tmp_path: Path) -> None:
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165626_before",
        created_at="2026-05-31T16:56:26Z",
        checks=["ops report"],
    )
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165727_after",
        created_at="2026-05-31T16:57:27Z",
        checks=["ops report"],
    )
    payload = json.loads(
        runner.invoke(
            app,
            [
                "session",
                "summary",
                "compare",
                "interactive_summary_20260531_165626_before",
                "interactive_summary_20260531_165727_after",
                "--only-changed",
                "--json",
            ],
            env=_env(tmp_path),
        ).stdout
    )
    assert payload["stable"] == {}


def test_compare_include_stable_includes_stable_items(tmp_path: Path) -> None:
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165626_before",
        created_at="2026-05-31T16:56:26Z",
        checks=["ops report"],
    )
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165727_after",
        created_at="2026-05-31T16:57:27Z",
        checks=["ops report"],
    )
    payload = json.loads(
        runner.invoke(
            app,
            [
                "session",
                "summary",
                "compare",
                "interactive_summary_20260531_165626_before",
                "interactive_summary_20260531_165727_after",
                "--include-stable",
                "--json",
            ],
            env=_env(tmp_path),
        ).stdout
    )
    assert payload["stable"]["checks"] == ["ops report"]


def test_compare_json_emits_strict_json(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    _artifact(
        tmp_path, "interactive_summary_20260531_165727_after", created_at="2026-05-31T16:57:27Z"
    )
    result = runner.invoke(
        app,
        [
            "session",
            "summary",
            "compare",
            "interactive_summary_20260531_165626_before",
            "interactive_summary_20260531_165727_after",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert json.loads(result.stdout)["mode"] == "interactive_summary_compare"
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")


def test_compare_missing_before_ref_returns_controlled_not_found_and_nonzero(
    tmp_path: Path,
) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165727_after", created_at="2026-05-31T16:57:27Z"
    )
    result = runner.invoke(
        app,
        [
            "session",
            "summary",
            "compare",
            "missing",
            "interactive_summary_20260531_165727_after",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert result.exit_code == 1
    assert json.loads(result.stdout)["status"] == "not_found"
    assert "Traceback" not in result.stdout


def test_compare_missing_after_ref_returns_controlled_not_found_and_nonzero(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    result = runner.invoke(
        app,
        [
            "session",
            "summary",
            "compare",
            "interactive_summary_20260531_165626_before",
            "missing",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert result.exit_code == 1
    assert json.loads(result.stdout)["status"] == "not_found"
    assert "Traceback" not in result.stdout


def test_compare_invalid_json_artifact_returns_controlled_failed_status_and_nonzero(
    tmp_path: Path,
) -> None:
    bad = _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    _artifact(
        tmp_path, "interactive_summary_20260531_165727_after", created_at="2026-05-31T16:57:27Z"
    )
    (bad / "interactive-summary.json").write_text("{bad", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "session",
            "summary",
            "compare",
            "interactive_summary_20260531_165626_before",
            "interactive_summary_20260531_165727_after",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert result.exit_code == 1
    assert json.loads(result.stdout)["status"] == "failed"
    assert "Traceback" not in result.stdout


def test_compare_does_not_write_files_or_mutate_state(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    _artifact(
        tmp_path, "interactive_summary_20260531_165727_after", created_at="2026-05-31T16:57:27Z"
    )
    before = _all_files(tmp_path)
    result = runner.invoke(
        app,
        [
            "session",
            "summary",
            "compare",
            "interactive_summary_20260531_165626_before",
            "interactive_summary_20260531_165727_after",
            "--json",
        ],
        env=_env(tmp_path),
    )
    assert result.exit_code == 0
    assert _all_files(tmp_path) == before


def test_compare_latest_with_fewer_than_two_summaries_returns_controlled_not_enough_data(
    tmp_path: Path,
) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_only", created_at="2026-05-31T16:56:26Z"
    )
    result = runner.invoke(
        app, ["session", "summary", "compare-latest", "--json"], env=_env(tmp_path)
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["compare_latest"] is True
    assert payload["status"] == "not_enough_data"


def test_compare_latest_with_two_summaries_compares_the_latest_two(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    _artifact(
        tmp_path,
        "interactive_summary_20260531_165727_after",
        created_at="2026-05-31T16:57:27Z",
        findings=["new latest finding"],
    )
    payload = json.loads(
        runner.invoke(
            app, ["session", "summary", "compare-latest", "--json"], env=_env(tmp_path)
        ).stdout
    )
    assert payload["status"] == "ok"
    assert payload["compare_latest"] is True
    assert payload["before_summary_id"] == "interactive_summary_20260531_165626_before"
    assert payload["after_summary_id"] == "interactive_summary_20260531_165727_after"
    assert payload["new_findings"] == ["new latest finding"]


def test_compare_latest_json_emits_strict_json(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["session", "summary", "compare-latest", "--json"], env=_env(tmp_path)
    )
    assert json.loads(result.stdout)["mode"] == "interactive_summary_compare"
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")


def test_safety_blocks_and_static_source_forbid_mutation_and_execution(tmp_path: Path) -> None:
    _artifact(
        tmp_path, "interactive_summary_20260531_165626_before", created_at="2026-05-31T16:56:26Z"
    )
    _artifact(
        tmp_path, "interactive_summary_20260531_165727_after", created_at="2026-05-31T16:57:27Z"
    )
    payload = json.loads(
        runner.invoke(
            app, ["session", "summary", "compare-latest", "--json"], env=_env(tmp_path)
        ).stdout
    )
    safety = payload["safety"]
    assert safety["cleanup_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["container_restarted"] is False
    assert safety["shell_true"] is False
    assert safety["arbitrary_command_execution"] is False
    assert safety["natural_language_execution"] is False
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False

    sources = [Path("src/shellforgeai/core/interactive_summary_artifact.py")]
    joined = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    forbidden = [
        "cleanup execute",
        "remediation execute --confirm",
        "rollback-execute --confirm",
        "docker compose restart",
        "docker compose up",
        "docker compose down",
        "docker restart",
        "production restart",
        "shell=True",
        "build_provider(",
        "diagnose_target(",
    ]
    for needle in forbidden:
        assert needle not in joined
    for path in sources:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert not (
                    getattr(node.func.value, "id", "") == "subprocess"
                    and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}
                )
