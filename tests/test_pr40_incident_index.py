"""PR40: audit-aware incident index / search tests.

Deterministic, fixture-based. No Docker, no systemd/journal, no network,
no root, no host mutation. All paths are under ``tmp_path``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from shellforgeai.audit.storage import AuditStorage
from shellforgeai.cli import app
from shellforgeai.core.incident_index import (
    INDEX_FILENAME,
    SearchFilters,
    build_index,
    is_did_anything_execute_intent,
    is_incident_search_ask_intent,
    load_index,
    search_items,
    validate_index_payload,
    write_index,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures


@pytest.fixture()
def data_env(tmp_path: Path, monkeypatch):
    data_dir = tmp_path / "sfdata"
    data_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(data_dir))
    monkeypatch.setenv("HOME", str(tmp_path))
    return data_dir


def _write_event(data_dir: Path, payload: dict) -> None:
    audit = data_dir / "audit"
    audit.mkdir(parents=True, exist_ok=True)
    events = audit / "events.jsonl"
    with events.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")


def _make_event(**kwargs) -> dict:
    base = {
        "schema_version": "1",
        "event_id": f"evt_{kwargs.get('id_suffix', '0001')}",
        "timestamp": kwargs.get("timestamp") or datetime.now(UTC).isoformat(),
        "kind": "diagnose",
        "action": "created",
        "status": "success",
        "session_id": kwargs.get("session_id", ""),
        "proposal_id": kwargs.get("proposal_id", ""),
        "proposal_fingerprint": kwargs.get("proposal_fingerprint", ""),
        "target": kwargs.get("target", ""),
        "risk": kwargs.get("risk"),
        "summary": kwargs.get("summary", ""),
        "artifacts": list(kwargs.get("artifacts", [])),
        "safety": {
            "execution_allowed": False,
            "execution_status": "not_executed",
            "mutation_performed": False,
        },
        "details": dict(kwargs.get("details", {})),
    }
    base.update({k: v for k, v in kwargs.items() if k in base})
    if "kind" in kwargs:
        base["kind"] = kwargs["kind"]
    if "action" in kwargs:
        base["action"] = kwargs["action"]
    if "status" in kwargs:
        base["status"] = kwargs["status"]
    return base


def _make_session(data_dir: Path, session_id: str = "sf_pr40_001", target: str = "docker") -> Path:
    sess = data_dir / "artifacts" / session_id
    sess.mkdir(parents=True, exist_ok=True)
    (sess / "evidence.json").write_text(
        json.dumps({"session_id": session_id, "items": [{"source": "docker.ps"}]}),
        encoding="utf-8",
    )
    (sess / "plan.json").write_text(
        json.dumps({"plan_id": f"plan_{session_id}", "steps": []}), encoding="utf-8"
    )
    (sess / "summary.md").write_text(
        f"# Diagnose summary\n\nSession: {session_id}\nTarget: {target}\nType: docker\n",
        encoding="utf-8",
    )
    (sess / "runbook.json").write_text(
        json.dumps(
            {
                "session_id": session_id,
                "target": target,
                "overall_risk": "medium",
                "problems": [{"title": "X"}, {"title": "Y"}],
                "remediation_options": [],
            }
        ),
        encoding="utf-8",
    )
    (sess / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    return sess


def _make_proposal_file(
    data_dir: Path,
    *,
    proposal_id: str = "prop_pr40_001",
    status: str = "approved",
    component: str = "sfai-bad-network",
    risk: str = "medium",
    target: str = "docker",
    reason: str = "approved for PR40 test",
) -> Path:
    pdir = data_dir / "approvals" / status
    pdir.mkdir(parents=True, exist_ok=True)
    path = pdir / f"{proposal_id}.proposal.json"
    payload = {
        "schema_version": "1",
        "proposal_id": proposal_id,
        "created_at": datetime.now(UTC).isoformat(),
        "status": status,
        "source": {"session_id": "sf_pr40_001"},
        "target": target,
        "component": component,
        "kind": "container_env_config_change",
        "title": f"Fix {component}",
        "risk": risk,
        "confidence": "medium",
        "proposed_steps": ["OPERATOR-RUN: edit env file"],
        "rollback": ["revert"],
        "verification": ["docker logs --tail 50"],
        "execution": {"allowed": False, "status": "not_executed"},
        "fingerprint": {"value": "fp_pr40_001"},
        "approval": {"reason": reason},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _make_apply_bundle(
    data_dir: Path, *, proposal_id: str = "prop_pr40_001", bundle_status: str = "created"
) -> Path:
    bdir = data_dir / "apply_bundles" / proposal_id
    bdir.mkdir(parents=True, exist_ok=True)
    preflight = bdir / "apply-preflight.json"
    preflight.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "proposal_id": proposal_id,
                "created_at": datetime.now(UTC).isoformat(),
                "preflight_status": "passed",
                "bundle_status": bundle_status,
                "guard_status": "fresh",
                "risk": "medium",
                "blocked_actions": 0,
                "manual_only_actions": 1,
                "execution_allowed": False,
                "execution_status": "not_executed",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return preflight


def _make_export(
    data_dir: Path,
    *,
    export_id: str = "export_pr40_001",
    source_proposal: str = "prop_pr40_001",
    source_session: str = "sf_pr40_001",
    redacted: bool = True,
) -> Path:
    edir = data_dir / "exports" / export_id
    edir.mkdir(parents=True, exist_ok=True)
    manifest = edir / "export-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "export_id": export_id,
                "created_at": datetime.now(UTC).isoformat(),
                "source_type": "latest-approved",
                "source_session_id": source_session,
                "source_proposal_id": source_proposal,
                "included_files": ["evidence.json", "runbook.md", "proposal.json"],
                "redaction_applied": redacted,
                "execution_allowed": False,
                "execution_status": "not_executed",
                "proposal": {
                    "proposal_id": source_proposal,
                    "risk": "medium",
                    "component": "sfai-bad-network",
                    "title": "Fix sfai-bad-network",
                    "fingerprint": "fp_pr40_001",
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return manifest


def _make_actions(data_dir: Path, *, proposal_id: str = "prop_pr40_001") -> Path:
    adir = data_dir / "actions" / proposal_id
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / "actions.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "created_at": datetime.now(UTC).isoformat(),
                "proposal_id": proposal_id,
                "proposal_component": "sfai-bad-network",
                "proposal_risk": "medium",
                "proposal_status": "approved",
                "status": "compiled",
                "summary": {
                    "total_actions": 3,
                    "blocked": 1,
                    "manual_only": 2,
                    "read_only": 0,
                },
                "execution_allowed": False,
                "execution_status": "not_executed",
                "actions": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (adir / "actions.md").write_text("# actions\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Index build


def test_build_index_from_events_only(data_env: Path):
    _write_event(
        data_env,
        _make_event(
            id_suffix="a01",
            kind="diagnose",
            action="created",
            status="success",
            session_id="sf_pr40_001",
            target="docker",
            summary="diagnose complete for docker",
        ),
    )
    _write_event(
        data_env,
        _make_event(
            id_suffix="a02",
            kind="guard_check",
            action="checked",
            status="refused",
            proposal_id="prop_pr40_001",
            risk="medium",
            summary="guard refused: source drift",
            details={"component": "sfai-bad-network"},
        ),
    )
    index = build_index(data_env)
    assert index.source_counts["events"] == 2
    types = {i.item_type for i in index.items}
    assert types == {"event"}
    summaries = [i.summary for i in index.items]
    assert any("guard refused" in s for s in summaries)


def test_build_index_from_session_artifacts(data_env: Path):
    _make_session(data_env, session_id="sf_pr40_aaa")
    index = build_index(data_env)
    assert index.source_counts["sessions"] == 1
    sessions = [i for i in index.items if i.item_type == "session"]
    assert sessions and sessions[0].session_id == "sf_pr40_aaa"
    assert sessions[0].risk == "medium"
    # No raw evidence body leaks into the index item
    payload = index.to_dict()
    blob = json.dumps(payload)
    assert "docker.ps" not in blob


def test_build_index_from_proposal(data_env: Path):
    _make_proposal_file(data_env)
    index = build_index(data_env)
    assert index.source_counts["proposals"] == 1
    p_items = [i for i in index.items if i.item_type == "proposal"]
    assert p_items
    p = p_items[0]
    assert p.component == "sfai-bad-network"
    assert p.proposal_id == "prop_pr40_001"
    assert p.risk == "medium"
    assert p.status == "approved"


def test_build_index_from_export_manifest(data_env: Path):
    _make_export(data_env)
    index = build_index(data_env)
    assert index.source_counts["exports"] == 1
    e_items = [i for i in index.items if i.item_type == "export"]
    assert e_items
    assert e_items[0].proposal_id == "prop_pr40_001"
    assert "redacted" in e_items[0].tags


def test_build_index_from_apply_preflight(data_env: Path):
    _make_apply_bundle(data_env)
    index = build_index(data_env)
    assert index.source_counts["apply_bundles"] == 1
    items = [i for i in index.items if i.item_type == "apply_bundle"]
    assert items
    assert items[0].kind == "apply_preflight"


def test_build_index_from_actions(data_env: Path):
    _make_actions(data_env)
    index = build_index(data_env)
    assert index.source_counts["actions"] == 1
    items = [i for i in index.items if i.item_type == "actions"]
    assert items and items[0].component == "sfai-bad-network"


def test_build_skips_malformed_source_with_warning(data_env: Path):
    # malformed event line
    audit = data_env / "audit"
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "events.jsonl").write_text("{not json\n", encoding="utf-8")
    # malformed proposal file
    pdir = data_env / "approvals" / "approved"
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "prop_bad.proposal.json").write_text("nope", encoding="utf-8")
    index = build_index(data_env)
    assert index.source_counts["events"] == 0
    assert index.source_counts["proposals"] == 0
    assert any("malformed" in w for w in index.warnings)


def test_build_respects_configured_data_dir(tmp_path: Path):
    custom = tmp_path / "custom_data"
    custom.mkdir(parents=True)
    _write_event(custom, _make_event(id_suffix="c1", summary="hi"))
    index = build_index(custom)
    path = write_index(custom, index)
    assert path == custom / "audit" / INDEX_FILENAME
    assert path.exists()
    # nothing was written under /data
    assert not Path("/data").exists() or not (Path("/data") / "audit" / INDEX_FILENAME).exists()


# ---------------------------------------------------------------------------
# Search


def _build_full(data_env: Path):
    _write_event(
        data_env,
        _make_event(
            id_suffix="s1",
            kind="diagnose",
            action="created",
            status="success",
            session_id="sf_pr40_001",
            target="docker",
            summary="diagnose complete for docker",
        ),
    )
    _write_event(
        data_env,
        _make_event(
            id_suffix="s2",
            kind="guard_check",
            action="checked",
            status="refused",
            proposal_id="prop_pr40_001",
            risk="medium",
            summary="guard refused: source drift on sfai-bad-network",
            details={"component": "sfai-bad-network"},
        ),
    )
    _make_session(data_env, session_id="sf_pr40_001")
    _make_proposal_file(data_env)
    _make_apply_bundle(data_env)
    _make_export(data_env)
    _make_actions(data_env)
    idx = build_index(data_env)
    write_index(data_env, idx)
    return idx


def test_search_freetext_substring_component(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    items = payload["items"]
    matches = search_items(items, query="bad-network")
    assert matches
    assert any("sfai-bad-network" in (m.get("component") or m.get("summary", "")) for m in matches)


def test_search_filter_component(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    matches = search_items(payload["items"], filters=SearchFilters(component="sfai-bad-network"))
    assert matches
    assert all(m.get("component") == "sfai-bad-network" for m in matches)


def test_search_filter_target(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    matches = search_items(payload["items"], filters=SearchFilters(target="docker"))
    assert matches
    assert all(m.get("target") == "docker" for m in matches)


def test_search_filter_kind(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    matches = search_items(payload["items"], filters=SearchFilters(kind="guard_check"))
    assert matches
    assert all(m.get("kind") == "guard_check" for m in matches)


def test_search_filter_status(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    matches = search_items(payload["items"], filters=SearchFilters(status="refused"))
    assert matches
    assert all(m.get("status") == "refused" for m in matches)


def test_search_filter_risk(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    matches = search_items(payload["items"], filters=SearchFilters(risk="medium"))
    assert matches
    assert all(m.get("risk") == "medium" for m in matches)


def test_search_filter_proposal(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    matches = search_items(payload["items"], filters=SearchFilters(proposal="prop_pr40_001"))
    assert matches
    assert all("prop_pr40_001" in (m.get("proposal_id") or "") for m in matches)


def test_search_filter_session(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    matches = search_items(payload["items"], filters=SearchFilters(session="sf_pr40_001"))
    assert matches
    assert all("sf_pr40_001" in (m.get("session_id") or "") for m in matches)


def test_search_combined_filters_and(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    matches = search_items(
        payload["items"],
        filters=SearchFilters(kind="guard_check", risk="medium", status="refused"),
    )
    assert matches
    for m in matches:
        assert m.get("kind") == "guard_check"
        assert m.get("risk") == "medium"
        assert m.get("status") == "refused"


def test_search_no_results_message_cli(data_env: Path):
    _build_full(data_env)
    out = runner.invoke(app, ["audit", "search", "definitely-not-there-token"])
    assert out.exit_code == 0
    assert "No matching audit/index records found." in out.stdout


def test_search_json_output_cli(data_env: Path):
    _build_full(data_env)
    out = runner.invoke(app, ["audit", "search", "--component", "sfai-bad-network", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert isinstance(payload, list)
    assert payload
    assert all(item.get("component") == "sfai-bad-network" for item in payload)


# ---------------------------------------------------------------------------
# CLI: index build / validate


def test_cli_audit_index_builds_and_writes(data_env: Path):
    _write_event(data_env, _make_event(id_suffix="i1", summary="hi"))
    out = runner.invoke(app, ["audit", "index"])
    assert out.exit_code == 0, out.stdout
    assert "Audit index written:" in out.stdout
    assert "execution: none" in out.stdout
    assert (data_env / "audit" / INDEX_FILENAME).exists()


def test_cli_audit_index_rebuild_flag(data_env: Path):
    _write_event(data_env, _make_event(id_suffix="r1", summary="hi"))
    out = runner.invoke(app, ["audit", "index", "--rebuild"])
    assert out.exit_code == 0
    assert "rebuilt" in out.stdout.lower()


def test_cli_audit_index_validate_passes(data_env: Path):
    _write_event(data_env, _make_event(id_suffix="v1", summary="hi"))
    build_out = runner.invoke(app, ["audit", "index"])
    assert build_out.exit_code == 0
    out = runner.invoke(app, ["audit", "index", "validate"])
    assert out.exit_code == 0, out.stdout
    assert "Audit index validation passed" in out.stdout


def test_cli_audit_index_validate_missing(data_env: Path):
    out = runner.invoke(app, ["audit", "index", "validate"])
    assert out.exit_code == 1
    assert "validation failed" in out.stdout.lower()


def test_validate_payload_rejects_malformed_root():
    res = validate_index_payload("nope")
    assert not res.ok
    assert any("must be an object" in e for e in res.errors)


def test_validate_payload_rejects_duplicate_item_id():
    payload = {
        "schema_version": "1",
        "items": [
            {
                "item_id": "idx_dup",
                "item_type": "event",
                "created_at": "",
                "title": "t",
                "summary": "s",
                "paths": [],
                "tags": [],
                "safety": {
                    "execution_allowed": False,
                    "execution_status": "not_executed",
                    "mutation_performed": False,
                },
            },
            {
                "item_id": "idx_dup",
                "item_type": "event",
                "created_at": "",
                "title": "t",
                "summary": "s",
                "paths": [],
                "tags": [],
                "safety": {
                    "execution_allowed": False,
                    "execution_status": "not_executed",
                    "mutation_performed": False,
                },
            },
        ],
    }
    res = validate_index_payload(payload)
    assert not res.ok
    assert any("duplicate item_id" in e for e in res.errors)


def test_validate_payload_rejects_execution_allowed_true():
    payload = {
        "schema_version": "1",
        "items": [
            {
                "item_id": "idx_1",
                "item_type": "event",
                "created_at": "",
                "title": "t",
                "summary": "s",
                "paths": [],
                "tags": [],
                "safety": {
                    "execution_allowed": True,
                    "execution_status": "not_executed",
                    "mutation_performed": False,
                },
            }
        ],
    }
    res = validate_index_payload(payload)
    assert not res.ok
    assert any("execution_allowed must be false" in e for e in res.errors)


def test_validate_payload_rejects_mutation_performed_true():
    payload = {
        "schema_version": "1",
        "items": [
            {
                "item_id": "idx_1",
                "item_type": "event",
                "created_at": "",
                "title": "t",
                "summary": "s",
                "paths": [],
                "tags": [],
                "safety": {
                    "execution_allowed": False,
                    "execution_status": "not_executed",
                    "mutation_performed": True,
                },
            }
        ],
    }
    res = validate_index_payload(payload)
    assert not res.ok
    assert any("mutation_performed must be false" in e for e in res.errors)


def test_validate_payload_rejects_bad_execution_status():
    payload = {
        "schema_version": "1",
        "items": [
            {
                "item_id": "idx_1",
                "item_type": "event",
                "created_at": "",
                "title": "t",
                "summary": "s",
                "paths": [],
                "tags": [],
                "safety": {
                    "execution_allowed": False,
                    "execution_status": "executed",
                    "mutation_performed": False,
                },
            }
        ],
    }
    res = validate_index_payload(payload)
    assert not res.ok
    assert any("execution_status must be 'not_executed'" in e for e in res.errors)


def test_validate_payload_rejects_bad_source_counts():
    payload = {
        "schema_version": "1",
        "source_counts": {"events": "lots"},
        "items": [],
    }
    res = validate_index_payload(payload)
    assert not res.ok
    assert any("must be numeric" in e for e in res.errors)


def test_validate_payload_rejects_bad_paths():
    payload = {
        "schema_version": "1",
        "items": [
            {
                "item_id": "idx_1",
                "item_type": "event",
                "created_at": "",
                "title": "t",
                "summary": "s",
                "paths": ["ok", 5],
                "tags": [],
                "safety": {
                    "execution_allowed": False,
                    "execution_status": "not_executed",
                    "mutation_performed": False,
                },
            }
        ],
    }
    res = validate_index_payload(payload)
    assert not res.ok
    assert any("paths must be a list of strings" in e for e in res.errors)


def test_cli_audit_index_validate_rejects_malformed_index(data_env: Path):
    audit_dir = data_env / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / INDEX_FILENAME).write_text("{not json", encoding="utf-8")
    out = runner.invoke(app, ["audit", "index", "validate"])
    assert out.exit_code == 1
    assert "validation failed" in out.stdout.lower()


# ---------------------------------------------------------------------------
# Ask routing


def test_ask_search_audit_for_bad_network_runs(data_env: Path):
    _build_full(data_env)
    out = runner.invoke(app, ["ask", "search audit for bad-network"])
    assert out.exit_code == 0, out.stdout
    assert "Incident-search results" in out.stdout
    assert "sfai-bad-network" in out.stdout


def test_ask_find_drift_refusals_returns_records(data_env: Path):
    _build_full(data_env)
    out = runner.invoke(app, ["ask", "find drift refusals"])
    assert out.exit_code == 0
    assert "Incident-search results" in out.stdout
    assert "guard_check" in out.stdout or "refused" in out.stdout


def test_ask_did_anything_execute_safe_answer(data_env: Path):
    _build_full(data_env)
    out = runner.invoke(app, ["ask", "did anything execute?"])
    assert out.exit_code == 0
    assert "did not execute" in out.stdout.lower()


def test_ask_intent_recognition():
    assert is_incident_search_ask_intent("search audit for bad-network").matched
    assert is_incident_search_ask_intent("find drift refusals").matched
    assert is_incident_search_ask_intent("show recent guard failures").matched
    assert is_incident_search_ask_intent("find approved proposals").matched
    assert not is_incident_search_ask_intent("how do I restart docker").matched
    assert is_did_anything_execute_intent("did anything execute?")
    assert is_did_anything_execute_intent("did ShellForgeAI run anything")
    assert not is_did_anything_execute_intent("what time is it")


def test_ask_builds_index_if_missing(data_env: Path):
    # Don't build the index up front. Just write a single event so there's
    # something to find when ask routes to incident search.
    _write_event(
        data_env,
        _make_event(
            id_suffix="m1",
            kind="diagnose",
            action="created",
            status="success",
            session_id="sf_pr40_001",
            target="docker",
            summary="diagnose complete for sfai-bad-network",
            details={"component": "sfai-bad-network"},
        ),
    )
    assert not (data_env / "audit" / INDEX_FILENAME).exists()
    out = runner.invoke(app, ["ask", "search audit for bad-network"])
    assert out.exit_code == 0, out.stdout
    assert (data_env / "audit" / INDEX_FILENAME).exists()
    # Building the index does not execute any operator command.
    assert (
        "No commands executed" in out.stdout
        or "did not execute" in out.stdout.lower()
        or "no remediation" in out.stdout.lower()
        or "no commands" in out.stdout.lower()
    )


# ---------------------------------------------------------------------------
# Regression: PR39 audit timeline/show/validate still works


def test_pr39_timeline_still_works(data_env: Path):
    s = AuditStorage(data_env)
    evt = s.write_event(
        kind="diagnose", action="created", status="success", session_id="sf_r1", summary="d"
    )
    out = runner.invoke(app, ["audit", "timeline", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert any(e["event_id"] == evt["event_id"] for e in payload)


def test_pr39_audit_validate_still_works(data_env: Path):
    s = AuditStorage(data_env)
    s.write_event(kind="guard_check", action="checked", status="refused", summary="drift")
    out = runner.invoke(app, ["audit", "validate"])
    assert out.exit_code == 0


# ---------------------------------------------------------------------------
# Safety invariants


def test_index_items_preserve_safety_invariants(data_env: Path):
    _build_full(data_env)
    payload, _ = load_index(data_env)
    assert payload is not None
    for item in payload["items"]:
        s = item["safety"]
        assert s["execution_allowed"] is False
        assert s["execution_status"] == "not_executed"
        assert s["mutation_performed"] is False
