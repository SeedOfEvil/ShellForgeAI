from __future__ import annotations

from types import SimpleNamespace

from shellforgeai.core.diagnose import Finding, diagnose_target
from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem
from shellforgeai.render.summary import write_diagnosis_summary_md


def _ctx():
    return SimpleNamespace(session=SimpleNamespace(session_id="s1", online_enabled=False))


def _item(source: str, summary: str, content: str = "", ok: bool = True) -> EvidenceItem:
    return EvidenceItem(
        source=source,
        category=EvidenceCategory.logs,
        ok=ok,
        title=source,
        summary=summary,
        content=content or summary,
        metadata={"status": "ok" if ok else "unavailable"},
    )


def _patch_knowledge(monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.diagnose.collect_local_knowledge_evidence", lambda c, q: []
    )


def test_no_storage_error_patterns_do_not_create_warning(monkeypatch):
    _patch_knowledge(monkeypatch)
    monkeypatch.setattr("shellforgeai.core.diagnose.collect_host_evidence", lambda c: [])
    monkeypatch.setattr(
        "shellforgeai.core.diagnose.collect_disk_evidence",
        lambda c: [_item("storage.error_summary", "no recent storage error patterns found")],
    )
    res = diagnose_target(_ctx(), "disk")
    assert not any("storage.error_summary" in f.title.lower() for f in res.findings)


def test_systemctl_missing_in_container_is_limitation(monkeypatch):
    _patch_knowledge(monkeypatch)
    monkeypatch.setattr(
        "shellforgeai.core.diagnose.collect_host_evidence",
        lambda c: [_item("system.container_detect", "container=docker")],
    )
    monkeypatch.setattr(
        "shellforgeai.core.diagnose.collect_service_evidence",
        lambda c, t, since="30m": [_item("systemd.list_failed", "systemctl not found", ok=False)],
    )
    res = diagnose_target(_ctx(), "nginx")
    assert any(f.severity == "limitation" and "systemd" in f.title.lower() for f in res.findings)


def test_nginx_not_found_rolls_up_without_raw_probe_limitations(monkeypatch):
    _patch_knowledge(monkeypatch)
    monkeypatch.setattr("shellforgeai.core.diagnose.collect_host_evidence", lambda c: [])
    monkeypatch.setattr(
        "shellforgeai.core.diagnose.collect_service_evidence",
        lambda c, t, since="30m": [
            _item("process.find nginx", "no matching process", ok=False),
            _item("logs.file_tail", "not found", ok=False),
            _item("systemd.status", "not found", ok=False),
        ],
    )
    monkeypatch.setattr("shellforgeai.core.diagnose.collect_nginx_evidence", lambda c: [])
    res = diagnose_target(_ctx(), "nginx")
    assert (
        sum("nginx was not found in this environment" in f.title.lower() for f in res.findings) == 1
    )
    assert not any("process.find" in f.title for f in res.findings)


def test_nginx_not_found_wording(monkeypatch):
    _patch_knowledge(monkeypatch)
    monkeypatch.setattr("shellforgeai.core.diagnose.collect_host_evidence", lambda c: [])
    monkeypatch.setattr(
        "shellforgeai.core.diagnose.collect_service_evidence",
        lambda c, t, since="30m": [_item("service.status", "no matching process for nginx")],
    )
    monkeypatch.setattr("shellforgeai.core.diagnose.collect_nginx_evidence", lambda c: [])
    res = diagnose_target(_ctx(), "nginx")
    assert any("not found in this environment" in f.title.lower() for f in res.findings)


def test_summary_uses_no_actionable_message(tmp_path):
    p = tmp_path / "summary.md"
    write_diagnosis_summary_md(
        path=p,
        session_id="s1",
        target="performance",
        target_type="host",
        created_at="2026-05-06T00:00:00+00:00",
        evidence_items=[_item("storage.error_summary", "no recent storage error patterns found")],
        findings=[Finding(severity="limitation", title="systemd unavailable", detail="x")],
        artifact_dir=tmp_path,
    )
    t = p.read_text()
    assert "No actionable findings were raised" in t
    assert "Potential issues in storage.error_summary" not in t


def test_summary_humanizes_limitations_and_assessment(tmp_path):
    p = tmp_path / "summary.md"
    write_diagnosis_summary_md(
        path=p,
        session_id="s1",
        target="nginx",
        target_type="service",
        created_at="2026-05-06T00:00:00+00:00",
        evidence_items=[_item("system.container_detect", "container=docker")],
        findings=[
            Finding(
                severity="limitation", title="systemd is unavailable in this container", detail="x"
            ),
            Finding(
                severity="limitation",
                title="journalctl is unavailable in this container",
                detail="x",
            ),
            Finding(
                severity="warning", title="nginx was not found in this environment", detail="x"
            ),
        ],
        artifact_dir=tmp_path,
    )
    t = p.read_text()
    assert "1 warning and 2 context limitations" in t
    assert "systemd.status" not in t
    assert "journal.unit" not in t


def test_summary_rolls_up_raw_systemd_journal_collector_errors(tmp_path):
    p = tmp_path / "summary.md"
    write_diagnosis_summary_md(
        path=p,
        session_id="s1",
        target="nginx",
        target_type="service",
        created_at="2026-05-06T00:00:00+00:00",
        evidence_items=[_item("system.container_detect", "container=docker")],
        findings=[
            Finding(severity="limitation", title="systemd.status reported error", detail="x"),
            Finding(severity="limitation", title="journal.unit reported error", detail="x"),
            Finding(severity="limitation", title="systemd.list_failed reported error", detail="x"),
            Finding(
                severity="warning", title="nginx was not found in this environment", detail="x"
            ),
        ],
        artifact_dir=tmp_path,
    )
    t = p.read_text()
    assert "systemd.status reported error" not in t
    assert "journal.unit reported error" not in t
    assert "systemd.list_failed reported error" not in t
    assert t.count("systemd and journal checks are unavailable in this container") == 1
    assert "Findings count: 2" in t
    assert "Findings severity: 0 critical, 1 warning, 1 info/limitations" in t
