from types import SimpleNamespace

from shellforgeai.core.diagnose import diagnose_target
from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem


def _ctx():
    return SimpleNamespace(session=SimpleNamespace(session_id="s1", online_enabled=False))


def _item(source: str, summary: str, ok: bool = True) -> EvidenceItem:
    return EvidenceItem(
        source=source,
        category=EvidenceCategory.service,
        ok=ok,
        title=source,
        summary=summary,
        content=summary,
        metadata={"status": "ok" if ok else "unavailable"},
    )


def test_nginx_absent_process_and_listener_is_warning(monkeypatch):
    monkeypatch.setattr(
        "shellforgeai.core.diagnose.collect_local_knowledge_evidence", lambda *_a, **_k: []
    )
    monkeypatch.setattr(
        "shellforgeai.core.diagnose.collect_service_evidence",
        lambda *_a, **_k: [
            _item("service.processes", "not found", ok=False),
            _item("service.ports", "nginx expected_ports=80,443 listeners=none", ok=True),
            _item("service.manager_detect", "manager=container-none"),
        ],
    )
    monkeypatch.setattr("shellforgeai.core.diagnose.collect_nginx_evidence", lambda *_a, **_k: [])
    res = diagnose_target(_ctx(), "nginx")
    assert any(f.severity == "warning" and "not found running" in f.title for f in res.findings)
