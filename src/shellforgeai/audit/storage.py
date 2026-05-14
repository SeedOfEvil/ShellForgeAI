from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REQUIRED_EVENT_FIELDS = {
    "schema_version",
    "event_id",
    "timestamp",
    "kind",
    "action",
    "status",
    "session_id",
    "proposal_id",
    "proposal_fingerprint",
    "target",
    "risk",
    "summary",
    "artifacts",
    "safety",
    "details",
}


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str]
    event_count: int


class AuditStorage:
    def __init__(self, base: Path):
        self.base = base.expanduser()
        self.sessions_dir = self.base / "sessions"
        self.audit_dir = self.base / "audit"
        self.events_path = self.audit_dir / "events.jsonl"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        (self.base / "artifacts").mkdir(parents=True, exist_ok=True)

    def append(self, record: dict) -> None:
        sid = record["session_id"]
        p = self.sessions_dir / f"{sid}.json"
        p.write_text(json.dumps(record, indent=2), encoding="utf-8")
        with (self.sessions_dir / "sessions.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def write_event(self, **kwargs: Any) -> dict[str, Any]:
        # PR47: allow a single scoped mutation event. Callers must pass an
        # explicit ``safety`` block to opt in; every other event keeps the
        # historical strict no-execution invariant.
        safety_override = kwargs.get("safety")
        safety: dict[str, Any]
        if isinstance(safety_override, dict):
            safety = {
                "execution_allowed": bool(safety_override.get("execution_allowed", False)),
                "execution_status": str(safety_override.get("execution_status", "not_executed")),
                "mutation_performed": bool(safety_override.get("mutation_performed", False)),
            }
            scope = safety_override.get("mutation_scope")
            if scope:
                safety["mutation_scope"] = str(scope)
        else:
            safety = {
                "execution_allowed": False,
                "execution_status": "not_executed",
                "mutation_performed": False,
            }
        event = {
            "schema_version": "1",
            "event_id": kwargs.get("event_id") or self._new_event_id(),
            "timestamp": kwargs.get("timestamp") or datetime.now(UTC).isoformat(),
            "kind": kwargs.get("kind", "ask"),
            "action": kwargs.get("action", "checked"),
            "status": kwargs.get("status", "success"),
            "session_id": kwargs.get("session_id"),
            "proposal_id": kwargs.get("proposal_id"),
            "proposal_fingerprint": kwargs.get("proposal_fingerprint"),
            "target": kwargs.get("target"),
            "risk": kwargs.get("risk"),
            "summary": kwargs.get("summary", ""),
            "artifacts": list(kwargs.get("artifacts", [])),
            "safety": safety,
            "details": dict(kwargs.get("details", {})),
        }
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        return event

    def read_events(self) -> list[dict[str, Any]]:
        if not self.events_path.exists():
            return []
        rows = []
        for line in self.events_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
        return rows

    def query_events(
        self,
        *,
        session_id: str | None = None,
        proposal_id: str | None = None,
        kind: str | None = None,
        since: str | None = None,
        latest: bool = False,
    ) -> list[dict[str, Any]]:
        events = self.read_events()
        if since:
            events = [e for e in events if str(e.get("timestamp", "")) >= since]
        if session_id:
            events = [e for e in events if e.get("session_id") == session_id]
        if proposal_id:
            events = [e for e in events if e.get("proposal_id") == proposal_id]
        if kind:
            events = [e for e in events if e.get("kind") == kind]
        events.sort(key=lambda e: str(e.get("timestamp", "")))
        if latest and events:
            ref = events[-1].get("session_id") or events[-1].get("proposal_id")
            if ref:
                events = [
                    e for e in events if e.get("session_id") == ref or e.get("proposal_id") == ref
                ]
        return events

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        for event in self.read_events():
            if event.get("event_id") == event_id:
                return event
        return None

    def validate_events(self) -> ValidationResult:
        errors: list[str] = []
        if not self.events_path.exists():
            return ValidationResult(ok=True, errors=[], event_count=0)
        seen: set[str] = set()
        count = 0
        for idx, line in enumerate(
            self.events_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            count += 1
            try:
                event = json.loads(line)
            except Exception:
                errors.append(f"line {idx} malformed JSON")
                continue
            missing = sorted(REQUIRED_EVENT_FIELDS - set(event.keys()))
            if missing:
                errors.append(f"line {idx} missing required fields: {','.join(missing)}")
            eid = str(event.get("event_id", ""))
            if eid in seen:
                errors.append(f"duplicate event_id: {eid}")
            seen.add(eid)
            safety = event.get("safety", {})
            # PR47: a single, narrowly-scoped real mutation event type is
            # allowed. Audit validation accepts it only when the kind, action,
            # scope, and status all line up exactly; every other event must
            # remain strict no-execution.
            is_allowed_mutation_event = (
                event.get("kind") == "execution"
                and event.get("action") == "lab_container_restart"
                and safety.get("mutation_scope") == "lab_container_restart_only"
            )
            if is_allowed_mutation_event:
                if safety.get("execution_allowed") is not True:
                    errors.append(
                        f"event {eid} lab_container_restart execution_allowed must be true"
                    )
                if safety.get("execution_status") != "executed":
                    errors.append(
                        f"event {eid} lab_container_restart execution_status must be 'executed'"
                    )
                if safety.get("mutation_performed") is not True:
                    errors.append(
                        f"event {eid} lab_container_restart mutation_performed must be true"
                    )
            else:
                if safety.get("execution_allowed") is not False:
                    errors.append(f"event {eid} execution_allowed must be false")
                if safety.get("execution_status") != "not_executed":
                    errors.append(f"event {eid} execution_status must be not_executed")
                if safety.get("mutation_performed") is not False:
                    errors.append(f"event {eid} mutation_performed must be false")
        return ValidationResult(ok=not errors, errors=errors, event_count=count)

    def list_sessions(self) -> list[str]:
        return sorted(
            [p.stem for p in self.sessions_dir.glob("*.json") if p.name != "sessions.jsonl"]
        )

    def show(self, sid: str) -> str | None:
        p = self.sessions_dir / f"{sid}.json"
        return p.read_text() if p.exists() else None

    def _new_event_id(self) -> str:
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        return f"evt_{stamp}_{uuid.uuid4().hex[:8]}"
