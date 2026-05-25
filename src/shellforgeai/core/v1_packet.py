from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from shellforgeai.core.ask_routing import is_mutation_request, is_ops_report_ask
from shellforgeai.core.ops_report_artifact import (
    FORBIDDEN_COMMAND_FRAGMENTS,
    _resolve_ref,
    _safety,
    _sha256_file,
)

SCHEMA_VERSION = 1
PACKET_MODE = "v1_readiness_packet"

REQUIRED_PACKET_FILES = ("v1-packet.json", "v1-packet.md", "manifest.json")
REQUIRED_EXPORT_FILES = (*REQUIRED_PACKET_FILES, "export-manifest.json")


def _now_utc() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _packet_id() -> str:
    import uuid
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"v1_packet_{stamp}_{uuid.uuid4().hex[:6]}"


def _check(status: str, **kwargs: Any) -> dict[str, Any]:
    return {"status": status, **kwargs}


def build_packet(app: Any) -> dict[str, Any]:
    runner = CliRunner()

    def invoke(argv: list[str]) -> tuple[int, str]:
        r = runner.invoke(app, argv)
        return r.exit_code, r.stdout or ""

    checks: dict[str, Any] = {}
    docs = [
        "README.md",
        "docs/v1-scope.md",
        "docs/V1_COMMAND_SURFACE.md",
        "docs/safety.md",
        "docs/demo.md",
    ]
    optional_docs = ["docs/V1_VALIDATION.md"]
    missing = [d for d in docs if not Path(d).exists()]
    checks["docs_contract"] = _check(
        "ok" if not missing else "failed",
        present=[d for d in docs if Path(d).exists()],
        missing=missing,
    )

    command_surface = (
        Path("docs/V1_COMMAND_SURFACE.md").read_text(encoding="utf-8")
        if Path("docs/V1_COMMAND_SURFACE.md").exists()
        else ""
    )
    has_classes = all(x in command_surface for x in ("READ_ONLY", "ARTIFACT_WRITE"))
    checks["command_surface"] = _check(
        "ok" if has_classes else "failed", has_safety_classes=has_classes
    )

    c, out = invoke(["v1", "check", "--profile", "standard", "--json"])
    v1_payload = json.loads(out) if c == 0 and out.strip().startswith("{") else {"status": "failed"}
    checks["v1_check"] = _check(
        v1_payload.get("status", "failed"), summary=v1_payload.get("summary", {})
    )

    c, out = invoke(["ops", "report", "--json"])
    ops_payload = (
        json.loads(out) if c == 0 and out.strip().startswith("{") else {"status": "failed"}
    )
    checks["ops_report"] = _check(
        ops_payload.get("status", "failed"), summary=ops_payload.get("summary", {})
    )

    asks_ops = is_ops_report_ask("It's 2AM, what is on fire?")
    asks_refusal = is_mutation_request("please restart shellforgeai")
    checks["ask_routes"] = _check("ok" if asks_ops else "failed", deterministic_ops_route=asks_ops)
    checks["mutation_refusal"] = _check(
        "ok" if asks_refusal else "failed", deterministic_refusal=asks_refusal
    )

    c, out = invoke(["remediation", "self-test", "--profile", "full", "--json"])
    rem_payload = (
        json.loads(out) if c == 0 and out.strip().startswith("{") else {"status": "failed"}
    )
    checks["remediation_self_test"] = _check(
        rem_payload.get("status", "failed"), summary=rem_payload.get("summary", {})
    )

    safety = _safety()
    checks["safety"] = _check(
        "ok"
        if all(v is False for k, v in safety.items() if k != "read_only") and safety["read_only"]
        else "failed",
        flags=safety,
    )

    passed = sum(1 for v in checks.values() if v.get("status") == "ok")
    failed = sum(1 for v in checks.values() if v.get("status") == "failed")
    warned = sum(1 for v in checks.values() if v.get("status") == "warn")
    status = "failed" if failed else ("warn" if warned else "ok")

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": PACKET_MODE,
        "status": status,
        "created_at": _now_utc(),
        "v1": {
            "scope": "CLI-first Linux/Docker operator knife",
            "non_goals": [
                "mutation",
                "production remediation execution",
                "web ui",
                "secrets/config sprawl",
                "platform sprawl",
            ],
        },
        "checks": checks,
        "summary": {"passed": passed, "failed": failed, "warned": warned, "status": status},
        "safe_next_commands": [
            "shellforgeai v1 check --profile standard --json",
            "shellforgeai ops report --json",
            "shellforgeai remediation self-test --profile full --json",
            "shellforgeai ops report --save",
        ],
        "safety": safety,
        "warnings": (
            []
            if Path(optional_docs[0]).exists()
            else ["docs/V1_VALIDATION.md not present (optional)"]
        ),
    }


def save_packet(packet: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    pid = _packet_id()
    d = data_dir / "v1_packets" / pid
    d.mkdir(parents=True, exist_ok=False)
    (d / "v1-packet.json").write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    md = ["V1 readiness packet", "", f"Status: {packet.get('status', 'failed')}", "", "Checks:"]
    for name, check in (packet.get("checks") or {}).items():
        md.append(f"- {name.replace('_', ' ')}: {check.get('status')}")
    (d / "v1-packet.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    checksums = {f: _sha256_file(d / f) for f in ("v1-packet.json", "v1-packet.md")}
    manifest = {
        "packet_id": pid,
        "created_at": _now_utc(),
        "schema_version": SCHEMA_VERSION,
        "required_files": list(REQUIRED_PACKET_FILES),
        "checksums": checksums,
        "safety": packet.get("safety") or _safety(),
        "source_command": "shellforgeai v1 packet --save",
    }
    (d / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    checksums["manifest.json"] = _sha256_file(d / "manifest.json")
    return {"status": "saved", "packet_id": pid, "packet_path": str(d), "checksums": checksums}


def validate_packet(packet_ref: str, data_dir: Path) -> dict[str, Any]:
    d = _resolve_ref(packet_ref, data_dir / "v1_packets")
    checks = {
        k: False
        for k in [
            "required_files",
            "json_parse",
            "schema",
            "manifest",
            "checksums",
            "safety",
            "safe_commands",
            "status_consistency",
        ]
    }
    if d is None:
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_validate",
            "status": "error",
            "checks": checks,
            "warnings": ["unsafe packet reference"],
        }
    if d.is_file() and d.name == "v1-packet.json":
        d = d.parent
    if not d.exists():
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_validate",
            "status": "not_found",
            "checks": checks,
            "warnings": ["packet not found"],
        }
    if any(not (d / f).exists() for f in REQUIRED_PACKET_FILES):
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_validate",
            "status": "failed",
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        packet = json.loads((d / "v1-packet.json").read_text(encoding="utf-8"))
        manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_validate",
            "status": "failed",
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["schema"] = packet.get("schema_version") == 1 and packet.get("mode") == PACKET_MODE
    checks["manifest"] = manifest.get("packet_id") == d.name
    checks["checksums"] = all(
        _sha256_file(d / rel) == expected
        for rel, expected in (manifest.get("checksums") or {}).items()
        if (d / rel).exists()
    )
    s = packet.get("safety") or {}
    checks["safety"] = all((k in s and s[k] is v) for k, v in _safety().items())
    cmds = [str(c).lower() for c in packet.get("safe_next_commands") or []]
    checks["safe_commands"] = not any(
        any(b in c for b in FORBIDDEN_COMMAND_FRAGMENTS) for c in cmds
    )
    summary = packet.get("summary") or {}
    checks["status_consistency"] = packet.get("status") == summary.get("status")
    status = "ok" if all(checks.values()) else "failed"
    return {
        "schema_version": 1,
        "mode": "v1_readiness_packet_validate",
        "status": status,
        "checks": checks,
        "warnings": [],
    }


def export_packet(packet_ref: str, data_dir: Path) -> dict[str, Any]:
    validation = validate_packet(packet_ref, data_dir)
    if validation.get("status") == "not_found":
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_export",
            "status": "not_found",
            "safety": _safety(),
        }
    if validation.get("status") != "ok":
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_export",
            "status": "failed",
            "safety": _safety(),
            "warnings": ["source packet validation failed"],
        }
    src = _resolve_ref(packet_ref, data_dir / "v1_packets")
    if src and src.is_file():
        src = src.parent
    assert src is not None
    out = data_dir / "exports" / f"export_{src.name}"
    if out.exists():
        vv = validate_packet_export(out.name, data_dir)
        if vv.get("status") == "ok":
            return {
                "schema_version": 1,
                "mode": "v1_readiness_packet_export",
                "status": "exported",
                "existing": True,
                "export": {"id": out.name, "path": str(out)},
                "safety": _safety(),
            }
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_export",
            "status": "already_exists",
            "export": {"id": out.name, "path": str(out)},
            "warnings": ["existing export path failed validation"],
            "safety": _safety(),
        }
    out.mkdir(parents=True, exist_ok=False)
    for f in REQUIRED_PACKET_FILES:
        (out / f).write_bytes((src / f).read_bytes())
    checksums = {f: _sha256_file(out / f) for f in REQUIRED_PACKET_FILES}
    export_manifest = {
        "schema_version": 1,
        "mode": "v1_readiness_packet_export",
        "export_id": out.name,
        "source_packet": src.name,
        "files": list(REQUIRED_EXPORT_FILES),
        "checksums": checksums,
        "safety": _safety(),
    }
    (out / "export-manifest.json").write_text(
        json.dumps(export_manifest, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "schema_version": 1,
        "mode": "v1_readiness_packet_export",
        "status": "exported",
        "existing": False,
        "export": {"id": out.name, "path": str(out)},
        "safety": _safety(),
    }


def validate_packet_export(export_ref: str, data_dir: Path) -> dict[str, Any]:
    d = _resolve_ref(export_ref, data_dir / "exports")
    checks = {
        k: False
        for k in ["required_files", "json_parse", "checksums", "source_safety", "export_safety"]
    }
    if d is None:
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_export_validate",
            "status": "error",
            "checks": checks,
            "warnings": ["unsafe export reference"],
        }
    if not d.exists():
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_export_validate",
            "status": "not_found",
            "checks": checks,
            "warnings": ["export not found"],
        }
    if any(not (d / f).exists() for f in REQUIRED_EXPORT_FILES):
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_export_validate",
            "status": "failed",
            "checks": checks,
            "warnings": ["missing required files"],
        }
    checks["required_files"] = True
    try:
        p = json.loads((d / "v1-packet.json").read_text(encoding="utf-8"))
        e = json.loads((d / "export-manifest.json").read_text(encoding="utf-8"))
    except Exception:
        return {
            "schema_version": 1,
            "mode": "v1_readiness_packet_export_validate",
            "status": "failed",
            "checks": checks,
            "warnings": ["malformed json"],
        }
    checks["json_parse"] = True
    checks["checksums"] = all(
        _sha256_file(d / rel) == expected
        for rel, expected in (e.get("checksums") or {}).items()
        if (d / rel).exists()
    )
    checks["source_safety"] = all(
        (k in (p.get("safety") or {}) and p["safety"][k] is v) for k, v in _safety().items()
    )
    checks["export_safety"] = all(
        (k in (e.get("safety") or {}) and e["safety"][k] is v) for k, v in _safety().items()
    )
    return {
        "schema_version": 1,
        "mode": "v1_readiness_packet_export_validate",
        "status": "ok" if all(checks.values()) else "failed",
        "checks": checks,
        "warnings": [],
    }
