from __future__ import annotations

import json
from typing import Any

_COMPOSE_KEYS = {
    "project": "com.docker.compose.project",
    "service": "com.docker.compose.service",
    "container_number": "com.docker.compose.container-number",
    "config_hash": "com.docker.compose.config-hash",
    "working_dir": "com.docker.compose.project.working_dir",
    "config_files": "com.docker.compose.project.config_files",
    "compose_version": "com.docker.compose.version",
    "oneoff": "com.docker.compose.oneoff",
    "image_label": "com.docker.compose.image",
    "depends_on": "com.docker.compose.depends_on",
}


def _safe(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _parse_bool(value: Any) -> bool | None:
    txt = _safe(value).lower()
    if txt in {"true", "1", "yes"}:
        return True
    if txt in {"false", "0", "no"}:
        return False
    return None


def compose_context_from_row(row: dict[str, Any] | None) -> dict[str, Any]:
    """Return a normalized Compose context dict from a container evidence row.

    Prefers a pre-parsed ``row["compose"]`` block (as emitted by
    :func:`shellforgeai.tools.containers.containers`); falls back to parsing
    raw ``row["labels"]`` via :func:`parse_compose_context`. Adds a
    ``source="docker_labels"`` marker when Compose ownership is detected.
    """
    if not isinstance(row, dict):
        row = {}
    compose = row.get("compose")
    if isinstance(compose, dict) and compose.get("detected"):
        out = dict(compose)
    else:
        labels = row.get("labels") or {}
        if not isinstance(labels, dict):
            labels = {}
        out = parse_compose_context(labels)
    if out.get("detected"):
        out.setdefault("source", "docker_labels")
    return out


def parse_compose_context(labels: dict[str, Any] | None) -> dict[str, Any]:
    labels = labels or {}
    if not isinstance(labels, dict):
        labels = {}
    project = _safe(labels.get(_COMPOSE_KEYS["project"]))
    service = _safe(labels.get(_COMPOSE_KEYS["service"]))
    if not project and not service:
        return {"detected": False, "reason": "compose labels not present"}
    config_files_raw = _safe(labels.get(_COMPOSE_KEYS["config_files"]))
    config_files = (
        [p.strip() for p in config_files_raw.split(",") if p.strip()] if config_files_raw else []
    )
    depends_raw = labels.get(_COMPOSE_KEYS["depends_on"])
    depends_on: list[str] = []
    if isinstance(depends_raw, str) and depends_raw.strip():
        txt = depends_raw.strip()
        try:
            parsed = json.loads(txt)
            if isinstance(parsed, list):
                depends_on = [str(x) for x in parsed if str(x).strip()]
            elif isinstance(parsed, dict):
                depends_on = [str(k) for k in parsed if str(k).strip()]
        except Exception:
            depends_on = [p.strip() for p in txt.split(",") if p.strip()]
    oneoff = _parse_bool(labels.get(_COMPOSE_KEYS["oneoff"]))
    out: dict[str, Any] = {
        "detected": True,
        "project": project,
        "service": service,
        "container_number": _safe(labels.get(_COMPOSE_KEYS["container_number"])),
        "working_dir": _safe(labels.get(_COMPOSE_KEYS["working_dir"])),
        "config_files": config_files,
        "config_hash": _safe(labels.get(_COMPOSE_KEYS["config_hash"])),
        "compose_version": _safe(labels.get(_COMPOSE_KEYS["compose_version"])),
        "oneoff": oneoff if oneoff is not None else False,
        "image_label": _safe(labels.get(_COMPOSE_KEYS["image_label"])),
        "depends_on": depends_on,
    }
    return out
