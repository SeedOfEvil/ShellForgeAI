from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class EvidenceCategory(str, Enum):
    host = "host"
    service = "service"
    logs = "logs"
    files = "files"
    network = "network"
    packages = "packages"
    knowledge = "knowledge"
    policy = "policy"


class TargetType(str, Enum):
    host = "host"
    service = "service"
    disk = "disk"
    network = "network"
    generic = "generic"


class EvidenceItem(BaseModel):
    source: str
    category: EvidenceCategory
    command: list[str] | None = None
    path: str | None = None
    ok: bool = True
    exit_code: int | None = None
    title: str
    summary: str
    content: str
    truncated: bool = False
    metadata: dict[str, str | int | bool | float] = Field(default_factory=dict)


class EvidenceBundle(BaseModel):
    target: str
    target_type: TargetType
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    items: list[EvidenceItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def classify_target(target: str) -> TargetType:
    t = target.lower().strip()
    if any(
        k in t
        for k in [
            "slow",
            "sluggish",
            "laggy",
            "high cpu",
            "high memory",
            "high load",
            "performance",
            "crawling",
        ]
    ):
        return TargetType.host
    if (
        t
        in {
            "nginx",
            "ssh",
            "sshd",
            "docker",
            "cron",
            "services",
            "service-discovery",
            "listening",
            "ports",
        }
        or ".service" in t
    ):
        return TargetType.service
    if any(k in t for k in ["disk", "storage", "filesystem", "space"]):
        return TargetType.disk
    if t in {"storage_performance", "disk-performance", "io", "iowait"}:
        return TargetType.disk
    if any(k in t for k in ["network", "dns", "route", "latency"]):
        return TargetType.network
    if any(k in t for k in ["host", "machine", "server"]):
        return TargetType.host
    return TargetType.generic
