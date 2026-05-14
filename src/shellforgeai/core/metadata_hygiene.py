from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shellforgeai.core.retention import (
    RetentionCategory,
    build_categories,
    collect_category,
    file_size,
)


def human_bytes(num: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    n = float(max(num, 0))
    for unit in units:
        if n < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{int(num)} B"


@dataclass(frozen=True)
class HygieneThresholds:
    total_warn_bytes: int = 1024**3
    total_critical_bytes: int = 5 * 1024**3
    category_warn_bytes: int = 512 * 1024**2
    category_critical_bytes: int = 2 * 1024**3
    category_warn_count: int = 100
    category_critical_count: int = 500

    @classmethod
    def from_env(cls) -> HygieneThresholds:
        def _int(name: str, default: int) -> int:
            raw = os.getenv(name)
            if not raw:
                return default
            try:
                return max(int(raw), 0)
            except ValueError:
                return default

        defaults = cls()
        return cls(
            total_warn_bytes=_int("SHELLFORGEAI_METADATA_WARN_BYTES", defaults.total_warn_bytes),
            total_critical_bytes=_int(
                "SHELLFORGEAI_METADATA_CRITICAL_BYTES", defaults.total_critical_bytes
            ),
            category_warn_bytes=_int(
                "SHELLFORGEAI_METADATA_CATEGORY_WARN_BYTES", defaults.category_warn_bytes
            ),
            category_critical_bytes=_int(
                "SHELLFORGEAI_METADATA_CATEGORY_CRITICAL_BYTES",
                defaults.category_critical_bytes,
            ),
            category_warn_count=defaults.category_warn_count,
            category_critical_count=defaults.category_critical_count,
        )


def _category_severity(count: int, size: int, t: HygieneThresholds) -> str:
    if count >= t.category_critical_count or size >= t.category_critical_bytes:
        return "critical"
    if count >= t.category_warn_count or size >= t.category_warn_bytes:
        return "warning"
    return "ok"


def _scan_safe_items(cat: RetentionCategory, data_dir: Path) -> list[Path]:
    safe: list[Path] = []
    for item in collect_category(cat):
        try:
            resolved = item.resolve(strict=True)
        except FileNotFoundError:
            continue
        if item.is_symlink() and data_dir.resolve() not in resolved.parents:
            continue
        if data_dir.resolve() in resolved.parents:
            safe.append(item)
    return safe


def scan_metadata_hygiene(
    data_dir: Path, thresholds: HygieneThresholds | None = None
) -> dict[str, object]:
    t = thresholds or HygieneThresholds.from_env()
    cats = build_categories(data_dir)
    names = [
        "artifacts",
        "exports",
        "audit-exports",
        "apply-bundles",
        "actions",
        "approvals",
        "audit-events",
        "indexes",
    ]
    categories: dict[str, dict[str, Any]] = {}
    total = 0
    total_items = 0
    for name in names:
        items = _scan_safe_items(cats[name], data_dir)
        sz = sum(file_size(p) for p in items)
        total += sz
        total_items += len(items)
        sev = _category_severity(len(items), sz, t)
        key = name.replace("-", "_")
        categories[key] = {
            "count": len(items),
            "bytes": sz,
            "human": human_bytes(sz),
            "severity": sev,
        }

    warnings: list[str] = []
    if total >= t.total_critical_bytes:
        severity = "critical"
        warnings.append("ShellForgeAI metadata total is above critical threshold")
    elif total >= t.total_warn_bytes:
        severity = "warning"
        warnings.append("ShellForgeAI metadata total is above warning threshold")
    else:
        severity = "ok"

    for name, entry in categories.items():
        if entry["severity"] != "ok":
            warnings.append(f"{name} category is above {entry['severity']} threshold")
            if entry["severity"] == "critical" and severity != "critical":
                severity = "critical"
            elif entry["severity"] == "warning" and severity == "ok":
                severity = "warning"

    recs = ["shellforgeai audit retention"]
    recs.append("shellforgeai audit prune --dry-run --category exports --max-age-days 30")
    if categories["exports"]["severity"] != "ok":
        recs.extend(
            [
                "shellforgeai audit prune --dry-run --category exports --max-age-days 30",
                "shellforgeai audit prune --archive --dry-run --category exports --max-age-days 30",
            ]
        )
    if categories["audit_exports"]["severity"] != "ok":
        recs.append("shellforgeai audit prune --dry-run --category audit-exports --max-age-days 30")
    if categories["apply_bundles"]["severity"] != "ok":
        recs.append("shellforgeai audit prune --dry-run --category apply-bundles --max-age-days 30")
    if categories["artifacts"]["severity"] != "ok":
        recs.append("artifacts may contain evidence; archive before deletion")
        recs.append(
            "shellforgeai audit prune --archive --dry-run --category artifacts --max-age-days 60"
        )
    if categories["approvals"]["severity"] != "ok":
        recs.append("review approvals via: shellforgeai approvals list --status pending")
        recs.append("review audit history via: shellforgeai audit search approvals")

    recs.append("After reviewing the dry-run and archive, an operator may rerun with --execute.")

    return {
        "severity": severity,
        "data_dir": str(data_dir),
        "audit_dir": str(data_dir / "audit"),
        "total_bytes": total,
        "total_human": human_bytes(total),
        "total_items": total_items,
        "categories": categories,
        "warnings": warnings,
        "recommendations": recs,
    }
