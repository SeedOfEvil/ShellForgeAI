from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
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


def _scan_safe_items(cat: RetentionCategory, data_dir: Path) -> tuple[list[Path], list[str]]:
    safe: list[Path] = []
    warnings: list[str] = []
    data_root = data_dir.resolve()
    for item in collect_category(cat):
        try:
            resolved = item.resolve(strict=True)
        except FileNotFoundError:
            continue
        except OSError as exc:
            warnings.append(f"unreadable item skipped: {item} ({exc})")
            continue
        if item.is_symlink() and data_root not in resolved.parents:
            warnings.append(f"outside-data-dir symlink skipped: {item}")
            continue
        if data_root in resolved.parents:
            safe.append(item)
        else:
            warnings.append(f"outside-data-dir path skipped: {item}")
    return safe, warnings


def _iso_from_mtime(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()
    except OSError:
        return None


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
    reasons: list[dict[str, Any]] = []
    warnings: list[str] = []
    total = 0
    total_items = 0
    for name in names:
        items, item_warnings = _scan_safe_items(cats[name], data_dir)
        warnings.extend(item_warnings)
        sz = sum(file_size(p) for p in items)
        total += sz
        total_items += len(items)
        sev = _category_severity(len(items), sz, t)
        key = name.replace("-", "_")
        item_ts = sorted(filter(None, (_iso_from_mtime(p) for p in items)))
        categories[key] = {
            "count": len(items),
            "bytes": sz,
            "human": human_bytes(sz),
            "severity": sev,
            "oldest_created_at": item_ts[0] if item_ts else None,
            "newest_created_at": item_ts[-1] if item_ts else None,
        }
        if sev != "ok":
            reasons.append(
                {
                    "category": name,
                    "count": len(items),
                    "threshold": t.category_critical_count
                    if sev == "critical"
                    else t.category_warn_count,
                    "estimated_bytes": sz,
                    "oldest_created_at": item_ts[0] if item_ts else None,
                    "newest_created_at": item_ts[-1] if item_ts else None,
                    "severity": sev,
                    "recommended_action": "cleanup_plan",
                }
            )

    if total >= t.total_critical_bytes:
        severity = "critical"
        warnings.append("ShellForgeAI metadata total is above critical threshold")
    elif total >= t.total_warn_bytes:
        severity = "warning"
        warnings.append("ShellForgeAI metadata total is above warning threshold")
    else:
        severity = "ok"

    for entry in reasons:
        if entry["severity"] == "critical":
            severity = "critical"
            break
        if severity == "ok":
            severity = "warning"

    recs = [
        "shellforgeai audit retention",
        "shellforgeai audit prune --dry-run --category exports --max-age-days 30",
        "shellforgeai audit cleanup plan --category exports --max-age-days 7 --keep-latest 5",
        "shellforgeai audit cleanup archive <cleanup-plan>",
        "shellforgeai audit cleanup validate <cleanup-archive>",
        "shellforgeai audit cleanup execute <cleanup-plan> --confirm",
    ]

    return {
        "severity": severity,
        "status": severity,
        "data_dir": str(data_dir),
        "audit_dir": str(data_dir / "audit"),
        "total_bytes": total,
        "total_human": human_bytes(total),
        "total_items": total_items,
        "categories": categories,
        "reasons": reasons,
        "warnings": warnings,
        "recommendations": recs,
        "suggested_commands": recs,
    }
