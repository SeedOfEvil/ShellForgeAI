from __future__ import annotations

import hashlib
import io
import json
import tarfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass
class RetentionCategory:
    name: str
    roots: tuple[Path, ...]
    patterns: tuple[str, ...]


def _walk_matching(root: Path, patterns: tuple[str, ...]) -> list[Path]:
    if not root.exists():
        return []
    out: list[Path] = []
    for pat in patterns:
        out.extend(root.glob(pat))
    return sorted({p for p in out if p.exists()})


def build_categories(data_dir: Path) -> dict[str, RetentionCategory]:
    audit_dir = data_dir / "audit"
    return {
        "artifacts": RetentionCategory("artifacts", (data_dir / "artifacts",), ("sf_*",)),
        "approvals": RetentionCategory("approvals", (data_dir / "approvals",), ("*",)),
        "apply-bundles": RetentionCategory("apply-bundles", (data_dir / "apply_bundles",), ("*",)),
        "actions": RetentionCategory("actions", (data_dir / "actions",), ("*",)),
        "exports": RetentionCategory("exports", (data_dir / "exports",), ("*",)),
        "audit-exports": RetentionCategory("audit-exports", (data_dir / "audit_exports",), ("*",)),
        "indexes": RetentionCategory("indexes", (audit_dir,), ("incident-index.json",)),
        "audit-events": RetentionCategory("audit-events", (audit_dir,), ("events.jsonl",)),
    }


def collect_category(cat: RetentionCategory) -> list[Path]:
    items: list[Path] = []
    for root in cat.roots:
        items.extend(_walk_matching(root, cat.patterns))
    return sorted({p for p in items if p.exists()})


def file_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total


def prune_select(
    paths: list[Path], *, max_age_days: int | None, keep_latest: int | None
) -> list[Path]:
    selected = sorted(paths, key=lambda p: p.stat().st_mtime, reverse=True)
    if keep_latest:
        selected = selected[keep_latest:]
    if max_age_days is not None:
        cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
        selected = [p for p in selected if datetime.fromtimestamp(p.stat().st_mtime, UTC) < cutoff]
    return sorted(selected)


def safe_under_roots(path: Path, roots: list[Path]) -> bool:
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return False
    for root in roots:
        rr = root.resolve()
        if resolved == rr:
            return False
        if rr in resolved.parents:
            return True
    return False


def delete_paths(paths: list[Path], allowed_roots: list[Path]) -> tuple[list[Path], list[str], int]:
    deleted: list[Path] = []
    errors: list[str] = []
    bytes_removed = 0
    for p in paths:
        if not safe_under_roots(p, allowed_roots):
            errors.append(f"refused outside allowed roots: {p}")
            continue
        try:
            size = file_size(p)
            if p.is_dir() and not p.is_symlink():
                for child in sorted(p.rglob("*"), reverse=True):
                    if child.is_file() or child.is_symlink():
                        child.unlink(missing_ok=True)
                    elif child.is_dir():
                        child.rmdir()
                p.rmdir()
            else:
                p.unlink(missing_ok=True)
            deleted.append(p)
            bytes_removed += size
        except Exception as exc:
            errors.append(f"delete failed {p}: {exc}")
    return deleted, errors, bytes_removed


def create_archive(
    paths: list[Path], data_dir: Path, source: str, output: Path | None = None
) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    archive_id = f"archive_{ts}_{uuid.uuid4().hex[:6]}"
    out = output or (data_dir / "archives" / f"{archive_id}.tar.gz")
    out.parent.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {
        "schema_version": "1",
        "archive_id": archive_id,
        "created_at": datetime.now(UTC).isoformat(),
        "source": source,
        "included_paths": [str(p) for p in paths],
        "checksums": {},
        "redaction_applied": False,
        "execution_allowed": False,
        "execution_status": "not_executed",
        "mutation_performed": False,
    }
    checksum_map: dict[str, str] = {}
    checksums: list[str] = []
    with tarfile.open(out, "w:gz") as tf:
        for p in paths:
            if not p.exists():
                continue
            if p.is_file():
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
                checksum_map[str(p)] = digest
                checksums.append(f"{digest}  {p}")
            tf.add(p, arcname=f"payload/{p.name}")
        manifest["checksums"] = checksum_map
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        m_info = tarfile.TarInfo("archive-manifest.json")
        m_info.size = len(manifest_bytes)
        tf.addfile(m_info, fileobj=io.BytesIO(manifest_bytes))
    return out
