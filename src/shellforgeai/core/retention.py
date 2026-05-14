from __future__ import annotations

import hashlib
import io
import json
import tarfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from posixpath import normpath


@dataclass
class RetentionCategory:
    name: str
    roots: tuple[Path, ...]
    patterns: tuple[str, ...]


DEFAULT_PRUNE_CATEGORIES = ("exports", "apply-bundles", "actions", "audit-exports", "indexes")

ALLOWED_PRUNE_CATEGORIES = (
    "exports",
    "apply-bundles",
    "actions",
    "audit-exports",
    "indexes",
    "artifacts",
)

PROTECTED_PRUNE_CATEGORIES = ("approvals", "audit-events")


def write_prune_receipt(
    data_dir: Path,
    *,
    mode: str,
    category: str,
    selection: list[Path],
    deleted: list[Path],
    failed: list[str],
    bytes_removed: int,
    max_age_days: int | None,
    keep_latest: int | None,
) -> tuple[Path, Path]:
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    short = uuid.uuid4().hex[:6]
    receipt_id = f"prune_{ts}_{short}"
    out_dir = data_dir / "prune_receipts"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{receipt_id}.json"
    md_path = out_dir / f"{receipt_id}.md"
    payload = {
        "schema_version": "1",
        "receipt_id": receipt_id,
        "created_at": datetime.now(UTC).isoformat(),
        "mode": mode,
        "category": category,
        "selection": {
            "count": len(selection),
            "paths": [str(p) for p in selection],
            "max_age_days": max_age_days,
            "keep_latest": keep_latest,
        },
        "deleted": [str(p) for p in deleted],
        "failed": list(failed),
        "bytes_removed": int(bytes_removed),
        "safety": {
            "shellforgeai_metadata_only": True,
            "remediation_execution": False,
            "docker_mutation": False,
            "service_mutation": False,
            "package_mutation": False,
        },
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_lines = [
        f"# Prune Receipt {receipt_id}",
        "",
        f"- mode: {mode}",
        f"- category: {category}",
        f"- selected: {len(selection)}",
        f"- deleted: {len(deleted)}",
        f"- failed: {len(failed)}",
        f"- bytes_removed: {bytes_removed}",
        "- scope: ShellForgeAI-owned metadata only",
        "- remediation_execution: false",
        "",
    ]
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    return json_path, md_path


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


def ensure_safe_delete_target(path: Path, allowed_roots: list[Path]) -> str | None:
    try:
        rp = path.resolve(strict=True)
    except FileNotFoundError:
        return "target missing"
    protected = {Path("/"), Path("/data"), *[r.resolve() for r in allowed_roots]}
    if rp in protected:
        return f"refused protected path: {rp}"
    if not safe_under_roots(path, allowed_roots):
        return f"refused outside allowed roots: {path}"
    if path.is_symlink():
        target = rp
        if not any(root.resolve() in target.parents for root in allowed_roots):
            return f"refused symlink outside allowed roots: {path}"
    return None


def delete_paths(paths: list[Path], allowed_roots: list[Path]) -> tuple[list[Path], list[str], int]:
    deleted: list[Path] = []
    errors: list[str] = []
    bytes_removed = 0
    for p in paths:
        refusal = ensure_safe_delete_target(p, allowed_roots)
        if refusal:
            errors.append(refusal)
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
        "included_paths": [],
        "checksums": {},
        "redaction_applied": False,
        "execution_allowed": False,
        "execution_status": "not_executed",
        "mutation_performed": False,
    }
    checksum_map: dict[str, str] = {}
    checksums: list[str] = []
    included_paths: list[str] = []
    with tarfile.open(out, "w:gz") as tf:
        for p in paths:
            if not p.exists():
                continue
            base = p.parent if p.parent != Path("/") else p
            if p.is_file():
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
                rel = p.relative_to(base).as_posix()
                payload_rel = f"payload/{rel}"
                checksum_map[payload_rel] = digest
                checksums.append(f"{digest}  {payload_rel}")
                included_paths.append(payload_rel)
                tf.add(p, arcname=payload_rel)
            elif p.is_dir():
                for child in sorted(p.rglob("*")):
                    if child.is_file():
                        digest = hashlib.sha256(child.read_bytes()).hexdigest()
                        rel = child.relative_to(base).as_posix()
                        payload_rel = f"payload/{rel}"
                        checksum_map[payload_rel] = digest
                        checksums.append(f"{digest}  {payload_rel}")
                        included_paths.append(payload_rel)
                        tf.add(child, arcname=payload_rel)
        manifest["included_paths"] = included_paths
        manifest["checksums"] = checksum_map
        manifest_bytes = json.dumps(manifest, indent=2).encode()
        m_info = tarfile.TarInfo("archive-manifest.json")
        m_info.size = len(manifest_bytes)
        tf.addfile(m_info, fileobj=io.BytesIO(manifest_bytes))
        checksums_bytes = ("\n".join(checksums) + "\n").encode()
        c_info = tarfile.TarInfo("checksums.sha256")
        c_info.size = len(checksums_bytes)
        tf.addfile(c_info, fileobj=io.BytesIO(checksums_bytes))
        summary = (
            f"# Archive Summary\n\n- archive_id: {archive_id}\n- source: {source}\n"
            f"- files_hashed: {len(checksum_map)}\n- execution: none\n"
        ).encode()
        s_info = tarfile.TarInfo("archive-summary.md")
        s_info.size = len(summary)
        tf.addfile(s_info, fileobj=io.BytesIO(summary))
    return out


def validate_archive(path: Path) -> tuple[bool, list[str], int]:
    if path.is_dir():
        return _validate_archive_dir(path)
    return _validate_archive_tar(path)


def _normalize_member_path(raw: str) -> str | None:
    p = raw.strip().replace("\\", "/")
    if not p:
        return None
    if p.startswith("/"):
        return None
    n = normpath(p)
    if n == "." or n.startswith("../") or "/../" in n:
        return None
    return n


def _validate_archive_dir(path: Path) -> tuple[bool, list[str], int]:
    errors: list[str] = []
    file_count = 0
    manifest_path = path / "archive-manifest.json"
    checksums_path = path / "checksums.sha256"
    summary_path = path / "archive-summary.md"
    for required in (manifest_path, checksums_path, summary_path):
        if not required.exists():
            errors.append(f"missing {required.name}")
    if errors:
        return False, errors, file_count
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("execution_allowed") is not False:
        errors.append("execution_allowed must be false")
    if manifest.get("execution_status") != "not_executed":
        errors.append("execution_status must be not_executed")
    if manifest.get("mutation_performed") is not False:
        errors.append("mutation_performed must be false")
    for line in checksums_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, sep, src = line.partition("  ")
        if not sep:
            errors.append(f"invalid checksum line: {line}")
            continue
        rel = _normalize_member_path(src)
        if rel is None:
            errors.append(f"invalid checksum path: {src.strip()}")
            continue
        target = (path / rel).resolve()
        if path.resolve() not in target.parents:
            errors.append(f"path escapes archive root: {rel}")
            continue
        if not target.exists():
            errors.append(f"missing payload for checksum entry: {rel}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        file_count += 1
        if actual != expected:
            errors.append(f"checksum mismatch: {rel}")
    return (not errors), errors, file_count


def _validate_archive_tar(path: Path) -> tuple[bool, list[str], int]:
    errors: list[str] = []
    file_count = 0
    try:
        with tarfile.open(path, "r:gz") as tf:
            names = set(tf.getnames())
            for required in ("archive-manifest.json", "checksums.sha256", "archive-summary.md"):
                if required not in names:
                    errors.append(f"missing {required}")
            if errors:
                return False, errors, file_count
            mf = tf.extractfile("archive-manifest.json")
            cs = tf.extractfile("checksums.sha256")
            if mf is None or cs is None:
                return False, ["missing manifest/checksums content"], file_count
            manifest = json.loads(mf.read().decode("utf-8"))
            if manifest.get("execution_allowed") is not False:
                errors.append("execution_allowed must be false")
            if manifest.get("execution_status") != "not_executed":
                errors.append("execution_status must be not_executed")
            if manifest.get("mutation_performed") is not False:
                errors.append("mutation_performed must be false")
            checksum_lines = [
                ln.strip() for ln in cs.read().decode("utf-8").splitlines() if ln.strip()
            ]
            members = {n: n for n in names}
            for line in checksum_lines:
                expected, sep, src = line.partition("  ")
                if not sep:
                    errors.append(f"invalid checksum line: {line}")
                    continue
                member = _normalize_member_path(src)
                if member is None:
                    errors.append(f"invalid checksum path: {src.strip()}")
                    continue
                member = members.get(member)
                if member is None:
                    errors.append(f"missing payload for checksum entry: {src.strip()}")
                    continue
                fileobj = tf.extractfile(member)
                if fileobj is None:
                    errors.append(f"missing payload stream: {member}")
                    continue
                actual = hashlib.sha256(fileobj.read()).hexdigest()
                file_count += 1
                if actual != expected:
                    errors.append(f"checksum mismatch: {src.strip()}")
    except Exception as exc:
        return False, [str(exc)], file_count
    return (not errors), errors, file_count
