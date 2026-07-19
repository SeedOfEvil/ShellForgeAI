#!/usr/bin/env python3
"""Build a governed preview-only Windows durable-runtime reconciliation packet."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
from collections import Counter
from pathlib import Path
from typing import Any

MODE = "windows_runtime_reconcile"
RECIPE_ID = "windows.runtime_reconcile"
OPS = (
    ("config/profiles/inspect.yaml", "config/profiles/inspect.yaml"),
    ("scripts/windows/sfai.cmd", "bin/sfai.cmd"),
)
OP_ORDER = ("no_change", "create_required", "replace_required", "blocked")
GATE_NAMES = (
    "platform.windows",
    "pr304.artifact_count",
    "pr304.artifact_validation",
    "pr304.stable_identity",
    "staged_source_root.explicit",
    "durable_runtime_root.explicit",
    "pr304.runtime_profile_and_wrapper_blockers_only",
    "allowlist.exact_two_files",
    "paths.contained",
    "files.regular_no_reparse",
    "hashes.available",
    "operations.maximum_two",
    "future.operator_confirmation",
    "future.saved_preflight_validation",
    "future.unchanged_rechecks",
    "future.same_directory_backup_before_replace",
    "future.atomic_replacement",
    "future.post_copy_hash_verification",
    "future.receipt_required",
    "future.pr304_post_change_staged_root",
    "future.pr304_post_change_system32_multi_artifact_acceptance",
)
FALSE_KEYS = (
    "mutation_performed",
    "execution_available",
    "execution_implemented",
    "copy_executed",
    "create_executed",
    "replace_executed",
    "delete_executed",
    "rename_executed",
    "backup_created",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "software_install_executed",
    "software_uninstall_executed",
    "service_control_executed",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
    "powershell_executed",
    "winrm_used",
    "qga_used",
    "subprocess_executed",
    "shell_executed",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "network_call",
    "model_called",
    "secret_read",
    "auth_cache_read",
)


def safety() -> dict[str, bool]:
    return {"read_only": True, **{k: False for k in FALSE_KEYS}}


def norm(p: Path | None) -> str | None:
    if p is None:
        return None
    try:
        return str(p.expanduser().resolve(strict=False))
    except OSError:
        return str(p.expanduser().absolute())


def case(s: str) -> str:
    return s.casefold() if platform.system().lower() == "windows" else s


def contained(child: Path, parent: Path) -> bool:
    c = case(norm(child) or "")
    p = case(norm(parent) or "").rstrip("\\/")
    return (
        c == p
        or c.startswith(p + "/")
        or c.startswith(p + "\\")
        or c.startswith(p + os.sep)
    )


def sha(p: Path) -> str | None:
    try:
        h = hashlib.sha256()
        h.update(p.read_bytes())
        return h.hexdigest()
    except OSError:
        return None


def is_reparse(p: Path) -> bool:
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return bool(getattr(st, "st_file_attributes", 0) & 0x400) or p.is_symlink()


def gate(name, status, reason=""):
    d = {"name": name, "status": status}
    if reason:
        d["reason"] = reason
    return d


def load_json(path: Path):
    try:
        obj = json.loads(path.read_text(encoding="utf-8-sig"))
        return obj if isinstance(obj, dict) else None, (
            [] if isinstance(obj, dict) else ["JSON must be an object"]
        )
    except Exception as e:
        return None, [f"invalid JSON: {e.__class__.__name__}: {str(e)[:160]}"]


def pr304_validator():
    path = Path(__file__).with_name("windows_runtime_integrity_acceptance.py")
    spec = importlib.util.spec_from_file_location(
        "windows_runtime_integrity_acceptance", path
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def check_artifacts(paths: list[str]):
    errs = []
    payloads = []
    val = pr304_validator()
    if len(paths) not in (1, 2):
        errs.append("one or two PR304 artifacts are required")
    for p in paths:
        obj, e = load_json(Path(p))
        errs += [f"{p}: {x}" for x in e]
        if obj is not None:
            payloads.append(obj)
            errs += [f"{p}: {x}" for x in val.validate(obj)]
    if len(payloads) == len(paths):
        errs += val.compare(payloads)
    blockers = []
    allowed = {
        "runtime.profile_context",
        "wrapper.exists",
        "wrapper.semantic_markers",
        "wrapper.canonical_match",
    }
    for obj in payloads:
        for c in obj.get("checks", []):
            if (
                isinstance(c, dict)
                and c.get("status") == "blocked"
                and c.get("id") not in allowed
            ):
                blockers.append(c.get("id"))
    return payloads, errs, blockers


def operation(
    src_root: Path, dst_root: Path, rel_src: str, rel_dst: str
) -> dict[str, Any]:
    src = src_root / rel_src
    dst = dst_root / rel_dst
    blockers = []
    if not contained(src, src_root):
        blockers.append("source path escapes staged root")
    if not contained(dst, dst_root):
        blockers.append("destination path escapes durable root")
    if is_reparse(src) or (dst.exists() and is_reparse(dst)):
        blockers.append("reparse or symlink path refused")
    if not src.exists() or not src.is_file():
        blockers.append("source is missing or not a regular file")
    if dst.exists() and not dst.is_file():
        blockers.append("destination exists and is not a regular file")
    src_hash = sha(src) if not blockers or src.exists() else None
    dst_hash = (
        sha(dst) if dst.exists() and dst.is_file() and not is_reparse(dst) else None
    )
    if src_hash is None:
        blockers.append("source sha256 unavailable")
    if dst.exists() and dst.is_file() and dst_hash is None:
        blockers.append("destination sha256 unavailable")
    if blockers:
        status = "blocked"
        reason = "; ".join(blockers)
    elif dst_hash is None:
        status = "create_required"
        reason = "durable destination is missing"
    elif dst_hash == src_hash:
        status = "no_change"
        reason = "durable destination already matches staged source"
    else:
        status = "replace_required"
        reason = "durable destination hash differs from staged source"
    return {
        "operation": status,
        "allowlist_source": rel_src,
        "allowlist_destination": rel_dst,
        "source_path": norm(src),
        "destination_path": norm(dst),
        "source_sha256": src_hash,
        "existing_destination_sha256": dst_hash,
        "expected_post_change_sha256": src_hash,
        "reason": reason,
        "creation_required": status == "create_required",
        "replacement_required": status == "replace_required",
        "backup_path_pattern": norm(
            dst.parent / (dst.name + ".sfai-pr305-backup-<UTCSTAMP>.bak")
        ),
        "post_change_pr304_verification": [
            "run PR304 from staged source root",
            "run PR304 from C:\\Windows\\System32",
            "validate both artifacts with multi-artifact acceptance",
        ],
    }


def build_packet(
    artifacts: list[str],
    staged_source_root: str | None,
    durable_runtime_root: str | None,
) -> dict[str, Any]:
    system = platform.system().lower()
    gates = []
    blockers = []
    warnings = []
    ops = []
    gates.append(
        gate("platform.windows", "passed" if system == "windows" else "unsupported")
    )
    status = "unsupported" if system != "windows" else "blocked"
    payloads, art_errs, pr304_blockers = check_artifacts(artifacts)
    gates.append(
        gate(
            "pr304.artifact_count", "passed" if len(artifacts) in (1, 2) else "blocked"
        )
    )
    gates.append(
        gate(
            "pr304.artifact_validation",
            "passed" if not art_errs else "blocked",
            "; ".join(art_errs[:4]),
        )
    )
    gates.append(
        gate(
            "pr304.stable_identity",
            "passed" if len(payloads) < 2 or not art_errs else "blocked",
        )
    )
    if art_errs:
        blockers.extend(art_errs)
    if pr304_blockers:
        blockers.append(
            "PR304 has non-runtime-profile/wrapper blockers: "
            + ",".join(sorted(set(pr304_blockers)))
        )
    gates.append(
        gate(
            "staged_source_root.explicit", "passed" if staged_source_root else "blocked"
        )
    )
    gates.append(
        gate(
            "durable_runtime_root.explicit",
            "passed" if durable_runtime_root else "blocked",
        )
    )
    gates.append(
        gate(
            "pr304.runtime_profile_and_wrapper_blockers_only",
            "passed" if not pr304_blockers else "blocked",
        )
    )
    gates.append(gate("allowlist.exact_two_files", "passed"))
    src_root = Path(staged_source_root).expanduser() if staged_source_root else None
    dst_root = Path(durable_runtime_root).expanduser() if durable_runtime_root else None
    if (
        system == "windows"
        and src_root
        and dst_root
        and not art_errs
        and not pr304_blockers
    ):
        ops = [operation(src_root, dst_root, a, b) for a, b in OPS]
    op_blocked = any(o["operation"] == "blocked" for o in ops)
    gates += [
        gate("paths.contained", "blocked" if op_blocked else "passed"),
        gate("files.regular_no_reparse", "blocked" if op_blocked else "passed"),
        gate("hashes.available", "blocked" if op_blocked else "passed"),
        gate("operations.maximum_two", "passed" if len(ops) <= 2 else "blocked"),
    ]
    gates += [gate(n, "future_gate") for n in GATE_NAMES if n.startswith("future.")]
    if system == "windows":
        if blockers or op_blocked or not src_root or not dst_root:
            status = "blocked"
        elif any(
            o["operation"] in ("create_required", "replace_required") for o in ops
        ):
            status = "ready"
        elif ops and all(o["operation"] == "no_change" for o in ops):
            status = "no_change"
        else:
            status = "blocked"
    residue = max(
        (
            p.get("invalid_distribution_residue", {}).get("residue_count", 0)
            for p in payloads
        ),
        default=0,
    )
    if residue:
        warnings.append(
            "Deferred PR304 invalid distribution residue warning only; "
            "no PR305 operation generated."
        )
    counts = Counter(o["operation"] for o in ops)
    return {
        "schema_version": 1,
        "mode": MODE,
        "recipe_id": RECIPE_ID,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "preview_only": True,
        "execution_available": False,
        "execution_implemented": False,
        "future_confirmation_required": True,
        "future_verification_required": True,
        "future_receipt_required": True,
        "artifact_count": len(artifacts),
        "platform": {"system": system},
        "staged_source_root": norm(src_root),
        "durable_runtime_root": norm(dst_root),
        "allowlist": [{"source": a, "destination": b} for a, b in OPS],
        "operations": ops,
        "summary": {
            "total_operations": len(ops),
            "no_change": counts["no_change"],
            "create_required": counts["create_required"],
            "replace_required": counts["replace_required"],
            "blocked": counts["blocked"],
        },
        "gates": gates,
        "blockers": blockers
        + [o["reason"] for o in ops if o["operation"] == "blocked"],
        "warnings": warnings,
        "safety": safety(),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("artifacts", nargs="+")
    ap.add_argument("--staged-source-root", required=True)
    ap.add_argument("--durable-runtime-root", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out-json")
    a = ap.parse_args(argv)
    p = build_packet(a.artifacts, a.staged_source_root, a.durable_runtime_root)
    text = json.dumps(p, sort_keys=True, separators=(",", ":"))
    if a.out_json:
        out = Path(a.out_json)
        if out.exists():
            ap.error(f"refusing to overwrite existing artifact: {out}")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
    print(text if a.json else json.dumps(p, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
