#!/usr/bin/env python3
"""Validate saved Windows runtime reconcile preflight packets."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

MODE = "windows_runtime_reconcile"
RECIPE = "windows.runtime_reconcile"
STAT = {"ready", "no_change", "blocked", "unsupported"}
OPS = ("no_change", "create_required", "replace_required", "blocked")
ALLOW = [
    ("config/profiles/inspect.yaml", "config/profiles/inspect.yaml"),
    ("scripts/windows/sfai.cmd", "bin/sfai.cmd"),
]
# Exact fixed destination-parent contract (see the preflight helper).
PARENT_CONTRACT_VERSION = 1
PARENT_RELATIVE = {
    "config/profiles/inspect.yaml": "config/profiles",
    "bin/sfai.cmd": "bin",
}
PARENT_CREATION_ALLOWED = {
    "config/profiles/inspect.yaml": True,
    "bin/sfai.cmd": False,
}
AUTHORIZED_PARENT_DIRECTORIES = ["config", "config/profiles"]
PARENT_STATES = {"present", "create_required", "blocked"}
FUT = {
    "future.operator_confirmation",
    "future.saved_preflight_validation",
    "future.unchanged_rechecks",
    "future.same_directory_backup_before_replace",
    "future.atomic_replacement",
    "future.post_copy_hash_verification",
    "future.receipt_required",
    "future.pr304_post_change_staged_root",
    "future.pr304_post_change_system32_multi_artifact_acceptance",
}
FALSE = (
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


def parent_errs(op: dict[str, Any]) -> list[str]:
    """Validate the exact fixed destination-parent contract for one operation."""
    e: list[str] = []
    rel_dst = op.get("allowlist_destination")
    parent = op.get("destination_parent")
    if not isinstance(parent, dict):
        return ["missing destination_parent contract"]
    if rel_dst not in PARENT_RELATIVE:
        return ["destination_parent on a non-allowlisted destination"]
    if parent.get("contract_version") != PARENT_CONTRACT_VERSION:
        e.append("destination_parent contract_version must be 1")
    if parent.get("relative_path") != PARENT_RELATIVE[rel_dst]:
        e.append("destination_parent relative_path mismatch")
    allowed = PARENT_CREATION_ALLOWED[rel_dst]
    if parent.get("creation_allowed") is not allowed:
        e.append("destination_parent creation permission mismatch")
    state = parent.get("state")
    if state not in PARENT_STATES:
        e.append("invalid destination_parent state")
    chain = parent.get("creation_chain")
    if not isinstance(chain, list) or any(not isinstance(x, str) for x in chain):
        e.append("destination_parent creation_chain must be a list of strings")
        chain = []
    if not allowed and chain:
        e.append("destination_parent creation is not authorized for this destination")
    for entry in chain:
        if entry not in AUTHORIZED_PARENT_DIRECTORIES:
            e.append("destination_parent creation_chain entry outside the exact allowlist")
        if entry.startswith("/") or entry.startswith("\\") or re.match(r"^[A-Za-z]:", entry):
            e.append("destination_parent creation_chain entry must be relative")
        if ".." in entry.split("/") or "\\" in entry:
            e.append("destination_parent creation_chain entry uses an unsafe path form")
    if len(set(chain)) != len(chain):
        e.append("destination_parent creation_chain contains duplicates")
    if chain != [x for x in AUTHORIZED_PARENT_DIRECTORIES if x in chain]:
        e.append("destination_parent creation_chain ordering mismatch")
    if state == "create_required" and not chain:
        e.append("destination_parent create_required without a creation chain")
    if state in {"present", "blocked"} and chain:
        e.append("destination_parent creation chain on a non-creating state")
    if state == "blocked" and not (parent.get("blockers") or []):
        e.append("blocked destination_parent without a blocker")
    if state != "blocked" and (parent.get("blockers") or []):
        e.append("destination_parent blockers on a non-blocked state")
    return e


def errs(p: dict[str, Any]) -> list[str]:
    e = []
    if p.get("schema_version") != 1:
        e.append("schema_version must be 1")
    if p.get("destination_parent_contract_version") != PARENT_CONTRACT_VERSION:
        e.append("destination_parent_contract_version must be 1")
    if p.get("mode") != MODE:
        e.append("mode must be windows_runtime_reconcile")
    if p.get("recipe_id") != RECIPE:
        e.append("recipe_id must be windows.runtime_reconcile")
    if p.get("status") not in STAT:
        e.append("invalid status")
    if p.get("read_only") is not True or p.get("mutation_performed") is not False:
        e.append("unsafe top-level safety")
    s = p.get("safety") if isinstance(p.get("safety"), dict) else {}
    if s.get("read_only") is not True:
        e.append("safety.read_only must be true")
    for k in FALSE:
        if s.get(k) is not False:
            e.append(f"unsafe safety flag: {k}")
    ops = p.get("operations") if isinstance(p.get("operations"), list) else None
    if ops is None:
        e.append("operations must be list")
        ops = []
    if len(ops) > 2:
        e.append("too many operations")
    if [
        (o.get("allowlist_source"), o.get("allowlist_destination")) for o in ops
    ] != ALLOW[: len(ops)]:
        e.append("operation ordering or allowlist mismatch")
    counts = {k: 0 for k in OPS}
    for o in ops:
        op = o.get("operation")
        if op not in OPS:
            e.append("invalid operation")
        else:
            counts[op] += 1
        if not re.fullmatch(r"[0-9a-f]{64}", str(o.get("source_sha256") or "")):
            e.append("missing/invalid source sha256")
        if o.get("existing_destination_sha256") is not None and not re.fullmatch(
            r"[0-9a-f]{64}", str(o.get("existing_destination_sha256"))
        ):
            e.append("invalid destination sha256")
        if o.get("expected_post_change_sha256") != o.get("source_sha256"):
            e.append("expected post-change hash mismatch")
        if op == "create_required" and o.get("creation_required") is not True:
            e.append("create flag mismatch")
        if op == "replace_required" and o.get("replacement_required") is not True:
            e.append("replace flag mismatch")
        if "<UTCSTAMP>" not in str(o.get("backup_path_pattern")):
            e.append("backup pattern missing UTCSTAMP")
        e += parent_errs(o)
    summ = p.get("summary") if isinstance(p.get("summary"), dict) else {}
    if summ.get("total_operations") != len(ops):
        e.append("summary total mismatch")
    for k, v in counts.items():
        if summ.get(k) != v:
            e.append(f"summary count mismatch: {k}")
    parent_counts = {k: 0 for k in PARENT_STATES}
    for o in ops:
        state = (o.get("destination_parent") or {}).get("state")
        if state in parent_counts:
            parent_counts[state] += 1
    for state, value in parent_counts.items():
        if summ.get(f"parent_{state}") != value:
            e.append(f"summary count mismatch: parent_{state}")
    if parent_counts["blocked"] and p.get("status") != "blocked":
        e.append("plan with a blocked destination parent must be blocked")
    expected = (
        "unsupported"
        if p.get("platform", {}).get("system") != "windows"
        else (
            "blocked"
            if counts["blocked"] or p.get("blockers")
            else (
                "ready"
                if counts["create_required"] or counts["replace_required"]
                else "no_change"
            )
        )
    )
    if p.get("status") != expected:
        e.append("status precedence mismatch")
    gates = p.get("gates") if isinstance(p.get("gates"), list) else []
    names = [g.get("name") for g in gates]
    if len(names) != len(set(names)):
        e.append("duplicate gates")
    for g in gates:
        if g.get("name") in FUT and g.get("status") != "future_gate":
            e.append("future gate not marked future_gate")
    if not FUT.issubset(set(names)):
        e.append("missing future gates")
    return e


def read(path: Path):
    try:
        p = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(p, dict):
            return None, ["JSON must be object"]
        return p, []
    except Exception as ex:
        return None, [f"invalid JSON: {ex.__class__.__name__}: {str(ex)[:160]}"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("packet")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    p, e = read(Path(a.packet))
    e = e + (errs(p) if p else [])
    r = {"accepted": not e, "failures": e}
    print(
        json.dumps(r, sort_keys=True, separators=(",", ":"))
        if a.json
        else ("accepted" if not e else "rejected\n- " + "\n- ".join(e))
    )
    return 0 if not e else 1


if __name__ == "__main__":
    raise SystemExit(main())
