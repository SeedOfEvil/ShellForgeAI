#!/usr/bin/env python3
"""Build a deterministic read-only Windows runtime integrity packet."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import shlex
import site
import sys
import sysconfig
from collections import Counter
from contextlib import suppress
from pathlib import Path
from typing import Any

SAFETY_FALSE_KEYS = (
    "natural_language_execution",
    "powershell_executed",
    "winrm_used",
    "qga_used",
    "remote_execution",
    "subprocess_executed",
    "shell_executed",
    "shell_true",
    "arbitrary_command_execution",
    "network_call",
    "model_called",
    "secret_read",
    "auth_cache_read",
    "software_install_executed",
    "software_uninstall_executed",
    "wrapper_modified",
    "file_deleted",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "recovery_executed",
    "service_control_executed",
    "process_termination_executed",
    "registry_modified",
    "execution_policy_modified",
)
SAFETY = {
    "read_only": True,
    "mutation_performed": False,
    **{key: False for key in SAFETY_FALSE_KEYS},
}
CHECK_ORDER = (
    "platform.windows",
    "python.runtime",
    "python.runtime_root",
    "shellforgeai.import",
    "shellforgeai.expected_source",
    "runtime.profile_context",
    "wrapper.exists",
    "wrapper.semantic_markers",
    "wrapper.canonical_match",
    "embedded_python.exists",
    "entrypoint.exists",
    "invalid_distribution_residue",
)
MARKERS = {
    "wrapper_relative_dp0": "%~dp0",
    "runtime_root_env": "SHELLFORGEAI_RUNTIME_ROOT",
    "embedded_python314": "Python314\\python.exe",
    "module_entry": "-m shellforgeai %*",
    "errorlevel": "%ERRORLEVEL%",
}
ALLOWED_CHECK = {"pass", "attention", "blocked", "not_requested", "unsupported"}


def _path(value: str | None) -> Path | None:
    return Path(value).expanduser() if value else None


def _norm(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.expanduser().resolve(strict=False))
    except OSError:
        return str(path.expanduser().absolute())


def _case(value: str) -> str:
    return value.casefold() if platform.system().lower() == "windows" else value


def _contained(child: Path, parent: Path) -> bool:
    child_s = _case(_norm(child) or "")
    parent_s = (_case(_norm(parent) or "")).rstrip("\\/")
    return (
        child_s == parent_s
        or child_s.startswith(parent_s + os.sep)
        or child_s.startswith(parent_s + "/")
        or child_s.startswith(parent_s + "\\")
    )


def _inside_root(child: Path | None, parent: Path | None) -> bool | None:
    if child is None or parent is None:
        return None
    return _contained(child, parent)


def _sha(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _normalized_text(text: str | None) -> str | None:
    if text is None:
        return None
    return "\n".join(
        line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    )


def _check(cid: str, status: str, summary: str, **details: Any) -> dict[str, Any]:
    item = {"id": cid, "status": status, "summary": summary}
    if details:
        item["details"] = details
    return item


def _runtime_kind(exe: Path, prefix: Path, base_prefix: Path) -> dict[str, bool]:
    exe_s = _case(_norm(exe) or "")
    return {
        "appears_virtual": _case(_norm(prefix) or "") != _case(_norm(base_prefix) or ""),
        "appears_embedded": "python314" in exe_s and (exe.name.casefold() == "python.exe"),
        "appears_system_level": "windows" in exe_s and "python314" not in exe_s,
    }


def _platform_block() -> dict[str, str]:
    return {
        "system": platform.system().lower(),
        "release": platform.release(),
        "machine": platform.machine(),
        "platform": platform.platform(),
    }


def _import_block(expected: Path | None, checks: list[dict[str, Any]]) -> dict[str, Any]:
    block: dict[str, Any] = {
        "success": False,
        "module_file": None,
        "package_root": None,
        "expected_source_root": _norm(expected),
        "expected_source_match": None,
        "mismatch_reason": None,
        "error_class": None,
        "error_message": None,
    }
    try:
        mod = importlib.import_module("shellforgeai")
        module_file = Path(getattr(mod, "__file__", ""))
        root = module_file.parent
        block.update(
            {"success": True, "module_file": _norm(module_file), "package_root": _norm(root)}
        )
        checks.append(_check("shellforgeai.import", "pass", "ShellForgeAI imported in-process."))
        if expected is not None:
            match = _inside_root(root, expected)
            block["expected_source_match"] = bool(match)
            if match:
                checks.append(
                    _check(
                        "shellforgeai.expected_source",
                        "pass",
                        "Import is under expected source root.",
                    )
                )
            else:
                block["mismatch_reason"] = "import_package_root_outside_expected_source_root"
                checks.append(
                    _check(
                        "shellforgeai.expected_source",
                        "blocked",
                        "Import is outside expected source root.",
                        actual=block["package_root"],
                        expected=block["expected_source_root"],
                    )
                )
        else:
            checks.append(
                _check(
                    "shellforgeai.expected_source",
                    "not_requested",
                    "Expected source root was not supplied.",
                )
            )
    except Exception as exc:  # controlled packet, no traceback
        block.update({"error_class": exc.__class__.__name__, "error_message": str(exc)[:240]})
        checks.append(
            _check(
                "shellforgeai.import",
                "blocked",
                "ShellForgeAI import failed.",
                error_class=block["error_class"],
                error_message=block["error_message"],
            )
        )
        checks.append(
            _check(
                "shellforgeai.expected_source",
                "not_requested" if expected is None else "blocked",
                "Expected source could not be verified.",
            )
        )
    return block


def _runtime_context(
    profile: str, runtime_root: Path | None, checks: list[dict[str, Any]]
) -> dict[str, Any]:
    block: dict[str, Any] = {
        "profile": profile,
        "supplied_runtime_root": _norm(runtime_root),
        "config_path": None,
        "resolved": False,
        "runtime_root": None,
        "profile_root": None,
        "source": None,
        "checked_sources": [],
        "error_class": None,
        "error_message": None,
        "matches_supplied_runtime_root": None,
    }
    try:
        from shellforgeai.core.runtime_resolution import resolve_runtime_profile_context

        cfg = runtime_root / "config" / "profiles" / f"{profile}.yaml" if runtime_root else None
        block["config_path"] = _norm(cfg)
        ctx = resolve_runtime_profile_context(profile, config_path=cfg)
        block.update(
            {
                "resolved": ctx.resolved,
                "runtime_root": _norm(ctx.runtime_root),
                "profile_root": _norm(ctx.profile_root),
                "source": ctx.source,
                "checked_sources": list(ctx.checked_sources),
                "error_class": ctx.error_class,
                "error_message": ctx.error_message,
            }
        )
        if runtime_root is not None:
            # The established resolver reports the profile root for explicit profile files.
            # For this explicit runtime contract, the supplied runtime root is authoritative
            # when the requested profile file resolved successfully.
            if ctx.resolved and ctx.source == "explicit_config_path":
                block["runtime_root"] = _norm(runtime_root)
                block["profile_root"] = _norm(runtime_root)
            block["matches_supplied_runtime_root"] = _case(block["runtime_root"] or "") == _case(
                _norm(runtime_root) or ""
            )
        if runtime_root is not None and not (
            ctx.resolved and block["matches_supplied_runtime_root"]
        ):
            checks.append(
                _check(
                    "runtime.profile_context",
                    "blocked",
                    "Supplied runtime/profile contract did not resolve.",
                    source=ctx.source,
                    checked_sources=list(ctx.checked_sources),
                )
            )
        elif ctx.resolved:
            status = (
                "attention"
                if runtime_root is None
                and ctx.source not in {"explicit_config_path", "SHELLFORGEAI_RUNTIME_ROOT"}
                else "pass"
            )
            checks.append(
                _check(
                    "runtime.profile_context",
                    status,
                    "Runtime profile context resolved.",
                    source=ctx.source,
                )
            )
        else:
            checks.append(
                _check(
                    "runtime.profile_context",
                    "attention",
                    "Runtime profile context was not requested and did not resolve.",
                )
            )
    except Exception as exc:
        block.update({"error_class": exc.__class__.__name__, "error_message": str(exc)[:240]})
        checks.append(
            _check("runtime.profile_context", "blocked", "Runtime profile resolver failed.")
        )
    return block


def _wrapper(
    wrapper: Path | None, canonical: Path | None, checks: list[dict[str, Any]]
) -> dict[str, Any]:
    block: dict[str, Any] = {
        "wrapper_path": _norm(wrapper),
        "exists": None,
        "is_file": None,
        "sha256": None,
        "canonical_wrapper_path": _norm(canonical),
        "canonical_exists": None,
        "canonical_sha256": None,
        "normalized_text_equal": None,
        "semantic_markers": {},
        "material_match": None,
    }
    if wrapper is None:
        checks += [
            _check("wrapper.exists", "not_requested", "Durable wrapper was not supplied."),
            _check(
                "wrapper.semantic_markers", "not_requested", "Wrapper markers were not requested."
            ),
            _check(
                "wrapper.canonical_match",
                "not_requested",
                "Canonical wrapper comparison was not requested.",
            ),
        ]
        return block
    block["exists"] = wrapper.exists()
    block["is_file"] = wrapper.is_file()
    block["sha256"] = _sha(wrapper) if wrapper.is_file() else None
    text = _read_text(wrapper) if wrapper.is_file() else None
    checks.append(
        _check(
            "wrapper.exists",
            "pass" if wrapper.is_file() else "blocked",
            "Durable wrapper exists."
            if wrapper.is_file()
            else "Durable wrapper is missing or not a file.",
        )
    )
    markers = {name: (needle in (text or "")) for name, needle in MARKERS.items()}
    block["semantic_markers"] = markers
    checks.append(
        _check(
            "wrapper.semantic_markers",
            "pass" if all(markers.values()) else "blocked",
            "Required wrapper markers are present."
            if all(markers.values())
            else "Required wrapper markers are missing.",
            markers=markers,
        )
    )
    if canonical is None:
        checks.append(
            _check(
                "wrapper.canonical_match", "not_requested", "Canonical wrapper was not supplied."
            )
        )
        return block
    block["canonical_exists"] = canonical.exists()
    block["canonical_sha256"] = _sha(canonical) if canonical.is_file() else None
    ctext = _read_text(canonical) if canonical.is_file() else None
    equal = (
        _normalized_text(text) == _normalized_text(ctext)
        if text is not None and ctext is not None
        else False
    )
    block["normalized_text_equal"] = equal
    block["material_match"] = equal
    checks.append(
        _check(
            "wrapper.canonical_match",
            "pass" if equal and canonical.is_file() else "blocked",
            "Durable wrapper materially matches canonical wrapper."
            if equal and canonical.is_file()
            else "Durable wrapper does not materially match canonical wrapper.",
        )
    )
    return block


def _embedded(
    runtime_root: Path | None, wrapper: Path | None, checks: list[dict[str, Any]]
) -> tuple[dict[str, Any], Path | None]:
    derived = runtime_root or (wrapper.parent.parent if wrapper else None)
    expected = derived / "Python314" / "python.exe" if derived else None
    exe = Path(sys.executable)
    block = {
        "derived_runtime_root": _norm(derived),
        "expected_path": _norm(expected),
        "exists": expected.exists() if expected else None,
        "active_executable_equals_expected": (
            _case(_norm(exe) or "") == _case(_norm(expected) or "") if expected else None
        ),
        "active_executable_under_runtime_root": _inside_root(exe, derived) if derived else None,
    }
    if expected is None:
        checks.append(
            _check(
                "embedded_python.exists",
                "not_requested",
                "Embedded Python contract was not supplied.",
            )
        )
    else:
        checks.append(
            _check(
                "embedded_python.exists",
                "pass" if expected.exists() else "blocked",
                "Expected embedded Python exists."
                if expected.exists()
                else "Expected embedded Python is missing.",
            )
        )
    return block, expected


def _entrypoint(
    entry: Path | None, expected_py: Path | None, checks: list[dict[str, Any]]
) -> dict[str, Any]:
    scripts_dir = expected_py.parent / "Scripts" if expected_py else None
    block = {
        "path": _norm(entry),
        "exists": entry.exists() if entry else None,
        "is_file": entry.is_file() if entry else None,
        "basename": entry.name if entry else None,
        "under_embedded_scripts": _inside_root(entry, scripts_dir)
        if entry and scripts_dir
        else None,
    }
    if entry is None:
        checks.append(_check("entrypoint.exists", "not_requested", "Entry point was not supplied."))
    else:
        checks.append(
            _check(
                "entrypoint.exists",
                "pass" if entry.is_file() else "blocked",
                "Entry point exists."
                if entry.is_file()
                else "Entry point is missing or not a file.",
            )
        )
    return block


def _site_roots() -> list[Path]:
    roots: list[Path] = []
    for getter in (site.getsitepackages,):
        with suppress(Exception):
            roots.extend(Path(p) for p in getter())
    with suppress(Exception):
        user = site.getusersitepackages()
        if user:
            roots.append(Path(user))
    for key in ("purelib", "platlib"):
        val = sysconfig.get_paths().get(key)
        if val:
            roots.append(Path(val))
    seen: set[str] = set()
    out: list[Path] = []
    for root in roots:
        n = _case(_norm(root) or str(root))
        if n not in seen:
            seen.add(n)
            out.append(root)
    return out


def _residue(checks: list[dict[str, Any]], max_results: int = 20) -> dict[str, Any]:
    matches: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    for root in _site_roots():
        try:
            if not root.is_dir():
                warnings.append({"root": _norm(root) or str(root), "warning": "not_directory"})
                continue
            for child in sorted(root.iterdir(), key=lambda p: p.name.casefold()):
                if child.name.casefold().startswith("~hellforgeai") and len(matches) < max_results:
                    matches.append({"root": _norm(root) or str(root), "name": child.name})
        except OSError:
            warnings.append({"root": _norm(root) or str(root), "warning": "unreadable"})
    status = "attention" if matches or warnings else "pass"
    checks.append(
        _check(
            "invalid_distribution_residue",
            status,
            "Invalid distribution residue check completed.",
            residue_count=len(matches),
            warnings=len(warnings),
        )
    )
    return {
        "roots_checked": [_norm(r) for r in _site_roots()],
        "matches": matches,
        "max_results": max_results,
        "truncated": len(matches) >= max_results,
        "residue_count": len(matches),
        "warnings": warnings,
    }


def _summarize(checks: list[dict[str, Any]]) -> dict[str, int]:
    c = Counter(item["status"] for item in checks)
    return {
        state: c.get(state, 0)
        for state in ("pass", "attention", "blocked", "not_requested", "unsupported")
    }


def _status(checks: list[dict[str, Any]], system: str) -> str:
    if system != "windows":
        return "unsupported"
    states = {c["status"] for c in checks}
    if "blocked" in states:
        return "blocked"
    if states & {"attention", "not_requested"}:
        return "attention"
    return "ok"


def build_packet(args: argparse.Namespace) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    system = platform.system().lower()
    platform_block = _platform_block()
    checks.append(
        _check(
            "platform.windows",
            "pass" if system == "windows" else "unsupported",
            "Windows platform detected."
            if system == "windows"
            else "Windows runtime integrity is unsupported on this host.",
        )
    )
    helper = Path(__file__)
    expected = _path(args.expected_source_root)
    runtime = _path(args.runtime_root)
    wrapper_path = _path(args.wrapper_path)
    canonical = _path(args.canonical_wrapper_path)
    entry = _path(args.entrypoint_path)
    invocation = {
        "cwd": _norm(Path.cwd()),
        "helper_path": _norm(helper),
        "arguments": {
            "expected_source_root": _norm(expected),
            "runtime_root": _norm(runtime),
            "wrapper_path": _norm(wrapper_path),
            "canonical_wrapper_path": _norm(canonical),
            "entrypoint_path": _norm(entry),
            "profile": args.profile,
        },
        "supplied": {
            "expected_source_root": expected is not None,
            "runtime_root": runtime is not None,
            "wrapper_path": wrapper_path is not None,
            "canonical_wrapper_path": canonical is not None,
            "entrypoint_path": entry is not None,
        },
    }
    py = {
        "executable": _norm(Path(sys.executable)),
        "version": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "prefix": _norm(Path(sys.prefix)),
        "base_prefix": _norm(Path(sys.base_prefix)),
        "supplied_runtime_root": _norm(runtime),
        "active_executable_inside_supplied_runtime_root": _inside_root(
            Path(sys.executable), runtime
        )
        if runtime
        else None,
        **_runtime_kind(Path(sys.executable), Path(sys.prefix), Path(sys.base_prefix)),
    }
    checks.append(_check("python.runtime", "pass", "Active Python runtime recorded."))
    checks.append(
        _check(
            "python.runtime_root",
            "pass"
            if runtime and py["active_executable_inside_supplied_runtime_root"]
            else ("not_requested" if runtime is None else "attention"),
            "Python runtime root relationship recorded.",
        )
    )
    if system != "windows":
        for cid in CHECK_ORDER:
            if cid not in {c["id"] for c in checks}:
                checks.append(
                    _check(
                        cid, "unsupported", "Windows-only inspection skipped on unsupported host."
                    )
                )
        shell_import = {
            "success": None,
            "module_file": None,
            "package_root": None,
            "expected_source_root": _norm(expected),
            "expected_source_match": None,
            "mismatch_reason": None,
        }
        runtime_context = {
            "profile": args.profile,
            "supplied_runtime_root": _norm(runtime),
            "resolved": None,
            "source": None,
            "checked_sources": [],
        }
        wrapper = {
            "wrapper_path": _norm(wrapper_path),
            "canonical_wrapper_path": _norm(canonical),
            "material_match": None,
        }
        embedded = {"derived_runtime_root": _norm(runtime), "expected_path": None, "exists": None}
        entrypoint = {"path": _norm(entry), "exists": None}
        residue = {
            "roots_checked": [],
            "matches": [],
            "max_results": 20,
            "truncated": False,
            "residue_count": 0,
            "warnings": [],
        }
    else:
        shell_import = _import_block(expected, checks)
        runtime_context = _runtime_context(args.profile, runtime, checks)
        wrapper = _wrapper(wrapper_path, canonical, checks)
        embedded, expected_py = _embedded(runtime, wrapper_path, checks)
        entrypoint = _entrypoint(entry, expected_py, checks)
        residue = _residue(checks)
    summary = _summarize(checks)
    first = " ".join(
        shlex.quote(part)
        for part in [sys.executable, str(helper), "--json"]
        + sum(
            (
                [flag, val]
                for flag, val in (
                    ("--expected-source-root", args.expected_source_root),
                    ("--runtime-root", args.runtime_root),
                    ("--wrapper-path", args.wrapper_path),
                    ("--canonical-wrapper-path", args.canonical_wrapper_path),
                    ("--entrypoint-path", args.entrypoint_path),
                    ("--profile", args.profile),
                )
                if val
            ),
            [],
        )
    )
    packet = {
        "schema_version": 1,
        "mode": "windows_runtime_integrity",
        "status": _status(checks, system),
        "platform": platform_block,
        "invocation": invocation,
        "python_runtime": py,
        "shellforgeai_import": shell_import,
        "runtime_context": runtime_context,
        "wrapper": wrapper,
        "embedded_python": embedded,
        "entrypoint": entrypoint,
        "invalid_distribution_residue": residue,
        "checks": checks,
        "summary": summary,
        "first_safe_command": first,
        "read_only": True,
        "mutation_performed": False,
        "safety": dict(SAFETY),
    }
    return packet


def render_text(p: dict[str, Any]) -> str:
    return "\n".join(
        [
            "ShellForgeAI Windows runtime integrity",
            f"Status: {p['status']}",
            f"Active Python: {p['python_runtime'].get('executable')}",
            f"ShellForgeAI import: {p['shellforgeai_import'].get('module_file')}",
            f"Expected source match: {p['shellforgeai_import'].get('expected_source_match')}",
            f"Runtime source: {p['runtime_context'].get('source')}",
            f"Wrapper match: {p['wrapper'].get('material_match')}",
            f"Embedded Python exists: {p['embedded_python'].get('exists')}",
            f"Entry point exists: {p['entrypoint'].get('exists')}",
            "Invalid distribution residue count: "
            f"{p['invalid_distribution_residue'].get('residue_count')}",
            f"Summary: {p['summary']}",
            f"First safe command: {p['first_safe_command']}",
            "Read-only: true; mutation performed: false.",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-source-root")
    parser.add_argument("--runtime-root")
    parser.add_argument("--wrapper-path")
    parser.add_argument("--canonical-wrapper-path")
    parser.add_argument("--entrypoint-path")
    parser.add_argument("--profile", default="inspect")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out-json")
    args = parser.parse_args(argv)
    packet = build_packet(args)
    if args.out_json:
        out = Path(args.out_json)
        if out.exists():
            parser.error(f"refusing to overwrite existing artifact: {out}")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
    print(
        json.dumps(packet, sort_keys=True, separators=(",", ":"))
        if args.json
        else render_text(packet)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
