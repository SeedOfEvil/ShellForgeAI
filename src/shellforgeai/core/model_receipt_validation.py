"""Read-only validation for model doctor live-probe receipt bundles."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shellforgeai.core.read_only_safety import read_only_safety_metadata

REQUIRED_RECEIPT_FILES = (
    "model-doctor-live-probe.json",
    "model-doctor-live-probe-summary.md",
    "manifest.json",
    "checksums.json",
)
SECRET_MARKERS = (
    "OPENAI_API_KEY",
    "Authorization:",
    "Bearer",
    "sk-",
    "ghp_",
    "BEGIN PRIVATE KEY",
)
ALLOWED_PROBE_STATUSES = {"passed", "failed", "skipped", "unknown"}
MAX_RECEIPT_FILE_BYTES = 256 * 1024
MAX_SUMMARY_BYTES = 64 * 1024
VALIDATION_FILES = (
    "model-doctor-receipt-validation.json",
    "model-doctor-receipt-validation-summary.md",
    "manifest.json",
    "checksums.json",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validation_safety() -> dict[str, bool]:
    safety = read_only_safety_metadata(model_call_performed=False)
    safety["live_probe_performed"] = False
    safety["validation_only"] = True
    safety["github_post_approve_merge"] = False
    return safety


def _check(checks: list[dict[str, str]], name: str, status: str, detail: str) -> None:
    checks.append({"name": name, "status": status, "detail": detail})


def _file_meta(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}


def _listed_files(value: Any) -> set[str]:
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, dict):
        return {str(key) for key in value}
    return set()


def validate_model_doctor_receipt(receipt_dir: Path) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    warnings: list[str] = []
    errors: list[str] = []
    receipt_dir = receipt_dir.expanduser()

    json_data: dict[str, Any] = {}
    manifest: dict[str, Any] = {}
    checksums: dict[str, Any] = {}
    json_parse_ok = True

    if not receipt_dir.exists() or not receipt_dir.is_dir():
        errors.append("receipt directory does not exist")
        _check(checks, "receipt_dir_exists", "failed", "receipt directory is missing")
    else:
        _check(checks, "receipt_dir_exists", "passed", "receipt directory exists")

    present = receipt_dir.is_dir() and all(
        (receipt_dir / name).is_file() for name in REQUIRED_RECEIPT_FILES
    )
    missing = [name for name in REQUIRED_RECEIPT_FILES if not (receipt_dir / name).is_file()]
    if present:
        _check(checks, "required_files_present", "passed", "all required receipt files are present")
    else:
        errors.append("missing required receipt files: " + ", ".join(missing))
        _check(checks, "required_files_present", "failed", "missing: " + ", ".join(missing))

    size_ok = True
    if receipt_dir.is_dir():
        for name in REQUIRED_RECEIPT_FILES:
            path = receipt_dir / name
            if path.is_file():
                limit = MAX_SUMMARY_BYTES if name.endswith(".md") else MAX_RECEIPT_FILE_BYTES
                size = path.stat().st_size
                if size > limit:
                    size_ok = False
                    errors.append(f"receipt file is too large: {name}")
    _check(checks, "bounded_files", "passed" if size_ok else "failed", "receipt files are bounded")

    if present and size_ok:
        for name in ("model-doctor-live-probe.json", "manifest.json", "checksums.json"):
            try:
                parsed = json.loads((receipt_dir / name).read_text(encoding="utf-8"))
                if name == "model-doctor-live-probe.json":
                    json_data = parsed
                elif name == "manifest.json":
                    manifest = parsed
                else:
                    checksums = parsed
            except Exception:
                json_parse_ok = False
                errors.append(f"invalid JSON: {name}")
        _check(checks, "json_parse_ok", "passed" if json_parse_ok else "failed", "JSON files parse")
    elif present:
        json_parse_ok = False
        _check(checks, "json_parse_ok", "failed", "oversized files were not parsed")
    else:
        json_parse_ok = False
        _check(checks, "json_parse_ok", "failed", "required JSON files unavailable")

    manifest_files = _listed_files(manifest.get("files"))
    manifest_ok = json_parse_ok and set(REQUIRED_RECEIPT_FILES).issubset(manifest_files)
    if manifest_ok and "mode" in manifest:
        manifest_ok = str(manifest.get("mode")) in {"model_doctor", "model_doctor_live_probe"}
    if not manifest_ok:
        errors.append("manifest does not list the expected model doctor receipt files")
    _check(
        checks,
        "manifest_ok",
        "passed" if manifest_ok else "failed",
        "manifest lists expected files",
    )

    checksum_files = (
        checksums.get("files") if isinstance(checksums.get("files"), dict) else checksums
    )
    checksum_names = _listed_files(checksum_files)
    checksum_required = set(REQUIRED_RECEIPT_FILES) - {"checksums.json"}
    checksums_ok = json_parse_ok and checksum_required.issubset(checksum_names)
    if checksums_ok:
        for name in checksum_required:
            expected = checksum_files.get(name, {})
            actual = _file_meta(receipt_dir / name)
            if expected.get("sha256") != actual["sha256"]:
                checksums_ok = False
            if (
                "size_bytes" in expected
                and int(expected.get("size_bytes", -1)) != actual["size_bytes"]
            ):
                checksums_ok = False
    if not checksums_ok:
        errors.append("checksum or size metadata mismatch")
    _check(
        checks,
        "checksums_ok",
        "passed" if checksums_ok else "failed",
        "checksums and represented sizes match",
    )

    secret_scan_ok = True
    if receipt_dir.is_dir():
        for name in REQUIRED_RECEIPT_FILES:
            path = receipt_dir / name
            if path.is_file() and path.stat().st_size <= MAX_RECEIPT_FILE_BYTES:
                text = path.read_text(encoding="utf-8", errors="ignore")
                lower = text.lower()
                if any(marker.lower() in lower for marker in SECRET_MARKERS):
                    secret_scan_ok = False
                    errors.append(f"secret marker found in {name}")
                    break
    _check(
        checks,
        "secret_scan_ok",
        "passed" if secret_scan_ok else "failed",
        "known secret markers are absent",
    )

    probe_status = str((json_data.get("probe") or {}).get("status") or "unknown")
    probe_status_ok = probe_status in ALLOWED_PROBE_STATUSES
    live_probe_requested = json_data.get("live_probe_requested") is True
    live_probe_performed = json_data.get("live_probe_performed") is True
    model_called = json_data.get("model_called") is True
    timeout_present = probe_status in {"skipped", "unknown"} or isinstance(
        (json_data.get("probe") or {}).get("timeout_seconds"), int
    )
    safety_payload = json_data.get("safety") if isinstance(json_data.get("safety"), dict) else {}
    safety_ok = bool(
        json_data.get("read_only") is True and json_data.get("mutation_performed") is False
    )
    for key in (
        "cleanup_executed",
        "docker_prune_executed",
        "docker_image_removed",
        "file_deleted",
        "docker_compose_executed",
        "container_restarted",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "natural_language_execution",
        "shell_true",
        "arbitrary_command_execution",
    ):
        if safety_payload.get(key) is True:
            safety_ok = False
    if not (
        probe_status_ok
        and live_probe_requested
        and live_probe_performed
        and model_called
        and timeout_present
    ):
        errors.append("receipt probe metadata is incomplete or inconsistent")
    if not safety_ok:
        errors.append("receipt safety posture is not read-only/no-mutation")
    _check(
        checks,
        "safety_ok",
        "passed" if safety_ok else "failed",
        "receipt safety posture is read-only/no-mutation",
    )
    _check(
        checks,
        "probe_metadata",
        "passed"
        if probe_status_ok
        and live_probe_requested
        and live_probe_performed
        and model_called
        and timeout_present
        else "failed",
        "probe metadata is present and bounded",
    )

    summary_ok = (receipt_dir / "model-doctor-live-probe-summary.md").is_file() and (
        receipt_dir / "model-doctor-live-probe-summary.md"
    ).stat().st_size <= MAX_SUMMARY_BYTES
    _check(
        checks,
        "summary_markdown",
        "passed" if summary_ok else "failed",
        "summary Markdown is present and bounded",
    )

    failed = any(item["status"] == "failed" for item in checks)
    warning = any(item["status"] == "warning" for item in checks)
    status = "failed" if failed else "partial" if warning else "passed"
    return {
        "schema_version": 1,
        "mode": "model_doctor_receipt_validation",
        "status": status,
        "receipt_dir": str(receipt_dir),
        "created_at": _now_iso(),
        "read_only": True,
        "mutation_performed": False,
        "summary": {
            "required_files_present": present,
            "json_parse_ok": json_parse_ok,
            "manifest_ok": manifest_ok,
            "checksums_ok": checksums_ok,
            "secret_scan_ok": secret_scan_ok,
            "safety_ok": safety_ok,
            "probe_status": probe_status if probe_status_ok else "unknown",
            "live_probe_requested": live_probe_requested,
            "live_probe_performed": live_probe_performed,
            "model_called": model_called,
        },
        "checks": checks,
        "warnings": warnings,
        "errors": errors,
        "safety": _validation_safety(),
        "first_safe_command": "shellforgeai model doctor --validate-receipt <receipt_dir> --json",
    }


def render_model_receipt_validation_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    by_name = {item["name"]: item for item in result["checks"]}

    def status(name: str) -> str:
        return by_name.get(name, {}).get("status", "failed")

    return (
        "# Model Doctor Receipt Validation\n\n"
        f"Receipt: {result['receipt_dir']}\n"
        f"Status: {result['status']}\n\n"
        "## Checks\n"
        f"* required files: {status('required_files_present')}\n"
        f"* JSON parse: {status('json_parse_ok')}\n"
        f"* manifest: {status('manifest_ok')}\n"
        f"* checksums: {status('checksums_ok')}\n"
        f"* secret scan: {status('secret_scan_ok')}\n"
        f"* safety posture: {status('safety_ok')}\n"
        f"* probe status: {summary['probe_status']}\n\n"
        "## Result\n"
        f"* {result['status']}\n\n"
        "## Safety\n"
        "* validation only\n"
        "* no live probe performed\n"
        "* no model call performed\n"
        "* no cleanup/prune/delete/restart\n"
        "* no remediation/rollback/recovery\n"
        "* no natural-language execution\n"
        "* no shell=True\n"
    )


def write_model_receipt_validation(out_dir: Path, result: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "model-doctor-receipt-validation.json"
    summary_path = out_dir / "model-doctor-receipt-validation-summary.md"
    manifest_path = out_dir / "manifest.json"
    checksums_path = out_dir / "checksums.json"
    json_path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    summary_path.write_text(render_model_receipt_validation_markdown(result), encoding="utf-8")
    metas = {name: _file_meta(out_dir / name) for name in VALIDATION_FILES[:2]}
    manifest = {
        "schema_version": 1,
        "mode": "model_doctor_receipt_validation",
        "files": list(VALIDATION_FILES),
        "read_only": True,
        "mutation_performed": False,
        "checksums": metas,
    }
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    metas["manifest.json"] = _file_meta(manifest_path)
    checksums_path.write_text(
        json.dumps(
            {"schema_version": 1, "algorithm": "sha256", "files": metas}, sort_keys=True, indent=2
        )
        + "\n",
        encoding="utf-8",
    )
