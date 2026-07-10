"""``model`` command group registration (extracted in PR196).

Behavior-preserving move of the ``model`` command group: ``model doctor``
(previously registered from :mod:`shellforgeai.commands.doctor` since PR182)
and ``model test`` (previously inline in ``cli.py``). The handlers delegate to
existing ``shellforgeai.cli`` module attributes (resolved at call time) so
monkeypatch hooks like ``cli.build_provider``, the shared console, output,
exit codes, and safety behavior are preserved exactly.

``model doctor`` remains the read-only provider-readiness report: it prints
the provider doctor fields (provider/model/fallback, codex binary detection,
auth cache presence separately from live auth readiness, sandbox/approval) and suggests
``codex login`` recovery when the auth cache is missing. It never calls model
inference, never starts a Codex task, and never mutates anything. ``model
test`` keeps its existing explicit one-shot model call surface unchanged. No
cleanup, remediation, rollback, recovery, Docker/Compose mutation, restart,
shell execution, or arbitrary/natural-language execution is introduced here.
"""

from __future__ import annotations

import hashlib
import json as json_lib
import sys
import time
from pathlib import Path
from typing import Annotated, Any

import typer

from shellforgeai.core.model_receipt_history import (
    build_model_receipt_compare,
    build_model_receipt_history,
    render_model_receipt_compare_markdown,
    render_model_receipt_history_markdown,
)
from shellforgeai.core.model_receipt_validation import (
    render_model_receipt_validation_markdown,
    validate_model_doctor_receipt,
    write_model_receipt_validation,
)
from shellforgeai.core.read_only_safety import read_only_safety_metadata
from shellforgeai.llm.schemas import ModelRequest, ModelResponse

MODEL_DOCTOR_PROBE_PROMPT = (
    "ShellForgeAI model doctor readiness probe. Reply with exactly: SFAI_MODEL_DOCTOR_READY"
)
# PR289 — one bounded live probe still needs a realistic model roundtrip
# budget: CLI startup plus a real completion regularly exceeds the old 10s,
# which misreported healthy auth as "codex timed out" on Windows. Still
# bounded; never indefinite.
MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS = 60


def _bounded_error(text: object) -> str | None:
    if text is None:
        return None
    value = str(text).replace("\n", " ").replace("\r", " ").strip()
    lowered = value.lower()
    if any(
        word in lowered
        for word in ("token", "secret", "password", "api_key", "authorization", "bearer")
    ):
        return "provider error details redacted"
    return value[:240]


def _probe_invocation_diagnostics(info: dict[str, Any], resp: Any | None = None) -> dict[str, Any]:
    """Bounded PR291 invocation diagnostics for the live probe payload.

    Reports the sandbox mode and whether the scoped Codex repository-trust
    bypass (``--skip-git-repo-check``) was applied, preferring the actual
    invocation metadata over the static doctor readiness fields. Never reads
    auth-cache contents and never records the process environment.
    """
    meta: dict[str, Any] = {}
    if resp is not None and getattr(resp, "metadata", None):
        meta = resp.metadata
    return {
        "sandbox_mode": meta.get("sandbox_mode") or info.get("sandbox_mode") or info.get("sandbox"),
        "skip_git_repo_check_used": bool(
            meta.get("skip_git_repo_check_used", info.get("skip_git_repo_check_used", False))
        ),
    }


def _auth_readiness_after_probe_timeout(info: dict[str, Any]) -> str:
    """Auth readiness when the bounded live probe timed out.

    A model-response timeout is a live-probe outcome, not an authentication
    failure: when login status was already proven (``login_status_ok``), auth
    readiness keeps its verified value instead of degrading to ``failed`` /
    ``missing_auth_cache`` / ``not_configured``. Without proven login the
    pre-existing behavior (``failed``) is kept — a timeout cannot prove auth.
    """
    if bool(info.get("login_status_ok")):
        return str(info.get("auth_readiness") or "verified_login_status")
    return "failed"


def _run_live_probe(provider: Any, info: dict[str, Any], runtime: Any) -> dict[str, Any]:
    # PR289 — a tester-scoped CODEX_HOME proven by safe `codex login status`
    # configures the provider even when the profile-default auth cache is
    # absent (QGA/SYSTEM lanes). Skip as not_configured only when neither
    # signal indicates credentials.
    login_status_ok = bool(info.get("login_status_ok"))
    if (not bool(info.get("auth_cache_present")) and not login_status_ok) or str(
        info.get("auth_readiness")
    ) in {
        "missing_auth_cache",
        "missing_binary",
        "not_configured",
        "login_status_not_proven",
    }:
        return {
            "auth_readiness": "not_configured",
            "probe": {
                "status": "skipped",
                "provider": info.get("provider") or runtime.settings.model.provider,
                "model": info.get("model") or runtime.settings.model.model,
                "timeout_seconds": MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS,
                "request_id": None,
                "latency_ms": 0,
                "error_class": "not_configured",
                "error_message": "model credentials are not configured",
                "model_response_captured": False,
                **_probe_invocation_diagnostics(info),
            },
            "model_call_performed": False,
            "timed_out": False,
        }
    req = ModelRequest(
        prompt=MODEL_DOCTOR_PROBE_PROMPT,
        model=str(info.get("model") or runtime.settings.model.model),
        provider=str(info.get("provider") or runtime.settings.model.provider),
        timeout_seconds=MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS,
        max_output_tokens=8,
        metadata={
            "purpose": "model_doctor_live_probe",
            "tools_allowed": False,
            "operator_prompt_included": False,
        },
    )
    started = time.monotonic()
    try:
        resp: ModelResponse = provider.complete(req)
    except TimeoutError as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        return {
            "auth_readiness": _auth_readiness_after_probe_timeout(info),
            "model_call_performed": True,
            "timed_out": True,
            "probe": {
                "status": "failed",
                "provider": req.provider,
                "model": req.model,
                "timeout_seconds": MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS,
                "request_id": None,
                "latency_ms": latency_ms,
                "error_class": "model_probe_timeout",
                "error_message": _bounded_error(exc) or "probe timed out",
                "model_response_captured": False,
                **_probe_invocation_diagnostics(info),
            },
        }
    except Exception as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        return {
            "auth_readiness": "failed",
            "model_call_performed": True,
            "timed_out": False,
            "probe": {
                "status": "failed",
                "provider": req.provider,
                "model": req.model,
                "timeout_seconds": MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS,
                "request_id": None,
                "latency_ms": latency_ms,
                "error_class": exc.__class__.__name__,
                "error_message": _bounded_error(exc),
                "model_response_captured": False,
                **_probe_invocation_diagnostics(info),
            },
        }
    latency_ms = int(resp.duration_ms or ((time.monotonic() - started) * 1000))
    request_id = None
    if resp.metadata:
        request_id = resp.metadata.get("request_id") or resp.metadata.get("thread_id")
    if resp.ok:
        meta = resp.metadata or {}
        return {
            "auth_readiness": "verified",
            "model_call_performed": True,
            "timed_out": False,
            "probe": {
                "status": "passed",
                "provider": resp.provider or req.provider,
                "model": resp.model or req.model,
                "timeout_seconds": MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS,
                "request_id": request_id,
                "latency_ms": latency_ms,
                "error_class": None,
                "error_message": None,
                # Deterministic capture: ok already requires a non-empty final
                # response; providers that report the --output-last-message
                # capture explicitly take precedence.
                "model_response_captured": bool(
                    meta.get("model_response_captured", bool((resp.text or "").strip()))
                ),
                **_probe_invocation_diagnostics(info, resp),
            },
        }
    err = _bounded_error(resp.error) or "live probe failed"
    # PR291 — keep the failure class precise: a repository-trust rejection,
    # CLI argument-ordering failure, or other classified Codex invocation
    # failure must never collapse into a generic provider/auth error.
    meta = resp.metadata or {}
    err_class = str(meta.get("codex_exec_error_class") or "")
    if not err_class:
        err_class = (
            "timeout"
            if "timeout" in err.lower() or "timed out" in err.lower()
            else "provider_error"
        )
    timed_out = bool(meta.get("codex_exec_timed_out")) or err_class == "timeout"
    if timed_out:
        # PR291 fix — a bounded model-response timeout is a live-probe
        # outcome, never an authentication failure once login is proven.
        err_class = "model_probe_timeout"
    return {
        "auth_readiness": (_auth_readiness_after_probe_timeout(info) if timed_out else "failed"),
        "model_call_performed": True,
        "timed_out": timed_out,
        "probe": {
            "status": "failed",
            "provider": resp.provider or req.provider,
            "model": resp.model or req.model,
            "timeout_seconds": MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS,
            "request_id": request_id,
            "latency_ms": latency_ms,
            "error_class": err_class,
            "error_message": err,
            "codex_exec_stderr_excerpt": str(meta.get("codex_exec_stderr_excerpt") or ""),
            "model_response_captured": bool(meta.get("model_response_captured", False)),
            **_probe_invocation_diagnostics(info, resp),
        },
    }


def _write_model_doctor_receipt(out_dir: Path, payload: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "model-doctor-live-probe.json"
    summary_path = out_dir / "model-doctor-live-probe-summary.md"
    manifest_path = out_dir / "manifest.json"
    checksums_path = out_dir / "checksums.json"
    json_path.write_text(json_lib.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    probe = payload.get("probe") or {}
    summary = (
        "# Model Doctor live probe receipt\n\n"
        f"- Auth readiness: {payload.get('auth_readiness')}\n"
        f"- Live probe requested: {str(payload.get('live_probe_requested')).lower()}\n"
        f"- Live probe performed: {str(payload.get('live_probe_performed')).lower()}\n"
        f"- Live probe: {probe.get('status', 'skipped')}\n"
        "- No tools were executed.\n"
        "- No mutation was performed.\n"
    )
    summary_path.write_text(summary, encoding="utf-8")
    files = ["model-doctor-live-probe.json", "model-doctor-live-probe-summary.md"]
    checksums: dict[str, dict[str, object]] = {}
    for rel in files:
        data = (out_dir / rel).read_bytes()
        checksums[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    manifest = {
        "schema_version": 1,
        "mode": "model_doctor",
        "files": files + ["manifest.json", "checksums.json"],
        "read_only": True,
        "mutation_performed": False,
        "checksums": checksums,
    }
    manifest_path.write_text(
        json_lib.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    data = manifest_path.read_bytes()
    checksums["manifest.json"] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }
    checksums_path.write_text(
        json_lib.dumps(
            {"schema_version": 1, "algorithm": "sha256", "files": checksums},
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def register(model_app: typer.Typer) -> None:
    """Register ``doctor`` and ``test`` on the existing ``model`` Typer app.

    Both handlers resolve shared ``shellforgeai.cli`` helpers lazily (for
    example ``cli.build_provider`` and ``cli.console``) to preserve the
    monkeypatch hooks used by the test suite and the exact current behavior.
    """

    cli = sys.modules["shellforgeai.cli"]

    receipt_app = typer.Typer(help="Read-only Model Doctor receipt history and compare.")
    model_app.add_typer(receipt_app, name="receipt")

    @receipt_app.command("history")
    def model_receipt_history(
        root: Annotated[
            Path,
            typer.Option(
                "--root", file_okay=False, help="Bounded root to scan for receipt directories."
            ),
        ] = Path("/tmp"),
        json_output: bool = typer.Option(False, "--json", help="Emit strict JSON output."),
    ) -> None:
        result = build_model_receipt_history(root)
        if json_output:
            typer.echo(json_lib.dumps(result, sort_keys=True, separators=(",", ":")))
        else:
            cli.console.print(render_model_receipt_history_markdown(result))

    @receipt_app.command("compare")
    def model_receipt_compare(
        old_receipt_dir: Annotated[Path, typer.Argument(file_okay=False, exists=False)],
        new_receipt_dir: Annotated[Path, typer.Argument(file_okay=False, exists=False)],
        json_output: bool = typer.Option(False, "--json", help="Emit strict JSON output."),
    ) -> None:
        result = build_model_receipt_compare(old_receipt_dir, new_receipt_dir)
        if json_output:
            typer.echo(json_lib.dumps(result, sort_keys=True, separators=(",", ":")))
        else:
            cli.console.print(render_model_receipt_compare_markdown(result))

    @model_app.command("doctor")
    def model_doctor(
        ctx: typer.Context,
        json_output: bool = typer.Option(False, "--json", help="Emit strict JSON output."),
        live_probe: bool = typer.Option(
            False, "--live-probe", help="Perform one bounded live auth/readiness probe."
        ),
        receipt_out: Annotated[
            Path | None,
            typer.Option(
                "--receipt-out", file_okay=False, help="Write bounded model doctor receipt files."
            ),
        ] = None,
        validate_receipt: Annotated[
            Path | None,
            typer.Option(
                "--validate-receipt",
                file_okay=False,
                exists=False,
                help="Validate an existing model doctor receipt directory.",
            ),
        ] = None,
        validation_out: Annotated[
            Path | None,
            typer.Option(
                "--validation-out",
                file_okay=False,
                help="Write bounded receipt validation artifacts.",
            ),
        ] = None,
    ) -> None:
        if validate_receipt is not None:
            result = validate_model_doctor_receipt(validate_receipt)
            if validation_out is not None:
                write_model_receipt_validation(validation_out, result)
            if json_output:
                typer.echo(json_lib.dumps(result, sort_keys=True, separators=(",", ":")))
            else:
                cli.console.print(render_model_receipt_validation_markdown(result))
            return
        runtime = cli._ctx(ctx)
        warnings: list[str] = []
        provider: Any | None = None
        try:
            provider = cli.build_provider(runtime.settings)
            info = provider.doctor()
        except Exception as exc:
            info = {
                "provider": runtime.settings.model.provider,
                "model": runtime.settings.model.model,
                "auth_readiness": "unknown",
                "auth_reason": "doctor_unavailable",
            }
            warnings.append(f"model doctor readiness unavailable: {exc}")
        auth_cache_present = bool(info.get("auth_cache_present"))
        auth_readiness = str(info.get("auth_readiness") or "unknown")
        auth_reason = str(info.get("auth_reason") or "status_unknown")
        codex_home_configured = bool(info.get("codex_home_configured"))
        login_status_checked = bool(info.get("login_status_checked"))
        login_status_ok = bool(info.get("login_status_ok"))
        ok = auth_readiness not in {
            "failed",
            "error",
            "missing_binary",
            "missing_auth_cache",
            "unauthorized",
            "login_status_not_proven",
        }
        live_probe_available = bool(info.get("live_probe_available", False))
        live_probe_performed = bool(info.get("live_probe_performed", False))
        safe_next_command = str(info.get("safe_next_command") or "shellforgeai model doctor --json")
        live_result: dict[str, Any] | None = None
        live_probe_timed_out = False
        live_probe_error_class: str | None = None
        live_probe_status = "not_requested"
        live_probe_completed = False
        model_call_attempted = False
        model_response_captured = False
        if live_probe:
            if provider is None:
                live_result = {
                    "auth_readiness": "failed",
                    "model_call_performed": False,
                    "timed_out": False,
                    "probe": {
                        "status": "failed",
                        "provider": info.get("provider"),
                        "model": info.get("model"),
                        "timeout_seconds": MODEL_DOCTOR_PROBE_TIMEOUT_SECONDS,
                        "request_id": None,
                        "latency_ms": 0,
                        "error_class": "doctor_unavailable",
                        "error_message": "model doctor provider unavailable",
                        "model_response_captured": False,
                    },
                }
            else:
                live_result = _run_live_probe(provider, info, runtime)
            auth_readiness = str(live_result["auth_readiness"])
            live_probe_timed_out = bool(live_result.get("timed_out"))
            # PR291 fix — a bounded probe timeout keeps the proven auth
            # readiness; the warning is expressed through the probe outcome
            # fields and the overall doctor status, not by faking auth
            # failure (never missing_auth_cache / not_configured here).
            auth_reason = "live_probe_timed_out" if live_probe_timed_out else "live_probe_requested"
            live_probe_available = True
            live_probe_performed = bool(live_result["model_call_performed"])
            model_call_attempted = live_probe_performed
            live_probe_status = str(live_result["probe"].get("status") or "failed")
            live_probe_error_class = live_result["probe"].get("error_class")
            live_probe_completed = live_probe_performed and not live_probe_timed_out
            model_response_captured = bool(live_result["probe"].get("model_response_captured"))
            ok = (
                auth_readiness not in {"failed", "not_configured"} and live_probe_status == "passed"
            )
        payload = {
            "schema_version": 1,
            "mode": "model_doctor",
            "status": "ok" if ok else "warning",
            "ok": ok,
            "read_only": True,
            "mutation_performed": False,
            "provider": info.get("provider"),
            "model": info.get("model"),
            "codex_binary": info.get("codex_binary"),
            "codex_resolved_binary": info.get("codex_resolved_binary"),
            "codex_version": info.get("codex_version"),
            "auth_cache_present": auth_cache_present,
            "auth_cache_contents_inspected": bool(info.get("auth_cache_contents_inspected", False)),
            "codex_home_configured": codex_home_configured,
            "login_status_checked": login_status_checked,
            "login_status_ok": login_status_ok,
            "login_status_source": info.get("login_status_source", "not_checked"),
            "auth_readiness": auth_readiness,
            "auth_reason": auth_reason,
            "auth_verification_status": auth_readiness,
            "auth_readiness_label": auth_readiness.replace("_", " "),
            "sandbox_mode": info.get("sandbox_mode", info.get("sandbox")),
            "skip_git_repo_check_used": bool(info.get("skip_git_repo_check_used", False)),
            "live_probe_requested": live_probe,
            "live_probe_available": live_probe_available,
            "live_probe_performed": live_probe_performed,
            "live_probe_completed": live_probe_completed,
            "live_probe_status": live_probe_status,
            "live_probe_timed_out": live_probe_timed_out,
            "live_probe_error_class": live_probe_error_class,
            "model_call_attempted": model_call_attempted,
            "model_response_captured": model_response_captured,
            "model_called": live_probe_performed,
            "safe_next_command": safe_next_command,
            "warnings": warnings,
            "doctor": info,
            "safety": read_only_safety_metadata(model_call_performed=live_probe_performed),
        }
        if live_result is not None:
            payload["probe"] = live_result["probe"]
        else:
            payload["reason"] = "Live auth probe was not requested."
            payload["safety"]["model_call_performed"] = False
        if receipt_out is not None:
            _write_model_doctor_receipt(receipt_out, payload)
        if json_output:
            typer.echo(json_lib.dumps(payload, sort_keys=True, separators=(",", ":")))
            return
        for k, v in info.items():
            cli.console.print(f"{k}={v}")
        cli.console.print(f"Auth cache: {'present' if auth_cache_present else 'missing'}")
        if login_status_checked:
            cli.console.print(
                "Codex login status: "
                + ("proven (Logged in using ChatGPT)" if login_status_ok else "not proven")
            )
            cli.console.print("Auth cache contents were not inspected.")
        readiness_label = auth_readiness.replace("_", " ")
        cli.console.print(f"Live auth readiness: {readiness_label}")
        cli.console.print(f"Auth readiness: {readiness_label}")
        if live_result is None:
            if auth_reason == "auth_cache_present_live_probe_not_run":
                cli.console.print("Reason: default model doctor does not call the model")
            cli.console.print("Reason: live auth probe was not requested.")
            cli.console.print("No model call was made.")
        else:
            probe = live_result["probe"]
            cli.console.print(f"Live probe: {probe['status']}")
            if probe.get("error_message"):
                cli.console.print(f"Reason: {probe['error_message']}")
            cli.console.print("No tools were executed.")
            cli.console.print("No mutation was performed.")
        cli.console.print(f"Safe next step: {safe_next_command}")
        if auth_readiness == "missing_binary":
            cli.console.print(
                "Codex CLI binary is missing; configure Codex before model-backed synthesis."
            )
        elif not login_status_ok and (
            auth_readiness in {"missing_auth_cache", "failed", "login_status_not_proven"}
            or not auth_cache_present
        ):
            cli.console.print("Suggested login: codex login (or codex login --device-auth)")

    @model_app.command("test")
    def model_test(
        ctx: typer.Context,
        prompt: Annotated[str, typer.Argument()] = "Reply with: Hello.",
        raw: bool = typer.Option(False, "--raw"),
        timeout: int | None = typer.Option(None, "--timeout"),
        model: str | None = typer.Option(None, "--model"),
    ) -> None:
        runtime = cli._ctx(ctx)
        provider = cli.build_provider(runtime.settings)
        req = ModelRequest(
            prompt=prompt,
            model=model or runtime.settings.model.model,
            provider=runtime.settings.model.provider,
            timeout_seconds=timeout or runtime.settings.model.timeout_seconds,
            metadata={"raw": raw},
        )
        resp = provider.complete(req)
        cli.console.print(resp.text)
        cli.console.print(
            f"\nProvider: {resp.provider}\n"
            f"Model: {resp.model}\n"
            f"OK: {str(resp.ok).lower()}\n"
            f"{cli._usage_line(resp)}"
        )
        if raw and resp.raw and resp.raw.get("stdout_jsonl"):
            cli.console.print(resp.raw["stdout_jsonl"])
