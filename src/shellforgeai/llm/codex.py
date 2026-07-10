from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from shellforgeai.llm.codex_events import parse_codex_jsonl
from shellforgeai.llm.schemas import ModelRequest, ModelResponse


def _redact(text: str) -> str:
    if not text:
        return text
    out = []
    for ln in text.splitlines():
        low = ln.lower()
        if any(
            k in low for k in ("token", "secret", "password", "api_key", "authorization", "bearer")
        ):
            out.append("[REDACTED]")
        else:
            out.append(ln)
    return "\n".join(out)


def _format_human_value(value: str | None) -> str:
    """Quote a human-facing provider value without repr-style path escaping."""
    if value is None:
        return "'<unresolved>'"
    return f"'{str(value)}'"


CODEX_LOGIN_STATUS_PHRASE = "Logged in using ChatGPT"
CODEX_LOGIN_STATUS_TIMEOUT_SECONDS = 30


def _codex_home_configured() -> bool:
    """True when the caller supplied a tester-scoped CODEX_HOME environment.

    The value itself is only inherited by Codex CLI child processes; nothing
    inside the directory is ever read, listed, or parsed by ShellForgeAI.
    """
    return bool(os.environ.get("CODEX_HOME", "").strip())


# Codex exec reads the prompt from stdin when the prompt argument is "-".
CODEX_STDIN_PROMPT_ARG = "-"


def _prompt_via_stdin() -> bool:
    """Send the prompt over stdin instead of argv on Windows.

    On Windows the Codex CLI is a ``.CMD`` batch wrapper, so CreateProcess
    routes the invocation through ``cmd.exe``. A multi-kilobyte evidence
    prompt passed as an argv element there hits the cmd.exe 8191-character
    command-line limit and its ``%``/``!``/metacharacter expansion rules,
    which mangles or wedges the exec call even though short invocations like
    ``codex login status`` work. Piping the prompt over stdin (with the
    documented ``-`` prompt argument) keeps the command line tiny and
    byte-exact. POSIX invocation is unchanged.
    """
    return os.name == "nt"


class CodexProvider:
    name = "openai-codex"
    _active_procs: set[subprocess.Popen[str]] = set()
    _active_lock = threading.Lock()

    def __init__(
        self,
        binary: str = "codex",
        default_model: str = "gpt-5.5",
        fallback_model: str = "gpt-5.4",
        timeout_seconds: int = 180,
        sandbox: str = "read-only",
        use_json: bool = True,
        skip_git_repo_check: bool = True,
        allow_fallback: bool = True,
        approval: str = "never",
    ) -> None:
        self.binary = binary
        self.default_model = default_model
        self.fallback_model = fallback_model
        self.timeout_seconds = timeout_seconds
        self.sandbox = sandbox
        self.use_json = use_json
        self.skip_git_repo_check = skip_git_repo_check
        self.allow_fallback = allow_fallback
        self.approval = approval
        self._resolved_binary: str | None = None

    def _has_path_separator(self) -> bool:
        return any(sep in self.binary for sep in {"/", "\\", os.sep, os.altsep} if sep)

    def _resolve_binary(self) -> str | None:
        """Resolve the configured Codex executable once for subprocess launches."""
        if self._resolved_binary is not None:
            return self._resolved_binary
        if os.path.isabs(self.binary) or self._has_path_separator():
            path = Path(self.binary)
            if path.is_file():
                self._resolved_binary = str(path)
                return self._resolved_binary
        resolved = shutil.which(self.binary)
        if resolved is not None:
            self._resolved_binary = resolved
            return resolved
        return None

    def _provider_unavailable_error(self, reason: str, resolved: str | None = None) -> str:
        return (
            "codex provider unavailable: "
            f"configured_binary={_format_human_value(self.binary)}; "
            f"resolved_binary={_format_human_value(resolved)}; "
            f"reason={reason}; run: shellforgeai model doctor --json"
        )

    def login_status(
        self, timeout_seconds: int = CODEX_LOGIN_STATUS_TIMEOUT_SECONDS
    ) -> dict[str, bool | str]:
        """Safe command-level Codex login readiness via ``codex login status``.

        Runs the resolved Codex CLI with the inherited process environment
        (so a tester-scoped ``CODEX_HOME`` governs which auth state is
        checked). Login is proven only by exit code 0 plus the
        ``Logged in using ChatGPT`` phrase on stdout OR stderr. No auth-cache
        or token file is ever read, copied, printed, archived, or parsed.
        """
        resolved = self._resolve_binary()
        if resolved is None:
            return {"checked": False, "ok": False, "reason": "codex_binary_missing"}
        try:
            r = subprocess.run(
                [resolved, "login", "status"],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return {"checked": True, "ok": False, "reason": "login_status_timeout"}
        except (FileNotFoundError, OSError):
            return {"checked": True, "ok": False, "reason": "login_status_launch_failed"}
        except Exception:
            return {"checked": True, "ok": False, "reason": "login_status_error"}
        ok = r.returncode == 0 and (
            CODEX_LOGIN_STATUS_PHRASE in (r.stdout or "")
            or CODEX_LOGIN_STATUS_PHRASE in (r.stderr or "")
        )
        return {
            "checked": True,
            "ok": ok,
            "reason": "codex_login_status_ok" if ok else "login_status_not_proven",
        }

    def available(self) -> tuple[bool, str]:
        if self._resolve_binary() is None:
            return False, self._provider_unavailable_error("codex executable not found")
        if _codex_home_configured():
            # Tester-scoped CODEX_HOME: readiness comes from safe command-level
            # login status, never from a profile-default auth-cache path.
            status = self.login_status()
            if status.get("ok"):
                return True, "ok"
            return False, "codex login status not proven for configured CODEX_HOME"
        auth_cache = Path.home() / ".codex" / "auth.json"
        if not auth_cache.exists():
            return False, "codex auth cache missing"
        return True, "ok"

    def doctor(self) -> dict[str, str | bool]:
        found = self._resolve_binary()
        auth_cache = Path.home() / ".codex" / "auth.json"
        version = "unknown"
        if found:
            try:
                r = subprocess.run(
                    [found, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    stdin=subprocess.DEVNULL,
                )
                version = (r.stdout or r.stderr).strip() or "unknown"
            except (FileNotFoundError, OSError):
                version = "unknown"
            except Exception:
                version = "unknown"
        auth_cache_present = auth_cache.exists()
        codex_home_configured = _codex_home_configured()
        login_info: dict[str, bool | str] = {
            "checked": False,
            "ok": False,
            "reason": "login_status_not_checked",
        }
        if found and codex_home_configured:
            # PR289 — honor the tester-scoped CODEX_HOME context: readiness is
            # proven by safe `codex login status` in the same process
            # environment, not by a profile-default auth-cache path that the
            # QGA/SYSTEM profile does not own.
            login_info = self.login_status()
        login_status_checked = bool(login_info.get("checked"))
        login_status_ok = bool(login_info.get("ok"))
        if not found:
            auth_readiness = "missing_binary"
            auth_reason = "codex_binary_missing"
        elif codex_home_configured and login_status_ok:
            auth_readiness = "verified_login_status"
            auth_reason = "codex_login_status_ok"
        elif codex_home_configured:
            auth_readiness = "login_status_not_proven"
            auth_reason = str(login_info.get("reason") or "login_status_not_proven")
        elif auth_cache_present:
            auth_readiness = "not_verified"
            auth_reason = "auth_cache_present_live_probe_not_run"
        else:
            auth_readiness = "missing_auth_cache"
            auth_reason = "auth_cache_missing"
        return {
            "provider": self.name,
            "model": self.default_model,
            "fallback_model": self.fallback_model,
            "codex_binary": self.binary,
            "codex_resolved_binary": found or "",
            "codex_found": bool(found),
            "codex_version": version,
            "auth_cache_present": auth_cache_present,
            "auth_cache_contents_inspected": False,
            "codex_home_configured": codex_home_configured,
            "login_status_checked": login_status_checked,
            "login_status_ok": login_status_ok,
            "login_status_source": (
                "codex_login_status" if login_status_checked else "not_checked"
            ),
            "auth_readiness": auth_readiness,
            "auth_reason": auth_reason,
            "auth_verification_status": auth_readiness,
            "auth_readiness_label": auth_readiness.replace("_", " "),
            "live_probe_available": False,
            "live_probe_performed": False,
            "model_called": False,
            "safe_next_command": "shellforgeai model doctor --json",
            "auth_next_step": "codex login --device-auth",
            "sandbox": self.sandbox,
            "approval": self.approval,
            "timeout_seconds": str(self.timeout_seconds),
            "fallback_enabled": self.allow_fallback,
        }

    @classmethod
    def cleanup_active_processes(cls) -> None:
        with cls._active_lock:
            procs = list(cls._active_procs)
            cls._active_procs.clear()
        for proc in procs:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.communicate(timeout=2)
            except Exception:
                continue

    def _build_cmd(self, prompt: str, model: str, last_message_path: Path | None) -> list[str]:
        """Build a codex-cli 0.130.0 invocation.

        Shape: ``codex [GLOBAL OPTIONS] exec [EXEC OPTIONS] [PROMPT]``.
        Global options must precede ``exec``; ``--ask-for-approval`` and
        ``--sandbox`` are global.
        """
        resolved = self._resolve_binary()
        if resolved is None:
            raise FileNotFoundError(self._provider_unavailable_error("codex executable not found"))
        cmd = [resolved, "--sandbox", self.sandbox, "--ask-for-approval", self.approval]
        if model:
            cmd.extend(["-m", model])
        cmd.append("exec")
        if self.skip_git_repo_check:
            cmd.append("--skip-git-repo-check")
        if self.use_json:
            cmd.append("--json")
        if last_message_path is not None:
            cmd.extend(["--output-last-message", str(last_message_path)])
        cmd.append(prompt)
        return cmd

    @staticmethod
    def _stop_timed_out_process(proc: subprocess.Popen) -> None:
        """Best-effort bounded shutdown of a timed-out codex child.

        On Windows the direct child is the ``cmd.exe`` batch wrapper, so a
        CTRL_BREAK to its process group (created below) reaches the wrapped
        codex process too before terminate/kill; POSIX terminate/kill is
        unchanged. Never waits unbounded and never hides the timeout.
        """
        if os.name == "nt":
            ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", None)
            if ctrl_break is not None:
                with contextlib.suppress(Exception):
                    proc.send_signal(ctrl_break)
        proc.terminate()

    def _run(
        self, prompt: str, model: str, timeout: int
    ) -> tuple[int, str, str, str | None, list[str]]:
        """Return (returncode, stdout, stderr, last_message, cmd)."""
        prompt_via_stdin = _prompt_via_stdin()
        with tempfile.TemporaryDirectory(prefix="sfai-codex-") as tmp:
            last_msg_path = Path(tmp) / "last_message.txt"
            cmd = self._build_cmd(
                CODEX_STDIN_PROMPT_ARG if prompt_via_stdin else prompt, model, last_msg_path
            )
            popen_kwargs: dict = {
                "stdin": subprocess.PIPE if prompt_via_stdin else subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "start_new_session": True,
            }
            if os.name == "nt":
                # A dedicated process group lets the timeout handler signal the
                # cmd.exe wrapper AND the codex process it spawned, instead of
                # orphaning the child after killing only the wrapper.
                popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            proc = subprocess.Popen(cmd, **popen_kwargs)
            with self._active_lock:
                self._active_procs.add(proc)
            communicate_kwargs: dict = {"timeout": timeout}
            if prompt_via_stdin:
                communicate_kwargs["input"] = prompt
            try:
                try:
                    out, err = proc.communicate(**communicate_kwargs)
                except subprocess.TimeoutExpired as exc:
                    self._stop_timed_out_process(proc)
                    try:
                        out, err = proc.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        try:
                            out, err = proc.communicate(timeout=2)
                        except subprocess.TimeoutExpired:
                            out, err = "", ""
                    raise subprocess.TimeoutExpired(
                        cmd=cmd, timeout=timeout, output=out, stderr=err
                    ) from exc
            finally:
                with self._active_lock:
                    self._active_procs.discard(proc)
            last_message: str | None = None
            try:
                if last_msg_path.exists():
                    last_message = last_msg_path.read_text(errors="ignore")[:65536].strip()
            except OSError:
                last_message = None
            return proc.returncode, out, err, last_message, cmd

    def stream_complete(self, request: ModelRequest):
        response = self.complete(request)
        if response.text:
            yield {"type": "text", "text": response.text}
        yield {"type": "final", "response": response}

    def _classify_error(self, rc: int, err: str, out: str = "") -> str:
        failure = classify_model_failure(stdout=out, stderr=err, returncode=rc)
        if failure["category"] == "auth":
            return (
                "codex auth failed; run: codex login --device-auth"
                if failure["reason"]
                in {"login_required", "auth_expired", "auth_invalid", "token_refresh_failed"}
                else "codex auth failed"
            )
        low = (err or "").lower()
        if "unexpected argument" in low or "error: " in low and "argument" in low:
            return "codex CLI argument error"
        if (
            "not authenticated" in low
            or "please run codex login" in low
            or "auth" in low
            and "fail" in low
        ):
            return "codex auth failed; run: codex login"
        if rc == 124:
            return "codex timed out"
        return f"codex exited with code {rc}"

    def complete(self, request: ModelRequest) -> ModelResponse:
        started = time.monotonic()
        warnings: list[str] = []
        resolved = self._resolve_binary()
        if resolved is None:
            return ModelResponse(
                provider=self.name,
                model=request.model,
                text="",
                ok=False,
                error=self._provider_unavailable_error("codex executable not found", resolved),
                duration_ms=int((time.monotonic() - started) * 1000),
                raw={"stderr": ""},
            )
        try:
            rc, out, err, last_message, cmd = self._run(
                request.prompt, request.model or self.default_model, request.timeout_seconds
            )
        except (FileNotFoundError, OSError) as exc:
            return ModelResponse(
                provider=self.name,
                model=request.model,
                text="",
                ok=False,
                error=self._provider_unavailable_error(exc.__class__.__name__, resolved),
                duration_ms=int((time.monotonic() - started) * 1000),
                raw={"stderr": ""},
            )
        except subprocess.TimeoutExpired as exc:
            return ModelResponse(
                provider=self.name,
                model=request.model,
                text="",
                ok=False,
                error=(
                    f"codex timed out after {request.timeout_seconds}s "
                    "(bounded timeout; no indefinite wait)"
                ),
                duration_ms=int((time.monotonic() - started) * 1000),
                raw={
                    "stderr": _redact(str(exc.stderr or "")),
                    "stdout": _redact(str(exc.output or "")),
                },
            )

        model_used = request.model or self.default_model
        if (
            rc != 0
            and self.allow_fallback
            and self.fallback_model
            and model_used != self.fallback_model
            and "model" in (err + out).lower()
        ):
            try:
                rc, out, err, last_message, cmd = self._run(
                    request.prompt, self.fallback_model, request.timeout_seconds
                )
            except (FileNotFoundError, OSError) as exc:
                return ModelResponse(
                    provider=self.name,
                    model=request.model,
                    text="",
                    ok=False,
                    error=self._provider_unavailable_error(exc.__class__.__name__, resolved),
                    duration_ms=int((time.monotonic() - started) * 1000),
                    raw={"stderr": ""},
                )
            model_used = self.fallback_model
            warnings.append(
                f"{request.model or self.default_model} was unavailable through Codex; "
                f"retried with fallback model {self.fallback_model}."
            )

        text = ""
        usage: dict[str, int | None] | None = None
        metadata: dict[str, str] = {}
        if last_message:
            text = last_message
        if self.use_json and out.strip():
            parsed = parse_codex_jsonl(out, keep_raw=bool(request.metadata.get("raw")))
            warnings.extend(parsed.warnings)
            if parsed.final_text and not text:
                text = parsed.final_text
            usage = {
                "input_tokens": parsed.usage.input_tokens,
                "cached_input_tokens": parsed.usage.cached_input_tokens,
                "output_tokens": parsed.usage.output_tokens,
                "reasoning_output_tokens": parsed.usage.reasoning_output_tokens,
            }
            if parsed.thread_id:
                metadata["thread_id"] = parsed.thread_id
        if not text:
            text = (out or err).strip()

        if rc == 0 and not text:
            error: str | None = "codex returned no final response"
            ok = False
        else:
            error = None if rc == 0 else self._classify_error(rc, err, out)
            ok = rc == 0

        return ModelResponse(
            provider=self.name,
            model=model_used,
            text=text,
            raw=(
                {"stderr": _redact(err), "stdout_jsonl": out}
                if request.metadata.get("raw")
                else {"stderr": _redact(err)}
            ),
            ok=ok,
            error=error,
            duration_ms=int((time.monotonic() - started) * 1000),
            usage=usage,
            warnings=warnings,
            metadata=metadata,
        )


def _auth_reason_blob(text: str) -> str:
    low = (text or "").lower()
    if "refresh token already used" in low or "token refresh" in low:
        return "token_refresh_failed"
    if "invalid_grant" in low or "invalid token" in low:
        return "auth_invalid"
    if "token expired" in low or "auth expired" in low or "expired" in low:
        return "auth_expired"
    if "please run codex login" in low or "login required" in low or "not authenticated" in low:
        return "login_required"
    if "unauthorized" in low:
        return "auth_invalid"
    return ""


def classify_model_failure(
    stdout: str, stderr: str, events: list[dict] | None = None, returncode: int | None = None
) -> dict[str, str | bool]:
    blob = "\n".join([stdout or "", stderr or ""])
    reason = _auth_reason_blob(blob)
    event_blob = ""
    for ev in events or []:
        event_blob += f"\n{ev.get('type', '')} {ev.get('message', '')}"
    if not reason and event_blob:
        reason = _auth_reason_blob(event_blob)
    if returncode == 124 or "timed out" in blob.lower():
        return {
            "status": "unavailable",
            "category": "timeout",
            "reason": "timeout",
            "user_message": "Model-assisted assessment unavailable: model command timed out.",
            "next_step": "Retry model-assisted assessment later.",
            "raw_suppressed": True,
        }
    if reason:
        return {
            "status": "unavailable",
            "category": "auth",
            "reason": reason,
            "user_message": "Model-assisted assessment unavailable: Codex auth expired or invalid.",
            "next_step": "codex login --device-auth",
            "raw_suppressed": True,
        }
    return {
        "status": "unavailable",
        "category": "model",
        "reason": "unknown_model_failure",
        "user_message": "Model-assisted assessment unavailable: model command failed.",
        "next_step": "Review model provider configuration and retry.",
        "raw_suppressed": True,
    }
