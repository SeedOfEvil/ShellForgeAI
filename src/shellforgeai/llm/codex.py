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

# Bounded stderr excerpt kept in provider diagnostics and validation artifacts.
CODEX_STDERR_EXCERPT_MAX_CHARS = 400
CODEX_SUBPROCESS_ENCODING = "utf-8"
CODEX_SUBPROCESS_ERRORS = "replace"

# Codex CLI phrases that identify the repository/git trust gate. Staged
# Windows QGA/SYSTEM source directories (C:\Tools\ShellForgeAI\src\...) are
# not trusted git repositories, so Codex refuses to exec from them unless
# --skip-git-repo-check is supplied.
CODEX_REPO_TRUST_MARKERS = (
    "not inside a trusted directory",
    "--skip-git-repo-check was not specified",
)


def _sanitize_stderr_excerpt(text: str, limit: int = CODEX_STDERR_EXCERPT_MAX_CHARS) -> str:
    """Bounded, sanitized stderr/failure excerpt for diagnostics artifacts.

    Token-like lines are redacted, control characters are replaced with
    spaces, blank lines are dropped, and the result is capped so validation
    artifacts never carry unbounded, token-bearing, or unprintable output.
    """
    if not text:
        return ""
    redacted = _redact(str(text))
    cleaned = "".join(ch if ch == "\n" or ch.isprintable() else " " for ch in redacted)
    compact = "\n".join(ln.strip() for ln in cleaned.splitlines() if ln.strip())
    return compact[:limit]


def _is_repo_trust_failure(text: str) -> bool:
    low = (text or "").lower()
    return any(marker in low for marker in CODEX_REPO_TRUST_MARKERS)


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


def _windows_codex_lane() -> bool:
    """True when product Codex execution runs on a Windows host.

    Windows model assessments (model doctor live probe, ask, interactive,
    authenticated acceptance) execute from staged QGA/SYSTEM source
    directories such as ``C:\\Tools\\ShellForgeAI\\src\\ShellForgeAI-pr<PR>-<head>``
    that Codex never treats as trusted git repositories. The scoped
    repository-trust bypass applies only here (command construction itself is
    identical on every platform; only the stdin prompt transport differs).
    This bypasses ONLY Codex's repository/git trust gate — the mandatory
    ``read-only`` sandbox, ``--ask-for-approval never``, and every
    ShellForgeAI mutation/execution boundary stay intact.
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
        skip_git_repo_check: bool = False,
        allow_fallback: bool = True,
        approval: str = "never",
    ) -> None:
        # skip_git_repo_check is the one centralized trust-bypass option: it
        # defaults to False and is enabled explicitly by configuration
        # (``model.codex_skip_git_repo_check`` via ``build_provider``) or by
        # the scoped Windows Codex lane (see ``skip_git_repo_check_used``).
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

    def skip_git_repo_check_used(self) -> bool:
        """Effective scoped repository-trust-bypass state for exec invocations.

        False by default; enabled explicitly via configuration
        (``codex_skip_git_repo_check``) or by the scoped Windows Codex lane,
        where staged QGA/SYSTEM source directories are never trusted git
        repositories. This bypasses ONLY Codex's repository/git trust gate;
        the ``read-only`` sandbox and approval boundaries are unchanged.
        """
        return bool(self.skip_git_repo_check or _windows_codex_lane())

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
                encoding=CODEX_SUBPROCESS_ENCODING,
                errors=CODEX_SUBPROCESS_ERRORS,
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
            return (
                False,
                "codex_login_not_verified: codex login status not proven for configured CODEX_HOME",
            )
        auth_cache = Path.home() / ".codex" / "auth.json"
        if not auth_cache.exists():
            return (
                False,
                "codex_context_not_configured_for_process: set CODEX_HOME for this "
                "process context or run codex login status from the same account",
            )
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
        elif auth_cache_present:
            auth_readiness = "not_verified"
            auth_reason = "auth_cache_present_live_probe_not_run"
        elif codex_home_configured:
            auth_readiness = "login_status_not_proven"
            auth_reason = str(login_info.get("reason") or "login_status_not_proven")
        else:
            auth_readiness = "missing_auth_cache"
            auth_reason = "codex_context_not_configured_for_process"
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
            "sandbox_mode": self.sandbox,
            "skip_git_repo_check_used": self.skip_git_repo_check_used(),
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

    def _global_options(self, model: str) -> list[str]:
        """Global Codex options — they MUST precede the ``exec`` subcommand.

        ``--model``, ``--sandbox``, and ``--ask-for-approval`` are global
        Codex CLI options: the installed CLIs (codex 0.130.0 on Linux/Docker,
        codex 0.137.0 on the Windows QA lane) reject them after ``exec``
        (``error: unexpected argument '--ask-for-approval' found``).
        """
        opts: list[str] = []
        if model:
            opts.extend(["--model", model])
        opts.extend(["--sandbox", self.sandbox, "--ask-for-approval", self.approval])
        return opts

    def _exec_options(self, last_message_path: Path | None) -> list[str]:
        """Exec-scoped Codex options — they follow the ``exec`` subcommand.

        ``--skip-git-repo-check`` (the scoped repository-trust bypass),
        ``--json``, and ``--output-last-message`` (deterministic final
        model-response capture) are ``codex exec`` options.
        """
        opts: list[str] = []
        if self.skip_git_repo_check_used():
            opts.append("--skip-git-repo-check")
        if self.use_json:
            opts.append("--json")
        if last_message_path is not None:
            opts.extend(["--output-last-message", str(last_message_path)])
        return opts

    def _build_cmd(self, prompt: str, model: str, last_message_path: Path | None) -> list[str]:
        """Build the one canonical codex-cli invocation for every platform.

        Sections, in order: executable, global options, the ``exec``
        subcommand, exec-scoped options, prompt (or the ``-`` stdin target on
        Windows). Verified against codex 0.130.0 (Linux/Docker) and codex
        0.137.0 (Windows QA lane):

        ``codex --model <model> --sandbox read-only --ask-for-approval never
        exec --skip-git-repo-check [--json] [--output-last-message <path>]
        <prompt|->``

        Global options never appear after ``exec``. The read-only sandbox and
        ``--ask-for-approval never`` are always present; the trust bypass is
        exec-scoped and never weakens either.
        """
        resolved = self._resolve_binary()
        if resolved is None:
            raise FileNotFoundError(self._provider_unavailable_error("codex executable not found"))
        return [
            resolved,
            *self._global_options(model),
            "exec",
            *self._exec_options(last_message_path),
            prompt,
        ]

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

    @staticmethod
    def _read_last_message(last_msg_path: Path) -> str | None:
        """Bounded read of the deterministic capture file (None when absent)."""
        try:
            if last_msg_path.exists():
                return last_msg_path.read_text(encoding=CODEX_SUBPROCESS_ENCODING)[:65536].strip()
        except (OSError, UnicodeError):
            return None
        return None

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
                "encoding": CODEX_SUBPROCESS_ENCODING,
                "errors": CODEX_SUBPROCESS_ERRORS,
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
                    timeout_exc = subprocess.TimeoutExpired(
                        cmd=cmd, timeout=timeout, output=out, stderr=err
                    )
                    # PR291 fix — inspect the deterministic capture BEFORE the
                    # temp directory is cleaned up, so a timeout can still
                    # report whether the final-response file was produced.
                    # This never converts the timeout into success; it only
                    # makes the failure explainable (output captured but
                    # process timed out vs no output at all).
                    timeout_exc.output_last_message_path = str(last_msg_path)
                    timeout_exc.output_file_created = last_msg_path.exists()
                    timeout_exc.last_message = self._read_last_message(last_msg_path)
                    timeout_exc.child_cleanup_performed = True
                    timeout_exc.prompt_via_stdin = prompt_via_stdin
                    raise timeout_exc from exc
            finally:
                with self._active_lock:
                    self._active_procs.discard(proc)
            last_message = self._read_last_message(last_msg_path)
            return proc.returncode, out, err, last_message, cmd

    def _exec_diagnostics(
        self,
        *,
        attempted: bool,
        exit_code: int | None = None,
        timed_out: bool = False,
        error_class: str | None = None,
        error_message: str | None = None,
        stderr: str = "",
        resolved: str | None = None,
        command_built: bool = False,
        command_started: bool = False,
        last_message: str | None = None,
        response_text: str = "",
        process_completed: bool = False,
        child_cleanup_performed: bool = False,
        output_path: str | None = None,
        output_file_created: bool | None = None,
        stdin_prompt_sent: bool = False,
        stdin_closed: bool = False,
        prompt_character_count: int | None = None,
        prompt_utf8_byte_count: int | None = None,
    ) -> dict[str, object]:
        """Bounded, sanitized Codex invocation diagnostics.

        Attached to every ``ModelResponse.metadata`` so provider results and
        validation artifacts can distinguish CLI argument-ordering failures,
        repository trust failures, timeouts, binary resolution failures,
        missing/empty deterministic output capture, model command failures,
        and authentication readiness failures — without ever reading
        auth-cache contents or recording the process environment. Command
        start success, process completion, and model-response capture are
        tracked separately: ``codex_command_started`` means the child
        launched; ``codex_process_completed`` means it finished inside the
        bounded timeout; ``model_response_captured`` means the
        ``--output-last-message`` file held a non-empty final response (read
        only after the process ended or was cleaned up). Output captured
        while the process still timed out stays a failure — the capture flag
        only makes the failure explainable, never a PASS.
        """
        captured = bool(last_message is not None and last_message.strip())
        return {
            "codex_command_built": bool(command_built),
            "codex_command_started": bool(command_started),
            "codex_exec_attempted": bool(attempted),
            "model_call_attempted": bool(attempted),
            "codex_exec_exit_code": exit_code,
            "codex_exec_timed_out": bool(timed_out),
            "codex_process_completed": bool(process_completed),
            "codex_child_cleanup_performed": bool(child_cleanup_performed),
            "codex_exec_error_class": error_class,
            "codex_exec_error_message": (
                _sanitize_stderr_excerpt(error_message, 240) or None if error_message else None
            ),
            "codex_exec_stderr_excerpt": _sanitize_stderr_excerpt(stderr),
            "output_last_message_requested": bool(command_built),
            "output_last_message_path": output_path,
            "output_file_created": (
                bool(output_file_created)
                if output_file_created is not None
                else last_message is not None
            ),
            "model_response_captured": captured,
            "model_response_nonempty": bool((response_text or "").strip()),
            "model_response_excerpt": _sanitize_stderr_excerpt(response_text or "", 240),
            "stdin_prompt_sent": bool(stdin_prompt_sent),
            "stdin_closed": bool(stdin_closed),
            "stdin_encoding": CODEX_SUBPROCESS_ENCODING,
            "stdout_encoding": CODEX_SUBPROCESS_ENCODING,
            "stderr_encoding": CODEX_SUBPROCESS_ENCODING,
            "output_file_encoding": CODEX_SUBPROCESS_ENCODING,
            "prompt_character_count": prompt_character_count,
            "prompt_utf8_byte_count": prompt_utf8_byte_count,
            "codex_binary": self.binary,
            "codex_resolved_binary": resolved or "",
            "sandbox_mode": self.sandbox,
            "approval_policy": self.approval,
            "skip_git_repo_check_used": self.skip_git_repo_check_used(),
        }

    def stream_complete(self, request: ModelRequest):
        response = self.complete(request)
        if response.text:
            yield {"type": "text", "text": response.text}
        yield {"type": "final", "response": response}

    def _classify_error(self, rc: int, err: str, out: str = "") -> str:
        failure = classify_model_failure(stdout=out, stderr=err, returncode=rc)
        if failure["category"] == "cli_argument_order":
            return (
                "codex CLI argument error: global options "
                "(--model/--sandbox/--ask-for-approval) must precede the exec subcommand"
            )
        if failure["category"] == "repository_trust":
            return (
                "codex repository trust check blocked execution: the working "
                "directory is not a trusted git repository "
                "(scoped --skip-git-repo-check bypass not applied)"
            )
        if failure["category"] == "stdin_encoding":
            return "codex rejected provider stdin as non-UTF-8 input"
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
            unavailable_error = self._provider_unavailable_error(
                "codex executable not found", resolved
            )
            return ModelResponse(
                provider=self.name,
                model=request.model,
                text="",
                ok=False,
                error=unavailable_error,
                duration_ms=int((time.monotonic() - started) * 1000),
                raw={"stderr": ""},
                metadata=self._exec_diagnostics(
                    attempted=False,
                    error_class="binary_resolution",
                    error_message=unavailable_error,
                    resolved=resolved,
                ),
            )
        try:
            rc, out, err, last_message, cmd = self._run(
                request.prompt, request.model or self.default_model, request.timeout_seconds
            )
        except (FileNotFoundError, OSError) as exc:
            unavailable_error = self._provider_unavailable_error(exc.__class__.__name__, resolved)
            return ModelResponse(
                provider=self.name,
                model=request.model,
                text="",
                ok=False,
                error=unavailable_error,
                duration_ms=int((time.monotonic() - started) * 1000),
                raw={"stderr": ""},
                metadata=self._exec_diagnostics(
                    attempted=True,
                    error_class="binary_resolution",
                    error_message=unavailable_error,
                    resolved=resolved,
                    command_built=True,
                ),
            )
        except subprocess.TimeoutExpired as exc:
            timeout_error = (
                f"codex timed out after {request.timeout_seconds}s "
                "(bounded timeout; no indefinite wait)"
            )
            return ModelResponse(
                provider=self.name,
                model=request.model,
                text="",
                ok=False,
                error=timeout_error,
                duration_ms=int((time.monotonic() - started) * 1000),
                raw={
                    "stderr": _redact(str(exc.stderr or "")),
                    "stdout": _redact(str(exc.output or "")),
                },
                metadata=self._exec_diagnostics(
                    attempted=True,
                    timed_out=True,
                    error_class="timeout",
                    error_message=timeout_error,
                    stderr=str(exc.stderr or ""),
                    resolved=resolved,
                    command_built=True,
                    command_started=True,
                    process_completed=False,
                    child_cleanup_performed=bool(getattr(exc, "child_cleanup_performed", True)),
                    output_path=getattr(exc, "output_last_message_path", None),
                    output_file_created=bool(getattr(exc, "output_file_created", False)),
                    # A capture produced before the timeout is reported
                    # honestly, but the invocation stays a bounded failure.
                    last_message=getattr(exc, "last_message", None),
                    response_text=getattr(exc, "last_message", None) or "",
                    stdin_prompt_sent=bool(getattr(exc, "prompt_via_stdin", _prompt_via_stdin())),
                    stdin_closed=True,
                    prompt_character_count=len(request.prompt),
                    prompt_utf8_byte_count=len(request.prompt.encode(CODEX_SUBPROCESS_ENCODING)),
                ),
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
                unavailable_error = self._provider_unavailable_error(
                    exc.__class__.__name__, resolved
                )
                return ModelResponse(
                    provider=self.name,
                    model=request.model,
                    text="",
                    ok=False,
                    error=unavailable_error,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    raw={"stderr": ""},
                    metadata=self._exec_diagnostics(
                        attempted=True,
                        error_class="binary_resolution",
                        error_message=unavailable_error,
                        resolved=resolved,
                        command_built=True,
                    ),
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

        error_class: str | None = None
        if rc == 0 and not text:
            # Process start/exit success is NOT model-response success: the
            # deterministic --output-last-message capture must hold a
            # non-empty final response. Classify the two gaps explicitly.
            if last_message is None:
                error: str | None = (
                    "codex returned no final response (--output-last-message file was not created)"
                )
                error_class = "output_capture_missing"
            else:
                error = "codex returned no final response (empty final message output)"
                error_class = "empty_response"
            ok = False
        else:
            error = None if rc == 0 else self._classify_error(rc, err, out)
            ok = rc == 0
            if not ok:
                error_class = str(
                    classify_model_failure(stdout=out, stderr=err, returncode=rc)["category"]
                )
        output_path: str | None = None
        if "--output-last-message" in cmd:
            path_index = cmd.index("--output-last-message") + 1
            if path_index < len(cmd):
                output_path = cmd[path_index]
        response_metadata: dict[str, object] = {
            **self._exec_diagnostics(
                attempted=True,
                exit_code=rc,
                error_class=error_class,
                error_message=error,
                stderr=err,
                resolved=resolved,
                command_built=True,
                command_started=True,
                last_message=last_message,
                # The response fields describe the model answer, never
                # error/stderr text that `text` may fall back to on failure.
                response_text=text if ok else "",
                process_completed=True,
                output_path=output_path,
                output_file_created=last_message is not None,
                stdin_prompt_sent=_prompt_via_stdin(),
                stdin_closed=True,
                prompt_character_count=len(request.prompt),
                prompt_utf8_byte_count=len(request.prompt.encode(CODEX_SUBPROCESS_ENCODING)),
            ),
            **metadata,
        }

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
            metadata=response_metadata,
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
    if "unexpected argument" in blob.lower() or "unexpected argument" in event_blob.lower():
        # The Codex CLI rejected the command line before running anything —
        # typically a global option (--model/--sandbox/--ask-for-approval)
        # placed after the exec subcommand. Never a model or auth failure.
        return {
            "status": "unavailable",
            "category": "cli_argument_order",
            "reason": "cli_argument_order",
            "user_message": (
                "Model-assisted assessment unavailable: Codex CLI rejected the "
                "command arguments (global options must precede exec)."
            ),
            "next_step": (
                "Keep --model/--sandbox/--ask-for-approval before the exec "
                "subcommand; only exec-scoped options follow it."
            ),
            "raw_suppressed": True,
        }
    if _is_repo_trust_failure(blob) or _is_repo_trust_failure(event_blob):
        # Codex's repository/git trust gate is not an authentication failure:
        # the staged source directory is not a trusted git repository. Keep
        # this class precise so operators are not sent to `codex login`.
        return {
            "status": "unavailable",
            "category": "repository_trust",
            "reason": "repository_trust",
            "user_message": (
                "Model-assisted assessment unavailable: Codex repository trust "
                "check blocked execution from this directory."
            ),
            "next_step": (
                "Enable the scoped Codex --skip-git-repo-check bypass "
                "(codex_skip_git_repo_check) for staged source directories."
            ),
            "raw_suppressed": True,
        }
    encoding_blob = "\n".join([blob, event_blob]).lower()
    if (
        "input is not valid utf-8" in encoding_blob
        or "failed to read prompt from stdin" in encoding_blob
    ):
        return {
            "status": "unavailable",
            "category": "stdin_encoding",
            "reason": "provider_stdin_not_utf8",
            "user_message": (
                "Model-assisted assessment unavailable: Codex rejected provider "
                "stdin as non-UTF-8 input."
            ),
            "next_step": (
                "Retry with the ShellForgeAI provider boundary using explicit "
                "UTF-8 stdin/stdout/stderr encoding."
            ),
            "raw_suppressed": True,
        }
    if returncode == 124 or "timed out" in blob.lower():
        return {
            "status": "unavailable",
            "category": "timeout",
            "reason": "timeout",
            "user_message": "Model-assisted assessment unavailable: model command timed out.",
            "next_step": "Retry model-assisted assessment later.",
            "raw_suppressed": True,
        }
    low_blob = blob.lower()
    if "codex_context_not_configured_for_process" in low_blob or (
        "codex auth cache missing" in low_blob and "expired" not in low_blob
    ):
        return {
            "status": "unavailable",
            "category": "codex_context_not_configured_for_process",
            "reason": "CODEX_HOME is not configured for this process context",
            "user_message": (
                "Model-assisted assessment unavailable: Codex context is not "
                "configured for this process."
            ),
            "next_step": (
                "Configure CODEX_HOME for the same account/process context, run "
                "codex login status there, then run shellforgeai model doctor --json."
            ),
            "raw_suppressed": True,
        }
    if "codex_login_not_verified" in low_blob or "login status not proven" in low_blob:
        return {
            "status": "unavailable",
            "category": "codex_login_not_verified",
            "reason": "codex login status was not verified",
            "user_message": (
                "Model-assisted assessment unavailable: Codex login status was not "
                "verified for this process."
            ),
            "next_step": (
                "Run codex login status from the same process context and check "
                "shellforgeai model doctor --json."
            ),
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
