from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from shellforgeai.llm.codex_events import parse_codex_jsonl
from shellforgeai.llm.schemas import ModelRequest, ModelResponse


class CodexProvider:
    name = "openai-codex"

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
    ) -> None:
        self.binary = binary
        self.default_model = default_model
        self.fallback_model = fallback_model
        self.timeout_seconds = timeout_seconds
        self.sandbox = sandbox
        self.use_json = use_json
        self.skip_git_repo_check = skip_git_repo_check
        self.allow_fallback = allow_fallback

    def available(self) -> tuple[bool, str]:
        if shutil.which(self.binary) is None:
            return False, "codex CLI not found on PATH"
        return True, "ok"

    def doctor(self) -> dict[str, str | bool]:
        found = shutil.which(self.binary)
        auth_cache = Path.home() / ".codex" / "auth.json"
        version = "unknown"
        if found:
            try:
                r = subprocess.run(
                    [self.binary, "--version"], capture_output=True, text=True, timeout=10
                )
                version = (r.stdout or r.stderr).strip() or "unknown"
            except Exception:
                version = "unknown"
        return {
            "provider": self.name,
            "model": self.default_model,
            "fallback_model": self.fallback_model,
            "codex_binary": found or self.binary,
            "codex_found": bool(found),
            "codex_version": version,
            "auth_cache_present": auth_cache.exists(),
            "sandbox": self.sandbox,
            "timeout_seconds": str(self.timeout_seconds),
            "fallback_enabled": self.allow_fallback,
        }

    def _run(self, prompt: str, model: str, timeout: int) -> tuple[int, str, str]:
        cmd = [self.binary, "exec", "-m", model, "--sandbox", self.sandbox]
        if self.use_json:
            cmd.append("--json")
        if self.skip_git_repo_check:
            cmd.append("--skip-git-repo-check")
        cmd.append(prompt)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr

    def stream_complete(self, request: ModelRequest):
        cmd = [
            self.binary,
            "exec",
            "-m",
            request.model or self.default_model,
            "--sandbox",
            self.sandbox,
        ]
        if self.use_json:
            cmd.append("--json")
        if self.skip_git_repo_check:
            cmd.append("--skip-git-repo-check")
        cmd.append(request.prompt)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert p.stdout is not None
        chunks: list[str] = []
        raw_lines: list[str] = []
        for line in p.stdout:
            raw_lines.append(line.rstrip("\n"))
            if not self.use_json:
                chunks.append(line)
                yield {"type": "text", "text": line}
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = event.get("msg") or {}
            if msg.get("type") == "agent_message_delta":
                delta = msg.get("delta") or ""
                if delta:
                    chunks.append(delta)
                    yield {"type": "text", "text": delta}
            yield {"type": "raw", "raw": line.rstrip("\n")}
        rc = p.wait(timeout=request.timeout_seconds)
        stderr = (p.stderr.read() if p.stderr else "").strip()
        final_text = "".join(chunks).strip()
        parsed_usage = None
        parsed_meta: dict[str, str] = {}
        warnings: list[str] = []
        if self.use_json:
            parsed = parse_codex_jsonl(
                "\n".join(raw_lines), keep_raw=bool(request.metadata.get("raw"))
            )
            warnings = parsed.warnings
            if parsed.final_text:
                final_text = parsed.final_text
            parsed_usage = {
                "input_tokens": parsed.usage.input_tokens,
                "cached_input_tokens": parsed.usage.cached_input_tokens,
                "output_tokens": parsed.usage.output_tokens,
                "reasoning_output_tokens": parsed.usage.reasoning_output_tokens,
            }
            if parsed.thread_id:
                parsed_meta["thread_id"] = parsed.thread_id
        yield {
            "type": "final",
            "response": ModelResponse(
                provider=self.name,
                model=request.model or self.default_model,
                text=final_text or stderr,
                raw={"stderr": stderr, "stdout_jsonl": "\n".join(raw_lines)}
                if request.metadata.get("raw")
                else {"stderr": stderr},
                ok=rc == 0,
                error=None if rc == 0 else f"codex exit {rc}",
                usage=parsed_usage,
                warnings=warnings,
                metadata=parsed_meta,
            ),
        }

    def complete(self, request: ModelRequest) -> ModelResponse:
        started = time.monotonic()
        warnings: list[str] = []
        try:
            rc, out, err = self._run(
                request.prompt, request.model or self.default_model, request.timeout_seconds
            )
        except subprocess.TimeoutExpired:
            return ModelResponse(
                provider=self.name,
                model=request.model,
                text="",
                ok=False,
                error="timeout",
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        model_used = request.model or self.default_model
        if (
            rc != 0
            and self.allow_fallback
            and self.fallback_model
            and model_used != self.fallback_model
            and "model" in (err + out).lower()
        ):
            rc, out, err = self._run(request.prompt, self.fallback_model, request.timeout_seconds)
            model_used = self.fallback_model
            warnings.append(
                f"{request.model or self.default_model} was unavailable through Codex; "
                f"retried with fallback model {self.fallback_model}."
            )

        text = (out or err).strip()
        usage: dict[str, int | None] | None = None
        metadata: dict[str, str] = {}
        if self.use_json and out.strip():
            parsed = parse_codex_jsonl(out, keep_raw=bool(request.metadata.get("raw")))
            warnings.extend(parsed.warnings)
            if parsed.final_text:
                text = parsed.final_text
            usage = {
                "input_tokens": parsed.usage.input_tokens,
                "cached_input_tokens": parsed.usage.cached_input_tokens,
                "output_tokens": parsed.usage.output_tokens,
                "reasoning_output_tokens": parsed.usage.reasoning_output_tokens,
            }
            if parsed.thread_id:
                metadata["thread_id"] = parsed.thread_id
        return ModelResponse(
            provider=self.name,
            model=model_used,
            text=text,
            raw={"stderr": err, "stdout_jsonl": out}
            if request.metadata.get("raw")
            else {"stderr": err},
            ok=rc == 0,
            error=None if rc == 0 else f"codex exit {rc}",
            duration_ms=int((time.monotonic() - started) * 1000),
            usage=usage,
            warnings=warnings,
            metadata=metadata,
        )
