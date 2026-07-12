from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

MODEL_PHASE_HISTORY_LIMIT = 32
TERMINAL_MODEL_PHASES = {"completed", "timed_out", "cancelled", "failed"}

ProgressCallback = Callable[[str], None]


@dataclass
class ModelCallLifecycle:
    timeout_seconds: int
    monotonic: Callable[[], float]
    progress: ProgressCallback | None = None
    phase: str = "preparing_context"
    history: list[dict[str, int | str]] = field(default_factory=list)
    started_at: float = field(init=False)
    checkpoints: dict[str, float] = field(default_factory=dict)
    timeout_phase: str | None = None

    def __post_init__(self) -> None:
        self.started_at = self.monotonic()
        self.transition("preparing_context")

    def elapsed_ms(self, at: float | None = None) -> int:
        return max(0, int(((self.monotonic() if at is None else at) - self.started_at) * 1000))

    def mark(self, name: str) -> None:
        self.checkpoints[name] = self.monotonic()

    def transition(self, phase: str) -> None:
        self.phase = phase
        entry = {"phase": phase, "elapsed_ms": self.elapsed_ms()}
        self.history.append(entry)
        if len(self.history) > MODEL_PHASE_HISTORY_LIMIT:
            self.history = self.history[-MODEL_PHASE_HISTORY_LIMIT:]
        if self.progress is not None:
            self.progress(phase)

    def ensure_terminal(self, phase: str = "failed") -> None:
        if self.phase not in TERMINAL_MODEL_PHASES:
            self.transition(phase)

    def remaining_seconds(self) -> float:
        return max(0.0, self.timeout_seconds - (self.monotonic() - self.started_at))

    def deadline_exceeded(self) -> bool:
        return self.remaining_seconds() <= 0

    def duration_ms(self, start: str, end: str) -> int | None:
        if start not in self.checkpoints or end not in self.checkpoints:
            return None
        return max(0, int((self.checkpoints[end] - self.checkpoints[start]) * 1000))

    def since_start_ms(self, name: str) -> int | None:
        if name not in self.checkpoints:
            return None
        return self.elapsed_ms(self.checkpoints[name])

    def timing_fields(self) -> dict[str, object]:
        return {
            "model_phase": self.phase,
            "model_phase_history": list(self.history),
            "context_build_ms": self.duration_ms("context_start", "context_end"),
            "prompt_build_ms": self.duration_ms("prompt_start", "prompt_end"),
            "provider_spawn_ms": self.duration_ms("spawn_start", "spawn_end"),
            "stdin_write_ms": self.duration_ms("stdin_write_start", "stdin_write_end"),
            "provider_wait_ms": self.duration_ms("stdin_close", "provider_exit"),
            "output_file_first_seen_ms": self.since_start_ms("output_file_first_seen"),
            "output_file_nonempty_ms": self.since_start_ms("output_file_nonempty"),
            "response_capture_ms": self.duration_ms(
                "response_capture_start", "response_capture_end"
            ),
            "process_cleanup_ms": self.duration_ms("cleanup_start", "cleanup_end"),
            "model_total_ms": self.elapsed_ms(),
            "first_stdout_ms": self.since_start_ms("first_stdout"),
            "first_stderr_ms": self.since_start_ms("first_stderr"),
            "provider_exit_ms": self.since_start_ms("provider_exit"),
            "model_timeout_seconds": self.timeout_seconds,
            "model_deadline_exceeded": self.phase == "timed_out" or self.deadline_exceeded(),
            "timeout_phase": self.timeout_phase,
        }
