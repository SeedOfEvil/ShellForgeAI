"""PR47: first non-metadata mutation gate — lab-allowlisted Docker container restart.

ShellForgeAI is a Tier-3 triage tool, not a remediation platform. This module is
the *only* place that may execute a non-metadata mutation, and the *only*
mutation it may perform is::

    docker restart <explicitly-allowlisted-lab-container>

Every other Docker/service/package/filesystem/firewall operation remains
review-only. The executor abstraction never accepts ``shell=True`` and never
accepts arbitrary command strings: only an exact list-form ``argv`` of
``["docker", "restart", "<safe-name>"]``.

Tests use :class:`FakeCommandExecutor` exclusively; no live Docker is required.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LAB_RESTART_SCHEMA_VERSION = "1"

# Allowed mutation scope label. Audit/receipt code anchors on this exact value.
MUTATION_SCOPE = "lab_container_restart_only"

# Allowed audit event kind/action for the one allowed real mutation.
AUDIT_KIND_EXECUTION = "execution"
AUDIT_ACTION_LAB_RESTART = "lab_container_restart"

# Action-compiler policy-override decision name.
EXECUTION_POLICY_ALLOWED = "allowed_lab_container_restart"

# Allowlist policy file location (relative to data_dir).
POLICY_DIR = "policy"
POLICY_FILE = "lab-container-restart-allowlist.json"

# Safe container name (Docker container names use this character set).
SAFE_CONTAINER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")

# Hard-block any shell metacharacters even if regex above happened to admit one.
FORBIDDEN_CHARS = set(" \t\n\r\f\v;&|`$<>()'\"\\/*?[]{}")

# Refusal gate names. The CLI surfaces these verbatim.
GATE_EXECUTE_FLAG = "execute_flag_missing"
GATE_CONFIRM_FLAG = "confirm_flag_missing"
GATE_MUTATION_MODE = "mutation_mode_disabled"
GATE_ALLOWLIST_MISSING = "allowlist_missing"
GATE_ALLOWLIST_DISABLED = "allowlist_disabled"
GATE_ALLOWLIST_EMPTY = "allowlist_empty"
GATE_CONTAINER_NOT_ALLOWLISTED = "container_not_allowlisted"
GATE_CONTAINER_NAME_UNSAFE = "container_name_unsafe"
GATE_PROPOSAL_NOT_APPROVED = "proposal_not_approved"
GATE_GUARD_FAILED = "guard_failed"
GATE_NO_RESTART_ACTION = "no_restart_action_found"
GATE_MULTIPLE_RESTART_ACTIONS = "multiple_restart_actions_require_action_id"
GATE_ACTION_NOT_FOUND = "action_not_found"
GATE_ACTION_NOT_RESTART = "action_not_lab_container_restart"
GATE_COMMAND_PREVIEW_MISMATCH = "command_preview_mismatch"

# Env overrides — explicit, not authoritative. The on-disk allowlist is the
# source of truth in tests.
ENV_MUTATION_MODE = "SHELLFORGEAI_MUTATION_MODE"
ENV_ALLOW_LAB_RESTART = "SHELLFORGEAI_ALLOW_LAB_CONTAINER_RESTART"


# ---------------------------------------------------------------------------
# Allowlist


@dataclass(frozen=True)
class Allowlist:
    enabled: bool
    containers: tuple[str, ...]
    source_path: Path | None
    notes: str = ""

    def contains(self, name: str) -> bool:
        return name in self.containers


def policy_path(data_dir: Path) -> Path:
    return Path(data_dir) / POLICY_DIR / POLICY_FILE


def load_allowlist(data_dir: Path) -> Allowlist | None:
    """Load the lab restart allowlist from disk.

    Returns ``None`` when the policy file is missing. Returns an
    :class:`Allowlist` with ``enabled=False`` for any other parse problem so
    callers can refuse with a precise gate name.
    """
    p = policy_path(Path(data_dir))
    if not p.exists() or not p.is_file():
        return None
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return Allowlist(enabled=False, containers=(), source_path=p, notes="malformed JSON")
    if not isinstance(payload, dict):
        return Allowlist(enabled=False, containers=(), source_path=p, notes="not a JSON object")
    enabled = bool(payload.get("enabled", False))
    raw_list = payload.get("allowed_containers") or []
    if not isinstance(raw_list, list):
        raw_list = []
    containers: list[str] = []
    for item in raw_list:
        if (
            isinstance(item, str)
            and item
            and is_safe_container_name(item)
            and item not in containers
        ):
            containers.append(item)
    notes = str(payload.get("notes", "") or "")
    return Allowlist(enabled=enabled, containers=tuple(containers), source_path=p, notes=notes)


def write_default_allowlist(
    data_dir: Path, *, containers: list[str], enabled: bool = False
) -> Path:
    """Write a starter allowlist policy file. Used for tests + operator setup."""
    p = policy_path(Path(data_dir))
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": LAB_RESTART_SCHEMA_VERSION,
        "enabled": bool(enabled),
        "allowed_containers": list(containers),
        "notes": "Lab-only restart allowlist. No production containers.",
    }
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def is_safe_container_name(name: str) -> bool:
    if not isinstance(name, str) or not name:
        return False
    if any(ch in FORBIDDEN_CHARS for ch in name):
        return False
    return bool(SAFE_CONTAINER_RE.match(name))


def mutation_mode_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True only when the env opt-ins are explicitly set.

    The on-disk allowlist's ``enabled=true`` is still required separately. The
    env vars only express operator intent; they cannot substitute for the
    policy file.
    """
    env = env if env is not None else dict(os.environ)
    mode = env.get(ENV_MUTATION_MODE, "").strip().lower()
    allow = env.get(ENV_ALLOW_LAB_RESTART, "").strip().lower()
    if mode != "lab":
        return False
    return allow in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Executor abstraction


@dataclass(frozen=True)
class ExecResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str


class CommandExecutor(ABC):
    """Minimal executor interface. Only ``["docker", "restart", "<name>"]`` argv
    is accepted by the production implementation."""

    @abstractmethod
    def run(self, argv: list[str], *, timeout_seconds: int) -> ExecResult: ...


class SubprocessExecutor(CommandExecutor):
    """Real executor. Refuses anything other than ``docker restart <safe-name>``."""

    def run(self, argv: list[str], *, timeout_seconds: int) -> ExecResult:
        ok, reason = is_valid_restart_argv(argv)
        if not ok:
            return ExecResult(ok=False, exit_code=2, stdout="", stderr=reason)
        try:
            cp = subprocess.run(  # noqa: S603 - argv is validated above; never shell=True
                argv,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=int(timeout_seconds),
            )
        except subprocess.TimeoutExpired as exc:
            return ExecResult(ok=False, exit_code=124, stdout="", stderr=f"timeout: {exc}")
        except FileNotFoundError as exc:
            return ExecResult(ok=False, exit_code=127, stdout="", stderr=str(exc))
        except OSError as exc:
            return ExecResult(ok=False, exit_code=1, stdout="", stderr=str(exc))
        return ExecResult(
            ok=cp.returncode == 0,
            exit_code=cp.returncode,
            stdout=cp.stdout or "",
            stderr=cp.stderr or "",
        )


@dataclass
class FakeCommandExecutor(CommandExecutor):
    """Test executor: records argv and returns a configurable result. No subprocess."""

    result: ExecResult = field(
        default_factory=lambda: ExecResult(ok=True, exit_code=0, stdout="restarted", stderr="")
    )
    calls: list[list[str]] = field(default_factory=list)
    last_timeout: int | None = None

    def run(self, argv: list[str], *, timeout_seconds: int) -> ExecResult:
        self.calls.append(list(argv))
        self.last_timeout = int(timeout_seconds)
        ok, reason = is_valid_restart_argv(argv)
        if not ok:
            return ExecResult(ok=False, exit_code=2, stdout="", stderr=reason)
        return self.result


def is_valid_restart_argv(argv: list[str]) -> tuple[bool, str]:
    if not isinstance(argv, list):
        return False, "argv must be a list"
    if len(argv) != 3:
        return False, "argv must be exactly ['docker', 'restart', '<container>']"
    if argv[0] != "docker" or argv[1] != "restart":
        return False, "argv prefix must be ['docker', 'restart']"
    if not is_safe_container_name(argv[2]):
        return False, "argv[2] is not a safe container name"
    return True, ""


# ---------------------------------------------------------------------------
# Action selection


_RESTART_RE = re.compile(r"^\s*docker\s+restart\s+(\S+)\s*$", re.IGNORECASE)


def parse_restart_command(text: str) -> str | None:
    """Return the container name from ``docker restart <name>`` lines only.

    Refuses any extra arguments, flags, pipes, or alternative verbs.
    """
    if not isinstance(text, str):
        return None
    m = _RESTART_RE.match(text)
    if not m:
        return None
    name = m.group(1)
    if not is_safe_container_name(name):
        return None
    return name


@dataclass(frozen=True)
class RestartCandidate:
    action_id: str
    container: str
    command_argv: tuple[str, ...]
    source_section: str


def find_restart_candidates(actions_payload: dict[str, Any]) -> list[RestartCandidate]:
    """Pick out ``docker restart <safe-name>`` actions from a compiled actions payload."""
    out: list[RestartCandidate] = []
    for action in actions_payload.get("actions", []) or []:
        if not isinstance(action, dict):
            continue
        text = action.get("normalized_text") or action.get("command_preview") or ""
        name = parse_restart_command(str(text))
        if name is None:
            continue
        out.append(
            RestartCandidate(
                action_id=str(action.get("action_id", "")),
                container=name,
                command_argv=("docker", "restart", name),
                source_section=str(action.get("source_section", "")),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Gate evaluation


@dataclass
class GateResult:
    allowed: bool
    failed_gate: str = ""
    message: str = ""
    container: str = ""
    action_id: str = ""
    candidate: RestartCandidate | None = None
    allowlist: Allowlist | None = None
    mutation_mode: str = "disabled"

    def gates_dict(self) -> dict[str, Any]:
        return {
            "execute_flag": self.allowed or self.failed_gate != GATE_EXECUTE_FLAG,
            "confirm_flag": self.allowed or self.failed_gate != GATE_CONFIRM_FLAG,
            "mutation_mode": self.mutation_mode,
            "allowlisted": self.allowed,
            "container_name_safe": bool(self.container) and is_safe_container_name(self.container),
        }


def evaluate_gates(
    *,
    execute: bool,
    confirm: bool,
    proposal_status: str,
    guard_decision: str,
    actions_payload: dict[str, Any],
    allowlist: Allowlist | None,
    action_id: str | None,
    env: dict[str, str] | None = None,
) -> GateResult:
    """Run every required gate. Returns the first failing gate, or success."""
    if not execute:
        return GateResult(allowed=False, failed_gate=GATE_EXECUTE_FLAG, message="--execute missing")
    if not confirm:
        return GateResult(allowed=False, failed_gate=GATE_CONFIRM_FLAG, message="--confirm missing")

    mode_on = mutation_mode_enabled(env)
    if not mode_on:
        return GateResult(
            allowed=False,
            failed_gate=GATE_MUTATION_MODE,
            message=(
                f"mutation mode is disabled. Set {ENV_MUTATION_MODE}=lab and "
                f"{ENV_ALLOW_LAB_RESTART}=1 to opt in."
            ),
            mutation_mode="disabled",
        )

    if allowlist is None:
        return GateResult(
            allowed=False,
            failed_gate=GATE_ALLOWLIST_MISSING,
            message="lab restart allowlist not configured",
            mutation_mode="lab",
        )
    if not allowlist.enabled:
        return GateResult(
            allowed=False,
            failed_gate=GATE_ALLOWLIST_DISABLED,
            message="lab restart allowlist is disabled (enabled=false)",
            allowlist=allowlist,
            mutation_mode="lab",
        )
    if not allowlist.containers:
        return GateResult(
            allowed=False,
            failed_gate=GATE_ALLOWLIST_EMPTY,
            message="lab restart allowlist contains no containers",
            allowlist=allowlist,
            mutation_mode="lab",
        )

    if proposal_status != "approved":
        return GateResult(
            allowed=False,
            failed_gate=GATE_PROPOSAL_NOT_APPROVED,
            message=f"proposal status '{proposal_status}' is not approved",
            allowlist=allowlist,
            mutation_mode="lab",
        )

    if guard_decision not in ("fresh", "warning"):
        return GateResult(
            allowed=False,
            failed_gate=GATE_GUARD_FAILED,
            message=f"guard decision '{guard_decision}' blocks execution",
            allowlist=allowlist,
            mutation_mode="lab",
        )

    candidates = find_restart_candidates(actions_payload)
    if action_id:
        match = next((c for c in candidates if c.action_id == action_id), None)
        if match is None:
            # Maybe it's a non-restart action_id — distinguish for the operator.
            for action in actions_payload.get("actions", []) or []:
                if isinstance(action, dict) and action.get("action_id") == action_id:
                    return GateResult(
                        allowed=False,
                        failed_gate=GATE_ACTION_NOT_RESTART,
                        message=(
                            f"action {action_id} is not a `docker restart <container>` action"
                        ),
                        allowlist=allowlist,
                        mutation_mode="lab",
                    )
            return GateResult(
                allowed=False,
                failed_gate=GATE_ACTION_NOT_FOUND,
                message=f"action {action_id} not found in compiled actions",
                allowlist=allowlist,
                mutation_mode="lab",
            )
        candidate = match
    else:
        if not candidates:
            return GateResult(
                allowed=False,
                failed_gate=GATE_NO_RESTART_ACTION,
                message="no `docker restart <container>` action present in compiled actions",
                allowlist=allowlist,
                mutation_mode="lab",
            )
        if len(candidates) > 1:
            return GateResult(
                allowed=False,
                failed_gate=GATE_MULTIPLE_RESTART_ACTIONS,
                message=(
                    "multiple restart actions present; rerun with --action-id <act_xxx> "
                    "to select exactly one"
                ),
                allowlist=allowlist,
                mutation_mode="lab",
            )
        candidate = candidates[0]

    if not is_safe_container_name(candidate.container):
        return GateResult(
            allowed=False,
            failed_gate=GATE_CONTAINER_NAME_UNSAFE,
            message=f"container name failed safety regex: {candidate.container!r}",
            container=candidate.container,
            action_id=candidate.action_id,
            allowlist=allowlist,
            mutation_mode="lab",
        )

    if candidate.container not in allowlist.containers:
        return GateResult(
            allowed=False,
            failed_gate=GATE_CONTAINER_NOT_ALLOWLISTED,
            message=(f"container {candidate.container!r} is not in the lab restart allowlist"),
            container=candidate.container,
            action_id=candidate.action_id,
            allowlist=allowlist,
            mutation_mode="lab",
        )

    expected_argv = ["docker", "restart", candidate.container]
    if list(candidate.command_argv) != expected_argv:
        return GateResult(
            allowed=False,
            failed_gate=GATE_COMMAND_PREVIEW_MISMATCH,
            message="compiled command preview does not match docker restart <container>",
            container=candidate.container,
            action_id=candidate.action_id,
            allowlist=allowlist,
            mutation_mode="lab",
        )

    return GateResult(
        allowed=True,
        container=candidate.container,
        action_id=candidate.action_id,
        candidate=candidate,
        allowlist=allowlist,
        mutation_mode="lab",
    )


# ---------------------------------------------------------------------------
# Receipts


def receipts_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "execution_receipts"


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def write_execution_receipt(
    data_dir: Path,
    *,
    proposal_id: str,
    action_id: str,
    container: str,
    command_argv: list[str],
    gates: dict[str, Any],
    status: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    failed_gate: str = "",
    verification: dict[str, Any] | None = None,
    rollback: dict[str, Any] | None = None,
    receipt_path: Path | None = None,
    compose_context: dict[str, Any] | None = None,
) -> Path:
    receipts = receipts_dir(Path(data_dir))
    receipts.mkdir(parents=True, exist_ok=True)
    if receipt_path is None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = receipts / f"exec_{stamp}_{_short_id()}.json"
    else:
        out = Path(receipt_path)
        out.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "schema_version": LAB_RESTART_SCHEMA_VERSION,
        "created_at": _now(),
        "proposal_id": proposal_id,
        "action_id": action_id,
        "kind": AUDIT_ACTION_LAB_RESTART,
        "container": container,
        "command_argv": list(command_argv),
        "gates": dict(gates),
        "result": {
            "status": status,
            "exit_code": int(exit_code),
            "stdout_preview": (stdout or "")[:400],
            "stderr_preview": (stderr or "")[:400],
        },
        "safety": {
            "scope": MUTATION_SCOPE,
            # The restart command exited 0 if exit_code==0; verification
            # status is independent and reflected separately.
            "docker_mutation": int(exit_code) == 0,
            "service_impacting": True,
            "package_mutation": False,
            "filesystem_mutation": False,
            "firewall_mutation": False,
            "arbitrary_command_execution": False,
            "compose_mutation": False,
            "restart_scope": "container",
        },
    }
    if failed_gate:
        payload["result"]["failed_gate"] = failed_gate
    if verification is not None:
        payload["verification"] = dict(verification)
    if rollback is not None:
        payload["rollback"] = dict(rollback)
    if compose_context is not None:
        payload["compose_context"] = dict(compose_context)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _write_receipt_markdown(out, payload)
    return out


def _write_receipt_markdown(json_path: Path, payload: dict[str, Any]) -> None:
    """Write a human-readable receipt.md next to receipt JSON.

    The markdown is informational only; receipt.json remains the canonical
    machine-readable artifact.
    """
    md_path = json_path.with_suffix(".md")
    lines: list[str] = []
    container = payload.get("container", "")
    result = payload.get("result", {})
    status = str(result.get("status", ""))
    lines.append(f"# Lab container restart receipt — {status}")
    lines.append("")
    lines.append(f"- container: {container}")
    lines.append(f"- proposal: {payload.get('proposal_id', '')}")
    lines.append(f"- action: {payload.get('action_id', '')}")
    lines.append(f"- command_argv: {payload.get('command_argv', [])}")
    lines.append(f"- exit_code: {result.get('exit_code', '')}")
    lines.append(f"- mutation_scope: {payload.get('safety', {}).get('scope', '')}")
    if result.get("failed_gate"):
        lines.append(f"- failed_gate: {result['failed_gate']}")
    verification = payload.get("verification")
    if isinstance(verification, dict):
        lines.append("")
        lines.append("## Verification")
        lines.append(f"- status: {verification.get('status', '')}")
        lines.append(f"- running_after: {verification.get('running_after', '')}")
        lines.append(f"- started_at_before: {verification.get('started_at_before', '')}")
        lines.append(f"- started_at_after: {verification.get('started_at_after', '')}")
        lines.append(f"- started_at_changed: {verification.get('started_at_changed', '')}")
        lines.append(f"- health_before: {verification.get('health_before', '')}")
        lines.append(f"- health_after: {verification.get('health_after', '')}")
        lines.append(f"- restart_count_before: {verification.get('restart_count_before', '')}")
        lines.append(f"- restart_count_after: {verification.get('restart_count_after', '')}")
        for note in verification.get("notes", []) or []:
            lines.append(f"  - note: {note}")
        evidence = verification.get("evidence") or {}
        if evidence:
            lines.append("")
            lines.append("### Evidence")
            for key in ("before_inspect_path", "after_inspect_path", "logs_tail_path"):
                val = evidence.get(key)
                if val:
                    lines.append(f"- {key}: {val}")
    rollback = payload.get("rollback")
    if isinstance(rollback, dict):
        lines.append("")
        lines.append("## Rollback")
        lines.append(f"- rollback_preview_path: {rollback.get('rollback_preview_path', '')}")
        lines.append(f"- rollback_readiness: {rollback.get('rollback_readiness', '')}")
        lines.append(f"- rollback_status: {rollback.get('rollback_status', '')}")
        lines.append(
            f"- rollback_executable_by_shellforgeai: "
            f"{rollback.get('rollback_executable_by_shellforgeai', '')}"
        )

    compose_context = payload.get("compose_context")
    if isinstance(compose_context, dict) and compose_context:
        lines.append("")
        lines.append("## Compose context")
        if compose_context.get("detected"):
            lines.append("- Compose-managed: yes")
            lines.append(f"- project: {compose_context.get('project') or '-'}")
            lines.append(f"- service: {compose_context.get('service') or '-'}")
            if compose_context.get("working_dir"):
                lines.append(f"- working_dir: {compose_context.get('working_dir')}")
            for path in compose_context.get("config_files") or []:
                lines.append(f"- config_file: {path}")
        else:
            lines.append("- Compose-managed: no")
        lines.append("- restart_scope: container")
        lines.append("- compose_mutation: false")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# PR48: post-mutation verification (read-only)
#
# Verification is bounded, read-only, and never re-attempts restart. It never
# uses ``docker exec``, ``shell=True``, or arbitrary command strings. Only the
# argv ``["docker", "inspect", "<safe-name>"]`` (and optionally
# ``["docker", "logs", "--tail", "<N>", "<safe-name>"]``) is allowed.


VERIFICATION_STATUS_PASSED = "passed"
VERIFICATION_STATUS_WARNING = "warning"
VERIFICATION_STATUS_FAILED = "failed"
VERIFICATION_STATUS_SKIPPED = "skipped"

HEALTH_NONE = "none"
HEALTH_HEALTHY = "healthy"
HEALTH_STARTING = "starting"
HEALTH_UNHEALTHY = "unhealthy"
HEALTH_UNKNOWN = "unknown"


@dataclass(frozen=True)
class VerificationConfig:
    post_restart_wait_seconds: float = 2.0
    health_wait_seconds: float = 10.0
    health_poll_interval_seconds: float = 1.0


@dataclass(frozen=True)
class InspectResult:
    """Raw result of a ``docker inspect`` call (or fake)."""

    ok: bool
    exists: bool
    raw: dict[str, Any] | None
    error: str = ""


@dataclass(frozen=True)
class ContainerState:
    """Normalized container state derived from ``docker inspect``."""

    exists: bool
    container_id: str
    running: bool
    status: str
    started_at: str
    exit_code: int | None
    health: str
    restart_count: int | None
    has_healthcheck: bool


def _normalize_health(raw_health: Any) -> str:
    if not isinstance(raw_health, str):
        return HEALTH_UNKNOWN
    val = raw_health.strip().lower()
    if val in ("healthy",):
        return HEALTH_HEALTHY
    if val in ("starting",):
        return HEALTH_STARTING
    if val in ("unhealthy",):
        return HEALTH_UNHEALTHY
    if val == "" or val == "none":
        return HEALTH_NONE
    return HEALTH_UNKNOWN


def parse_inspect_payload(payload: Any) -> ContainerState:
    """Convert a ``docker inspect`` JSON payload into a :class:`ContainerState`.

    ``docker inspect`` returns a top-level list. Callers may pass either the
    list or the first object.
    """
    obj: dict[str, Any] | None = None
    if isinstance(payload, list):
        if payload and isinstance(payload[0], dict):
            obj = payload[0]
    elif isinstance(payload, dict):
        obj = payload
    if obj is None:
        return ContainerState(
            exists=False,
            container_id="",
            running=False,
            status="",
            started_at="",
            exit_code=None,
            health=HEALTH_NONE,
            restart_count=None,
            has_healthcheck=False,
        )
    state = obj.get("State") or {}
    health_obj = state.get("Health") if isinstance(state, dict) else None
    has_health = isinstance(health_obj, dict) and bool(health_obj)
    health_status = (
        _normalize_health(health_obj.get("Status")) if isinstance(health_obj, dict) else HEALTH_NONE
    )
    restart_count: int | None
    rc = obj.get("RestartCount")
    if isinstance(rc, int):
        restart_count = rc
    elif isinstance(rc, str) and rc.isdigit():
        restart_count = int(rc)
    else:
        restart_count = None
    exit_code: int | None
    ec = state.get("ExitCode") if isinstance(state, dict) else None
    if isinstance(ec, int):
        exit_code = ec
    elif isinstance(ec, str) and ec.lstrip("-").isdigit():
        exit_code = int(ec)
    else:
        exit_code = None
    return ContainerState(
        exists=True,
        container_id=str(obj.get("Id", "") or ""),
        running=bool(state.get("Running", False)) if isinstance(state, dict) else False,
        status=str(state.get("Status", "")) if isinstance(state, dict) else "",
        started_at=str(state.get("StartedAt", "")) if isinstance(state, dict) else "",
        exit_code=exit_code,
        health=health_status,
        restart_count=restart_count,
        has_healthcheck=has_health,
    )


class ContainerInspector(ABC):
    """Read-only ``docker inspect`` abstraction. No mutation, no exec."""

    @abstractmethod
    def inspect(self, container: str) -> InspectResult: ...


class DockerCliInspector(ContainerInspector):
    """Production inspector. Runs ``docker inspect <safe-name>`` via argv only."""

    def __init__(self, *, timeout_seconds: int = 10) -> None:
        self.timeout_seconds = int(timeout_seconds)

    def inspect(self, container: str) -> InspectResult:
        if not is_safe_container_name(container):
            return InspectResult(ok=False, exists=False, raw=None, error="unsafe container name")
        argv = ["docker", "inspect", container]
        try:
            cp = subprocess.run(  # noqa: S603 - argv validated; never shell=True
                argv,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return InspectResult(ok=False, exists=False, raw=None, error=f"timeout: {exc}")
        except FileNotFoundError as exc:
            return InspectResult(ok=False, exists=False, raw=None, error=str(exc))
        except OSError as exc:
            return InspectResult(ok=False, exists=False, raw=None, error=str(exc))
        if cp.returncode != 0:
            return InspectResult(ok=False, exists=False, raw=None, error=(cp.stderr or "").strip())
        try:
            data = json.loads(cp.stdout or "[]")
        except ValueError as exc:
            return InspectResult(ok=False, exists=False, raw=None, error=f"malformed json: {exc}")
        if isinstance(data, list) and not data:
            return InspectResult(ok=True, exists=False, raw=None, error="not found")
        return InspectResult(ok=True, exists=True, raw=data if isinstance(data, dict) else data[0])


@dataclass
class FakeContainerInspector(ContainerInspector):
    """Test inspector returning queued :class:`InspectResult` values.

    If ``results`` is non-empty, each call pops the next entry. Otherwise the
    single ``result`` is returned for every call.
    """

    result: InspectResult | None = None
    results: list[InspectResult] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    def inspect(self, container: str) -> InspectResult:
        self.calls.append(container)
        if not is_safe_container_name(container):
            return InspectResult(ok=False, exists=False, raw=None, error="unsafe container name")
        if self.results:
            return self.results.pop(0)
        if self.result is not None:
            return self.result
        return InspectResult(ok=False, exists=False, raw=None, error="no fake result configured")


def make_inspect_payload(
    *,
    container_id: str = "abc123",
    running: bool = True,
    status: str = "running",
    started_at: str = "2026-05-14T12:00:00.000000000Z",
    exit_code: int | None = 0,
    restart_count: int | None = 0,
    health: str | None = None,
) -> dict[str, Any]:
    """Build a minimal docker-inspect-shaped payload for tests."""
    state: dict[str, Any] = {
        "Running": running,
        "Status": status,
        "StartedAt": started_at,
    }
    if exit_code is not None:
        state["ExitCode"] = exit_code
    if health is not None:
        state["Health"] = {"Status": health}
    obj: dict[str, Any] = {"Id": container_id, "State": state}
    if restart_count is not None:
        obj["RestartCount"] = restart_count
    return obj


def capture_container_state(inspector: ContainerInspector, container: str) -> ContainerState:
    """Inspect the container and return a normalized state (or a missing state)."""
    res = inspector.inspect(container)
    if not res.ok or not res.exists or res.raw is None:
        return ContainerState(
            exists=False,
            container_id="",
            running=False,
            status="",
            started_at="",
            exit_code=None,
            health=HEALTH_NONE,
            restart_count=None,
            has_healthcheck=False,
        )
    return parse_inspect_payload(res.raw)


def _noop_sleep(_seconds: float) -> None:  # pragma: no cover - default in production
    import time as _time

    _time.sleep(_seconds)


@dataclass(frozen=True)
class VerificationOutcome:
    """Result of post-mutation verification: a serializable block plus raw after-payload."""

    summary: dict[str, Any]
    after_raw: dict[str, Any] | None


def run_post_restart_verification(
    *,
    inspector: ContainerInspector,
    container: str,
    before_state: ContainerState,
    restart_ok: bool,
    config: VerificationConfig | None = None,
    sleep_fn: Any = None,
) -> VerificationOutcome:
    """Run bounded read-only verification after a restart.

    Returns a :class:`VerificationOutcome` whose ``summary`` is suitable for
    embedding in the execution receipt and audit event, and whose ``after_raw``
    is the most recent raw inspect payload (for evidence). Never restarts,
    never execs, and only calls the injected ``inspector`` (which itself only
    performs read-only inspect).
    """
    cfg = config or VerificationConfig()
    sleep = sleep_fn or _noop_sleep
    notes: list[str] = []

    if not restart_ok:
        return VerificationOutcome(
            summary={
                "status": VERIFICATION_STATUS_SKIPPED,
                "started_at_before": before_state.started_at,
                "started_at_after": "",
                "started_at_changed": False,
                "running_after": False,
                "health_before": before_state.health,
                "health_after": HEALTH_UNKNOWN,
                "restart_count_before": before_state.restart_count,
                "restart_count_after": None,
                "has_healthcheck": before_state.has_healthcheck,
                "notes": ["restart command failed; verification skipped"],
            },
            after_raw=None,
        )

    if cfg.post_restart_wait_seconds > 0:
        sleep(cfg.post_restart_wait_seconds)

    after_inspect = inspector.inspect(container)
    if not after_inspect.ok:
        return VerificationOutcome(
            summary={
                "status": VERIFICATION_STATUS_FAILED,
                "started_at_before": before_state.started_at,
                "started_at_after": "",
                "started_at_changed": False,
                "running_after": False,
                "health_before": before_state.health,
                "health_after": HEALTH_UNKNOWN,
                "restart_count_before": before_state.restart_count,
                "restart_count_after": None,
                "has_healthcheck": before_state.has_healthcheck,
                "notes": [f"inspect failed after restart: {after_inspect.error}"],
            },
            after_raw=None,
        )
    after = capture_container_state_from(after_inspect)
    last_raw: dict[str, Any] | None = after_inspect.raw if after_inspect.exists else None

    if not after.exists:
        return VerificationOutcome(
            summary={
                "status": VERIFICATION_STATUS_FAILED,
                "started_at_before": before_state.started_at,
                "started_at_after": "",
                "started_at_changed": False,
                "running_after": False,
                "health_before": before_state.health,
                "health_after": HEALTH_UNKNOWN,
                "restart_count_before": before_state.restart_count,
                "restart_count_after": None,
                "has_healthcheck": before_state.has_healthcheck,
                "notes": ["container missing after restart"],
            },
            after_raw=last_raw,
        )

    if not after.running:
        return VerificationOutcome(
            summary={
                "status": VERIFICATION_STATUS_FAILED,
                "started_at_before": before_state.started_at,
                "started_at_after": after.started_at,
                "started_at_changed": before_state.started_at != after.started_at,
                "running_after": False,
                "health_before": before_state.health,
                "health_after": after.health,
                "restart_count_before": before_state.restart_count,
                "restart_count_after": after.restart_count,
                "has_healthcheck": after.has_healthcheck,
                "notes": [
                    "container not running after restart; no second restart attempted",
                ],
            },
            after_raw=last_raw,
        )

    started_changed = bool(before_state.started_at) and before_state.started_at != after.started_at
    if not started_changed:
        notes.append("StartedAt did not change after restart command exited 0")

    if (
        before_state.restart_count is not None
        and after.restart_count is not None
        and before_state.restart_count == after.restart_count
    ):
        notes.append("RestartCount did not change; manual docker restart may not increment it.")

    # Health polling — only when a healthcheck exists.
    final_health = after.health
    if after.has_healthcheck:
        deadline_polls = 0
        max_polls = 0
        if cfg.health_poll_interval_seconds > 0:
            max_polls = int(cfg.health_wait_seconds / cfg.health_poll_interval_seconds)
        # Initial reading already in after.health; poll further while starting.
        current = after
        while current.health == HEALTH_STARTING and deadline_polls < max_polls:
            sleep(cfg.health_poll_interval_seconds)
            deadline_polls += 1
            poll = inspector.inspect(container)
            if not poll.ok:
                notes.append(f"health poll inspect failed: {poll.error}")
                break
            if poll.exists and poll.raw is not None:
                last_raw = poll.raw
            current = capture_container_state_from(poll)
            if not current.exists or not current.running:
                return VerificationOutcome(
                    summary={
                        "status": VERIFICATION_STATUS_FAILED,
                        "started_at_before": before_state.started_at,
                        "started_at_after": current.started_at,
                        "started_at_changed": before_state.started_at != current.started_at,
                        "running_after": False,
                        "health_before": before_state.health,
                        "health_after": current.health,
                        "restart_count_before": before_state.restart_count,
                        "restart_count_after": current.restart_count,
                        "has_healthcheck": current.has_healthcheck,
                        "notes": notes + ["container disappeared or stopped during health polling"],
                    },
                    after_raw=last_raw,
                )
        final_health = current.health

    if after.has_healthcheck:
        if final_health == HEALTH_UNHEALTHY:
            return VerificationOutcome(
                summary={
                    "status": VERIFICATION_STATUS_FAILED,
                    "started_at_before": before_state.started_at,
                    "started_at_after": after.started_at,
                    "started_at_changed": started_changed,
                    "running_after": True,
                    "health_before": before_state.health,
                    "health_after": final_health,
                    "restart_count_before": before_state.restart_count,
                    "restart_count_after": after.restart_count,
                    "has_healthcheck": True,
                    "notes": notes + ["healthcheck reports unhealthy after restart"],
                },
                after_raw=last_raw,
            )
        if final_health == HEALTH_STARTING:
            notes.append("Healthcheck still starting after timeout.")
            return VerificationOutcome(
                summary={
                    "status": VERIFICATION_STATUS_WARNING,
                    "started_at_before": before_state.started_at,
                    "started_at_after": after.started_at,
                    "started_at_changed": started_changed,
                    "running_after": True,
                    "health_before": before_state.health,
                    "health_after": final_health,
                    "restart_count_before": before_state.restart_count,
                    "restart_count_after": after.restart_count,
                    "has_healthcheck": True,
                    "notes": notes,
                },
                after_raw=last_raw,
            )
        if final_health == HEALTH_UNKNOWN:
            notes.append("Healthcheck status is unknown after restart")
            return VerificationOutcome(
                summary={
                    "status": VERIFICATION_STATUS_WARNING,
                    "started_at_before": before_state.started_at,
                    "started_at_after": after.started_at,
                    "started_at_changed": started_changed,
                    "running_after": True,
                    "health_before": before_state.health,
                    "health_after": final_health,
                    "restart_count_before": before_state.restart_count,
                    "restart_count_after": after.restart_count,
                    "has_healthcheck": True,
                    "notes": notes,
                },
                after_raw=last_raw,
            )

    # Pass path. Distinguish pass vs warning based on accumulated notes.
    if not started_changed:
        return VerificationOutcome(
            summary={
                "status": VERIFICATION_STATUS_WARNING,
                "started_at_before": before_state.started_at,
                "started_at_after": after.started_at,
                "started_at_changed": False,
                "running_after": True,
                "health_before": before_state.health,
                "health_after": final_health,
                "restart_count_before": before_state.restart_count,
                "restart_count_after": after.restart_count,
                "has_healthcheck": after.has_healthcheck,
                "notes": notes,
            },
            after_raw=last_raw,
        )

    return VerificationOutcome(
        summary={
            "status": VERIFICATION_STATUS_PASSED,
            "started_at_before": before_state.started_at,
            "started_at_after": after.started_at,
            "started_at_changed": True,
            "running_after": True,
            "health_before": before_state.health,
            "health_after": final_health,
            "restart_count_before": before_state.restart_count,
            "restart_count_after": after.restart_count,
            "has_healthcheck": after.has_healthcheck,
            "notes": notes,
        },
        after_raw=last_raw,
    )


def capture_container_state_from(result: InspectResult) -> ContainerState:
    if not result.ok or not result.exists or result.raw is None:
        return ContainerState(
            exists=False,
            container_id="",
            running=False,
            status="",
            started_at="",
            exit_code=None,
            health=HEALTH_NONE,
            restart_count=None,
            has_healthcheck=False,
        )
    return parse_inspect_payload(result.raw)


def write_verification_evidence(
    receipt_path: Path,
    *,
    before_raw: dict[str, Any] | None,
    after_raw: dict[str, Any] | None,
) -> dict[str, str]:
    """Persist before/after inspect JSON alongside the receipt and return paths.

    Evidence files live in a sibling directory whose name matches the receipt
    stem. The receipt JSON glob (``execution_receipts/exec_*.json``) does not
    descend into subdirectories, so PR47 receipts-list tests are unaffected.
    """
    evidence_dir = Path(receipt_path).with_suffix("")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    if before_raw is not None:
        p = evidence_dir / "before-inspect.json"
        p.write_text(json.dumps(before_raw, indent=2, default=str), encoding="utf-8")
        paths["before_inspect_path"] = str(p)
    if after_raw is not None:
        p = evidence_dir / "after-inspect.json"
        p.write_text(json.dumps(after_raw, indent=2, default=str), encoding="utf-8")
        paths["after_inspect_path"] = str(p)
    return paths


__all__ = [
    "AUDIT_ACTION_LAB_RESTART",
    "AUDIT_KIND_EXECUTION",
    "Allowlist",
    "CommandExecutor",
    "ContainerInspector",
    "ContainerState",
    "DockerCliInspector",
    "EXECUTION_POLICY_ALLOWED",
    "ENV_ALLOW_LAB_RESTART",
    "ENV_MUTATION_MODE",
    "ExecResult",
    "FakeCommandExecutor",
    "FakeContainerInspector",
    "HEALTH_HEALTHY",
    "HEALTH_NONE",
    "HEALTH_STARTING",
    "HEALTH_UNHEALTHY",
    "HEALTH_UNKNOWN",
    "InspectResult",
    "VERIFICATION_STATUS_FAILED",
    "VERIFICATION_STATUS_PASSED",
    "VERIFICATION_STATUS_SKIPPED",
    "VERIFICATION_STATUS_WARNING",
    "VerificationConfig",
    "GATE_ACTION_NOT_FOUND",
    "GATE_ACTION_NOT_RESTART",
    "GATE_ALLOWLIST_DISABLED",
    "GATE_ALLOWLIST_EMPTY",
    "GATE_ALLOWLIST_MISSING",
    "GATE_COMMAND_PREVIEW_MISMATCH",
    "GATE_CONFIRM_FLAG",
    "GATE_CONTAINER_NAME_UNSAFE",
    "GATE_CONTAINER_NOT_ALLOWLISTED",
    "GATE_EXECUTE_FLAG",
    "GATE_GUARD_FAILED",
    "GATE_MULTIPLE_RESTART_ACTIONS",
    "GATE_MUTATION_MODE",
    "GATE_NO_RESTART_ACTION",
    "GATE_PROPOSAL_NOT_APPROVED",
    "GateResult",
    "LAB_RESTART_SCHEMA_VERSION",
    "MUTATION_SCOPE",
    "POLICY_DIR",
    "POLICY_FILE",
    "RestartCandidate",
    "SubprocessExecutor",
    "capture_container_state",
    "capture_container_state_from",
    "evaluate_gates",
    "find_restart_candidates",
    "is_safe_container_name",
    "is_valid_restart_argv",
    "load_allowlist",
    "make_inspect_payload",
    "mutation_mode_enabled",
    "parse_inspect_payload",
    "parse_restart_command",
    "policy_path",
    "receipts_dir",
    "run_post_restart_verification",
    "write_default_allowlist",
    "write_execution_receipt",
    "write_verification_evidence",
]
