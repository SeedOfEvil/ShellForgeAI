"""ShellForgeAI CLI command modules.

This package holds the staged extraction of command registration/handler glue
out of the monolithic ``shellforgeai.cli`` module. ``cli.py`` remains the
canonical Typer entrypoint and root app owner; each module here exposes a
small ``register(...)`` surface that attaches its commands to the existing
Typer app(s).

The behavior-preserving extraction slices currently cover read-only domains:

* :mod:`shellforgeai.commands.status` — the ``status`` golden-path command.
* :mod:`shellforgeai.commands.doctor` — the read-only ``doctor`` command.
* :mod:`shellforgeai.commands.model` — the ``model`` command group:
  the read-only ``model doctor`` provider-readiness report (no model
  inference, no Codex task execution) and the existing explicit one-shot
  ``model test`` surface, both unchanged.
* :mod:`shellforgeai.commands.ops` — ``ops status`` and the ``ops report``
  report lifecycle handlers.
* :mod:`shellforgeai.commands.triage` — ``triage`` and compatibility
  ``triage docker`` handlers.
* :mod:`shellforgeai.commands.verify` — the read-only top-level ``verify``
  current-state and receipt-aware handler.
* :mod:`shellforgeai.commands.handoff` — the read-only V2 operator handoff
  packet and ShellForgeAI-owned handoff artifact lifecycle handlers.
* :mod:`shellforgeai.commands.propose` — the read-only V2 next-action
  proposal preview handler.
* :mod:`shellforgeai.commands.apply_preview` — the read-only V2
  execution-boundary (apply) preview handler; preview-only, never executes.
* :mod:`shellforgeai.commands.receipt_audit` — governed receipt history,
  inspect, export, compare, audit, integrity, finding explanation, and
  artifact-only receipt export/audit-bundle handlers.
* :mod:`shellforgeai.commands.receipt_safety` — the read-only governed
  receipt verify, validate, and rollback-preview handlers (including the
  top-level ``rollback-preview`` alias).
* :mod:`shellforgeai.commands.receipt_recovery_readonly` — the read-only
  recovery receipt status and validate handlers.
* :mod:`shellforgeai.commands.receipt_recovery_execute` — the governed,
  confirm-gated ``recipes receipt recovery-execute`` handler; the explicit
  ``--confirm`` gate, exact-target disposable/allowlist/production gates,
  JSON contract, and recovery receipt behavior are unchanged.
* :mod:`shellforgeai.commands.recipes` — the read-only governed recipe
  registry, list, inspect, eligibility, and preflight (build/save/validate)
  handlers; governed recipe execution (``recipes execute``) stays in
  ``cli.py``.
* :mod:`shellforgeai.commands.v1` — the read-only ``v1 check`` readiness
  handler; quick/standard/full profiles, JSON/human output, counts, and safety
  fields delegate to the existing V1 readiness core unchanged.
* :mod:`shellforgeai.commands.ask` — the top-level deterministic ``ask``
  command; deterministic read-only routing, mutation refusal, and the
  evidence-backed model path delegate to the existing ``cli.py`` helpers,
  which stay in ``cli.py`` (interactive mode and other surfaces share them).
* :mod:`shellforgeai.commands.remediation` — the ``remediation self-test``
  readiness/testing handler; quick/standard/full profiles, JSON/human output,
  safety flags, and the skipped-by-default live disposable execute gate are
  unchanged. All other remediation handlers (eligibility/plan/validate/
  preflight/execute/report/bundle/audit/status/rollback/receipt) stay in
  ``cli.py``.
* :mod:`shellforgeai.commands.interactive` — the top-level ``interactive``
  launcher; it is Typer wiring only, resolving the runtime context and handing
  off to the existing ``shellforgeai.interactive.start_interactive`` REPL. The
  ``--no-trust-cache``/``--yes-trust`` options, startup/exit behavior,
  deterministic read-only routing, mutation refusal, and not-a-shell posture
  are unchanged. The REPL internals stay in ``shellforgeai.interactive``.

Importing these modules has no side effects: they only define ``register``
functions and resolve ``shellforgeai.cli`` lazily so registration order, help
visibility, JSON behavior, exit codes, and safety gates are preserved exactly.
Future PRs will migrate additional domains (validation, audit, compose,
mission, etc.) one domain at a time, behavior-preserving each step.
"""

__all__ = [
    "apply_preview",
    "ask",
    "doctor",
    "handoff",
    "interactive",
    "model",
    "ops",
    "propose",
    "receipt_audit",
    "receipt_recovery_execute",
    "receipt_recovery_readonly",
    "receipt_safety",
    "recipes",
    "remediation",
    "status",
    "triage",
    "v1",
    "verify",
]
