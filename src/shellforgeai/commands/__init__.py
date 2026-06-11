"""ShellForgeAI CLI command modules.

This package holds the staged extraction of command registration/handler glue
out of the monolithic ``shellforgeai.cli`` module. ``cli.py`` remains the
canonical Typer entrypoint and root app owner; each module here exposes a
small ``register(...)`` surface that attaches its commands to the existing
Typer app(s).

The behavior-preserving extraction slices currently cover read-only domains:

* :mod:`shellforgeai.commands.status` — the ``status`` golden-path command.
* :mod:`shellforgeai.commands.doctor` — ``doctor`` and ``model doctor``.
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

Importing these modules has no side effects: they only define ``register``
functions and resolve ``shellforgeai.cli`` lazily so registration order, help
visibility, JSON behavior, exit codes, and safety gates are preserved exactly.
Future PRs will migrate additional domains (validation, audit, compose,
mission, etc.) one domain at a time, behavior-preserving each step.
"""

__all__ = ["apply_preview", "doctor", "handoff", "ops", "propose", "status", "triage", "verify"]
