"""ShellForgeAI CLI command modules.

This package holds the staged extraction of command registration/handler glue
out of the monolithic ``shellforgeai.cli`` module. ``cli.py`` remains the
canonical Typer entrypoint and root app owner; each module here exposes a
small ``register(...)`` surface that attaches its commands to the existing
Typer app(s).

The first extraction slice (PR182) covers the safest read-only domains:

* :mod:`shellforgeai.commands.status` — the ``status`` golden-path command.
* :mod:`shellforgeai.commands.doctor` — ``doctor`` and ``model doctor``.

Importing these modules has no side effects: they only define a ``register``
function and resolve ``shellforgeai.cli`` lazily so registration order, help
visibility, JSON behavior, exit codes, and safety gates are preserved exactly.
Future PRs will migrate additional domains (triage, validation, audit,
compose, mission, etc.) one domain at a time, behavior-preserving each step.
"""
