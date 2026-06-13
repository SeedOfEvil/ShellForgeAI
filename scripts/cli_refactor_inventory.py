#!/usr/bin/env python3
"""Read-only inventory of ShellForgeAI CLI command-module extraction status.

The helper parses repository source with ``ast`` and never imports the
ShellForgeAI runtime application. Default, JSON, and Markdown modes are
read-only. ``--write-doc`` is the only mode that writes a file, and it is
limited to the explicitly requested destination.
"""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "cli_refactor_inventory"
CHECK_MODE = "cli_refactor_inventory_check"
CLI_PATH = Path("src/shellforgeai/cli.py")
COMMANDS_DIR = Path("src/shellforgeai/commands")

# Documented inline-handler debt thresholds. These are deliberately pragmatic:
# they are the post-PR201 state plus a small buffer so routine formatting or a
# tiny import-only wiring change does not trip the guardrail, while an obvious
# regression (a large new inline ``@app.command`` body, or many new inline
# handlers) reintroduced directly into ``cli.py`` does fail the enforcement
# test. Lower these whenever a handler is intentionally extracted, never raise
# them without explicitly recording the new debt here and in the docs.
CLI_LINE_COUNT_THRESHOLD = 14500
CLI_INLINE_HANDLER_THRESHOLD = 105

REGRESSION_REQUIREMENTS = [
    "PR184 command-surface golden guardrail",
    "targeted module-split tests",
    "full pytest if command registration/safety surface changes",
]

# Files that constitute the PR184 golden command-surface guardrail. Their
# presence is a read-only signal that the protective regression harness is in
# place; the inventory never executes them.
COMMAND_SURFACE_GUARDRAIL_FILES = (
    Path("tests/test_pr184_cli_command_surface_golden.py"),
    Path("tests/golden/cli_command_surface_pr184.json"),
    Path("tests/helpers/cli_surface.py"),
)

# Narrative allowlist of what is intentionally allowed to remain in cli.py as
# Typer wiring/glue. This is documentation-only; the concrete glue functions are
# detected from the AST (Typer ``@*.callback()`` decorators) rather than guessed.
ALLOWED_INLINE_GLUE_NOTES = [
    "Typer `app`/group creation and shared app wiring (`typer.Typer(...)`).",
    "Root `@app.callback()` (`main`) including the no-subcommand interactive fallback.",
    "Typer group `@*.callback()` glue (for example `audit index` and `v1 packet`).",
    "`from shellforgeai.commands import <module> as <module>_commands` imports.",
    "`<module>_commands.register(...)` registration calls for extracted modules.",
    "Compatibility command/alias registration that preserves the public surface.",
    "Minimal bootstrap constants and shared option/context helpers.",
]

# What must never be (re)introduced into cli.py. The PR202 enforcement guardrail
# backs this up by failing if inline-handler debt grows past the documented
# thresholds.
NOT_ALLOWED_IN_CLI_NOTES = [
    "Large command handler bodies (extract into `src/shellforgeai/commands/`).",
    "Docker/Compose mutation or restart logic.",
    "Remediation/recovery/rollback execution logic.",
    "Ask deterministic routing/refusal decision bodies.",
    "Receipt artifact business logic.",
    "Interactive REPL loop internals.",
    "Model/Codex call logic.",
    "Large JSON response builders.",
]

# Explicit, reasoned allowlist of inline callables that are intentionally kept in
# cli.py as Typer wiring / root bootstrap. Every entry MUST carry a non-empty
# reason. This list is deliberately tiny: it is the closure boundary for the CLI
# command-module split. Anything not on this list is either a documented
# remaining-extraction candidate (classified debt, tracked by the inventory) or
# an unapproved inline handler (which fails ``--check``).
#
# Growing this list is a smell: if a future PR needs to add a substantial command
# handler here, it should extract the handler into src/shellforgeai/commands/
# instead. Only genuine Typer entrypoint/registration glue or a tiny read-only
# root command belongs here, and only with an explicit reason.
INLINE_ALLOWLIST: tuple[dict[str, str], ...] = (
    {
        "name": "main",
        "reason": (
            "Typer root @app.callback() / app bootstrap and no-subcommand "
            "interactive fallback (intentional Typer entrypoint)."
        ),
    },
    {
        "name": "version_cmd",
        "reason": "Intentional tiny read-only `version` root command kept inline.",
    },
    {
        "name": "audit_index_main",
        "reason": "Typer `audit index` group @*.callback() registration glue.",
    },
    {
        "name": "v1_packet",
        "reason": "Typer `v1 packet` group @*.callback() registration glue.",
    },
)


def validate_allowlist(allowlist: Any) -> list[str]:
    """Return a list of human-readable errors for a malformed allowlist.

    An allowlist entry is only acceptable when it is a mapping carrying a
    non-empty ``name`` and a non-empty ``reason``. An empty error list means the
    allowlist is well-formed. This is the data-integrity guard behind the rule
    that the allowlist must stay explicit and reasoned: an entry without a reason
    is rejected rather than silently honored.
    """

    errors: list[str] = []
    if not isinstance(allowlist, (list, tuple)):
        return ["allowlist must be a list/tuple of {name, reason} entries"]
    seen: set[str] = set()
    for index, entry in enumerate(allowlist):
        if not isinstance(entry, dict):
            errors.append(f"allowlist entry {index} is not a mapping")
            continue
        name = entry.get("name")
        reason = entry.get("reason")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"allowlist entry {index} is missing a non-empty 'name'")
            continue
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"allowlist entry for {name!r} is missing a non-empty 'reason'")
        if name in seen:
            errors.append(f"allowlist entry for {name!r} is duplicated")
        seen.add(name)
    return errors


EXTRACTED_MODULES: dict[str, dict[str, Any]] = {
    "apply-preview": {"module": "apply_preview.py", "category": "preview_only", "known_pr": 187},
    "ask": {"module": "ask.py", "category": "read_only", "known_pr": 190},
    "doctor": {"module": "doctor.py", "category": "read_only", "known_pr": 182},
    "handoff": {"module": "handoff.py", "category": "artifact_only", "known_pr": 186},
    "interactive": {"module": "interactive.py", "category": "read_only", "known_pr": 200},
    "model": {"module": "model.py", "category": "read_only", "known_pr": 196},
    "ops": {"module": "ops.py", "category": "read_only", "known_pr": 183},
    "propose": {"module": "propose.py", "category": "artifact_only", "known_pr": 187},
    "receipt audit": {"module": "receipt_audit.py", "category": "artifact_only", "known_pr": 191},
    "receipt recovery execute": {
        "module": "receipt_recovery_execute.py",
        "category": "confirm_gated_mutation",
        "known_pr": 194,
    },
    "receipt recovery readonly": {
        "module": "receipt_recovery_readonly.py",
        "category": "artifact_only",
        "known_pr": 193,
    },
    "receipt safety": {"module": "receipt_safety.py", "category": "preview_only", "known_pr": 192},
    "recipes/preflight": {"module": "recipes.py", "category": "read_only", "known_pr": 189},
    "remediation self-test": {
        "module": "remediation.py",
        "category": "preview_only",
        "known_pr": 199,
    },
    "status": {"module": "status.py", "category": "read_only", "known_pr": 182},
    "triage": {"module": "triage.py", "category": "read_only", "known_pr": 183},
    "v1": {"module": "v1.py", "category": "read_only", "known_pr": 195},
    "verify": {"module": "verify.py", "category": "read_only", "known_pr": 185},
}

# Known inline command-handler groups left in cli.py. This is intentionally
# conservative: unknown handlers stay unknown and trigger warnings.
INLINE_CLASSIFICATIONS: dict[str, dict[str, Any]] = {
    "main": {
        "name": "root callback / interactive fallback",
        "category": "read_only",
        "risk": "medium",
        "lane": "Lane C",
        "suggested_next_pr": None,
        "notes": [
            "Root no-subcommand behavior is CLI-surface sensitive; move only with full guardrails."
        ],
    },
    "version_cmd": {
        "name": "version",
        "category": "read_only",
        "risk": "low",
        "lane": "Lane B",
        "suggested_next_pr": 199,
        "notes": ["Small read-only root command; good low-risk extraction candidate."],
    },
    "logs": {
        "name": "logs",
        "category": "read_only",
        "risk": "medium",
        "lane": "Lane C",
        "suggested_next_pr": None,
        "notes": ["Evidence-facing log command; preserve no-mutation boundaries."],
    },
    "diagnose": {
        "name": "diagnose",
        "category": "read_only",
        "risk": "medium",
        "lane": "Lane C",
        "suggested_next_pr": None,
        "notes": [
            "Core diagnostic collector path; require command-surface and evidence "
            "regression coverage."
        ],
    },
    "research": {
        "name": "research",
        "category": "read_only",
        "risk": "medium",
        "lane": "Lane C",
        "suggested_next_pr": None,
        "notes": ["May involve synthesis/provider plumbing; preserve advisory-only semantics."],
    },
    "plan": {
        "name": "plan",
        "category": "preview_only",
        "risk": "medium",
        "lane": "Lane C",
        "suggested_next_pr": None,
        "notes": ["Plan generation must remain non-executing."],
    },
    "runbook": {
        "name": "runbook",
        "category": "artifact_only",
        "risk": "medium",
        "lane": "Lane C",
        "suggested_next_pr": None,
        "notes": ["Runbook artifacts must remain review-only."],
    },
    "validate_runbook_cmd": {
        "name": "validate-runbook",
        "category": "read_only",
        "risk": "low",
        "lane": "Lane B",
        "suggested_next_pr": 199,
        "notes": ["Read-only validator; can pair with runbook if scoped tightly."],
    },
    "apply": {
        "name": "apply",
        "category": "preview_only",
        "risk": "high",
        "lane": "Lane C",
        "suggested_next_pr": None,
        "notes": [
            "Alpha behavior is validation-only; dangerous/broad if mishandled; "
            "extraction must prove no broad/freeform mutation."
        ],
    },
    "v1_packet": {
        "name": "v1 packet callback",
        "category": "artifact_only",
        "risk": "medium",
        "lane": "Lane C",
        "suggested_next_pr": None,
        "notes": ["V1 packet group callback belongs with packet artifact lifecycle extraction."],
    },
    "safe_actions": {
        "name": "safe-actions",
        "category": "read_only",
        "risk": "medium",
        "lane": "Lane C",
        "suggested_next_pr": None,
        "notes": [
            "Safe-command suggestion surface; preserve refusal and safe-next-command wording."
        ],
    },
}

PREFIX_CLASSIFICATIONS: tuple[tuple[str, dict[str, Any]], ...] = (
    (
        "inspect_",
        {
            "name": "inspect",
            "category": "read_only",
            "risk": "low",
            "lane": "Lane B",
            "suggested_next_pr": 199,
            "notes": ["Read-only inspect group is a low-risk extraction candidate."],
        },
    ),
    (
        "tools_",
        {
            "name": "tools",
            "category": "read_only",
            "risk": "low",
            "lane": "Lane B",
            "suggested_next_pr": 199,
            "notes": ["Read-only tool catalog/help surface."],
        },
    ),
    (
        "audit_cleanup_execute",
        {
            "name": "audit cleanup execute",
            "category": "confirm_gated_mutation",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Governed cleanup execution must move last or with full validation."],
        },
    ),
    (
        "audit_cleanup_archive",
        {
            "name": "audit cleanup archive",
            "category": "artifact_only",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Cleanup archive is artifact mutation; require full safety validation."],
        },
    ),
    (
        "audit_cleanup_prepare",
        {
            "name": "audit cleanup prepare",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Writes ShellForgeAI-owned cleanup metadata only."],
        },
    ),
    (
        "audit_cleanup_",
        {
            "name": "audit cleanup readonly/preview",
            "category": "preview_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Cleanup planning/review/reporting must stay non-destructive."],
        },
    ),
    (
        "audit_archive",
        {
            "name": "audit archive",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Audit archive mutates ShellForgeAI-owned artifacts only."],
        },
    ),
    (
        "audit_prune",
        {
            "name": "audit prune",
            "category": "artifact_only",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Prune/archive behavior is artifact-mutating and needs full validation."],
        },
    ),
    (
        "audit_",
        {
            "name": "audit readonly",
            "category": "read_only",
            "risk": "low",
            "lane": "Lane B",
            "suggested_next_pr": 200,
            "notes": [
                "Mostly read-only audit views and validators; keep artifact-mutating "
                "variants separate."
            ],
        },
    ),
    (
        "actions_compile",
        {
            "name": "actions compile",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Compiles review-only action records from approved proposals; no execution."],
        },
    ),
    (
        "actions_",
        {
            "name": "actions readonly",
            "category": "read_only",
            "risk": "low",
            "lane": "Lane B",
            "suggested_next_pr": 200,
            "notes": ["Read-only action record show/validate surface."],
        },
    ),
    (
        "rollback_",
        {
            "name": "rollback preview/validate/show",
            "category": "preview_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": [
                "Rollback remains preview/validation only; no rollback execution in this group."
            ],
        },
    ),
    (
        "guard_",
        {
            "name": "guard",
            "category": "read_only",
            "risk": "low",
            "lane": "Lane B",
            "suggested_next_pr": 200,
            "notes": ["Read-only stale-evidence/drift guard checks."],
        },
    ),
    (
        "export_",
        {
            "name": "export",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Writes export packs; should remain ShellForgeAI-artifact-only."],
        },
    ),
    (
        "validate_export",
        {
            "name": "validate-export",
            "category": "read_only",
            "risk": "low",
            "lane": "Lane B",
            "suggested_next_pr": 200,
            "notes": ["Read-only export validator."],
        },
    ),
    (
        "approvals_approve",
        {
            "name": "approvals approve",
            "category": "artifact_only",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": [
                "Approval metadata can unlock later governed flows; move late with full validation."
            ],
        },
    ),
    (
        "approvals_",
        {
            "name": "approvals",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Proposal metadata lifecycle; no host/container mutation."],
        },
    ),
    (
        "mission_restart_execute",
        {
            "name": "mission restart execute",
            "category": "confirm_gated_mutation",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Governed execution handler; leave for last and require full validation."],
        },
    ),
    (
        "mission_compose_restart_execute",
        {
            "name": "mission compose-restart execute",
            "category": "confirm_gated_mutation",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Compose restart execution is governed and safety-sensitive; move last."],
        },
    ),
    (
        "mission_",
        {
            "name": "mission metadata/readiness",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": [
                "Mission metadata/checklist/report/export flows; split execution separately."
            ],
        },
    ),
    (
        "recipes_execute",
        {
            "name": "recipes execute",
            "category": "confirm_gated_mutation",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": [
                "Named governed recipe execution; leave for last or isolate with full validation."
            ],
        },
    ),
    (
        "compose_restart_preview",
        {
            "name": "compose restart-preview",
            "category": "preview_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Compose restart preview must not execute Compose."],
        },
    ),
    (
        "compose_propose_restart",
        {
            "name": "compose propose-restart",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Proposal artifact only; no Compose execution."],
        },
    ),
    (
        "compose_",
        {
            "name": "compose readonly/context",
            "category": "read_only",
            "risk": "low",
            "lane": "Lane B",
            "suggested_next_pr": 199,
            "notes": ["Read-only Compose ownership/environment context."],
        },
    ),
    (
        "v1_packet_export",
        {
            "name": "v1 packet export",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": [
                "V1 packet export/history/compare artifact lifecycle; v1 check is already "
                "extracted."
            ],
        },
    ),
    (
        "v1_packet_",
        {
            "name": "v1 packet readonly/artifact",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": [
                "V1 packet lifecycle should preserve readiness guidance and artifact-only behavior."
            ],
        },
    ),
    (
        "self_test_",
        {
            "name": "self-test commands",
            "category": "read_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Validation harness surface; must not start mutation or Docker operations."],
        },
    ),
    (
        "remediation_execute",
        {
            "name": "remediation execute",
            "category": "confirm_gated_mutation",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Governed disposable remediation execution; leave for last."],
        },
    ),
    (
        "remediation_rollback_execute",
        {
            "name": "remediation rollback-execute",
            "category": "confirm_gated_mutation",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Governed rollback execution; leave for last with full validation."],
        },
    ),
    (
        "remediation_rollback_",
        {
            "name": "remediation rollback preview/validate/status",
            "category": "preview_only",
            "risk": "high",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Rollback-adjacent surface is safety-sensitive even when preview-only."],
        },
    ),
    (
        "remediation_receipt_",
        {
            "name": "remediation receipt",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Receipt validation/reporting; avoid artifact repair/delete."],
        },
    ),
    (
        "remediation_bundle",
        {
            "name": "remediation bundle",
            "category": "artifact_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Bundle artifact lifecycle; no execution."],
        },
    ),
    (
        "remediation_",
        {
            "name": "remediation readonly/preview",
            "category": "preview_only",
            "risk": "medium",
            "lane": "Lane C",
            "suggested_next_pr": None,
            "notes": ["Keep eligibility/plan/preflight/report/audit/status separate from execute."],
        },
    ),
)

RECOMMENDED_GROUPS = [
    {
        "order": 1,
        "name": "inspect/tools/version helpers",
        "reason": "lowest-risk remaining read-only handlers with small command surfaces",
        "recommended_validation_lane": "Lane B",
        "required_regressions": REGRESSION_REQUIREMENTS,
    },
    {
        "order": 2,
        "name": "audit readonly and guard/actions validators",
        "reason": "read-only or validator-heavy groups after low-risk helpers",
        "recommended_validation_lane": "Lane B",
        "required_regressions": REGRESSION_REQUIREMENTS,
    },
    {
        "order": 3,
        "name": "compose context and V1 packet artifact lifecycle",
        "reason": "read-only/artifact-only groups with broader operator-facing behavior",
        "recommended_validation_lane": "Lane C",
        "required_regressions": REGRESSION_REQUIREMENTS,
    },
    {
        "order": 4,
        "name": "approvals/actions compile/export/mission metadata",
        "reason": "artifact-only workflow groups that influence governed execution readiness",
        "recommended_validation_lane": "Lane C",
        "required_regressions": REGRESSION_REQUIREMENTS,
    },
    {
        "order": 5,
        "name": (
            "interactive, apply, mission/recipe/remediation execute and rollback-adjacent handlers"
        ),
        "reason": "mutation-capable, broad, or safety-sensitive handlers should move last",
        "recommended_validation_lane": "Lane C",
        "required_regressions": REGRESSION_REQUIREMENTS,
    },
]

SAFETY_BLOCK = {
    "read_only": True,
    "mutation_performed": False,
    "validation_executed": False,
    "pytest_executed": False,
    "ruff_executed": False,
    "docker_compose_executed": False,
    "container_restarted": False,
    "cleanup_executed": False,
    "remediation_executed": False,
    "rollback_executed": False,
    "recovery_executed": False,
    "shell_true": False,
    "arbitrary_command_execution": False,
    "natural_language_execution": False,
    "model_called": False,
    "artifact_repaired": False,
    "artifact_deleted": False,
}


@dataclass(frozen=True)
class Handler:
    function: str
    line: int
    decorator: str


def _rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _decorator_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return "<unparseable decorator>"


def _is_typer_command_decorator(text: str) -> bool:
    return ".command(" in text or ".callback(" in text


def _is_callback_decorator(text: str) -> bool:
    """Typer ``@*.callback()`` glue, as opposed to a ``@*.command()`` handler."""

    return ".callback(" in text


def discover_inline_handlers(cli_path: Path) -> tuple[list[Handler], list[str]]:
    warnings: list[str] = []
    try:
        source = cli_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception as exc:
        return [], [f"unable to parse {cli_path}: {exc}"]

    handlers: list[Handler] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            text = _decorator_text(decorator)
            if _is_typer_command_decorator(text):
                handlers.append(Handler(function=node.name, line=node.lineno, decorator=text))
                break
    if not handlers:
        warnings.append(
            "no Typer-decorated inline handlers were detected; AST pattern may be incomplete"
        )
    return handlers, warnings


def _classification_for(function: str) -> dict[str, Any] | None:
    if function in INLINE_CLASSIFICATIONS:
        return dict(INLINE_CLASSIFICATIONS[function])
    for prefix, classification in PREFIX_CLASSIFICATIONS:
        if function.startswith(prefix):
            data = dict(classification)
            if data["name"] in {
                "inspect",
                "tools",
                "audit readonly",
                "actions readonly",
                "guard",
                "compose readonly/context",
            }:
                data["name"] = data["name"] + f" ({function})"
            return data
    return None


def classify_handlers(handlers: list[Handler]) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for handler in handlers:
        classification = _classification_for(handler.function)
        if classification is None:
            classification = {
                "name": handler.function.replace("_", "-"),
                "category": "unknown",
                "risk": "high",
                "lane": "Lane C",
                "suggested_next_pr": None,
                "notes": ["Unclassified Typer handler; classify before extraction."],
            }
            warnings.append(
                f"unclassified inline handler {handler.function!r} at line {handler.line}; "
                "category set to unknown"
            )
        rows.append(
            {
                "name": classification["name"],
                "function": handler.function,
                "line": handler.line,
                "category": classification["category"],
                "risk": classification["risk"],
                "recommended_validation_lane": classification["lane"],
                "suggested_next_pr": classification.get("suggested_next_pr"),
                "notes": list(classification.get("notes", [])),
            }
        )
    return rows, warnings


def discover_extracted_modules(
    commands_dir: Path, repo_root: Path
) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    present = {path.name: path for path in commands_dir.glob("*.py") if path.name != "__init__.py"}
    rows: list[dict[str, Any]] = []
    for name, meta in sorted(EXTRACTED_MODULES.items()):
        module = str(meta["module"])
        path = present.get(module, commands_dir / module)
        if module not in present:
            warnings.append(f"expected extracted command module missing: {module}")
        rows.append(
            {
                "name": name,
                "path": _rel(path, repo_root),
                "category": meta["category"],
                "known_pr": meta["known_pr"],
            }
        )
    for module, path in sorted(present.items()):
        if module not in {str(meta["module"]) for meta in EXTRACTED_MODULES.values()}:
            warnings.append(f"unclassified command module present: {module}")
            rows.append(
                {
                    "name": module.removesuffix(".py").replace("_", "-"),
                    "path": _rel(path, repo_root),
                    "category": "unknown",
                    "known_pr": None,
                }
            )
    return rows, warnings


def _count_lines(cli_path: Path) -> int:
    try:
        text = cli_path.read_text(encoding="utf-8")
    except OSError:
        return 0
    if not text:
        return 0
    # Count physical lines; a trailing newline should not inflate the count.
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def build_cli_py_block(
    cli_path: Path, repo_root: Path, handlers: list[Handler]
) -> tuple[dict[str, Any], list[str]]:
    """Summarize cli.py inline-handler debt against documented thresholds."""

    warnings: list[str] = []
    line_count = _count_lines(cli_path)
    inline_handler_count = len(handlers)
    line_within = line_count <= CLI_LINE_COUNT_THRESHOLD
    handlers_within = inline_handler_count <= CLI_INLINE_HANDLER_THRESHOLD
    if not line_within:
        warnings.append(
            f"cli.py line count {line_count} exceeds documented threshold "
            f"{CLI_LINE_COUNT_THRESHOLD}; extract a handler or update the inventory/docs"
        )
    if not handlers_within:
        warnings.append(
            f"cli.py inline handler count {inline_handler_count} exceeds documented "
            f"threshold {CLI_INLINE_HANDLER_THRESHOLD}; extract a handler or update "
            "the inventory/docs"
        )
    block = {
        "path": _rel(cli_path, repo_root),
        "line_count": line_count,
        "line_count_threshold": CLI_LINE_COUNT_THRESHOLD,
        "line_count_within_threshold": line_within,
        "inline_handler_count": inline_handler_count,
        "inline_handler_threshold": CLI_INLINE_HANDLER_THRESHOLD,
        "inline_handler_within_threshold": handlers_within,
        "within_threshold": line_within and handlers_within,
        "allowed_inline_wiring": True,
        "remaining_inline_handler_functions": [handler.function for handler in handlers],
    }
    return block, warnings


def build_closure_block(
    repo_root: Path,
    cli_path: Path,
    commands_dir: Path,
    handlers: list[Handler],
    remaining: list[dict[str, Any]],
    cli_py: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Summarize CLI-refactor closure: glue vs handlers, modules, guardrail.

    This is the read-only verification view for the refactor-closure step. It
    distinguishes intentional Typer wiring/glue (``@*.callback()``) from
    business-logic command handlers (``@*.command()``), confirms the expected
    extracted modules exist, checks that the PR184 command-surface guardrail
    files are present, and reports any *unexpected* (unclassified) inline
    handlers. It never claims a false OK: missing modules, unexpected handlers,
    a missing guardrail, or threshold breaches downgrade ``closure_status``.
    """

    warnings: list[str] = []

    glue_functions = sorted(h.function for h in handlers if _is_callback_decorator(h.decorator))
    command_handler_functions = sorted(
        h.function for h in handlers if not _is_callback_decorator(h.decorator)
    )
    unexpected = sorted(row["function"] for row in remaining if row["category"] == "unknown")

    present_module_stems = sorted(
        path.stem for path in commands_dir.glob("*.py") if path.name != "__init__.py"
    )
    expected_modules = sorted(
        {str(meta["module"]).removesuffix(".py") for meta in EXTRACTED_MODULES.values()}
    )
    missing_expected = [
        module for module in expected_modules if not (commands_dir / f"{module}.py").exists()
    ]

    guardrail_present = all((repo_root / rel).exists() for rel in COMMAND_SURFACE_GUARDRAIL_FILES)
    missing_guardrail = [
        rel.as_posix() for rel in COMMAND_SURFACE_GUARDRAIL_FILES if not (repo_root / rel).exists()
    ]

    if not cli_path.exists():
        warnings.append("closure: cli.py is missing; cannot verify Typer wiring role")
        closure_status = "needs_attention"
    elif unexpected or missing_expected or not cli_py["within_threshold"] or not guardrail_present:
        closure_status = "needs_attention"
    else:
        closure_status = "ok"

    if missing_expected:
        warnings.append("closure: expected command modules missing: " + ", ".join(missing_expected))
    if unexpected:
        warnings.append(
            "closure: unexpected (unclassified) inline handlers present: " + ", ".join(unexpected)
        )
    if not guardrail_present:
        warnings.append(
            "closure: PR184 command-surface guardrail files missing: "
            + ", ".join(missing_guardrail)
        )

    if closure_status == "ok":
        recommendation = (
            f"cli split enforced and behavior-preserving: {len(present_module_stems)} command "
            f"modules extracted; {len(command_handler_functions)} classified inline command "
            "handlers remain as documented future-extraction candidates; "
            f"{len(glue_functions)} Typer callbacks intentionally remain as wiring; "
            "0 unexpected inline handlers; PR184/PR202 guardrails present"
        )
    else:
        recommendation = (
            "closure needs attention: resolve unexpected inline handlers, missing command "
            "modules, the command-surface guardrail, or cli.py threshold breaches before "
            "claiming structural closure"
        )

    block = {
        "cli_py_role": "typer_wiring",
        "command_surface_guardrail": "present" if guardrail_present else "missing",
        "command_modules": present_module_stems,
        "expected_modules": expected_modules,
        "missing_expected_modules": missing_expected,
        "allowed_inline_glue": glue_functions,
        "remaining_command_handlers": len(command_handler_functions),
        "remaining_command_handler_functions": command_handler_functions,
        "unexpected_inline_handlers": unexpected,
        "closure_status": closure_status,
        "recommendation": recommendation,
    }
    return block, warnings


def build_inventory(repo_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    cli_path = repo_root / CLI_PATH
    commands_dir = repo_root / COMMANDS_DIR
    extracted, extracted_warnings = discover_extracted_modules(commands_dir, repo_root)
    handlers, handler_warnings = discover_inline_handlers(cli_path)
    remaining, classification_warnings = classify_handlers(handlers)
    cli_py, cli_py_warnings = build_cli_py_block(cli_path, repo_root, handlers)
    closure, closure_warnings = build_closure_block(
        repo_root, cli_path, commands_dir, handlers, remaining, cli_py
    )
    warnings = (
        extracted_warnings
        + handler_warnings
        + classification_warnings
        + cli_py_warnings
        + closure_warnings
    )
    unknown_handlers = sum(1 for row in remaining if row["category"] == "unknown")
    status = (
        "ok"
        if not extracted_warnings and cli_path.exists() and cli_py["within_threshold"]
        else "failed"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "source": {
            "cli_path": _rel(cli_path, repo_root),
            "commands_dir": _rel(commands_dir, repo_root),
        },
        "summary": {
            "extracted_modules": len(extracted),
            "remaining_inline_handlers": len(remaining),
            "unknown_handlers": unknown_handlers,
            "recommended_next_count": len(RECOMMENDED_GROUPS),
            "cli_line_count": cli_py["line_count"],
            "cli_inline_handler_count": cli_py["inline_handler_count"],
            "cli_within_threshold": cli_py["within_threshold"],
            "closure_status": closure["closure_status"],
            "unexpected_inline_handlers": len(closure["unexpected_inline_handlers"]),
            "allowed_inline_glue": len(closure["allowed_inline_glue"]),
        },
        "cli_py": cli_py,
        "closure": closure,
        "extracted_modules": extracted,
        "remaining_inline_handlers": remaining,
        "recommended_next_extractions": RECOMMENDED_GROUPS,
        "warnings": warnings,
        "first_safe_command": "python scripts/cli_refactor_inventory.py --markdown",
        "safe_next_commands": [
            "python scripts/cli_refactor_inventory.py --json",
            "pytest -q tests/test_pr184_cli_command_surface_golden.py",
        ],
        "safety": dict(SAFETY_BLOCK),
    }


def build_check(
    repo_root: Path, allowlist: tuple[dict[str, str], ...] | list[dict[str, str]] | None = None
) -> dict[str, Any]:
    """Strict wiring-only enforcement view for ``cli.py``.

    Every inline Typer callable in ``cli.py`` is sorted into exactly one bucket:

    * ``allowed`` — explicitly allowlisted Typer wiring / root bootstrap
      (each allowlist entry must carry a reason);
    * ``remaining_extraction_candidate`` — a *classified* inline command handler
      that is documented in the inventory as future-extraction debt (tracked, not
      silently allowed away);
    * ``unapproved`` — an unclassified inline command handler, or a non-allowlisted
      Typer callback. These fail the check: they must move into
      ``src/shellforgeai/commands/`` or earn an explicit allowlist reason.

    The check passes only when there are no unapproved inline handlers, the
    allowlist is well-formed (reasoned), ``cli.py`` parses, and the documented
    inline-handler debt stays within thresholds. It never claims literal
    wiring-only closure while classified handlers remain: ``cli_py_role`` reports
    ``wiring_with_tracked_remaining`` and the remaining extraction map is surfaced
    rather than folded into the allowlist.
    """

    repo_root = repo_root.resolve()
    if allowlist is None:
        allowlist = INLINE_ALLOWLIST
    cli_path = repo_root / CLI_PATH
    commands_dir = repo_root / COMMANDS_DIR

    allowlist_errors = validate_allowlist(allowlist)
    allowlist_names = {
        entry["name"]
        for entry in allowlist
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }

    handlers, handler_warnings = discover_inline_handlers(cli_path)
    cli_py, cli_py_warnings = build_cli_py_block(cli_path, repo_root, handlers)

    allowed: list[str] = []
    remaining_candidates: list[str] = []
    unapproved: list[str] = []
    for handler in handlers:
        if handler.function in allowlist_names:
            allowed.append(handler.function)
        elif _is_callback_decorator(handler.decorator):
            # Typer callbacks are wiring glue, but they must still be explicitly
            # allowlisted; an unlisted callback is unapproved by design.
            unapproved.append(handler.function)
        elif _classification_for(handler.function) is None:
            unapproved.append(handler.function)
        else:
            remaining_candidates.append(handler.function)

    allowed.sort()
    remaining_candidates.sort()
    unapproved.sort()

    present_module_stems = sorted(
        path.stem for path in commands_dir.glob("*.py") if path.name != "__init__.py"
    )
    guardrail_present = all((repo_root / rel).exists() for rel in COMMAND_SURFACE_GUARDRAIL_FILES)

    warnings = handler_warnings + cli_py_warnings
    if allowlist_errors:
        warnings.append("allowlist is malformed: " + "; ".join(allowlist_errors))
    if unapproved:
        warnings.append(
            "unapproved inline handlers must move to src/shellforgeai/commands/ or be "
            "allowlisted with a reason: " + ", ".join(unapproved)
        )

    cli_exists = cli_path.exists()
    within_threshold = bool(cli_py["within_threshold"])
    passed = cli_exists and not unapproved and not allowlist_errors and within_threshold
    status = "passed" if passed else "failed"

    if not cli_exists:
        cli_py_role = "missing"
    elif unapproved or allowlist_errors or not within_threshold:
        cli_py_role = "needs_attention"
    elif remaining_candidates:
        cli_py_role = "wiring_with_tracked_remaining"
    else:
        cli_py_role = "wiring_only"

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": CHECK_MODE,
        "status": status,
        "read_only": True,
        "mutation_performed": False,
        "cli_py_role": cli_py_role,
        "source": {
            "cli_path": _rel(cli_path, repo_root),
            "commands_dir": _rel(commands_dir, repo_root),
        },
        "allowlist": [dict(entry) for entry in allowlist if isinstance(entry, dict)],
        "allowlist_errors": allowlist_errors,
        "allowed_inline_handlers": allowed,
        "unapproved_inline_handlers": unapproved,
        "remaining_extraction_candidates": remaining_candidates,
        "command_modules": present_module_stems,
        "command_surface_guardrail": "present" if guardrail_present else "missing",
        "summary": {
            "allowed_inline_count": len(allowed),
            "unapproved_inline_count": len(unapproved),
            "remaining_extraction_candidate_count": len(remaining_candidates),
            "command_modules_count": len(present_module_stems),
            "cli_line_count": cli_py["line_count"],
            "cli_inline_handler_count": cli_py["inline_handler_count"],
            "cli_within_threshold": within_threshold,
        },
        "cli_py": cli_py,
        "warnings": warnings,
        "first_safe_command": "python scripts/cli_refactor_inventory.py --markdown",
        "safe_next_commands": [
            "python scripts/cli_refactor_inventory.py --check --json",
            "pytest -q tests/test_pr184_cli_command_surface_golden.py",
        ],
        "safety": dict(SAFETY_BLOCK),
    }


def render_check_human(payload: dict[str, Any]) -> str:
    status = payload["status"]
    lines = [f"CLI refactor inventory check: {status}", ""]
    if status == "passed":
        lines.extend(
            [
                "cli.py role:",
                "",
                "* Typer app wiring",
                "* command module registration",
                "* root/bootstrap helpers only",
                "",
                "Remaining inline allowlist:",
                "",
            ]
        )
        for entry in payload["allowlist"]:
            lines.append(f"* {entry['name']}: {entry['reason']}")
        remaining = payload["summary"]["remaining_extraction_candidate_count"]
        lines.extend(
            [
                "",
                (
                    f"Tracked remaining extraction candidates: {remaining} "
                    "(documented in docs/CLI_REFACTOR_MAP.md; not silently allowlisted)."
                ),
                "",
                "No unapproved inline command handlers found.",
            ]
        )
    else:
        if payload["allowlist_errors"]:
            lines.extend(["Allowlist errors:", ""])
            for err in payload["allowlist_errors"]:
                lines.append(f"* {err}")
            lines.append("")
        lines.extend(["Unapproved inline handlers:", ""])
        for name in payload["unapproved_inline_handlers"]:
            lines.append(f"* {name}")
        if not payload["unapproved_inline_handlers"]:
            lines.append("* (none — see warnings below)")
        lines.extend(
            [
                "",
                (
                    "Move these handlers into src/shellforgeai/commands/ or add an "
                    "explicit allowlist reason."
                ),
            ]
        )
    if payload["warnings"]:
        lines.extend(["", "Warnings:", ""])
        for warning in payload["warnings"]:
            lines.append(f"* {warning}")
    lines.extend(
        [
            "",
            "Safety:",
            "",
            "* Inventory check only; read-only AST inspection.",
            "* No command execution.",
            "* No Docker/Compose operation.",
            "* No file mutation.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_human(payload: dict[str, Any]) -> str:
    lines = [
        "ShellForgeAI CLI refactor inventory",
        "",
        f"Status: {payload['status']}",
        "",
        "Extracted command modules:",
        "",
    ]
    for row in payload["extracted_modules"]:
        lines.append(f"* {row['name']}: {row['path']} ({row['category']}, PR{row['known_pr']})")
    lines.extend(["", "Remaining inline handlers in cli.py:", ""])
    for row in payload["remaining_inline_handlers"]:
        suggested = row["suggested_next_pr"]
        suggested_text = f"PR{suggested}" if suggested is not None else "later / not first wave"
        lines.extend(
            [
                f"* {row['name']} [{row['function']}:{row['line']}]",
                f"  Category: {row['category']}",
                f"  Suggested PR: {suggested_text}",
                f"  Risk: {row['risk']}",
                f"  Required validation: {row['recommended_validation_lane']}",
                f"  Notes: {'; '.join(row['notes']) if row['notes'] else 'n/a'}",
            ]
        )
    lines.extend(["", "Recommended next extraction:", ""])
    for row in payload["recommended_next_extractions"]:
        lines.append(f"{row['order']}. Extract {row['name']} — {row['reason']}")
    if payload["warnings"]:
        lines.extend(["", "Warnings:", ""])
        for warning in payload["warnings"]:
            lines.append(f"* {warning}")
    lines.extend(
        [
            "",
            "Safety:",
            "",
            "* Inventory only.",
            "* No command execution.",
            "* No Docker/Compose operation.",
            "* No file mutation unless explicit --write-doc was used.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# ShellForgeAI CLI Refactor Map",
        "",
        (
            "This map is an inventory aid for command-module extraction planning. "
            "It is not a runtime command and does not change ShellForgeAI "
            "command behavior."
        ),
        "",
        "## Status",
        "",
        f"- Status: `{payload['status']}`",
        f"- Extracted command modules: {payload['summary']['extracted_modules']}",
        f"- Remaining inline CLI handlers: {payload['summary']['remaining_inline_handlers']}",
        f"- Unknown inline handlers: {payload['summary']['unknown_handlers']}",
        "",
        "## cli.py inline-handler debt",
        "",
        (
            f"- `{payload['cli_py']['path']}` line count: "
            f"{payload['cli_py']['line_count']} "
            f"(threshold {payload['cli_py']['line_count_threshold']}, "
            f"within: {str(payload['cli_py']['line_count_within_threshold']).lower()})"
        ),
        (
            f"- Inline Typer handlers in cli.py: "
            f"{payload['cli_py']['inline_handler_count']} "
            f"(threshold {payload['cli_py']['inline_handler_threshold']}, "
            f"within: {str(payload['cli_py']['inline_handler_within_threshold']).lower()})"
        ),
        (
            "- `cli.py` remains Typer/app wiring plus the explicitly inventoried "
            "remaining inline handlers below; the PR202 enforcement guardrail "
            "(`tests/test_pr202_cli_refactor_inventory_enforcement.py`) fails if a "
            "new large inline handler is added without lowering the debt or "
            "updating these thresholds and docs."
        ),
        "",
        "## CLI refactor closure status",
        "",
        f"- Closure status: `{payload['closure']['closure_status']}`",
        f"- `cli.py` role: `{payload['closure']['cli_py_role']}`",
        f"- Command-surface guardrail (PR184): `{payload['closure']['command_surface_guardrail']}`",
        f"- Extracted command modules: {len(payload['closure']['command_modules'])}",
        (
            "- Missing expected modules: "
            + (
                ", ".join(f"`{m}`" for m in payload["closure"]["missing_expected_modules"])
                if payload["closure"]["missing_expected_modules"]
                else "none"
            )
        ),
        (
            "- Intentional Typer wiring/glue (callbacks) left in cli.py: "
            + (
                ", ".join(f"`{g}`" for g in payload["closure"]["allowed_inline_glue"])
                if payload["closure"]["allowed_inline_glue"]
                else "none"
            )
        ),
        (
            f"- Classified inline command handlers remaining (future-extraction "
            f"candidates): {payload['closure']['remaining_command_handlers']}"
        ),
        (
            "- Unexpected (unclassified) inline handlers: "
            + (
                ", ".join(f"`{u}`" for u in payload["closure"]["unexpected_inline_handlers"])
                if payload["closure"]["unexpected_inline_handlers"]
                else "none"
            )
        ),
        f"- Recommendation: {payload['closure']['recommendation']}",
        "",
        "## CLI wiring-only enforcement (`--check`)",
        "",
        (
            "`src/shellforgeai/cli.py` is treated as **wiring-only**: Typer app/group "
            "creation, command-module registration, shared app metadata, and thin "
            "root/bootstrap helpers. The split is guarded by a strict check that fails "
            "if an unapproved inline command handler appears in `cli.py`."
        ),
        "",
        "```bash",
        "python scripts/cli_refactor_inventory.py --check",
        "python scripts/cli_refactor_inventory.py --check --json",
        "```",
        "",
        (
            "The check is read-only (AST inspection only) and sorts every inline Typer "
            "callable in `cli.py` into one of three buckets:"
        ),
        "",
        (
            "- **Allowed** — explicitly allowlisted Typer wiring / root bootstrap. Every "
            "allowlist entry must carry a reason."
        ),
        (
            "- **Remaining extraction candidate** — a classified inline command handler "
            "documented as future-extraction debt (tracked, not silently allowlisted)."
        ),
        (
            "- **Unapproved** — an unclassified inline command handler or a "
            "non-allowlisted Typer callback. These fail the check and must move into "
            "`src/shellforgeai/commands/` or earn an explicit allowlist reason."
        ),
        "",
        "### Allowlist (intentional remaining inline callables)",
        "",
        "| Symbol | Reason |",
        "| --- | --- |",
        *[f"| `{entry['name']}` | {entry['reason']} |" for entry in INLINE_ALLOWLIST],
        "",
        (
            "The allowlist is deliberately tiny and must stay reasoned. A future PR that "
            "needs to keep a new inline callable in `cli.py` must add an explicit entry "
            "**with a reason**; an entry without a reason is rejected. If the allowlist "
            "would grow beyond a few genuine wiring/bootstrap items, extract the handler "
            "into `src/shellforgeai/commands/` instead — new command handlers belong in a "
            "command module, not inline in `cli.py`. The PR184 golden command-surface "
            "guardrail remains required for any command refactor."
        ),
        "",
        "## Intentional `cli.py` responsibilities (allowed Typer wiring/glue)",
        "",
        (
            "`src/shellforgeai/cli.py` is intended to remain the Typer app entrypoint "
            "and registration glue. The following are allowed to stay:"
        ),
        "",
        *[f"- {note}" for note in ALLOWED_INLINE_GLUE_NOTES],
        "",
        "## Not allowed in `cli.py`",
        "",
        "The following belong in command modules, not inline in `cli.py`:",
        "",
        *[f"- {note}" for note in NOT_ALLOWED_IN_CLI_NOTES],
        "",
        "## How to run the inventory",
        "",
        "```bash",
        "python scripts/cli_refactor_inventory.py",
        "python scripts/cli_refactor_inventory.py --json",
        "python scripts/cli_refactor_inventory.py --markdown",
        "python scripts/cli_refactor_inventory.py --write-doc docs/CLI_REFACTOR_MAP.md",
        "```",
        "",
        (
            "Default, JSON, and Markdown modes are read-only. `--write-doc` "
            "writes only the explicitly named Markdown file."
        ),
        "",
        "## Extracted command modules",
        "",
        "| Command/group | Module | Category | PR |",
        "| --- | --- | --- | --- |",
    ]
    for row in payload["extracted_modules"]:
        lines.append(
            f"| `{row['name']}` | `{row['path']}` | `{row['category']}` | PR{row['known_pr']} |"
        )
    lines.extend(
        [
            "",
            "## Remaining inline handlers in `src/shellforgeai/cli.py`",
            "",
            (
                "| Handler/group | Function | Line | Category | Risk | Validation | "
                "Suggested PR | Notes |"
            ),
            "| --- | --- | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    for row in payload["remaining_inline_handlers"]:
        suggested = row["suggested_next_pr"]
        suggested_text = f"PR{suggested}" if suggested is not None else "later / not first wave"
        notes = "<br>".join(row["notes"])
        lines.append(
            f"| `{row['name']}` | `{row['function']}` | {row['line']} | "
            f"`{row['category']}` | `{row['risk']}` | `{row['recommended_validation_lane']}` | "
            f"{suggested_text} | {notes} |"
        )
    lines.extend(
        [
            "",
            "## Recommended next extraction order",
            "",
        ]
    )
    for row in payload["recommended_next_extractions"]:
        lines.extend(
            [
                f"{row['order']}. **{row['name']}**",
                f"   - Reason: {row['reason']}",
                f"   - Validation: {row['recommended_validation_lane']}",
                "   - Required regressions: " + "; ".join(row["required_regressions"]),
            ]
        )
    lines.extend(
        [
            "",
            "## Validation requirements for future module-split PRs",
            "",
            "- The PR184 golden command-surface guardrail must run for every CLI split.",
            (
                "- Add targeted module-split tests that prove the new module owns "
                "registration and imports without runtime side effects."
            ),
            (
                "- Use Lane B for narrow read-only moves that do not alter command "
                "registration, option names, refusal wording, or safety surfaces "
                "beyond the intended module ownership proof."
            ),
            (
                "- Use Lane C / full validation for safety-sensitive or broad "
                "command-surface moves, including interactive mode, ask routing, "
                "apply/refusal semantics, recovery, rollback-adjacent flows, "
                "recipe execution, mission execution, or anything that can affect "
                "governed mutation readiness."
            ),
            (
                "- Mutation-capable governed execution handlers move last, or move "
                "only with full validation and explicit confirmation that "
                "execution/refusal semantics are unchanged."
            ),
            "",
            "## Safety summary",
            "",
            "- Inventory only.",
            "- No ShellForgeAI runtime command execution.",
            "- No Docker/Compose operation or mutation.",
            (
                "- No pytest, ruff, validation, cleanup, rollback, recovery, or "
                "recipe execution from the helper."
            ),
            "- No model/Codex call.",
            "- No artifact repair/delete.",
            "- No source mutation; `--write-doc` may write only the requested Markdown doc.",
        ]
    )
    if payload["warnings"]:
        lines.extend(["", "## Warnings", ""])
        for warning in payload["warnings"]:
            lines.append(f"- {warning}")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inventory ShellForgeAI CLI refactor status.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true", help="Emit strict JSON only.")
    mode.add_argument("--markdown", action="store_true", help="Emit Markdown suitable for docs.")
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Strict wiring-only enforcement: fail if cli.py contains unapproved "
            "inline command handlers. Read-only. Combine with --json for strict JSON."
        ),
    )
    parser.add_argument(
        "--write-doc",
        type=Path,
        help="Write Markdown inventory to this explicit path. This is the only writing mode.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.check:
        check_payload = build_check(args.repo_root)
        if args.json:
            print(json.dumps(check_payload, sort_keys=True))
        else:
            print(render_check_human(check_payload), end="")
        return 0 if check_payload["status"] == "passed" else 1

    payload = build_inventory(args.repo_root)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
        return 0 if payload["status"] == "ok" else 1

    if args.markdown:
        print(render_markdown(payload), end="")
        return 0 if payload["status"] == "ok" else 1

    if args.write_doc is not None:
        markdown = render_markdown(payload)
        args.write_doc.parent.mkdir(parents=True, exist_ok=True)
        args.write_doc.write_text(markdown, encoding="utf-8")
        print(f"Wrote CLI refactor map: {args.write_doc}")
        return 0 if payload["status"] == "ok" else 1

    print(render_human(payload), end="")
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
