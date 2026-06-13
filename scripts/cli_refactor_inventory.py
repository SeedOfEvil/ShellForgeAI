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


def build_inventory(repo_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    cli_path = repo_root / CLI_PATH
    commands_dir = repo_root / COMMANDS_DIR
    extracted, extracted_warnings = discover_extracted_modules(commands_dir, repo_root)
    handlers, handler_warnings = discover_inline_handlers(cli_path)
    remaining, classification_warnings = classify_handlers(handlers)
    cli_py, cli_py_warnings = build_cli_py_block(cli_path, repo_root, handlers)
    warnings = extracted_warnings + handler_warnings + classification_warnings + cli_py_warnings
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
        },
        "cli_py": cli_py,
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
