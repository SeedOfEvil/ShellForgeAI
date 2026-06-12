"""``doctor`` command registration (extracted in PR182).

Behavior-preserving move of the read-only ``doctor`` health/metadata-hygiene
command. All shared helpers, the console, the tool registry, and the
subprocess wrapper remain owned by ``shellforgeai.cli`` and are resolved
lazily at call time, so monkeypatching, output, exit codes, JSON strictness,
advisory wording, and safety behavior are preserved exactly. No cleanup,
remediation, rollback, recovery, Docker/Compose mutation, restart, shell
execution, or arbitrary/model-driven execution is introduced here.

The ``model doctor`` provider-readiness command originally registered here
moved (unchanged) to :mod:`shellforgeai.commands.model` in PR196.
"""

from __future__ import annotations

import platform
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

import typer

from shellforgeai.core.metadata_hygiene import human_bytes
from shellforgeai.util.subprocess import run_command


def register(app: typer.Typer) -> None:
    """Register ``doctor`` on the root app.

    The handler delegates to existing ``shellforgeai.cli`` module attributes
    (resolved at call time) to preserve monkeypatch hooks used by the test
    suite and the exact current behavior.
    """

    cli = sys.modules["shellforgeai.cli"]

    @app.command()
    def doctor(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
        runtime = cli._ctx(ctx)
        audit = cli.AuditStorage(runtime.session.data_dir)
        build = cli.get_build_info()
        pid1 = "unknown"
        with suppress(Exception):
            pid1 = Path("/proc/1/comm").read_text(encoding="utf-8").strip()
        ps = run_command(["ps", "-eo", "stat=,comm="], timeout=5)
        defunct_codex = 0
        if ps.exit_code == 0:
            for line in ps.stdout.splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2 and "Z" in parts[0] and parts[1] == "codex":
                    defunct_codex += 1
        init_reaper = "yes" if pid1 in {"tini", "dumb-init", "systemd", "init"} else "no"
        hygiene: dict[str, Any] = cli.scan_metadata_hygiene(Path(runtime.session.data_dir))
        hygiene_attention = hygiene["severity"] in {"warning", "critical"}
        hygiene["human_context"] = (
            "ShellForgeAI-owned historical artifacts exceed advisory threshold."
            if hygiene_attention
            else "ShellForgeAI-owned artifacts are within advisory thresholds."
        )
        hygiene["active_runtime_failure"] = False
        hygiene["cleanup_performed"] = False
        hygiene["first_safe_command"] = "shellforgeai audit cleanup review"
        hygiene["cleanup_execution_gated"] = True
        payload: dict[str, Any] = {
            "shellforgeai": {
                "version": build.display_version,
                "python": sys.version.split()[0],
                "platform": platform.system(),
                "profile": runtime.profile.name,
                "mode": runtime.session.mode,
                "data_dir": str(runtime.session.data_dir),
                "audit_dir": str(audit.sessions_dir),
                "tools": len(cli.registry.list_tools()),
                "model": f"{runtime.settings.model.provider}/{runtime.settings.model.model}",
            },
            "runtime_hygiene": {
                "pid1": pid1,
                "init_reaper": init_reaper,
                "defunct_codex": defunct_codex,
            },
            "metadata_hygiene": hygiene,
            "safety": {
                "cleanup_executed": False,
                "mutation_performed": False,
                "docker_compose_executed": False,
                "remediation_executed": False,
                "rollback_executed": False,
            },
        }
        if json_output:
            cli.console.print_json(data=payload)
            return

        cli.console.print("ShellForgeAI")
        cli.console.print(
            " ".join(
                [
                    f"version={build.display_version}",
                    f"python={sys.version.split()[0]}",
                    f"platform={platform.system()}",
                ]
            )
        )
        if build.build_line():
            cli.console.print(build.build_line())
        cli.console.print(f"profile={runtime.profile.name} mode={runtime.session.mode}")
        cli.console.print(f"data_dir={runtime.session.data_dir} audit_dir={audit.sessions_dir}")
        cli.console.print(
            " ".join(
                [
                    f"tools={len(cli.registry.list_tools())}",
                    f"model={runtime.settings.model.provider}/{runtime.settings.model.model}",
                ]
            )
        )
        cli.console.print(
            f"runtime_hygiene pid1={pid1} init_reaper={init_reaper} defunct_codex={defunct_codex}"
        )
        cli.console.print("Metadata hygiene")
        runtime_ok = "OK" if defunct_codex == 0 else "needs attention"
        metadata_attention = "attention needed" if hygiene_attention else "OK"
        cli.console.print(f"- Runtime: {runtime_ok}")
        cli.console.print(f"- Metadata hygiene: {metadata_attention}")
        if hygiene_attention:
            cli.console.print("- Note:")
            cli.console.print(
                "  - ShellForgeAI-owned historical artifacts exceed the advisory threshold."
            )
            cli.console.print("  - This is not an active Docker/system failure by itself.")
            cli.console.print("  - No cleanup was performed.")
            cli.console.print("- First safe command: shellforgeai audit cleanup review")
            cli.console.print("- Cleanup remains gated:")
            cli.console.print("  review -> plan -> archive -> validate -> execute --confirm")
        cli.console.print(
            "- severity: "
            f"{hygiene['severity']} | ShellForgeAI metadata: "
            f"{hygiene['total_human']} across {hygiene['total_items']} items"
        )
        reasons = hygiene.get("reasons") or []
        if reasons:
            cli.console.print("- Reasons:")
            for reason in reasons[:5]:
                cli.console.print(
                    "  - "
                    f"{reason['category']}: {reason['count']} items, "
                    f"estimated_size={human_bytes(int(reason['estimated_bytes']))}, "
                    f"threshold={reason['threshold']}, "
                    f"oldest={reason['oldest_created_at'] or 'unknown'}"
                )
        else:
            cats = sorted(
                hygiene["categories"].items(), key=lambda kv: int(kv[1]["bytes"]), reverse=True
            )
            cli.console.print("- Largest categories:")
            for name, row in cats[:3]:
                cli.console.print(f"  - {name}: {row['human']} / {row['count']} items")
        if hygiene["warnings"]:
            cli.console.print(f"- Warning: {hygiene['warnings'][0]}")
        if hygiene["recommendations"]:
            cli.console.print("- Suggested safe next steps:")
            for cmd in hygiene["recommendations"][:5]:
                cli.console.print(f"  - {cmd}")
