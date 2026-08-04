"""Pure, platform-aware interactive help rendering."""

from __future__ import annotations

from shellforgeai.core.platform_operator_contract import PlatformOperatorContract

HELP_USAGE = "Usage: help [advanced]"


def render_quick_help(contract: PlatformOperatorContract) -> str:
    """Render the bounded first-screen guide without probing the host."""

    common_end = """Session commands:
  /pending  /summary

Safety:
  Natural-language fixes and mutation requests are refused; they are never run.
  Interactive mode is not a shell. Help performs no collection or model call.
  Full command reference: /help advanced"""
    if contract.platform_system == "linux":
        body = """ShellForgeAI quick start — Linux/Docker read-only

Try a read-only investigation:
  What looks unhealthy?
  Why does this system feel slow?
  Is my Docker container crashing?
  What is the strongest CPU, memory, disk, or process signal?
  Based on evidence already collected, what is the best read-only next check?

Safe explicit commands:
  status --brief
  ops report --brief
  v1 check quick
  triage docker"""
    elif contract.platform_system == "windows":
        body = """ShellForgeAI quick start — Windows local read-only

Try a native read-only investigation:
  What looks unhealthy?
  Is anything crashing?
  Why does this system feel slow?
  Are any services unhealthy?
  Am I running out of disk space?
  Is networking okay?
  What is the strongest CPU, memory, disk, or process signal?
  Based on evidence already collected, what is the best read-only next check?

Safe explicit commands:
  shellforgeai windows evidence --profile standard --json
  shellforgeai windows status --json"""
    else:
        body = f"""ShellForgeAI quick start — {contract.display_name} limited read-only support

Local operator evidence support is unavailable for this platform.
Current runtime and safe assistance:
  status --brief
  shellforgeai platform doctor --json
  ask explain this command: <command>
  ask review this shell snippet: <snippet>
  ask <question>"""
    return f"{body}\n\n{common_end}"


def render_advanced_help() -> str:
    """Render the curated complete interactive reference."""

    return """ShellForgeAI advanced interactive help

Session:
  help / /help / ? / commands / what can I do?
  help advanced / /help advanced
  pending / /pending / summary / /summary / summary --json
  /exit / /clear / /context <minimal|standard|full> / /raw on|off / /examples

Status and evidence:
  status [--brief|--json]
  doctor [--json] / model doctor [--json]
  ops report [--brief|--json]
  v1 check quick / v1 check --profile quick --json
  shellforgeai platform doctor --json

Linux/Docker diagnostics (Linux hosts):
  diagnose <target>
  triage docker [--brief|--json]
  triage docker detail <target> --json

Windows read-only diagnostics (Windows hosts):
  shellforgeai windows evidence --profile standard --json
  shellforgeai windows status --json
  shellforgeai windows doctor --json
  shellforgeai windows processes --json --limit 10
  shellforgeai windows services --json
  shellforgeai windows events --json
  shellforgeai windows network --json
  shellforgeai windows volumes --json

V2 read-only lifecycle:
  triage / propose / apply-preview / verify / handoff
  triage|propose|apply-preview|verify|handoff [--brief|--json]
  triage|propose|verify|handoff --target <target> --json
  verify --receipt <id> [--json] / handoff summary / handoff --save
  status -> triage -> propose -> apply-preview -> verify -> handoff

Reports and artifacts:
  ops report --save / ops report history --limit 5
  ops report compare-latest [--json]
  handoff validate <id> / handoff export <id> / handoff export-validate <id>
  handoff history / handoff compare <before> <after> / handoff compare-latest

Governed explicit workflows — never executed from natural language:
  recipes list [--json] / recipes inspect <id>
  recipes eligibility --recipe docker.disposable_restart --target <target>
  recipes preflight --recipe docker.disposable_restart --target <target> [--json|--save]
  recipes preflight validate <id>
  recipes execute <id> --confirm [--json]
  recipes receipt validate <id> [--json] / recipes receipt verify <id> [--json]
  recipes receipt history / inspect / explain / integrity / audit / compare
  recipes receipt export / export-validate [--json]
  recipes receipt rollback-preview <id> [--json]
  recipes receipt recovery-execute <id> --confirm [--json]
  recipes receipt recovery-status <id> [--json]
  Natural language cannot invoke governed execution; explicit confirmation is required.

Refused natural-language actions (examples only; not run):
  docker restart <container> / docker compose restart <service>
  cleanup execute --confirm / remediation execute --confirm
  rollback-execute --confirm / recovery requests / arbitrary shell commands (for example rm -rf /)

Safety:
  Deterministic help is local: no provider, dispatcher, collector, or command runs.
  Interactive mode is not a shell; natural-language mutation is refused."""
