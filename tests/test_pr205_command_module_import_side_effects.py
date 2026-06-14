"""PR205 — command-module import side-effect guardrail.

The CLI command-module split (PR182–PR204) moved the major handlers out of the
monolithic ``shellforgeai.cli`` into ``shellforgeai.commands.*`` modules. This
guardrail protects that architecture from a different failure mode than the
PR184 golden command-surface guardrail: PR184 protects *user-visible commands*;
PR205 protects against *hidden import-time behavior*.

Importing ``shellforgeai.cli`` and every ``shellforgeai.commands.*`` module must
be import-safe — it may only define Typer apps/functions/classes, import local
modules, define constants/option metadata, and register commands. Importing must
never execute operational logic: no subprocess/``os.system``/``shell=True``
execution, no Docker/Compose call or container/production restart, no cleanup/
remediation/rollback/recovery execution, no model/Codex call, no network call,
and no artifact write/repair/delete.

These tests prove that in three complementary ways:

* **Module discovery** confirms the expected command modules exist and import.
* **Runtime guard** imports the audited modules in a *fresh subprocess* with
  recording stubs installed over the dangerous primitives *before* any
  ShellForgeAI import, then asserts no stub fired at import time. Running in a
  fresh interpreter keeps the check fully isolated — nothing is import-cached and
  the parent test process's ``sys.modules``/global state is never mutated.
* **Static guard** parses each command module with ``ast`` and confirms there are
  no top-level operational calls (while harmless help text / command strings are
  not flagged).

The tests themselves are safe: no Docker daemon is required, no real ``/data`` is
mutated, no network is called, and the only subprocesses launched are local
Python probes/helper/test scripts already normal for this harness (the import
probe, the read-only audit helper, and the PR184/PR204 guardrail suites).
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
COMMANDS_DIR = SRC / "shellforgeai" / "commands"
CLI_PATH = SRC / "shellforgeai" / "cli.py"
AUDIT_SCRIPT = REPO / "scripts" / "cli_import_audit.py"

COMMANDS_PACKAGE = "shellforgeai.commands"
CLI_MODULE = "shellforgeai.cli"

# The command modules the split is expected to own. Kept in lockstep with the
# PR204 wiring-only enforcement guardrail's expected set.
EXPECTED_COMMAND_MODULES = {
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
}


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _discovered_command_modules() -> set[str]:
    return {path.stem for path in COMMANDS_DIR.glob("*.py") if path.name != "__init__.py"}


def _command_module_paths() -> list[Path]:
    return sorted(p for p in COMMANDS_DIR.glob("*.py") if p.name != "__init__.py")


def _all_command_dotted() -> list[str]:
    return [f"{COMMANDS_PACKAGE}.{name}" for name in sorted(_discovered_command_modules())]


# The probe harness runs in a *fresh* subprocess so the runtime import checks are
# fully isolated: nothing is import-cached, the dangerous primitives are stubbed
# *before* any ShellForgeAI import, and there is zero chance of polluting the
# parent test process's ``sys.modules`` or global state. ``{patches}`` installs a
# recording stub over the primitive(s) under test; each stub appends a label to
# ``fired`` instead of performing the real operation. Importing the targets must
# leave ``fired`` empty and raise no import error.
_PROBE_HARNESS = """
import importlib, json, sys

fired = []
errors = {{}}

{patches}

for _mod in {targets!r}:
    try:
        importlib.import_module(_mod)
    except Exception as exc:  # pragma: no cover - reported to the parent, not raised
        errors[_mod] = "{{}}: {{}}".format(type(exc).__name__, exc)

print(json.dumps({{"fired": fired, "errors": errors}}))
"""


def _run_python(code: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(SRC), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    return subprocess.run(  # noqa: S603 - test launches a local, fixed Python probe.
        [sys.executable, "-c", code],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def _probe_import(patches: str, targets: list[str]) -> list[str]:
    """Import ``targets`` in a fresh subprocess under ``patches`` and return fired labels.

    Fails the calling test with a clear message if any target raised on import.
    """

    result = _run_python(_PROBE_HARNESS.format(patches=patches, targets=targets))
    assert result.returncode == 0, (
        f"import probe crashed (exit {result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["errors"] == {}, f"modules failed to import: {payload['errors']}"
    return payload["fired"]


def _load_audit_module() -> Any:
    spec = importlib.util.spec_from_file_location("cli_import_audit_pr205", AUDIT_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_audit_script(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # Ensure the in-tree package is importable in the fresh process.
    env["PYTHONPATH"] = os.pathsep.join([str(SRC), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    return subprocess.run(  # noqa: S603 - test executes only the local audit helper.
        [sys.executable, str(AUDIT_SCRIPT), *args],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


# --------------------------------------------------------------------------
# Static checker (used by tests 13–17)
# --------------------------------------------------------------------------

_SUBPROCESS_EXEC_CALLS = {
    "run",
    "Popen",
    "call",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput",
}
_OS_EXEC_CALLS = {"system", "popen", "execv", "execve", "spawnv", "spawnl"}
_MODEL_CALLS = {"build_provider", "complete", "generate", "chat", "create_completion"}
_OPERATIONAL_NAME_TOKENS = (
    "cleanup_execute",
    "remediation_execute",
    "rollback_execute",
    "recovery_execute",
    "execute_receipt_recovery",
    "execute_recipe",
    "run_post_restart_verification",
)


def _top_level_calls(tree: ast.Module) -> list[ast.Call]:
    """Return Call nodes that live at module top level (not inside def/class).

    Statements inside ``FunctionDef``/``AsyncFunctionDef``/``ClassDef`` bodies are
    the legitimate place for operational calls (they only run when the command is
    invoked), so they are intentionally not descended into.
    """

    calls: list[ast.Call] = []

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Call):
                calls.append(child)
            visit(child)

    visit(tree)
    return calls


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _call_qualifier(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return ""


def static_scan_source(source: str) -> dict[str, list[str]]:
    """Scan a module source for top-level operational calls.

    Returns a mapping of finding category -> list of human-readable findings.
    Only Call nodes (and ``shell=True`` keywords) are inspected, so help text and
    command strings that merely *mention* ``subprocess.run`` or ``docker compose``
    are never flagged.
    """

    tree = ast.parse(source)
    findings: dict[str, list[str]] = {
        "subprocess": [],
        "shell_true": [],
        "operational": [],
        "model": [],
    }

    for call in _top_level_calls(tree):
        name = _call_name(call)
        qualifier = _call_qualifier(call)

        if (qualifier == "subprocess" and name in _SUBPROCESS_EXEC_CALLS) or (
            qualifier == "os" and name in _OS_EXEC_CALLS
        ):
            findings["subprocess"].append(f"{qualifier}.{name} at line {call.lineno}")

        for keyword in call.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                findings["shell_true"].append(f"shell=True at line {call.lineno}")

        if any(token in name for token in _OPERATIONAL_NAME_TOKENS):
            findings["operational"].append(f"{name} at line {call.lineno}")

        if name in _MODEL_CALLS:
            findings["model"].append(f"{name} at line {call.lineno}")

    return findings


# --------------------------------------------------------------------------
# 1–4: module discovery
# --------------------------------------------------------------------------


def test_01_command_module_discovery_finds_expected_modules() -> None:
    discovered = _discovered_command_modules()
    missing = EXPECTED_COMMAND_MODULES - discovered
    assert not missing, f"expected command modules missing: {sorted(missing)}"
    # Any new module is allowed but should be tracked: surface unexpected ones.
    assert discovered >= EXPECTED_COMMAND_MODULES


def test_02_cli_imports_successfully() -> None:
    module = importlib.import_module(CLI_MODULE)
    assert module is not None
    assert hasattr(module, "app")


def test_03_commands_package_imports_successfully() -> None:
    package = importlib.import_module(COMMANDS_PACKAGE)
    assert package is not None
    for name in EXPECTED_COMMAND_MODULES:
        assert name in getattr(package, "__all__", []), name


def test_04_every_command_module_imports_successfully() -> None:
    for dotted in _all_command_dotted():
        module = importlib.import_module(dotted)
        assert hasattr(module, "register"), f"{dotted} must expose register(...)"


# --------------------------------------------------------------------------
# 5–12: runtime side-effect guard (fresh-subprocess import under recording stubs)
# --------------------------------------------------------------------------


def test_05_importing_cli_does_not_call_subprocess_run() -> None:
    patches = "import subprocess\nsubprocess.run = lambda *a, **k: fired.append('subprocess.run')"
    assert _probe_import(patches, [CLI_MODULE]) == []


def test_06_importing_command_modules_does_not_call_subprocess_run() -> None:
    patches = "import subprocess\nsubprocess.run = lambda *a, **k: fired.append('subprocess.run')"
    assert _probe_import(patches, _all_command_dotted()) == []


def test_07_importing_command_modules_does_not_call_subprocess_popen() -> None:
    patches = (
        "import subprocess\nsubprocess.Popen = lambda *a, **k: fired.append('subprocess.Popen')"
    )
    assert _probe_import(patches, _all_command_dotted()) == []


def test_08_importing_command_modules_does_not_call_os_system() -> None:
    patches = (
        "import os\n"
        "os.system = lambda *a, **k: fired.append('os.system')\n"
        "os.popen = lambda *a, **k: fired.append('os.popen')"
    )
    assert _probe_import(patches, _all_command_dotted()) == []


def test_09_importing_does_not_call_docker_compose_executor() -> None:
    # Docker/Compose/restart execution funnels through subprocess; additionally
    # guard the named executor helpers where they are patchable.
    patches = (
        "import subprocess\n"
        "subprocess.run = lambda *a, **k: fired.append('subprocess.run')\n"
        "subprocess.Popen = lambda *a, **k: fired.append('subprocess.Popen')\n"
        "import shellforgeai.core.recipe_execution as _re\n"
        "_re.DockerExactTargetClient.restart = "
        "lambda *a, **k: fired.append('DockerExactTargetClient.restart')\n"
        "import shellforgeai.core.lab_restart as _lr\n"
        "_lr.run_post_restart_verification = "
        "lambda *a, **k: fired.append('lab_restart.run_post_restart_verification')"
    )
    assert _probe_import(patches, [CLI_MODULE, *_all_command_dotted()]) == []


def test_10_importing_does_not_call_model_or_codex() -> None:
    patches = (
        "import shellforgeai.llm.manager as _m\n"
        "_m.build_provider = lambda *a, **k: fired.append('build_provider')"
    )
    assert _probe_import(patches, [CLI_MODULE, *_all_command_dotted()]) == []


def test_11_importing_does_not_perform_network_calls() -> None:
    patches = (
        "import socket\n"
        "socket.create_connection = lambda *a, **k: fired.append('socket.create_connection')\n"
        "import httpx\n"
        "httpx.Client.send = lambda *a, **k: fired.append('httpx.Client.send')\n"
        "httpx.request = lambda *a, **k: fired.append('httpx.request')\n"
        "import urllib.request as _u\n"
        "_u.urlopen = lambda *a, **k: fired.append('urllib.request.urlopen')"
    )
    assert _probe_import(patches, [CLI_MODULE, *_all_command_dotted()]) == []


def test_12_importing_does_not_write_or_delete_artifacts() -> None:
    patches = (
        "import os, pathlib\n"
        "pathlib.Path.write_text = lambda *a, **k: fired.append('Path.write_text')\n"
        "pathlib.Path.write_bytes = lambda *a, **k: fired.append('Path.write_bytes')\n"
        "pathlib.Path.unlink = lambda *a, **k: fired.append('Path.unlink')\n"
        "os.remove = lambda *a, **k: fired.append('os.remove')\n"
        "os.unlink = lambda *a, **k: fired.append('os.unlink')"
    )
    assert _probe_import(patches, [CLI_MODULE, *_all_command_dotted()]) == []


# --------------------------------------------------------------------------
# 13–17: static guard
# --------------------------------------------------------------------------


def test_13_no_top_level_subprocess_execution() -> None:
    offenders: dict[str, list[str]] = {}
    for path in _command_module_paths():
        findings = static_scan_source(path.read_text(encoding="utf-8"))
        if findings["subprocess"]:
            offenders[path.name] = findings["subprocess"]
    assert offenders == {}


def test_14_no_top_level_shell_true_execution() -> None:
    offenders: dict[str, list[str]] = {}
    for path in _command_module_paths():
        findings = static_scan_source(path.read_text(encoding="utf-8"))
        if findings["shell_true"]:
            offenders[path.name] = findings["shell_true"]
    assert offenders == {}


def test_15_no_top_level_cleanup_remediation_rollback_recovery_calls() -> None:
    offenders: dict[str, list[str]] = {}
    for path in _command_module_paths():
        findings = static_scan_source(path.read_text(encoding="utf-8"))
        if findings["operational"]:
            offenders[path.name] = findings["operational"]
    assert offenders == {}


def test_16_no_top_level_model_invocation_calls() -> None:
    offenders: dict[str, list[str]] = {}
    for path in _command_module_paths():
        findings = static_scan_source(path.read_text(encoding="utf-8"))
        if findings["model"]:
            offenders[path.name] = findings["model"]
    assert offenders == {}


def test_17_static_checker_allows_harmless_help_text_and_strings() -> None:
    # Strings/help text that merely mention dangerous operations must not trip the
    # static checker; only real top-level Call nodes / shell=True keywords do.
    benign = (
        "from __future__ import annotations\n"
        "import typer\n"
        "HELP = 'runs subprocess.run and docker compose restart with shell=True'\n"
        "NOTE = 'remediation_execute and rollback_execute are governed handlers'\n"
        "def register(app: typer.Typer) -> None:\n"
        "    @app.command()\n"
        "    def demo(\n"
        "        x: str = typer.Option('', help='docker compose restart; subprocess.run')\n"
        "    ) -> None:\n"
        "        import subprocess\n"
        "        subprocess.run(['echo', 'ok'], shell=True)\n"
    )
    findings = static_scan_source(benign)
    assert findings["subprocess"] == []
    assert findings["shell_true"] == []
    assert findings["operational"] == []
    assert findings["model"] == []

    # Sanity: a real top-level offender IS detected, so the checker has teeth.
    offending = "import subprocess\nsubprocess.run(['docker', 'restart', 'x'], shell=True)\n"
    offending_findings = static_scan_source(offending)
    assert offending_findings["subprocess"]
    assert offending_findings["shell_true"]


# --------------------------------------------------------------------------
# 18–22: read-only audit helper script
# --------------------------------------------------------------------------


def test_18_audit_json_emits_strict_json() -> None:
    result = _run_audit_script("--json")
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip().startswith("{")
    assert result.stdout.strip().endswith("}")
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert payload["schema_version"] == 1
    assert payload["mode"] == "cli_import_audit"
    assert payload["status"] == "ok"


def test_19_audit_json_reports_read_only_and_non_mutating() -> None:
    result = _run_audit_script("--json")
    payload = json.loads(result.stdout)
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["mutation_performed"] is False
    assert payload["summary"]["side_effect_attempts"] == 0


def test_20_audit_json_reports_all_expected_modules() -> None:
    result = _run_audit_script("--json")
    payload = json.loads(result.stdout)
    reported = {m["module"] for m in payload["modules"]}
    for name in EXPECTED_COMMAND_MODULES:
        assert f"{COMMANDS_PACKAGE}.{name}" in reported, name
    assert CLI_MODULE in reported
    assert COMMANDS_PACKAGE in reported
    for module in payload["modules"]:
        assert module["status"] == "ok", module
        assert module["imported"] is True
        assert module["side_effects_detected"] == []


def test_21_audit_markdown_emits_non_empty_markdown() -> None:
    result = _run_audit_script("--markdown")
    assert result.returncode == 0
    text = result.stdout
    assert text.strip()
    assert "# ShellForgeAI CLI Import Side-Effect Audit" in text
    assert "shellforgeai.cli" in text
    assert "| Module | Status | Imported | Side effects detected |" in text


def test_22_audit_helper_does_not_execute_dangerous_primitives() -> None:
    # The helper source must not itself shell out, call Docker/Compose, or call a
    # model/network; it only installs recording stubs and imports modules. The
    # check is AST-based so prose/docstrings that merely mention these tokens are
    # not flagged.
    source = AUDIT_SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            qualifier = _call_qualifier(node)
            # The only subprocess/os names that may appear are the *patched*
            # attribute references (setattr targets), never executed calls.
            if qualifier == "subprocess":
                assert name not in _SUBPROCESS_EXEC_CALLS, name
            if qualifier == "os":
                assert name not in _OS_EXEC_CALLS, name
            for keyword in node.keywords:
                assert not (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ), "audit helper must not use shell=True"
    payload = json.loads(_run_audit_script("--json").stdout)
    safety = payload["safety"]
    assert safety["subprocess_executed"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["model_called"] is False
    assert safety["network_called"] is False


# --------------------------------------------------------------------------
# 23–25: command-surface / wiring-only / inventory regression
# --------------------------------------------------------------------------


def _run_pytest(target: str, *extra: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(SRC), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    return subprocess.run(  # noqa: S603 - test runs the local pytest guardrail suites.
        [sys.executable, "-m", "pytest", "-q", "-p", "no:xdist", target, *extra],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


def test_23_pr184_command_surface_golden_still_passes() -> None:
    target = "tests/test_pr184_cli_command_surface_golden.py"
    assert (REPO / target).exists()
    result = _run_pytest(target)
    assert result.returncode == 0, result.stdout + result.stderr


def test_24_pr204_wiring_only_enforcement_still_passes() -> None:
    target = "tests/test_pr204_cli_wiring_only_enforcement.py"
    assert (REPO / target).exists()
    result = _run_pytest(target)
    assert result.returncode == 0, result.stdout + result.stderr


def test_25_cli_refactor_inventory_tests_still_pass() -> None:
    target = "tests/test_pr198_cli_refactor_inventory.py"
    assert (REPO / target).exists()
    result = _run_pytest(target)
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------
# 26–40: safety invariants
# --------------------------------------------------------------------------


def _audit_payload_in_process() -> dict[str, Any]:
    return _load_audit_module().build_audit_payload()


def test_26_to_40_safety_block_asserts_no_execution_or_mutation() -> None:
    payload = json.loads(_run_audit_script("--json").stdout)
    safety = payload["safety"]
    expected_false = {
        "mutation_performed",  # (general mutation)
        "cleanup_executed",  # 26 no cleanup execute
        "remediation_executed",  # 27 no arbitrary remediation execute
        "rollback_executed",  # 28 no rollback execute
        "recovery_executed",  # 29 no recovery execute
        "docker_compose_executed",  # 30 no Docker/Compose mutation
        "container_restarted",  # 31 no Docker restart
        "production_restarted",  # 32 no production restart
        "shell_true",  # 33 no shell=True
        "arbitrary_command_execution",  # 34 no arbitrary command execution
        "natural_language_execution",  # 35 no natural-language execution
        "model_called",  # 36 no model call
        "artifact_repaired",  # 37a no artifact repair
        "artifact_deleted",  # 37b no artifact delete
        "network_called",  # 38 no network call
        "package_installed",  # 39 no package install
        "cloud_apply_merge_push",  # 40 no cloud apply/merge/push
        "subprocess_executed",
    }
    for key in expected_false:
        assert safety[key] is False, key
    assert safety["read_only"] is True
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False


def test_audit_helper_in_process_payload_matches_contract() -> None:
    # The helper's payload builder is importable and self-consistent (covers the
    # in-process path; the subprocess path is exercised by tests 18–22).
    payload = _audit_payload_in_process()
    assert payload["mode"] == "cli_import_audit"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert set(payload["safety"]) >= {
        "subprocess_executed",
        "docker_compose_executed",
        "container_restarted",
        "production_restarted",
        "cleanup_executed",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
        "shell_true",
        "arbitrary_command_execution",
        "natural_language_execution",
        "model_called",
        "network_called",
        "package_installed",
        "cloud_apply_merge_push",
        "artifact_repaired",
        "artifact_deleted",
    }


def test_discovered_modules_match_audit_helper_discovery() -> None:
    module = _load_audit_module()
    discovered = set(module.discover_command_modules())
    expected = {f"{COMMANDS_PACKAGE}.{name}" for name in EXPECTED_COMMAND_MODULES}
    assert expected <= discovered
