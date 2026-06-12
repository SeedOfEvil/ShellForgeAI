"""PR194 confirm-gated receipt recovery-execute command-module extraction.

These tests prove ``recipes receipt recovery-execute`` is registered from
``shellforgeai.commands.receipt_recovery_execute`` while ``cli.py`` stays root
Typer wiring. The extraction is behavior-preserving: the command surface,
explicit ``--confirm`` requirement, exact-target disposable/allowlist/
production gates, blocked-case JSON safety contract, recovery receipt writing,
verification recording, exit codes, and the read-only recovery-status/
recovery-validate companions are unchanged. No new execution or mutation
behavior is introduced.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai import cli as cli_mod
from shellforgeai.cli import app
from shellforgeai.core import recipe_receipt_recovery
from shellforgeai.core.recipe_execution import (
    CommandResult,
    DockerContainerState,
    execute_disposable_restart,
    validate_receipt,
)
from shellforgeai.core.recipe_preflight import build_preflight_packet, save_preflight_packet

runner = CliRunner()

MODULE_PATH = Path("src/shellforgeai/commands/receipt_recovery_execute.py")
CLI_PATH = Path("src/shellforgeai/cli.py")
GOLDEN_PATH = Path("tests/golden/cli_command_surface_pr184.json")

BLOCKED_FALSE_FLAGS = (
    "mutation_performed",
    "recovery_executed",
    "container_restarted",
    "production_restart_executed",
    "docker_compose_executed",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "model_called",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
    "command_executed",
)
SUCCESS_TRUE_FLAGS = ("mutation_performed", "recovery_executed", "container_restarted")
SUCCESS_FALSE_FLAGS = (
    "production_restart_executed",
    "docker_compose_executed",
    "shell_true",
    "arbitrary_command_execution",
    "natural_language_execution",
    "model_called",
    "cleanup_executed",
    "remediation_executed",
    "rollback_executed",
)


class FakeDocker:
    def __init__(
        self,
        *,
        labels: dict[str, str] | None = None,
        before_started: str = "2026-06-12T00:00:00Z",
        after_started: str = "2026-06-12T00:00:05Z",
        return_code: int = 0,
        found: bool = True,
        name: str | None = None,
    ) -> None:
        self.labels = labels or {
            "shellforgeai.disposable": "true",
            "shellforgeai.allow_restart": "true",
        }
        self.before_started = before_started
        self.after_started = after_started
        self.return_code = return_code
        self.found = found
        self.name = name
        self.restart_calls: list[list[str]] = []
        self.inspect_calls = 0

    def inspect(self, target: str) -> DockerContainerState:
        self.inspect_calls += 1
        after = self.inspect_calls > 1
        return DockerContainerState(
            found=self.found,
            name=self.name or target,
            container_id="abc123",
            started_at=self.after_started if after else self.before_started,
            labels=dict(self.labels),
        )

    def restart(self, target: str) -> CommandResult:
        argv = ["docker", "restart", target]
        self.restart_calls.append(argv)
        return CommandResult(
            argv=argv,
            return_code=self.return_code,
            stdout=f"{target}\n",
            stderr="boom" if self.return_code else "",
        )


def _receipt(data_dir: Path, target: str = "sfai-pr194-user-sim") -> dict:
    scene = {
        "containers": [
            {
                "name": target,
                "labels": {"shellforgeai.disposable": "true", "shellforgeai.allow_restart": "true"},
                "state": "running",
            }
        ]
    }
    packet = build_preflight_packet("docker.disposable_restart", target, scene=scene)
    saved = save_preflight_packet(packet, data_dir)
    result = execute_disposable_restart(
        saved["preflight_id"], data_dir, confirm=True, docker=FakeDocker()
    )
    assert result["status"] == "executed"
    return result


def _rewrite_receipt(receipt: dict, mutate) -> None:  # noqa: ANN001
    d = Path(receipt["receipt"]["path"])
    p = d / "recipe-receipt.json"
    payload = json.loads(p.read_text(encoding="utf-8"))
    mutate(payload)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    manifest["recipe_id"] = payload.get("recipe_id")
    manifest["target"] = payload.get("target")
    manifest["checksums"]["recipe-receipt.json"] = hashlib.sha256(p.read_bytes()).hexdigest()
    (d / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(root: Path) -> list[tuple[str, str | None]]:
    return [
        (str(p.relative_to(root)), _sha(p) if p.is_file() else None)
        for p in sorted(root.rglob("*"))
    ]


def _patch_docker(monkeypatch, fake: FakeDocker) -> FakeDocker:
    monkeypatch.setattr(recipe_receipt_recovery, "DockerExactTargetClient", lambda: fake)
    return fake


def _forbid_model_and_subprocess(monkeypatch) -> None:
    def fail_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError(f"recovery-execute must not run subprocesses in tests: {cmd!r}")

    def fail_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("recovery-execute must never build or call a model provider")

    monkeypatch.setattr(cli_mod.subprocess, "run", fail_run)
    monkeypatch.setattr(cli_mod, "build_provider", fail_provider)


def _invoke(args: list[str], monkeypatch, tmp_path: Path, *, expect_code: int = 0):
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, args)
    assert result.exit_code == expect_code, result.output
    assert "Traceback" not in (result.stdout + (result.stderr or ""))
    return result


def _invoke_json(args: list[str], monkeypatch, tmp_path: Path, *, expect_code: int = 0) -> dict:
    result = _invoke(args, monkeypatch, tmp_path, expect_code=expect_code)
    stdout = result.stdout.strip()
    assert stdout.startswith("{"), result.stdout
    assert stdout.endswith("}"), result.stdout
    return json.loads(stdout)


def _assert_blocked_payload(payload: dict) -> None:
    assert payload["status"] != "executed"
    assert payload["confirm_required"] is True
    safety = payload.get("safety") if isinstance(payload.get("safety"), dict) else {}
    for flag in BLOCKED_FALSE_FLAGS:
        if flag in payload:
            assert payload[flag] is False, flag
        if flag in safety:
            assert safety[flag] is False, flag
    action = payload.get("action") if isinstance(payload.get("action"), dict) else {}
    assert action.get("docker_restart_attempted") is False
    assert action.get("docker_restart_succeeded") is False
    assert payload.get("recovery_receipt_id") is None


# ---------------------------------------------------------------------------
# Module split / registration
# ---------------------------------------------------------------------------


def test_recovery_execute_module_owns_command_wiring() -> None:
    assert MODULE_PATH.exists()
    module_source = MODULE_PATH.read_text(encoding="utf-8")
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    assert "def register(" in module_source
    assert '@recipes_receipt_app.command("recovery-execute")' in module_source
    assert "execute_receipt_recovery(" in module_source
    assert '"--confirm"' in module_source
    assert (
        "from shellforgeai.commands import receipt_recovery_execute as "
        "receipt_recovery_execute_commands"
    ) in cli_source
    assert "receipt_recovery_execute_commands.register(recipes_receipt_app)" in cli_source


def test_cli_no_longer_owns_recovery_execute_implementation_body() -> None:
    cli_source = CLI_PATH.read_text(encoding="utf-8")
    tree = ast.parse(cli_source)
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "recipes_receipt_recovery_execute" not in function_names
    assert "_render_receipt_recovery_execute_human" not in function_names
    assert "execute_receipt_recovery" not in cli_source
    assert '@recipes_receipt_app.command("recovery-execute")' not in cli_source


def test_recovery_execute_help_surface_preserved(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    receipt_help = runner.invoke(app, ["recipes", "receipt", "--help"])
    assert receipt_help.exit_code == 0
    for command in ("recovery-execute", "recovery-status", "recovery-validate"):
        assert command in receipt_help.stdout

    result = runner.invoke(app, ["recipes", "receipt", "recovery-execute", "--help"])
    assert result.exit_code == 0, result.output
    assert "RECEIPT_REF" in result.stdout
    assert "--confirm" in result.stdout
    assert "--json" in result.stdout
    assert "Not true rollback" in " ".join(result.stdout.split())


# ---------------------------------------------------------------------------
# Blocked behavior preservation
# ---------------------------------------------------------------------------


def test_no_confirm_blocks_without_restart_or_receipt(monkeypatch, tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    fake = _patch_docker(monkeypatch, FakeDocker())
    _forbid_model_and_subprocess(monkeypatch)
    before = _tree(tmp_path)

    human = _invoke(
        ["recipes", "receipt", "recovery-execute", receipt["receipt_id"]],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert "Recovery execution: blocked" in human.stdout
    assert "No container was restarted." in human.stdout

    payload = _invoke_json(
        ["recipes", "receipt", "recovery-execute", receipt["receipt_id"], "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert payload["status"] == "blocked"
    assert payload["reason"] == "explicit --confirm required"
    assert payload["confirm_provided"] is False
    _assert_blocked_payload(payload)
    assert fake.restart_calls == []
    assert _tree(tmp_path) == before, "no-confirm must not restart or write receipts"


def test_missing_malformed_and_unsupported_receipts_block_cleanly(
    monkeypatch, tmp_path: Path
) -> None:
    fake = _patch_docker(monkeypatch, FakeDocker())
    _forbid_model_and_subprocess(monkeypatch)

    missing = _invoke_json(
        ["recipes", "receipt", "recovery-execute", "missing", "--confirm", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert missing["status"] == "not_found"
    _assert_blocked_payload(missing)

    bad = tmp_path / "recipe_receipts" / "bad"
    bad.mkdir(parents=True)
    (bad / "recipe-receipt.json").write_text("{bad", encoding="utf-8")
    malformed = _invoke_json(
        ["recipes", "receipt", "recovery-execute", "bad", "--confirm", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert malformed["status"] == "failed"
    _assert_blocked_payload(malformed)

    receipt = _receipt(tmp_path)
    _rewrite_receipt(receipt, lambda p: p.update({"recipe_id": "other.recipe"}))
    unsupported = _invoke_json(
        ["recipes", "receipt", "recovery-execute", receipt["receipt_id"], "--confirm", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert unsupported["status"] == "unsupported_recipe"
    _assert_blocked_payload(unsupported)
    assert fake.restart_calls == []


def test_production_missing_label_drift_and_broad_targets_block(
    monkeypatch, tmp_path: Path
) -> None:
    receipt = _receipt(tmp_path)
    cases = {
        "production target refused": FakeDocker(name="shellforgeai"),
        "target not found": FakeDocker(found=False),
        "current target labels no longer satisfy gates (no disposable)": FakeDocker(
            labels={"shellforgeai.allow_restart": "true"}
        ),
        "current target labels no longer satisfy gates (no allow_restart)": FakeDocker(
            labels={"shellforgeai.disposable": "true"}
        ),
    }
    for label, fake in cases.items():
        _patch_docker(monkeypatch, fake)
        _forbid_model_and_subprocess(monkeypatch)
        before = _tree(tmp_path)
        payload = _invoke_json(
            [
                "recipes",
                "receipt",
                "recovery-execute",
                receipt["receipt_id"],
                "--confirm",
                "--json",
            ],
            monkeypatch,
            tmp_path,
            expect_code=1,
        )
        assert payload["status"] == "blocked", label
        assert payload["reason"] in (
            "production target refused",
            "target not found",
            "current target labels no longer satisfy gates",
        ), label
        _assert_blocked_payload(payload)
        assert fake.restart_calls == [], label
        assert _tree(tmp_path) == before, f"{label}: blocked case must not write receipts"

    broad = _receipt(tmp_path, target="sfai-pr194-broad-sim")
    _rewrite_receipt(broad, lambda p: p.update({"target": "all"}))
    fake = _patch_docker(monkeypatch, FakeDocker())
    before = _tree(tmp_path)
    payload = _invoke_json(
        ["recipes", "receipt", "recovery-execute", broad["receipt_id"], "--confirm", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert payload["reason"] == "broad or invalid target refused"
    _assert_blocked_payload(payload)
    assert fake.restart_calls == []
    assert _tree(tmp_path) == before


def test_failed_docker_restart_is_controlled_and_never_successful(
    monkeypatch, tmp_path: Path
) -> None:
    receipt = _receipt(tmp_path)
    fake = _patch_docker(monkeypatch, FakeDocker(return_code=1))
    _forbid_model_and_subprocess(monkeypatch)
    payload = _invoke_json(
        ["recipes", "receipt", "recovery-execute", receipt["receipt_id"], "--confirm", "--json"],
        monkeypatch,
        tmp_path,
        expect_code=1,
    )
    assert payload["status"] == "failed"
    assert payload["action"]["docker_restart_attempted"] is True
    assert payload["action"]["docker_restart_succeeded"] is False
    assert payload["safety"]["container_restarted"] is False
    assert payload["safety"]["mutation_performed"] is False
    assert payload["safety"]["recovery_executed"] is False
    # Existing behavior: a controlled *failed* recovery receipt is recorded.
    rid = payload["recovery_receipt_id"]
    recorded = json.loads(
        (tmp_path / "recipe_receipts" / rid / "recipe-receipt.json").read_text(encoding="utf-8")
    )
    assert recorded["status"] == "failed"
    assert recorded["safety"]["recovery_executed"] is False
    assert fake.restart_calls == [["docker", "restart", "sfai-pr194-user-sim"]]


# ---------------------------------------------------------------------------
# Successful confirmed disposable recovery
# ---------------------------------------------------------------------------


def test_confirmed_disposable_recovery_executes_exact_argv_and_writes_receipt(
    monkeypatch, tmp_path: Path
) -> None:
    receipt = _receipt(tmp_path)
    fake = _patch_docker(
        monkeypatch,
        FakeDocker(before_started="2026-06-12T00:10:00Z", after_started="2026-06-12T00:10:05Z"),
    )
    _forbid_model_and_subprocess(monkeypatch)
    payload = _invoke_json(
        ["recipes", "receipt", "recovery-execute", receipt["receipt_id"], "--confirm", "--json"],
        monkeypatch,
        tmp_path,
    )
    assert payload["mode"] == "v2_receipt_recovery_execute"
    assert payload["status"] == "executed"
    assert fake.restart_calls == [["docker", "restart", "sfai-pr194-user-sim"]]
    assert payload["action"]["argv"] == ["docker", "restart", "sfai-pr194-user-sim"]
    assert payload["action"]["docker_restart_attempted"] is True
    assert payload["action"]["docker_restart_succeeded"] is True
    assert payload["verification"]["started_at_changed"] is True
    for flag in SUCCESS_TRUE_FLAGS:
        assert payload["safety"][flag] is True, flag
    for flag in SUCCESS_FALSE_FLAGS:
        assert payload["safety"][flag] is False, flag
    assert payload["action"]["docker_compose_executed"] is False
    assert payload["action"]["shell_true"] is False

    rid = payload["recovery_receipt_id"]
    assert (tmp_path / "recipe_receipts" / rid / "receipt.json").exists()
    assert validate_receipt(rid, tmp_path)["status"] == "ok"


def test_confirmed_recovery_human_output_preserved(monkeypatch, tmp_path: Path) -> None:
    receipt = _receipt(tmp_path)
    _patch_docker(
        monkeypatch,
        FakeDocker(before_started="2026-06-12T00:20:00Z", after_started="2026-06-12T00:20:05Z"),
    )
    _forbid_model_and_subprocess(monkeypatch)
    result = _invoke(
        ["recipes", "receipt", "recovery-execute", receipt["receipt_id"], "--confirm"],
        monkeypatch,
        tmp_path,
    )
    assert "Recovery execution: completed" in result.stdout
    assert "docker restart sfai-pr194-user-sim" in result.stdout
    assert "Explicit --confirm was required." in result.stdout
    assert "No Docker Compose command was executed." in result.stdout
    assert "not true rollback" in result.stdout


def test_recovery_receipt_supports_readonly_verify_status_and_validate(
    monkeypatch, tmp_path: Path
) -> None:
    receipt = _receipt(tmp_path)
    _patch_docker(
        monkeypatch,
        FakeDocker(before_started="2026-06-12T00:30:00Z", after_started="2026-06-12T00:30:05Z"),
    )
    payload = _invoke_json(
        ["recipes", "receipt", "recovery-execute", receipt["receipt_id"], "--confirm", "--json"],
        monkeypatch,
        tmp_path,
    )
    rid = payload["recovery_receipt_id"]
    before = _tree(tmp_path)
    _forbid_model_and_subprocess(monkeypatch)

    verify = _invoke_json(["verify", "--receipt", rid, "--json"], monkeypatch, tmp_path)
    assert verify["status"] == "passed"
    assert verify["safety"]["container_restarted_by_verify"] is False

    status = _invoke_json(
        ["recipes", "receipt", "recovery-status", rid, "--json"], monkeypatch, tmp_path
    )
    assert status["status"] == "passed"
    assert status["safety"]["mutation_performed"] is False

    validate = _invoke_json(
        ["recipes", "receipt", "recovery-validate", rid, "--json"], monkeypatch, tmp_path
    )
    assert validate["status"] == "ok"
    assert validate["read_only"] is True
    assert validate["mutation_performed"] is False
    assert _tree(tmp_path) == before, "read-only companions must not mutate artifacts"


# ---------------------------------------------------------------------------
# Execution boundary / static safety
# ---------------------------------------------------------------------------


def test_recovery_execute_module_has_no_forbidden_execution_surfaces() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    forbidden = (
        "subprocess",
        "build_provider",
        "shell=True",
        "os.system",
        "docker compose",
        "execute_disposable_restart",
        "preview_receipt_rollback",
        "remediate",
        "cleanup_execute",
        "artifact_repaired = True",
        "artifact_deleted = True",
    )
    for token in forbidden:
        assert token not in source, token


def test_pr184_golden_guardrail_still_covers_recovery_execute() -> None:
    fixture = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    commands = {entry["name"]: entry for entry in fixture["commands"]}
    for name in (
        "recipes_receipt_recovery_execute_help",
        "recipes_receipt_recovery_status_help",
        "recipes_receipt_recovery_validate_help",
    ):
        assert name in commands
    execute_help = commands["recipes_receipt_recovery_execute_help"]
    assert "--confirm" in execute_help["required_substrings"]
    assert execute_help.get("governed_execution") is True
