from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import (
    _interactive_mutation_refusal,
    _run_interactive_cli_dispatch,
)

runner = CliRunner()


def _scene(labels: dict[str, str] | None = None) -> dict:
    return {
        "containers": [
            {
                "name": "sfai-test",
                "state": "running",
                "status": "Up",
                "labels": labels
                if labels is not None
                else {
                    "shellforgeai.disposable": "true",
                    "shellforgeai.allow_restart": "true",
                },
            },
            {"name": "unlabeled", "state": "running", "status": "Up", "labels": {}},
            {
                "name": "no-disposable",
                "state": "running",
                "status": "Up",
                "labels": {"shellforgeai.allow_restart": "true"},
            },
            {
                "name": "no-allow",
                "state": "running",
                "status": "Up",
                "labels": {"shellforgeai.disposable": "true"},
            },
        ]
    }


def _patch_scene(monkeypatch, scene: dict | None = None) -> None:
    from shellforgeai.core import triage_ranking

    monkeypatch.setattr(triage_ranking, "collect_scene", lambda: scene or _scene())


def _invoke(args: list[str], tmp_path: Path | None = None):
    env = {"SHELLFORGEAI_DATA_DIR": str(tmp_path)} if tmp_path else None
    return runner.invoke(app, args, env=env)


def _json(
    args: list[str], monkeypatch, tmp_path: Path | None = None, scene: dict | None = None
) -> dict:
    _patch_scene(monkeypatch, scene)
    result = _invoke(args, tmp_path)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


# Command / JSON ----------------------------------------------------------------


def test_eligible_preflight_json_is_strict_read_only_exact_target(monkeypatch) -> None:
    payload = _json(
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-test",
            "--json",
        ],
        monkeypatch,
    )
    assert payload["schema_version"] == 1
    assert payload["mode"] == "v2_recipe_preflight"
    assert payload["status"] == "preflight_ready"
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["command_preview_only"] is True
    assert payload["command_executed"] is False
    assert payload["execution_available"] is False
    assert payload["exact_target_only"] is True
    assert payload["action_preview"]["argv"] == ["docker", "restart", "sfai-test"]
    assert payload["safety"]["container_restarted"] is False
    assert payload["safety"]["shell_true"] is False
    assert payload["safety"]["arbitrary_command_execution"] is False
    assert payload["safety"]["natural_language_execution"] is False
    assert payload["safety"]["cleanup_executed"] is False
    assert payload["safety"]["remediation_executed"] is False
    assert payload["safety"]["rollback_executed"] is False
    assert payload["safety"]["docker_compose_executed"] is False
    json.loads(json.dumps(payload))


def test_eligible_preflight_human_states_no_execution(monkeypatch) -> None:
    _patch_scene(monkeypatch)
    result = _invoke(
        ["recipes", "preflight", "--recipe", "docker.disposable_restart", "--target", "sfai-test"]
    )
    assert result.exit_code == 0, result.output
    assert "Recipe preflight: ready" in result.output
    assert "docker restart sfai-test" in result.output
    assert "No command was executed." in result.output
    assert "No container was restarted." in result.output


# Blocked targets ---------------------------------------------------------------


def test_blocked_targets_return_controlled_statuses(monkeypatch) -> None:
    cases = {
        "shellforgeai": "production target refused",
        "missing": "target not found",
        "unlabeled": "missing required label",
        "no-disposable": "shellforgeai.disposable=true",
        "no-allow": "shellforgeai.allow_restart=true",
        "*": "broad target refused",
        "all": "broad target refused",
        "docker-compose-down": "broad target refused",
    }
    for target, expected in cases.items():
        payload = _json(
            [
                "recipes",
                "preflight",
                "--recipe",
                "docker.disposable_restart",
                "--target",
                target,
                "--json",
            ],
            monkeypatch,
        )
        assert payload["status"] in {"blocked", "not_found"}
        assert payload["command_executed"] is False
        assert payload["safety"]["container_restarted"] is False
        assert any(expected in blocker for blocker in payload["blockers"]), payload


# Save / validate ---------------------------------------------------------------


def test_save_writes_owned_artifact_and_validate_by_id_and_path(
    monkeypatch, tmp_path: Path
) -> None:
    saved = _json(
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-test",
            "--save",
            "--json",
        ],
        monkeypatch,
        tmp_path,
    )
    assert saved["artifact_written"] is True
    artifact_dir = Path(saved["preflight_path"])
    assert tmp_path in artifact_dir.parents
    assert (artifact_dir / "recipe-preflight.json").exists()
    assert (artifact_dir / "recipe-preflight.md").exists()
    assert (artifact_dir / "manifest.json").exists()
    assert saved["safety"]["mutation_performed"] is False
    assert saved["safety"]["container_restarted"] is False

    by_id = _invoke(["recipes", "preflight", "validate", saved["preflight_id"], "--json"], tmp_path)
    assert by_id.exit_code == 0, by_id.output
    assert json.loads(by_id.output)["status"] == "ok"

    by_path = _invoke(["recipes", "preflight", "validate", str(artifact_dir), "--json"], tmp_path)
    assert by_path.exit_code == 0, by_path.output
    assert json.loads(by_path.output)["checks"]["secrets"] is True


def test_validate_invalid_malformed_and_checksum_mismatch_fail_cleanly(
    monkeypatch, tmp_path: Path
) -> None:
    missing = _invoke(["recipes", "preflight", "validate", "does-not-exist", "--json"], tmp_path)
    assert missing.exit_code != 0
    assert "Traceback" not in missing.output
    assert json.loads(missing.output)["status"] == "not_found"

    bad_dir = tmp_path / "recipe_preflights" / "bad"
    bad_dir.mkdir(parents=True)
    (bad_dir / "recipe-preflight.json").write_text("{bad", encoding="utf-8")
    (bad_dir / "recipe-preflight.md").write_text("bad", encoding="utf-8")
    (bad_dir / "manifest.json").write_text("{}", encoding="utf-8")
    malformed = _invoke(["recipes", "preflight", "validate", "bad", "--json"], tmp_path)
    assert malformed.exit_code != 0
    assert "Traceback" not in malformed.output
    assert json.loads(malformed.output)["status"] == "failed"

    saved = _json(
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-test",
            "--save",
            "--json",
        ],
        monkeypatch,
        tmp_path,
    )
    artifact_dir = Path(saved["preflight_path"])
    (artifact_dir / "recipe-preflight.md").write_text("tampered", encoding="utf-8")
    tampered = _invoke(
        ["recipes", "preflight", "validate", saved["preflight_id"], "--json"], tmp_path
    )
    assert tampered.exit_code != 0
    assert "Traceback" not in tampered.output
    payload = json.loads(tampered.output)
    assert payload["status"] == "failed"
    assert payload["checks"]["checksums"] is False


# Ask routing -------------------------------------------------------------------


def test_ask_preflight_and_eligibility_phrases_route_without_model(monkeypatch) -> None:
    _patch_scene(monkeypatch)
    for prompt in (
        "preflight docker restart for sfai-test",
        "what gates are needed to restart this?",
        "is sfai-test eligible for disposable restart?",
    ):
        result = _invoke(["ask", prompt])
        assert result.exit_code == 0, result.output
        assert "deterministic ask routing" in result.output
        assert "No action was taken." in result.output


def test_ask_mutation_and_mixed_preflight_refuse_execution(monkeypatch) -> None:
    _patch_scene(monkeypatch)
    for prompt in ("execute the restart recipe", "run docker restart", "confirm restart"):
        result = _invoke(["ask", prompt])
        assert result.exit_code == 0, result.output
        assert "Refused" in result.output
        assert "No container was restarted." in result.output
    mixed = _invoke(["ask", "preflight restart and then do it"])
    assert mixed.exit_code == 0, mixed.output
    assert "Read-only recipe preflight" in mixed.output
    assert "Refused mutation portion" in mixed.output
    assert "No action was taken." in mixed.output


# Interactive -------------------------------------------------------------------


def test_interactive_routes_preflight_commands_and_refuses_execute(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_scene(monkeypatch)
    routed = route_input(
        "recipes preflight --recipe docker.disposable_restart --target sfai-test --json"
    )
    assert routed.name == "cli_dispatch"
    out = _run_interactive_cli_dispatch(Console(file=None), routed.argv)
    assert json.loads(out)["mode"] == "v2_recipe_preflight"

    saved = _json(
        [
            "recipes",
            "preflight",
            "--recipe",
            "docker.disposable_restart",
            "--target",
            "sfai-test",
            "--save",
            "--json",
        ],
        monkeypatch,
        tmp_path,
    )
    validate = route_input(f"recipes preflight validate {saved['preflight_id']} --json")
    assert validate.name == "cli_dispatch"

    refused = route_input("execute the recipe")
    assert refused.name == "mutation_refused"
    assert "No command was executed" in _interactive_mutation_refusal(refused.args)


# Regression / surfaces ---------------------------------------------------------


def test_registry_and_v2_surfaces_still_return_read_only(monkeypatch) -> None:
    _patch_scene(monkeypatch)
    for args in (
        ["recipes", "--json"],
        ["propose", "--json"],
        ["apply-preview", "--json"],
        ["verify", "--json"],
        ["handoff", "--json"],
    ):
        result = _invoke(list(args))
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload.get("read_only") is True
        assert payload.get("mutation_performed") is False
