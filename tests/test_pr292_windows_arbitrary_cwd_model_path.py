from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app


def _write_runtime(root: Path) -> None:
    profiles = root / "config" / "profiles"
    profiles.mkdir(parents=True)
    (profiles / "inspect.yaml").write_text(
        "name: inspect\ndescription: runtime\nallow_risks: []\nask_risks: []\ndeny_risks: []\n",
        encoding="utf-8",
    )


def test_model_doctor_json_reports_wrapper_runtime_from_arbitrary_cwd(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    _write_runtime(runtime)
    cwd = tmp_path / "Windows" / "System32"
    cwd.mkdir(parents=True)
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("SHELLFORGEAI_RUNTIME_ROOT", str(runtime))
    monkeypatch.setenv("SHELLFORGEAI_CODEX_BINARY", str(tmp_path / "missing-codex"))

    result = CliRunner().invoke(app, ["model", "doctor", "--json"])

    assert result.exit_code == 0
    assert '"runtime_root_resolved":true' in result.stdout
    assert '"profile_context_resolved":true' in result.stdout
    assert '"runtime_context_source":"SHELLFORGEAI_RUNTIME_ROOT"' in result.stdout
    assert "Traceback" not in result.stdout


def test_missing_runtime_root_returns_bounded_cli_diagnostic(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SHELLFORGEAI_RUNTIME_ROOT", str(tmp_path / "missing"))

    result = CliRunner().invoke(app, ["--profile", "absent-profile", "model", "doctor", "--json"])

    assert result.exit_code == 2
    assert "profile context" in result.stdout
    assert "SHELLFORGEAI_RUNTIME_ROOT" in result.stdout
    assert "Traceback" not in result.stdout
    assert "CODEX_HOME" not in result.stdout
