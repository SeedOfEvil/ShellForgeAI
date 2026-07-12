from shellforgeai.core.profiles import load_profile
from shellforgeai.core.runtime_resolution import resolve_runtime_profile_context


def test_runtime_context_uses_wrapper_runtime_root_from_arbitrary_cwd(tmp_path, monkeypatch):
    runtime = tmp_path / "Runtime"
    profiles = runtime / "config" / "profiles"
    profiles.mkdir(parents=True)
    (profiles / "inspect.yaml").write_text(
        "name: inspect\ndescription: wrapper\nallow_risks: []\nask_risks: []\ndeny_risks: []\n",
        encoding="utf-8",
    )
    system32 = tmp_path / "Windows" / "System32"
    system32.mkdir(parents=True)
    monkeypatch.setenv("SHELLFORGEAI_RUNTIME_ROOT", str(runtime))

    ctx = resolve_runtime_profile_context("inspect", system32)

    assert ctx.resolved is True
    assert ctx.runtime_root == runtime
    assert ctx.profile_root == runtime
    assert ctx.source == "SHELLFORGEAI_RUNTIME_ROOT"
    assert "current_working_directory" not in ctx.checked_sources
    assert load_profile("inspect", ctx.profile_root).description == "wrapper"


def test_runtime_context_falls_back_to_valid_workspace_cwd(tmp_path, monkeypatch):
    monkeypatch.delenv("SHELLFORGEAI_RUNTIME_ROOT", raising=False)
    monkeypatch.delenv("SHELLFORGEAI_PROFILE_ROOT", raising=False)
    profiles = tmp_path / "config" / "profiles"
    profiles.mkdir(parents=True)
    (profiles / "inspect.yaml").write_text(
        "name: inspect\ndescription: cwd\nallow_risks: []\nask_risks: []\ndeny_risks: []\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("SHELLFORGEAI_RUNTIME_ROOT", str(tmp_path))

    ctx = resolve_runtime_profile_context("inspect", tmp_path)

    assert ctx.resolved is True
    assert ctx.source == "SHELLFORGEAI_RUNTIME_ROOT"
    assert load_profile("inspect", ctx.profile_root).description == "cwd"


def test_missing_runtime_profile_reports_precise_sources(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLFORGEAI_RUNTIME_ROOT", str(tmp_path / "missing"))
    ctx = resolve_runtime_profile_context("does-not-exist", tmp_path / "empty")

    assert ctx.resolved is False
    assert ctx.error_class == "runtime_profile_not_resolved"
    assert "SHELLFORGEAI_RUNTIME_ROOT" in ctx.checked_sources
    assert "current_working_directory" in ctx.checked_sources
    assert "sfai.cmd" in (ctx.error_message or "")
