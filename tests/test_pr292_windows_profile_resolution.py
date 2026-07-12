from shellforgeai.core.runtime_resolution import resolve_runtime_profile_context


def test_explicit_profile_root_precedes_wrapper_runtime(tmp_path, monkeypatch):
    explicit = tmp_path / "explicit"
    wrapper = tmp_path / "wrapper"
    for root, desc in ((explicit, "explicit"), (wrapper, "wrapper")):
        profiles = root / "config" / "profiles"
        profiles.mkdir(parents=True)
        (profiles / "inspect.yaml").write_text(
            f"name: inspect\ndescription: {desc}\nallow_risks: []\nask_risks: []\ndeny_risks: []\n",
            encoding="utf-8",
        )
    monkeypatch.setenv("SHELLFORGEAI_PROFILE_ROOT", str(explicit))
    monkeypatch.setenv("SHELLFORGEAI_RUNTIME_ROOT", str(wrapper))

    ctx = resolve_runtime_profile_context("inspect", tmp_path / "elsewhere")

    assert ctx.source == "SHELLFORGEAI_PROFILE_ROOT"
    assert ctx.profile_root == explicit


def test_packaged_profile_defaults_allow_non_workspace_cwd(tmp_path, monkeypatch):
    monkeypatch.delenv("SHELLFORGEAI_PROFILE_ROOT", raising=False)
    monkeypatch.delenv("SHELLFORGEAI_RUNTIME_ROOT", raising=False)

    ctx = resolve_runtime_profile_context("inspect", tmp_path / "System32")

    assert ctx.resolved is True
    assert ctx.source in {
        "installed_package_parent",
        "installed_package_grandparent",
        "installed_package_root",
        "package_defaults",
    }
