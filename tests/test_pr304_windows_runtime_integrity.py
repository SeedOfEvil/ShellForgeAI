import argparse
import ast
import importlib.util
import json
from pathlib import Path

import pytest

HELPER = Path("scripts/windows_runtime_integrity.py")
VALIDATOR = Path("scripts/windows_runtime_integrity_acceptance.py")
WRAPPER_TEXT = r"""@echo off
setlocal
set "SFAI_WRAPPER_DIR=%~dp0"
for %%I in ("%SFAI_WRAPPER_DIR%..") do set "SHELLFORGEAI_RUNTIME_ROOT=%%~fI"
set "SFAI_PYTHON=python"
if exist "%SHELLFORGEAI_RUNTIME_ROOT%\Python314\python.exe" ^
  set "SFAI_PYTHON=%SHELLFORGEAI_RUNTIME_ROOT%\Python314\python.exe"
"%SFAI_PYTHON%" -m shellforgeai %*
exit /b %ERRORLEVEL%
"""


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def args(**kw):
    base = dict(
        expected_source_root=None,
        runtime_root=None,
        wrapper_path=None,
        canonical_wrapper_path=None,
        entrypoint_path=None,
        profile="inspect",
        json=True,
        out_json=None,
    )
    base.update(kw)
    return argparse.Namespace(**base)


def runtime(tmp_path):
    root = tmp_path / "Runtime"
    (root / "config" / "profiles").mkdir(parents=True, exist_ok=True)
    (root / "config" / "profiles" / "inspect.yaml").write_text("name: inspect\n", encoding="utf-8")
    (root / "Python314" / "Scripts").mkdir(parents=True, exist_ok=True)
    (root / "Python314" / "python.exe").write_text("", encoding="utf-8")
    (root / "Python314" / "Scripts" / "shellforgeai.exe").write_text("", encoding="utf-8")
    (root / "bin").mkdir(exist_ok=True)
    return root


def patch_windows(monkeypatch, helper, site_roots=()):
    monkeypatch.setattr(helper.platform, "system", lambda: "Windows")
    monkeypatch.setattr(helper.platform, "release", lambda: "2025")
    monkeypatch.setattr(helper.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(helper.platform, "platform", lambda: "Windows-2025")
    monkeypatch.setattr(helper, "_site_roots", lambda: list(site_roots))


def packet_ok(tmp_path, monkeypatch):
    helper = load(HELPER)
    root = runtime(tmp_path)
    durable = root / "bin" / "sfai.cmd"
    canonical = tmp_path / "sfai.cmd"
    durable.write_text(WRAPPER_TEXT.replace("\n", "\r\n"), encoding="utf-8")
    canonical.write_text(WRAPPER_TEXT, encoding="utf-8")
    patch_windows(monkeypatch, helper)
    monkeypatch.setattr(helper.sys, "executable", str(root / "Python314" / "python.exe"))
    import shellforgeai

    src = Path(shellforgeai.__file__).parent.parent
    return helper.build_packet(
        args(
            expected_source_root=str(src),
            runtime_root=str(root),
            wrapper_path=str(durable),
            canonical_wrapper_path=str(canonical),
            entrypoint_path=str(root / "Python314" / "Scripts" / "shellforgeai.exe"),
        )
    )


def test_healthy_requested_contract_is_ok_and_deterministic(tmp_path, monkeypatch):
    p1 = packet_ok(tmp_path, monkeypatch)
    p2 = packet_ok(tmp_path, monkeypatch)
    assert p1["status"] == "ok"
    assert p1["wrapper"]["normalized_text_equal"] is True
    assert p1["embedded_python"]["exists"] is True
    assert p1["entrypoint"]["exists"] is True
    assert json.dumps(p1, sort_keys=True) == json.dumps(p2, sort_keys=True)


def test_expected_source_mismatch_blocks(tmp_path, monkeypatch):
    helper = load(HELPER)
    patch_windows(monkeypatch, helper)
    p = helper.build_packet(args(expected_source_root=str(tmp_path / "other")))
    assert p["status"] == "blocked"
    assert p["shellforgeai_import"]["expected_source_match"] is False
    assert any(
        c["id"] == "shellforgeai.expected_source" and c["status"] == "blocked" for c in p["checks"]
    )


def test_import_failure_blocks_without_traceback(tmp_path, monkeypatch):
    helper = load(HELPER)
    patch_windows(monkeypatch, helper)
    real = helper.importlib.import_module

    def fail(name):
        if name == "shellforgeai":
            raise ImportError("controlled failure")
        return real(name)

    monkeypatch.setattr(helper.importlib, "import_module", fail)
    p = helper.build_packet(args(expected_source_root=str(tmp_path)))
    assert p["status"] == "blocked"
    assert "Traceback" not in json.dumps(p)


def test_runtime_profile_resolution_valid_and_missing(tmp_path, monkeypatch):
    helper = load(HELPER)
    patch_windows(monkeypatch, helper)
    good = runtime(tmp_path)
    p = helper.build_packet(args(runtime_root=str(good)))
    assert p["runtime_context"]["resolved"] is True
    assert p["runtime_context"]["source"] == "explicit_config_path"
    bad = tmp_path / "missing_runtime"
    q = helper.build_packet(args(runtime_root=str(bad)))
    assert q["status"] == "blocked"
    assert any(
        c["id"] == "runtime.profile_context" and c["status"] == "blocked" for c in q["checks"]
    )


@pytest.mark.parametrize("marker", list(load(HELPER).MARKERS))
def test_missing_each_wrapper_marker_blocks(tmp_path, monkeypatch, marker):
    helper = load(HELPER)
    patch_windows(monkeypatch, helper)
    root = runtime(tmp_path)
    durable = root / "bin" / "sfai.cmd"
    canonical = tmp_path / "sfai.cmd"
    durable.write_text(WRAPPER_TEXT.replace(helper.MARKERS[marker], "MISSING"), encoding="utf-8")
    canonical.write_text(WRAPPER_TEXT, encoding="utf-8")
    p = helper.build_packet(args(wrapper_path=str(durable), canonical_wrapper_path=str(canonical)))
    assert p["status"] == "blocked"
    assert p["wrapper"]["semantic_markers"][marker] is False


def test_wrapper_missing_canonical_missing_and_command_drift_block(tmp_path, monkeypatch):
    helper = load(HELPER)
    patch_windows(monkeypatch, helper)
    root = runtime(tmp_path)
    durable = root / "bin" / "sfai.cmd"
    missing = helper.build_packet(args(wrapper_path=str(durable)))
    assert missing["status"] == "blocked"
    durable.write_text(WRAPPER_TEXT.replace("-m shellforgeai %*", "-m other %*"), encoding="utf-8")
    drift = helper.build_packet(
        args(wrapper_path=str(durable), canonical_wrapper_path=str(tmp_path / "no.cmd"))
    )
    assert drift["status"] == "blocked"
    assert drift["wrapper"]["sha256"]


def test_embedded_python_and_entrypoint_cases(tmp_path, monkeypatch):
    helper = load(HELPER)
    patch_windows(monkeypatch, helper)
    root = runtime(tmp_path)
    p = helper.build_packet(
        args(
            runtime_root=str(root),
            entrypoint_path=str(root / "Python314" / "Scripts" / "shellforgeai.exe"),
        )
    )
    assert p["embedded_python"]["exists"] is True
    assert p["entrypoint"]["under_embedded_scripts"] is True
    (root / "Python314" / "python.exe").unlink()
    q = helper.build_packet(args(runtime_root=str(root), entrypoint_path=str(root / "missing.exe")))
    assert q["status"] == "blocked"
    r = helper.build_packet(args())
    assert any(
        c["id"] == "entrypoint.exists" and c["status"] == "not_requested" for c in r["checks"]
    )


def test_invalid_distribution_residue_bounded_direct_child_attention(tmp_path, monkeypatch):
    helper = load(HELPER)
    site_root = tmp_path / "site"
    site_root.mkdir()
    for i in range(25):
        (site_root / f"~HellForgeAI-{i}.dist-info").mkdir()
    nested = site_root / "pkg"
    nested.mkdir()
    (nested / "~hellforgeai-hidden").mkdir()
    patch_windows(monkeypatch, helper, [site_root, tmp_path / "missing"])
    p = helper.build_packet(args())
    residue = p["invalid_distribution_residue"]
    assert p["status"] == "attention"
    assert residue["residue_count"] == 20
    assert residue["truncated"] is True
    assert all("~" in m["name"] for m in residue["matches"])


def test_status_precedence_unsupported_blocked_attention_ok(tmp_path, monkeypatch):
    helper = load(HELPER)
    monkeypatch.setattr(helper.platform, "system", lambda: "Linux")
    assert helper.build_packet(args())["status"] == "unsupported"
    assert packet_ok(tmp_path, monkeypatch)["status"] == "ok"
    helper = load(HELPER)
    patch_windows(monkeypatch, helper)
    assert helper.build_packet(args())["status"] == "attention"
    assert helper.build_packet(args(runtime_root=str(tmp_path / "bad")))["status"] == "blocked"


def test_validator_valid_and_invalid_artifacts(tmp_path, monkeypatch):
    validator = load(VALIDATOR)
    ok = packet_ok(tmp_path, monkeypatch)
    assert validator.validate(ok) == []
    for status in ("attention", "blocked", "unsupported"):
        p = json.loads(json.dumps(ok))
        p["status"] = status
        if status == "attention":
            p["checks"][1]["status"] = "attention"
        if status == "blocked":
            p["checks"][1]["status"] = "blocked"
        if status == "unsupported":
            p["platform"]["system"] = "linux"
            p["checks"][0]["status"] = "unsupported"
        p["summary"] = {
            s: [c["status"] for c in p["checks"]].count(s)
            for s in ("pass", "attention", "blocked", "not_requested", "unsupported")
        }
        assert validator.validate(p) == []
    bad = json.loads(json.dumps(ok))
    bad["schema_version"] = 2
    assert validator.validate(bad)
    bad = json.loads(json.dumps(ok))
    bad["mode"] = "wrong"
    assert validator.validate(bad)
    bad = json.loads(json.dumps(ok))
    bad["summary"]["pass"] = -1
    assert validator.validate(bad)
    bad = json.loads(json.dumps(ok))
    bad["safety"]["network_call"] = True
    assert validator.validate(bad)
    bad = json.loads(json.dumps(ok))
    bad["first_safe_command"] = ""
    assert validator.validate(bad)
    assert validator.validate(ok, "blocked")


def test_validator_multi_artifact_cwd_allowed_stable_mismatch_rejected(tmp_path, monkeypatch):
    validator = load(VALIDATOR)
    a = packet_ok(tmp_path, monkeypatch)
    b = json.loads(json.dumps(a))
    b["invocation"]["cwd"] = "C:/Windows/System32"
    assert validator.compare([a, b]) == []
    b["wrapper"]["sha256"] = "different"
    assert validator.compare([a, b])


def test_source_guardrails_and_positive_control():
    tree = ast.parse(
        HELPER.read_text(encoding="utf-8") + "\n" + VALIDATOR.read_text(encoding="utf-8")
    )
    banned_imports = {"subprocess", "socket", "requests", "urllib", "pip"}
    banned_attrs = {"walk", "remove", "unlink", "rename", "rmdir"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [a.name.split(".")[0] for a in getattr(node, "names", [])]
                if isinstance(node, ast.Import)
                else [(node.module or "").split(".")[0]]
            )
            assert not (set(names) & banned_imports)
        if isinstance(node, ast.Attribute):
            assert node.attr not in banned_attrs
        if isinstance(node, ast.keyword) and node.arg == "shell":
            assert node.value is not True
    injected = ast.parse("import subprocess\nos.system('x')\n")
    assert any(
        isinstance(n, ast.Import) and n.names[0].name == "subprocess" for n in ast.walk(injected)
    )
