import argparse
import importlib.util
import json
from pathlib import Path

PR304 = Path("scripts/windows_runtime_integrity.py")
HELPER = Path("scripts/windows_runtime_reconcile_preflight.py")
VALIDATOR = Path("scripts/windows_runtime_reconcile_acceptance.py")
WRAP = (
    "@echo off\n%~dp0\nSHELLFORGEAI_RUNTIME_ROOT\n"
    "Python314\\python.exe\n-m shellforgeai %*\n%ERRORLEVEL%\n"
)


def load(p):
    spec = importlib.util.spec_from_file_location(p.stem, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def win(monkeypatch, *mods):
    for m in mods:
        monkeypatch.setattr(m.platform, "system", lambda: "Windows")
        monkeypatch.setattr(m.platform, "release", lambda: "2025")
        monkeypatch.setattr(m.platform, "machine", lambda: "AMD64")
        monkeypatch.setattr(m.platform, "platform", lambda: "Windows-2025")


def pr304_packet(tmp_path, monkeypatch, residue=False):
    h = load(PR304)
    win(monkeypatch, h)
    monkeypatch.setattr(h, "_site_roots", lambda: [])
    root = tmp_path / "Runtime"
    (root / "config/profiles").mkdir(parents=True)
    (root / "config/profiles/inspect.yaml").write_text("old\n")
    (root / "bin").mkdir()
    (root / "bin/sfai.cmd").write_text(WRAP)
    (root / "Python314/Scripts").mkdir(parents=True)
    (root / "Python314/python.exe").write_text("")
    (root / "Python314/Scripts/shellforgeai.exe").write_text("")
    args = argparse.Namespace(
        expected_source_root=str(Path.cwd() / "src"),
        runtime_root=str(root),
        wrapper_path=str(root / "bin/sfai.cmd"),
        canonical_wrapper_path=str(root / "bin/sfai.cmd"),
        entrypoint_path=str(root / "Python314/Scripts/shellforgeai.exe"),
        profile="inspect",
        json=True,
        out_json=None,
    )
    p = h.build_packet(args)
    if residue:
        p["status"] = "attention"
        p["invalid_distribution_residue"]["residue_count"] = 1
        p["invalid_distribution_residue"]["matches"] = [{"name": "~hellforgeai-x"}]
        p["checks"][-1]["status"] = "attention"
        p["summary"] = {
            s: [c["status"] for c in p["checks"]].count(s)
            for s in ("pass", "attention", "blocked", "not_requested", "unsupported")
        }
    f = tmp_path / "pr304.json"
    f.write_text(json.dumps(p, sort_keys=True), encoding="utf-8")
    return f, root


def staged(tmp_path, profile="old\n", wrap=WRAP):
    s = tmp_path / "staged"
    (s / "config/profiles").mkdir(parents=True)
    (s / "config/profiles/inspect.yaml").write_text(profile)
    (s / "scripts/windows").mkdir(parents=True)
    (s / "scripts/windows/sfai.cmd").write_text(wrap)
    return s


def test_linux_unsupported_and_saved_validator(tmp_path):
    m = load(HELPER)
    v = load(VALIDATOR)
    src = staged(tmp_path)
    p = m.build_packet(["missing.json"], str(src), str(tmp_path / "rt"))
    assert p["status"] == "unsupported"
    assert p["safety"]["copy_executed"] is False
    out = tmp_path / "packet.json"
    out.write_text(json.dumps(p, sort_keys=True), encoding="utf-8")
    assert v.errs(p) == []


def test_ready_create_replace_no_change_and_deferred_residue(tmp_path, monkeypatch):
    m = load(HELPER)
    v = load(VALIDATOR)
    win(monkeypatch, m)
    art, root = pr304_packet(tmp_path, monkeypatch, residue=True)
    src = staged(tmp_path, profile="new\n", wrap=WRAP + "x")
    p = m.build_packet([str(art)], str(src), str(root))
    assert p["status"] == "ready"
    assert [o["operation"] for o in p["operations"]] == [
        "replace_required",
        "replace_required",
    ]
    assert p["warnings"]
    assert v.errs(p) == []
    (root / "config/profiles/inspect.yaml").unlink()
    p = m.build_packet([str(art)], str(src), str(root))
    assert p["operations"][0]["operation"] == "create_required"
    assert v.errs(p) == []
    (root / "config/profiles/inspect.yaml").write_text("new\n")
    (root / "bin/sfai.cmd").write_text(WRAP + "x")
    p = m.build_packet([str(art)], str(src), str(root))
    assert p["status"] == "no_change"
    assert v.errs(p) == []


def test_blocked_malformed_disagreement_symlink_overwrite_and_deterministic(
    tmp_path, monkeypatch
):
    m = load(HELPER)
    v = load(VALIDATOR)
    win(monkeypatch, m)
    art, root = pr304_packet(tmp_path, monkeypatch)
    src = staged(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("{bad")
    assert m.build_packet([str(bad)], str(src), str(root))["status"] == "blocked"
    b = json.loads(art.read_text())
    b["wrapper"]["sha256"] = "0" * 64
    art2 = tmp_path / "b.json"
    art2.write_text(json.dumps(b))
    assert (
        m.build_packet([str(art), str(art2)], str(src), str(root))["status"]
        == "blocked"
    )
    (src / "scripts/windows/sfai.cmd").unlink()
    (src / "scripts/windows/sfai.cmd").symlink_to(src / "config/profiles/inspect.yaml")
    p = m.build_packet([str(art)], str(src), str(root))
    assert p["status"] == "blocked"
    assert v.errs(p) == []
    p1 = m.build_packet([str(art)], str(staged(tmp_path / "x")), str(root))
    p2 = m.build_packet([str(art)], str(tmp_path / "x/staged"), str(root))
    assert json.dumps(p1, sort_keys=True) == json.dumps(p2, sort_keys=True)
    out = tmp_path / "out.json"
    out.write_text("{}")
    import pytest

    with pytest.raises(SystemExit):
        m.main(
            [
                str(art),
                "--staged-source-root",
                str(src),
                "--durable-runtime-root",
                str(root),
                "--out-json",
                str(out),
            ]
        )


def test_validator_rejects_contradictions(tmp_path, monkeypatch):
    m = load(HELPER)
    v = load(VALIDATOR)
    win(monkeypatch, m)
    art, root = pr304_packet(tmp_path, monkeypatch)
    src = staged(tmp_path)
    p = m.build_packet([str(art)], str(src), str(root))
    p["safety"]["copy_executed"] = True
    assert v.errs(p)
    p = m.build_packet([str(art)], str(src), str(root))
    p["status"] = "ready"
    assert v.errs(p)
