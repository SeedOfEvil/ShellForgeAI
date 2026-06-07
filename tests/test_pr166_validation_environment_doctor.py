"""PR166 — read-only validation environment doctor/preflight."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_validation_env.py"
VALIDATE_PR_PATH = REPO_ROOT / "scripts" / "validate_pr.py"


def load_doctor():
    spec = importlib.util.spec_from_file_location("pr166_check_validation_env", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["pr166_check_validation_env"] = module
    spec.loader.exec_module(module)
    return module


def load_validate_pr():
    spec = importlib.util.spec_from_file_location("pr166_validate_pr", VALIDATE_PR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["pr166_validate_pr"] = module
    spec.loader.exec_module(module)
    return module


def force_clean_environment(monkeypatch, doctor, *, xdist: bool = True) -> None:
    monkeypatch.setattr(
        doctor,
        "check_python",
        lambda: doctor._check(
            "ok",
            required=True,
            path="/py",
            version="3.12.1",
            python3_path="/py3",
            usr_bin_python3_exists=True,
            warnings=[],
        ),
    )
    monkeypatch.setattr(
        doctor,
        "check_shellforgeai_import",
        lambda: doctor._check("ok", required=True, available=True),
    )
    monkeypatch.setattr(
        doctor,
        "check_import",
        lambda module, required=True: doctor._check("ok", required=required, available=True),
    )
    monkeypatch.setattr(
        doctor, "check_compileall", lambda: doctor._check("ok", required=True, available=True)
    )
    monkeypatch.setattr(
        doctor,
        "check_package_metadata",
        lambda: doctor._check("ok", required=False, available=True, version="0.0"),
    )
    monkeypatch.setattr(
        doctor,
        "check_tool",
        lambda name, required=True, label=None: doctor._check(
            "ok", required=required, available=True, path=f"/usr/bin/{name}", label=label or name
        ),
    )
    monkeypatch.setattr(
        doctor, "check_helpers", lambda: doctor._check("ok", required=True, missing=[], files={})
    )
    monkeypatch.setattr(
        doctor,
        "check_xdist",
        lambda *, strict, profile: doctor._check(
            "ok" if xdist else ("failed" if strict and profile == "docker01" else "warn"),
            required=strict and profile == "docker01" and not xdist,
            available=xdist,
            detail="pytest-xdist available"
            if xdist
            else "serial full pytest fallback will be used",
        ),
    )
    monkeypatch.setattr(
        doctor,
        "check_hygiene",
        lambda: {
            "source_tree_writable": True,
            "root_owned_pycache_count": 0,
            "root_owned_pycache_paths": [],
            "cache_counts": {"__pycache__": 0, ".pytest_cache": 0, ".ruff_cache": 0},
            "warnings": [],
        },
    )


def test_env_doctor_human_output_works(monkeypatch, capsys):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor)

    rc = doctor.main(["--profile", "local"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "ShellForgeAI validation environment doctor" in out
    assert "Required:" in out
    assert "Optional:" in out
    assert "Hygiene:" in out
    assert "Result: ok" in out


def test_json_emits_strict_json_with_profile_safety_and_xdist(monkeypatch, capsys):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor, xdist=False)

    rc = doctor.main(["--json", "--profile", "local"])

    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert rc == 0
    assert out.lstrip().startswith("{")
    assert parsed["profile"] == "local"
    assert parsed["safety"]["read_only"] is True
    assert parsed["safety"]["mutation_performed"] is False
    assert parsed["safety"]["docker_daemon_contacted"] is False
    assert parsed["checks"]["xdist"]["available"] is False


def test_required_checks_passing_returns_status_ok(monkeypatch):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor)

    result = doctor.run_doctor(profile="local")

    assert result["status"] == "ok"
    assert result["required_passed"] is True


def test_missing_pytest_returns_failed(monkeypatch):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor)

    def fake_import(module: str, required: bool = True):
        if module == "pytest":
            return doctor._check("failed", required=True, available=False)
        return doctor._check("ok", required=required, available=True)

    monkeypatch.setattr(doctor, "check_import", fake_import)

    result = doctor.run_doctor(profile="local")

    assert result["status"] == "failed"
    assert result["checks"]["pytest"]["status"] == "failed"
    assert any("pytest" in rec for rec in result["recommendations"])


def test_missing_ruff_is_required_and_returns_failed(monkeypatch):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor)

    def fake_import(module: str, required: bool = True):
        if module == "ruff":
            return doctor._check("failed", required=True, available=False)
        return doctor._check("ok", required=required, available=True)

    monkeypatch.setattr(doctor, "check_import", fake_import)

    result = doctor.run_doctor(profile="local")

    assert result["status"] == "failed"
    assert result["checks"]["ruff"]["status"] == "failed"


def test_missing_xdist_warns_by_default_and_fails_in_strict_docker01(monkeypatch):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor, xdist=False)

    default = doctor.run_doctor(profile="docker01")
    strict = doctor.run_doctor(profile="docker01", strict=True)

    assert default["status"] == "warn"
    assert default["required_passed"] is True
    assert default["checks"]["xdist"]["status"] == "warn"
    assert strict["status"] == "failed"
    assert strict["checks"]["xdist"]["status"] == "failed"


def test_missing_usr_bin_python3_warns_not_fails(monkeypatch):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor)
    monkeypatch.setattr(
        doctor,
        "check_python",
        lambda: doctor._check(
            "ok",
            required=True,
            path="/usr/local/bin/python",
            version="3.12.1",
            python3_path="/usr/local/bin/python3",
            usr_bin_python3_exists=False,
            warnings=["/usr/bin/python3 is missing; not required unless tests hardcode it"],
        ),
    )

    result = doctor.run_doctor(profile="local")

    assert result["required_passed"] is True
    assert result["status"] == "ok"
    assert result["checks"]["python"]["usr_bin_python3_exists"] is False
    assert any("/usr/bin/python3" in rec for rec in result["recommendations"])


def test_missing_ps_procps_is_required_for_docker01_profile(monkeypatch):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor)

    def fake_tool(name: str, required: bool = True, label: str | None = None):
        if name == "ps":
            return doctor._check(
                "failed", required=True, available=False, path=None, label=label or name
            )
        return doctor._check(
            "ok", required=required, available=True, path=f"/usr/bin/{name}", label=label or name
        )

    monkeypatch.setattr(doctor, "check_tool", fake_tool)

    result = doctor.run_doctor(profile="docker01")

    assert result["status"] == "failed"
    assert result["checks"]["procps"]["status"] == "failed"
    assert any("procps" in rec for rec in result["recommendations"])


def test_root_owned_pycache_detection_reports_without_deleting(monkeypatch, tmp_path):
    doctor = load_doctor()
    repo = tmp_path / "repo"
    pycache = repo / "src" / "pkg" / "__pycache__"
    pycache.mkdir(parents=True)
    marker = pycache / "kept.pyc"
    marker.write_bytes(b"cache")
    (repo / "tests").mkdir()
    (repo / "scripts").mkdir()
    monkeypatch.setattr(doctor, "REPO_ROOT", repo)
    monkeypatch.setattr(doctor, "_is_root_owned", lambda path: path.name == "__pycache__")

    hygiene = doctor.check_hygiene()

    assert hygiene["root_owned_pycache_count"] == 1
    assert marker.exists()
    assert any("root-owned __pycache__" in warning for warning in hygiene["warnings"])


def test_recommendations_include_dev_validation_environment_for_missing_required(monkeypatch):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor)
    monkeypatch.setattr(
        doctor,
        "check_import",
        lambda module, required=True: doctor._check(
            "failed" if module == "pytest" else "ok",
            required=required,
            available=module != "pytest",
        ),
    )

    result = doctor.run_doctor(profile="local", fix_hints=True)

    assert any("dev validation environment" in rec for rec in result["recommendations"])
    assert any("advisory only" in rec for rec in result["recommendations"])


def test_script_does_not_mutate_files_or_use_install_shell_true_or_docker_daemon_terms():
    text = SCRIPT_PATH.read_text(encoding="utf-8")
    forbidden = [
        "shell=True",
        "subprocess",
        "os.system",
        "apt install",
        "pip install",
        "docker info",
        "docker compose up",
        "docker compose down",
        "chmod(",
        "chown(",
        "unlink(",
        "rmtree(",
    ]
    for needle in forbidden:
        assert needle not in text


def test_docker01_does_not_contact_docker_daemon_by_default(monkeypatch):
    doctor = load_doctor()
    force_clean_environment(monkeypatch, doctor)

    result = doctor.run_doctor(profile="docker01")

    assert result["safety"]["docker_daemon_contacted"] is False
    assert (
        result["checks"]["docker_compose"]["detail"]
        == "CLI presence only; Docker daemon not contacted"
    )


def test_validate_pr_recommends_env_doctor_for_full_lane():
    validate_pr = load_validate_pr()

    plan = validate_pr.plan_validation(["scripts/run_full_pytest.py"], profile="full")
    rendered = validate_pr.render_human(plan)

    assert "python scripts/check_validation_env.py --profile docker01" in rendered
