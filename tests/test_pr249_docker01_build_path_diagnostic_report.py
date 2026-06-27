"""PR249 Docker01 build path diagnostic report tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

HELPER_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "docker01_build_path_diagnostic_report.py"
)
_SPEC = importlib.util.spec_from_file_location("docker01_build_path_diagnostic_report", HELPER_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
report_helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(report_helper)


def _repo(tmp_path: Path, dockerfile_text: str) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "Dockerfile").write_text(dockerfile_text, encoding="utf-8")
    return root


def test_json_contract_detects_chown_paths_sha_and_safety(tmp_path: Path, monkeypatch) -> None:
    text = (
        "FROM python:3.12\n"
        "RUN chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai\n"
    )
    root = _repo(tmp_path, text)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")

    report = report_helper.build_report(root)
    encoded = json.dumps(report)
    decoded = json.loads(encoded)

    assert decoded["schema_version"] == 1
    assert decoded["mode"] == "docker01_build_path_diagnostic_report"
    assert decoded["read_only"] is True
    assert decoded["mutation_performed"] is False
    assert decoded["status"] == "warning"
    assert decoded["summary"]["dockerfile_found"] is True
    assert decoded["summary"]["broad_chown_detected"] is True
    assert decoded["summary"]["recursive_ownership_operations"] == 1
    assert decoded["summary"]["known_chown_paths_detected"] == [
        "/data",
        "/home/appuser/.codex",
        "/opt/shellforgeai",
    ]
    assert decoded["dockerfile"]["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert decoded["dockerfile"]["recursive_ownership_lines"] == [
        {
            "line_number": 2,
            "text": "RUN chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai",
            "paths": ["/data", "/home/appuser/.codex", "/opt/shellforgeai"],
        }
    ]
    assert decoded["safety"]["docker_build_executed"] is False
    assert decoded["safety"]["docker_compose_executed"] is False
    assert decoded["safety"]["chown_executed"] is False
    assert decoded["safety"]["chmod_executed"] is False
    assert decoded["safety"]["shell_true"] is False


def test_human_output_is_concise_operator_facing(tmp_path: Path, monkeypatch) -> None:
    root = _repo(tmp_path, "FROM scratch\n")
    monkeypatch.setattr(shutil, "which", lambda name: f"/bin/{name}")

    human = report_helper.render_human(report_helper.build_report(root))

    assert human.startswith("# Docker01 Build Path Diagnostic Report")
    assert "Read-only: yes" in human
    assert "Mutation performed: no" in human
    assert "## Dockerfile ownership scan" in human
    assert "## Relevant paths" in human
    assert "## Tools" in human
    assert "This is a diagnostic report only." in human
    assert "* no docker build" in human
    assert "* no shell=True" in human
    assert len(human.splitlines()) < 45


def test_explicit_absolute_dockerfile_scans_external_path(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    external = tmp_path / "compose" / "shellforgeai" / "Dockerfile"
    external.parent.mkdir(parents=True)
    text = (
        "FROM python:3.12\n"
        "RUN chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai\n"
    )
    external.write_text(text, encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")

    report = report_helper.build_report(repo, dockerfile_path=external)

    assert report["status"] == "warning"
    assert report["dockerfile"]["source"] == "explicit_argument"
    assert report["dockerfile"]["path"] == str(external.resolve(strict=False))
    assert report["dockerfile"]["exists"] is True
    assert report["summary"]["dockerfile_found"] is True
    assert report["summary"]["known_chown_paths_detected"] == [
        "/data",
        "/home/appuser/.codex",
        "/opt/shellforgeai",
    ]
    assert report["dockerfile"]["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert report["dockerfile"]["recursive_ownership_lines"][0]["line_number"] == 2
    assert report["read_only"] is True
    assert report["mutation_performed"] is False
    assert report["safety"]["docker_build_executed"] is False
    assert report["safety"]["docker_compose_executed"] is False
    assert report["safety"]["chown_executed"] is False
    assert report["safety"]["chmod_executed"] is False
    assert report["safety"]["package_install_executed"] is False


def test_missing_explicit_dockerfile_fails_safely(tmp_path: Path, monkeypatch) -> None:
    missing = tmp_path / "compose" / "shellforgeai" / "Dockerfile"
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")

    report = report_helper.build_report(tmp_path / "repo", dockerfile_path=missing)

    assert report["status"] == "failed"
    assert report["dockerfile"]["source"] == "explicit_argument"
    assert report["dockerfile"]["path"] == str(missing.resolve(strict=False))
    assert report["dockerfile"]["exists"] is False
    assert report["summary"]["dockerfile_found"] is False
    assert any(str(missing.resolve(strict=False)) in error for error in report["errors"])


def test_repo_default_dockerfile_source_and_path_still_work(tmp_path: Path, monkeypatch) -> None:
    text = "FROM scratch\n"
    root = _repo(tmp_path, text)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")

    report = report_helper.build_report(root)

    assert report["status"] == "ok"
    assert report["dockerfile"]["source"] == "repo_default"
    assert report["dockerfile"]["path"] == str((root / "Dockerfile").resolve(strict=False))
    assert report["dockerfile"]["exists"] is True
    assert report["dockerfile"]["sha256"] == hashlib.sha256(text.encode()).hexdigest()


def test_out_writes_required_artifacts_for_explicit_dockerfile(tmp_path: Path, monkeypatch) -> None:
    external = tmp_path / "external" / "Dockerfile"
    external.parent.mkdir()
    external.write_text("FROM scratch\n", encoding="utf-8")
    out = tmp_path / "reports"
    monkeypatch.setattr(shutil, "which", lambda name: f"/bin/{name}")

    report_helper.write_artifacts(
        out, report_helper.build_report(tmp_path, dockerfile_path=external)
    )

    diagnostic = json.loads((out / "docker01-build-path-diagnostic.json").read_text())
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checksums = json.loads((out / "checksums.json").read_text(encoding="utf-8"))["sha256"]
    assert diagnostic["dockerfile"]["source"] == "explicit_argument"
    assert diagnostic["dockerfile"]["path"] == str(external.resolve(strict=False))
    assert manifest["artifacts"] == report_helper.ARTIFACTS
    assert set(checksums) == set(report_helper.ARTIFACTS) - {"checksums.json"}
    for name, digest in checksums.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_human_output_includes_explicit_dockerfile_path(tmp_path: Path, monkeypatch) -> None:
    external = tmp_path / "external" / "Dockerfile"
    external.parent.mkdir()
    external.write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda name: f"/bin/{name}")

    human = report_helper.render_human(
        report_helper.build_report(tmp_path, dockerfile_path=external)
    )

    assert f"Dockerfile: {external.resolve(strict=False)}" in human
    assert "Source: explicit argument" in human
    assert "## Dockerfile ownership scan" in human


def test_tooling_baseline_and_missing_ps_procps_warning(tmp_path: Path, monkeypatch) -> None:
    root = _repo(tmp_path, "FROM scratch\n")

    def fake_which(name: str) -> str | None:
        if name == "ps":
            return None
        return f"/usr/bin/{name}"

    monkeypatch.setattr(shutil, "which", fake_which)
    report = report_helper.build_report(root)

    assert report["tools"] == {"python3": True, "ps": False, "git": True, "rsync": True}
    assert report["summary"]["tooling_baseline_ok"] is False
    assert report["status"] == "warning"
    assert any("procps" in check["detail"] for check in report["checks"])


def test_out_writes_required_artifacts_manifest_and_checksums(tmp_path: Path, monkeypatch) -> None:
    root = _repo(tmp_path, "FROM scratch\n")
    out = tmp_path / "reports"
    monkeypatch.setattr(shutil, "which", lambda name: f"/bin/{name}")

    report_helper.write_artifacts(out, report_helper.build_report(root))

    for name in report_helper.ARTIFACTS:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checksums = json.loads((out / "checksums.json").read_text(encoding="utf-8"))["sha256"]
    assert manifest["artifacts"] == report_helper.ARTIFACTS
    assert set(checksums) == set(report_helper.ARTIFACTS) - {"checksums.json"}
    for name, digest in checksums.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_non_empty_out_fails_safely(tmp_path: Path, monkeypatch) -> None:
    root = _repo(tmp_path, "FROM scratch\n")
    out = tmp_path / "reports"
    out.mkdir()
    (out / "existing.txt").write_text("keep", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda name: f"/bin/{name}")

    try:
        report_helper.write_artifacts(out, report_helper.build_report(root))
    except SystemExit as exc:
        assert "non-empty" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected non-empty output directory to fail")
    assert (out / "existing.txt").read_text(encoding="utf-8") == "keep"


def test_helper_source_safety_guardrails() -> None:
    source = Path(report_helper.__file__).read_text(encoding="utf-8")
    forbidden = [
        "shell=True",
        "subprocess",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "apt-get install",
        "pip install",
        "pytest.main",
    ]
    for token in forbidden:
        assert token not in source


def test_docs_describe_read_only_context_and_separate_remediation() -> None:
    root = Path(__file__).resolve().parents[1]
    docs = "\n".join(
        (root / path).read_text(encoding="utf-8").lower()
        for path in [
            "OPS.md",
            "docs/VALIDATION_LANES.md",
            "docs/VALIDATION_MATRIX.md",
            "docs/roadmap.md",
        ]
    )
    assert "docker01 build path diagnostic" in docs
    assert "read-only" in docs
    assert "not remediation" in docs or "does not remediate" in docs
    assert "pr247/pr248" in docs
    assert "chown -r" in docs
    assert "separate pr" in docs
    assert "/srv/compose/shellforgeai/dockerfile" in docs
    assert "--dockerfile" in docs
    assert "external dockerfile path" in docs
    assert "does not fix the chown-layer hang" in docs
    assert "no duplicate full pytest" in docs or "full pytest should run once only" in docs
