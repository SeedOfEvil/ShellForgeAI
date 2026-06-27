"""PR250 Docker01 build path ownership proposal report tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

HELPER_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "docker01_build_path_ownership_proposal.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "docker01_build_path_ownership_proposal", HELPER_PATH
)
assert _SPEC is not None
assert _SPEC.loader is not None
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)

CHOWN_LINE = "RUN chown -R appuser:appuser /data /home/appuser/.codex /opt/shellforgeai"


def _dockerfile(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "compose" / "shellforgeai" / "Dockerfile"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_json_output_strict_proposal_ready_paths_sha_and_safety(tmp_path: Path) -> None:
    text = f"FROM python:3.12\n{CHOWN_LINE}\n"
    dockerfile = _dockerfile(tmp_path, text)

    report = helper.build_report(dockerfile)
    decoded = json.loads(json.dumps(report))

    assert decoded["schema_version"] == 1
    assert decoded["mode"] == "docker01_build_path_ownership_proposal"
    assert decoded["status"] == "proposal_ready"
    assert decoded["dockerfile_path"] == str(dockerfile.resolve(strict=False))
    assert decoded["dockerfile"]["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert decoded["read_only"] is True
    assert decoded["mutation_performed"] is False
    assert decoded["proposal_only"] is True
    assert decoded["apply_available"] is False
    assert decoded["summary"]["dockerfile_found"] is True
    assert decoded["summary"]["broad_recursive_ownership_detected"] is True
    assert decoded["summary"]["recursive_ownership_operations"] == 1
    assert decoded["summary"]["known_risk_paths_detected"] == [
        "/data",
        "/home/appuser/.codex",
        "/opt/shellforgeai",
    ]
    assert decoded["detected_operations"] == [
        {
            "line_number": 2,
            "operation": "chown -R",
            "text": CHOWN_LINE,
            "paths": ["/data", "/home/appuser/.codex", "/opt/shellforgeai"],
            "risk": "broad_recursive_ownership_on_build_paths",
        }
    ]
    assert decoded["proposal"]["dockerfile_not_modified"] is True
    descriptions = "\n".join(p["description"] for p in decoded["proposal"]["suggested_patterns"])
    assert "empty runtime directories" in descriptions
    assert "COPY --chown=appuser:appuser" in descriptions
    assert "recursively chown /data" in descriptions
    assert decoded["safety"]["dockerfile_modified"] is False
    assert decoded["safety"]["docker_build_executed"] is False
    assert decoded["safety"]["docker_compose_executed"] is False
    assert decoded["safety"]["chown_executed"] is False
    assert decoded["safety"]["chmod_executed"] is False


def test_human_output_is_concise_operator_facing(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, f"FROM scratch\n{CHOWN_LINE}\n")

    human = helper.render_human(helper.build_report(dockerfile))

    assert human.startswith("# Docker01 Build Path Ownership Proposal")
    assert "Read-only: yes" in human
    assert "Mutation performed: no" in human
    assert "Apply available: no" in human
    assert "## Detected ownership operations" in human
    assert "## Proposal" in human
    assert "Prefer COPY --chown" in human
    assert "This is a proposal only." in human
    assert "* no Dockerfile modification" in human
    assert "* no shell=True" in human
    assert len(human.splitlines()) < 45


def test_no_issue_detected_for_plain_dockerfile(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, "FROM scratch\n")

    report = helper.build_report(dockerfile)

    assert report["status"] == "no_issue_detected"
    assert report["summary"]["broad_recursive_ownership_detected"] is False
    assert report["detected_operations"] == []


def test_out_writes_required_report_files_manifest_and_checksums(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, f"FROM scratch\n{CHOWN_LINE}\n")
    out = tmp_path / "proposal-report"

    helper.write_artifacts(out, helper.build_report(dockerfile))

    for name in helper.ARTIFACTS:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checksums = json.loads((out / "checksums.json").read_text(encoding="utf-8"))["sha256"]
    assert manifest["artifacts"] == helper.ARTIFACTS
    assert set(checksums) == set(helper.ARTIFACTS) - {"checksums.json"}
    for name, digest in checksums.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_non_empty_out_fails_safely(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, "FROM scratch\n")
    out = tmp_path / "proposal-report"
    out.mkdir()
    (out / "existing.txt").write_text("keep", encoding="utf-8")

    try:
        helper.write_artifacts(out, helper.build_report(dockerfile))
    except SystemExit as exc:
        assert "non-empty" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected non-empty output directory to fail")
    assert (out / "existing.txt").read_text(encoding="utf-8") == "keep"


def test_missing_dockerfile_fails_safely_read_only(tmp_path: Path) -> None:
    missing = tmp_path / "missing" / "Dockerfile"

    report = helper.build_report(missing)

    assert report["status"] == "failed"
    assert report["summary"]["dockerfile_found"] is False
    assert report["read_only"] is True
    assert report["mutation_performed"] is False
    assert report["safety"]["dockerfile_modified"] is False


def test_optional_diagnostic_report_consumed_and_cross_checked(tmp_path: Path) -> None:
    text = f"FROM scratch\n{CHOWN_LINE}\n"
    dockerfile = _dockerfile(tmp_path, text)
    diagnostic_dir = tmp_path / "diagnostic"
    diagnostic_dir.mkdir()
    (diagnostic_dir / "docker01-build-path-diagnostic.json").write_text(
        json.dumps(
            {
                "dockerfile": {
                    "path": str(dockerfile.resolve(strict=False)),
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                }
            }
        ),
        encoding="utf-8",
    )

    report = helper.build_report(dockerfile, diagnostic_dir)

    assert report["status"] == "proposal_ready"
    assert report["diagnostic_cross_check"] == {"provided": True, "consumed": True}
    assert any(
        check["name"] == "diagnostic_cross_check" and check["status"] == "passed"
        for check in report["checks"]
    )


def test_helper_source_safety_guardrails_and_command_surface() -> None:
    source = Path(helper.__file__).read_text(encoding="utf-8")
    forbidden = [
        "shell=True",
        "subprocess",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "apt-get install",
        "pip install",
        "pytest.main",
        "--cleanup",
        "--execute-cleanup",
        "--cleanup-now",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
        "--apply",
        "--execute",
        "--approve",
        "--merge",
        "--post-comment",
    ]
    for token in forbidden:
        assert token not in source


def test_docs_describe_read_only_proposal_and_separate_remediation() -> None:
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
    assert "docker01 build path ownership proposal" in docs
    assert "read-only" in docs
    assert "proposal only" in docs
    assert "pr249" in docs
    assert "chown -r" in docs
    assert "/srv/compose/shellforgeai/dockerfile" in docs
    assert "--dockerfile" in docs
    assert "does not edit dockerfile" in docs
    assert "does not run docker" in docs
    assert "separate pr" in docs or "operator-reviewed" in docs
    assert "no duplicate full pytest" in docs or "full pytest should run once only" in docs
