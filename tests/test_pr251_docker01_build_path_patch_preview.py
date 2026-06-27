"""PR251 Docker01 build path ownership patch preview tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

HELPER_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "docker01_build_path_patch_preview.py"
)
_SPEC = importlib.util.spec_from_file_location("docker01_build_path_patch_preview", HELPER_PATH)
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


def test_json_output_strict_preview_ready_paths_sha_static_verification_and_safety(
    tmp_path: Path,
) -> None:
    text = f"FROM python:3.12\n{CHOWN_LINE}\n"
    dockerfile = _dockerfile(tmp_path, text)

    report = helper._public_report(helper.build_report(dockerfile))
    decoded = json.loads(json.dumps(report))

    assert decoded["schema_version"] == 1
    assert decoded["mode"] == "docker01_build_path_ownership_patch_preview"
    assert decoded["status"] == "preview_ready"
    assert decoded["dockerfile_path"] == str(dockerfile.resolve(strict=False))
    assert decoded["dockerfile"]["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert decoded["read_only"] is True
    assert decoded["mutation_performed"] is False
    assert decoded["patch_preview_only"] is True
    assert decoded["apply_available"] is False
    assert decoded["dockerfile_modified"] is False
    assert decoded["compose_modified"] is False
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
    assert decoded["summary"]["preview_generated"] is True
    assert decoded["summary"]["preview_removes_broad_recursive_ownership"] is True
    assert decoded["summary"]["preview_static_verification_passed"] is True
    assert decoded["static_verification"] == {
        "preview_contains_chown_r": False,
        "preview_contains_recursive_chown_data": False,
        "preview_contains_recursive_chown_codex": False,
        "preview_contains_recursive_chown_opt_shellforgeai": False,
        "preview_mentions_targeted_runtime_dirs": True,
        "preview_mentions_copy_chown_guidance": True,
    }
    assert decoded["patch_preview"]["applied"] is False
    assert decoded["patch_preview"]["dockerfile_not_modified"] is True
    assert decoded["safety"]["docker_build_executed"] is False
    assert decoded["safety"]["docker_compose_executed"] is False
    assert decoded["safety"]["chown_executed"] is False
    assert decoded["safety"]["chmod_executed"] is False
    assert decoded["safety"]["dockerfile_modified"] is False
    assert decoded["safety"]["compose_modified"] is False


def test_human_output_is_concise_operator_facing(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, f"FROM scratch\n{CHOWN_LINE}\n")

    human = helper.render_human(helper._public_report(helper.build_report(dockerfile)))

    assert human.startswith("# Docker01 Build Path Ownership Patch Preview")
    assert "Read-only: yes" in human
    assert "Mutation performed: no" in human
    assert "Apply available: no" in human
    assert "## Detected ownership operations" in human
    assert "## Patch preview" in human
    assert "Preview static verification: true" in human
    assert "Prefer COPY --chown" in human
    assert "This is a patch preview only." in human
    assert "* no Dockerfile modification" in human
    assert "* no Compose modification" in human
    assert "* no shell=True" in human
    assert len(human.splitlines()) < 55


def test_no_issue_detected_for_plain_dockerfile(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, "FROM scratch\n")

    report = helper.build_report(dockerfile)

    assert report["status"] == "no_issue_detected"
    assert report["summary"]["broad_recursive_ownership_detected"] is False
    assert report["detected_operations"] == []


def test_out_writes_required_preview_files_manifest_checksums_and_static_artifacts(
    tmp_path: Path,
) -> None:
    dockerfile = _dockerfile(tmp_path, f"FROM scratch\n{CHOWN_LINE}\n")
    out = tmp_path / "patch-preview"

    helper.write_artifacts(out, helper.build_report(dockerfile))

    for name in helper.ARTIFACTS:
        assert (out / name).is_file(), name
    preview = (out / "dockerfile-ownership-preview.Dockerfile").read_text(encoding="utf-8")
    diff = (out / "dockerfile-ownership-preview.diff").read_text(encoding="utf-8")
    static = json.loads((out / "dockerfile-ownership-static-verification.json").read_text())
    assert CHOWN_LINE not in preview
    assert "chown -R appuser:appuser /data" not in preview
    assert "RUN install -d -o appuser -g appuser /data /home/appuser/.codex" in preview
    assert "COPY --chown=appuser:appuser" in preview
    assert "-" + CHOWN_LINE in diff
    assert "+RUN install -d -o appuser -g appuser /data /home/appuser/.codex" in diff
    assert static["preview_contains_chown_r"] is False
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checksums = json.loads((out / "checksums.json").read_text(encoding="utf-8"))["sha256"]
    assert manifest["artifacts"] == helper.ARTIFACTS
    assert set(checksums) == set(helper.ARTIFACTS) - {"checksums.json"}
    for name, digest in checksums.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_non_empty_out_fails_safely(tmp_path: Path) -> None:
    dockerfile = _dockerfile(tmp_path, "FROM scratch\n")
    out = tmp_path / "patch-preview"
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


def test_optional_pr250_proposal_report_consumed_and_cross_checked(tmp_path: Path) -> None:
    text = f"FROM scratch\n{CHOWN_LINE}\n"
    dockerfile = _dockerfile(tmp_path, text)
    proposal_dir = tmp_path / "proposal"
    proposal_dir.mkdir()
    (proposal_dir / "docker01-build-path-ownership-proposal.json").write_text(
        json.dumps(
            {
                "dockerfile_path": str(dockerfile.resolve(strict=False)),
                "dockerfile": {"sha256": hashlib.sha256(text.encode()).hexdigest()},
                "summary": {"broad_recursive_ownership_detected": True},
                "proposal": {"intent": "replace broad recursive ownership"},
            }
        ),
        encoding="utf-8",
    )

    report = helper.build_report(None, proposal_dir)

    assert report["status"] == "preview_ready"
    assert report["proposal_cross_check"] == {"provided": True, "consumed": True}
    assert any(
        check["name"] == "proposal_cross_check" and check["status"] == "passed"
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


def test_docs_describe_read_only_patch_preview_and_separate_remediation() -> None:
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
    assert "docker01 build path ownership patch preview" in docs
    assert "read-only" in docs
    assert "patch preview only" in docs
    assert "pr249" in docs
    assert "pr250" in docs
    assert "separate pr" in docs or "operator-reviewed" in docs
