import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr232_archive_plan", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr232_archive_plan"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def touch(path: Path, text: str = "x") -> Path:
    path.write_text(text)
    return path


def make_plan(tmp_path: Path, *, empty: bool = False) -> Path:
    """Produce a real PR231 plan directory and return it."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    root = tmp_path / "root"
    root.mkdir()
    if not empty:
        touch(root / "sfai-pr232-qa-bundle-20260622T000000Z.json", "qa")
        touch(root / "sfai-pr232-validation-20260622T000000Z.json", "validation")
        touch(root / "sfai-pr232-storage-health-20260622T000000Z.json", "storage")
    plan = h.build_plan(str(root))
    out = tmp_path / "plan"
    h.write_outputs(plan, str(out))
    return out


def _validate(plan_dir: Path):
    return h.validate_plan(str(plan_dir))


def test_valid_plan_validates_as_passed(tmp_path):
    plan_dir = make_plan(tmp_path)
    result = _validate(plan_dir)
    loaded = json.loads(json.dumps(result))
    assert loaded["schema_version"] == 1
    assert loaded["mode"] == "docker01_artifact_archive_plan_validation"
    assert loaded["status"] == "passed"
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["future_execution_available"] is False
    assert loaded["future_execution_eligible_for_review"] is True
    assert loaded["plan_id"].startswith("sha256:")
    assert all(c["status"] == "passed" for c in loaded["checks"])
    assert all(v is False for k, v in loaded["safety"].items() if k.endswith("_executed"))


def test_empty_but_structurally_valid_plan_passes(tmp_path):
    plan_dir = make_plan(tmp_path, empty=True)
    result = _validate(plan_dir)
    assert result["status"] == "passed"
    assert result["summary"]["candidate_items"] == 0


def test_missing_required_file_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    (plan_dir / "safety-notes.md").unlink()
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(
        c["name"] == "required_files_present" and c["status"] == "failed" for c in result["checks"]
    )


def test_invalid_json_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    (plan_dir / "candidate-manifest.json").write_text("{")
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(c["name"] == "json_parse_ok" and c["status"] == "failed" for c in result["checks"])


def test_checksum_mismatch_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    # mutate a file that is covered by checksums but whose size is unchanged
    target = plan_dir / "safety-notes.md"
    original = target.read_text()
    target.write_text("Z" * len(original))
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(c["name"] == "checksums_ok" and c["status"] == "failed" for c in result["checks"])


def test_manifest_missing_file_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    manifest = json.loads((plan_dir / "manifest.json").read_text())
    manifest["files"].append({"name": "does-not-exist.md", "size_bytes": 1, "path": "x"})
    (plan_dir / "manifest.json").write_text(json.dumps(manifest))
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(c["name"] == "manifest_ok" and c["status"] == "failed" for c in result["checks"])


def test_manifest_size_mismatch_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    manifest = json.loads((plan_dir / "manifest.json").read_text())
    manifest["files"][0]["size_bytes"] = manifest["files"][0]["size_bytes"] + 999
    (plan_dir / "manifest.json").write_text(json.dumps(manifest))
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(c["name"] == "manifest_ok" and c["status"] == "failed" for c in result["checks"])


def test_execution_available_true_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    plan = json.loads((plan_dir / "artifact-archive-plan.json").read_text())
    plan["execution_available"] = True
    (plan_dir / "artifact-archive-plan.json").write_text(json.dumps(plan))
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(
        c["name"] == "execution_unavailable" and c["status"] == "failed" for c in result["checks"]
    )


def test_mutation_performed_true_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    plan = json.loads((plan_dir / "artifact-archive-plan.json").read_text())
    plan["mutation_performed"] = True
    (plan_dir / "artifact-archive-plan.json").write_text(json.dumps(plan))
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(
        c["name"] == "mutation_not_performed" and c["status"] == "failed" for c in result["checks"]
    )


def test_mutation_safety_flags_true_fail(tmp_path):
    for flag in (
        "archive_created",
        "source_moved",
        "source_deleted",
        "cleanup_executed",
        "docker_prune_executed",
        "container_restarted",
    ):
        plan_dir = make_plan(tmp_path / flag)
        plan = json.loads((plan_dir / "artifact-archive-plan.json").read_text())
        plan["safety"][flag] = True
        (plan_dir / "artifact-archive-plan.json").write_text(json.dumps(plan))
        result = _validate(plan_dir)
        assert result["status"] == "failed", flag
        assert any(
            c["name"] == "safety_flags_clear" and c["status"] == "failed" for c in result["checks"]
        ), flag


def test_source_copied_flag_true_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    manifest = json.loads((plan_dir / "manifest.json").read_text())
    manifest["candidate_contents_copied"] = True
    (plan_dir / "manifest.json").write_text(json.dumps(manifest))
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(
        c["name"] == "safety_flags_clear" and c["status"] == "failed" for c in result["checks"]
    )


def test_missing_confirmation_phrase_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    plan = json.loads((plan_dir / "artifact-archive-plan.json").read_text())
    plan["future_confirmation_phrase"] = "WRONG_PHRASE"
    (plan_dir / "artifact-archive-plan.json").write_text(json.dumps(plan))
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(
        c["name"] == "confirmation_phrase_present" and c["status"] == "failed"
        for c in result["checks"]
    )


def test_unsafe_candidate_path_fails(tmp_path):
    plan_dir = make_plan(tmp_path)
    cm = json.loads((plan_dir / "candidate-manifest.json").read_text())
    cm["candidates"].append(
        {
            "path": "/var/lib/docker/overlay2/abc",
            "class": "qa_bundle_artifacts",
            "type": "file",
            "size_bytes": 1,
        }
    )
    (plan_dir / "candidate-manifest.json").write_text(json.dumps(cm))
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(
        c["name"] == "candidate_scope_bounded" and c["status"] == "failed" for c in result["checks"]
    )


def test_symlink_candidate_fails_and_is_not_followed(tmp_path):
    plan_dir = make_plan(tmp_path)
    secret = touch(tmp_path / "secret-target.json", "TOP_SECRET_VALUE")
    link = tmp_path / "sfai-pr232-qa-bundle-link.json"
    link.symlink_to(secret)
    cm = json.loads((plan_dir / "candidate-manifest.json").read_text())
    cm["candidates"].append(
        {
            "path": str(link),
            "class": "qa_bundle_artifacts",
            "type": "file",
            "size_bytes": 1,
        }
    )
    (plan_dir / "candidate-manifest.json").write_text(json.dumps(cm))
    result = _validate(plan_dir)
    assert result["status"] == "failed"
    assert any(
        c["name"] == "candidate_symlinks_rejected" and c["status"] == "failed"
        for c in result["checks"]
    )
    # the secret target is never read into the result payload
    assert "TOP_SECRET_VALUE" not in json.dumps(result)


def test_out_writes_validation_output_files(tmp_path):
    plan_dir = make_plan(tmp_path)
    out = tmp_path / "validation"
    result = _validate(plan_dir)
    h.write_validation_outputs(result, str(out))
    for name in h.VALIDATION_OUT_FILES:
        assert (out / name).exists(), name
    manifest = json.loads((out / "manifest.json").read_text())
    checksums = json.loads((out / "checksums.json").read_text())
    assert {f["name"] for f in manifest["files"]} == {
        "artifact-archive-plan-validation.json",
        "artifact-archive-plan-validation-summary.md",
    }
    assert "manifest.json" in checksums["checksums"]
    assert "checksums.json" not in checksums["checksums"]
    for name, recorded in checksums["checksums"].items():
        assert recorded == "sha256:" + h.sha256_file(out / name)
    assert not any(p.suffix in {".tar", ".gz", ".zst", ".zip"} for p in out.iterdir())


def test_source_plan_files_not_modified_and_no_archive_created(tmp_path):
    plan_dir = make_plan(tmp_path)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in plan_dir.iterdir()}
    out = tmp_path / "validation"
    result = _validate(plan_dir)
    h.write_validation_outputs(result, str(out))
    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in plan_dir.iterdir()}
    assert before == after
    assert not any(p.suffix in {".tar", ".gz", ".zst", ".zip"} for p in plan_dir.iterdir())


def test_human_output_is_concise_and_pasteable(tmp_path):
    plan_dir = make_plan(tmp_path)
    result = _validate(plan_dir)
    out = h.render_validation_summary(result)
    assert "# Docker01 ShellForgeAI Artifact Archive Plan Validation" in out
    assert "Validation status: passed" in out
    assert "Future execution available: no" in out
    assert "* no archive created" in out
    assert "* no source copied" in out
    assert "* no source moved" in out
    assert "* no source deleted" in out
    assert result["plan_id"] in out
    assert len(out.splitlines()) < 50


def test_cli_validate_json_and_summary(tmp_path, capsys):
    plan_dir = make_plan(tmp_path)
    rc = h.main(["--validate", str(plan_dir), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "docker01_artifact_archive_plan_validation"
    assert payload["status"] == "passed"

    rc = h.main(["--validate", str(plan_dir)])
    assert rc == 0
    assert "Validation status: passed" in capsys.readouterr().out


def test_cli_validate_failed_returns_nonzero(tmp_path, capsys):
    plan_dir = make_plan(tmp_path)
    (plan_dir / "safety-notes.md").unlink()
    rc = h.main(["--validate", str(plan_dir), "--json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"


def test_source_contains_no_shell_true_or_mutation_flags():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    for flag in (
        "--execute",
        "--apply",
        "--archive-now",
        "--cleanup",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
        "--repair",
    ):
        assert flag not in source
    assert "subprocess" not in source
    assert "docker.from_env" not in source
    assert "shutil.copy2" in source
    assert "shutil.move" not in source
