import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr231_archive_plan", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr231_archive_plan"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def touch(path: Path, text: str = "x") -> Path:
    path.write_text(text)
    return path


def make_tree(tmp_path: Path):
    touch(tmp_path / "sfai-pr231-qa-bundle-20260622T000000Z.json", "qa")
    touch(tmp_path / "sfai-pr231-validation-20260622T000000Z.json", "validation")
    touch(tmp_path / "sfai-pr231-hygiene-20260622T000000Z.md", "hygiene")
    touch(tmp_path / "sfai-pr231-live-probe-receipt-20260622T000000Z.json", "receipt")
    touch(tmp_path / "sfai-pr231-storage-health-20260622T000000Z.json", "storage")
    touch(tmp_path / "unrelated.txt", "ignore")
    (tmp_path / "srv").mkdir()
    (tmp_path / "sfai-pr231-v2-readiness-20260622T000000Z").mkdir()
    target = touch(tmp_path / "target-secret.txt", "secret")
    (tmp_path / "sfai-pr231-validation-symlink").symlink_to(target)


def test_json_strict_and_shape(tmp_path):
    make_tree(tmp_path)
    plan = h.build_plan(str(tmp_path))
    loaded = json.loads(json.dumps(plan))
    assert loaded["schema_version"] == 1
    assert loaded["mode"] == "docker01_artifact_archive_plan"
    assert loaded["execution_available"] is False
    assert loaded["mutation_performed"] is False
    assert loaded["read_only"] is True
    assert loaded["future_confirmation_phrase"] == "CONFIRM_SHELLFORGEAI_ARTIFACT_ARCHIVE"


def test_human_output_concise_and_execution_unavailable(tmp_path):
    make_tree(tmp_path)
    plan = h.build_plan(str(tmp_path))
    out = h.render_summary(plan)
    assert "# Docker01 ShellForgeAI Artifact Archive Plan" in out
    assert "Execution available: no" in out
    assert plan["plan_id"] in out
    assert "source deletion is not part of this PR" in out
    assert len(out.splitlines()) < 50


def test_out_writes_required_plan_files_and_checksums(tmp_path):
    make_tree(tmp_path)
    out = tmp_path / "out"
    plan = h.build_plan(str(tmp_path))
    h.write_outputs(plan, str(out))
    for name in h.REQUIRED_OUT_FILES:
        assert (out / name).exists(), name
    manifest = json.loads((out / "manifest.json").read_text())
    checksums = json.loads((out / "checksums.json").read_text())
    assert {f["name"] for f in manifest["files"]} >= {
        "artifact-archive-plan.json",
        "artifact-archive-plan-summary.md",
        "candidate-manifest.json",
        "excluded-candidates.json",
        "safety-notes.md",
    }
    assert "manifest.json" in checksums["checksums"]
    assert "checksums.json" not in checksums["checksums"]
    assert not any(p.suffix in {".tar", ".gz", ".zst", ".zip"} for p in out.iterdir())


def test_known_candidate_classes_and_exclusions(tmp_path):
    make_tree(tmp_path)
    plan = h.build_plan(str(tmp_path))
    classes = {c["class"] for c in plan["candidates"]}
    assert "qa_bundle_artifacts" in classes
    assert "validation_artifacts" in classes
    assert "hygiene_report_artifacts" in classes
    assert "model_receipt_artifacts" in classes
    assert "storage_health_report_artifacts" in classes
    assert "v2_readiness_artifacts" in classes
    excluded_reasons = {e["reason"] for e in plan["excluded"]}
    assert "outside_known_patterns" in excluded_reasons
    assert "symlink" in excluded_reasons
    assert "current_runtime_path" in excluded_reasons


def test_counts_bytes_and_bounds(tmp_path):
    make_tree(tmp_path)
    plan = h.build_plan(str(tmp_path), max_scan=3, max_returned=2, max_warnings=50)
    assert plan["summary"]["candidate_items"] <= 2
    assert len(plan["candidates"]) <= 2
    assert plan["summary"]["candidate_bytes"] == sum(c["size_bytes"] for c in plan["candidates"])
    assert plan["warnings"]


def test_plan_id_is_deterministic_and_changes_with_metadata(tmp_path):
    artifact = touch(tmp_path / "sfai-pr231-storage-health-20260622T000000Z.json", "a")
    first = h.build_plan(str(tmp_path))["plan_id"]
    second = h.build_plan(str(tmp_path))["plan_id"]
    assert first == second
    artifact.write_text("changed")
    third = h.build_plan(str(tmp_path))["plan_id"]
    assert third != first


def test_source_files_are_not_modified_moved_or_deleted(tmp_path):
    artifact = touch(tmp_path / "sfai-pr231-validation-20260622T000000Z.json", "keep")
    before = (artifact.read_text(), artifact.stat().st_mtime_ns)
    plan = h.build_plan(str(tmp_path))
    h.write_outputs(plan, str(tmp_path / "out"))
    assert artifact.exists()
    assert artifact.read_text() == before[0]
    assert artifact.stat().st_mtime_ns == before[1]


def test_safety_contract_and_future_requirements(tmp_path):
    plan = h.build_plan(str(tmp_path))
    safety = plan["safety"]
    assert plan["execution_available"] is False
    assert safety["archive_created"] is False
    assert safety["source_deleted"] is False
    assert safety["source_moved"] is False
    assert safety["docker_prune_executed"] is False
    assert safety["container_restarted"] is False
    assert safety["shell_true"] is False
    contract = plan["future_archive_contract"]
    assert contract["receipt_required"] is True
    assert contract["manifest_required"] is True
    assert contract["checksums_required"] is True
    assert contract["source_deletion_is_not_part_of_this_pr"] is True


def test_source_contains_no_shell_true_or_mutation_flags():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    for flag in (
        "--execute",
        "--apply",
        "--archive-now",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--fix",
        "--rm",
        "--rmi",
    ):
        assert flag not in source
    assert "subprocess" not in source
    assert "docker.from_env" not in source
