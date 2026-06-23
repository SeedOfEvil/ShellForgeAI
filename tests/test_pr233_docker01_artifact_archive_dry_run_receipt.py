import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr233_archive_receipt", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr233_archive_receipt"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def touch(path: Path, text: str = "x") -> Path:
    path.write_text(text)
    return path


def make_plan(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "root"
    root.mkdir(parents=True)
    source = touch(root / "sfai-pr233-qa-bundle-20260622T000000Z.json", "candidate-secret")
    touch(root / "sfai-pr233-storage-health-20260622T000000Z.json", "storage")
    plan = h.build_plan(str(root))
    out = tmp_path / "plan"
    h.write_outputs(plan, str(out))
    return out, source, root


def load_plan_id(plan_dir: Path) -> str:
    return json.loads((plan_dir / "artifact-archive-plan.json").read_text())["plan_id"]


def test_happy_path_strict_json_human_and_out_are_read_only(tmp_path):
    plan_dir, source, root = make_plan(tmp_path)
    before = {
        p.name: (p.read_text(), p.stat().st_mtime_ns) for p in plan_dir.iterdir() if p.is_file()
    }
    source_before = (source.read_text(), source.stat().st_mtime_ns)
    plan_id = load_plan_id(plan_dir)

    receipt = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id=plan_id)
    loaded = json.loads(json.dumps(receipt))
    assert loaded["schema_version"] == 1
    assert loaded["mode"] == "docker01_artifact_archive_dry_run_receipt"
    assert loaded["status"] == "ready_for_review"
    assert loaded["plan_validation"]["status"] == "passed"
    assert loaded["plan_id"] == plan_id
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["execution_available"] is False
    assert loaded["dry_run_only"] is True
    assert loaded["summary"]["candidate_items"] == 2
    assert loaded["summary"]["candidate_bytes"] > 0
    assert loaded["summary"]["candidate_classes"]["qa_bundle_artifacts"]["items"] == 1
    assert "Docker volumes" in loaded["summary"]["future_archive_out_of_scope"]
    assert (
        loaded["future_execution_contract"]["future_confirmation_phrase"] == h.CONFIRMATION_PHRASE
    )
    assert loaded["future_execution_contract"]["future_source_delete_default"] is False
    assert loaded["future_execution_contract"]["future_source_move_default"] is False
    assert loaded["future_execution_contract"]["future_execution_available_in_this_pr"] is False
    assert all(
        v is False for k, v in loaded["safety"].items() if k != "read_only" and k != "dry_run_only"
    )

    human = h.render_dry_run_receipt_summary(receipt)
    assert "# Docker01 Artifact Archive Dry-Run Receipt" in human
    assert "Execution available: no" in human
    assert "dry-run only" in human
    assert len(human.splitlines()) < 50

    out = tmp_path / "receipt"
    h.write_dry_run_receipt_outputs(receipt, str(out))
    for name in h.DRY_RUN_RECEIPT_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    checksums = json.loads((out / "checksums.json").read_text())
    assert {f["name"] for f in manifest["files"]} >= set(h.DRY_RUN_RECEIPT_OUT_FILES) - {
        "manifest.json",
        "checksums.json",
    }
    assert "manifest.json" in checksums["checksums"]
    assert "checksums.json" not in checksums["checksums"]
    assert manifest["archive_created"] is False
    assert manifest["candidate_contents_copied"] is False
    assert not any(p.suffix in {".tar", ".gz", ".zst", ".zip"} for p in out.iterdir())
    assert "candidate-secret" not in (out / "candidate-manifest.json").read_text()

    assert {
        p.name: (p.read_text(), p.stat().st_mtime_ns) for p in plan_dir.iterdir() if p.is_file()
    } == before
    assert source.exists() and source.read_text() == source_before[0]
    assert source.stat().st_mtime_ns == source_before[1]
    assert not (root / source.name).with_suffix(".moved").exists()


def test_missing_and_mismatched_plan_id_fail_clearly(tmp_path):
    plan_dir, _, _ = make_plan(tmp_path)
    expected = load_plan_id(plan_dir)
    missing = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id=None)
    mismatch = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id="sha256:0000000000000000")
    matched = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id=expected)
    assert missing["status"] == "failed"
    assert any("--plan-id is required" in e for e in missing["errors"])
    assert mismatch["status"] == "failed"
    assert any(expected in e and "sha256:0000000000000000" in e for e in mismatch["errors"])
    assert matched["status"] == "ready_for_review"


def test_validation_failures_prevent_ready_receipt(tmp_path):
    plan_dir, _, _ = make_plan(tmp_path)
    plan_id = load_plan_id(plan_dir)
    target = plan_dir / "safety-notes.md"
    target.write_text("Z" * len(target.read_text()))
    receipt = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id=plan_id)
    assert receipt["status"] == "failed"
    assert receipt["plan_validation"]["status"] == "failed"
    assert any("checksum mismatch" in e for e in receipt["errors"])
    assert receipt["execution_available"] is False


def test_unsafe_plan_flags_fail_dry_run_receipt(tmp_path):
    for flag in ("archive_created", "source_deleted", "source_moved"):
        plan_dir, _, _ = make_plan(tmp_path / flag)
        plan_id = load_plan_id(plan_dir)
        plan = json.loads((plan_dir / "artifact-archive-plan.json").read_text())
        plan["safety"][flag] = True
        (plan_dir / "artifact-archive-plan.json").write_text(json.dumps(plan))
        receipt = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id=plan_id)
        assert receipt["status"] == "failed", flag
        assert any("safety flag" in e for e in receipt["errors"]), flag


def test_source_contains_no_shell_true_subprocess_or_real_mutation_cli_flags():
    source = HELPER_PATH.read_text()
    assert "shell=True" not in source
    assert "subprocess" not in source
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
        "--post-comment",
        "--approve",
        "--merge",
    ):
        assert flag not in source
