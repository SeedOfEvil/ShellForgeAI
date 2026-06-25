import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_artifact_archive_plan.py"


def _load():
    spec = importlib.util.spec_from_file_location("pr234_archive_receipt_validation", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["pr234_archive_receipt_validation"] = module
    spec.loader.exec_module(module)
    return module


h = _load()


def make_receipt(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "root"
    root.mkdir(parents=True)
    source = root / "sfai-pr234-qa-bundle-20260622T000000Z.json"
    source.write_text("candidate-secret")
    (root / "sfai-pr234-storage-health-20260622T000000Z.json").write_text("storage")
    plan = h.build_plan(str(root))
    plan_dir = tmp_path / "plan"
    h.write_outputs(plan, str(plan_dir))
    receipt = h.build_dry_run_receipt(str(plan_dir), supplied_plan_id=plan["plan_id"])
    receipt_dir = tmp_path / "receipt"
    h.write_dry_run_receipt_outputs(receipt, str(receipt_dir))
    return receipt_dir, plan_dir, source


def test_valid_dry_run_receipt_validates_as_passed_standalone_and_with_plan(tmp_path):
    receipt_dir, plan_dir, source = make_receipt(tmp_path)
    before_receipt = {
        p.name: (p.read_text(), p.stat().st_mtime_ns) for p in receipt_dir.iterdir() if p.is_file()
    }
    before_plan = {
        p.name: (p.read_text(), p.stat().st_mtime_ns) for p in plan_dir.iterdir() if p.is_file()
    }
    source_before = (source.read_text(), source.stat().st_mtime_ns)

    standalone = h.validate_dry_run_receipt(str(receipt_dir))
    assert standalone["mode"] == "docker01_artifact_archive_dry_run_receipt_validation"
    assert standalone["status"] == "partial"
    assert standalone["summary"]["plan_cross_check_status"] == "not_requested"
    assert standalone["future_execution_available"] is False
    assert standalone["safety"]["validation_only"] is True
    assert standalone["safety"]["dry_run_only"] is True

    result = h.validate_dry_run_receipt(str(receipt_dir), plan_dir=str(plan_dir))
    loaded = json.loads(json.dumps(result))
    assert loaded["schema_version"] == 1
    assert loaded["status"] == "passed"
    assert loaded["read_only"] is True
    assert loaded["mutation_performed"] is False
    assert loaded["summary"]["plan_cross_check_status"] == "passed"
    assert loaded["summary"]["candidate_items"] == 2
    assert loaded["summary"]["candidate_bytes"] > 0
    assert loaded["future_execution_eligible_for_review"] is True
    assert all(
        v is False
        for k, v in loaded["safety"].items()
        if k not in {"read_only", "validation_only", "dry_run_only"}
    )

    human = h.render_dry_run_receipt_validation_summary(result)
    assert "# Docker01 Artifact Archive Dry-Run Receipt Validation" in human
    assert "Execution available: no" in human
    assert len(human.splitlines()) < 45

    out = tmp_path / "validation"
    h.write_dry_run_receipt_validation_outputs(result, str(out))
    for name in h.DRY_RUN_RECEIPT_VALIDATION_OUT_FILES:
        assert (out / name).is_file(), name
    manifest = json.loads((out / "manifest.json").read_text())
    checksums = json.loads((out / "checksums.json").read_text())
    assert manifest["archive_created"] is False
    assert manifest["candidate_contents_copied"] is False
    assert "manifest.json" in checksums["checksums"]
    assert "checksums.json" not in checksums["checksums"]
    assert not any(p.suffix in {".tar", ".gz", ".zst", ".zip"} for p in out.iterdir())

    assert {
        p.name: (p.read_text(), p.stat().st_mtime_ns) for p in receipt_dir.iterdir() if p.is_file()
    } == before_receipt
    assert {
        p.name: (p.read_text(), p.stat().st_mtime_ns) for p in plan_dir.iterdir() if p.is_file()
    } == before_plan
    assert source.exists() and source.read_text() == source_before[0]
    assert source.stat().st_mtime_ns == source_before[1]


def test_receipt_validation_failures(tmp_path):
    cases = []
    for name, mutate, expected in [
        ("missing", lambda d: (d / "safety-notes.md").unlink(), "required_files_present"),
        (
            "invalid_json",
            lambda d: (d / "artifact-archive-dry-run-receipt.json").write_text("{"),
            "json_parse_ok",
        ),
        (
            "checksum",
            lambda d: (d / "safety-notes.md").write_text("same-size-change"),
            "checksums_ok",
        ),
        (
            "manifest_missing",
            lambda d: _append_manifest(d, {"name": "missing.md", "size_bytes": 1}),
            "manifest_ok",
        ),
        ("manifest_size", lambda d: _bump_manifest_size(d), "manifest_ok"),
        (
            "execution",
            lambda d: _mutate_receipt(d, ["execution_available"], True),
            "receipt_safety_ok",
        ),
        (
            "mutation",
            lambda d: _mutate_receipt(d, ["mutation_performed"], True),
            "receipt_safety_ok",
        ),
        (
            "archive",
            lambda d: _mutate_receipt(d, ["safety", "archive_created"], True),
            "receipt_safety_ok",
        ),
        (
            "copied",
            lambda d: _mutate_receipt(d, ["safety", "source_copied"], True),
            "receipt_safety_ok",
        ),
        (
            "cleanup",
            lambda d: _mutate_receipt(d, ["safety", "cleanup_executed"], True),
            "receipt_safety_ok",
        ),
        (
            "restart",
            lambda d: _mutate_receipt(d, ["safety", "container_restarted"], True),
            "receipt_safety_ok",
        ),
        (
            "confirmation",
            lambda d: _mutate_receipt(
                d, ["future_execution_contract", "future_confirmation_phrase"], ""
            ),
            "future_contract_ok",
        ),
        (
            "unsafe_path",
            lambda d: _mutate_candidate(d, "/var/lib/docker/bad"),
            "candidate_manifest_ok",
        ),
    ]:
        receipt_dir, _, _ = make_receipt(tmp_path / name)
        mutate(receipt_dir)
        result = h.validate_dry_run_receipt(str(receipt_dir))
        cases.append((name, result))
        assert result["status"] == "failed", name
        assert any(c["name"] == expected and c["status"] == "failed" for c in result["checks"]), (
            name
        )

    receipt_dir, _, _ = make_receipt(tmp_path / "symlink")
    target = tmp_path / "symlink-target"
    target.write_text("x")
    link = tmp_path / "sfai-pr234-qa-bundle-symlink"
    link.symlink_to(target)
    _mutate_candidate(receipt_dir, str(link))
    result = h.validate_dry_run_receipt(str(receipt_dir))
    assert result["status"] == "failed"
    assert any("symlink" in e for e in result["errors"])


def test_plan_cross_check_failures(tmp_path):
    receipt_dir, plan_dir, _ = make_receipt(tmp_path)
    _mutate_receipt(receipt_dir, ["plan_id"], "sha256:0000000000000000")
    assert (
        h.validate_dry_run_receipt(str(receipt_dir), plan_dir=str(plan_dir))["status"] == "failed"
    )

    receipt_dir, plan_dir, _ = make_receipt(tmp_path / "count")
    cm = json.loads((receipt_dir / "candidate-manifest.json").read_text())
    cm["candidates"] = cm["candidates"][:1]
    (receipt_dir / "candidate-manifest.json").write_text(json.dumps(cm))
    result = h.validate_dry_run_receipt(str(receipt_dir), plan_dir=str(plan_dir))
    assert result["status"] == "failed"

    receipt_dir, plan_dir, _ = make_receipt(tmp_path / "bytes")
    cm = json.loads((receipt_dir / "candidate-manifest.json").read_text())
    cm["candidates"][0]["size_bytes"] += 9
    (receipt_dir / "candidate-manifest.json").write_text(json.dumps(cm))
    result = h.validate_dry_run_receipt(str(receipt_dir), plan_dir=str(plan_dir))
    assert result["status"] == "failed"

    receipt_dir, plan_dir, _ = make_receipt(tmp_path / "class")
    cm = json.loads((receipt_dir / "candidate-manifest.json").read_text())
    cm["candidates"][0]["class"] = "storage_health_report_artifacts"
    (receipt_dir / "candidate-manifest.json").write_text(json.dumps(cm))
    result = h.validate_dry_run_receipt(str(receipt_dir), plan_dir=str(plan_dir))
    assert result["status"] == "failed"

    receipt_dir, _, _ = make_receipt(tmp_path / "invalid_plan")
    bad_plan = tmp_path / "bad-plan"
    bad_plan.mkdir()
    result = h.validate_dry_run_receipt(str(receipt_dir), plan_dir=str(bad_plan))
    assert result["status"] == "failed"
    assert result["summary"]["plan_cross_check_status"] == "failed"


def test_no_mutation_cli_or_shell_true_introduced():
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


def _mutate_receipt(receipt_dir: Path, path: list[str], value):
    doc = json.loads((receipt_dir / "artifact-archive-dry-run-receipt.json").read_text())
    cur = doc
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = value
    (receipt_dir / "artifact-archive-dry-run-receipt.json").write_text(json.dumps(doc))


def _mutate_candidate(receipt_dir: Path, new_path: str):
    doc = json.loads((receipt_dir / "candidate-manifest.json").read_text())
    doc["candidates"][0]["path"] = new_path
    (receipt_dir / "candidate-manifest.json").write_text(json.dumps(doc))


def _append_manifest(receipt_dir: Path, entry: dict):
    doc = json.loads((receipt_dir / "manifest.json").read_text())
    doc["files"].append(entry)
    (receipt_dir / "manifest.json").write_text(json.dumps(doc))


def _bump_manifest_size(receipt_dir: Path):
    doc = json.loads((receipt_dir / "manifest.json").read_text())
    doc["files"][0]["size_bytes"] += 1
    (receipt_dir / "manifest.json").write_text(json.dumps(doc))
