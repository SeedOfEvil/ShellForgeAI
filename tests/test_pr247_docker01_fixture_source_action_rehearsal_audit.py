import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "docker01_artifact_archive_plan.py"
CONFIRM = "CONFIRM_SHELLFORGEAI_FIXTURE_SOURCE_ACTION_REHEARSAL"
PLAN = "sha256:0123456789abcdef"


def run_helper(*args):
    return subprocess.run(
        [sys.executable, str(HELPER), *map(str, args)], cwd=ROOT, text=True, capture_output=True
    )


def make_rehearsal(tmp_path, name="a", plan=PLAN):
    fixture = tmp_path / f"sfai-fixture-source-action-{name}"
    out = tmp_path / f"rehearsal-{name}"
    res = run_helper(
        "--archive-source-action-fixture-rehearsal",
        "--fixture-root",
        fixture,
        "--plan-id",
        plan,
        "--confirm",
        CONFIRM,
        "--restore-before-exit",
        "--out",
        out,
        "--json",
    )
    assert res.returncode == 0, res.stderr + res.stdout
    return fixture, out


def audit(out, *extra):
    res = run_helper("--archive-source-action-fixture-audit", out, *extra, "--json")
    data = json.loads(res.stdout)
    return res, data


def test_happy_path_json_human_out_comparison_and_no_input_mutation(tmp_path):
    fixture, rehearsal = make_rehearsal(tmp_path, "a")
    before = {p.name: p.read_bytes() for p in rehearsal.iterdir() if p.is_file()}
    res, data = audit(rehearsal)
    assert res.returncode == 0
    assert data["mode"] == "docker01_artifact_archive_source_action_fixture_audit"
    assert data["status"] == "audit_passed"
    assert data["read_only"] is True
    assert data["mutation_performed"] is False
    assert data["fixture_only"] is True
    assert data["production_source_action_available"] is False
    assert data["production_cleanup_available"] is False
    assert data["summary"]["rollback_proof_ok"] is True
    assert data["summary"]["restore_proof_ok"] is True
    assert data["summary"]["path_guard_ok"] is True
    assert {p.name: p.read_bytes() for p in rehearsal.iterdir() if p.is_file()} == before
    assert len(list((fixture / "source" / "sfai-fixture-artifacts").glob("sfai-fixture-*"))) == 2

    human = run_helper("--archive-source-action-fixture-audit", rehearsal)
    assert human.returncode == 0
    assert "# Docker01 Fixture Source-Action Rehearsal Audit" in human.stdout
    assert "Production cleanup available: no" in human.stdout

    audit_dir = tmp_path / "audit"
    res, data = audit(rehearsal, "--out", audit_dir)
    assert res.returncode == 0
    for name in [
        "fixture-source-action-audit.json",
        "fixture-source-action-audit-summary.md",
        "fixture-candidate-audit.json",
        "fixture-rehearsal-comparison.json",
        "fixture-audit-safety-notes.md",
        "manifest.json",
        "checksums.json",
    ]:
        assert (audit_dir / name).is_file()
    checks = json.loads((audit_dir / "checksums.json").read_text())["checksums"]
    for name, expected in checks.items():
        import hashlib

        assert "sha256:" + hashlib.sha256((audit_dir / name).read_bytes()).hexdigest() == expected

    _, rehearsal_b = make_rehearsal(tmp_path, "b")
    res, data = audit(rehearsal, "--compare-to", rehearsal_b)
    assert res.returncode == 0
    assert data["comparison"]["status"] == "passed"


def test_blocking_refusals(tmp_path):
    _, rehearsal = make_rehearsal(tmp_path, "base")
    cases = []
    missing = tmp_path / "missing"
    missing.mkdir()
    for p in rehearsal.iterdir():
        if p.name != "fixture-rollback-proof.json":
            (missing / p.name).write_bytes(p.read_bytes())
    cases.append(missing)
    bad_json = tmp_path / "bad-json"
    bad_json.mkdir()
    for p in rehearsal.iterdir():
        (bad_json / p.name).write_bytes(p.read_bytes())
    (bad_json / "fixture-source-action-rehearsal.json").write_text("{")
    cases.append(bad_json)
    bad_checksum = tmp_path / "bad-checksum"
    bad_checksum.mkdir()
    for p in rehearsal.iterdir():
        (bad_checksum / p.name).write_bytes(p.read_bytes())
    (bad_checksum / "fixture-safety-notes.md").write_text("changed")
    cases.append(bad_checksum)
    for key, value in [
        ("fixture_only", False),
        ("production_source_action_available", True),
        ("production_cleanup_available", True),
    ]:
        d = tmp_path / f"bad-{key}"
        d.mkdir()
        for p in rehearsal.iterdir():
            (d / p.name).write_bytes(p.read_bytes())
        obj = json.loads((d / "fixture-source-action-rehearsal.json").read_text())
        obj[key] = value
        (d / "fixture-source-action-rehearsal.json").write_text(json.dumps(obj))
        cases.append(d)
    bad_proof = tmp_path / "bad-proof"
    bad_proof.mkdir()
    for p in rehearsal.iterdir():
        (bad_proof / p.name).write_bytes(p.read_bytes())
    proof = json.loads((bad_proof / "fixture-rollback-proof.json").read_text())
    proof["restored_source_matches_original"] = False
    (bad_proof / "fixture-rollback-proof.json").write_text(json.dumps(proof))
    cases.append(bad_proof)
    for flag in [
        "source_deleted",
        "source_moved",
        "source_modified",
        "source_copied",
        "cleanup_executed",
        "docker_prune_executed",
        "container_restarted",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
    ]:
        d = tmp_path / f"bad-{flag}"
        d.mkdir()
        for p in rehearsal.iterdir():
            (d / p.name).write_bytes(p.read_bytes())
        obj = json.loads((d / "fixture-source-action-rehearsal.json").read_text())
        obj.setdefault("safety", {})[flag] = True
        (d / "fixture-source-action-rehearsal.json").write_text(json.dumps(obj))
        cases.append(d)
    for d in cases:
        res, data = audit(d)
        assert res.returncode == 1, d.name
        assert data["status"] == "audit_failed"


def test_path_guards_symlink_escape_runtime_and_compare_plan(tmp_path):
    fixture, rehearsal = make_rehearsal(tmp_path, "paths")
    obj = json.loads((rehearsal / "fixture-source-action-rehearsal.json").read_text())
    for label, path in [("escape", str(tmp_path / "outside")), ("runtime", "/var/lib/docker/x")]:
        d = tmp_path / label
        d.mkdir()
        for p in rehearsal.iterdir():
            (d / p.name).write_bytes(p.read_bytes())
        changed = dict(obj)
        changed["fixture_candidate_manifest"] = [
            dict(obj["fixture_candidate_manifest"][0], fixture_source_path=path)
        ]
        (d / "fixture-source-action-rehearsal.json").write_text(json.dumps(changed))
        res, data = audit(d)
        assert res.returncode == 1
        assert data["summary"]["path_guard_ok"] is False

    link = fixture / "source" / "sfai-fixture-artifacts" / "link"
    link.symlink_to(
        fixture / "source" / "sfai-fixture-artifacts" / "sfai-fixture-qa-bundle-001.json"
    )
    d = tmp_path / "symlink"
    d.mkdir()
    for p in rehearsal.iterdir():
        (d / p.name).write_bytes(p.read_bytes())
    changed = dict(obj)
    changed["fixture_candidate_manifest"] = [
        dict(obj["fixture_candidate_manifest"][0], fixture_source_path=str(link))
    ]
    (d / "fixture-source-action-rehearsal.json").write_text(json.dumps(changed))
    res, data = audit(d)
    assert res.returncode == 1
    assert data["fixture_candidate_audit"][0]["symlink_detected"] is True

    _, other = make_rehearsal(tmp_path, "other", "sha256:fedcba9876543210")
    res, data = audit(rehearsal, "--compare-to", other)
    assert res.returncode == 1
    assert data["comparison"]["plan_id_match"] is False


def test_no_forbidden_source_patterns_or_cli_flags():
    source = HELPER.read_text()
    assert "shell=True" not in source
    for flag in [
        "--cleanup",
        "--execute-cleanup",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--rm",
        "--rmi",
        "--apply",
        "--execute",
        "--approve",
        "--merge",
        "--post-comment",
    ]:
        assert flag not in source
    assert "--archive-source-action-fixture-audit" in source
    assert "--compare-to" in source
