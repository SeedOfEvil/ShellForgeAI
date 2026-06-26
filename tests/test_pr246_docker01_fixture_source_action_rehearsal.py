import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "docker01_artifact_archive_plan.py"
CONFIRM = "CONFIRM_SHELLFORGEAI_FIXTURE_SOURCE_ACTION_REHEARSAL"
PLAN_ID = "sha256:0123456789abcdef"


def run_helper(*args):
    return subprocess.run(
        [sys.executable, str(HELPER), *map(str, args)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def fixture_root(tmp_path: Path) -> Path:
    return tmp_path / "sfai-fixture-source-action-pr246"


def test_happy_path_json_outputs_and_held_fixture(tmp_path):
    root = fixture_root(tmp_path)
    out = tmp_path / "sfai-pr246-out"
    res = run_helper(
        "--archive-source-action-fixture-rehearsal",
        "--fixture-root",
        root,
        "--plan-id",
        PLAN_ID,
        "--confirm",
        CONFIRM,
        "--out",
        out,
        "--json",
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["status"] == "rehearsal_passed"
    assert data["mode"] == "docker01_artifact_archive_source_action_fixture_rehearsal"
    assert data["fixture_only"] is True
    assert data["mutation_performed"] is True
    assert data["production_source_action_available"] is False
    assert data["production_cleanup_available"] is False
    assert data["safety"]["source_deleted"] is False
    assert data["safety"]["source_moved"] is False
    assert data["safety"]["source_modified"] is False
    assert data["rollback_proof"]["restored_source_matches_original"] is True
    assert (root / ".shellforgeai-fixture-root.json").is_file()
    assert not list((root / "source" / "sfai-fixture-artifacts").glob("*"))
    assert len(list((root / "rehearsal" / "held" / "sfai-fixture-artifacts").glob("*.held"))) == 2
    for name in [
        "fixture-source-action-rehearsal.json",
        "fixture-source-action-rehearsal-summary.md",
        "fixture-candidate-manifest.json",
        "fixture-archive-manifest.json",
        "fixture-rollback-proof.json",
        "fixture-safety-notes.md",
        "manifest.json",
        "checksums.json",
    ]:
        assert (out / name).is_file()
    checks = json.loads((out / "checksums.json").read_text())
    assert "fixture-source-action-rehearsal.json" in checks["checksums"]


def test_restore_before_exit_restores_sources_and_human_output(tmp_path):
    root = fixture_root(tmp_path)
    out = tmp_path / "sfai-pr246-out"
    res = run_helper(
        "--archive-source-action-fixture-rehearsal",
        "--fixture-root",
        root,
        "--plan-id",
        PLAN_ID,
        "--confirm",
        CONFIRM,
        "--restore-before-exit",
        "--out",
        out,
    )
    assert res.returncode == 0, res.stderr
    assert "# Docker01 Fixture Source-Action Rehearsal" in res.stdout
    assert "Production source action available: no" in res.stdout
    data = json.loads((out / "fixture-source-action-rehearsal.json").read_text())
    assert data["summary"]["source_restored_before_exit"] is True
    assert data["summary"]["fixture_files_restored"] == 2
    assert len(list((root / "source" / "sfai-fixture-artifacts").glob("sfai-fixture-*"))) == 2
    for item in data["fixture_candidate_manifest"]:
        assert item["original_sha256"] == item["archive_sha256"] == item["restored_sha256"]


def test_refuses_missing_or_wrong_confirmation_before_mutation(tmp_path):
    root = fixture_root(tmp_path)
    out = tmp_path / "out"
    for args in [(), ("--confirm", "WRONG")]:
        res = run_helper(
            "--archive-source-action-fixture-rehearsal",
            "--fixture-root",
            root,
            "--plan-id",
            PLAN_ID,
            "--out",
            out,
            *args,
            "--json",
        )
        assert res.returncode != 0
        assert not root.exists()
        assert not out.exists()


def test_refuses_missing_required_arguments(tmp_path):
    res = run_helper("--archive-source-action-fixture-rehearsal", "--confirm", CONFIRM)
    assert res.returncode != 0
    assert "requires --fixture-root" in res.stderr


def test_refuses_unsafe_fixture_roots_and_non_empty_unmarked(tmp_path):
    unsafe_roots = [
        Path("/tmp"),
        Path("/srv/sfai-fixture-source-action-x"),
        Path("/data/sfai-fixture-source-action-x"),
        Path("/var/lib/docker/sfai-fixture-source-action-x"),
        ROOT / "sfai-fixture-source-action-x",
    ]
    for root in unsafe_roots:
        res = run_helper(
            "--archive-source-action-fixture-rehearsal",
            "--fixture-root",
            root,
            "--plan-id",
            PLAN_ID,
            "--confirm",
            CONFIRM,
            "--out",
            tmp_path / ("out-" + str(abs(hash(str(root))))),
            "--json",
        )
        assert res.returncode != 0, root
    root = fixture_root(tmp_path)
    root.mkdir()
    (root / "foreign.txt").write_text("no")
    res = run_helper(
        "--archive-source-action-fixture-rehearsal",
        "--fixture-root",
        root,
        "--plan-id",
        PLAN_ID,
        "--confirm",
        CONFIRM,
        "--out",
        tmp_path / "out-x",
        "--json",
    )
    assert res.returncode != 0


def test_refuses_symlink_and_unsafe_output(tmp_path):
    root = fixture_root(tmp_path)
    root.mkdir()
    (root / ".shellforgeai-fixture-root.json").write_text("{}")
    (root / "link").symlink_to(tmp_path)
    res = run_helper(
        "--archive-source-action-fixture-rehearsal",
        "--fixture-root",
        root,
        "--plan-id",
        PLAN_ID,
        "--confirm",
        CONFIRM,
        "--out",
        tmp_path / "out",
        "--json",
    )
    assert res.returncode != 0

    root = tmp_path / "sfai-fixture-source-action-output"
    out = root / "source" / "bad"
    res = run_helper(
        "--archive-source-action-fixture-rehearsal",
        "--fixture-root",
        root,
        "--plan-id",
        PLAN_ID,
        "--confirm",
        CONFIRM,
        "--out",
        out,
        "--json",
    )
    assert res.returncode != 0
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "x").write_text("x")
    res = run_helper(
        "--archive-source-action-fixture-rehearsal",
        "--fixture-root",
        tmp_path / "sfai-fixture-source-action-y",
        "--plan-id",
        PLAN_ID,
        "--confirm",
        CONFIRM,
        "--out",
        nonempty,
        "--json",
    )
    assert res.returncode != 0


def test_no_forbidden_command_surface_or_shell_true_literals():
    source = HELPER.read_text()
    assert "--archive-source-action-fixture-rehearsal" in source
    assert "--fixture-root" in source
    assert "--restore-before-exit" in source
    for forbidden in [
        "--cleanup-now",
        "--execute-cleanup",
        "--delete",
        "--move",
        "--prune",
        "--restart",
        "--rm",
        "--rmi",
        "--apply",
        "--approve",
        "--merge",
        "--post-comment",
    ]:
        assert forbidden not in source
    assert "shell=True" not in source
