import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FINALIZER = ROOT / "scripts" / "docker01_validation_evidence.py"
VIEWER = ROOT / "scripts" / "validation_status.py"
LANE = ROOT / "scripts" / "sfai_docker01_pr_lane.py"
MERGE = ROOT / "scripts" / "docker01_merge_readiness.py"
FALLBACK = ROOT / "scripts" / "validation_container_fallback.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


finalizer = load(FINALIZER, "docker01_validation_evidence")
viewer = load(VIEWER, "validation_status_pr219")
lane = load(LANE, "sfai_lane_pr219")
merge = load(MERGE, "merge_pr219")
fallback = load(FALLBACK, "fallback_pr219")

PR = 219
COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def finalize(tmp_path, log_text, **kw):
    tmp_path.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "validation.log"
    log.write_text(log_text, encoding="utf-8")
    run_dir = tmp_path / kw.pop("name", "sfai-pr219-abcdef123456-validation-20260617T000000")
    return finalizer.finalize_validation_evidence(
        pr=PR,
        commit=COMMIT,
        log_path=log,
        run_dir=run_dir,
        lane=kw.pop("lane", "targeted"),
        commands=kw.pop(
            "commands",
            [{"key": "ruff", "argv": ["ruff", "check", "."], "status": "passed", "exit_code": 0}],
        ),
        **kw,
    )


def status_doc(run_dir):
    return json.loads((Path(run_dir) / "validation-status.json").read_text())


def test_passed_targeted_validation_writes_required_artifacts(tmp_path):
    result = finalize(tmp_path, "ruff passed\ncompileall passed\ntargeted tests passed\n")
    run_dir = Path(result["run_dir"])
    assert {
        "validation-status.json",
        "validation-manifest.json",
        "validation-summary.md",
        "commands-run.json",
        "source-log-excerpt.txt",
    } <= {p.name for p in run_dir.iterdir()}
    doc = status_doc(run_dir)
    assert doc["mode"] == "docker01_pr_lane_validation_status"
    assert doc["status"] == "passed"
    assert doc["classification"] == "passed"
    assert doc["pass_eligible"] is True
    assert doc["rerun_required"] is False
    assert doc["pr"] == PR and doc["commit"] == COMMIT


def test_full_validation_sets_full_flags(tmp_path):
    result = finalize(
        tmp_path,
        "full pytest passed 100%, exit 0\n",
        lane="full",
        full_validation=True,
        full_validation_reason="release lane",
    )
    doc = status_doc(result["run_dir"])
    assert doc["lane"] == "full"
    assert doc["full_validation"] is True
    assert doc["full_validation_reason"] == "release lane"


def test_manifest_has_sha256_sizes_and_summary_is_pasteable(tmp_path):
    result = finalize(tmp_path, "ruff passed\n")
    run_dir = Path(result["run_dir"])
    manifest = json.loads((run_dir / "validation-manifest.json").read_text())
    assert all(item["sha256"] and item["size_bytes"] > 0 for item in manifest["artifacts"])
    summary = (run_dir / "validation-summary.md").read_text()
    assert (
        "Docker01 PR Lane Validation Evidence" in summary
        and "does not run validation or QA" in summary
    )


def test_commands_json_and_excerpt_are_bounded(tmp_path):
    result = finalize(tmp_path, "x" * 20000 + "\nruff passed\n")
    run_dir = Path(result["run_dir"])
    commands = json.loads((run_dir / "commands-run.json").read_text())
    assert isinstance(commands, list) and commands[0]["key"] == "ruff"
    assert (run_dir / "source-log-excerpt.txt").stat().st_size <= finalizer.MAX_EXCERPT_BYTES + 100


def test_failed_and_setup_and_interrupted_unknown_never_pass_eligible(tmp_path):
    cases = [
        ("pytest failed\n", "failed"),
        ("ruff failed\n", "failed"),
        ("compileall failed\n", "failed"),
        ("missing pytest\n", "setup_failure"),
        ("missing procps in disposable wrapper\n", "setup_failure"),
        ("interrupted by SIGINT\n", "interrupted_or_incomplete"),
        ("some unrelated log\n", "unknown"),
    ]
    for idx, (text, classification) in enumerate(cases):
        result = finalize(tmp_path / str(idx), text, commands=[])
        doc = status_doc(result["run_dir"])
        assert doc["classification"] == classification
        assert doc["pass_eligible"] is False
        assert doc["rerun_required"] is True


def test_later_pass_beats_earlier_setup_for_same_pr_commit(tmp_path, monkeypatch):
    finalize(
        tmp_path,
        "missing pytest\n",
        name="sfai-pr219-abcdef123456-validation-20260617T000000",
        commands=[],
    )
    passed = finalize(
        tmp_path,
        "setup failure earlier\nruff passed\ncompileall passed\ntargeted tests passed\n",
        name="sfai-pr219-abcdef123456-validation-20260617T010000",
    )
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    report = viewer.generate_report(
        type(
            "Args",
            (),
            {
                "latest": True,
                "pr": PR,
                "commit": COMMIT,
                "include_legacy": False,
                "run_root": None,
                "explain_selection": True,
                "run_dir": None,
                "heartbeat": None,
                "status_file": None,
                "manifest": None,
                "summary": None,
                "log": None,
            },
        )()
    )
    assert report["status"] == "passed"
    assert report["pass_eligible"] is True
    assert report["source"]["run_dir"] == passed["run_dir"]
    assert any("ignored" in w for w in report["warnings"])


def test_later_failed_beats_earlier_setup_for_same_pr_commit(tmp_path, monkeypatch):
    finalize(
        tmp_path,
        "missing pytest\n",
        name="sfai-pr219-abcdef123456-validation-20260617T000000",
        commands=[],
    )
    failed = finalize(
        tmp_path,
        "pytest failed\n",
        name="sfai-pr219-abcdef123456-validation-20260617T020000",
        commands=[],
    )
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    report = viewer.generate_report(
        type(
            "Args",
            (),
            {
                "latest": True,
                "pr": PR,
                "commit": COMMIT,
                "include_legacy": False,
                "run_root": None,
                "explain_selection": True,
                "run_dir": None,
                "heartbeat": None,
                "status_file": None,
                "manifest": None,
                "summary": None,
                "log": None,
            },
        )()
    )
    assert report["status"] == "failed"
    assert report["source"]["run_dir"] == failed["run_dir"]


def test_different_commit_not_selected_and_not_found(tmp_path, monkeypatch):
    finalizer.finalize_validation_evidence(
        pr=PR,
        commit="deadbeef" * 5,
        log_path=tmp_path / "missing.log",
        run_dir=tmp_path / "sfai-pr219-deadbeefdead-validation-x",
        status="passed",
    )
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    args = type(
        "Args",
        (),
        {
            "latest": True,
            "pr": PR,
            "commit": COMMIT,
            "include_legacy": False,
            "run_root": None,
            "explain_selection": True,
            "run_dir": None,
            "heartbeat": None,
            "status_file": None,
            "manifest": None,
            "summary": None,
            "log": None,
        },
    )()
    report = viewer.generate_report(args)
    assert report["status"] == "not_found"


def test_lane_writer_uses_finalizer_and_does_not_rerun_validation(tmp_path):
    plan = lane.plan_docker01_lane(changed_files=["docs/VALIDATION_LANES.md"], pr_number=str(PR))
    manifest = lane.build_validation_manifest(
        plan, pr_number=str(PR), head_commit=COMMIT, status="passed"
    )
    out = tmp_path / "run"
    lane.write_lane_validation_evidence(
        run_dir=out,
        manifest=manifest,
        command_records=[],
        log_path=None,
        created_at="2026-06-17T00:00:00Z",
    )
    doc = status_doc(out)
    assert doc["source"]["kind"] == "docker01_validation_finalizer"
    assert doc["safety"]["validation_executed"] is False


def test_host_setup_failure_warning_plus_fallback_success_passes(tmp_path):
    result = finalize(
        tmp_path,
        (
            "environment preflight failed\nsetup failure\n"
            "ruff passed\ncompileall passed\ntargeted tests passed\n"
        ),
        warnings=["host setup_failure; disposable fallback succeeded"],
    )
    doc = status_doc(result["run_dir"])
    assert doc["status"] == "passed"
    assert doc["pass_eligible"] is True
    assert any("host setup_failure" in w for w in doc["warnings"])


def test_safety_source_contains_no_forbidden_execution_paths(tmp_path):
    src = FINALIZER.read_text(encoding="utf-8")
    forbidden = [
        "shell=True",
        "run_full_pytest",
        "docker compose",
        "docker restart",
        "docker system prune",
        "docker build",
        "post-comment",
        "approve",
        "gh pr merge",
        "--cleanup",
        "--prune",
        "--delete",
        "--restart",
        "--rm",
        "--rmi",
        "docker01_operator_qa_bundle",
    ]
    for item in forbidden:
        assert item not in src
    doc = finalizer.finalize_validation_evidence(
        pr=PR,
        commit=COMMIT,
        log_path=None,
        run_dir=tmp_path / "sfai-pr219-safety-test",
        status="unknown",
    )["status"]
    assert all(value is False for key, value in doc["safety"].items() if key != "read_only")


def test_generated_disposable_fallback_installs_procps_git_rsync_inside_container(tmp_path):
    command = fallback.build_container_command(
        run_dir=tmp_path,
        lane=fallback.LANE_FULL,
        pr=str(PR),
        commit=COMMIT,
        repo_root=ROOT,
    )
    preview = command["copy_paste"]
    assert "apt-get update" in preview
    assert "apt-get install -y --no-install-recommends procps git rsync" in preview
    assert command["container_packages"] == ["procps", "git", "rsync"]
    assert "tests/test_investigation_tools.py" not in preview
    assert " -k " not in preview and "--ignore" not in preview and "--deselect" not in preview


def test_generated_fallback_package_install_is_container_only_and_inert(tmp_path):
    report = fallback.generate_packet(
        run_dir=tmp_path,
        lane=fallback.LANE_FULL,
        pr=str(PR),
        commit=COMMIT,
        force=True,
    )
    container = report["container_validation"]
    assert container["host_package_install_required"] is False
    assert container["container_packages"] == ["procps", "git", "rsync"]
    assert report["safety"]["packages_installed"] is False
    assert report["safety"]["validation_executed"] is False
    assert (
        "apt-get install -y --no-install-recommends procps git rsync"
        in container["command_preview"]
    )


def test_generated_fallback_command_safety_surfaces_no_host_mutation_options(tmp_path):
    report = fallback.generate_packet(
        run_dir=tmp_path, lane=fallback.LANE_FULL, pr=str(PR), commit=COMMIT, force=True
    )
    surfaces = [
        report["container_validation"]["command_preview"],
        " ".join(report["container_validation"]["command_argv"]),
        (tmp_path / fallback.FALLBACK_COMMAND_NAME).read_text(encoding="utf-8"),
    ]
    forbidden = [
        "shell=True",
        "docker compose",
        "docker restart",
        "docker system prune",
        "--cleanup",
        "--delete",
        "--prune",
        "--restart",
        "--post-comment",
        "--approve",
        "gh pr merge",
    ]
    for surface in surfaces:
        for item in forbidden:
            assert item not in surface


def _passed_preflight(path=None):
    return {
        "schema_version": 1,
        "mode": "validation_environment_preflight",
        "status": "passed",
        "classification": "passed",
        "failed_checks": [],
        "warning_checks": [],
        "path": str(path) if path else None,
    }


def test_standard_lane_execute_success_auto_finalizes_exact_commit(tmp_path, monkeypatch):
    run_dir = tmp_path / "sfai-pr219-abcdef123456-validation-auto"
    monkeypatch.setattr(
        lane.validation_env_preflight, "run_preflight", lambda **_: _passed_preflight()
    )
    monkeypatch.setattr(
        lane.validation_env_preflight,
        "write_report",
        lambda report, path: Path(path).write_text(json.dumps(report)),
    )

    def fake_run_validation(plan, *, return_records, log_path, heartbeat, record_sink):
        records = []
        for command in plan["_commands"]:
            phase = lane.validation_heartbeat.COMMAND_KIND_TO_PHASE.get(command["kind"])
            if phase:
                heartbeat.start_phase(phase)
                if command["kind"] == "pytest_full_runner":
                    heartbeat.record_full_pytest_exit(0, phase=phase)
                else:
                    heartbeat.complete_phase(phase, status="passed")
            record = lane._command_record(
                command, status="passed", duration=0.01, log_path=log_path
            )
            records.append(record)
            record_sink.append(record)
        return 0, records

    monkeypatch.setattr(lane, "run_validation", fake_run_validation)
    rc = lane.main(
        [
            "--changed-files",
            "src/shellforgeai/core/ask_routing.py",
            "--pr",
            str(PR),
            "--commit",
            COMMIT,
            "--execute-validation",
            "--run-dir",
            str(run_dir),
        ]
    )
    assert rc == 0
    doc = status_doc(run_dir)
    assert doc["status"] == "passed"
    assert doc["classification"] == "passed"
    assert doc["pass_eligible"] is True
    assert doc["commit"] == COMMIT
    assert doc["source"]["kind"] == "docker01_validation_finalizer"


def test_standard_lane_full_execute_success_preserves_full_metadata(tmp_path, monkeypatch):
    run_dir = tmp_path / "sfai-pr219-abcdef123456-validation-full"
    monkeypatch.setattr(
        lane.validation_env_preflight, "run_preflight", lambda **_: _passed_preflight()
    )
    monkeypatch.setattr(
        lane.validation_env_preflight,
        "write_report",
        lambda report, path: Path(path).write_text(json.dumps(report)),
    )

    def fake_full(plan, *, return_records, log_path, heartbeat, record_sink):
        records = []
        for command in plan["_commands"]:
            phase = lane.validation_heartbeat.COMMAND_KIND_TO_PHASE.get(command["kind"])
            if phase:
                heartbeat.start_phase(phase)
                if command["kind"] == "pytest_full_runner":
                    heartbeat.record_full_pytest_exit(0, phase=phase)
                else:
                    heartbeat.complete_phase(phase, status="passed")
            record = lane._command_record(
                command, status="passed", duration=0.01, log_path=log_path
            )
            records.append(record)
            record_sink.append(record)
        return 0, records

    monkeypatch.setattr(lane, "run_validation", fake_full)
    assert (
        lane.main(
            [
                "--changed-files",
                "Dockerfile",
                "--pr",
                str(PR),
                "--commit",
                COMMIT,
                "--full-validation",
                "--full-validation-reason",
                "operator requested Lane C",
                "--execute-validation",
                "--run-dir",
                str(run_dir),
            ]
        )
        == 0
    )
    doc = status_doc(run_dir)
    assert doc["full_validation"] is True
    assert doc["full_validation_reason"] == "operator requested Lane C"


def test_standard_lane_execute_failure_auto_finalizes_failed(tmp_path, monkeypatch):
    run_dir = tmp_path / "sfai-pr219-abcdef123456-validation-failed"
    monkeypatch.setattr(
        lane.validation_env_preflight, "run_preflight", lambda **_: _passed_preflight()
    )
    monkeypatch.setattr(
        lane.validation_env_preflight,
        "write_report",
        lambda report, path: Path(path).write_text(json.dumps(report)),
    )

    def fake_failed(plan, *, return_records, log_path, heartbeat, record_sink):
        command = plan["_commands"][0]
        phase = lane.validation_heartbeat.COMMAND_KIND_TO_PHASE.get(command["kind"])
        heartbeat.start_phase(phase)
        heartbeat.complete_phase(phase, status="failed")
        record = lane._command_record(command, status="failed", duration=0.01, log_path=log_path)
        record_sink.append(record)
        return 1, [record]

    monkeypatch.setattr(lane, "run_validation", fake_failed)
    assert (
        lane.main(
            [
                "--changed-files",
                "src/shellforgeai/core/ask_routing.py",
                "--pr",
                str(PR),
                "--commit",
                COMMIT,
                "--execute-validation",
                "--run-dir",
                str(run_dir),
            ]
        )
        == 1
    )
    doc = status_doc(run_dir)
    assert doc["status"] == "failed"
    assert doc["pass_eligible"] is False
    assert doc["rerun_required"] is True


def test_standard_lane_setup_failure_auto_finalizes_setup_failure(tmp_path, monkeypatch):
    run_dir = tmp_path / "sfai-pr219-abcdef123456-validation-setup"
    report = _passed_preflight()
    report.update(
        {"status": "failed", "classification": "setup_failure", "failed_checks": ["pytest"]}
    )
    monkeypatch.setattr(lane.validation_env_preflight, "run_preflight", lambda **_: report)
    monkeypatch.setattr(
        lane.validation_env_preflight,
        "write_report",
        lambda report, path: Path(path).write_text(json.dumps(report)),
    )
    monkeypatch.setattr(
        lane.validation_container_fallback, "generate_packet", lambda **_: {"status": "created"}
    )
    assert (
        lane.main(
            [
                "--changed-files",
                "src/shellforgeai/core/ask_routing.py",
                "--pr",
                str(PR),
                "--commit",
                COMMIT,
                "--execute-validation",
                "--run-dir",
                str(run_dir),
            ]
        )
        == 1
    )
    doc = status_doc(run_dir)
    assert doc["status"] == "setup_failure"
    assert doc["classification"] == "setup_failure"
    assert doc["pass_eligible"] is False


def test_validation_status_exposes_full_validation_metadata(tmp_path, monkeypatch):
    finalize(
        tmp_path,
        "full pytest passed 100%, exit 0\n",
        lane="full",
        full_validation=True,
        full_validation_reason="Lane C",
    )
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    args = type(
        "Args",
        (),
        {
            "latest": True,
            "pr": PR,
            "commit": COMMIT,
            "include_legacy": False,
            "run_root": None,
            "explain_selection": True,
            "run_dir": None,
            "heartbeat": None,
            "status_file": None,
            "manifest": None,
            "summary": None,
            "log": None,
        },
    )()
    report = viewer.generate_report(args)
    assert report["full_validation"] is True
    assert report["full_validation_reason"] == "Lane C"


def test_pr_lane_status_sees_auto_finalizer_pass_eligible(tmp_path, monkeypatch):
    result = finalize(tmp_path, "ruff passed\ncompileall passed\ntargeted tests passed\n")
    monkeypatch.setenv(viewer.RUNS_DIR_ENV, str(tmp_path))
    monkeypatch.setattr(lane, "_status_git_head", lambda **_: COMMIT)
    monkeypatch.setattr(
        lane, "_read_compose_image", lambda: f"lab/shellforgeai:pr{PR}-{COMMIT[:7]}"
    )
    monkeypatch.setattr(
        lane,
        "_status_container",
        lambda **_: {
            "container_image": f"lab/shellforgeai:pr{PR}-{COMMIT[:7]}",
            "container_image_id": "sha256:x",
            "container_status": "running",
            "container_health": "healthy",
            "restart_count": 0,
            "labels": {"homelab.pr": str(PR), "homelab.commit": COMMIT},
        },
    )
    monkeypatch.setattr(
        lane,
        "_qa_bundle_latest",
        lambda pr, commit: {
            "available": True,
            "status": "passed",
            "bundle_path": str(tmp_path / "qa"),
            "commands_passed": 1,
            "commands_failed": 0,
            "safety_assertions_failed": 0,
        },
    )
    doc = lane.build_pr_lane_status(pr=PR, commit=COMMIT)
    assert doc["status"] == "already_complete"
    assert doc["validation"]["pass_eligible"] is True
    assert doc["validation"]["run_dir"] == result["run_dir"]


def test_merge_readiness_and_comment_preserve_full_validation_true(monkeypatch, tmp_path):
    validation_doc = {
        "status": "passed",
        "classification": "passed",
        "pass_eligible": True,
        "rerun_required": False,
        "full_validation": True,
        "full_validation_reason": "Lane C",
        "source": {"run_dir": str(tmp_path / "run")},
    }
    lane_doc = {
        "status": "already_complete",
        "state": {"container_status": "running", "container_health": "healthy", "restart_count": 0},
        "checks": [
            {"name": "source_head_matches", "passed": True},
            {"name": "compose_image_matches", "passed": True},
            {"name": "container_labels_match", "passed": True},
            {"name": "container_image_matches", "passed": True},
            {"name": "container_running", "passed": True},
            {"name": "container_healthy", "passed": True},
            {"name": "restart_count_acceptable", "passed": True},
        ],
    }
    monkeypatch.setenv("SFAI_QA_BUNDLE_ROOT", str(tmp_path))
    from test_pr216_docker01_merge_readiness import write_qa

    write_qa(tmp_path, pr=PR, commit=COMMIT)
    monkeypatch.setattr(merge, "load_pr_lane_status", lambda pr, commit: lane_doc)
    monkeypatch.setattr(merge, "load_validation_status", lambda pr, commit: validation_doc)
    report, _raw = merge.build_report(PR, COMMIT, created_at="2026-06-17T00:00:00Z")
    assert report["status"] == "pass_candidate"
    assert report["summary"]["full_pytest_run"] is True
    assert report["evidence"]["validation"]["full_validation"] is True
    assert "Full pytest: true" in merge.render_comment(report)
