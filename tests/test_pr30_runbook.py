"""PR30: evidence-backed operator runbook / safe fix plan tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from shellforgeai.core.ask_routing import (
    EVIDENCE_BACKED,
    is_fix_plan_intent,
    route_ask_intent,
)
from shellforgeai.core.evidence import (
    EvidenceBundle,
    EvidenceCategory,
    EvidenceItem,
    TargetType,
)
from shellforgeai.core.runbook import (
    SAFETY_LINE,
    build_runbook,
    latest_evidence_artifact,
    render_runbook_md,
    runbook_from_evidence_file,
)

# ---------- Fixtures ----------


def _docker_problem_summary_payload() -> dict:
    return {
        "available": True,
        "total": 6,
        "failing": [
            {
                "name": "sfai-missing-env",
                "image": "img",
                "state": "exited",
                "status": "Exited (42)",
                "exit_code": 42,
                "restart_count": 0,
                "health": None,
                "oom_killed": False,
                "log_themes": {"missing_required_setting": 1, "error_line": 1},
                "log_sample": ["ERROR REQUIRED_SETTING is missing"],
            },
            {
                "name": "sfai-bad-volume-perms",
                "image": "img",
                "state": "exited",
                "status": "Exited (1)",
                "exit_code": 1,
                "restart_count": 0,
                "health": None,
                "oom_killed": False,
                "log_themes": {"read_only_fs": 1, "permission_denied": 1, "error_line": 1},
                "log_sample": [
                    "ERROR cannot create /data/out.txt: read-only file system",
                    "permission denied opening /data/out.txt",
                ],
            },
            {
                "name": "sfai-restart-loop",
                "image": "img",
                "state": "restarting",
                "status": "Restarting",
                "exit_code": 1,
                "restart_count": 5,
                "health": None,
                "oom_killed": False,
                "log_themes": {"simulated_crash": 6},
                "log_sample": ["Simulated crash before startup"],
            },
        ],
        "noisy": [
            {
                "name": "sfai-bad-network",
                "image": "img",
                "state": "running",
                "status": "Up",
                "exit_code": 0,
                "restart_count": 0,
                "health": None,
                "oom_killed": False,
                "log_themes": {"dns_failure": 2, "error_line": 1},
                "log_sample": [
                    "Could not resolve host upstream.invalid",
                    "temporary failure in name resolution",
                ],
            },
            {
                "name": "sfai-noisy-logs",
                "image": "img",
                "state": "running",
                "status": "Up",
                "exit_code": 0,
                "restart_count": 0,
                "health": None,
                "oom_killed": False,
                "log_themes": {"warn_line": 1, "error_line": 1},
                "log_sample": ["WARN slow", "ERROR something noisy"],
            },
        ],
        "healthy": [],
    }


def _docker_inventory_payload() -> dict:
    return {
        "containers": [
            {"name": "sfai-healthy-web", "image": "nginx", "state": "running", "status": "Up"},
            {
                "name": "sfai-missing-env",
                "image": "img",
                "state": "exited",
                "status": "Exited (42)",
            },
            {
                "name": "sfai-bad-volume-perms",
                "image": "img",
                "state": "exited",
                "status": "Exited (1)",
            },
            {
                "name": "sfai-restart-loop",
                "image": "img",
                "state": "restarting",
                "status": "Restarting",
            },
            {"name": "sfai-bad-network", "image": "img", "state": "running", "status": "Up"},
            {"name": "sfai-noisy-logs", "image": "img", "state": "running", "status": "Up"},
        ],
        "total": 6,
    }


def _docker_evidence() -> list[EvidenceItem]:
    return [
        EvidenceItem(
            source="docker.containers",
            category=EvidenceCategory.service,
            ok=True,
            title="Docker containers",
            summary="docker containers=6",
            content=json.dumps(_docker_inventory_payload()),
        ),
        EvidenceItem(
            source="docker.problem_summary",
            category=EvidenceCategory.logs,
            ok=True,
            title="Docker problem summary",
            summary="failing=3 noisy=2",
            content=json.dumps(_docker_problem_summary_payload()),
        ),
    ]


# ---------- build_runbook ----------


def test_build_runbook_includes_all_lab_failures():
    rb = build_runbook(
        session_id="sf_test",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    names = " | ".join(p.name for p in rb.problems)
    assert "sfai-missing-env: missing-env" in names
    assert "sfai-bad-volume-perms: bad-volume-perms" in names
    assert "sfai-restart-loop: restart-loop" in names
    assert "sfai-bad-network: bad-network" in names


def test_runbook_treats_noisy_as_lower_priority():
    rb = build_runbook(
        session_id="sf_test",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    titles = [opt.title for opt in rb.operator_steps]
    # noisy-logs option is last
    noisy_idx = next(i for i, t in enumerate(titles) if "sfai-noisy-logs" in t)
    assert noisy_idx == len(titles) - 1
    # And the noisy option is risk=low
    noisy_opt = rb.operator_steps[noisy_idx]
    assert noisy_opt.risk == "low"


def test_runbook_marks_healthy_web_as_known_good():
    rb = build_runbook(
        session_id="sf_test",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    # healthy-web should not appear in problems
    assert all("sfai-healthy-web" not in p.name for p in rb.problems)
    # Should be mentioned in safety_notes as known-good baseline
    assert any("sfai-healthy-web" in s for s in rb.safety_notes)


def test_runbook_safety_line_present():
    rb = build_runbook(
        session_id="sf_test",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    md = render_runbook_md(rb)
    assert SAFETY_LINE in md


def test_runbook_mutating_steps_labelled_operator_run():
    rb = build_runbook(
        session_id="sf_test",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    md = render_runbook_md(rb)
    # Every option's steps include OPERATOR-RUN
    for opt in rb.operator_steps:
        if opt.steps:
            joined = "\n".join(opt.steps)
            assert "OPERATOR-RUN" in joined or "operator-run" in joined.lower()
    # SERVICE-IMPACTING / REQUIRES APPROVAL appear for at least one option
    assert "SERVICE-IMPACTING" in md or "REQUIRES APPROVAL" in md


def test_runbook_render_includes_sections():
    rb = build_runbook(
        session_id="sf_test",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    md = render_runbook_md(rb)
    for section in (
        "# ShellForgeAI Operator Runbook",
        "## Executive summary",
        "## Problems found",
        "## Pre-checks before changing anything",
        "## Operator-run remediation options",
        "## Recommended order",
        "## Post-fix validation",
        "## Rollback notes",
        "## Safety note",
    ):
        assert section in md


def test_runbook_json_is_valid():
    rb = build_runbook(
        session_id="sf_test",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    payload = json.loads(rb.model_dump_json())
    assert payload["session_id"] == "sf_test"
    assert payload["target"] == "docker"
    assert "operator_steps" in payload
    assert payload["risk_level"] in {"low", "medium", "high"}


def test_runbook_problems_include_severity_and_evidence():
    rb = build_runbook(
        session_id="sf_test",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    restart_problem = next(p for p in rb.problems if "sfai-restart-loop" in p.name)
    assert restart_problem.severity == "critical"
    assert any("log_themes" in e for e in restart_problem.evidence)


def test_runbook_with_no_failures_yields_empty_options():
    items = [
        EvidenceItem(
            source="docker.problem_summary",
            category=EvidenceCategory.logs,
            ok=True,
            title="Docker problem summary",
            summary="failing=0 noisy=0",
            content=json.dumps({"available": True, "total": 0, "failing": [], "noisy": []}),
        ),
    ]
    rb = build_runbook(session_id="sf_x", target="docker", evidence_items=items)
    assert rb.problems == []
    assert rb.operator_steps == []
    assert SAFETY_LINE in render_runbook_md(rb)


# ---------- Package / file-owner / config-changes ----------


def test_runbook_nginx_not_installed_does_not_blindly_install():
    items = [
        EvidenceItem(
            source="package.query",
            category=EvidenceCategory.packages,
            ok=True,
            title="package.query nginx",
            summary="installed=False",
            content=json.dumps(
                {
                    "query": "nginx",
                    "manager": "apt/dpkg",
                    "installed": False,
                    "raw_status": "not-installed",
                }
            ),
        ),
    ]
    rb = build_runbook(session_id="sf_x", target="packages:nginx", evidence_items=items)
    titles = " | ".join(o.title for o in rb.operator_steps)
    md = render_runbook_md(rb)
    assert "nginx" in titles.lower() or "nginx" in md.lower()
    # First step is confirmation, not install
    nginx_opt = rb.operator_steps[0]
    assert "Confirm" in nginx_opt.title or "confirm" in nginx_opt.preconditions[0]
    # An install step exists but is REQUIRES APPROVAL
    install_steps = [s for s in nginx_opt.steps if "apt install" in s]
    assert install_steps, "expected an install step for guidance"
    assert all("REQUIRES APPROVAL" in s for s in install_steps)
    assert nginx_opt.risk == "low"


def test_runbook_docker_cli_mount_is_documentation_only():
    items = [
        EvidenceItem(
            source="package.file_owner",
            category=EvidenceCategory.packages,
            ok=True,
            title="package.file_owner /usr/local/bin/docker",
            summary="not_owned",
            content=json.dumps(
                {
                    "path": "/usr/local/bin/docker",
                    "exists": True,
                    "owner_status": "not_owned",
                    "manager": "apt/dpkg",
                }
            ),
        ),
        EvidenceItem(
            source="storage.mounts",
            category=EvidenceCategory.host,
            ok=True,
            title="mounts",
            summary="bind /usr/bin/docker -> /usr/local/bin/docker (ro)",
            content="/usr/bin/docker on /usr/local/bin/docker type bind (ro)",
        ),
    ]
    rb = build_runbook(session_id="sf_x", target="package-owner", evidence_items=items)
    assert rb.operator_steps, "expected a documentation option"
    opt = rb.operator_steps[0]
    assert opt.risk == "low"
    assert "no fix" in opt.title.lower() or "intentional" in opt.title.lower()


def test_runbook_config_change_recommends_backup_validate():
    items = [
        EvidenceItem(
            source="config.recent_changes",
            category=EvidenceCategory.files,
            ok=True,
            title="recent changes",
            summary="changes=2",
            content="2026-05-09 /etc/nginx/nginx.conf\n2026-05-09 /etc/hosts\n",
        ),
    ]
    rb = build_runbook(session_id="sf_x", target="config", evidence_items=items)
    assert rb.operator_steps
    opt = rb.operator_steps[0]
    text = " ".join(opt.steps + opt.preconditions).lower()
    assert "back up" in text or "backup" in text
    assert any("validate" in s.lower() for s in opt.steps)


# ---------- Safety: no execution ----------


def test_runbook_module_does_not_invoke_subprocess(monkeypatch):
    """Building/rendering a runbook must never shell out."""

    from shellforgeai.util import subprocess as sub

    def boom(*a, **kw):  # pragma: no cover - should never run
        raise AssertionError("runbook synthesis must be fully read-only")

    monkeypatch.setattr(sub, "run_command", boom)
    rb = build_runbook(
        session_id="sf_test",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    render_runbook_md(rb)


def test_apply_remains_validation_only(tmp_path):
    """Apply still refuses to execute."""

    from shellforgeai.cli import apply
    from shellforgeai.core.plans import Plan, PlanStep

    p = Plan(
        plan_id="p",
        goal="g",
        session_id="s",
        steps=[PlanStep(step_id="1", title="t", description="d")],
    )
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(p.model_dump_json(), encoding="utf-8")
    # Should not raise; returns silently after printing.
    apply(plan_file)


# ---------- Routing ----------


def test_route_ask_intent_safe_fix_plan_for_failed_containers():
    route = route_ask_intent("give me a safe fix plan for the failed containers")
    assert route.mode == EVIDENCE_BACKED
    assert route.fix_plan is True
    assert route.target == "docker"
    assert route.intent_label == "fix_plan"


def test_route_ask_intent_what_should_i_do_next():
    route = route_ask_intent("what should I do next?")
    assert route.mode == EVIDENCE_BACKED
    assert route.fix_plan is True


def test_route_ask_intent_fix_bad_network_safely():
    route = route_ask_intent("fix bad-network safely")
    assert route.mode == EVIDENCE_BACKED
    assert route.fix_plan is True
    assert route.target == "docker"


def test_route_ask_intent_fix_write_permissions_safely():
    route = route_ask_intent("fix write permissions safely")
    assert route.mode == EVIDENCE_BACKED
    assert route.fix_plan is True


def test_route_ask_intent_fix_missing_env_safely():
    route = route_ask_intent("fix missing env safely")
    assert route.mode == EVIDENCE_BACKED
    assert route.fix_plan is True
    assert route.target == "docker"


def test_route_ask_intent_runbook_typos():
    for q in (
        "create a runbook for the latest diagnosis",
        "make me a runbok",
        "give me a runboook",
        "remeditation plan",
        "remdiation steps",
        "safe fix paln",
    ):
        route = route_ask_intent(q)
        assert route.fix_plan is True, q


def test_is_fix_plan_intent_negative():
    assert is_fix_plan_intent("hello world") is False
    assert is_fix_plan_intent("how is the weather") is False


# ---------- Artifact / on-disk ----------


def _write_evidence_bundle(dirpath: Path) -> Path:
    bundle = EvidenceBundle(
        target="docker",
        target_type=TargetType.service,
        created_at=datetime.now(timezone.utc),
        items=_docker_evidence(),
    )
    p = dirpath / "evidence.json"
    p.write_text(bundle.model_dump_json(), encoding="utf-8")
    return p


def test_runbook_from_evidence_file(tmp_path):
    sess_dir = tmp_path / "sf_20260509_000000_aaaaaa"
    sess_dir.mkdir()
    ev = _write_evidence_bundle(sess_dir)
    rb = runbook_from_evidence_file(ev)
    assert rb.session_id == sess_dir.name
    assert rb.problems
    assert any("sfai-missing-env" in p.name for p in rb.problems)
    assert str(ev) in rb.source_artifacts


def test_latest_evidence_artifact(tmp_path):
    artifacts_root = tmp_path / "artifacts"
    a = artifacts_root / "sf_20260509_000000_aaaaaa"
    a.mkdir(parents=True)
    _write_evidence_bundle(a)
    b = artifacts_root / "sf_20260509_120000_bbbbbb"
    b.mkdir(parents=True)
    p2 = _write_evidence_bundle(b)
    import os
    import time

    # ensure b is newer
    now = time.time()
    os.utime(p2, (now + 5, now + 5))
    latest = latest_evidence_artifact(tmp_path)
    assert latest == p2


def test_runbook_cli_writes_artifacts(tmp_path):
    """End-to-end: `shellforgeai runbook <evidence.json>` writes runbook files."""

    from typer.testing import CliRunner

    from shellforgeai.cli import app

    sess_dir = tmp_path / "sf_test_session"
    sess_dir.mkdir()
    ev = _write_evidence_bundle(sess_dir)
    runner = CliRunner()
    result = runner.invoke(app, ["runbook", str(ev)])
    assert result.exit_code == 0, result.output
    assert (sess_dir / "runbook.md").exists()
    assert (sess_dir / "runbook.json").exists()
    md = (sess_dir / "runbook.md").read_text(encoding="utf-8")
    assert SAFETY_LINE in md
    assert "sfai-missing-env" in md
    # Validate runbook.json shape
    rb_json = json.loads((sess_dir / "runbook.json").read_text(encoding="utf-8"))
    assert rb_json["session_id"]
    assert "operator_steps" in rb_json


def test_runbook_cli_requires_an_input(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from shellforgeai.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["runbook"])
    assert result.exit_code != 0


# ---------- Risk scoring ----------


def test_risk_level_promoted_when_any_option_medium_or_higher():
    rb = build_runbook(
        session_id="sf_x",
        target="docker",
        evidence_items=_docker_evidence(),
    )
    # Has missing-env (medium), restart-loop (medium), bad-network (medium) -> overall medium
    assert rb.risk_level == "medium"


def test_risk_level_low_when_only_noisy_or_documentation():
    items = [
        EvidenceItem(
            source="docker.problem_summary",
            category=EvidenceCategory.logs,
            ok=True,
            title="Docker problem summary",
            summary="noisy=1",
            content=json.dumps(
                {
                    "available": True,
                    "total": 1,
                    "failing": [],
                    "noisy": [
                        {
                            "name": "sfai-noisy-logs",
                            "image": "img",
                            "state": "running",
                            "status": "Up",
                            "exit_code": 0,
                            "log_themes": {"warn_line": 1, "error_line": 1},
                            "log_sample": ["WARN x", "ERROR y"],
                        }
                    ],
                }
            ),
        ),
    ]
    rb = build_runbook(session_id="sf_x", target="docker", evidence_items=items)
    assert rb.risk_level == "low"


# ---------- Diagnose --with-runbook ----------


def test_diagnose_with_runbook_writes_runbook(tmp_path, monkeypatch):
    """`diagnose docker --with-runbook` should produce runbook.md alongside evidence."""

    from typer.testing import CliRunner

    from shellforgeai.cli import app
    from shellforgeai.core import diagnose as diag_mod
    from shellforgeai.core.diagnose import DiagnosisResult, Finding
    from shellforgeai.core.plans import Plan

    bundle = EvidenceBundle(
        target="docker",
        target_type=TargetType.service,
        created_at=datetime.now(timezone.utc),
        items=_docker_evidence(),
    )
    fake_result = DiagnosisResult(
        session_id="sf_fake",
        target="docker",
        target_type=TargetType.service,
        evidence=bundle,
        findings=[Finding(severity="warning", title="sfai-missing-env exited 42", detail="x")],
        proposed_plan=Plan(plan_id="p", goal="g", session_id="sf_fake", steps=[]),
    )

    def fake_diag(runtime, target, online=False, since="30m"):
        return fake_result

    monkeypatch.setattr(diag_mod, "diagnose_target", fake_diag)
    # patch the imported binding inside cli too
    from shellforgeai import cli as cli_mod

    monkeypatch.setattr(cli_mod, "diagnose_target", fake_diag)
    # redirect data_dir
    monkeypatch.setenv("HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["diagnose", "docker", "--with-runbook"])
    assert result.exit_code == 0, result.output
    # Find the runbook artifact
    runbooks = list(Path(tmp_path).rglob("runbook.md"))
    assert runbooks, f"no runbook.md found under {tmp_path}\n{result.output}"
    md = runbooks[0].read_text(encoding="utf-8")
    assert SAFETY_LINE in md
    assert "sfai-missing-env" in md


# ---------- Regression: PR27/28/29 routing still healthy ----------


def test_pr27_failed_containers_routing_still_works():
    route = route_ask_intent("find failed containers and explain likely cause")
    assert route.mode == EVIDENCE_BACKED
    assert route.target == "docker"


def test_pr28_network_reachability_still_routes():
    route = route_ask_intent("network reachability is broken")
    assert route.mode == EVIDENCE_BACKED
    assert route.target == "docker"
    assert route.network_reachability is True


def test_pr29_path_owner_still_routes():
    route = route_ask_intent("what owns /usr/local/bin/docker?")
    assert route.mode == EVIDENCE_BACKED
    assert route.target.startswith("package-owner")
