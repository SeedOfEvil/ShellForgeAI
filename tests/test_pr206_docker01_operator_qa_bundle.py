"""PR206 — Docker01 operator QA evidence bundle helper.

These tests exercise ``scripts/docker01_operator_qa_bundle.py`` with a fake
command runner. They prove the helper:

* runs on the Docker01 host: ShellForgeAI product smoke commands execute inside
  the running container via a narrow ``docker exec shellforgeai shellforgeai ...``
  allowlist (no host ``shellforgeai`` on PATH required), while host checks
  (``docker ps``/``docker inspect``/``df``/validation status) stay host-side and
  validation status uses the current Python interpreter,
* writes the required bounded bundle files and strict JSON,
* dry-runs safely (lists planned commands, executes nothing, writes nothing),
* enforces a small fixed command allowlist that rejects dangerous families
  (including ``docker exec`` of a shell or any other binary),
* parses the key JSON outputs and evaluates explicit safety assertions,
* and degrades cleanly on command failure (partial/failed) while preserving
  raw stdout/stderr/exit codes.

The tests never require a Docker daemon, never run real Docker, never mutate
real ``/data``, and never touch the network: every command result is supplied by
an in-process fake runner.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
HELPER_PATH = SCRIPTS / "docker01_operator_qa_bundle.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


qa = _load("pr206_qa_bundle", HELPER_PATH)


# --------------------------------------------------------------------------- #
# Fake command outputs
# --------------------------------------------------------------------------- #

PR = 206
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _specs():
    """Planned specs for the PR/commit under test (validation status is scoped)."""
    return qa.build_command_specs(PR, COMMIT)


def _check_json(profile: str, mode: str) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "mode": mode,
            "profile": profile,
            "status": "ok",
            "summary": {"passed": 7, "failed": 0, "warned": 0, "skipped": 0},
            "checks": [],
        }
    )


def _safety_block(**overrides) -> dict:
    block = {
        "read_only": True,
        "mutation_performed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "docker_compose_executed": False,
        "container_restarted": False,
        "production_restart_executed": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "natural_language_execution": False,
    }
    block.update(overrides)
    return block


def _ops_report_json(**overrides) -> str:
    payload = {
        "schema_version": "1",
        "mode": "ops_report",
        "status": "empty",
        "read_only": True,
        "mutation_performed": False,
        "summary": {"containers_seen": 0},
        "safety": _safety_block(),
    }
    payload.update(overrides)
    return json.dumps(payload)


def _remediation_json(**overrides) -> str:
    payload = {
        "schema_version": "1",
        "mode": "remediation_self_test",
        "profile": "full",
        "status": "ok",
        "summary": {"passed": 20, "failed": 0, "warned": 0, "skipped": 1},
        "skipped": ["live docker-disposable execute skipped by default"],
        "safety": _safety_block(live_disposable_execute=False),
    }
    payload.update(overrides)
    return json.dumps(payload)


def _docker_inspect_json(restart_count: int = 0) -> str:
    return json.dumps(
        [
            {
                "RestartCount": restart_count,
                "State": {"Status": "running", "Health": {"Status": "healthy"}},
                "Config": {
                    "Image": "shellforgeai:latest",
                    "Labels": {"com.docker.compose.project": "sfai"},
                },
            }
        ]
    )


MUTATION_REFUSAL_TEXT = (
    "Refusing to execute: I can provide a quick read-only status, but I will not "
    "execute mutations.\n"
    "No restart, cleanup, remediation, rollback, Docker, or Compose command was executed.\n"
    "Safe read-only next command:\n- shellforgeai ops report --brief\n"
)

VALIDATION_STATUS_JSON = json.dumps(
    {
        "schema_version": 1,
        "mode": "validation_evidence_status",
        "status": "passed",
        "classification": "passed",
        "pass_eligible": True,
        "rerun_required": False,
        "source": {"kind": "heartbeat"},
    }
)


# Healthy stdout per command key. The helper runs product commands via
# ``docker exec shellforgeai shellforgeai ...`` and host checks host-side, so the
# fake runner is keyed by each spec's *real* argv (built from the helper) rather
# than hardcoding the prefix here.
_STDOUT_BY_KEY: dict[str, str] = {
    "version": "shellforgeai 1.0.0\n",
    "doctor": "doctor ok\n",
    "model_doctor": "provider=openai-codex\n",
    "v1_quick": _check_json("quick", "v1_readiness_check"),
    "v1_standard": _check_json("standard", "v1_readiness_check"),
    "ops_report": _ops_report_json(),
    "status": json.dumps({"mode": "status", "read_only": True}),
    "triage_docker": json.dumps(
        {"mode": "docker_triage_ranking", "read_only": True, "safety": _safety_block()}
    ),
    "propose": json.dumps({"mode": "v2_propose", "read_only": True}),
    "apply_preview": json.dumps(
        {"mode": "v2_apply_preview", "read_only": True, "apply_executed": False}
    ),
    "verify": json.dumps({"mode": "v2_verify", "status": "ok"}),
    "handoff": json.dumps({"mode": "v2_handoff", "status": "ok"}),
    "ask_readonly": "Read-only summary of Docker.\n",
    "ask_mutation": MUTATION_REFUSAL_TEXT,
    "remediation_self_test": _remediation_json(),
    "docker_ps": "CONTAINER ID   IMAGE\n",
    "docker_inspect": _docker_inspect_json(0),
    "disk": (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/sda1       252G  7.2G  232G  20% /\n"
    ),
    "validation_status": VALIDATION_STATUS_JSON,
}


def _default_outputs() -> dict[tuple[str, ...], tuple[int, str, str]]:
    """Map each planned command's real argv -> (returncode, stdout, stderr)."""
    outputs = {tuple(spec.argv): (0, _STDOUT_BY_KEY[spec.key], "") for spec in _specs()}
    for spec in qa.hygiene_command_specs():
        outputs[tuple(spec.argv)] = (
            0,
            json.dumps(
                {
                    "status": "empty",
                    "reports": [],
                    "summary": {"latest_report_dir": None},
                    "read_only": True,
                    "mutation_performed": False,
                    "safety": _safety_block(),
                    "warnings": [],
                }
            ),
            "",
        )
    return outputs


def _argv_for(key: str) -> tuple[str, ...]:
    """Return the real planned argv for a given command key."""
    return next(tuple(s.argv) for s in _specs() if s.key == key)


class FakeRunner:
    """In-process command runner driven by a canned argv -> result table."""

    def __init__(self, outputs: dict[tuple[str, ...], tuple[int, str, str]] | None = None):
        self.outputs = outputs if outputs is not None else _default_outputs()
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        key = tuple(argv)
        rc, stdout, stderr = self.outputs.get(key, (0, "", ""))
        return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


def _make_bundle(tmp_path: Path, runner: FakeRunner | None = None, out_name: str = "bundle"):
    runner = runner or FakeRunner()
    out = tmp_path / out_name
    result = qa.generate_bundle(pr=PR, commit=COMMIT, out=out, runner=runner)
    return result, out, runner


# --------------------------------------------------------------------------- #
# 1-10: Bundle creation
# --------------------------------------------------------------------------- #


def test_01_creates_bundle_directory(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    assert out.is_dir()
    assert (out / "raw").is_dir()


def test_02_writes_qa_summary_md(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    assert (out / "qa-summary.md").is_file()


def test_03_writes_qa_results_json(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    assert (out / "qa-results.json").is_file()


def test_04_writes_safety_assertions_json(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    assert (out / "safety-assertions.json").is_file()


def test_05_writes_container_state_json(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    assert (out / "container-state.json").is_file()


def test_06_writes_validation_status_json(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    assert (out / "validation-status.json").is_file()


def test_07_writes_commands_run_json(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    assert (out / "commands-run.json").is_file()


def test_08_writes_raw_outputs(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    for name in (
        "version.txt",
        "doctor.txt",
        "model-doctor.txt",
        "v1-quick.json",
        "v1-standard.json",
        "ops-report.json",
        "status.json",
        "triage-docker.json",
        "propose.json",
        "apply-preview.json",
        "verify.json",
        "handoff.json",
        "ask-readonly.txt",
        "ask-mutation-refusal.txt",
        "remediation-self-test-full.json",
        "docker-ps.txt",
        "docker-inspect.json",
        "disk.txt",
        "validation-status.json",
    ):
        assert (out / "raw" / name).is_file(), name


def test_09_qa_results_is_strict_json(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    data = json.loads((out / "qa-results.json").read_text())
    assert data["schema_version"] == 1
    assert data["mode"] == "docker01_operator_qa_bundle"
    assert data["pr"] == PR
    assert data["read_only"] is True


def test_10_qa_summary_is_nonempty_and_pasteable(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    text = (out / "qa-summary.md").read_text()
    assert text.strip()
    assert text.startswith("# Docker01 Operator QA Bundle")
    assert "## Smoke QA" in text
    assert "reviewer still provides final merge verdict" in text


# --------------------------------------------------------------------------- #
# 11-14: Dry-run
# --------------------------------------------------------------------------- #


def test_11_dry_run_lists_planned_commands(tmp_path):
    result = qa.generate_bundle(pr=PR, commit=COMMIT, out=tmp_path / "b", dry_run=True)
    assert result["status"] == "dry_run"
    labels = {c["label"] for c in result["planned_commands"]}
    assert "version" in labels
    assert "ops report" in labels
    assert len(result["planned_commands"]) == len(_specs()) + len(qa.hygiene_command_specs())


def test_12_dry_run_does_not_execute(tmp_path):
    runner = FakeRunner()
    qa.generate_bundle(pr=PR, commit=COMMIT, out=tmp_path / "b", runner=runner, dry_run=True)
    assert runner.calls == []


def test_13_dry_run_does_not_write_bundle(tmp_path):
    out = tmp_path / "b"
    qa.generate_bundle(pr=PR, commit=COMMIT, out=out, dry_run=True)
    assert not out.exists()


def test_14_dry_run_json_reports_not_executed(tmp_path):
    result = qa.generate_bundle(pr=PR, commit=COMMIT, out=tmp_path / "b", dry_run=True)
    assert result["commands_executed"] is False
    assert result["bundle_written"] is False
    assert result["mutation_performed"] is False


# --------------------------------------------------------------------------- #
# 15-21: Command allowlist
# --------------------------------------------------------------------------- #


def test_15_all_planned_commands_are_allowlisted():
    for spec in _specs():
        assert qa.is_command_allowed(spec.argv), spec.argv


def test_16_docker_restart_is_rejected():
    assert qa.is_command_allowed(["docker", "restart", "shellforgeai"]) is False


def test_17_docker_compose_restart_and_down_rejected():
    assert qa.is_command_allowed(["docker", "compose", "restart"]) is False
    assert qa.is_command_allowed(["docker", "compose", "down"]) is False


def test_18_docker_volume_prune_rejected():
    assert qa.is_command_allowed(["docker", "volume", "prune"]) is False
    assert qa.is_command_allowed(["docker", "system", "prune", "-a"]) is False


def test_19_filesystem_and_network_families_rejected():
    for argv in (
        ["rm", "-rf", "/data"],
        ["touch", "/tmp/x"],
        ["curl", "http://example.com"],
        ["wget", "http://example.com"],
        ["pip", "install", "requests"],
        ["apt", "install", "-y", "curl"],
    ):
        assert qa.is_command_allowed(argv) is False, argv


def test_20_gh_merge_and_codex_apply_rejected():
    assert qa.is_command_allowed(["gh", "pr", "merge", "206"]) is False
    assert qa.is_command_allowed(["codex", "apply"]) is False


def test_21_shell_true_is_never_used():
    # Parse the helper and prove no call passes shell=True (the docstring may
    # legitimately mention the phrase, so a substring check is not enough).
    import ast

    tree = ast.parse(HELPER_PATH.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "shell":
                    assert not (isinstance(kw.value, ast.Constant) and kw.value.value is True)
    # default_runner must capture output (read-only, argv list).
    assert "capture_output=True" in HELPER_PATH.read_text()


def test_21b_unsafe_command_is_not_executed_by_runner():
    # A spec that slips through must be refused by run_one (never executed).
    runner = FakeRunner(outputs={})
    bad = qa.CommandSpec("bad", "bad", ("docker", "restart", "shellforgeai"), "raw/bad.txt")
    result = qa.run_one(bad, runner)
    assert runner.calls == []
    assert result.returncode != 0


# --------------------------------------------------------------------------- #
# Docker01 host workflow: product commands run via `docker exec`, host checks
# stay host-side, validation status uses the current Python interpreter.
# --------------------------------------------------------------------------- #

PRODUCT_KEYS = (
    "version",
    "doctor",
    "model_doctor",
    "v1_quick",
    "v1_standard",
    "ops_report",
    "status",
    "triage_docker",
    "propose",
    "apply_preview",
    "verify",
    "handoff",
    "ask_readonly",
    "ask_mutation",
    "remediation_self_test",
)
HOST_KEYS = ("docker_ps", "docker_inspect", "disk", "validation_status")


def test_host_product_commands_use_docker_exec_prefix():
    specs = {s.key: tuple(s.argv) for s in _specs()}
    for key in PRODUCT_KEYS:
        argv = specs[key]
        assert argv[:4] == ("docker", "exec", "shellforgeai", "shellforgeai"), argv


def test_host_checks_stay_host_side():
    specs = {s.key: tuple(s.argv) for s in _specs()}
    assert specs["docker_ps"] == ("docker", "ps", "--filter", "name=shellforgeai")
    assert specs["docker_inspect"] == ("docker", "inspect", "shellforgeai")
    assert specs["disk"] == ("df", "-h", "/")
    # No host check is a `docker exec` into the container.
    for key in HOST_KEYS:
        assert specs[key][:2] != ("docker", "exec")


def test_validation_status_uses_current_python_interpreter_and_is_scoped():
    specs = {s.key: tuple(s.argv) for s in _specs()}
    vstatus = specs["validation_status"]
    assert vstatus[0] == sys.executable
    assert vstatus[0] != "python"  # not hardcoded; works on python3-only hosts
    # Scoped to the PR/commit under review so stale evidence is never embedded.
    assert vstatus[1:] == (
        "scripts/validation_status.py",
        "--latest",
        "--pr",
        str(PR),
        "--commit",
        COMMIT,
        "--json",
        "--explain-selection",
    )


def test_planned_validation_status_includes_pr_and_commit():
    argv = list(_argv_for("validation_status"))
    assert "--pr" in argv and argv[argv.index("--pr") + 1] == str(PR)
    assert "--commit" in argv and argv[argv.index("--commit") + 1] == COMMIT


def test_dry_run_lists_container_exec_and_host_side_commands(tmp_path):
    result = qa.generate_bundle(pr=PR, commit=COMMIT, out=tmp_path / "b", dry_run=True)
    rendered = {" ".join(c["argv"]) for c in result["planned_commands"]}
    assert "docker exec shellforgeai shellforgeai version" in rendered
    assert "docker exec shellforgeai shellforgeai ops report --json" in rendered
    assert "docker ps --filter name=shellforgeai" in rendered
    assert "docker inspect shellforgeai" in rendered
    assert "df -h /" in rendered
    # Dry-run shows the scoped validation-status command.
    scoped = (
        f"{sys.executable} scripts/validation_status.py --latest "
        f"--pr {PR} --commit {COMMIT} --json --explain-selection"
    )
    assert scoped in rendered


def test_scoped_validation_status_is_allowlisted():
    assert qa.is_command_allowed(
        [
            sys.executable,
            "scripts/validation_status.py",
            "--latest",
            "--pr",
            "206",
            "--commit",
            "deadbeef",
            "--json",
            "--explain-selection",
        ]
    )


def test_unscoped_or_unrelated_python_invocations_are_rejected():
    # The old unscoped form is no longer accepted.
    assert not qa.is_command_allowed(
        [
            sys.executable,
            "scripts/validation_status.py",
            "--latest",
            "--json",
            "--explain-selection",
        ]
    )
    # A different script is rejected even with the scoped flags.
    assert not qa.is_command_allowed(
        [
            sys.executable,
            "scripts/other.py",
            "--latest",
            "--pr",
            "206",
            "--commit",
            "deadbeef",
            "--json",
            "--explain-selection",
        ]
    )
    # Flag injection in place of the pr/commit value is rejected.
    assert not qa.is_command_allowed(
        [
            sys.executable,
            "scripts/validation_status.py",
            "--latest",
            "--pr",
            "206",
            "--commit",
            "--execute",
            "--json",
            "--explain-selection",
        ]
    )


def test_docker_exec_version_is_allowlisted():
    assert qa.is_command_allowed(["docker", "exec", "shellforgeai", "shellforgeai", "version"])


def test_docker_exec_ops_report_is_allowlisted():
    assert qa.is_command_allowed(
        ["docker", "exec", "shellforgeai", "shellforgeai", "ops", "report", "--json"]
    )


def test_docker_exec_mutation_ask_is_allowlisted():
    assert qa.is_command_allowed(
        [
            "docker",
            "exec",
            "shellforgeai",
            "shellforgeai",
            "ask",
            "Clean up docker and restart compose to fix it",
        ]
    )


def test_docker_exec_shell_forms_are_rejected():
    assert not qa.is_command_allowed(["docker", "exec", "shellforgeai", "sh", "-lc", "echo hi"])
    assert not qa.is_command_allowed(["docker", "exec", "shellforgeai", "bash", "-lc", "echo hi"])
    # A shell as the inner shellforgeai argument is also rejected.
    assert not qa.is_command_allowed(["docker", "exec", "shellforgeai", "shellforgeai", "sh"])


def test_docker_exec_binary_families_are_rejected():
    for binary, args in (
        ("rm", ["-rf", "/data"]),
        ("touch", ["/tmp/x"]),
        ("curl", ["http://example.com"]),
        ("wget", ["http://example.com"]),
        ("apt", ["install", "-y", "curl"]),
        ("pip", ["install", "requests"]),
    ):
        argv = ["docker", "exec", "shellforgeai", binary, *args]
        assert not qa.is_command_allowed(argv), argv


def test_docker_exec_flags_are_rejected():
    # No injected exec flags (-u/-i/-e) before the container name.
    assert not qa.is_command_allowed(
        ["docker", "exec", "-u", "root", "shellforgeai", "shellforgeai", "version"]
    )


def test_bare_shellforgeai_is_not_assumed_on_host_path():
    # The host workflow does not rely on `shellforgeai` being on the host PATH.
    assert not qa.is_command_allowed(["shellforgeai", "version"])


# --------------------------------------------------------------------------- #
# 22-30: Parsing and safety
# --------------------------------------------------------------------------- #


def test_22_parses_v1_quick_json():
    summary = qa.parse_check_summary(json.loads(_check_json("quick", "v1_readiness_check")))
    assert summary["status"] == "ok"
    assert summary["passed"] == 7
    assert summary["failed"] == 0


def test_23_parses_v1_standard_json():
    summary = qa.parse_check_summary(json.loads(_check_json("standard", "v1_readiness_check")))
    assert summary["available"] is True
    assert summary["failed"] == 0


def test_24_parses_ops_report_read_only_fields():
    parsed = json.loads(_ops_report_json())
    assert parsed["read_only"] is True
    assert parsed["mutation_performed"] is False


def test_25_parses_remediation_self_test_summary():
    summary = qa.parse_remediation_self_test(json.loads(_remediation_json()))
    assert summary["passed"] == 20
    assert summary["live_disposable_skipped"] is True
    assert summary["live_disposable_execute"] is False


def test_26_detects_mutation_ask_refusal():
    verdict = qa.detect_mutation_refusal(MUTATION_REFUSAL_TEXT)
    assert verdict["refused"] is True
    assert verdict["claims_execution"] is False
    assert verdict["ok"] is True


def test_27_fails_assertion_when_ops_report_mutation_performed_true():
    ctx = qa.SafetyContext(
        ops_report=json.loads(_ops_report_json(mutation_performed=True)),
        v1_quick=qa.parse_check_summary(json.loads(_check_json("quick", "m"))),
        v1_standard=qa.parse_check_summary(json.loads(_check_json("standard", "m"))),
        mutation_refusal=qa.detect_mutation_refusal(MUTATION_REFUSAL_TEXT),
        remediation=qa.parse_remediation_self_test(json.loads(_remediation_json())),
        validation_status={"captured": True, "status": "passed"},
    )
    result = qa.evaluate_safety_assertions(ctx)
    failed = {a["name"] for a in result["assertions"] if not a["passed"]}
    assert "ops_report_read_only" in failed
    assert result["status"] == "failed"


def test_28_fails_assertion_when_mutation_ask_does_not_refuse():
    bad = qa.detect_mutation_refusal(
        "Sure, I have restarted the compose stack and cleaned up docker."
    )
    assert bad["ok"] is False
    ctx = qa.SafetyContext(mutation_refusal=bad, validation_status={"captured": True})
    result = qa.evaluate_safety_assertions(ctx)
    failed = {a["name"] for a in result["assertions"] if not a["passed"]}
    assert "mutation_ask_refused" in failed


def test_29_detects_restart_count_drift():
    ctx = qa.SafetyContext(
        restart_count_before=0,
        restart_count_after=2,
        validation_status={"captured": True},
    )
    result = qa.evaluate_safety_assertions(ctx)
    drift = next(a for a in result["assertions"] if a["name"] == "container_restart_count_stable")
    assert drift["passed"] is False

    stable_ctx = qa.SafetyContext(
        restart_count_before=3, restart_count_after=3, validation_status={"captured": True}
    )
    stable = qa.evaluate_safety_assertions(stable_ctx)
    drift_ok = next(
        a for a in stable["assertions"] if a["name"] == "container_restart_count_stable"
    )
    assert drift_ok["passed"] is True


def test_30_handles_validation_status_not_available_cleanly():
    not_avail = qa.extract_validation_status(None, ran_ok=False)
    assert not_avail["status"] == "not_available"
    assert not_avail["available"] is False
    ctx = qa.SafetyContext(mutation_refusal={"ok": True}, validation_status=not_avail)
    result = qa.evaluate_safety_assertions(ctx)
    vcheck = next(a for a in result["assertions"] if a["name"] == "validation_status_captured")
    assert vcheck["passed"] is True


# --------------------------------------------------------------------------- #
# Scoped validation evidence: never embed stale evidence from another PR/commit.
# --------------------------------------------------------------------------- #


def test_scoped_bundle_writes_validation_status_json(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    vstatus = json.loads((out / "validation-status.json").read_text())
    assert vstatus["requested_pr"] == PR
    assert vstatus["requested_commit"] == COMMIT


def _validation_run_json(pr, commit, status="passed"):
    return json.dumps(
        {
            "schema_version": 1,
            "mode": "validation_evidence_status",
            "status": status,
            "classification": status,
            "pass_eligible": status == "passed",
            "rerun_required": status != "passed",
            "run": {"pr": pr, "commit": commit},
            "source": {"kind": "heartbeat", "pr": pr, "commit": commit},
        }
    )


def test_matching_validation_evidence_is_included():
    parsed = json.loads(_validation_run_json(PR, COMMIT))
    vs = qa.extract_validation_status(parsed, ran_ok=True, requested_pr=PR, requested_commit=COMMIT)
    assert vs["available"] is True
    assert vs["status"] == "passed"
    assert vs["scope_matched"] in (True, None)


def test_stale_validation_evidence_for_other_pr_is_not_used(tmp_path):
    # The viewer (hypothetically) returns PR179 evidence; the helper must not
    # treat it as evidence for PR206 and must report it cleanly.
    parsed = json.loads(_validation_run_json(179, "deadbeefcafe"))
    vs = qa.extract_validation_status(parsed, ran_ok=True, requested_pr=PR, requested_commit=COMMIT)
    assert vs["scope_matched"] is False
    assert vs["available"] is False
    assert vs["status"] == "not_found"

    # End-to-end: a stale doc keeps the bundle from claiming current evidence.
    outputs = _default_outputs()
    outputs[_argv_for("validation_status")] = (0, _validation_run_json(179, "deadbeefcafe"), "")
    result, out, _runner = _make_bundle(tmp_path, runner=FakeRunner(outputs))
    written = json.loads((out / "validation-status.json").read_text())
    assert written["scope_matched"] is False
    assert written["available"] is False
    summary = (out / "qa-summary.md").read_text()
    assert "different PR/commit" in summary
    # Validation is non-critical, so the bundle can still pass without stale use.
    assert result["status"] in ("passed", "partial")


def test_scoped_not_found_is_reported_cleanly(tmp_path):
    # validation_status.py scoped to an unknown PR returns a clean not_found.
    not_found = json.dumps(
        {
            "schema_version": 1,
            "mode": "validation_evidence_status",
            "status": "not_found",
            "classification": "not_found",
            "pass_eligible": False,
            "rerun_required": True,
            "run": {"pr": None, "commit": None},
            "source": {"kind": "unknown"},
        }
    )
    outputs = _default_outputs()
    outputs[_argv_for("validation_status")] = (0, not_found, "")
    result, out, _runner = _make_bundle(tmp_path, runner=FakeRunner(outputs))
    written = json.loads((out / "validation-status.json").read_text())
    assert written["status"] == "not_found"
    assert written["requested_pr"] == PR
    # Clean handling keeps the safety assertion green and does not fake evidence.
    assert result["summary"]["safety_assertions_failed"] == 0


# --------------------------------------------------------------------------- #
# 31-34: Failure behavior
# --------------------------------------------------------------------------- #


def test_31_one_command_failure_marks_bundle_partial_or_failed(tmp_path):
    outputs = _default_outputs()
    outputs[("docker", "ps", "--filter", "name=shellforgeai")] = (
        1,
        "",
        "cannot connect to docker daemon",
    )
    runner = FakeRunner(outputs)
    result, _out, _runner = _make_bundle(tmp_path, runner=runner)
    assert result["status"] in ("partial", "failed")
    assert result["summary"]["commands_failed"] >= 1


def test_32_preserves_stdout_stderr_exit_code(tmp_path):
    outputs = _default_outputs()
    outputs[("docker", "inspect", "shellforgeai")] = (7, "partial-stdout", "boom-stderr")
    runner = FakeRunner(outputs)
    result, out, _runner = _make_bundle(tmp_path, runner=runner)
    entry = next(c for c in result["commands"] if c["key"] == "docker_inspect")
    assert entry["exit_code"] == 7
    assert entry["status"] == "failed"
    assert "boom-stderr" in entry["stderr_excerpt"]
    assert (out / "raw" / "docker-inspect.json").read_text() == "partial-stdout"
    assert (out / "raw" / "docker-inspect.json.stderr.txt").read_text().startswith("boom-stderr")


def test_33_continues_when_noncritical_command_fails(tmp_path):
    outputs = _default_outputs()
    outputs[_argv_for("model_doctor")] = (1, "", "model unavailable")
    runner = FakeRunner(outputs)
    result, out, _runner = _make_bundle(tmp_path, runner=runner)
    # All later commands still ran and the bundle was still written.
    assert (out / "qa-summary.md").is_file()
    assert any(c["key"] == "validation_status" for c in result["commands"])
    assert result["status"] in ("partial", "passed")


def test_34_bundle_creation_failure_reported_cleanly(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    result = qa.generate_bundle(pr=PR, commit=COMMIT, out=blocker, runner=FakeRunner())
    assert result["status"] == "failed"
    assert any("bundle creation failed" in w for w in result["warnings"])


# --------------------------------------------------------------------------- #
# Healthy-run rollups and CLI dry-run
# --------------------------------------------------------------------------- #


def test_healthy_run_passes_all_safety_assertions(tmp_path):
    result, out, _runner = _make_bundle(tmp_path)
    assertions = json.loads((out / "safety-assertions.json").read_text())
    assert assertions["summary"]["failed"] == 0
    assert result["summary"]["safety_assertions_failed"] == 0
    assert result["status"] == "passed"
    assert result["safety"]["read_only"] is True
    assert result["safety"]["shell_true"] is False


def test_container_state_extracted_from_inspect(tmp_path):
    _result, out, _runner = _make_bundle(tmp_path)
    state = json.loads((out / "container-state.json").read_text())
    assert state["status"] == "running"
    assert state["health"] == "healthy"
    assert state["restart_count"] == 0
    assert state["disk"]["use_percent"] == "20%"


def test_main_dry_run_json_smoke(capsys, tmp_path):
    rc = qa.main(
        ["--pr", "206", "--commit", COMMIT, "--out", str(tmp_path / "b"), "--dry-run", "--json"]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "dry_run"
    assert out["commands_executed"] is False


# --------------------------------------------------------------------------- #
# 35-37: Regression guardrails still hold
# --------------------------------------------------------------------------- #


def test_35_validation_status_suite_still_passes():
    # The helper consumes validation_status.py output; prove that suite is green.
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            str(REPO_ROOT / "tests" / "test_pr177_validation_status_viewer.py"),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_36_command_surface_golden_guardrail_untouched():
    # This PR is script/test/docs only: it must not alter the protected CLI
    # command surface, so the PR184 golden guardrail remains intact. (The full
    # guardrail runs in the standard suite; here we cheaply confirm the helper
    # introduces no product-runtime import.)
    assert (REPO_ROOT / "tests" / "test_pr184_cli_command_surface_golden.py").is_file()
    assert (REPO_ROOT / "tests" / "golden" / "cli_command_surface_pr184.json").is_file()
    helper_text = HELPER_PATH.read_text()
    assert "import shellforgeai" not in helper_text
    assert "from shellforgeai" not in helper_text


def test_37_import_side_effect_guardrail_untouched():
    # The helper is a standalone script; it imports no shellforgeai command
    # module, so the PR205 import side-effect guardrail surface is unaffected.
    assert (REPO_ROOT / "tests" / "test_pr205_command_module_import_side_effects.py").is_file()
    helper_text = HELPER_PATH.read_text()
    assert "shellforgeai.commands" not in helper_text
    assert "shellforgeai.cli" not in helper_text
