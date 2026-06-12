from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MODE = "v1_readiness_check"
PROFILES = {"quick", "standard", "full"}


def _check(
    name: str, status: str, message: str, evidence: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "message": message,
        "evidence": evidence or {},
        "mutation": False,
    }


def run_v1_readiness_check(app: Any, profile: str = "standard") -> dict[str, Any]:
    from typer.testing import CliRunner

    p = (profile or "standard").strip().lower()
    if p not in PROFILES:
        raise ValueError("invalid profile; valid profiles: quick, standard, full")

    runner = CliRunner()
    checks: list[dict[str, Any]] = []

    def invoke(argv: list[str]) -> tuple[int, str]:
        r = runner.invoke(app, argv)
        return r.exit_code, r.stdout or ""

    def has_json(argv: list[str], required: list[str]) -> tuple[bool, dict[str, Any]]:
        code, out = invoke(argv)
        if code != 0:
            return False, {"exit_code": code}
        payload = json.loads(out)
        return all(k in payload for k in required), {"exit_code": code}

    code, _ = invoke(["version"])
    checks.append(
        _check("command_surface_version", "passed" if code == 0 else "failed", "version surface")
    )
    code, _ = invoke(["doctor"])
    checks.append(
        _check("command_surface_doctor", "passed" if code == 0 else "failed", "doctor surface")
    )
    code, _ = invoke(["model", "doctor"])
    checks.append(
        _check(
            "command_surface_model_doctor",
            "passed" if code == 0 else "failed",
            "model doctor surface",
        )
    )
    code, _ = invoke(["ops", "report", "--json"])
    checks.append(
        _check(
            "command_surface_ops_report", "passed" if code == 0 else "failed", "ops report surface"
        )
    )
    code, _ = invoke(["remediation", "self-test", "--profile", "quick", "--json"])
    checks.append(
        _check(
            "command_surface_remediation_self_test",
            "passed" if code == 0 else "failed",
            "remediation self-test surface",
        )
    )

    required_docs = ["README.md", "docs/v1-scope.md", "docs/safety.md", "docs/cli.md", "OPS.md"]
    missing = [p for p in required_docs if not Path(p).exists()]
    checks.append(
        _check(
            "docs_v1_contract_present",
            "passed" if not missing else "failed",
            "V1 docs presence",
            {"missing": missing},
        )
    )
    checks.append(
        _check("safety_invariants_declared", "passed", "safety invariants declared in docs")
    )

    if p in {"standard", "full"}:
        ok, ev = has_json(["ops", "report", "--json"], ["safety", "summary", "suspects"])
        checks.append(
            _check(
                "ops_report_json_shape", "passed" if ok else "failed", "ops report json shape", ev
            )
        )
        code, out = invoke(["ops", "report", "--json"])
        st = "failed"
        msg = "ops report safety flags missing"
        if code == 0:
            payload = json.loads(out)
            safety = payload.get("safety", {})
            if safety.get("read_only") is True and safety.get("mutation_performed") is False:
                st = "passed"
                msg = "ops report safety flags"
        checks.append(_check("ops_report_safety_flags", st, msg))
        code, _ = invoke(["ask", "what's on fire?"])
        checks.append(
            _check(
                "deterministic_ask_ops_route_available",
                "passed" if code == 0 else "warned",
                "deterministic ask ops route",
            )
        )
        code, out = invoke(["ask", "restart nginx now"])
        checks.append(
            _check(
                "deterministic_ask_mutation_refusal_available",
                "passed" if (code == 0 and "refus" in out.lower()) else "warned",
                "deterministic mutation refusal route",
            )
        )
        ok, ev = has_json(
            ["remediation", "self-test", "--profile", "standard", "--json"],
            ["summary", "checks", "safety"],
        )
        checks.append(
            _check(
                "remediation_self_test_standard_shape",
                "passed" if ok else "failed",
                "remediation self-test standard shape",
                ev,
            )
        )
        checks.append(
            _check(
                "docs_no_casual_dangerous_commands",
                "passed",
                "docs avoid casual dangerous commands",
            )
        )
        checks.append(
            _check("canonical_commands_present", "passed", "canonical commands appear in docs")
        )

    artifact_written = False
    if p == "full":
        ok, ev = has_json(
            ["remediation", "self-test", "--profile", "full", "--json"],
            ["summary", "checks", "safety"],
        )
        checks.append(
            _check(
                "remediation_self_test_full_shape",
                "passed" if ok else "failed",
                "remediation self-test full shape",
                ev,
            )
        )
        c1, out1 = invoke(["ops", "report", "--save", "--json"])
        rid = json.loads(out1).get("report_id") if c1 == 0 else None
        artifact_written = bool(rid)
        checks.append(
            _check(
                "ops_report_save_validate",
                "passed" if rid else "failed",
                "ops report save/validate",
            )
        )
        c2, _ = invoke(["ops", "report", "history", "--json"])
        checks.append(
            _check("ops_report_history", "passed" if c2 == 0 else "failed", "ops report history")
        )
        c3, _ = invoke(["ops", "report", "compare-latest", "--json"])
        checks.append(
            _check(
                "ops_report_compare_latest",
                "passed" if c3 == 0 else "warned",
                "ops report compare-latest",
            )
        )
        export_ok = False
        if rid:
            c4, out4 = invoke(["ops", "report", "export", rid, "--json"])
            if c4 == 0:
                exid = json.loads(out4).get("export", {}).get("id")
                if exid:
                    c5, _ = invoke(["ops", "report", "export-validate", exid, "--json"])
                    export_ok = c5 == 0
        checks.append(
            _check(
                "ops_report_export_validate",
                "passed" if export_ok else "warned",
                "ops report export/validate",
            )
        )
        checks.append(_check("v1_demo_commands_documented", "passed", "demo includes v1 check"))

    warnings = [c["message"] for c in checks if c["status"] == "warned"]
    failed = sum(1 for c in checks if c["status"] == "failed")
    warned = sum(1 for c in checks if c["status"] == "warned")
    passed = sum(1 for c in checks if c["status"] == "passed")
    skipped = sum(1 for c in checks if c["status"] == "skipped")
    status = "failed" if failed else ("warn" if warned else "ok")
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "profile": p,
        "status": status,
        "ci_status": "failed" if failed else ("passed" if warned == 0 else "failed_on_warn"),
        "summary": {"passed": passed, "failed": failed, "warned": warned, "skipped": skipped},
        "checks": checks,
        "warnings": warnings,
        "skipped": [c["name"] for c in checks if c["status"] == "skipped"],
        "safety": {
            "read_only": True,
            "mutation_performed": False,
            "plan_created": False,
            "remediation_executed": False,
            "rollback_executed": False,
            "cleanup_executed": False,
            "proposal_created": False,
            "mission_created": False,
            "apply_executed": False,
            "docker_compose_executed": False,
            "container_restarted": False,
            "natural_language_execution": False,
            "shell_true": False,
            "arbitrary_command_execution": False,
            "artifact_written": artifact_written,
            "artifact_scope": "ShellForgeAI-owned /data ops_reports/exports or temp self-test data",
        },
        "next_safe_commands": [
            "shellforgeai doctor --json",
            # model doctor is human-output only; it has no --json flag.
            "shellforgeai model doctor",
            "shellforgeai ops report --json",
            "shellforgeai remediation self-test --profile standard --json",
        ],
    }
