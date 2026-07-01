"""PR265 Windows evidence bundle acceptance validator tests."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path("scripts/windows_smoke_acceptance.py")


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("windows_smoke_acceptance_pr265", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _safe_flags() -> dict[str, bool]:
    return {
        "read_only": True,
        "mutation_performed": False,
        "powershell_executed": False,
        "winrm_used": False,
        "remote_execution": False,
        "service_restart_executed": False,
        "process_termination_executed": False,
        "registry_modified": False,
        "execution_policy_modified": False,
        "software_install_executed": False,
        "cleanup_executed": False,
        "remediation_executed": False,
        "rollback_executed": False,
        "recovery_executed": False,
        "natural_language_execution": False,
        "shell_true": False,
        "arbitrary_command_execution": False,
        "secret_read": False,
        "auth_cache_read": False,
        "model_called": False,
        "network_call": False,
    }


def _component(mode: str) -> dict[str, Any]:
    scope = "local_read_only_status" if mode == "windows_status" else "local_read_only_doctor"
    return {
        "schema_version": 1,
        "mode": mode,
        "status": "ok",
        "platform": {"system": "windows", "release": "2025", "machine": "AMD64"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": scope,
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "host": {"hostname": "WIN2025-SFAI01", "cwd": "C:\\Tools\\ShellForgeAI"},
        "python_runtime": {
            "executable": "C:\\Tools\\ShellForgeAI\\Python314\\python.exe",
            "version": "3.14.6",
        },
        "filesystem": {"collection": "stdlib_only"},
        "safety": _safe_flags(),
    }


def _evidence_payload() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_evidence_bundle",
        "status": "ok",
        "platform": {"system": "windows", "release": "2025", "machine": "AMD64"},
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_evidence_bundle",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "host": {"hostname": "WIN2025-SFAI01"},
        "python_runtime": {"version": "3.14.6", "executable": "python.exe"},
        "components": {
            "doctor": _component("windows_doctor"),
            "status": _component("windows_status"),
        },
        "summary": {
            "component_count": 2,
            "ok_components": ["doctor", "status"],
            "failed_components": [],
        },
        "not_collected_in_pr264": {
            "powershell_version": True,
            "execution_policy": True,
            "services": True,
            "processes": True,
            "event_logs": True,
        },
        "safety": _safe_flags(),
    }


def _write_json(tmp_path: Path, name: str, payload: Any, *, bom: bool = False) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8-sig" if bom else "utf-8")
    return path


def _result_for(
    tmp_path: Path, payload: Any | None = None, extra: list[str] | None = None
) -> dict[str, Any]:
    module = _module()
    path = _write_json(
        tmp_path, "evidence.json", _evidence_payload() if payload is None else payload
    )
    return module._result(module.parse_args(["--evidence-json", str(path), *(extra or [])]))


def _assert_fails(tmp_path: Path, mutate, expected_check: str) -> None:
    payload = _evidence_payload()
    mutate(payload)
    result = _result_for(tmp_path, payload)
    assert result["status"] == "failed"
    assert any(
        check["name"] == expected_check and not check["passed"] for check in result["checks"]
    )


def test_evidence_only_valid_pr264_like_bundle_passes(tmp_path: Path) -> None:
    module = _module()
    evidence = _write_json(tmp_path, "windows-evidence.json", _evidence_payload())
    code = module.main(["--evidence-json", str(evidence), "--json"])
    result = module._result(module.parse_args(["--evidence-json", str(evidence)]))
    assert code == 0
    assert result["status"] == "ok"
    assert result["artifacts"]["evidence"]["validated"] is True


def test_evidence_status_doctor_valid_artifacts_pass(tmp_path: Path) -> None:
    module = _module()
    evidence = _write_json(tmp_path, "windows-evidence.json", _evidence_payload())
    status = _write_json(tmp_path, "windows-status.json", _component("windows_status"))
    doctor = _write_json(tmp_path, "windows-doctor.json", _component("windows_doctor"))
    result = module._result(
        module.parse_args(
            [
                "--evidence-json",
                str(evidence),
                "--status-json",
                str(status),
                "--doctor-json",
                str(doctor),
                "--expected-host",
                "WIN2025-SFAI01",
                "--expected-python",
                "3.14.6",
            ]
        )
    )
    assert result["status"] == "ok"
    assert result["artifacts"]["status"]["validated"] is True
    assert result["artifacts"]["doctor"]["validated"] is True
    assert any(check["name"] == "cross_check.status.mode" for check in result["checks"])


def test_existing_status_doctor_only_validation_still_passes(tmp_path: Path) -> None:
    module = _module()
    status = _write_json(tmp_path, "status.json", _component("windows_status"))
    doctor = _write_json(tmp_path, "doctor.json", _component("windows_doctor"))
    assert module.main(["--status-json", str(status), "--doctor-json", str(doctor), "--json"]) == 0


@pytest.mark.parametrize("bom", [True, False])
def test_evidence_json_accepts_utf8_with_and_without_bom(tmp_path: Path, bom: bool) -> None:
    module = _module()
    evidence = _write_json(tmp_path, "evidence.json", _evidence_payload(), bom=bom)
    result = module._result(module.parse_args(["--evidence-json", str(evidence)]))
    assert result["status"] == "ok"


def test_missing_all_inputs_fails_cleanly() -> None:
    module = _module()
    with pytest.raises(SystemExit) as exc:
        module.parse_args([])
    assert exc.value.code == 2


def test_missing_evidence_path_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    result = module._result(module.parse_args(["--evidence-json", str(tmp_path / "missing.json")]))
    assert result["status"] == "failed"
    assert result["checks"][0]["name"] == "evidence.file_exists"


def test_invalid_evidence_json_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    path = tmp_path / "bad.json"
    path.write_text("{bad", encoding="utf-8")
    result = module._result(module.parse_args(["--evidence-json", str(path)]))
    assert result["status"] == "failed"
    assert "invalid JSON" in result["checks"][0]["reason"]


def test_non_object_evidence_json_fails_cleanly(tmp_path: Path) -> None:
    result = _result_for(tmp_path, [])
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.object" and not check["passed"] for check in result["checks"]
    )


@pytest.mark.parametrize(
    ("mutate", "check_name"),
    [
        (lambda p: p.update(mode="other"), "evidence.mode"),
        (lambda p: p.update(status="failed"), "evidence.status"),
        (lambda p: p["platform"].update(system="linux"), "evidence.platform.system"),
        (lambda p: p.update(read_only=False), "evidence.read_only"),
        (lambda p: p.update(mutation_performed=True), "evidence.mutation_performed"),
        (lambda p: p["windows_v1"].update(available=False), "evidence.windows_v1.available"),
        (lambda p: p["components"].pop("doctor"), "evidence.components.doctor.exists"),
        (lambda p: p["components"].pop("status"), "evidence.components.status.exists"),
        (
            lambda p: p["components"]["doctor"].update(status="failed"),
            "evidence.components.doctor.status",
        ),
        (
            lambda p: p["components"]["status"].update(status="failed"),
            "evidence.components.status.status",
        ),
        (lambda p: p["summary"].update(component_count=1), "evidence.summary.component_count"),
        (
            lambda p: p["summary"].update(failed_components=["doctor"]),
            "evidence.summary.failed_components",
        ),
        (
            lambda p: p["not_collected_in_pr264"].pop("powershell_version"),
            "evidence.not_collected_in_pr264.powershell_version",
        ),
        (
            lambda p: p["not_collected_in_pr264"].pop("services"),
            "evidence.not_collected_in_pr264.services",
        ),
    ],
)
def test_evidence_required_contract_failures_surface(
    tmp_path: Path, mutate, check_name: str
) -> None:
    _assert_fails(tmp_path, mutate, check_name)


@pytest.mark.parametrize(
    "flag",
    [
        "powershell_executed",
        "winrm_used",
        "remote_execution",
        "shell_true",
        "arbitrary_command_execution",
        "network_call",
        "model_called",
        "secret_read",
        "auth_cache_read",
        "service_restart_executed",
        "process_termination_executed",
        "registry_modified",
        "execution_policy_modified",
        "remediation_executed",
        "rollback_executed",
        "recovery_executed",
    ],
)
def test_evidence_safety_false_flags_fail_when_true(tmp_path: Path, flag: str) -> None:
    def mutate(payload: dict[str, Any]) -> None:
        if flag in payload["windows_v1"]:
            payload["windows_v1"][flag] = True
        payload["safety"][flag] = True

    _assert_fails(tmp_path, mutate, f"evidence.safety.{flag}")


def test_expected_host_mismatch_fails_when_evidence_host_data_exists(tmp_path: Path) -> None:
    result = _result_for(tmp_path, extra=["--expected-host", "OTHER"])
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.host.expected" and not check["passed"]
        for check in result["checks"]
    )


def test_expected_python_mismatch_fails_when_runtime_data_exists(tmp_path: Path) -> None:
    result = _result_for(tmp_path, extra=["--expected-python", "3.13"])
    assert result["status"] == "failed"
    assert any(
        check["name"] == "evidence.python_runtime.expected" and not check["passed"]
        for check in result["checks"]
    )


def test_json_output_is_deterministic_and_includes_evidence_artifact_status(
    tmp_path: Path, capsys
) -> None:
    module = _module()
    evidence = _write_json(tmp_path, "evidence.json", _evidence_payload())
    args = ["--evidence-json", str(evidence), "--json"]
    assert module.main(args) == 0
    first = capsys.readouterr().out
    assert module.main(args) == 0
    second = capsys.readouterr().out
    assert first == second
    parsed = json.loads(first)
    assert parsed["artifacts"]["evidence"] == {
        "mode": "windows_evidence_bundle",
        "status": "ok",
        "validated": True,
    }


def test_text_output_is_concise_and_includes_pass_fail_summary(tmp_path: Path, capsys) -> None:
    module = _module()
    evidence = _write_json(tmp_path, "evidence.json", _evidence_payload())
    assert module.main(["--evidence-json", str(evidence)]) == 0
    output = capsys.readouterr().out
    assert "Windows smoke acceptance" in output
    assert "Status: ok" in output
    assert "Passed:" in output
    assert "Failed: 0" in output


def test_source_safety_confirms_validator_does_not_use_subprocess() -> None:
    assert "subprocess" not in SCRIPT.read_text(encoding="utf-8")


def test_source_safety_confirms_no_shellforgeai_product_command_imports() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "shellforgeai.commands" not in source
    assert "shellforgeai.windows_" not in source


def test_source_safety_confirms_no_powershell_winrm_execution_behavior() -> None:
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "run powershell" not in source
    assert "start-process" not in source
    assert "psremoting" not in source
    assert "winrs" not in source
