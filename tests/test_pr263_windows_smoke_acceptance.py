"""PR263 Windows smoke acceptance validator tests."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

SCRIPT = Path("scripts/windows_smoke_acceptance.py")


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("windows_smoke_acceptance", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _status_payload() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "windows_status",
        "status": "ok",
        "platform": {
            "system": "windows",
            "name": "Windows-test",
            "release": "2025",
            "machine": "AMD64",
        },
        "read_only": True,
        "mutation_performed": False,
        "windows_v1": {
            "available": True,
            "scope": "local_read_only_status",
            "remote_execution": False,
            "powershell_executed": False,
            "winrm_used": False,
        },
        "host": {
            "hostname": "WIN2025-SFAI01",
            "fqdn": "WIN2025-SFAI01.local",
            "cwd": "C:\\Tools\\ShellForgeAI",
        },
        "python_runtime": {
            "executable": "C:\\Tools\\ShellForgeAI\\Python312\\python.exe",
            "version": "3.12.10",
        },
        "filesystem": {
            "collection": "stdlib_only",
            "cwd_usage": {"total_bytes": 10, "used_bytes": 2, "free_bytes": 8},
        },
        "safety": _safe_flags(),
    }


def _doctor_payload() -> dict[str, Any]:
    payload = _status_payload()
    payload["mode"] = "windows_doctor"
    payload["windows_v1"]["scope"] = "local_read_only_doctor"
    return payload


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


def _write_json(tmp_path: Path, name: str, payload: Any) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run(
    tmp_path: Path, payload: Any | None = None, extra: list[str] | None = None
) -> tuple[int, dict[str, Any]]:
    module = _module()
    status = _write_json(tmp_path, "status.json", _status_payload() if payload is None else payload)
    args = ["--status-json", str(status), "--json", *(extra or [])]
    code = module.main(args)
    result = module._result(module.parse_args(args))
    return code, result


def test_valid_pr262_like_status_json_passes(tmp_path: Path) -> None:
    code, result = _run(tmp_path)
    assert code == 0
    assert result["status"] == "ok"
    assert result["summary"]["failed"] == 0


def test_valid_pr262_like_status_plus_doctor_json_passes(tmp_path: Path) -> None:
    module = _module()
    status = _write_json(tmp_path, "status.json", _status_payload())
    doctor = _write_json(tmp_path, "doctor.json", _doctor_payload())
    code = module.main(["--status-json", str(status), "--doctor-json", str(doctor), "--json"])
    result = module._result(
        module.parse_args(["--status-json", str(status), "--doctor-json", str(doctor)])
    )
    assert code == 0
    assert result["status"] == "ok"
    assert any(check["name"] == "doctor.mode" for check in result["checks"])


def test_text_output_is_concise_and_includes_status_pass_fail_summary(
    tmp_path: Path, capsys
) -> None:
    module = _module()
    status = _write_json(tmp_path, "status.json", _status_payload())
    assert module.main(["--status-json", str(status)]) == 0
    output = capsys.readouterr().out
    assert "Windows smoke acceptance" in output
    assert "Status: ok" in output
    assert "Passed:" in output
    assert "Failed: 0" in output
    assert len(output.splitlines()) == 4


def test_json_output_is_deterministic_and_includes_check_results(tmp_path: Path, capsys) -> None:
    module = _module()
    status = _write_json(tmp_path, "status.json", _status_payload())
    assert module.main(["--status-json", str(status), "--json"]) == 0
    first = capsys.readouterr().out
    assert module.main(["--status-json", str(status), "--json"]) == 0
    second = capsys.readouterr().out
    assert first == second
    parsed = json.loads(first)
    assert parsed["mode"] == "windows_smoke_acceptance"
    assert parsed["checks"][0]["name"] == "status.json_parse"


def test_missing_status_json_path_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    result = module._result(module.parse_args(["--status-json", str(tmp_path / "missing.json")]))
    assert result["status"] == "failed"
    assert result["summary"]["failed"] == 1


def test_invalid_json_fails_cleanly(tmp_path: Path) -> None:
    module = _module()
    path = tmp_path / "bad.json"
    path.write_text("{bad", encoding="utf-8")
    result = module._result(module.parse_args(["--status-json", str(path)]))
    assert result["status"] == "failed"
    assert "invalid JSON" in result["checks"][0]["reason"]


def test_non_object_json_fails_cleanly(tmp_path: Path) -> None:
    code, result = _run(tmp_path, [])
    assert code == 1
    assert any(
        check["name"] == "status.object" and not check["passed"] for check in result["checks"]
    )


def _assert_mutation_fails(tmp_path: Path, mutate) -> None:
    payload = _status_payload()
    mutate(payload)
    code, result = _run(tmp_path, payload)
    assert code == 1
    assert result["status"] == "failed"


def test_platform_system_not_windows_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["platform"].update(system="linux"))


def test_status_not_ok_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p.update(status="unsupported"))


def test_read_only_false_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p.update(read_only=False))


def test_mutation_performed_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p.update(mutation_performed=True))


def test_powershell_executed_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["windows_v1"].update(powershell_executed=True))


def test_winrm_used_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["windows_v1"].update(winrm_used=True))


def test_remote_execution_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["windows_v1"].update(remote_execution=True))


def test_shell_true_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["safety"].update(shell_true=True))


def test_arbitrary_command_execution_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["safety"].update(arbitrary_command_execution=True))


def test_network_call_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["safety"].update(network_call=True))


def test_model_called_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["safety"].update(model_called=True))


def test_secret_read_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["safety"].update(secret_read=True))


def test_auth_cache_read_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["safety"].update(auth_cache_read=True))


def test_service_restart_executed_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["safety"].update(service_restart_executed=True))


def test_registry_modified_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["safety"].update(registry_modified=True))


def test_execution_policy_modified_true_fails(tmp_path: Path) -> None:
    _assert_mutation_fails(tmp_path, lambda p: p["safety"].update(execution_policy_modified=True))


def test_expected_host_mismatch_fails_when_provided(tmp_path: Path) -> None:
    code, result = _run(tmp_path, extra=["--expected-host", "OTHER"])
    assert code == 1
    assert any(
        check["name"] == "status.host.expected" and not check["passed"]
        for check in result["checks"]
    )


def test_expected_python_mismatch_fails_when_provided(tmp_path: Path) -> None:
    code, result = _run(tmp_path, extra=["--expected-python", "3.11.0"])
    assert code == 1
    assert any(
        check["name"] == "status.python_runtime.expected" and not check["passed"]
        for check in result["checks"]
    )


def test_source_safety_confirms_validator_does_not_use_subprocess() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "subprocess" not in source


def test_source_safety_confirms_no_powershell_winrm_execution_behavior() -> None:
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "run powershell" not in source
    assert "start-process" not in source
    assert "psremoting" not in source
    assert "winrs" not in source


def test_source_safety_confirms_no_shellforgeai_runtime_command_imports() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "shellforgeai.commands" not in source
    assert "shellforgeai.windows_" not in source
