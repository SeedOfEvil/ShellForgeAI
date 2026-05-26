from __future__ import annotations

import json
import os
import subprocess
from importlib.resources import files
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

SCRIPT = Path("scripts/v1_validate.sh")


def _write_fake_python(bin_dir: Path) -> None:
    script = """#!/usr/bin/env python3
import os, subprocess, sys
log = os.environ.get('FAKE_LOG')
if log:
    with open(log, 'a', encoding='utf-8') as fh:
        fh.write('PYTHON ' + ' '.join(sys.argv[1:]) + '\\n')
if len(sys.argv) >= 2 and sys.argv[1] == '-m':
    mod = sys.argv[2] if len(sys.argv) > 2 else ''
    if mod == 'ruff' and '--version' in sys.argv:
        print('ruff 0.0')
        raise SystemExit(0)
    if mod in ('ruff', 'compileall', 'pytest'):
        raise SystemExit(0)
if len(sys.argv) >= 3 and sys.argv[1] == '-c':
    code = sys.argv[2]
    sys.argv = [sys.argv[0]] + sys.argv[3:]
    exec(compile(code, '<cmd>', 'exec'), {'__name__': '__main__'})
    raise SystemExit(0)
if len(sys.argv) >= 2 and sys.argv[1] == '-':
    data = sys.stdin.read()
    p = subprocess.run(["/usr/bin/python3", '-'] + sys.argv[2:], input=data, text=True)
    raise SystemExit(p.returncode)
p = subprocess.run(["/usr/bin/python3"] + sys.argv[1:])
raise SystemExit(p.returncode)
"""
    p = bin_dir / "python"
    p.write_text(script, encoding="utf-8")
    p.chmod(0o755)


def _write_fake_ps(bin_dir: Path) -> None:
    p = bin_dir / "ps"
    p.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    p.chmod(0o755)


def _write_fake_timeout(bin_dir: Path) -> None:
    p = bin_dir / "timeout"
    p.write_text(
        "#!/usr/bin/env bash\n"
        'secs="$1"; shift\n'
        'if [[ -n "${FAKE_LOG:-}" ]]; then echo "TIMEOUT ${secs} $*" >>"$FAKE_LOG"; fi\n'
        '"$@"\n',
        encoding="utf-8",
    )
    p.chmod(0o755)


def _write_fake_shellforgeai(bin_dir: Path) -> None:
    script = """#!/usr/bin/env python3
import json, os, sys
log = os.environ.get('FAKE_LOG')
if log:
    with open(log, 'a', encoding='utf-8') as fh:
        fh.write('SFAI ' + ' '.join(sys.argv[1:]) + '\\n')
args = sys.argv[1:]
if args == ['v1','packet','--save','--json']:
    mode = os.environ.get('SFAI_PACKET_SAVE_MODE', 'ok')
    if mode == 'fail':
        raise SystemExit(9)
    if mode == 'timeout':
        raise SystemExit(124)
    if mode == 'malformed':
        print('{not-json')
        raise SystemExit(0)
    if os.environ.get('SFAI_PACKET_SAVE_STDERR_WARN') == '1':
        print('packet warning on stderr', file=sys.stderr)
    shape = os.environ.get('SFAI_PACKET_SAVE_SHAPE', 'top')
    if shape == 'top':
        payload = {'packet_id': 'v1_packet_123', 'packet_path': '/d/p/v1_packet_123'}
    elif shape == 'path_only':
        payload = {'packet_path': '/d/p/v1_packet_123'}
    elif shape == 'nested_packet':
        payload = {'packet': {'id': 'v1_packet_123', 'path': '/d/p/v1_packet_123'}}
    elif shape == 'artifact':
        payload = {'artifact': {'id': 'v1_packet_123', 'path': '/d/p/v1_packet_123'}}
    elif shape == 'missing_ref':
        payload = {}
    else:
        payload = {'packet_id': 'v1_packet_123', 'packet_path': '/d/p/v1_packet_123'}
    payload['status'] = 'ok'
    payload['mode'] = 'v1_readiness_packet'
    print(json.dumps(payload))
    raise SystemExit(0)
if len(args) >= 5 and args[:3] == ['v1','packet','validate'] and args[-1] == '--json':
    status = os.environ.get('SFAI_PACKET_VALIDATE_STATUS', 'ok')
    if status == 'fail':
        raise SystemExit(8)
    payload = {'status': status}
    payload['safety'] = {'read_only': True, 'mutation_performed': False}
    payload['checks'] = {'readiness': {'status': 'ok'}, 'docs': {'status': 'ok'}}
    payload['checks']['command_surface'] = {'status': 'ok'}
    print(json.dumps(payload))
    raise SystemExit(0)
if len(args) >= 5 and args[:3] == ['v1','packet','export'] and args[-1] == '--json':
    if os.environ.get('SFAI_PACKET_EXPORT_FAIL') == '1':
        raise SystemExit(7)
    shape = os.environ.get('SFAI_PACKET_EXPORT_SHAPE', 'nested')
    if shape == 'nested':
        payload = {'export': {'id': 'exp123', 'path': '/d/e/exp123'}}
    elif shape == 'id_only':
        payload = {'export_id': 'exp123'}
    elif shape == 'path_only':
        payload = {'export_path': '/d/e/exp123'}
    elif shape == 'missing_ref':
        payload = {'status': 'ok'}
    else:
        payload = {'export': {'id': 'exp123', 'path': '/d/e/exp123'}}
    print(json.dumps(payload))
    raise SystemExit(0)
if len(args) >= 5 and args[:3] == ['v1','packet','export-validate'] and args[-1] == '--json':
    if os.environ.get('SFAI_PACKET_EXPORT_VALIDATE_FAIL') == '1':
        raise SystemExit(6)
    print(json.dumps({'status': 'ok'}))
    raise SystemExit(0)
raise SystemExit(0)
"""
    p = bin_dir / "shellforgeai"
    p.write_text(script, encoding="utf-8")
    p.chmod(0o755)


def _run(
    tmp_path: Path, *args: str, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    _write_fake_python(bindir)
    _write_fake_ps(bindir)
    _write_fake_timeout(bindir)
    _write_fake_shellforgeai(bindir)
    log = tmp_path / "calls.log"
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["FAKE_LOG"] = str(log)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["bash", str(SCRIPT), *args], text=True, capture_output=True, env=env)


def _calls(tmp_path: Path) -> str:
    return (tmp_path / "calls.log").read_text(encoding="utf-8")


def test_usage_mentions_packet_flags() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "--packet" in text
    assert "--export-packet" in text


def test_quick_and_full_are_compatible(tmp_path: Path) -> None:
    q = _run(tmp_path / "q", "--quick")
    f = _run(tmp_path / "f", "--full")
    assert q.returncode == 0
    assert f.returncode == 0


def test_bare_quick_and_full_still_fail_usage(tmp_path: Path) -> None:
    q = _run(tmp_path / "bq", "quick")
    f = _run(tmp_path / "bf", "full")
    assert q.returncode != 0
    assert f.returncode != 0
    assert "Unknown option" in q.stderr


# 1. --quick --packet calls save and validate and prints summary.
def test_quick_packet_calls_save_and_validate_and_prints_summary(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--packet")
    calls = _calls(tmp_path)
    assert r.returncode == 0
    assert "SFAI v1 packet --save --json" in calls
    assert "SFAI v1 packet validate v1_packet_123 --json" in calls
    assert "packet_id: v1_packet_123" in r.stdout
    assert "validation: ok" in r.stdout


# 2. --full --packet calls save and validate.
def test_full_packet_calls_save_and_validate(tmp_path: Path) -> None:
    r = _run(tmp_path, "--full", "--packet")
    calls = _calls(tmp_path)
    assert r.returncode == 0
    assert "SFAI v1 packet --save --json" in calls
    assert "SFAI v1 packet validate v1_packet_123 --json" in calls


# 3. Valid stdout JSON with a stderr warning still passes and reaches validate.
def test_stderr_warning_does_not_fail_valid_stdout_json(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--packet", extra_env={"SFAI_PACKET_SAVE_STDERR_WARN": "1"})
    calls = _calls(tmp_path)
    assert r.returncode == 0
    assert "SFAI v1 packet validate v1_packet_123 --json" in calls


# 4. save nonzero exits nonzero and does not call validate.
def test_save_nonzero_exits_nonzero_and_skips_validate(tmp_path: Path) -> None:
    r = _run(tmp_path, "--full", "--packet", extra_env={"SFAI_PACKET_SAVE_MODE": "fail"})
    assert r.returncode != 0
    assert "Packet save failed" in r.stderr
    assert "SFAI v1 packet validate" not in _calls(tmp_path)


# 5. invalid save JSON exits nonzero and does not call validate.
def test_invalid_save_json_exits_nonzero_and_skips_validate(tmp_path: Path) -> None:
    r = _run(tmp_path, "--full", "--packet", extra_env={"SFAI_PACKET_SAVE_MODE": "malformed"})
    assert r.returncode != 0
    assert "Failed to parse packet JSON" in r.stderr
    assert "SFAI v1 packet validate" not in _calls(tmp_path)


# 6. save JSON missing packet_id and packet_path exits nonzero and does not call validate.
def test_missing_ref_exits_nonzero_and_skips_validate(tmp_path: Path) -> None:
    r = _run(tmp_path, "--full", "--packet", extra_env={"SFAI_PACKET_SAVE_SHAPE": "missing_ref"})
    assert r.returncode != 0
    assert "Packet JSON did not include packet_id or packet_path" in r.stderr
    assert "SFAI v1 packet validate" not in _calls(tmp_path)


# 7. save JSON with packet_path but no packet_id reaches validate with packet_path.
def test_packet_path_only_reaches_validate_with_path(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--packet", extra_env={"SFAI_PACKET_SAVE_SHAPE": "path_only"})
    calls = _calls(tmp_path)
    assert r.returncode == 0
    assert "SFAI v1 packet validate /d/p/v1_packet_123 --json" in calls


def test_nested_packet_shape_reaches_validate(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--packet", extra_env={"SFAI_PACKET_SAVE_SHAPE": "nested_packet"})
    assert r.returncode == 0
    assert "SFAI v1 packet validate v1_packet_123 --json" in _calls(tmp_path)


def test_artifact_packet_shape_reaches_validate(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--packet", extra_env={"SFAI_PACKET_SAVE_SHAPE": "artifact"})
    assert r.returncode == 0
    assert "SFAI v1 packet validate v1_packet_123 --json" in _calls(tmp_path)


def test_validate_nonzero_exits_nonzero(tmp_path: Path) -> None:
    r = _run(tmp_path, "--full", "--packet", extra_env={"SFAI_PACKET_VALIDATE_STATUS": "fail"})
    assert r.returncode != 0
    assert "Packet validation failed" in r.stderr


# 8. --quick --export-packet implies packet mode and calls save, validate, export, export-validate.
def test_export_packet_implies_packet_mode_full_chain(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--export-packet")
    calls = _calls(tmp_path)
    assert r.returncode == 0
    assert "SFAI v1 packet --save --json" in calls
    assert "SFAI v1 packet validate v1_packet_123 --json" in calls
    assert "SFAI v1 packet export v1_packet_123 --json" in calls
    assert "SFAI v1 packet export-validate exp123 --json" in calls
    assert "TIMEOUT" in calls


# 9. export stdout JSON with export_id reaches export-validate.
def test_export_id_only_reaches_export_validate(tmp_path: Path) -> None:
    r = _run(
        tmp_path,
        "--quick",
        "--export-packet",
        extra_env={"SFAI_PACKET_EXPORT_SHAPE": "id_only"},
    )
    calls = _calls(tmp_path)
    assert r.returncode == 0
    assert "SFAI v1 packet export-validate exp123 --json" in calls


# 10. export stdout JSON with export_path reaches export-validate.
def test_export_path_only_reaches_export_validate(tmp_path: Path) -> None:
    r = _run(
        tmp_path,
        "--quick",
        "--export-packet",
        extra_env={"SFAI_PACKET_EXPORT_SHAPE": "path_only"},
    )
    calls = _calls(tmp_path)
    assert r.returncode == 0
    assert "SFAI v1 packet export-validate /d/e/exp123 --json" in calls


def test_export_missing_ref_exits_nonzero_and_skips_export_validate(tmp_path: Path) -> None:
    r = _run(
        tmp_path,
        "--quick",
        "--export-packet",
        extra_env={"SFAI_PACKET_EXPORT_SHAPE": "missing_ref"},
    )
    assert r.returncode != 0
    assert "Packet export JSON did not include export_id or export_path" in r.stderr
    assert "SFAI v1 packet export-validate" not in _calls(tmp_path)


# 11. export nonzero exits nonzero and does not call export-validate.
def test_export_nonzero_exits_nonzero_and_skips_export_validate(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--export-packet", extra_env={"SFAI_PACKET_EXPORT_FAIL": "1"})
    assert r.returncode != 0
    assert "Packet export failed" in r.stderr
    assert "SFAI v1 packet export-validate" not in _calls(tmp_path)


# 12. export-validate nonzero exits nonzero.
def test_export_validate_nonzero_exits_nonzero(tmp_path: Path) -> None:
    r = _run(
        tmp_path,
        "--quick",
        "--export-packet",
        extra_env={"SFAI_PACKET_EXPORT_VALIDATE_FAIL": "1"},
    )
    assert r.returncode != 0
    assert "Packet export validation failed" in r.stderr


def test_export_packet_prints_export_summary(tmp_path: Path) -> None:
    r = _run(tmp_path, "--full", "--packet", "--export-packet")
    assert r.returncode == 0
    assert "export_id: exp123" in r.stdout


# 13. packet/export-packet path does not call mutation commands.
def test_packet_mode_does_not_call_mutation_commands(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--export-packet")
    calls = _calls(tmp_path).lower()
    assert r.returncode == 0
    forbidden = [
        "cleanup execute",
        "remediation execute",
        "rollback execute",
        "mission execute",
        " apply",
        "docker restart",
        "docker compose restart",
        "docker compose up",
        "docker compose down",
    ]
    for token in forbidden:
        assert token not in calls


# 14. missing dev tools produces a clear validation-lane error.
def test_missing_ruff_has_clear_validation_lane_message(tmp_path: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    (bindir / "python").write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
    (bindir / "python").chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    r = subprocess.run(["bash", str(SCRIPT), "--quick"], text=True, capture_output=True, env=env)
    assert r.returncode != 0
    assert "requires dev validation dependencies" in r.stderr


def test_packet_timeout_failure_is_controlled(tmp_path: Path) -> None:
    r = _run(
        tmp_path,
        "--quick",
        "--packet",
        extra_env={
            "SFAI_PACKET_SAVE_MODE": "timeout",
            "SFAI_VALIDATE_COMMAND_TIMEOUT_SECONDS": "7",
        },
    )
    calls = _calls(tmp_path)
    assert r.returncode != 0
    assert "TIMEOUT 7 shellforgeai v1 packet --save --json" in calls
    assert "command timed out after 7s" in r.stderr


def test_cli_v1_packet_save_json_is_strict_and_has_ids(tmp_path: Path) -> None:
    runner = CliRunner()
    r = runner.invoke(
        app,
        ["v1", "packet", "--save", "--json"],
        env={"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")},
    )
    assert r.exit_code in {0, 1}
    payload = json.loads(r.stdout)
    assert payload.get("packet_id")
    assert payload.get("packet_path")
    assert r.stdout.strip().startswith("{")


def test_packaged_default_config_resource_exists() -> None:
    cfg = files("shellforgeai").joinpath("config/default.yaml")
    text = cfg.read_text(encoding="utf-8")
    assert "app:" in text


def test_pyproject_declares_hatch_wheel_package_target() -> None:
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.hatch.build.targets.wheel]" in text
    assert 'packages = ["src/shellforgeai"]' in text
