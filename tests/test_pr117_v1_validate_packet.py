from __future__ import annotations

import os
import subprocess
from pathlib import Path

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
    if mode == 'malformed':
        print('{not-json')
        raise SystemExit(0)
    print(json.dumps({'artifact': {'id': 'v1_packet_123', 'path': '/d/p/v1_packet_123'}}))
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
    print(json.dumps({'artifact': {'id': 'exp123', 'path': '/d/e/exp123'}}))
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
    _write_fake_shellforgeai(bindir)
    log = tmp_path / "calls.log"
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["FAKE_LOG"] = str(log)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["bash", str(SCRIPT), *args], text=True, capture_output=True, env=env)


def test_usage_mentions_packet_flags() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "--packet" in text
    assert "--export-packet" in text


def test_quick_and_full_are_compatible(tmp_path: Path) -> None:
    q = _run(tmp_path / "q", "--quick")
    f = _run(tmp_path / "f", "--full")
    assert q.returncode == 0
    assert f.returncode == 0


def test_packet_mode_calls_save_and_validate_and_prints_summary(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--packet")
    calls = (tmp_path / "calls.log").read_text(encoding="utf-8")
    assert "SFAI v1 packet --save --json" in calls
    assert "SFAI v1 packet validate v1_packet_123 --json" in calls
    assert "packet_id: v1_packet_123" in r.stdout
    assert "validation: ok" in r.stdout


def test_packet_failure_modes_are_nonzero(tmp_path: Path) -> None:
    bad_save = _run(
        tmp_path / "a", "--full", "--packet", extra_env={"SFAI_PACKET_SAVE_MODE": "fail"}
    )
    bad_validate = _run(
        tmp_path / "b", "--full", "--packet", extra_env={"SFAI_PACKET_VALIDATE_STATUS": "fail"}
    )
    bad_json = _run(
        tmp_path / "c", "--full", "--packet", extra_env={"SFAI_PACKET_SAVE_MODE": "malformed"}
    )
    assert bad_save.returncode != 0
    assert bad_validate.returncode != 0
    assert bad_json.returncode != 0
    assert "Failed to parse packet JSON" in bad_json.stderr


def test_packet_mode_does_not_call_mutation_commands(tmp_path: Path) -> None:
    r = _run(tmp_path, "--quick", "--packet")
    calls = (tmp_path / "calls.log").read_text(encoding="utf-8").lower()
    assert r.returncode == 0
    forbidden = [
        "remediation execute",
        "rollback-execute",
        "cleanup execute",
        "docker restart",
        "docker compose restart",
        "docker compose up",
        "docker compose down",
    ]
    for token in forbidden:
        assert token not in calls


def test_bare_quick_and_full_still_fail_usage(tmp_path: Path) -> None:
    q = _run(tmp_path / "bq", "quick")
    f = _run(tmp_path / "bf", "full")
    assert q.returncode != 0
    assert f.returncode != 0
    assert "Unknown option" in q.stderr


def test_export_packet_flow_and_failure(tmp_path: Path) -> None:
    ok = _run(tmp_path / "ok", "--full", "--packet", "--export-packet")
    fail = _run(
        tmp_path / "fail",
        "--full",
        "--packet",
        "--export-packet",
        extra_env={"SFAI_PACKET_EXPORT_VALIDATE_FAIL": "1"},
    )
    assert ok.returncode == 0
    assert "export_id: exp123" in ok.stdout
    assert fail.returncode != 0
