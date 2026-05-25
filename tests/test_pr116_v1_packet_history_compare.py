import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _env(tmp_path):
    return {"SHELLFORGEAI_DATA_DIR": str(tmp_path / "data")}


def _save_packet(tmp_path):
    r = runner.invoke(app, ["v1", "packet", "--save", "--json"], env=_env(tmp_path))
    return json.loads(r.stdout)


def _patch_packet(packet_path: str, fn):
    d = Path(packet_path)
    p = d / "v1-packet.json"
    payload = json.loads(p.read_text(encoding="utf-8"))
    fn(payload)
    p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    manifest_path = d / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    from shellforgeai.core.ops_report_artifact import _sha256_file

    checksums = manifest.get("checksums") or {}
    checksums["v1-packet.json"] = _sha256_file(p)
    checksums["v1-packet.md"] = _sha256_file(d / "v1-packet.md")
    manifest["checksums"] = checksums
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def test_history_empty_json(tmp_path):
    r = runner.invoke(app, ["v1", "packet", "history", "--json"], env=_env(tmp_path))
    assert r.exit_code == 0
    p = json.loads(r.stdout)
    assert p["mode"] == "v1_packet_history"
    assert p["status"] == "empty"


def test_history_newest_first_and_limit(tmp_path):
    a = _save_packet(tmp_path)
    b = _save_packet(tmp_path)
    r = runner.invoke(
        app, ["v1", "packet", "history", "--limit", "1", "--json"], env=_env(tmp_path)
    )
    p = json.loads(r.stdout)
    assert p["summary"]["packets_found"] >= 2
    assert len(p["packets"]) == 1
    assert p["packets"][0]["packet_id"] == b["packet_id"]
    assert p["packets"][0]["packet_id"] != a["packet_id"]


def test_history_invalid_limit_controlled(tmp_path):
    r = runner.invoke(
        app, ["v1", "packet", "history", "--limit", "0", "--json"], env=_env(tmp_path)
    )
    assert r.exit_code == 1
    p = json.loads(r.stdout)
    assert p["status"] == "error"
    assert "Traceback" not in r.stdout


def test_compare_identical_ok(tmp_path):
    p = _save_packet(tmp_path)
    r = runner.invoke(
        app,
        ["v1", "packet", "compare", p["packet_id"], p["packet_id"], "--json"],
        env=_env(tmp_path),
    )
    out = json.loads(r.stdout)
    assert out["status"] == "ok"
    assert out["summary"]["regressions"] == 0


def test_compare_detects_regression_and_warning_delta(tmp_path):
    before = _save_packet(tmp_path)
    after = _save_packet(tmp_path)

    def mutate(payload):
        payload["status"] = "failed"
        payload["warnings"] = ["new warning"]
        summary = payload["checks"]["v1_check"].setdefault("summary", {})
        full = summary.setdefault("full", {"passed": 0, "failed": 0, "warned": 0})
        full["failed"] = 1
        payload["safety"]["mutation_performed"] = True

    _patch_packet(after["packet_path"], mutate)
    r = runner.invoke(
        app,
        ["v1", "packet", "compare", before["packet_id"], after["packet_id"], "--json"],
        env=_env(tmp_path),
    )
    out = json.loads(r.stdout)
    assert out["summary"]["regressions"] >= 1
    assert out["summary"]["new_warnings"] == 1
    assert out["summary"]["new_failures"] >= 1
    assert out["summary"]["safety_drift"] >= 1


def test_compare_by_path_and_options(tmp_path):
    before = _save_packet(tmp_path)
    after = _save_packet(tmp_path)
    r = runner.invoke(
        app,
        [
            "v1",
            "packet",
            "compare",
            before["packet_path"],
            after["packet_path"],
            "--json",
            "--only-changed",
            "--top",
            "3",
        ],
        env=_env(tmp_path),
    )
    out = json.loads(r.stdout)
    assert out["status"] == "ok"
    assert out["stable"] == []

    r2 = runner.invoke(
        app,
        [
            "v1",
            "packet",
            "compare",
            before["packet_id"],
            after["packet_id"],
            "--json",
            "--include-stable",
        ],
        env=_env(tmp_path),
    )
    out2 = json.loads(r2.stdout)
    assert len(out2["stable"]) >= 1


def test_compare_missing_and_malformed_controlled(tmp_path):
    r = runner.invoke(
        app, ["v1", "packet", "compare", "missing", "missing2", "--json"], env=_env(tmp_path)
    )
    p = json.loads(r.stdout)
    assert p["status"] in {"not_found", "error"}

    saved = _save_packet(tmp_path)
    (Path(saved["packet_path"]) / "v1-packet.json").write_text("{bad", encoding="utf-8")
    r2 = runner.invoke(
        app,
        ["v1", "packet", "compare", saved["packet_id"], saved["packet_id"], "--json"],
        env=_env(tmp_path),
    )
    p2 = json.loads(r2.stdout)
    assert p2["status"] in {"failed", "error"}
    assert "Traceback" not in r2.stdout


def test_compare_latest_not_enough_and_ok(tmp_path):
    r = runner.invoke(app, ["v1", "packet", "compare-latest", "--json"], env=_env(tmp_path))
    p = json.loads(r.stdout)
    assert r.exit_code == 1
    assert p["status"] == "not_enough_history"

    _save_packet(tmp_path)
    _save_packet(tmp_path)
    r2 = runner.invoke(
        app, ["v1", "packet", "compare-latest", "--json", "--include-stable"], env=_env(tmp_path)
    )
    p2 = json.loads(r2.stdout)
    assert p2["status"] == "ok"
    assert p2["read_only"] is True
