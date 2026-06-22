import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_storage_health_report.py"


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


h = _load("pr230_storage_health", HELPER_PATH)


DF = (
    "Filesystem 1-blocks Used Available Capacity Mounted on\n"
    "/dev/mapper/vg-root 53687091200 10737418240 42949672960 20% /\n"
    "/dev/mapper/vg-data 107374182400 96636764160 10737418240 90% /data\n"
)

PROC_MOUNTS = (
    "/dev/mapper/vg-root / ext4 rw,relatime 0 0\n"
    "/dev/mapper/vg-data /data xfs rw,relatime 0 0\n"
    "overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n"
)

DMESG_WITH_WARNINGS = "\n".join(
    [
        "[Mon Jun 22 10:00:00 2026] EXT4-fs warning (device dm-10): ext4_check journal",
        "[Mon Jun 22 10:00:01 2026] EXT4-fs error (device dm-10): inode #1234 corrupted",
        "[Mon Jun 22 10:00:02 2026] Buffer I/O error on device dm-10, logical block 99",
        "[Mon Jun 22 10:00:03 2026] usb 1-1: new high-speed USB device number 5",
        "[Mon Jun 22 10:00:04 2026] wlan0: authenticated with access point",
    ]
)


class FakeUsage:
    def __init__(self, total, used, free):
        self.total = total
        self.used = used
        self.free = free


def fake_disk_usage(path):
    # root: 30% used; docker data path also returns a value
    if path == "/":
        return FakeUsage(100, 30, 70)
    return FakeUsage(200, 60, 140)


def make_runner(*, df=DF, dmesg=DMESG_WITH_WARNINGS, dmesg_available=True, findmnt_available=False):
    def runner(spec):
        if spec.key == "df":
            return h.CommandResult(spec.key, list(spec.argv), 0, df, "", True, "")
        if spec.key == "findmnt":
            if findmnt_available:
                return h.CommandResult(spec.key, list(spec.argv), 0, "{}", "", True, "")
            return h.CommandResult(
                spec.key, list(spec.argv), None, "", "missing", False, "command unavailable"
            )
        if spec.key == "dmesg":
            if dmesg_available:
                return h.CommandResult(spec.key, list(spec.argv), 0, dmesg, "", True, "")
            return h.CommandResult(
                spec.key,
                list(spec.argv),
                1,
                "",
                "dmesg: read kernel buffer failed: Operation not permitted",
                False,
                "permission denied",
            )
        if spec.key == "journalctl_kernel":
            return h.CommandResult(
                spec.key, list(spec.argv), None, "", "missing", False, "command unavailable"
            )
        raise AssertionError(f"unexpected spec {spec.key}")

    return runner


def build(tmp_path, **kwargs):
    mounts = tmp_path / "mounts"
    mounts.write_text(PROC_MOUNTS)
    defaults = dict(
        runner=make_runner(),
        disk_usage_fn=fake_disk_usage,
        proc_mounts=mounts,
        docker_data_path=str(tmp_path / "missing-docker"),
    )
    defaults.update(kwargs)
    return h.build_report(**defaults)


# ---------------------------------------------------------------------------
# JSON / human output
# ---------------------------------------------------------------------------


def test_json_strict_and_shape(tmp_path):
    report, _ = build(tmp_path)
    text = json.dumps(report)  # must be JSON-serializable
    loaded = json.loads(text)
    assert loaded["schema_version"] == 1
    assert loaded["mode"] == "docker01_storage_health_report"
    assert loaded["status"] in {"ok", "warning", "partial", "failed"}
    for key in ("summary", "filesystems", "kernel_warnings", "checks", "safety", "warnings"):
        assert key in loaded


def test_human_output_is_concise(tmp_path):
    report, _ = build(tmp_path)
    out = h.render_summary(report)
    assert "# Docker01 Storage Health Report" in out
    assert "Read-only: yes" in out
    assert "## Disk usage" in out
    assert "## Kernel/storage warnings" in out
    assert "## Safe next" in out
    assert len(out.splitlines()) < 60


def test_read_only_and_mutation_flags(tmp_path):
    report, _ = build(tmp_path)
    assert report["read_only"] is True
    assert report["mutation_performed"] is False


def test_core_disk_usage_in_summary(tmp_path):
    report, _ = build(tmp_path)
    s = report["summary"]
    assert s["root_total_bytes"] == 100
    assert s["root_used_bytes"] == 30
    assert s["root_free_bytes"] == 70
    assert s["root_used_percent"] == 30
    assert s["disk_pressure_level"] == "ok"


def test_missing_dmesg_permission_is_partial_not_crash(tmp_path):
    report, _ = build(tmp_path, runner=make_runner(dmesg_available=False))
    # no pressure (30%), no readable kernel evidence -> partial
    assert report["status"] == "partial"
    assert any("permission" in w or "unavailable" in w for w in report["warnings"])
    assert report["kernel_warnings"] == []


# ---------------------------------------------------------------------------
# Warning detection
# ---------------------------------------------------------------------------


def test_ext4_pattern_counted(tmp_path):
    report, _ = build(tmp_path)
    assert report["summary"]["ext4_warning_patterns_found"] >= 1


def test_dm_pattern_counted(tmp_path):
    report, _ = build(tmp_path)
    assert report["summary"]["dm_warning_patterns_found"] >= 1


def test_io_journal_inode_pattern_counted(tmp_path):
    report, _ = build(tmp_path)
    counts = report["kernel_warning_counts"]
    assert counts["io_error"] >= 1
    assert counts["journal"] >= 1
    assert counts["inode"] >= 1
    assert h._io_count(report) >= 1


def test_warning_lines_bounded(tmp_path):
    big = "\n".join(f"EXT4-fs error on dm-{i}: inode bad" for i in range(500))
    report, _ = build(
        tmp_path,
        runner=make_runner(dmesg=big),
        max_dmesg_lines=300,
        max_warning_lines=5,
    )
    assert len(report["kernel_warnings"]) <= 5
    for entry in report["kernel_warnings"]:
        assert len(entry["line"]) <= h.LINE_LIMIT


def test_unrelated_lines_ignored(tmp_path):
    benign = "usb device connected\nwlan0 authenticated\nCPU temperature normal\n"
    report, _ = build(tmp_path, runner=make_runner(dmesg=benign))
    assert report["summary"]["kernel_storage_warnings_found"] == 0
    assert report["kernel_warnings"] == []


# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------


def test_out_writes_required_files(tmp_path):
    report, results = build(tmp_path)
    out = tmp_path / "report-out"
    h.write_output_dir(out, report, results)
    for name in h.REQUIRED_OUT_FILES:
        assert (out / name).is_file(), name
    summary = (out / "storage-health-summary.md").read_text()
    assert "Docker01 Storage Health Report" in summary


def test_manifest_and_checksums_include_sha256_and_sizes(tmp_path):
    report, results = build(tmp_path)
    out = tmp_path / "report-out"
    h.write_output_dir(out, report, results)
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["artifacts"]
    for art in manifest["artifacts"]:
        assert len(art["sha256"]) == 64
        assert isinstance(art["size_bytes"], int)
        assert art["size_bytes"] > 0
    checksums = json.loads((out / "checksums.json").read_text())
    assert "storage-health-report.json" in checksums
    assert all(len(v) == 64 for v in checksums.values())


def test_commands_run_records_read_only_only(tmp_path):
    report, results = build(tmp_path)
    out = tmp_path / "report-out"
    h.write_output_dir(out, report, results)
    commands = json.loads((out / "commands-run.json").read_text())
    assert isinstance(commands, list)
    for entry in commands:
        assert entry["read_only"] is True
        assert entry["argv"][0] in h.ALLOWED_EXECUTABLES
        # raw logs are not copied in full
        assert "stdout" not in entry


# ---------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------


def test_no_repair_commands_used():
    for form in h.ALLOWED_COMMAND_FORMS:
        assert not h.command_is_forbidden(form)
    assert h.command_is_forbidden(("fsck", "/dev/dm-10"))
    assert h.command_is_forbidden(("e2fsck", "-y", "/dev/dm-10"))
    assert h.command_is_forbidden(("xfs_repair", "/dev/dm-10"))


@pytest.mark.parametrize(
    "argv",
    [
        ("fsck", "/dev/x"),
        ("e2fsck", "/dev/x"),
        ("xfs_repair", "/dev/x"),
        ("mount", "/dev/x", "/mnt"),
        ("umount", "/mnt"),
        ("rm", "-rf", "/tmp/x"),
        ("docker", "system", "prune"),
        ("docker", "image", "rm", "x"),
        ("docker", "restart", "x"),
        ("systemctl", "restart", "docker"),
        ("apt", "install", "x"),
        ("pip", "install", "x"),
        ("curl", "https://x"),
        ("wget", "https://x"),
        ("gh", "pr", "merge"),
        ("codex", "apply"),
    ],
)
def test_forbidden_commands_not_allowlisted(argv):
    assert not h.is_allowlisted_command(argv)


def test_source_has_no_shell_true():
    src = HELPER_PATH.read_text()
    assert "shell=True" not in src
    assert "shell=False" in src


def test_safety_block_all_mutation_flags_false():
    safety = h.safety_block()
    assert safety["read_only"] is True
    for key, value in safety.items():
        if key == "read_only":
            continue
        assert value is False, key


def test_helper_does_not_call_docker_mutation_commands():
    # Docker is not an allowlisted executable, so no docker command can run.
    assert "docker" not in h.ALLOWED_EXECUTABLES
    for form in h.ALLOWED_COMMAND_FORMS:
        assert form[0] != "docker"
    # And any docker mutation argv would be flagged forbidden / not allowlisted.
    for argv in [
        ("docker", "system", "prune"),
        ("docker", "image", "rm", "x"),
        ("docker", "volume", "rm", "x"),
        ("docker", "container", "rm", "x"),
        ("docker", "compose", "down"),
    ]:
        assert not h.is_allowlisted_command(argv)


def test_helper_does_not_call_network_or_model():
    src = HELPER_PATH.read_text().lower()
    for token in ("requests", "urllib.request", "http://", "https://", "openai", "anthropic"):
        assert token not in src


def test_allowlisted_commands_are_read_only():
    assert h.is_allowlisted_command(("df", "-P", "-B1"))
    assert h.is_allowlisted_command(("findmnt", "--json"))
    assert h.is_allowlisted_command(("dmesg", "--level=err,warn", "--ctime"))
    assert h.is_allowlisted_command(
        ("journalctl", "-k", "-p", "warning..alert", "--no-pager", "-n", "200")
    )
    assert not h.is_allowlisted_command(("journalctl", "-k", "--rotate"))


def test_run_allowed_command_rejects_non_allowlisted():
    with pytest.raises(ValueError):
        h.run_allowed_command(h.CommandSpec("x", ("rm", "-rf", "/")))


# ---------------------------------------------------------------------------
# Status / filesystem behaviors
# ---------------------------------------------------------------------------


def test_warning_status_when_patterns_found(tmp_path):
    report, _ = build(tmp_path)
    assert report["status"] == "warning"


def test_failed_when_core_disk_usage_unavailable(tmp_path):
    def boom(path):
        raise OSError("no disk_usage")

    report, _ = build(tmp_path, disk_usage_fn=boom)
    assert report["status"] == "failed"
    assert report["errors"]
    assert report["mutation_performed"] is False


def test_filesystems_use_proc_mounts_fstype(tmp_path):
    report, _ = build(tmp_path)
    by_mount = {fs["mount"]: fs for fs in report["filesystems"]}
    assert by_mount["/"]["fstype"] == "ext4"
    assert by_mount["/data"]["fstype"] == "xfs"
    assert by_mount["/data"]["used_percent"] == 90


def test_df_fallback_to_proc_mounts_when_df_unavailable(tmp_path):
    def runner(spec):
        if spec.key == "df":
            return h.CommandResult(
                spec.key, list(spec.argv), 1, "", "no df", False, "command failed"
            )
        return make_runner()(spec)

    report, _ = build(tmp_path, runner=runner)
    # fallback mounts still produce filesystem entries (without sizes)
    mounts = {fs["mount"] for fs in report["filesystems"]}
    assert "/" in mounts


def test_main_json_and_out(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(h.shutil, "disk_usage", fake_disk_usage)
    monkeypatch.setattr(h, "run_allowed_command", make_runner())
    out = tmp_path / "cli-out"
    rc = h.main(["--json", "--out", str(out)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "docker01_storage_health_report"
    assert (out / "storage-health-report.json").is_file()


def test_main_human_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(h.shutil, "disk_usage", fake_disk_usage)
    monkeypatch.setattr(h, "run_allowed_command", make_runner())
    rc = h.main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Docker01 Storage Health Report" in out
