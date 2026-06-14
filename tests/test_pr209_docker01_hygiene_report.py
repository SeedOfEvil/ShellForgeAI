import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "scripts" / "docker01_hygiene_report.py"


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


h = _load("pr209_hygiene", HELPER_PATH)


DF = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/root        50G   42G  8G  84% /\n"
INSPECT = json.dumps(
    [
        {
            "State": {"Status": "running", "Health": {"Status": "healthy"}},
            "RestartCount": 2,
            "Config": {"Image": "lab/shellforgeai:pr209-abcd", "Labels": {"app": "shellforgeai"}},
        }
    ]
)
IMAGES = "\n".join(
    [
        json.dumps(
            {
                "Repository": "lab/shellforgeai",
                "Tag": "pr209-abcd",
                "ID": "sha256:1",
                "Size": "1GB",
                "CreatedSince": "1 day ago",
            }
        ),
        json.dumps(
            {
                "Repository": "lab/shellforgeai",
                "Tag": "pr205-c3af0f7",
                "ID": "sha256:2",
                "Size": "950MB",
                "CreatedSince": "2 weeks ago",
            }
        ),
        json.dumps(
            {
                "Repository": "lab/shellforgeai",
                "Tag": "latest",
                "ID": "sha256:3",
                "Size": "1GB",
                "CreatedSince": "1 day ago",
            }
        ),
        json.dumps(
            {
                "Repository": "<none>",
                "Tag": "<none>",
                "ID": "sha256:4",
                "Size": "100MB",
                "CreatedSince": "3 weeks ago",
            }
        ),
    ]
)


def fake_runner(spec):
    out = {
        "disk": DF,
        "docker_ps": (
            "CONTAINER ID IMAGE COMMAND NAMES\nabc lab/shellforgeai:pr209-abcd shellforgeai\n"
        ),
        "docker_inspect": INSPECT,
        "docker_images": "REPOSITORY TAG DIGEST IMAGE ID CREATED SIZE\n",
        "docker_image_ls": IMAGES,
    }[spec.key]
    return h.CommandResult(spec.key, list(spec.argv), 0, out, "", True, "")


def test_report_creation_contract_and_parsing(tmp_path):
    (tmp_path / "sfai-pr208-validation-log").write_text("ok")
    (tmp_path / "sfai-pr207-qa-bundle-old").mkdir()
    (tmp_path / "sfai-pr206-packet-old").mkdir()
    (tmp_path / "sfai-prod-receipt.json").write_text("{}")
    (tmp_path / "compose.yml.bak-pr205").write_text("compose")

    report = h.write_report(
        tmp_path / "report", runner=fake_runner, roots=(str(tmp_path), str(tmp_path / "missing"))
    )

    report_dir = tmp_path / "report"
    for rel in [
        "hygiene-summary.md",
        "hygiene-report.json",
        "candidate-cleanup-plan.md",
        "commands-run.json",
        "raw/disk.txt",
        "raw/docker-ps.txt",
        "raw/docker-inspect.json",
        "raw/docker-images.txt",
        "raw/docker-image-ls.jsonl",
    ]:
        assert (report_dir / rel).exists(), rel
    loaded = json.loads((report_dir / "hygiene-report.json").read_text())
    assert loaded["status"] == "ok"
    assert loaded["disk"]["use_percent"] == "84%"
    assert loaded["container"]["status"] == "running"
    assert loaded["container"]["health"] == "healthy"
    assert loaded["summary"]["shellforgeai_images_total"] == 3
    assert loaded["summary"]["compose_backups_total"] == 1
    assert loaded["summary"]["validation_artifacts_total"] == 1
    assert loaded["summary"]["qa_bundles_total"] == 1
    assert loaded["summary"]["receipt_artifacts_total"] == 1
    assert loaded["filesystem_roots"][str(tmp_path / "missing")]["available"] is False
    assert "Docker01 Hygiene Report" in (report_dir / "hygiene-summary.md").read_text()
    plan = (report_dir / "candidate-cleanup-plan.md").read_text()
    assert "This is not an executable cleanup script" in plan
    assert "No cleanup was performed" in plan
    refs = {c["item"] for c in report["candidate_cleanup"]}
    assert "lab/shellforgeai:pr205-c3af0f7" in refs
    assert "lab/shellforgeai:pr209-abcd" not in refs
    assert all("risk_note" in c and "reason" in c for c in report["candidate_cleanup"])


def test_dry_run_lists_checks_and_writes_nothing(tmp_path, capsys):
    out = tmp_path / "dry"
    assert h.main(["--dry-run", "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "Planned read-only checks" in text
    assert "docker image ls --format json" in text
    assert not out.exists()
    assert h.dry_run_payload(out)["commands_executed"] is False
    assert h.dry_run_payload(out)["report_written"] is False


def test_dry_run_json(tmp_path, capsys):
    h.main(["--dry-run", "--json", "--out", str(tmp_path / "dry")])
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "dry_run"
    assert payload["commands_executed"] is False


@pytest.mark.parametrize("argv", [spec.argv for spec in h.COMMAND_SPECS])
def test_planned_commands_are_allowlisted(argv):
    assert h.is_allowlisted_command(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ("docker", "restart", "shellforgeai"),
        ("docker", "compose", "restart"),
        ("docker", "compose", "down"),
        ("docker", "volume", "prune"),
        ("docker", "system", "prune"),
        ("docker", "image", "rm", "x"),
        ("docker", "rmi", "x"),
        ("rm", "-rf", "/tmp/x"),
        ("touch", "/tmp/x"),
        ("curl", "https://example.invalid"),
        ("wget", "https://example.invalid"),
        ("pip", "install", "x"),
        ("apt", "install", "x"),
        ("gh", "pr", "merge"),
        ("codex", "apply"),
    ],
)
def test_unsafe_commands_rejected(argv):
    assert not h.is_allowlisted_command(argv)


def test_shell_true_safety_flag_and_source():
    assert h.safety_block()["shell_true"] is False
    assert "shell=False" in Path("scripts/docker01_hygiene_report.py").read_text()


def test_parsers_handle_inputs():
    assert h.parse_df_root(DF)["available"] == "8G"
    assert h.parse_docker_inspect(INSPECT)["restart_count"] == 2
    images = h.parse_image_jsonl(IMAGES)
    assert sum(1 for i in images if i["is_pr_image"]) == 2


def test_missing_docker_is_partial_not_crash(tmp_path):
    def runner(spec):
        if spec.key.startswith("docker"):
            return h.CommandResult(
                spec.key, list(spec.argv), None, "", "missing", False, "command unavailable"
            )
        return h.CommandResult(spec.key, list(spec.argv), 0, DF, "", True, "")

    report = h.write_report(tmp_path / "report", runner=runner, roots=(str(tmp_path / "missing"),))
    assert report["status"] == "partial"
    assert report["container"]["available"] is False
    commands = json.loads((tmp_path / "report" / "commands-run.json").read_text())
    assert any(c["stderr"] == "missing" and c["returncode"] is None for c in commands)


def test_report_creation_failure_reported_cleanly(tmp_path, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise OSError("nope")

    monkeypatch.setattr(h, "write_report", boom)
    assert h.main(["--json", "--out", str(tmp_path / "x")]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert payload["mutation_performed"] is False
