from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.interactive.repl import select_followup_investigation

runner = CliRunner()


def test_disk_space_question_selects_disk_capacity_deep_dive() -> None:
    checks = [
        {"tool": "disk.usage", "summary": "/ 35% used", "status": "ok"},
        {"tool": "disk.inodes", "summary": "/ 24% used", "status": "ok"},
    ]
    sel = select_followup_investigation("disk", checks, "what is using disk space?")
    assert sel and sel["intent"] == "disk_capacity_deep_dive"


def test_taking_up_space_selects_disk_capacity_deep_dive() -> None:
    checks = [{"tool": "disk.usage", "summary": "/ 30% used", "status": "ok"}]
    sel = select_followup_investigation("disk", checks, "what is taking up space?")
    assert sel and sel["intent"] == "disk_capacity_deep_dive"


def test_largest_folders_selects_disk_capacity_deep_dive() -> None:
    checks = [{"tool": "disk.inodes", "summary": "/ 30% used", "status": "ok"}]
    sel = select_followup_investigation("disk", checks, "largest folders")
    assert sel and sel["intent"] == "disk_capacity_deep_dive"


def test_diagnose_prints_existing_summary_path() -> None:
    res = runner.invoke(app, ["diagnose", "disk", "--save-plan"])
    assert res.exit_code == 0
    assert "- summary:" in res.output
    summary_path = [
        ln.split(": ", 1)[1] for ln in res.output.splitlines() if ln.startswith("- summary:")
    ][0]
    assert summary_path != "n/a"
