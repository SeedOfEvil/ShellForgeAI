from shellforgeai.interactive.repl import select_followup_investigation


def test_disk_healthy_no_followup() -> None:
    checks = [
        {"tool": "disk.usage", "summary": "/ 35% used", "status": "ok"},
        {"tool": "disk.inodes", "summary": "/ 24% used", "status": "ok"},
    ]
    sel = select_followup_investigation("disk", checks, "is my disk getting full?")
    assert sel is None


def test_disk_high_selects_disk_capacity() -> None:
    checks = [
        {"tool": "disk.usage", "summary": "/ 85% used", "status": "ok"},
        {"tool": "disk.inodes", "summary": "/ 24% used", "status": "ok"},
    ]
    sel = select_followup_investigation("disk", checks, "is my disk full?")
    assert sel and sel["intent"] == "disk_capacity_deep_dive"
