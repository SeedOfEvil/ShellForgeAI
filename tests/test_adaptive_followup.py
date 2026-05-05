from shellforgeai.interactive.repl import select_followup_investigation


def test_storage_pressure_selects_storage_followup() -> None:
    sel = select_followup_investigation(
        "performance",
        [{"tool": "storage.pressure", "summary": "io_some_avg10=1.7", "status": "ok"}],
        "is this server running slow?",
    )
    assert sel
    assert sel["intent"] == "storage_io_deep_dive"


def test_service_question_selects_service_followup() -> None:
    sel = select_followup_investigation("health", [], "what services are running?")
    assert sel
    assert sel["intent"] == "service_health_deep_dive"
