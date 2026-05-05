from shellforgeai.interactive.commands import route_input
from shellforgeai.interactive.repl import (
    _contains_internal_collector_language,
    _operator_followup_text,
)


def test_sluggish_routes_to_performance() -> None:
    assert route_input("system feels sluggish").name == "diagnose"
    assert route_input("system feels sluggish").args == "performance"
    assert route_input("things feel slow").args == "performance"
    assert route_input("host feels slow").args == "performance"


def test_operator_followup_is_human() -> None:
    out = _operator_followup_text("CPU/process pressure", "top processes and pressure signals")
    assert "process.top" not in out
    assert "Say `proceed` or `dig deeper`" in out


def test_collector_leak_detection_expanded() -> None:
    assert _contains_internal_collector_language("host.info: ok")
