from shellforgeai.interactive.repl import (
    _contains_internal_collector_language,
    _operator_followup_text,
)


def test_internal_collector_language_detected() -> None:
    assert _contains_internal_collector_language("Please run process.top and logs.search_errors")


def test_operator_followup_text_hides_collectors() -> None:
    txt = _operator_followup_text("performance")
    assert "process.top" not in txt
    assert "logs.search_errors" not in txt
    assert "Proceed with deeper read-only investigation?" in txt
