from shellforgeai.core.latest_context import detect_latest_context_intent
from shellforgeai.interactive.commands import route_input


def test_system_role_phrases_route_to_health_diagnose() -> None:
    for text in [
        "what does this system do?",
        "what is this box?",
        "what is this machine for?",
        "what role is this server playing?",
    ]:
        routed = route_input(text)
        assert routed.name == "diagnose"
        assert routed.args == "health"


def test_health_phrases_route_to_health_diagnose() -> None:
    for text in [
        "is it running normally?",
        "is this system healthy?",
        "does this look normal?",
        "give me a quick health check",
        "what should I check first?",
    ]:
        routed = route_input(text)
        assert routed.name == "diagnose"
        assert routed.args == "health"


def test_latest_context_intent_detection_expanded_phrases() -> None:
    assert detect_latest_context_intent("what is this machine for?") == "system_role"
    assert detect_latest_context_intent("what role is this server playing?") == "system_role"
    assert detect_latest_context_intent("is this system healthy?") == "health_status"
    assert detect_latest_context_intent("give me a quick health check") == "health_status"
    assert detect_latest_context_intent("what should I check first?") == "health_status"
