from shellforgeai.interactive.commands import route_input
from shellforgeai.llm.prompts import build_model_prompt


def test_disk_intents_route_to_diagnose_disk() -> None:
    for phrase in [
        "how much disk space do we have left?",
        "free disk space",
        "is disk full",
    ]:
        routed = route_input(phrase)
        assert routed.name == "diagnose"
        assert routed.args == "disk"


def test_health_intents_route_to_diagnose_health() -> None:
    for phrase in [
        "my system is glitchy",
        "machine is acting weird",
        "any issue on this machine",
        "Anything wrong with my computer?",
        "Anything wrong with this machine?",
        "Is my computer okay?",
        "Do you see any issues?",
        "System health",
    ]:
        routed = route_input(phrase)
        assert routed.name == "diagnose"
        assert routed.args == "health"


def test_service_intents_route_to_service_discovery() -> None:
    for phrase in [
        "What services this computer is running?",
        "what services are running",
        "what ports are open",
        "what is listening on ports",
    ]:
        routed = route_input(phrase)
        assert routed.name == "diagnose"
        assert routed.args == "services"


def test_storage_performance_intents_route_to_diagnose_storage_performance() -> None:
    for phrase in [
        "I think my disk is slow",
        "disk is slow",
        "storage is slow",
        "high IO",
        "disk is dying",
        "NVMe issue",
    ]:
        routed = route_input(phrase)
        assert routed.name == "diagnose"
        assert routed.args == "storage_performance"


def test_plain_english_slow_phrase_routes_to_diagnose_performance() -> None:
    routed = route_input("Hey my computer feels slow")
    assert routed.name == "diagnose"
    assert routed.args in {"performance", "storage_performance"}


def test_filler_prefixed_intents_still_route() -> None:
    assert route_input("Hey, can you check if my computer feels slow?").name == "diagnose"
    assert route_input("Please, so what services are running?").args == "services"
    assert route_input("Uh, could you tell me how much disk space do we have left?").args == "disk"


def test_tool_first_ops_hints_prevent_generic_ask_fallthrough() -> None:
    assert route_input("can you check cpu pressure quickly").args == "performance"
    assert route_input("what ports are exposed right now").args == "services"
    assert route_input("is docker healthy").args == "docker"


def test_prompt_includes_collected_evidence_instruction() -> None:
    prompt = build_model_prompt(
        "how much disk space left",
        {"evidence": [{"tool": "disk.usage", "status": "ok", "summary": "/ 70% used"}]},
    )
    assert "already collected evidence" in prompt
    assert "Do not ask operators to rerun collectors already collected" in prompt


def test_prompt_supports_general_health_label() -> None:
    prompt = build_model_prompt(
        "Anything wrong with my computer?",
        {
            "evidence_label": "general health evidence",
            "machine_health": [{"tool": "host.info", "status": "ok", "summary": "hostname=test"}],
        },
    )
    assert "already collected general health evidence" in prompt
