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
