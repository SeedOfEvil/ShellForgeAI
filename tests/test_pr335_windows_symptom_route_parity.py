from __future__ import annotations

from types import SimpleNamespace

import pytest

from shellforgeai.core import windows_evidence_context as context
from shellforgeai.core import windows_operator_ux as ux


@pytest.mark.parametrize(
    ("intent", "phrases"),
    [
        (
            ux.WINDOWS_OPERATOR_INTENT_PERFORMANCE,
            [
                "Why does this system feel slow?",
                "Why is this Windows host slow?",
                "The system feels sluggish.",
            ],
        ),
        (
            ux.WINDOWS_OPERATOR_INTENT_SERVICES,
            [
                "Are the services healthy?",
                "How do the services look?",
                "Any failed or unhealthy services?",
            ],
        ),
        (
            ux.WINDOWS_OPERATOR_INTENT_DISK_CAPACITY,
            [
                "How is disk capacity?",
                "Are any drives low on space?",
                "How much free space is available?",
                "How does C: look?",
            ],
        ),
        (
            ux.WINDOWS_OPERATOR_INTENT_NETWORK_HEALTH,
            [
                "How does the network look?",
                "Is networking healthy?",
                "Do you see a network problem?",
            ],
        ),
    ],
)
def test_native_windows_symptom_phrase_matrix(intent: str, phrases: list[str]) -> None:
    for phrase in phrases:
        route = ux.classify_windows_interactive_intent(phrase, host_system="Windows")
        assert route == ux.WindowsOperatorRoute(intent, True, "windows" in phrase.lower())
        linux_route = ux.classify_windows_interactive_intent(phrase, host_system="Linux")
        if "windows" in phrase.lower():
            assert linux_route == ux.WindowsOperatorRoute(intent, False, True)
        else:
            assert linux_route is None


@pytest.mark.parametrize(
    "phrase",
    [
        "customer service status",
        "contact the service desk",
        "software as a service",
        "network marketing",
        "disk jockey service",
    ],
)
def test_bounded_matching_avoids_unrelated_phrases(phrase: str) -> None:
    assert ux.classify_windows_interactive_intent(phrase, host_system="Windows") is None


@pytest.mark.parametrize(
    "phrase",
    [
        "Why is this Docker service slow?",
        "Is the container out of disk space?",
        "Does this Compose service have a network problem?",
    ],
)
def test_explicit_container_targets_keep_precedence(phrase: str) -> None:
    assert ux.classify_windows_interactive_intent(phrase, host_system="Windows") is None


@pytest.mark.parametrize(
    "phrase",
    [
        "Fix it now.",
        "Restart the failing service.",
        "Kill the slow process.",
        "Clean up the disk.",
        "Repair the network.",
    ],
)
def test_mutation_refusal_precedes_symptom_routes(phrase: str) -> None:
    route = ux.classify_windows_interactive_intent(phrase, host_system="Windows")
    assert route is not None
    assert route.intent == ux.WINDOWS_OPERATOR_INTENT_MUTATION_REFUSAL


def test_coherent_packet_projects_every_existing_native_domain(monkeypatch) -> None:
    info = SimpleNamespace(system="windows")
    calls: dict[str, int] = {}

    def once(name: str, payload: dict):
        def builder(*args, **kwargs):
            calls[name] = calls.get(name, 0) + 1
            return payload

        return builder

    monkeypatch.setattr(
        context,
        "windows_status_payload",
        once(
            "status",
            {
                "host": {"hostname": "win"},
                "filesystem": {
                    "root_usage": {
                        "path": "C:\\\\",
                        "total_bytes": 100,
                        "used_bytes": 40,
                        "free_bytes": 60,
                    }
                },
            },
        ),
    )
    monkeypatch.setattr(
        context,
        "windows_memory_payload",
        once(
            "memory",
            {
                "memory": {
                    "available": True,
                    "total_bytes": 100,
                    "available_bytes": 60,
                    "used_bytes": 40,
                    "used_percent": 40,
                }
            },
        ),
    )
    monkeypatch.setattr(
        context,
        "windows_disks_payload",
        once(
            "disks",
            {
                "summary": {"total_roots": 1},
                "disks": [
                    {
                        "status": "ok",
                        "root": "C:\\\\",
                        "total_bytes": 100,
                        "used_bytes": 40,
                        "free_bytes": 60,
                        "used_percent": 40,
                    }
                ],
            },
        ),
    )
    monkeypatch.setattr(
        context,
        "windows_processes_payload",
        once(
            "processes",
            {
                "status": "ok",
                "state": {},
                "total_count": 1,
                "processes": [{"pid": 1, "name": "native.exe", "thread_count": 2}],
            },
        ),
    )
    monkeypatch.setattr(
        context,
        "windows_services_payload",
        once(
            "services",
            {
                "status": "ok",
                "services": {
                    "total_count": 2,
                    "state_counts": {"running": 1, "stopped": 1},
                    "items": [],
                },
            },
        ),
    )
    monkeypatch.setattr(
        context,
        "windows_events_payload",
        once("events", {"status": "ok", "summary": {"error": 1}, "events": []}),
    )
    monkeypatch.setattr(
        context,
        "windows_network_payload",
        once(
            "network",
            {
                "status": "ok",
                "summary": {"interfaces_up": 1, "ipv4_addresses": 1},
                "interfaces": [{"name": "Ethernet"}],
            },
        ),
    )
    monkeypatch.setattr(
        context,
        "windows_volumes_payload",
        once(
            "volumes",
            {
                "status": "ok",
                "summary": {"available_volumes": 1},
                "volumes": [{"root": "C:\\\\", "free_bytes": 60}],
            },
        ),
    )

    packet = context.build_windows_evidence_context(info)
    assert set(calls.values()) == {1}
    assert all(
        packet[name]["available"]
        for name in ("memory", "disk", "processes", "services", "events", "network", "volumes")
    )
    rendered = "\n".join(row["summary"] for row in context.windows_evidence_prompt_facts(packet))
    assert "native.exe" in rendered and "C:\\" in rendered and "interfaces_up=1" in rendered
    assert "ps unavailable" not in rendered and "df unavailable" not in rendered
