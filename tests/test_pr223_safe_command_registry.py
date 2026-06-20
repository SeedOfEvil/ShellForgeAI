from __future__ import annotations

from shellforgeai.core.safe_commands import (
    filter_or_replace_unsafe_command_suggestions,
    is_known_safe_shellforgeai_command,
    registered_safe_commands,
    suggest_safe_next_command,
)


def test_registry_contains_only_read_only_non_mutating_safe_commands() -> None:
    commands = registered_safe_commands()
    assert commands
    text = "\n".join(entry.command for entry in commands)
    assert any(entry.id == "triage_docker" for entry in commands)
    assert any(entry.id == "triage_docker_detail" for entry in commands)
    assert any(entry.id in {"ops_report", "status"} for entry in commands)
    for entry in commands:
        assert entry.command.startswith("shellforgeai ")
        assert entry.read_only is True
        assert entry.mutation is False
        assert entry.suggest is True
        assert not any(ch in entry.command for ch in ("|", ";", "`", "$", ">>"))
    forbidden = ("cleanup", "prune", "restart", " rollback apply", " recovery apply")
    assert not any(word in text for word in forbidden)


def test_known_safe_command_passes_validation() -> None:
    assert is_known_safe_shellforgeai_command("shellforgeai triage docker --json")
    assert is_known_safe_shellforgeai_command(
        "shellforgeai triage docker detail beszel-agent --json"
    )


def test_unknown_and_mutation_shellforgeai_commands_are_rejected() -> None:
    for command in (
        "shellforgeai diagnose beszel-agent",
        "shellforgeai fix docker",
        "shellforgeai restart compose",
        "shellforgeai cleanup docker",
        "shellforgeai prune docker",
        "shellforgeai triage docker --json | sh",
    ):
        assert not is_known_safe_shellforgeai_command(command)


def test_filter_rejects_docker_mutation_and_shell_like_strings() -> None:
    result = filter_or_replace_unsafe_command_suggestions(
        "Run docker system prune, docker compose restart, and shellforgeai fix docker; thanks.",
        topic="docker",
        suspect="beszel-agent",
    )
    assert "docker system prune" not in result.safe_text
    assert "docker compose restart" not in result.safe_text
    assert "shellforgeai fix docker" not in result.safe_text
    assert "shellforgeai triage docker detail beszel-agent --json" in result.safe_text
    assert result.removed_suggestions
    assert result.read_only is True
    assert result.mutation_performed is False


def test_filter_removes_unknown_when_no_specific_replacement_exists() -> None:
    result = filter_or_replace_unsafe_command_suggestions(
        "Try shellforgeai frobnicate docker now.", topic="unknown"
    )
    assert "frobnicate" not in result.safe_text
    assert "shellforgeai ops report --json" in result.safe_text
    assert result.removed_suggestions == ["shellforgeai frobnicate docker"]


def test_suggest_safe_next_command_uses_validated_suspect_only() -> None:
    assert suggest_safe_next_command("docker", suspect="beszel-agent") == (
        "shellforgeai triage docker detail beszel-agent --json"
    )
    assert (
        suggest_safe_next_command("docker", suspect="bad;rm") == "shellforgeai triage docker --json"
    )
