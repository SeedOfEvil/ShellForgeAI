from __future__ import annotations

import pytest

from shellforgeai.core.command_suggestions import (
    remediation_eligibility_explain_command,
    remediation_plan_command,
    remediation_self_test_command,
    triage_detail_command,
)


def test_target_command_builder_normal_target() -> None:
    assert (
        triage_detail_command("sfai-crashloop")
        == "shellforgeai triage docker detail sfai-crashloop"
    )


def test_builder_rejects_suspicious_target() -> None:
    with pytest.raises(ValueError):
        triage_detail_command("sfai;rm -rf /")


def test_eligibility_explain_command() -> None:
    assert (
        remediation_eligibility_explain_command("sfai-crashloop", json=True)
        == "shellforgeai remediation eligibility --target sfai-crashloop --explain --json"
    )


def test_remediation_plan_command_plan_only_string() -> None:
    cmd = remediation_plan_command("sfai-noisy-errors", "sfai-noisy-errors")
    assert cmd.startswith("shellforgeai remediation plan --target sfai-noisy-errors")


def test_self_test_command_profiles() -> None:
    assert remediation_self_test_command(profile="quick")
    assert remediation_self_test_command(profile="standard")
    assert remediation_self_test_command(profile="full")
    with pytest.raises(ValueError):
        remediation_self_test_command(profile="bad")
