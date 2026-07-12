from shellforgeai.llm.codex import classify_model_failure


def test_missing_codex_home_is_not_reported_as_expired_auth():
    failure = classify_model_failure(
        stdout="",
        stderr="codex_context_not_configured_for_process: set CODEX_HOME for this process context",
        returncode=1,
    )

    assert failure["category"] == "codex_context_not_configured_for_process"
    assert "expired" not in failure["user_message"].lower()
    assert "CODEX_HOME" in failure["next_step"]


def test_unverified_login_status_is_distinct_from_invalid_auth():
    failure = classify_model_failure(
        stdout="",
        stderr="codex_login_not_verified: codex login status not proven for configured CODEX_HOME",
        returncode=1,
    )

    assert failure["category"] == "codex_login_not_verified"
    assert "invalid" not in failure["user_message"].lower()
    assert "codex login status" in failure["next_step"]


def test_expired_auth_remains_precise_when_proven_by_codex_output():
    failure = classify_model_failure(stdout="", stderr="token expired", returncode=1)

    assert failure["category"] == "auth"
    assert failure["next_step"] == "codex login --device-auth"
