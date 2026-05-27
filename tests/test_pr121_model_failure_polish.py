from shellforgeai.llm.codex import classify_model_failure


def test_classify_refresh_token_jsonl_auth() -> None:
    out = "\n".join(
        [
            '{"type":"thread.started"}',
            '{"type":"turn.started"}',
            '{"type":"error", "message":"refresh token already used"}',
            '{"type":"turn.failed"}',
        ]
    )
    r = classify_model_failure(out, "")
    assert r["category"] == "auth"
    assert r["reason"] == "token_refresh_failed"
    assert r["raw_suppressed"] is True


def test_classify_invalid_grant_auth_invalid() -> None:
    r = classify_model_failure("", "invalid_grant")
    assert r["reason"] == "auth_invalid"


def test_classify_expired_and_login_required() -> None:
    assert classify_model_failure("token expired", "")["reason"] == "auth_expired"
    assert classify_model_failure("please run codex login", "")["reason"] == "login_required"


def test_classify_non_auth_failure_and_timeout() -> None:
    assert classify_model_failure("", "segfault")["reason"] == "unknown_model_failure"
    assert classify_model_failure("", "", returncode=124)["reason"] == "timeout"
