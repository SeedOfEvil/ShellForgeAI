"""In-memory, session-local terminal model failure suppression."""

from shellforgeai.llm.schemas import ModelRequest, ModelResponse


def complete_for_session(session, provider, request: ModelRequest) -> ModelResponse:
    """Call the provider unless this session already proved it terminally failed."""
    failure = getattr(session, "provider_failure", None)
    if failure is not None:
        category = str(failure.get("category") or "provider_failure")[:64]
        return ModelResponse(
            provider=request.provider,
            model=request.model,
            text="",
            ok=False,
            error=f"model assistance suppressed for this session ({category})",
            metadata={
                "codex_exec_error_class": category,
                "provider_call_suppressed": True,
                "provider_attempt_count": 0,
            },
        )
    response = provider.complete(request)
    if not response.ok:
        metadata = response.metadata or {}
        session.provider_failure = {
            "category": str(metadata.get("codex_exec_error_class") or "provider_failure")[:64],
            "attempt_count": min(int(metadata.get("provider_attempt_count") or 1), 2),
            "suppressed": True,
        }
    return response
