from __future__ import annotations

from shellforgeai.core.config import Settings
from shellforgeai.llm.codex import CodexProvider


def build_provider(settings: Settings):
    if settings.model.provider == "openai-codex":
        return CodexProvider(
            binary=settings.model.codex_binary,
            default_model=settings.model.model,
            fallback_model=settings.model.fallback_model,
            timeout_seconds=settings.model.timeout_seconds,
            sandbox=settings.model.codex_sandbox,
            use_json=settings.model.codex_json,
            skip_git_repo_check=settings.model.codex_skip_git_repo_check,
            allow_fallback=settings.model.allow_model_fallback,
        )
    return CodexProvider(
        default_model=settings.model.model,
        skip_git_repo_check=settings.model.codex_skip_git_repo_check,
    )
