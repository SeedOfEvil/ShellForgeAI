from __future__ import annotations

from typing import Protocol

from shellforgeai.llm.schemas import ModelRequest, ModelResponse


class ModelProvider(Protocol):
    name: str

    def available(self) -> tuple[bool, str]: ...

    def doctor(self) -> dict[str, str | bool]: ...

    def complete(self, request: ModelRequest) -> ModelResponse: ...

    def stream_complete(self, request: ModelRequest): ...
