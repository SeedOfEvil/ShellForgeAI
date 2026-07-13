from __future__ import annotations

from typing import cast

from shellforgeai.llm.lifecycle import ModelCallLifecycle


def test_timing_fields_use_monotonic_clock_and_keep_missing_null() -> None:
    values = iter([10.0, 10.0, 10.1, 10.2, 10.4, 10.5, 10.7, 10.8, 10.9, 11.0])

    def clock() -> float:
        return next(values)

    lc = ModelCallLifecycle(5, clock)
    lc.mark("context_start")
    lc.mark("context_end")
    lc.mark("spawn_start")
    lc.mark("spawn_end")
    fields = lc.timing_fields()
    context_ms = cast(int, fields["context_build_ms"])
    spawn_ms = cast(int, fields["provider_spawn_ms"])
    total_ms = cast(int, fields["model_total_ms"])
    assert context_ms >= 0
    assert spawn_ms >= 0
    assert fields["prompt_build_ms"] is None
    assert fields["first_stdout_ms"] is None
    assert total_ms >= spawn_ms
