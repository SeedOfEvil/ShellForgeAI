from __future__ import annotations

import json

from typer.testing import CliRunner

from shellforgeai.cli import app
from shellforgeai.platform_detection import PlatformInfo

WINDOWS_INFO = PlatformInfo("windows", "Windows-test", "nt", "2025", "AMD64")


def test_windows_memory_json_shape_and_numeric_types(monkeypatch) -> None:
    monkeypatch.setattr("shellforgeai.windows_memory.detect_platform", lambda: WINDOWS_INFO)
    monkeypatch.setattr(
        "shellforgeai.windows_memory._read_global_memory_status",
        lambda: {"total_bytes": 1024, "available_bytes": 256, "memory_load_percent": 75},
    )
    result = CliRunner().invoke(app, ["windows", "memory", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["read_only"] is True
    assert payload["mutation_performed"] is False
    assert payload["memory"]["total_bytes"] == 1024
    assert payload["memory"]["available_bytes"] == 256
    assert payload["memory"]["used_bytes"] == 768
    assert payload["memory"]["used_percent"] == 75.0
    assert isinstance(payload["memory"]["total_bytes"], int)
    assert isinstance(payload["memory"]["used_percent"], float)
