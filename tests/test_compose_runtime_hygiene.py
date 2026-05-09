from pathlib import Path


def test_compose_service_has_init_reaper_enabled() -> None:
    text = Path("compose.yaml").read_text(encoding="utf-8")
    assert "shellforgeai:" in text
    assert "init: true" in text
