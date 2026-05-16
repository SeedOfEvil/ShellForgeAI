from shellforgeai.core.compose_context import parse_compose_context


def test_parse_compose_context_detected() -> None:
    labels = {
        "com.docker.compose.project": "sf",
        "com.docker.compose.service": "web",
        "com.docker.compose.oneoff": "false",
        "com.docker.compose.project.config_files": "/a.yml,/b.yml",
    }
    out = parse_compose_context(labels)
    assert out["detected"] is True
    assert out["project"] == "sf"
    assert out["service"] == "web"
    assert out["oneoff"] is False
    assert out["config_files"] == ["/a.yml", "/b.yml"]


def test_parse_compose_context_missing() -> None:
    out = parse_compose_context({"foo": "bar"})
    assert out["detected"] is False
