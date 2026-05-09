from shellforgeai.llm.codex import CodexProvider
from shellforgeai.llm.schemas import ModelRequest


def test_command_flags(monkeypatch):
    calls = {}

    def fake_run(cmd, capture_output, text, timeout):
        calls["cmd"] = cmd

        class R:
            returncode = 0
            stdout = "ok"
            stderr = ""

        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    p = CodexProvider()
    r = p.complete(ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex"))
    assert r.ok
    c = calls["cmd"]
    assert "exec" in c and "-m" in c and "gpt-5.5" in c
    assert "--sandbox" in c and "read-only" in c
    assert "--json" in c
    assert "--skip-git-repo-check" in c
    assert "--yolo" not in c


def test_stream_complete_reuses_complete_for_safe_cleanup(monkeypatch):
    p = CodexProvider()
    monkeypatch.setattr(
        p,
        "complete",
        lambda _req: type(
            "Resp",
            (),
            {
                "text": "hello",
                "provider": "openai-codex",
                "model": "gpt-5.5",
                "ok": True,
                "error": None,
            },
        )(),
    )
    evs = list(
        p.stream_complete(ModelRequest(prompt="hi", model="gpt-5.5", provider="openai-codex"))
    )
    assert evs[0]["type"] == "text"
    assert evs[-1]["type"] == "final"
