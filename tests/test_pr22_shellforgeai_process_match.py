from shellforgeai.tools import process
from shellforgeai.util.subprocess import CommandResult


def test_process_find_shellforgeai_can_match_self_named_process(monkeypatch):
    sample = "1 init /sbin/init\n22 shellforgeai shellforgeai interactive\n"
    monkeypatch.setattr(
        "shellforgeai.tools.process.run_command",
        lambda *_a, **_k: CommandResult(["ps"], 0, sample, "", 1),
    )
    r = process.find("shellforgeai")
    assert r.ok
    assert "shellforgeai" in r.stdout
