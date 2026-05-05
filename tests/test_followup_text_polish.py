from shellforgeai.interactive.repl import (
    _human_cpu_mem,
    _human_storage_pressure,
    _operator_followup_text,
)


def test_followup_text_no_duplication() -> None:
    txt = _operator_followup_text("broader read-only health pass", "x")
    assert "pass pass" not in txt
    assert "read-only read-only" not in txt


def test_cpu_mem_humanized() -> None:
    out = _human_cpu_mem("cpus=32 mem=78.1GiB/220.3GiB swap=0B/8.0GiB")
    assert "32 CPUs visible" in out
    assert "78.1 GiB / 220.3 GiB used" in out
    assert "swap unused" in out


def test_storage_pressure_humanized() -> None:
    out = _human_storage_pressure("some avg10=1.58 avg60=1.37 avg300=5.19 total=7022")
    assert "avg10 1.58 / avg60 1.37 / avg300 5.19" in out
    assert "total" not in out
