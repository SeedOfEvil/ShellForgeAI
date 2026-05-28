"""PR127 — doctor metadata hygiene clarity and cleanup-review guidance.

Warning clarity only. These tests assert that `shellforgeai doctor`:
- distinguishes runtime health from historical ShellForgeAI artifact hygiene,
- does not imply a live Docker/system runtime failure when only metadata
  hygiene thresholds are exceeded,
- states that no cleanup was performed,
- offers `audit cleanup review` as the first safe command,
- keeps cleanup execution explicitly gated,
- keeps JSON strict, parseable, and backwards-compatible with additive
  context/safety fields,
- and that this PR introduces no cleanup/remediation/rollback/mutation.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from shellforgeai.cli import app

runner = CliRunner()


def _seed_attention(data_dir: Path, count: int = 3, size: int = 64) -> None:
    exports = data_dir / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (exports / f"e{i}.bin").write_text("x" * size, encoding="utf-8")


# --- human output clarity -------------------------------------------------


def test_doctor_human_distinguishes_runtime_from_metadata(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor"])
    assert out.exit_code == 0
    text = out.stdout
    assert "- Runtime: OK" in text
    assert "Metadata hygiene: attention needed" in text
    assert "historical artifacts" in text.lower()
    assert "No cleanup was performed." in text
    assert "First safe command: shellforgeai audit cleanup review" in text


def test_doctor_human_does_not_imply_runtime_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor"])
    assert out.exit_code == 0
    text = out.stdout
    # Runtime is reported OK, and the note explicitly disclaims a live failure.
    assert "- Runtime: OK" in text
    assert "not an active Docker/system failure" in text


def test_doctor_human_first_command_is_review_not_execute(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor"])
    assert out.exit_code == 0
    text = out.stdout
    first_idx = text.index("First safe command:")
    first_line = text[first_idx : text.index("\n", first_idx)]
    assert "audit cleanup review" in first_line
    assert "execute" not in first_line
    assert "--confirm" not in first_line


def test_doctor_human_no_prune_commands(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor"])
    assert out.exit_code == 0
    text = out.stdout.lower()
    assert "docker system prune" not in text
    assert "docker volume prune" not in text
    assert "rm -rf" not in text


def test_doctor_human_states_cleanup_gates(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor"])
    assert out.exit_code == 0
    assert "review -> plan -> archive -> validate -> execute --confirm" in out.stdout


# --- JSON output ----------------------------------------------------------


def test_doctor_json_is_parseable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor", "--json"])
    assert out.exit_code == 0
    text = out.stdout.strip()
    assert text.startswith("{")
    payload = json.loads(text)
    assert "metadata_hygiene" in payload


def test_doctor_json_metadata_hygiene_context_fields(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor", "--json"])
    payload = json.loads(out.stdout)
    mh = payload["metadata_hygiene"]
    assert mh["cleanup_performed"] is False
    assert mh["active_runtime_failure"] is False
    assert mh["cleanup_execution_gated"] is True
    assert mh["first_safe_command"] == "shellforgeai audit cleanup review"
    assert "historical artifacts" in mh["human_context"].lower()


def test_doctor_json_backwards_compatible_fields(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor", "--json"])
    mh = json.loads(out.stdout)["metadata_hygiene"]
    # PR70/PR45 fields remain present.
    for key in ("severity", "status", "reasons", "recommendations", "categories"):
        assert key in mh


def test_doctor_json_safety_block(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor", "--json"])
    safety = json.loads(out.stdout)["safety"]
    assert safety["cleanup_executed"] is False
    assert safety["mutation_performed"] is False
    assert safety["docker_compose_executed"] is False
    assert safety["remediation_executed"] is False
    assert safety["rollback_executed"] is False


# --- happy path (no attention) regression --------------------------------


def test_doctor_happy_path_when_below_threshold(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "tiny.bin").write_text("z", encoding="utf-8")
    out = runner.invoke(app, ["doctor"])
    assert out.exit_code == 0
    assert "- Metadata hygiene: OK" in out.stdout
    # No alarming wording when within thresholds.
    assert "attention needed" not in out.stdout


# --- cleanup review remains read-only -------------------------------------


def test_cleanup_review_remains_read_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    _seed_attention(tmp_path, count=4)
    before = sorted(p.name for p in (tmp_path / "exports").iterdir())
    out = runner.invoke(app, ["audit", "cleanup", "review", "--json"])
    assert out.exit_code == 0
    payload = json.loads(out.stdout)
    assert payload["safety"]["cleanup_executed"] is False
    assert payload["safety"]["mutation_performed"] is False
    after = sorted(p.name for p in (tmp_path / "exports").iterdir())
    assert before == after
    assert not (tmp_path / "cleanup_plans").exists()
    assert not (tmp_path / "cleanup_archives").exists()


# --- safety regression: no mutation introduced ----------------------------


def test_doctor_does_not_mutate_data_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path, count=5)
    before = {p.name for p in tmp_path.iterdir()}
    runner.invoke(app, ["doctor"])
    runner.invoke(app, ["doctor", "--json"])
    after = {p.name for p in tmp_path.iterdir()}
    forbidden = {
        "cleanup_plans",
        "cleanup_archives",
        "cleanup_receipts",
        "archives",
        "prune_receipts",
        "execution_receipts",
    }
    assert (after - before).isdisjoint(forbidden)


def test_doctor_human_never_suggests_mutation_terms(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SHELLFORGEAI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHELLFORGEAI_METADATA_WARN_BYTES", "1")
    _seed_attention(tmp_path)
    out = runner.invoke(app, ["doctor"])
    text = out.stdout.lower()
    # execute --confirm only appears inside the gate explanation, never as a
    # first/standalone recommendation line.
    for line in text.splitlines():
        if line.strip().startswith("- suggested safe next steps"):
            continue
        if "first safe command" in line:
            assert "execute" not in line
    assert "docker compose restart" not in text
    assert "docker compose up" not in text
    assert "docker compose down" not in text


# --- docs contract --------------------------------------------------------


def test_safety_docs_clarify_metadata_hygiene_not_runtime_failure() -> None:
    text = Path("docs/safety.md").read_text(encoding="utf-8").lower()
    assert "shellforgeai-owned artifact hygiene" in text
    assert "automatic docker/system runtime failure" in text
    assert "not** an automatic docker/system runtime failure" in text


def test_ops_docs_recommend_review_first() -> None:
    text = Path("OPS.md").read_text(encoding="utf-8")
    assert "shellforgeai audit cleanup review" in text
    assert "Do not jump to" in text


def test_cli_docs_describe_doctor_hygiene_clarity() -> None:
    text = Path("docs/cli.md").read_text(encoding="utf-8")
    assert "doctor metadata hygiene clarity" in text.lower()
    assert "shellforgeai audit cleanup review" in text
    assert "active_runtime_failure" in text
