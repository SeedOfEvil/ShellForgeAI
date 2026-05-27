import importlib.metadata
import tomllib
from pathlib import Path

import pytest

CHANGELOG = Path("CHANGELOG.md")
RELEASE_NOTES = Path("docs/V1_RELEASE_NOTES.md")
README = Path("README.md")
OPS = Path("OPS.md")


def _lower(path: Path) -> str:
    return path.read_text(encoding="utf-8").lower()


def test_release_notes_or_changelog_exists() -> None:
    assert CHANGELOG.exists() or RELEASE_NOTES.exists()


def test_release_notes_core_identity_and_non_autonomous_boundary() -> None:
    text = _lower(RELEASE_NOTES)
    assert "cli-first linux/docker operator knife" in text
    assert "not an autonomous remediation agent" in text


def test_release_notes_include_core_v1_capabilities() -> None:
    text = _lower(RELEASE_NOTES)
    for needle in (
        "doctor",
        "model doctor",
        "triage docker detail",
        "ops report",
        "compare-latest",
        "deterministic 2am ask routing",
        "deterministic mutation refusal",
        "remediation eligibility",
        "remediation self-test",
        "v1 check",
        "v1 packet",
        "v1_validate.sh",
    ):
        assert needle in text


def test_release_notes_include_safety_boundaries_and_caveats() -> None:
    text = _lower(RELEASE_NOTES)
    for needle in (
        "read-only by default",
        "no natural-language mutation execution",
        "no arbitrary shell execution",
        "no `shell=true`",
        "no docker compose mutation in v1",
        "known caveats",
        "dev-validation lane",
    ):
        assert needle in text


def test_release_notes_include_first_commands_and_signoff_template() -> None:
    text = _lower(RELEASE_NOTES)
    for needle in (
        "recommended first commands",
        "shellforgeai doctor",
        "shellforgeai model doctor",
        "shellforgeai v1 check --profile quick",
        "shellforgeai ops report --save",
        "shellforgeai triage docker detail <target>",
        "release sign-off template",
        "version / commit",
        "release verdict",
    ):
        assert needle in text


def test_docs_reference_deterministic_routing_refusal_and_artifacts() -> None:
    corpus = "\n".join(_lower(path) for path in (RELEASE_NOTES, README, OPS, CHANGELOG))
    assert "deterministic ask routing" in corpus
    assert "deterministic mutation refusal" in corpus
    assert "ops report artifact lifecycle" in corpus


def test_docs_include_dev_validation_lane_packet_export_note() -> None:
    corpus = "\n".join(_lower(path) for path in (RELEASE_NOTES, OPS, CHANGELOG))
    assert "packet/export" in corpus
    assert "dev-validation lane" in corpus


def test_docs_do_not_casually_recommend_dangerous_commands() -> None:
    forbidden = (
        "docker restart",
        "docker compose restart",
        "cleanup execute --confirm",
        "remediation execute --confirm",
        "rollback-execute --confirm",
    )
    allowed_context = (
        "not",
        "no ",
        "non-goal",
        "gated",
        "governed",
        "refusal",
        "allowlisted",
        "disposable",
        "exact-container",
        "env vars",
        "requires",
    )
    for path in (RELEASE_NOTES, CHANGELOG):
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.lower()
            for token in forbidden:
                if token in line:
                    assert any(ctx in line for ctx in allowed_context), (
                        f"dangerous command appears casually in {path}: {raw_line!r}"
                    )


def test_version_surfaces_match_v1_release() -> None:
    from typer.testing import CliRunner

    from shellforgeai.cli import app
    from shellforgeai.version import __version__

    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ShellForgeAI 1.0.0" in result.stdout

    assert __version__ == "1.0.0"

    try:
        metadata_version = importlib.metadata.version("shellforgeai")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("installed package metadata unavailable in source-tree test env")
    assert metadata_version == "1.0.0"

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == "1.0.0"

    assert __version__ == metadata_version == pyproject["project"]["version"]


def test_release_docs_call_out_v1_100() -> None:
    assert "v1 baseline / 1.0.0" in _lower(RELEASE_NOTES)
    assert "## [1.0.0]" in CHANGELOG.read_text(encoding="utf-8")
