from pathlib import Path

SCRIPT = Path("scripts/v1_validate.sh")
VALIDATION_DOC = Path("docs/V1_VALIDATION.md")
OPS = Path("OPS.md")
README = Path("README.md")

FORBIDDEN_SCRIPT_TOKENS = [
    "docker restart",
    "docker compose restart",
    "docker compose up",
    "docker compose down",
    "docker system prune",
    "docker volume prune",
    "apt-get install",
    "apk add",
    "pip install",
]

DANGEROUS_CASUAL = [
    "shellforgeai remediation execute --confirm",
    "shellforgeai remediation rollback-execute --confirm",
    "shellforgeai audit cleanup execute --confirm",
    "docker volume prune",
    "docker compose down",
    "docker system prune",
]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_validation_script_exists() -> None:
    assert SCRIPT.exists()


def test_validation_script_has_required_behavior_markers() -> None:
    text = _text(SCRIPT)
    assert "set -euo pipefail" in text
    assert "--quick" in text
    assert "--full" in text
    assert "--help" in text
    assert "ruff check ." in text
    assert "compileall -q src tests" in text
    assert "pytest" in text


def test_validation_script_has_no_mutation_or_auto_install_commands() -> None:
    text = _text(SCRIPT).lower()
    for token in FORBIDDEN_SCRIPT_TOKENS:
        assert token not in text


def test_validation_script_checks_ps_requirement() -> None:
    text = _text(SCRIPT)
    assert (
        "ps not found; install procps in disposable validation containers "
        "before running full pytest"
    ) in text


def test_validation_doc_exists_and_mentions_required_topics() -> None:
    text = _text(VALIDATION_DOC).lower()
    assert "procps" in text
    assert "python:3.12-slim" in text or "python:3.12-bookworm" in text
    assert (
        "do not install test dependencies into the production shellforgeai runtime container"
        in text
    )
    assert "ruff_cache_dir" in text
    assert "pythonpycacheprefix" in text
    assert "writable copy" in text or "read-only" in text


def test_ops_compose_safety_guidance_present() -> None:
    text = _text(OPS).lower()
    assert "backup compose file" in text or "cp compose.yml compose.yml.bak" in text
    assert "compose.yml.tmp" in text
    assert "docker compose -f compose.yml.tmp config" in text
    assert "truncate `compose.yml`" in text or "truncate compose.yml" in text
    assert "do not prune volumes" in text
    assert "do not remove running containers" in text


def test_readme_links_validation_doc() -> None:
    text = _text(README)
    assert "docs/V1_VALIDATION.md" in text


def test_dangerous_strings_are_not_present_as_casual_steps() -> None:
    corpus = "\n".join((_text(SCRIPT), _text(VALIDATION_DOC), _text(OPS))).lower()
    guard_words = ["do not", "never", "non-goal", "warning", "refus"]
    for token in DANGEROUS_CASUAL:
        if token in corpus:
            assert any(g in corpus for g in guard_words), token
