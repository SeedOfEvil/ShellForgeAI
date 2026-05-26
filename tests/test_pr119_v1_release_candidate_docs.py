from pathlib import Path

RC_DOC = Path("docs/V1_RELEASE_CANDIDATE.md")
README = Path("README.md")
OPS = Path("OPS.md")
V1_SCOPE = Path("docs/v1-scope.md")
V1_SURFACE = Path("docs/V1_COMMAND_SURFACE.md")
SAFETY = Path("docs/safety.md")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _lower(path: Path) -> str:
    return _text(path).lower()


def test_rc_doc_exists() -> None:
    assert RC_DOC.exists()


def test_required_docs_link_to_release_candidate() -> None:
    for path in (README, OPS, V1_SCOPE, V1_SURFACE, SAFETY):
        assert "V1_RELEASE_CANDIDATE.md" in _text(path), f"missing link in {path}"


def test_rc_doc_contains_required_sections() -> None:
    text = _lower(RC_DOC)
    for section in (
        "v1 promise",
        "what v1 includes",
        "what v1 does not include",
        "required local/dev validation",
        "required docker01 smoke validation",
        "required deterministic ask validation",
        "required artifact validation",
        "safety invariants",
        "known acceptable caveats",
        "hard blockers",
        "docker01 handoff template",
        "final v1 release sign-off",
    ):
        assert section in text


def test_rc_doc_contains_required_validation_commands() -> None:
    text = _lower(RC_DOC)
    for cmd in (
        "./scripts/v1_validate.sh --quick",
        "./scripts/v1_validate.sh --full",
        "./scripts/v1_validate.sh --quick --packet",
        "./scripts/v1_validate.sh --quick --export-packet",
        "pytest -q",
        "ruff check .",
        "python -m compileall -q src tests",
    ):
        assert cmd in text


def test_rc_doc_contains_required_runtime_commands() -> None:
    text = _lower(RC_DOC)
    for cmd in (
        "shellforgeai version",
        "shellforgeai doctor",
        "shellforgeai model doctor",
        "shellforgeai v1 check --profile quick --json",
        "shellforgeai ops report --json",
        "shellforgeai remediation self-test --profile full --json",
    ):
        assert cmd in text


def test_rc_doc_contains_artifact_commands() -> None:
    text = _lower(RC_DOC)
    for cmd in (
        "shellforgeai ops report --save --json",
        "shellforgeai ops report validate",
        "shellforgeai ops report export",
        "shellforgeai ops report export-validate",
        "shellforgeai v1 packet --save --json",
        "shellforgeai v1 packet validate",
        "shellforgeai v1 packet export",
        "shellforgeai v1 packet export-validate",
    ):
        assert cmd in text


def test_rc_doc_contains_mutation_refusal_test() -> None:
    assert 'shellforgeai ask "please restart shellforgeai"' in _lower(RC_DOC)


def test_rc_doc_contains_out_of_scope_safety_statements() -> None:
    text = _lower(RC_DOC)
    assert "production autonomous remediation" in text and "does not include" in text
    assert "natural-language mutation execution" in text
    assert "docker/compose mutation" in text
    assert "arbitrary shell execution" in text


def test_dangerous_commands_not_casual_release_steps() -> None:
    text = _lower(RC_DOC)
    forbidden = (
        "docker restart",
        "docker compose restart",
        "docker compose up",
        "docker compose down",
        "docker system prune",
        "docker volume prune",
        "cleanup execute --confirm",
        "remediation execute --confirm",
        "rollback-execute --confirm",
    )
    allowed_context = ("not include", "hard blocker", "refus", "governed", "not v1")
    for line in text.splitlines():
        for token in forbidden:
            if token in line:
                assert any(ctx in line for ctx in allowed_context), (
                    f"dangerous command appears as casual step: {token} | line={line!r}"
                )
