from pathlib import Path

DOC_FILES = [
    Path("README.md"),
    Path("docs/v1-scope.md"),
    Path("docs/architecture.md"),
    Path("docs/safety.md"),
    Path("docs/demo.md"),
]


FORBIDDEN_COMMANDS = [
    "docker restart",
    "docker compose restart",
    "remediation execute --confirm",
    "rollback-execute --confirm",
    "cleanup execute --confirm",
    "docker system prune",
    "docker volume prune",
]


SAFE_COMMANDS = [
    "shellforgeai ops report",
    "shellforgeai ops report --save",
    "shellforgeai ops report history",
    "shellforgeai ops report compare-latest",
    "shellforgeai triage docker detail <target>",
    "shellforgeai remediation eligibility --target <target> --explain",
    "shellforgeai remediation self-test --profile quick",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").lower()


def test_v1_docs_exist() -> None:
    scoped_files = [Path("README.md"), Path("docs/v1-scope.md"), Path("docs/demo.md")]
    for path in scoped_files:
        assert path.exists(), f"missing required V1 doc: {path}"


def test_readme_contains_v1_shape() -> None:
    text = _read(Path("README.md"))
    for needle in (
        "what this is",
        "what this is not",
        "shellforgeai doctor",
        "shellforgeai ops report",
        "shellforgeai triage docker detail",
        "shellforgeai remediation eligibility",
        "mutation refusal",
    ):
        assert needle in text, f"README missing: {needle}"


def test_v1_scope_contains_contract_sections() -> None:
    text = _read(Path("docs/v1-scope.md"))
    for needle in (
        "v1 core capabilities",
        "v1 non-goals",
        "read-only by default",
        "mutation boundaries",
        "no autonomous production remediation",
    ):
        assert needle in text, f"docs/v1-scope.md missing: {needle}"


def test_safety_doc_contains_required_guards() -> None:
    text = _read(Path("docs/safety.md"))
    for needle in (
        "natural-language mutation",
        "no `shell=true`",
        "no arbitrary command execution",
        "governed remediation",
        "disposable-only",
    ):
        assert needle in text, f"docs/safety.md missing: {needle}"


def test_demo_doc_contains_fixture_and_flow() -> None:
    text = _read(Path("docs/demo.md"))
    for needle in (
        "crashloop",
        "bad http",
        "disk pressure",
        "noisy",
        "permission denied",
        "ops report",
        "compare-latest",
        "mutation refusal",
    ):
        assert needle in text, f"docs/demo.md missing: {needle}"


def test_forbidden_commands_not_present_casually() -> None:
    guarded_tokens = (
        "allowlist",
        "allowlisted",
        "disposable",
        "gated",
        "gate",
        "not v1",
        "not for v1",
        "exact-container",
        "metadata cleanup",
    )
    scoped_files = [Path("README.md"), Path("docs/v1-scope.md"), Path("docs/demo.md")]
    for path in scoped_files:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.lower()
            for forbidden in FORBIDDEN_COMMANDS:
                if forbidden in line and not any(token in line for token in guarded_tokens):
                    raise AssertionError(
                        f"forbidden casual doc command in {path}: {forbidden} | line={raw_line!r}"
                    )


def test_v1_safe_command_spine_present() -> None:
    corpus = "\n".join(_read(path) for path in DOC_FILES)
    for command in SAFE_COMMANDS:
        assert command in corpus, f"missing canonical safe command: {command}"
