"""PR248 — manual fallback validation container parity docs guard."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOC_PATHS = [
    REPO_ROOT / "OPS.md",
    REPO_ROOT / "docs" / "VALIDATION_LANES.md",
    REPO_ROOT / "docs" / "VALIDATION_MATRIX.md",
    REPO_ROOT / "docs" / "roadmap.md",
]
FALLBACK_HELPER = REPO_ROOT / "scripts" / "validation_container_fallback.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _docs_text() -> str:
    return "\n".join(_read(path) for path in DOC_PATHS).lower()


def _fallback_snippets() -> list[str]:
    docs = "\n".join(_read(path) for path in DOC_PATHS)
    snippets: list[str] = []
    in_fence = False
    current: list[str] = []
    for line in docs.splitlines():
        fence = line.strip().lower()
        if in_fence and fence == "```":
            snippet = "\n".join(current)
            if "apt-get install" in snippet.lower():
                snippets.append(snippet)
            current = []
            in_fence = False
            continue
        if not in_fence and fence in {"```bash", "```sh"}:
            in_fence = True
            current = []
            continue
        if in_fence:
            current.append(line)
    return snippets


def test_docs_describe_manual_fallback_procps_and_ps_requirement() -> None:
    docs = _docs_text()

    assert "manual fallback validation" in docs or "manual disposable fallback" in docs
    assert "procps" in docs
    assert "ps" in docs
    assert "tests/test_investigation_tools.py::test_process_snapshot_shape" in docs
    assert "false-fail" in docs or "false failure" in docs or "false-failure" in docs


def test_docs_cover_git_rsync_and_official_docker01_lane_helper_parity() -> None:
    docs = _docs_text()

    assert "official docker01 lane helper" in docs
    assert "git" in docs
    assert "rsync" in docs
    assert "python3" in docs or "python 3" in docs
    assert "pytest" in docs


def test_docs_prevent_duplicate_full_pytest_after_missing_tool_failure() -> None:
    docs = _docs_text()

    assert "do not duplicate full pytest" in docs or "full pytest should run once only" in docs
    assert "run full pytest once only" in docs or "full pytest should run once only" in docs
    assert (
        "fix the container baseline" in docs or "fix the disposable validation environment" in docs
    )
    assert "rerun that narrow test" in docs or "rerun only that narrow test" in docs


def test_fallback_snippets_keep_procps_and_narrow_test_first() -> None:
    snippets = _fallback_snippets()

    assert snippets, "expected at least one manual fallback/procps documentation snippet"
    assert any("apt-get install" in snippet and "procps" in snippet for snippet in snippets)
    assert any("git" in snippet and "rsync" in snippet for snippet in snippets)
    assert any("test_process_snapshot_shape" in snippet for snippet in snippets)


def test_fallback_snippets_do_not_suggest_production_mutation_or_remediation() -> None:
    forbidden = [
        "docker compose up",
        "docker compose down",
        "docker restart",
        "docker system prune",
        "docker image rm",
        "docker volume rm",
        "docker compose",
        "docker prune",
        "docker restart",
        "--cleanup",
        "--prune",
        "--restart",
        "--remediation",
        "--rollback",
        "--recovery",
    ]

    for snippet in _fallback_snippets():
        lowered = snippet.lower()
        for token in forbidden:
            assert token not in lowered


def test_generated_fallback_command_baseline_still_includes_procps_git_rsync() -> None:
    helper = _read(FALLBACK_HELPER)

    assert "apt-get install -y --no-install-recommends procps git rsync" in helper
    assert "procps" in helper
    assert "git" in helper
    assert "rsync" in helper
