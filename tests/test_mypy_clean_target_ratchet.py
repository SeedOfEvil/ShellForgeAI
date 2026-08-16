from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CLEAN_TARGETS = (
    Path("src/shellforgeai/commands/ops.py"),
    Path("src/shellforgeai/commands/triage.py"),
    Path("src/shellforgeai/core/recipe_receipt_audit.py"),
)
DIAGNOSTIC_PATTERN = re.compile(r"^(?P<path>.+?):\d+(?::\d+)?: error:", re.MULTILINE)


def test_clean_targets_remain_free_of_full_package_mypy_diagnostics() -> None:
    """Keep completed typing slices clean while exposing the package backlog."""

    environment = os.environ.copy()
    source_root = str(REPOSITORY_ROOT / "src")
    existing_mypy_path = environment.get("MYPYPATH")
    environment["MYPYPATH"] = (
        source_root + os.pathsep + existing_mypy_path if existing_mypy_path else source_root
    )
    result = subprocess.run(
        [sys.executable, "-m", "mypy"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    print(output, end="")

    assert result.returncode in (0, 1), (
        f"mypy did not complete normally (exit {result.returncode})\n{output}"
    )
    diagnostic_paths = {
        Path(match.group("path")).resolve()
        if Path(match.group("path")).is_absolute()
        else (REPOSITORY_ROOT / match.group("path")).resolve()
        for match in DIAGNOSTIC_PATTERN.finditer(output)
    }
    dirty_targets = [
        str(target)
        for target in CLEAN_TARGETS
        if (REPOSITORY_ROOT / target).resolve() in diagnostic_paths
    ]
    assert not dirty_targets, f"mypy ratchet regressed clean targets: {dirty_targets}"
