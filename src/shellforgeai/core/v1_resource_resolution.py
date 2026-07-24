from __future__ import annotations

from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

REQUIRED_V1_CONTRACT_RESOURCES: tuple[str, ...] = (
    "README.md",
    "docs/v1-scope.md",
    "docs/safety.md",
    "docs/cli.md",
    "OPS.md",
)


@dataclass(frozen=True)
class V1ResourceResolution:
    resolved: bool
    root: Path | None
    source: str
    checked_sources: tuple[str, ...] = field(default_factory=tuple)
    required_resources: tuple[str, ...] = REQUIRED_V1_CONTRACT_RESOURCES
    missing_resources: tuple[str, ...] = field(default_factory=tuple)
    cwd_independent: bool = False
    error_class: str | None = None
    error_message: str | None = None

    def evidence(self) -> dict[str, object]:
        return {
            "resolved": self.resolved,
            "source": self.source,
            "checked_sources": list(self.checked_sources),
            "required_resources": list(self.required_resources),
            "missing": list(self.missing_resources),
            "cwd_independent": self.cwd_independent,
            "error_class": self.error_class,
            "error_message": self.error_message,
        }


def _missing_resources(root: Path) -> tuple[str, ...]:
    return tuple(rel for rel in REQUIRED_V1_CONTRACT_RESOURCES if not (root / rel).is_file())


def _valid(root: Path) -> bool:
    return not _missing_resources(root)


def _candidate_roots(cwd: Path) -> tuple[tuple[str, Path], ...]:
    candidates: list[tuple[str, Path]] = []
    try:
        package_root = Path(str(files("shellforgeai"))).resolve()
    except Exception:
        package_root = None
    if package_root is not None:
        # Bounded imported package/source lineage: package dir, src dir, repo root.
        candidates.extend(
            (
                ("imported_package_source_root", package_root),
                ("imported_package_source_root", package_root.parent),
                ("imported_package_source_root", package_root.parent.parent),
            )
        )
    try:
        import sys

        executable = Path(sys.executable).resolve()
    except Exception:
        executable = None
    if executable is not None:
        # Bounded executable lineage only; no PATH, home, drive, or recursive search.
        candidates.extend(
            (
                ("python_executable_lineage", executable.parent),
                ("python_executable_lineage", executable.parent.parent),
            )
        )
    candidates.append(("current_working_directory", cwd.resolve()))
    return tuple(candidates)


def resolve_v1_contract_resource_root(cwd: Path | None = None) -> V1ResourceResolution:
    """Resolve required V1 contract resources without depending on caller cwd.

    The search is fixed and bounded to at most six candidates: three roots from
    the imported ``shellforgeai`` package lineage, two roots from the current
    Python executable lineage, then the current working directory as a final
    complete-contract fallback. It performs read-only existence checks only.
    """
    current = cwd or Path.cwd()
    checked: list[str] = []
    best_missing: tuple[str, ...] = REQUIRED_V1_CONTRACT_RESOURCES
    seen: set[Path] = set()
    for source, root in _candidate_roots(current):
        checked.append(source)
        if root in seen:
            continue
        seen.add(root)
        missing = _missing_resources(root)
        if len(missing) < len(best_missing):
            best_missing = missing
        if not missing:
            return V1ResourceResolution(
                True,
                root,
                source,
                tuple(checked),
                missing_resources=(),
                cwd_independent=source != "current_working_directory",
            )
    return V1ResourceResolution(
        False,
        None,
        "unresolved",
        tuple(checked) + ("unresolved",),
        missing_resources=best_missing,
        cwd_independent=False,
        error_class="v1_contract_resources_not_resolved",
        error_message=(
            "No bounded ShellForgeAI V1 contract resource root contains every required resource."
        ),
    )
